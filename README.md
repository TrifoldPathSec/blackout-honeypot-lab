# blackout-honeypot-lab

**An internal honeypot that trips Wazuh alerts: OpenCanary decoys on a dedicated VM, custom detection rules with MITRE ATT&CK mapping, and a live attack dashboard.**

*By @alex_mh · TrifoldPathSec lab series, Project 4 · October 2026*

---

## Lab setup

```mermaid
flowchart LR
    subgraph Host["MacBook Pro (macOS 26 Tahoe)"]
        A["Wazuh agent<br/>(existing)"]
        X["simulate_attacks.py<br/>(attacker)"]
        subgraph UTM["UTM hypervisor · shared network"]
            S["VM 1: Ubuntu<br/>Wazuh server + dashboard<br/>+ canary_dashboard.py"]
            C["VM 2: Ubuntu<br/>OpenCanary (Docker)<br/>+ Wazuh agent"]
        end
    end
    X -- "SSH, FTP, HTTP, Telnet,<br/>MySQL, RDP, VNC, Redis, Git" --> C
    C -- "opencanary.log (JSON)<br/>agent → 1514/tcp" --> S
    A --> S
    S -- "rules 100500–100549<br/>→ wazuh-alerts-*" --> D["Attack dashboard<br/>(SSH tunnel :8088)"]
```

### Why a separate VM for the honeypot

| Option | Verdict |
|---|---|
| **Dedicated canary VM** | ✅ Chosen. The decoys own real ports (22, 80, 3306...) on their own IP, a compromise of the honeypot is isolated from the SIEM, and Wazuh sees it as just another agent. |
| OpenCanary on the Wazuh VM | ❌ Port clashes (22 real SSH, 443 dashboard), and it puts attacker-facing services on the box that holds all your evidence. |
| OpenCanary on the Mac | ❌ Opens the ports the CIS hardening project just closed, and the firewall's stealth mode hides the decoys anyway. |

Sizing: OpenCanary is light. **1 vCPU, 1 GB RAM, 10 GB disk** is enough. Reuse the Ubuntu Server 26.04 arm64 ISO already used for the Wazuh VM.

## Build it

### 1. Create the canary VM (UTM)

1. New VM → Virtualize → Linux → Ubuntu Server 26.04 arm64 ISO.
2. 1 vCPU, 1024 MB RAM, 10 GB disk. Network: **Shared Network**, the same mode as the Wazuh VM, so the Mac and both VMs can reach each other.
3. Install with OpenSSH server enabled. Hostname: `canary-01`.
4. Note three IPs: canary VM (`ip -4 a`), Wazuh VM, and the Mac's address on the UTM bridge (`ifconfig bridge100` on the Mac).

### 2. Install OpenCanary and the Wazuh agent

Copy `canary-vm/` to the VM and run the setup script with the Wazuh VM's IP and the Mac's IP:

```bash
scp -r canary-vm <user>@<canary-ip>:~
```

```bash
ssh -t <user>@<canary-ip> 'cd canary-vm && sudo bash setup.sh <wazuh-ip> <mac-ip>'
```

The script:

- moves the real SSH to **port 2222**, reachable only from the Mac (UFW), so the decoy can take port 22;
- runs `thinkst/opencanary:0.9.10` in Docker on the host network with nine decoys: FTP 21, SSH 22, Telnet 23, HTTP 80 (NAS login page), MySQL 3306, RDP 3389, VNC 5900, Redis 6379, Git 9418;
- installs the Wazuh agent **4.14.8** (matching the manager), enrolls it as `canary-01`, and adds `/var/log/opencanary/opencanary.log` as a `json` log source;
- adds logrotate for the canary log.

From now on, manage the VM with `ssh -p 2222 <user>@<canary-ip>`.

### 3. Load the detection rules on the Wazuh server

```bash
scp wazuh-manager/opencanary_rules.xml <user>@<wazuh-ip>:/tmp/
```

On the Wazuh VM:

```bash
sudo install -o wazuh -g wazuh -m 0660 /tmp/opencanary_rules.xml /var/ossec/etc/rules/ && sudo systemctl restart wazuh-manager
```

Test the rules before generating traffic: run `sudo /var/ossec/bin/wazuh-logtest` and paste a line from `wazuh-manager/sample-events.jsonl`. The SSH sample should match rule **100512**, level 10, MITRE T1110.

### 4. Attack it

From the Mac:

```bash
python3 attack-sim/simulate_attacks.py <canary-ip>
```

Then in the Wazuh dashboard: **Threat Hunting** → filter `rule.groups: opencanary`. For a deeper run, use real tools from the Mac or a Kali VM: `nmap -sV <canary-ip>`, `hydra -l root -P rockyou.txt ssh://<canary-ip>`.

### 5. Open the attack dashboard

On the Wazuh VM (copy `dashboard/` over first; it needs only Python 3, no packages, no internet):

The indexer's CA certificate lives in a root-only folder, so copy it next to the dashboard once:

```bash
sudo install -m 0644 /etc/wazuh-indexer/certs/root-ca.pem ~/dashboard/root-ca.pem
```

```bash
INDEXER_PASS='<indexer admin password>' python3 ~/dashboard/canary_dashboard.py --ca ~/dashboard/root-ca.pem
```

On the Mac, tunnel to it and open http://127.0.0.1:8088:

```bash
ssh -L 8088:127.0.0.1:8088 <user>@<wazuh-ip>
```

Preview it anywhere with generated data: `python3 dashboard/canary_dashboard.py --demo`.

The indexer admin password is in `wazuh-install-files.tar` (`wazuh-passwords.txt`) from the all-in-one install. A read-only indexer user is better than `admin`. Set it with `INDEXER_USER`.

## Detection rules

`wazuh-manager/opencanary_rules.xml`. OpenCanary writes one JSON object per line, so Wazuh's built-in JSON decoder handles it with no custom decoder. Every rule keys off `node_id` starting with `canary-` and the numeric `logtype` from OpenCanary's `logger.py`.

| Rule | Level | Trigger | MITRE ATT&CK |
|---|---|---|---|
| 100501 | 3 | Honeypot started (logtype 1000) | — |
| 100510 | 10 | FTP login attempt (2000) | T1110 |
| 100511 | 10 | HTTP login POST (3001) | T1110 |
| 100512 | 10 | SSH login attempt (4002) | T1110, T1021.004 |
| 100513 | 10 | Telnet login attempt (6001) | T1110 |
| 100514 | 10 | MySQL login attempt (8001) | T1110 |
| 100515 | 10 | VNC authentication attempt (12001) | T1110, T1021.005 |
| 100520 | 6 | HTTP request (3000) | T1595 |
| 100521 | 6 | SSH connection / version exchange (4000, 4001) | T1021.004 |
| 100522 | 8 | RDP connection (14001) | T1021.001 |
| 100523 | 8 | Redis command (17001) | T1190 |
| 100524 | 8 | Git clone request (16001) | T1213 |
| 100529 | 6 | Any other decoy activity | — |
| **100540** | **12** | **Brute force:** 5+ login attempts from one source in 2 min | T1110.001 |
| **100541** | **12** | **Service sweep:** one source touches 3+ decoy ports in 2 min | T1046 |

Why the levels are high: nothing legitimate ever talks to a canary. One touch is already a lead, unlike a real SSH server where failed logins are noise.

## Dashboard

`dashboard/canary_dashboard.py` + `index.html`: a single-file Python server that queries `wazuh-alerts-*` on the indexer and serves:

- KPIs: decoy hits, unique source hosts, credential attempts, correlated attacks
- hits over time (1 h / 24 h / 7 d)
- decoy services targeted and top source hosts
- usernames and passwords attackers tried
- latest alerts with severity, credentials and MITRE technique

Binds to `127.0.0.1` by default, so it is only reachable through the SSH tunnel. It refreshes every 15 seconds.

## Results

First live run, 16 October 2026: `simulate_attacks.py` from the Mac (192.168.64.1) against canary-01 (192.168.64.6).

| Check | Result |
|---|---|
| canary-01 enrolled in Wazuh 4.14.8 | ✅ Active |
| Alerts in Threat Hunting (`rule.groups: opencanary`) | ✅ 32 alerts within seconds of the run |
| Per-service rules | ✅ SSH (100512, 100521), FTP (100510), HTTP (100511, 100520), Redis (100523) |
| Brute-force correlation (100540, level 12) | ✅ Fired twice (SSH and FTP rounds) |
| Service-sweep correlation (100541, level 12) | ✅ Fired |
| Attacker attribution | ✅ Every alert names 192.168.64.1, with the usernames and passwords tried |
| Attack dashboard (24 h) | ✅ 32 decoy hits · 1 source host · 12 credential attempts · 5 correlated attacks. Services: SSH 18, FTP 6, Redis 3, HTTP 3, Telnet 1, Git 1 |

**canary-01 enrolled next to the macOS endpoint**

![Wazuh agents list with canary-01 active](images/agents.png)

**Threat Hunting: 32 OpenCanary alerts from one run, including the service-sweep correlation**

![Threat Hunting results for rule.groups: opencanary](images/threat-hunting.webp)

**Brute-force correlation (rule 100540, level 12)**

![Two brute-force alerts from 192.168.64.1](images/brute-force.webp)

**Wazuh overview and MITRE ATT&CK views after the run.** The honeypot adds Brute Force, Password Guessing, Network Service Discovery, Exploit Public-Facing Application and Active Scanning to the technique mix.

![Wazuh overview with canary-01 in the top agents](images/wazuh-overview.png)

![MITRE ATT&CK dashboard with canary-01 techniques](images/mitre-attack.png)

**Canary Attack Dashboard**

![Canary Attack Dashboard: KPIs, timeline, services, sources, credentials](images/dashboard.png)

![Latest alerts table with severity, credentials and MITRE technique](images/dashboard-alerts.webp)

## Lessons learned

- **Check what already owns the ports.** The Wazuh manager would not start: `wazuh-authd` failed with `Unable to Bind port '1515'`. A Docker Wazuh stack from an earlier lab (`ai-soc-lab`) was starting at boot and holding 1514, 1515, 443 and 9200. `ss -ltnp` showed `docker-proxy` as the owner. The fix was to stop those containers and set `--restart=no`, so only one SIEM owns the ports.
- **Two SIEMs means two sets of credentials.** The dashboard rejected the saved admin password because it belonged to the Docker stack. Testing it against the indexer directly (`curl -u admin:… https://127.0.0.1:9200` → `401`) separated "wrong password" from "service down".
- **Changing the admin password has a second step.** Filebeat ships alerts to the indexer with the admin password. After `wazuh-passwords-tool.sh`, the Filebeat keystore must be updated too, or alerts stop reaching the dashboard without any visible error.
- **Newer Python is stricter about certificates.** Python 3.13+ rejects Wazuh's self-generated root CA ("CA cert does not include key usage extension"). The dashboard clears only that strict flag and still verifies the chain against the Wazuh CA, rather than turning verification off.
- **Validate rules before restarting.** `wazuh-analysisd -t` returned 0, which ruled out the new rules file as the cause of the outage.
- **Decoys move the real services.** After setup, port 22 on the canary is the honeypot, and administration happens on 2222, restricted to the Mac.

## Repository layout

```
canary-vm/
  setup.sh                 builds the canary VM end to end
  opencanary.conf          decoy services and JSON file logging
  docker-compose.yml       OpenCanary 0.9.10, host network
wazuh-manager/
  opencanary_rules.xml     rules 100500-100549
  sample-events.jsonl      real-format events for wazuh-logtest
dashboard/
  canary_dashboard.py      indexer query + web server (stdlib only)
  index.html               the dashboard page
attack-sim/
  simulate_attacks.py      safe traffic generator for your own canary
```

## Safety

- **Do not port-forward the canary to the internet** from a home router. This lab is an *internal* tripwire: it detects movement inside your network. An internet-facing honeypot needs its own isolated network segment.
- Run `simulate_attacks.py` only against your own canary VM.
- The canary's real SSH is limited to the Mac's IP. If that IP changes, update UFW from the UTM console: `sudo ufw allow from <new-ip> to any port 2222 proto tcp`.

## Next steps

- [ ] Wazuh active response: block the source on other agents when 100540 fires (needs `srcip`; add a decoder that maps `src_host`)
- [ ] Enable the OpenCanary port-scan module (iptables logging) for SYN / NMAP OS-fingerprint detection
- [ ] Add an SMB file-share decoy with Samba audit logging
- [ ] Import the dashboard into the Wazuh dashboard as saved objects
- [ ] Integrate alerts at level 12 with Slack or email

---

*Part of the TrifoldPathSec lab series. Lab-only.*
