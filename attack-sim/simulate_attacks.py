#!/usr/bin/env python3
"""Generate realistic attacker traffic against YOUR OWN canary VM to test the pipeline.

  python3 simulate_attacks.py <canary-ip>            # every scenario
  python3 simulate_attacks.py <canary-ip> --only ssh http

Each scenario should show up in Wazuh as the rule listed beside it. The SSH and
FTP rounds send 6 attempts so the brute-force correlation rule (100540) fires,
and touching several services trips the service-sweep rule (100541).
Standard library only; SSH uses the system ssh client.

Author: @alex_mh
"""
import argparse
import ftplib
import os
import socket
import stat
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

CREDS = [("root", "toor"), ("admin", "admin"), ("ubuntu", "ubuntu"),
         ("pi", "raspberry"), ("root", "123456"), ("oracle", "Winter2026!")]


def ssh(host):
    """Rule 100512 x6 -> 100540. Password auth via SSH_ASKPASS, no extra packages."""
    for user, pw in CREDS:
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
            f.write(f"#!/bin/sh\necho '{pw}'\n")
        os.chmod(f.name, stat.S_IRWXU)
        env = dict(os.environ, SSH_ASKPASS=f.name, SSH_ASKPASS_REQUIRE="force", DISPLAY=":0")
        subprocess.run(
            ["ssh", "-p", "22", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
             "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
             "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=5", f"{user}@{host}", "true"],
            env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
        os.unlink(f.name)
        print(f"  ssh   {user}/{pw}")


def ftp(host):
    """Rule 100510 x6 -> 100540."""
    for user, pw in CREDS:
        try:
            with ftplib.FTP(host, timeout=5) as f:
                f.login(user, pw)
        except ftplib.all_errors:
            pass
        print(f"  ftp   {user}/{pw}")


def http(host):
    """Rule 100520 (GET) and 100511 (login POST)."""
    urllib.request.urlopen(f"http://{host}/", timeout=5).read()
    print("  http  GET /")
    for user, pw in CREDS[:2]:
        data = urllib.parse.urlencode({"username": user, "password": pw}).encode()
        try:
            urllib.request.urlopen(f"http://{host}/index.html", data=data, timeout=5).read()
        except Exception:  # noqa: BLE001 - the decoy answers with an error page by design
            pass
        print(f"  http  POST login {user}/{pw}")


def telnet(host):
    """Rule 100513."""
    with socket.create_connection((host, 23), timeout=5) as s:
        for line in (b"admin\r\n", b"admin123\r\n"):
            time.sleep(1)
            s.recv(1024)
            s.sendall(line)
        time.sleep(1)
    print("  telnet admin/admin123")


def mysql(host):
    """Connection only: a real login needs a MySQL client (`mysql -h <ip> -u root -p`) for rule 100514."""
    with socket.create_connection((host, 3306), timeout=5) as s:
        s.recv(1024)
    print("  mysql banner grab (use a mysql client for a login attempt)")


def redis(host):
    """Rule 100523."""
    with socket.create_connection((host, 6379), timeout=5) as s:
        for cmd in (b"INFO\r\n", b"CONFIG GET dir\r\n", b"KEYS *\r\n"):
            s.sendall(cmd)
            time.sleep(0.5)
            s.recv(4096)
    print("  redis INFO, CONFIG GET dir, KEYS *")


def git(host):
    """Rule 100524."""
    req = b"git-upload-pack /secret-infra.git\0host=" + host.encode() + b"\0"
    with socket.create_connection((host, 9418), timeout=5) as s:
        s.sendall(f"{len(req) + 4:04x}".encode() + req)
        time.sleep(1)
    print("  git   clone /secret-infra.git")


SCENARIOS = {"ssh": ssh, "ftp": ftp, "http": http, "telnet": telnet,
             "mysql": mysql, "redis": redis, "git": git}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("target", help="IP of your canary VM")
    ap.add_argument("--only", nargs="+", choices=SCENARIOS, help="run only these scenarios")
    args = ap.parse_args()
    for name in args.only or SCENARIOS:
        print(f"[{name}]")
        try:
            SCENARIOS[name](args.target)
        except Exception as e:  # noqa: BLE001 - keep going so one closed port does not stop the run
            print(f"  skipped: {e}")
    print("\nDone. Check Wazuh: Threat Hunting -> filter rule.groups: opencanary")


if __name__ == "__main__":
    main()
