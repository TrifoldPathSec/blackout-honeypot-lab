#!/usr/bin/env python3
"""Honeypot attack dashboard for OpenCanary alerts stored in the Wazuh indexer.

Standard library only, no internet needed: run it on the Wazuh server VM and
reach it through an SSH tunnel from your Mac.

  # on the Wazuh VM
  INDEXER_PASS='...' python3 canary_dashboard.py
  # on the Mac
  ssh -L 8088:127.0.0.1:8088 <user>@<wazuh-vm-ip>   then open http://127.0.0.1:8088

  # preview with generated data, anywhere
  python3 canary_dashboard.py --demo

Author: @alex_mh
"""
import argparse
import base64
import datetime as dt
import json
import os
import random
import ssl
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent
RANGES = {"1h": ("now-1h", "2m", 3600), "24h": ("now-24h", "1h", 86400), "7d": ("now-7d", "6h", 604800)}
GROUPS = ["opencanary_hit", "opencanary_correlation"]


# ---------------------------------------------------------------- indexer

class Indexer:
    def __init__(self, url, user, password, ca, insecure):
        self.url = url.rstrip("/")
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.headers = {"Authorization": f"Basic {token}", "Content-Type": "application/json"}
        if insecure:
            self.ctx = ssl._create_unverified_context()
        elif ca and Path(ca).exists():
            # Lab certs are issued to the node IP, so verify the chain but not the hostname.
            self.ctx = ssl.create_default_context(cafile=ca)
            self.ctx.check_hostname = False
            # Python 3.13+ enables strict X.509 checks; Wazuh's generated root CA has no
            # keyUsage extension and fails them. The chain is still verified against this CA.
            self.ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
        else:
            self.ctx = ssl.create_default_context()

    def search(self, body):
        req = urllib.request.Request(
            f"{self.url}/wazuh-alerts-*/_search", data=json.dumps(body).encode(),
            headers=self.headers, method="POST")
        with urllib.request.urlopen(req, context=self.ctx, timeout=15) as r:
            return json.load(r)

    def summary(self, rng):
        since, interval, _ = RANGES[rng]
        body = {
            "size": 60,
            "sort": [{"timestamp": "desc"}],
            "_source": ["timestamp", "rule.id", "rule.level", "rule.description",
                        "rule.mitre.id", "data.src_host", "data.dst_port",
                        "data.logdata.USERNAME", "data.logdata.PASSWORD", "agent.name"],
            "query": {"bool": {"filter": [
                {"terms": {"rule.groups": GROUPS}},
                {"range": {"timestamp": {"gte": since}}},
            ]}},
            "aggs": {
                "timeline": {"date_histogram": {
                    "field": "timestamp", "fixed_interval": interval, "min_doc_count": 0,
                    "extended_bounds": {"min": since, "max": "now"}}},
                "sources": {"terms": {"field": "data.src_host", "size": 8}},
                "uniq": {"cardinality": {"field": "data.src_host"}},
                "ports": {"terms": {"field": "data.dst_port", "size": 12}},
                "users": {"terms": {"field": "data.logdata.USERNAME", "size": 8}},
                "passwords": {"terms": {"field": "data.logdata.PASSWORD", "size": 8}},
                "auth": {"filter": {"term": {"rule.groups": "opencanary_auth"}}},
                "corr": {"filter": {"term": {"rule.groups": "opencanary_correlation"}}},
            },
        }
        res = self.search(body)
        a = res["aggregations"]
        buckets = lambda name: [{"k": str(b["key"]), "n": b["doc_count"]} for b in a[name]["buckets"]]
        feed = []
        for h in res["hits"]["hits"]:
            s = h["_source"]
            d, r, ld = s.get("data", {}), s.get("rule", {}), s.get("data", {}).get("logdata", {})
            feed.append({
                "ts": s.get("timestamp"), "level": int(r.get("level", 0)), "rule": r.get("id"),
                "desc": r.get("description", ""), "src": d.get("src_host", ""),
                "port": str(d.get("dst_port", "")), "user": ld.get("USERNAME", ""),
                "pass": ld.get("PASSWORD", ""), "mitre": r.get("mitre", {}).get("id", []),
                "node": s.get("agent", {}).get("name", ""),
            })
        return {
            "demo": False, "range": rng, "interval": interval,
            "kpis": {"events": res["hits"]["total"]["value"], "sources": a["uniq"]["value"],
                     "auth": a["auth"]["doc_count"], "corr": a["corr"]["doc_count"]},
            "timeline": [{"t": b["key_as_string"] if "key_as_string" in b else b["key"], "n": b["doc_count"]}
                         for b in a["timeline"]["buckets"]],
            "sources": buckets("sources"), "ports": buckets("ports"),
            "users": buckets("users"), "passwords": buckets("passwords"), "feed": feed,
        }


# ---------------------------------------------------------------- demo data

DEMO_SRC = ["10.0.0.15", "10.0.0.15", "10.0.0.15", "10.0.0.22", "10.0.0.22", "10.0.0.41", "10.0.0.8", "10.0.0.63"]
DEMO_USERS = ["root", "admin", "root", "ubuntu", "pi", "oracle", "admin", "test", "postgres", "user"]
DEMO_PASS = ["123456", "password", "admin", "root", "Winter2026!", "qwerty", "toor", "letmein", "P@ssw0rd"]
DEMO_EVENTS = [  # (rule, level, port, auth, desc, mitre)
    ("100512", 10, "22", True, "OpenCanary: SSH login attempt from {s} as '{u}'", ["T1110", "T1021.004"]),
    ("100512", 10, "22", True, "OpenCanary: SSH login attempt from {s} as '{u}'", ["T1110", "T1021.004"]),
    ("100521", 6, "22", False, "OpenCanary: SSH connection from {s}", ["T1021.004"]),
    ("100511", 10, "80", True, "OpenCanary: HTTP login attempt from {s} as '{u}'", ["T1110"]),
    ("100520", 6, "80", False, "OpenCanary: HTTP request from {s} for /index.html", ["T1595"]),
    ("100510", 10, "21", True, "OpenCanary: FTP login attempt from {s} as '{u}'", ["T1110"]),
    ("100513", 10, "23", True, "OpenCanary: Telnet login attempt from {s} as '{u}'", ["T1110"]),
    ("100514", 10, "3306", True, "OpenCanary: MySQL login attempt from {s} as '{u}'", ["T1110"]),
    ("100522", 8, "3389", False, "OpenCanary: RDP connection from {s} as '{u}'", ["T1021.001"]),
    ("100523", 8, "6379", False, "OpenCanary: Redis command 'INFO' from {s}", ["T1190"]),
    ("100515", 10, "5900", True, "OpenCanary: VNC authentication attempt from {s}", ["T1110", "T1021.005"]),
]


def demo_summary(rng):
    since, interval, span = RANGES[rng]
    rnd = random.Random(rng + dt.datetime.now().strftime("%Y%m%d%H%M"))
    now = dt.datetime.now(dt.timezone.utc)
    step = {"2m": 120, "1h": 3600, "6h": 21600}[interval]
    nb = span // step
    events = []
    # A quiet baseline plus two bursts, the way a real sweep-then-brute-force looks.
    for _ in range(int(span / 600) + 40):
        events.append(now - dt.timedelta(seconds=rnd.uniform(0, span)))
    for centre in (0.35, 0.8):
        c = span * centre
        for _ in range(rnd.randint(60, 120)):
            events.append(now - dt.timedelta(seconds=max(0, rnd.gauss(c, span * 0.02))))
    events.sort(reverse=True)

    timeline = [0] * nb
    feed, src_c, port_c, user_c, pass_c = [], {}, {}, {}, {}
    auth = corr = 0
    for i, t in enumerate(events):
        idx = nb - 1 - int((now - t).total_seconds() // step)
        if 0 <= idx < nb:
            timeline[idx] += 1
        rule, lvl, port, is_auth, desc, mitre = rnd.choice(DEMO_EVENTS)
        s, u, p = rnd.choice(DEMO_SRC), rnd.choice(DEMO_USERS), rnd.choice(DEMO_PASS)
        src_c[s] = src_c.get(s, 0) + 1
        port_c[port] = port_c.get(port, 0) + 1
        if is_auth:
            auth += 1
            user_c[u] = user_c.get(u, 0) + 1
            pass_c[p] = pass_c.get(p, 0) + 1
        if i < 60:
            if i in (3, 17):
                corr += 1
                feed.append({"ts": t.isoformat(), "level": 12, "rule": "100540",
                             "desc": f"OpenCanary: brute force - 5+ login attempts from {s} in 2 minutes",
                             "src": s, "port": port, "user": "", "pass": "", "mitre": ["T1110.001"], "node": "canary-01"})
                continue
            if i == 9:
                corr += 1
                feed.append({"ts": t.isoformat(), "level": 12, "rule": "100541",
                             "desc": f"OpenCanary: service sweep - {s} touched 3+ decoy services in 2 minutes",
                             "src": s, "port": port, "user": "", "pass": "", "mitre": ["T1046"], "node": "canary-01"})
                continue
            feed.append({"ts": t.isoformat(), "level": lvl, "rule": rule, "desc": desc.format(s=s, u=u),
                         "src": s, "port": port, "user": u if is_auth else "", "pass": p if is_auth else "",
                         "mitre": mitre, "node": "canary-01"})
    top = lambda c, n: [{"k": k, "n": v} for k, v in sorted(c.items(), key=lambda kv: -kv[1])[:n]]
    start = now - dt.timedelta(seconds=step * nb)
    return {
        "demo": True, "range": rng, "interval": interval,
        "kpis": {"events": len(events), "sources": len(src_c), "auth": auth, "corr": corr},
        "timeline": [{"t": (start + dt.timedelta(seconds=step * (i + 1))).isoformat(), "n": n}
                     for i, n in enumerate(timeline)],
        "sources": top(src_c, 8), "ports": top(port_c, 12),
        "users": top(user_c, 8), "passwords": top(pass_c, 8), "feed": feed,
    }


# ---------------------------------------------------------------- web

def make_handler(source):
    page = (HERE / "index.html").read_bytes()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            u = urlparse(self.path)
            if u.path == "/":
                return self.send(200, page, "text/html; charset=utf-8")
            if u.path == "/api/summary":
                rng = parse_qs(u.query).get("range", ["24h"])[0]
                rng = rng if rng in RANGES else "24h"
                try:
                    data = source(rng)
                    return self.send(200, json.dumps(data).encode(), "application/json")
                except urllib.error.HTTPError as e:
                    msg = f"Indexer returned HTTP {e.code}. Check INDEXER_USER / INDEXER_PASS."
                except Exception as e:  # noqa: BLE001 - surface any indexer problem in the UI
                    msg = f"Cannot reach the indexer: {e}"
                return self.send(502, json.dumps({"error": msg}).encode(), "application/json")
            self.send(404, b"not found", "text/plain")

    return Handler


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--demo", action="store_true", help="serve generated data instead of querying the indexer")
    ap.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1, use an SSH tunnel)")
    ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--indexer", default=os.environ.get("INDEXER_URL", "https://127.0.0.1:9200"))
    ap.add_argument("--ca", default=os.environ.get("INDEXER_CA", "/etc/wazuh-indexer/certs/root-ca.pem"))
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (lab only)")
    args = ap.parse_args()

    if args.demo:
        source = demo_summary
    else:
        pw = os.environ.get("INDEXER_PASS")
        if not pw:
            sys.exit("Set INDEXER_PASS (and INDEXER_USER if not 'admin'), or use --demo.")
        # The indexer's cert folder is root-only, so a normal user cannot read the CA there.
        ca_dir = Path(args.ca).parent
        if not args.insecure and os.path.isdir(ca_dir.parent) and not os.access(args.ca, os.R_OK):
            sys.exit(f"Cannot read {args.ca}. Copy it somewhere readable and pass --ca, e.g.:\n"
                     f"  sudo install -m 0644 {args.ca} ~/dashboard/root-ca.pem\n"
                     f"  python3 {sys.argv[0]} --ca ~/dashboard/root-ca.pem")
        source = Indexer(args.indexer, os.environ.get("INDEXER_USER", "admin"), pw,
                         args.ca, args.insecure).summary

    srv = ThreadingHTTPServer((args.host, args.port), make_handler(source))
    mode = "demo data" if args.demo else args.indexer
    print(f"Canary dashboard on http://{args.host}:{args.port}  ({mode})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
