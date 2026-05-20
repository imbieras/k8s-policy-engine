#!/usr/bin/env python3
"""
Traffic generator for k8s-policy-engine anomaly detection dataset.

Usage:
    python generate_traffic.py \
        --base-url http://localhost:8080 \
        --jwt-secret dev-secret-change-in-prod \
        --output-dir ./data/raw \
        --duration 1800  # seconds

Writes:
    data/raw/labels.jsonl  - event_id → label sidecar
    (The server writes audit.jsonl separately; copy it to data/raw/ after the run.)
"""

import argparse
import json
import random
import threading
import time
import uuid
from pathlib import Path

import jwt
import requests
from faker import Faker

fake = Faker()

def make_token(sub: str, secret: str, ttl: int = 86400) -> str:
    return jwt.encode(
        {"sub": sub, "exp": int(time.time()) + ttl, "iat": int(time.time())},
        secret,
        algorithm="HS256",
    )


def post(base: str, path: str, token: str, body: dict,
         source_ip: str = "78.57.100.1", label_sink=None, label: str = "benign") -> dict:
    event_id = str(uuid.uuid4())
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Request-ID": event_id,
        "X-Forwarded-For": source_ip,
        "Content-Type": "application/json",
    }
    try:
        r = requests.post(f"{base}{path}", json=body, headers=headers, timeout=5)
        code = r.status_code
        resp = r.json() if r.content else {}
    except Exception:
        code, resp = 0, {}

    if label_sink is not None:
        label_sink.write(json.dumps({"event_id": event_id, "label": label}) + "\n")
        label_sink.flush()
    return resp


def get(base: str, path: str, token: str, source_ip: str = "78.57.100.1",
        label_sink=None, label: str = "benign") -> dict:
    event_id = str(uuid.uuid4())
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Request-ID": event_id,
        "X-Forwarded-For": source_ip,
    }
    try:
        r = requests.get(f"{base}{path}", headers=headers, timeout=5)
        resp = r.json() if r.content else {}
    except Exception:
        resp = {}

    if label_sink is not None:
        label_sink.write(json.dumps({"event_id": event_id, "label": label}) + "\n")
        label_sink.flush()
    return resp


def scenario_benign(base: str, secret: str, sink, stop: threading.Event):
    """Normal developer: create requests, list them, occasional re-checks."""
    users = [f"dev-{i}@example.com" for i in range(5)]
    tokens = {u: make_token(u, secret) for u in users}
    home_ips = [f"78.57.{random.randint(1,254)}.{random.randint(1,254)}" for _ in users]

    while not stop.is_set():
        user = random.choice(users)
        idx = users.index(user)
        token, ip = tokens[user], home_ips[idx]

        resp = post(base, "/request", token,
                    {"user": user, "role": "viewer", "reason": "routine", "duration": "2h"},
                    source_ip=ip, label_sink=sink, label="benign")
        req_id = resp.get("id")

        # Simulate approver
        if req_id:
            time.sleep(random.uniform(0.5, 2.0))
            post(base, f"/approve/{req_id}", make_token("approver@example.com", secret),
                 {}, source_ip=ip, label_sink=sink, label="benign")

        get(base, "/requests", token, source_ip=ip, label_sink=sink, label="benign")
        time.sleep(random.lognormvariate(1.5, 0.8))  # realistic inter-arrival


def scenario_bruteforce(base: str, secret: str, sink, stop: threading.Event,
                        burst_sleep_max: int | None = None):
    """Rapid invalid JWT attempts then one valid request."""
    bad_token = "invalid.token.value"
    ip = f"45.33.{random.randint(1,254)}.{random.randint(1,254)}"
    while not stop.is_set():
        for _ in range(random.randint(30, 80)):
            if stop.is_set():
                return
            post(base, "/requests", bad_token, {}, source_ip=ip,
                 label_sink=sink, label="bruteforce")
            time.sleep(random.uniform(0.02, 0.1))
        # one valid request after burst
        valid = make_token("bruteforcer@example.com", secret)
        get(base, "/requests", valid, source_ip=ip, label_sink=sink, label="bruteforce")
        time.sleep(random.uniform(2, burst_sleep_max if burst_sleep_max is not None else 180))


def scenario_geo_ip(base: str, secret: str, sink, stop: threading.Event,
                    burst_sleep_max: int | None = None):
    """User starts with LT IP, switches mid-session to foreign IP."""
    user = "geo-user@example.com"
    token = make_token(user, secret)
    lt_ip = "78.57.44.100"
    foreign_ip = f"103.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

    while not stop.is_set():
        resp = post(base, "/request", token,
                    {"user": user, "role": "viewer", "reason": "geo-test", "duration": "1h"},
                    source_ip=lt_ip, label_sink=sink, label="benign")
        req_id = resp.get("id")
        if req_id:
            post(base, f"/approve/{req_id}", make_token("approver@example.com", secret),
                 {}, source_ip=lt_ip, label_sink=sink, label="benign")

        # switch to foreign IP
        for _ in range(random.randint(5, 15)):
            if stop.is_set():
                return
            get(base, "/requests", token, source_ip=foreign_ip,
                label_sink=sink, label="geo_ip")
            time.sleep(random.uniform(1, 4))
        time.sleep(random.uniform(2, burst_sleep_max if burst_sleep_max is not None else 90))


def scenario_role_mismatch(base: str, secret: str, sink, stop: threading.Event,
                           burst_sleep_max: int | None = None):
    """User approved for viewer repeatedly requests admin."""
    user = "mismatch-user@example.com"
    token = make_token(user, secret)
    ip = "78.57.55.200"

    while not stop.is_set():
        # legitimate viewer request
        resp = post(base, "/request", token,
                    {"user": user, "role": "viewer", "reason": "legit", "duration": "2h"},
                    source_ip=ip, label_sink=sink, label="benign")
        req_id = resp.get("id")
        if req_id:
            post(base, f"/approve/{req_id}", make_token("approver@example.com", secret),
                 {}, source_ip=ip, label_sink=sink, label="benign")

        # role mismatch attempts
        for role in ["admin", "cluster-admin", "admin", "edit"]:
            if stop.is_set():
                return
            post(base, "/request", token,
                 {"user": user, "role": role, "reason": "escalation", "duration": "1h"},
                 source_ip=ip, label_sink=sink, label="role_mismatch")
            time.sleep(random.uniform(0.5, 2))
        time.sleep(random.uniform(2, burst_sleep_max if burst_sleep_max is not None else 60))


def scenario_breakglass_abuse(base: str, secret: str, sink, stop: threading.Event,
                              burst_sleep_max: int | None = None):
    """Legitimate admin session followed by mass listing."""
    user = "breakglass-user@example.com"
    token = make_token(user, secret)
    approver = make_token("approver@example.com", secret)
    ip = "78.57.66.150"

    while not stop.is_set():
        resp = post(base, "/request", token,
                    {"user": user, "role": "admin", "reason": "emergency", "duration": "4h"},
                    source_ip=ip, label_sink=sink, label="benign")
        req_id = resp.get("id")
        if req_id:
            post(base, f"/approve/{req_id}", approver, {}, source_ip=ip,
                 label_sink=sink, label="benign")

        # mass listing - break-glass abuse
        for _ in range(random.randint(40, 80)):
            if stop.is_set():
                return
            get(base, "/requests", token, source_ip=ip,
                label_sink=sink, label="breakglass_abuse")
            time.sleep(random.uniform(0.1, 0.5))
        time.sleep(random.uniform(2, burst_sleep_max if burst_sleep_max is not None else 180))


def scenario_multi_ip(base: str, secret: str, sink, stop: threading.Event):
    """Same JWT used concurrently from two different IPs."""
    user = "multi-ip-user@example.com"
    token = make_token(user, secret)
    ip1 = "78.57.77.10"
    ip2 = "91.200.12.45"

    def worker(ip: str):
        while not stop.is_set():
            get(base, "/requests", token, source_ip=ip,
                label_sink=sink, label="multi_ip")
            time.sleep(random.uniform(1, 5))

    t1 = threading.Thread(target=worker, args=(ip1,), daemon=True)
    t2 = threading.Thread(target=worker, args=(ip2,), daemon=True)
    t1.start(); t2.start()
    stop.wait()


def _burst_sleep_type(value: str) -> int:
    i = int(value)
    if i < 2:
        raise argparse.ArgumentTypeError(f"--burst-sleep-max must be >= 2, got {i}")
    return i


SCENARIOS = {
    "benign": scenario_benign,
    "bruteforce": scenario_bruteforce,
    "geo_ip": scenario_geo_ip,
    "role_mismatch": scenario_role_mismatch,
    "breakglass_abuse": scenario_breakglass_abuse,
    "multi_ip": scenario_multi_ip,
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://localhost:8080")
    parser.add_argument("--jwt-secret", default="dev-secret-change-in-prod")
    parser.add_argument("--output-dir", default="data/raw")
    parser.add_argument("--duration", type=int, default=1800, help="seconds")
    parser.add_argument("--scenarios", nargs="+", default=list(SCENARIOS.keys()))
    parser.add_argument("--burst-sleep-max", type=_burst_sleep_type, default=None,
                        help="Cap inter-cycle sleep to this value (seconds, >= 2). "
                             "Only applies to attack scenarios. Default uses original values.")
    args = parser.parse_args()

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    stop = threading.Event()
    sink_path = out / "labels.jsonl"

    with open(sink_path, "w") as sink:
        threads = []
        for name in args.scenarios:
            fn = SCENARIOS[name]
            bsm = args.burst_sleep_max
            # benign and multi_ip don't accept burst_sleep_max
            if name in ("benign", "multi_ip"):
                t = threading.Thread(target=fn,
                                     args=(args.base_url, args.jwt_secret, sink, stop),
                                     daemon=True)
            else:
                t = threading.Thread(target=fn,
                                     args=(args.base_url, args.jwt_secret, sink, stop, bsm),
                                     daemon=True)
            t.start()
            threads.append(t)
            print(f"Started scenario: {name}")

        print(f"Running for {args.duration}s. Ctrl-C to stop early.")
        try:
            time.sleep(args.duration)
        except KeyboardInterrupt:
            pass
        finally:
            stop.set()
            for t in threads:
                t.join(timeout=5)

    print(f"Labels written to {sink_path}")
    print("Copy the server's audit.jsonl to data/raw/audit.jsonl, then run data/join.py")


if __name__ == "__main__":
    main()
