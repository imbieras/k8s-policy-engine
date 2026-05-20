#!/usr/bin/env python3
"""Merge audit.jsonl (from server) with labels.jsonl (from generator)."""
import json
import sys
from pathlib import Path


def join(audit_path: str, labels_path: str, output_path: str):
    labels = {}
    with open(labels_path) as f:
        for line in f:
            row = json.loads(line)
            labels[row["event_id"]] = row["label"]

    with open(audit_path) as fin, open(output_path, "w") as fout:
        matched = unlabeled = 0
        for line in fin:
            rec = json.loads(line)
            eid = rec.get("event_id", "")
            rec["label"] = labels.get(eid, "benign")  # default benign for server-internal events
            if eid in labels:
                matched += 1
            else:
                unlabeled += 1
            fout.write(json.dumps(rec) + "\n")

    print(f"Joined: {matched} labeled, {unlabeled} unlabeled (defaulted benign)")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--audit",  default="data/raw/audit.jsonl")
    p.add_argument("--labels", default="data/raw/labels.jsonl")
    p.add_argument("--output", default="data/labeled_audit.jsonl")
    args = p.parse_args()
    join(args.audit, args.labels, args.output)
