#!/usr/bin/env python3
import argparse
import struct
from pathlib import Path
import duckdb


def _fnv32a(s: str) -> float:
    """FNV-32a hash matching Go's hash/fnv.New32a() → float32(int32(h.Sum32()))."""
    if s is None:
        s = ""
    h = 2166136261  # FNV offset basis
    for b in s.encode("utf-8"):
        h ^= b
        h = (h * 16777619) & 0xFFFFFFFF  # FNV prime, keep 32 bits
    # Reinterpret as signed int32, then widen to float64 - matches Go exactly.
    return float(struct.unpack("i", struct.pack("I", h))[0])


def materialise(input_jsonl: str, output_parquet: str):
    sql_template = (Path(__file__).parent / "materialise.sql").read_text()
    sql = sql_template.replace("{{ input }}", input_jsonl).replace("{{ output }}", output_parquet)
    con = duckdb.connect()
    con.create_function("fnv32a", _fnv32a, [duckdb.typing.VARCHAR], duckdb.typing.DOUBLE)
    con.execute(sql)
    con.close()
    print(f"Wrote {output_parquet}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--input",  default="data/labeled_audit.jsonl")
    p.add_argument("--output", default="data/features.parquet")
    args = p.parse_args()
    materialise(args.input, args.output)
