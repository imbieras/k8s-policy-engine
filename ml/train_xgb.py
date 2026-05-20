#!/usr/bin/env python3
"""Train XGBoost on the full train pool using best HPO params."""
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb
from imblearn.over_sampling import SMOTE

LABEL_MAP = {"benign": 0, "bruteforce": 1, "geo_ip": 2,
             "role_mismatch": 3, "breakglass_abuse": 4, "multi_ip": 5}

FEATURE_COLS = [
    "country_hash", "asn", "endpoint_hash", "endpoint_lag1_hash",
    "endpoint_lag2_hash", "role_hash", "role_lag1_hash", "delta_ts_t1_s",
    "is_high_privilege_role", "session_age_s", "session_total_actions",
    "unique_endpoints", "req_count_1m", "failed_req_count_1m",
    "req_count_5m", "reads_5m", "writes_5m", "read_write_ratio_5m",
    "interarrival_avg_5m", "req_count_15m", "role_mismatch_count_5m",
    "simultaneous_ip_count", "mass_request_score", "unique_roles_requested_5m",
    "hour_sin", "hour_cos", "is_weekend", "is_outside_hours",
]


def load(parquet: str) -> pd.DataFrame:
    df = pd.read_parquet(parquet)
    df["y"] = (df["label"] != "benign").astype(int)
    return df.dropna(subset=FEATURE_COLS)


def train(parquet: str, params_path: str | None, output_dir: str) -> xgb.XGBClassifier:
    df = load(parquet)
    X = df[FEATURE_COLS].values.astype(np.float32)
    y = df["y"].values

    hpo_params: dict = {}
    if params_path and Path(params_path).exists():
        with open(params_path) as f:
            hpo_params = json.load(f)
        print(f"Loaded HPO params from {params_path}")
    else:
        print("No HPO params found - using defaults")

    X_res, y_res = SMOTE(random_state=42).fit_resample(X, y)
    print(f"After SMOTE: {len(X_res)} samples ({y_res.mean()*100:.1f}% anomaly)")

    base_params = {
        "objective": "binary:logistic",
        "tree_method": "hist",
        "device": "cpu",
        "eval_metric": "logloss",
        "seed": 42,
    }
    p = {**base_params, **hpo_params}

    model = xgb.XGBClassifier(**p, n_estimators=500)
    model.fit(X_res, y_res, eval_set=[(X_res, y_res)], verbose=100)

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    model.get_booster().save_model(str(out / "xgb_model.json"))

    loss_curve = model.evals_result()["validation_0"]["logloss"]
    with open(out / "xgb_loss_curve.json", "w") as f:
        json.dump({"logloss": loss_curve}, f)

    print(f"Saved model      → {out}/xgb_model.json")
    print(f"Saved loss curve → {out}/xgb_loss_curve.json")
    return model


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--input",  default="data/train.parquet")
    p.add_argument("--params", default="data/models/hpo_xgb_params.json")
    p.add_argument("--output", default="data/models")
    args = p.parse_args()
    train(args.input, args.params, args.output)
