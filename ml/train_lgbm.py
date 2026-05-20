#!/usr/bin/env python3
"""Train LightGBM on the full train pool using best HPO params."""
import argparse
import json
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE

from train_xgb import FEATURE_COLS, load


def train(parquet: str, params_path: str | None, output_dir: str) -> lgb.Booster:
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
        "objective": "binary",
        "boosting_type": "gbdt",
        "metric": "binary_logloss",
        "verbosity": -1,
        "seed": 42,
    }
    p = {**base_params, **hpo_params}

    loss_curve: list[float] = []

    def record_loss(env):
        loss_curve.append(env.evaluation_result_list[0][2])

    dtrain = lgb.Dataset(X_res, label=y_res, feature_name=FEATURE_COLS)
    model = lgb.train(
        p,
        dtrain,
        num_boost_round=500,
        valid_sets=[dtrain],
        callbacks=[lgb.log_evaluation(100), record_loss],
    )

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    model.save_model(str(out / "lgbm_model.txt"))

    with open(out / "lgbm_loss_curve.json", "w") as f:
        json.dump({"logloss": loss_curve}, f)

    print(f"Saved model      → {out}/lgbm_model.txt")
    print(f"Saved loss curve → {out}/lgbm_loss_curve.json")
    return model


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--input",  default="data/train.parquet")
    p.add_argument("--params", default="data/models/hpo_lgbm_params.json")
    p.add_argument("--output", default="data/models")
    args = p.parse_args()
    train(args.input, args.params, args.output)
