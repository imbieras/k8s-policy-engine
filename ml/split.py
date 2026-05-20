#!/usr/bin/env python3
"""Session-grouped stratified ~70/30 train/test split.

Run once before HPO:
    python split.py --input data/features.parquet \
                    --train data/train.parquet \
                    --test  data/test.parquet
"""
import argparse
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

from train_xgb import FEATURE_COLS

RANDOM_STATE = 42


def split(input_parquet: str, train_parquet: str, test_parquet: str):
    df = pd.read_parquet(input_parquet)
    df["y"] = (df["label"] != "benign").astype(int)
    df = df.dropna(subset=FEATURE_COLS)

    # n_splits=3 → test fold ≈ 33% of events, balanced anomaly rate in both splits
    sgkf = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=RANDOM_STATE)
    train_idx, test_idx = next(sgkf.split(df, df["y"], df["session_id"]))

    train_df = df.iloc[train_idx].reset_index(drop=True)
    test_df  = df.iloc[test_idx].reset_index(drop=True)

    train_df.to_parquet(train_parquet, index=False)
    test_df.to_parquet(test_parquet, index=False)

    print(f"Train: {len(train_df)} events, {train_df['y'].mean()*100:.1f}% anomaly")
    print(f"Test:  {len(test_df)} events,  {test_df['y'].mean()*100:.1f}% anomaly")
    print(f"Saved → {train_parquet}, {test_parquet}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--input", default="data/features.parquet")
    p.add_argument("--train", default="data/train.parquet")
    p.add_argument("--test",  default="data/test.parquet")
    args = p.parse_args()
    split(args.input, args.train, args.test)
