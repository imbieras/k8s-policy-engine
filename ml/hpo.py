#!/usr/bin/env python3
"""Optuna HPO for both XGBoost and LightGBM."""
import argparse
import json
from pathlib import Path

import numpy as np
import optuna
import xgboost as xgb
import lightgbm as lgb
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import roc_auc_score
from imblearn.over_sampling import SMOTE

from train_xgb import FEATURE_COLS, load

optuna.logging.set_verbosity(optuna.logging.WARNING)


def objective_xgb(trial, X, y, groups):
    params = {
        "objective": "binary:logistic",
        "tree_method": "hist",
        "device": "cpu",
        "eta": trial.suggest_float("eta", 0.01, 0.3, log=True),
        "max_depth": trial.suggest_int("max_depth", 3, 12),
        "min_child_weight": trial.suggest_int("min_child_weight", 1, 50),
        "subsample": trial.suggest_float("subsample", 0.6, 1.0),
        "colsample_bytree": trial.suggest_float("colsample_bytree", 0.5, 1.0),
        "reg_alpha": trial.suggest_float("reg_alpha", 1e-3, 10, log=True),
        "reg_lambda": trial.suggest_float("reg_lambda", 1e-3, 10, log=True),
        "eval_metric": "aucpr",
        "seed": 42,
    }
    splitter = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=42)
    aucs = []
    for tr, val in splitter.split(X, y, groups):
        X_tr, y_tr = SMOTE(random_state=42).fit_resample(X[tr], y[tr])
        model = xgb.XGBClassifier(**params, n_estimators=200, early_stopping_rounds=20, verbosity=0)
        model.fit(X_tr, y_tr, eval_set=[(X[val], y[val])], verbose=False)
        aucs.append(roc_auc_score(y[val], model.predict_proba(X[val])[:, 1]))
    return np.mean(aucs)


def objective_lgbm(trial, X, y, groups):
    params = {
        "objective": "binary",
        "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.3, log=True),
        "num_leaves": trial.suggest_int("num_leaves", 15, 255),
        "min_data_in_leaf": trial.suggest_int("min_data_in_leaf", 10, 200),
        "feature_fraction": trial.suggest_float("feature_fraction", 0.5, 1.0),
        "bagging_fraction": trial.suggest_float("bagging_fraction", 0.6, 1.0),
        "bagging_freq": 5,
        "reg_alpha": trial.suggest_float("reg_alpha", 1e-3, 10, log=True),
        "reg_lambda": trial.suggest_float("reg_lambda", 1e-3, 10, log=True),
        "verbosity": -1, "seed": 42,
    }
    splitter = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=42)
    aucs = []
    for tr, val in splitter.split(X, y, groups):
        X_tr, y_tr = SMOTE(random_state=42).fit_resample(X[tr], y[tr])
        dtrain = lgb.Dataset(X_tr, label=y_tr)
        dval   = lgb.Dataset(X[val], label=y[val], reference=dtrain)
        cb = [lgb.early_stopping(20, verbose=False), lgb.log_evaluation(-1)]
        m = lgb.train(params, dtrain, num_boost_round=200, valid_sets=[dval], callbacks=cb)
        aucs.append(roc_auc_score(y[val], m.predict(X[val])))
    return np.mean(aucs)


def run(parquet: str, model: str, n_trials: int, output_dir: str) -> dict:
    df = load(parquet)
    X = df[FEATURE_COLS].values.astype(np.float32)
    y = df["y"].values
    groups = df["session_id"].values

    obj = objective_xgb if model == "xgb" else objective_lgbm
    study = optuna.create_study(
        direction="maximize",
        sampler=optuna.samplers.TPESampler(seed=42),
        pruner=optuna.pruners.MedianPruner(n_warmup_steps=10),
    )
    study.optimize(lambda t: obj(t, X, y, groups), n_trials=n_trials, show_progress_bar=True)

    best_params = study.best_params
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    params_path = out / f"hpo_{model}_params.json"
    with open(params_path, "w") as f:
        json.dump(best_params, f, indent=2)

    print(f"Best {model} PR-AUC: {study.best_value:.4f}")
    print(f"Best params saved → {params_path}")
    return best_params


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--input",    default="data/train.parquet")
    p.add_argument("--model",    choices=["xgb", "lgbm"], default="xgb")
    p.add_argument("--n-trials", type=int, default=100)
    p.add_argument("--output",   default="data/models")
    args = p.parse_args()
    run(args.input, args.model, args.n_trials, args.output)
