#!/usr/bin/env python3
"""Export XGBoost and LightGBM to ONNX, verify round-trip AUC."""
import argparse
import numpy as np
import onnx
import xgboost as xgb
import lightgbm as lgb
import onnxmltools
import onnxruntime as ort
from onnxmltools.convert.common.data_types import FloatTensorType
from onnxmltools.convert.xgboost.operator_converters.XGBoost import convert_xgboost   # noqa
from sklearn.metrics import roc_auc_score
from train_xgb import FEATURE_COLS, load

N_FEATURES = len(FEATURE_COLS)


def _strip_zipmap(model: onnx.ModelProto) -> onnx.ModelProto:
    """Remove ZipMap node so 'probabilities' output is a plain float32 tensor [N, 2].

    onnxmltools converts LightGBM to seq(map(int64, tensor(float))) which the Go
    onnxruntime_go AdvancedSession cannot consume. We redirect the float tensor
    that feeds ZipMap directly to the 'probabilities' output instead.
    """
    zipmap_input = None
    new_nodes = []
    for node in model.graph.node:
        if node.op_type == "ZipMap":
            zipmap_input = node.input[0]
        else:
            new_nodes.append(node)

    if zipmap_input is None:
        return model

    del model.graph.node[:]
    model.graph.node.extend(new_nodes)
    model.graph.node.append(
        onnx.helper.make_node("Identity", inputs=[zipmap_input], outputs=["probabilities"])
    )

    for out in model.graph.output:
        if out.name == "probabilities":
            out.type.CopyFrom(
                onnx.helper.make_tensor_type_proto(onnx.TensorProto.FLOAT, [None, 2])
            )
    return model


def export_xgb(model_path: str, output_path: str, X_val: np.ndarray, y_val: np.ndarray):
    model = xgb.XGBClassifier(); model.load_model(model_path)
    native_proba = model.predict_proba(X_val)[:, 1]
    native_auc = roc_auc_score(y_val, native_proba)

    onnx_model = onnxmltools.convert_xgboost(
        model, initial_types=[("input", FloatTensorType([None, N_FEATURES]))], target_opset=15
    )
    with open(output_path, "wb") as f:
        f.write(onnx_model.SerializeToString())

    sess = ort.InferenceSession(output_path)
    onnx_proba = sess.run(None, {"input": X_val})[1][:, 1]
    onnx_auc = roc_auc_score(y_val, onnx_proba)
    diff = abs(native_auc - onnx_auc)
    assert diff < 1e-4, f"XGB ONNX AUC mismatch: native={native_auc:.6f} onnx={onnx_auc:.6f} diff={diff}"
    print(f"XGB ONNX exported: AUC={onnx_auc:.4f} (diff={diff:.2e})")


def export_lgbm(model_path: str, output_path: str, X_val: np.ndarray, y_val: np.ndarray):
    model = lgb.Booster(model_file=model_path)
    native_proba = model.predict(X_val)
    native_auc = roc_auc_score(y_val, native_proba)

    onnx_model = onnxmltools.convert_lightgbm(
        model, initial_types=[("input", FloatTensorType([None, N_FEATURES]))], target_opset=15
    )

    onnx_model = _strip_zipmap(onnx.load_from_string(onnx_model.SerializeToString()))
    with open(output_path, "wb") as f:
        f.write(onnx_model.SerializeToString())

    sess = ort.InferenceSession(output_path)
    onnx_proba = sess.run(None, {"input": X_val})[1][:, 1]
    onnx_auc = roc_auc_score(y_val, onnx_proba)
    diff = abs(native_auc - onnx_auc)
    assert diff < 1e-4, f"LGBM ONNX AUC mismatch: native={native_auc:.6f} onnx={onnx_auc:.6f} diff={diff}"
    print(f"LGBM ONNX exported: AUC={onnx_auc:.4f} (diff={diff:.2e})")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--test",   default="data/test.parquet")
    p.add_argument("--models", default="data/models")
    args = p.parse_args()

    df = load(args.test)
    X_test = df[FEATURE_COLS].values.astype(np.float32)
    y_test  = df["y"].values

    # Train scripts save into a subdirectory
    import os
    xgb_path  = f"{args.models}/xgb_model.json"
    lgbm_path = f"{args.models}/lgbm_model.txt"
    if os.path.isdir(xgb_path):
        xgb_path  = f"{xgb_path}/xgb_model.json"
    if os.path.isdir(lgbm_path):
        lgbm_path = f"{lgbm_path}/lgbm_model.txt"

    export_xgb( xgb_path,  f"{args.models}/model_xgb.onnx",  X_test, y_test)
    export_lgbm(lgbm_path, f"{args.models}/model_lgbm.onnx", X_test, y_test)
