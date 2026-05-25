"""
CICFlowMeter CSV → Random Forest 예측 스크립트

사용법:
  python ml/predict_cicflow.py                          # 기본 경로
  python ml/predict_cicflow.py path/to/cicflow.csv      # CSV 직접 지정
"""

import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import pickle
import os
import numpy as np
import pandas as pd
from pathlib import Path

BASE_DIR      = Path(__file__).parent.parent
MODEL_PATH    = BASE_DIR / "cic_rf_model.pkl"
LABELMAP_PATH = BASE_DIR / "cic_label_map.pkl"
DEFAULT_CSV   = BASE_DIR / "cicflow_output.csv"
OUTPUT_CSV    = BASE_DIR / "results" / "predictions_cicflow.csv"

CSV_PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_CSV

# CICFlowMeter 컬럼명 → 모델 학습 컬럼명 매핑
# Python cicflowmeter 패키지: snake_case
# Java CICFlowMeter / CIC-IDS2017 원본 CSV: CamelCase (공백 포함)
COL_MAP = {
    "dst_port":         "Destination Port",
    "tot_fwd_pkts":     "Total Fwd Packets",
    "tot_bwd_pkts":     "Total Backward Packets",
    "totlen_fwd_pkts":  "Total Length of Fwd Packets",
    "totlen_bwd_pkts":  "Total Length of Bwd Packets",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean",
    "bwd_pkt_len_mean": "Bwd Packet Length Mean",
    "syn_flag_cnt":     "SYN Flag Count",
    "rst_flag_cnt":     "RST Flag Count",
    "psh_flag_cnt":     "PSH Flag Count",
    "ack_flag_cnt":     "ACK Flag Count",
    " Destination Port":            "Destination Port",
    " Total Fwd Packets":           "Total Fwd Packets",
    " Total Backward Packets":      "Total Backward Packets",
    " Total Length of Fwd Packets": "Total Length of Fwd Packets",
    " Total Length of Bwd Packets": "Total Length of Bwd Packets",
    " Fwd Packet Length Mean":      "Fwd Packet Length Mean",
    " Bwd Packet Length Mean":      "Bwd Packet Length Mean",
    " SYN Flag Count":              "SYN Flag Count",
    " RST Flag Count":              "RST Flag Count",
    " PSH Flag Count":              "PSH Flag Count",
    " ACK Flag Count":              "ACK Flag Count",
}

META_CANDIDATES = [
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp",
    "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "Timestamp",
    " Source IP", " Destination IP", " Source Port",
]

FEATURE_COLS = [
    "Destination Port",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
]

# ── 1. 모델 로드 ──────────────────────────────────────────────
print("[1/5] 모델 로드 중...")
with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)
with open(LABELMAP_PATH, "rb") as f:
    label_map = pickle.load(f)
print(f"  클래스: {label_map}")

# ── 2. CSV 로드 ──────────────────────────────────────────────
print(f"\n[2/5] CSV 로드 중...")
print(f"  파일: {CSV_PATH}")
df = pd.read_csv(CSV_PATH, low_memory=False)
print(f"  원본: {len(df):,}행, {df.shape[1]}컬럼")

# ── 3. 컬럼 매핑 ────────────────────────────────────────────
print(f"\n[3/5] 컬럼 매핑 중...")
df.columns = [c.strip() for c in df.columns]

rename_dict = {}
for col in df.columns:
    if col in FEATURE_COLS:
        continue
    if col in COL_MAP:
        rename_dict[col] = COL_MAP[col]
    elif col.strip() in COL_MAP:
        rename_dict[col] = COL_MAP[col.strip()]

if rename_dict:
    df.rename(columns=rename_dict, inplace=True)
    print(f"  매핑된 컬럼 수: {len(rename_dict)}개")

missing = [f for f in FEATURE_COLS if f not in df.columns]
if missing:
    print(f"\n  [오류] 아래 피처를 찾을 수 없습니다:")
    for m in missing:
        print(f"    - {m}")
    print(f"\n  현재 컬럼 목록:")
    for c in df.columns.tolist():
        print(f"    {repr(c)}")
    sys.exit(1)

print(f"  필요한 {len(FEATURE_COLS)}개 피처 모두 확인됨")
meta_cols = [c for c in META_CANDIDATES if c in df.columns]

# ── 4. 예측 ─────────────────────────────────────────────────
print(f"\n[4/5] 예측 중...")
X = df[FEATURE_COLS].copy()
X.replace([float("inf"), float("-inf")], np.nan, inplace=True)
X.fillna(0, inplace=True)
X = X.values.astype(np.float64)

y_pred     = model.predict(X)
y_proba    = model.predict_proba(X)
confidence = y_proba.max(axis=1)
print(f"  예측 완료: {len(y_pred):,}건")

# ── 5. 결과 저장 ────────────────────────────────────────────
print(f"\n[5/5] 결과 저장 중...")
OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)

df_out = df[meta_cols + FEATURE_COLS].copy() if meta_cols else df[FEATURE_COLS].copy()
df_out["pred_label"] = y_pred
df_out["pred_name"]  = [label_map[p] for p in y_pred]
df_out["confidence"] = confidence.round(4)

for code, name in sorted(label_map.items()):
    df_out[f"prob_{name}"] = y_proba[:, code].round(4)

df_out.to_csv(OUTPUT_CSV, index=False, encoding="utf-8")
print(f"  저장: {OUTPUT_CSV}")

print("\n" + "="*60)
print("예측 결과 요약")
print("="*60)

total = len(df_out)
for code in sorted(label_map.keys()):
    name = label_map[code]
    cnt  = (df_out["pred_label"] == code).sum()
    pct  = cnt / total * 100
    bar  = "█" * int(pct / 2)
    print(f"  {code} ({name:>10}): {cnt:>7,}건  ({pct:5.2f}%)  {bar}")

print(f"\n  전체: {total:,}건")

attacks = df_out[df_out["pred_label"] != 0].copy()
if len(attacks) > 0:
    print(f"\n  탐지된 공격 플로우: {len(attacks):,}건")
    show_cols = [c for c in ["timestamp", "src_ip", "dst_ip", "dst_port",
                              "protocol", "pred_name", "confidence"] if c in attacks.columns]
    if not show_cols:
        show_cols = ["pred_name", "confidence"] + FEATURE_COLS[:5]
    print(attacks[show_cols].head(30).to_string(index=False))
else:
    print("\n  탐지된 공격 없음 (전부 BENIGN 예측)")

print(f"\n결과 CSV: {OUTPUT_CSV}")
