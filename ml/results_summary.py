"""
results_summary.py
탐지 결과 요약 출력 스크립트 

사용법:
  python ml/results_summary.py                            # 기본 경로
  python ml/results_summary.py path/to/predictions.csv   # CSV 직접 지정
"""

import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import pickle
import pandas as pd
import numpy as np
from pathlib import Path

BASE_DIR      = Path(__file__).parent.parent
MODEL_PATH    = BASE_DIR / "cic_rf_model.pkl"
LABELMAP_PATH = BASE_DIR / "cic_label_map.pkl"
PRED_CSV      = BASE_DIR / "results" / "predictions_cicflow.csv"

if len(sys.argv) > 1:
    PRED_CSV = Path(sys.argv[1])
if len(sys.argv) > 2:
    MODEL_PATH = Path(sys.argv[2])

FEATURE_COLS = [
    "Destination Port", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Mean", "Bwd Packet Length Mean",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
]

with open(LABELMAP_PATH, "rb") as f:
    label_map = pickle.load(f)

# ── 1. 탐지 결과 요약 ─────────────────────────────────────────
print("=" * 65)
print("  ML-NIDS 탐지 결과 요약 (CIC-IDS2017 Random Forest)")
print("=" * 65)

df = pd.read_csv(PRED_CSV)
total = len(df)

attacks = df[df["pred_label"] != 0]
benign  = df[df["pred_label"] == 0]

print(f"\n  분석 플로우: {total:,}건")
print(f"  탐지된 공격: {len(attacks):,}건")
print(f"  정상(BENIGN): {len(benign):,}건")

print()
print("  ┌─────────────────────────────────────────────────────┐")
print("  │              클래스별 탐지 결과                      │")
print("  ├────────────┬──────────┬─────────────┬──────────────┤")
print("  │  클래스    │  건수    │  비율       │  평균 신뢰도  │")
print("  ├────────────┼──────────┼─────────────┼──────────────┤")

for code in sorted(label_map.keys()):
    name = label_map[code]
    subset = df[df["pred_label"] == code]
    cnt = len(subset)
    pct = cnt / total * 100
    avg_conf = subset["confidence"].mean() if cnt > 0 else 0
    marker = " ★" if code != 0 and cnt > 0 else ""
    print(f"  │ {name:<10} │ {cnt:>8,} │ {pct:>9.2f}%  │   {avg_conf:>6.1%}      │{marker}")

print("  └────────────┴──────────┴─────────────┴──────────────┘")

# ── 2. 공격 플로우 상세 ───────────────────────────────────────
if len(attacks) > 0:
    print(f"\n  ★ 탐지된 공격 플로우 (상위 20건)")
    print()

    show_cols = []
    for c in ["timestamp", "src_ip", "dst_ip", "Destination Port",
              "pred_name", "confidence", "prob_BENIGN"]:
        if c in attacks.columns:
            show_cols.append(c)

    top = attacks.sort_values("confidence", ascending=False).head(20)
    print(top[show_cols].to_string(index=False))

    print(f"\n  신뢰도 분포:")
    conf = attacks["confidence"]
    print(f"    최소: {conf.min():.1%}  |  평균: {conf.mean():.1%}  |  최대: {conf.max():.1%}")
    bins = [0, 0.5, 0.6, 0.7, 0.8, 0.9, 1.01]
    labels_b = ["<50%", "50-60%", "60-70%", "70-80%", "80-90%", "90%+"]
    cuts = pd.cut(conf, bins=bins, labels=labels_b, right=False)
    dist = cuts.value_counts().sort_index()
    for lbl, cnt in dist.items():
        bar = "█" * int(cnt / max(dist) * 30) if max(dist) > 0 else ""
        print(f"    {lbl:>8}  {cnt:>4}건  {bar}")

# ── 3. 피처 분포 (공격 vs 정상 비교) ─────────────────────────
print(f"\n{'=' * 65}")
print("  피처 분포 비교 (공격 vs 정상)")
print("=" * 65)

key_feats = [
    "Destination Port", "Total Fwd Packets", "Total Backward Packets",
    "Fwd Packet Length Mean", "Bwd Packet Length Mean",
    "PSH Flag Count", "SYN Flag Count",
]

avail = [f for f in key_feats if f in df.columns]
if avail:
    print(f"\n  {'피처':<30}  {'정상(중간값)':>12}  {'공격(중간값)':>12}")
    print(f"  {'-'*30}  {'-'*12}  {'-'*12}")
    for feat in avail:
        b_med = benign[feat].median() if len(benign) > 0 else float("nan")
        a_med = attacks[feat].median() if len(attacks) > 0 else float("nan")
        b_str = f"{b_med:>12.1f}" if not pd.isna(b_med) else f"{'N/A':>12}"
        a_str = f"{a_med:>12.1f}" if not pd.isna(a_med) else f"{'N/A':>12}"
        diff = ""
        if not pd.isna(b_med) and not pd.isna(a_med):
            diff = "◀" if abs(a_med - b_med) > 1 else ""
        print(f"  {feat:<30}  {b_str}  {a_str}  {diff}")

# ── 4. 모델 피처 중요도 ───────────────────────────────────────
print(f"\n{'=' * 65}")
print("  모델 피처 중요도 (Random Forest)")
print("=" * 65)

try:
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)

    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    print()
    for rank, idx in enumerate(indices, 1):
        feat = FEATURE_COLS[idx]
        imp  = importances[idx]
        bar  = "█" * int(imp * 150)
        print(f"  {rank:2d}. {feat:<40}  {imp:.4f}  {bar}")
except Exception as e:
    print(f"  (모델 로드 실패: {e})")

print(f"\n{'=' * 65}")
print("  분석 완료")
print("=" * 65)
