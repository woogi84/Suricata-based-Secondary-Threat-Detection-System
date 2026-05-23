"""
KISTI RF 모델 검증 스크립트 (전체 데이터)

Usage:
  python analyze.py [model.pkl] [data.csv]

Default paths (same directory as this script):
  model_kisti_rf.pkl
  suricata_kisti_mapped.csv
"""
import os, pickle, sys, warnings
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

BASE     = Path(__file__).parent
PKL_PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else BASE / "model_kisti_rf.pkl"
CSV_PATH = Path(sys.argv[2]) if len(sys.argv) > 2 else BASE / "suricata_kisti_mapped.csv"

FEATURES = ["sourcePort", "destinationPort", "protocol", "eventCount", "duration", "packetSize"]
LABEL    = "attackType"
CLASSES  = [0, 1, 2, 3, 4]
NAMES    = ["Normal(0)", "Malware(1)", "WebAtk(2)", "Exploit(3)", "Scan(4)"]

# ── 1. 모델 로드 ──────────────────────────────────────────────────────────────
print("=== 1. 모델 정보 ===")
with open(PKL_PATH, "rb") as f:
    model = pickle.load(f)

print(f"  알고리즘     : RandomForestClassifier")
print(f"  트리 수      : {model.n_estimators}")
print(f"  입력 피처 수 : {model.n_features_in_}")
print(f"  클래스       : {model.classes_.tolist()}")
print()

# ── 2. CSV 로드 ───────────────────────────────────────────────────────────────
print("=== 2. 데이터 개요 ===")
df = pd.read_csv(CSV_PATH)
print(f"  전체 행      : {len(df):,}")
print(f"  컬럼         : {df.columns.tolist()}")
print()

print("  결측값 현황:")
nulls = df[FEATURES].isnull().sum()
for col, cnt in nulls.items():
    pct = cnt / len(df) * 100
    print(f"    {col:<20} {cnt:>8,}  ({pct:.1f}%)")
print()

print("  attackType 분포:")
vc = df[LABEL].value_counts().sort_index()
for cls, cnt in vc.items():
    name = NAMES[cls] if cls < len(NAMES) else str(cls)
    bar  = "#" * int(cnt / len(df) * 40)
    print(f"    {name:<12} {cnt:>10,}  {bar}")
print()

# ── 3. 피처 통계 ──────────────────────────────────────────────────────────────
print("=== 3. 피처 통계 ===")
print(df[FEATURES].describe().to_string())
print()

# ── 4. 모델 예측 (샘플 10만건) ────────────────────────────────────────────────
SAMPLE = min(100_000, len(df))
print(f"=== 4. 모델 예측 (샘플 {SAMPLE:,}건) ===")

X = df[FEATURES].fillna(0)
y = df[LABEL]

X_s = X.iloc[:SAMPLE].values
y_s = y.iloc[:SAMPLE]

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    y_pred  = model.predict(X_s)
    y_proba = model.predict_proba(X_s)

acc = accuracy_score(y_s, y_pred)
print(f"  Accuracy : {acc:.4f}")
print()

pred_dist = pd.Series(y_pred).value_counts().sort_index()
print("  예측 분포:")
for cls, cnt in pred_dist.items():
    name = NAMES[cls] if cls < len(NAMES) else str(cls)
    print(f"    {name:<12} {cnt:>8,}")
print()

print("  Classification Report:")
print(classification_report(y_s, y_pred, labels=CLASSES,
      target_names=NAMES, zero_division=0))

print("  Confusion Matrix (actual \\ pred):")
cm = confusion_matrix(y_s, y_pred, labels=CLASSES)
header = "               " + "  ".join(f"{n[:8]:>8}" for n in NAMES)
print(header)
for i, row in enumerate(cm):
    row_label = f"  {NAMES[i][:12]:<12} "
    print(row_label + "  ".join(f"{v:>8,}" for v in row))
print()

# ── 5. 피처 중요도 ────────────────────────────────────────────────────────────
print("=== 5. 피처 중요도 ===")
for feat, imp in sorted(zip(FEATURES, model.feature_importances_), key=lambda x: -x[1]):
    bar = "#" * int(imp * 50)
    print(f"  {feat:<20} {imp:.4f}  {bar}")
print()

# ── 6. 기능 검증: 합성 샘플 ──────────────────────────────────────────────────
print("=== 6. 기능 검증 (합성 샘플) ===")
synth = pd.DataFrame([
    {"sourcePort": 52341, "destinationPort": 443,  "protocol": 6,  "eventCount": 10,  "duration": 2,   "packetSize": 1500,   "label": "Normal"},
    {"sourcePort": 1024,  "destinationPort": 80,   "protocol": 6,  "eventCount": 1,   "duration": 0,   "packetSize": 60,     "label": "Scan"},
    {"sourcePort": 1025,  "destinationPort": 443,  "protocol": 6,  "eventCount": 1,   "duration": 0,   "packetSize": 60,     "label": "Scan"},
    {"sourcePort": 55000, "destinationPort": 3389, "protocol": 6,  "eventCount": 500, "duration": 120, "packetSize": 500000, "label": "Exploit"},
    {"sourcePort": 12345, "destinationPort": 80,   "protocol": 17, "eventCount": 9999,"duration": 1,   "packetSize": 999000, "label": "DoS-like"},
])

X_syn = synth[FEATURES].values
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    preds  = model.predict(X_syn)
    probas = model.predict_proba(X_syn)

for i, (pred, proba, row) in enumerate(zip(preds, probas, synth.itertuples())):
    name    = NAMES[pred] if pred < len(NAMES) else str(pred)
    top     = sorted(zip(CLASSES, proba), key=lambda x: -x[1])[:2]
    top_str = ", ".join(f"{NAMES[c]}:{p:.2f}" for c, p in top)
    print(f"  [{row.label:<10}] 예측={name:<12}  확률 상위2: {top_str}")

print()
print("=== 완료 ===")
