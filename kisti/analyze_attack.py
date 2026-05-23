"""
KISTI RF 모델 검증 스크립트 (공격 트래픽만)

Usage:
  python analyze_attack.py [model.pkl] [attack_data.csv]

Default paths (same directory as this script):
  model_kisti_rf.pkl
  kisti_mapped_attack.csv
"""
import os, pickle, warnings, sys
from pathlib import Path
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

BASE     = Path(__file__).parent
PKL_PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else BASE / "model_kisti_rf.pkl"
CSV_PATH = Path(sys.argv[2]) if len(sys.argv) > 2 else BASE / "kisti_mapped_attack.csv"

FEATURES = ["sourcePort", "destinationPort", "protocol", "eventCount", "duration", "packetSize"]
LABEL    = "attackType"
CLASSES  = [0, 1, 2, 3, 4]
NAMES    = ["Normal(0)", "Malware(1)", "WebAtk(2)", "Exploit(3)", "Scan(4)"]

print("=== 모델 로드 ===")
with open(PKL_PATH, "rb") as f:
    model = pickle.load(f)
print(f"  트리: {model.n_estimators} | 피처: {model.n_features_in_} | 클래스: {model.classes_.tolist()}")

print("\n=== CSV 로드 ===")
df = pd.read_csv(CSV_PATH)
print(f"  전체 행: {len(df):,}")

print("\n  Suricata 시그니처 기반 attackType 분포 (변환 결과):")
for cls, cnt in df[LABEL].value_counts().sort_index().items():
    bar = "#" * int(cnt / len(df) * 40)
    print(f"    {NAMES[cls]:<12} {cnt:>8,}  {bar}")

print("\n=== 모델 예측 ===")
X = df[FEATURES].fillna(0)
y = df[LABEL]
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    y_pred  = model.predict(X.values)
    y_proba = model.predict_proba(X.values)

print("\n  모델 예측 분포:")
for cls, cnt in pd.Series(y_pred).value_counts().sort_index().items():
    bar = "#" * int(cnt / len(df) * 40)
    print(f"    {NAMES[cls]:<12} {cnt:>8,}  {bar}")

print(f"\n  Accuracy (시그니처 vs 모델): {accuracy_score(y, y_pred):.4f}")

print("\n  Classification Report:")
print(classification_report(y, y_pred, labels=CLASSES, target_names=NAMES, zero_division=0))

print("  Confusion Matrix:")
cm = confusion_matrix(y, y_pred, labels=CLASSES)
print("               " + "  ".join(f"{n[:9]:>9}" for n in NAMES))
for i, row in enumerate(cm):
    print(f"  {NAMES[i][:12]:<12} " + "  ".join(f"{v:>9,}" for v in row))

print("\n=== 피처 중요도 ===")
for feat, imp in sorted(zip(FEATURES, model.feature_importances_), key=lambda x: -x[1]):
    print(f"  {feat:<20} {imp:.4f}  " + "#" * int(imp * 50))

print("\n=== 공격으로 예측된 샘플 (클래스별 상위 5건) ===")
df["pred"] = y_pred
df["conf"] = y_proba.max(axis=1)
for cls in [1, 2, 3, 4]:
    sub = df[df["pred"] == cls].nlargest(5, "conf")
    if not sub.empty:
        print(f"\n  [{NAMES[cls]}]")
        for _, r in sub.iterrows():
            dp = int(r["destinationPort"]) if pd.notna(r["destinationPort"]) else "?"
            print(f"    {r.sourceIP} -> {r.destinationIP}:{dp}  conf={r['conf']:.2f}  pkts={r.eventCount}  bytes={r.packetSize}")
    else:
        print(f"\n  [{NAMES[cls]}] - 없음")
