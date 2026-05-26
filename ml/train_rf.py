"""
CIC-IDS2017 기반 Random Forest 학습 스크립트
입력 : CICIDS_Preprocessed_4class.csv  (CIC-IDS2017 전처리 데이터)
출력 : cic_rf_model.pkl  (모델)
       cic_label_map.pkl (라벨 인코딩 딕셔너리)

사용법:
  python ml/train_rf.py path/to/CICIDS_Preprocessed_4class.csv
  python ml/train_rf.py  # 기본 경로 (프로젝트 루트의 data/ 디렉터리)
"""

import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import os
import time
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

BASE_DIR     = Path(__file__).parent.parent
DATA_PATH    = Path(sys.argv[1]) if len(sys.argv) > 1 else BASE_DIR / "data" / "CICIDS_Preprocessed_4class.csv"
MODEL_OUT    = BASE_DIR / "cic_rf_model.pkl"
LABELMAP_OUT = BASE_DIR / "cic_label_map.pkl"

LABEL_MAP = {0: "BENIGN", 1: "PortScan", 2: "DDoS", 3: "Brute"}
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

# 1. 데이터 로드 
print("[1/5] 데이터 로드 중...")
df = pd.read_csv(DATA_PATH)
print(f"  전체: {len(df):,}행, {df.shape[1]}컬럼")

print("\n  클래스 분포:")
for code, name in LABEL_MAP.items():
    cnt = (df["Label"] == code).sum()
    pct = cnt / len(df) * 100
    print(f"    {code} ({name:>10}): {cnt:>9,}  ({pct:.2f}%)")

X = df[FEATURE_COLS].values
y = df["Label"].values

# 2. Train / Test 분할
print("\n[2/5] Train/Test 분할 (80:20, stratify)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"  Train: {len(X_train):,}행")
print(f"  Test : {len(X_test):,}행")

print("\n  Test 클래스 분포 확인:")
for code, name in LABEL_MAP.items():
    cnt = (y_test == code).sum()
    pct = cnt / len(y_test) * 100
    print(f"    {code} ({name:>10}): {cnt:>8,}  ({pct:.2f}%)")

#  3. 모델 학습 
# class_weight='balanced': 소수 클래스(Brute) 학습 강화
# n_jobs=-1: 전체 CPU 코어 병렬 사용
print("\n[3/5] Random Forest 학습 중...")
print("  (2M 행 × 100 트리 — 수 분 소요)")

rf = RandomForestClassifier(
    n_estimators=100,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
)

t0 = time.time()
rf.fit(X_train, y_train)
elapsed = time.time() - t0
print(f"  학습 완료: {elapsed:.1f}초")

# 4. 평가
print("\n[4/5] 모델 평가...")
y_pred = rf.predict(X_test)

print("\n  === Classification Report ===")
print(classification_report(
    y_test, y_pred,
    target_names=[LABEL_MAP[i] for i in sorted(LABEL_MAP)],
    digits=4
))

print("  === Confusion Matrix ===")
cm = confusion_matrix(y_test, y_pred, labels=sorted(LABEL_MAP.keys()))
header = f"{'':>12}" + "".join(f"  {LABEL_MAP[i]:>10}" for i in sorted(LABEL_MAP))
print(f"  {header}")
for i, row in zip(sorted(LABEL_MAP.keys()), cm):
    cells = []
    for j, v in enumerate(row):
        marker = "*" if i == j else " "
        cells.append(f"  {v:>9,}{marker}")
    label = f"실제 {LABEL_MAP[i]:>10}"
    print(f"  {label}:" + "".join(cells))
print("\n  (* = 정답 예측)")

print("\n  === 피처 중요도 ===")
importances = rf.feature_importances_
indices = np.argsort(importances)[::-1]
for rank, idx in enumerate(indices, 1):
    bar = "█" * int(importances[idx] * 200)
    print(f"  {rank:2d}. {FEATURE_COLS[idx]:<40s}  {importances[idx]:.4f}  {bar}")

# 5. 모델 저장
print(f"\n[5/5] 모델 저장 중...")
with open(MODEL_OUT, "wb") as f:
    pickle.dump(rf, f)
with open(LABELMAP_OUT, "wb") as f:
    pickle.dump(LABEL_MAP, f)

model_mb = os.path.getsize(MODEL_OUT) / 1024 / 1024
print(f"  모델 저장: {MODEL_OUT}  ({model_mb:.1f} MB)")
print(f"  라벨맵 저장: {LABELMAP_OUT}")

print("\n" + "="*55)
print("완료")
print("="*55)
print(f"  모델  : {MODEL_OUT}")
print(f"  라벨맵: {LABELMAP_OUT}")
print(f"  피처  : {len(FEATURE_COLS)}개 (타이밍 피처 제거: Flow Duration, Bytes/s, Packets/s)")
print(f"  클래스: {list(LABEL_MAP.values())}")
