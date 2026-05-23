"""
정상 트래픽 BENIGN 탐지 데모

실제 공격 도구를 사용하지 않고 수동으로 만든 정상 패킷 특성값을
CIC RF 모델에 입력했을 때 BENIGN으로 올바르게 분류되는지 검증합니다.

Usage:
  python ml/demo_benign.py [model.pkl] [labelmap.pkl]
"""
import sys
import pickle
import warnings
from pathlib import Path

import numpy as np
import pandas as pd

BASE_DIR    = Path(__file__).parent.parent
MODEL_PATH  = Path(sys.argv[1]) if len(sys.argv) > 1 else BASE_DIR / "cic_rf_model.pkl"
LMAP_PATH   = Path(sys.argv[2]) if len(sys.argv) > 2 else BASE_DIR / "cic_label_map.pkl"

FEATURE_COLS = [
    "Destination Port",
    "Total Length of Fwd Packets",
    "Fwd Packet Length Mean",
    "Total Fwd Packets",
    "Bwd Packet Length Mean",
    "Total Length of Bwd Packets",
    "PSH Flag Count",
    "Total Backward Packets",
    "ACK Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
]

# 정상 트래픽 시나리오: 실제 웹 브라우징과 유사한 피처값을 수동으로 구성
# 각 행은 하나의 네트워크 플로우를 나타냅니다.
BENIGN_SAMPLES = [
    {
        "scenario": "HTTP GET (웹 브라우징)",
        # HTTP 요청: 소수 패킷, PSH+ACK 포함, 일반 HTTP 응답 크기
        "Destination Port": 80,
        "Total Length of Fwd Packets": 320,   # 요청 패킷 총 크기 (GET 요청 2-3개)
        "Fwd Packet Length Mean": 107,         # 평균 요청 패킷 크기
        "Total Fwd Packets": 3,                # 요청 방향 패킷 수 (SYN, 데이터, FIN)
        "Bwd Packet Length Mean": 512,         # 평균 응답 패킷 크기 (HTML 페이지)
        "Total Length of Bwd Packets": 2048,   # 응답 패킷 총 크기
        "PSH Flag Count": 1,                   # 데이터 전송 시 PSH
        "Total Backward Packets": 4,           # 응답 패킷 수 (SYN-ACK, 데이터, FIN-ACK)
        "ACK Flag Count": 5,                   # 대부분 패킷에 ACK 포함
        "SYN Flag Count": 1,                   # 연결 수립 SYN 1회
        "RST Flag Count": 0,                   # 정상 종료이므로 RST 없음
    },
    {
        "scenario": "HTTPS (보안 웹 브라우징)",
        # TLS 핸드셰이크 + 암호화 데이터 교환
        "Destination Port": 443,
        "Total Length of Fwd Packets": 850,    # ClientHello + 데이터 패킷
        "Fwd Packet Length Mean": 212,         # TLS 레코드 크기
        "Total Fwd Packets": 4,
        "Bwd Packet Length Mean": 680,         # ServerHello + Certificate + 데이터
        "Total Length of Bwd Packets": 3400,
        "PSH Flag Count": 2,
        "Total Backward Packets": 5,
        "ACK Flag Count": 7,
        "SYN Flag Count": 1,
        "RST Flag Count": 0,
    },
    {
        "scenario": "DNS 쿼리 (UDP)",
        # DNS는 단일 요청-응답 패턴, 매우 작은 패킷
        "Destination Port": 53,
        "Total Length of Fwd Packets": 45,     # DNS 쿼리 패킷 (도메인명 포함)
        "Fwd Packet Length Mean": 45,
        "Total Fwd Packets": 1,                # 단일 쿼리
        "Bwd Packet Length Mean": 120,         # DNS 응답 (A 레코드 다수)
        "Total Length of Bwd Packets": 120,
        "PSH Flag Count": 0,                   # UDP는 PSH 없음
        "Total Backward Packets": 1,           # 단일 응답
        "ACK Flag Count": 0,                   # UDP는 ACK 없음
        "SYN Flag Count": 0,
        "RST Flag Count": 0,
    },
    {
        "scenario": "SSH 세션 (정상 로그인)",
        # SSH: 키 교환 후 암호화 세션, 패킷 크기와 수가 Brute Force와 다름
        # Brute Force는 매우 짧게 연결 후 실패 반복 → tot_fwd~15, tot_bwd~17
        # 정상 SSH: 연결 성공 후 더 긴 세션, 더 많은 바이트 교환
        "Destination Port": 22,
        "Total Length of Fwd Packets": 4200,   # 정상 세션: 명령 실행 후 데이터 전송
        "Fwd Packet Length Mean": 280,
        "Total Fwd Packets": 15,
        "Bwd Packet Length Mean": 380,
        "Total Length of Bwd Packets": 7600,   # 서버 응답 (명령 출력)
        "PSH Flag Count": 8,
        "Total Backward Packets": 20,
        "ACK Flag Count": 30,
        "SYN Flag Count": 1,
        "RST Flag Count": 0,
    },
    {
        "scenario": "FTP 데이터 전송 (파일 다운로드)",
        # FTP 데이터 채널: 큰 파일 전송, 다수 패킷, 단방향 위주
        "Destination Port": 21,
        "Total Length of Fwd Packets": 200,    # 제어 명령 (RETR 등)
        "Fwd Packet Length Mean": 50,
        "Total Fwd Packets": 4,
        "Bwd Packet Length Mean": 1460,        # 최대 세그먼트 크기(MSS) 패킷 연속
        "Total Length of Bwd Packets": 146000, # ~100KB 파일
        "PSH Flag Count": 5,
        "Total Backward Packets": 100,
        "ACK Flag Count": 104,
        "SYN Flag Count": 1,
        "RST Flag Count": 0,
    },
    {
        "scenario": "NTP (시간 동기화)",
        # NTP: UDP, 단일 요청-응답, 48바이트 고정 패킷
        "Destination Port": 123,
        "Total Length of Fwd Packets": 48,
        "Fwd Packet Length Mean": 48,
        "Total Fwd Packets": 1,
        "Bwd Packet Length Mean": 48,
        "Total Length of Bwd Packets": 48,
        "PSH Flag Count": 0,
        "Total Backward Packets": 1,
        "ACK Flag Count": 0,
        "SYN Flag Count": 0,
        "RST Flag Count": 0,
    },
]


def load_model():
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    with open(LMAP_PATH, "rb") as f:
        label_map = pickle.load(f)
    return model, label_map


def main():
    print("=" * 65)
    print("  정상 트래픽 BENIGN 탐지 데모")
    print("=" * 65)
    print(f"  모델: {MODEL_PATH.name}")
    print()

    model, label_map = load_model()
    inv_map = {v: k for k, v in label_map.items()}

    df = pd.DataFrame(BENIGN_SAMPLES)
    X  = df[FEATURE_COLS].values

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        preds  = model.predict(X)
        probas = model.predict_proba(X)

    all_benign = True
    print(f"  {'시나리오':<28}  {'예측':<10}  {'BENIGN 확률':>10}  {'결과'}")
    print(f"  {'-'*28}  {'-'*10}  {'-'*10}  {'-'*4}")

    for sample, pred, proba in zip(BENIGN_SAMPLES, preds, probas):
        pred_name     = inv_map.get(pred, str(pred))
        benign_idx    = list(label_map.values()).index(0) if 0 in label_map.values() else 0
        benign_prob   = proba[benign_idx]
        is_benign     = (pred_name == "BENIGN")
        result        = "✓" if is_benign else "✗"
        if not is_benign:
            all_benign = False

        print(f"  {sample['scenario']:<28}  {pred_name:<10}  {benign_prob:>9.1%}  {result}")

    print()
    if all_benign:
        print("  결과: 모든 정상 트래픽 샘플이 BENIGN으로 올바르게 분류되었습니다.")
    else:
        print("  결과: 일부 샘플이 오탐지되었습니다. 피처값을 확인하세요.")

    print()
    print("  [참고] 피처 입력값 요약")
    print(f"  {'피처':<35}  {'최소':>8}  {'최대':>8}  {'평균':>8}")
    print(f"  {'-'*35}  {'-'*8}  {'-'*8}  {'-'*8}")
    for col in FEATURE_COLS:
        vals = df[col]
        print(f"  {col:<35}  {vals.min():>8.0f}  {vals.max():>8.0f}  {vals.mean():>8.1f}")


if __name__ == "__main__":
    main()
