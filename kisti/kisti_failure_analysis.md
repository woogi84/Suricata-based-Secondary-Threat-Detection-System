# KISTI RF 모델 실패 분석
 KISTI 데이터셋 기반 Random Forest 분류기가 실제 Suricata 트래픽을 전혀 탐지하지 못한 원인을 분석한 문서입니다.

---
원인 1. 지나친 클래스 불균형

| 항목 | 수치 |
|------|------|
| 전체 행 수 | 66,610건 |
| Normal(0) 행 수 | 66,591건 (99.972%) |
| 공격 행 수 | 19건 (0.028%) |

Suricata가 캡처한 66,610개의 플로우 중 시그니처 기반으로 공격으로 분류된 행은 단 19건입니다.  
이는 `class_weight='balanced'`로 학습해도 극복하기 어려운 수준의 불균형입니다.

공격 19건의 분포:

| attackType | 건수 |
|------------|------|
| Exploit(3) | 14건 |
| Scan(4) | 5건 |
| Malware(1), WebAtk(2) | 0건 |

---

원인 2. sourcePort가 39.1% 중요도를 차지하는 노이즈 피처


| 피처 | 중요도 |
|------|--------|
| sourcePort | **39.1%** |
| destinationPort | 22.3% |
| packetSize | 18.7% |
| eventCount | 11.2% |
| duration | 5.8% |
| protocol | 2.9% |

`sourcePort`는 클라이언트가 임의로 선택하는 임시 포트(ephemeral port, 32768~60999)입니다.  
공격 트래픽과 정상 트래픽 모두 거의 동일한 범위에서 무작위 값을 가지므로 sourcePort가 높은 중요도를 가지는 것은 노이즈 피처로 작용합니다.

---

원인 3: 공격과 정상 트래픽의 피처 분포가 동일

아래는 Suricata 캡처 데이터에서 공격(19건) vs 정상(66,591건)의 피처 비교입니다:

| 피처 | 정상 평균 | 공격 평균 | 차이 |
|------|----------|---------|------|
| sourcePort | 47,832 | 46,215 | ≈ 동일 (임시 포트) |
| destinationPort | 12,441 | 8,847 | 일부 차이 |
| protocol | 6.2 | 6.0 | ≈ 동일 (주로 TCP) |
| eventCount | 8.3 | 11.4 | 근소한 차이 |
| duration | 4.1 | 3.2 | 근소한 차이 |
| packetSize | 1,247 | 1,893 | 일부 차이 |

6개 피처만으로는 공격과 정상 트래픽을 구분하기 위한 충분한 신호가 없습니다.
CIC-IDS2017이 사용하는 11개 피처(패킷 크기 분포, TCP 플래그 등)에 비해  
KISTI의 6개 피처는 정보량이 부족합니다.

---


## 관련 파일

| 파일 | 설명 |
|------|------|
| `convert_evejson_kisti.py` | Suricata eve.json → KISTI 포맷 CSV 변환 |
| `analyze.py` | 전체 데이터로 모델 예측 및 검증 |
| `analyze_attack.py` | 공격 트래픽만 분리하여 집중 분석 |
| `model_kisti_rf.pkl` | 학습된 KISTI RF 모델 (234MB, .gitignore 제외) |
| `suricata_kisti_mapped.csv` | Suricata 캡처 → KISTI 변환 데이터 (대용량, 제외) |
