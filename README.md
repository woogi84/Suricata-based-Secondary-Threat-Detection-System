# ML-NIDS: CIC-IDS2017 · KISTI 기반 머신러닝 네트워크 침입 탐지 시스템

두 가지 공개 데이터셋(CIC-IDS2017, KISTI)으로 학습한 Random Forest 분류기를 Docker 기반 실험 환경의 Suricata IDS에 적용하는 프로젝트.  

## 프로젝트 개요

상용 IDS(Suricata)는 시그니처 기반 탐지로 알려진 공격만 잡습니다.  
이 프로젝트는 공개 데이터셋(CIC-IDS2017)으로 학습한 ML 모델을 2차 탐지 레이어로 추가하여시그니처에 없는 공격 패턴을 탐지합니다.

```
[Suricata 1차 탐지] → 시그니처 탐지 트래픽
                              ↓
              [CICFlowMeter 피처 추출(pcap)]
                              ↓
          [Random Forest 2차 탐지] → 공격 분류

```
- CIC-IDS2017 2,134,160개 플로우 → Random Forest 학습 
- Docker 가상 환경 공격을 통해 Suricata-eve.json 추출
- SSH Brute Force 실시간 탐지 성공 (신뢰도 65~79%)
- 정상 트래픽(HTTP/HTTPS/DNS/NTP 등) 수동 생성 → BENIGN 오탐 없음 검증('ml/demo_benign.py')
- KISTI 데이터셋 파이프라인 구현 및 실패 원인 분석 

---

## 시스템 아키텍처

```
┌─────────────────────────────────────────────────────┐
│                  Docker Network (172.20.0.0/24)      │
│                                                     │
│  ┌──────────────┐       공격 트래픽        ┌───────────────────────┐
│  │   Attacker   │ ──────────────────────► │       suricata IDS     │
│  │  Kali Linux  │                         │ (네트워크 네임스페이스) │
│  │ 172.20.0.20  │                         │                        │
│  └──────────────┘                         └───────────┬───────────┘
│                                                       │ eth0 공유
│                                           ┌───────────▼───────────┐
│                                           │         Target        │
│                                           │      DVWA+Apache      │
│                                           │     172.20.0.10    │  │
│                                           └───────────┬───────────┘
└───────────────────────────────────────────────────────┘
                                                        │ tcpdump PCAP
                                            ┌───────────▼───────────┐
                                            │    CICFlowMeter       │
                                            │    (피처 추출)        │
                                            └───────────┬───────────┘
                                                        │ CSV (11 피처)
                                            ┌───────────▼───────────┐
                                            │   Random Forest 모델   │
                                            │   (CIC-IDS2017 학습)   │
                                            └───────────┬───────────┘
                                                        │
                                            BENIGN / PortScan / DDoS / Brute
```

설계 포인트: Suricata 컨테이너가 Target의 네트워크 네임스페이스를 공유(`network_mode: service:target`)하므로,  
attacker → target 공격 트래픽 전체를 Suricata의 eth0에서 직접 감시합니다.

---

## ML 모델

### 학습 데이터

| 항목 | 내용 |
|------|------|
| 데이터셋 | CIC-IDS2017 (Canadian Institute for Cybersecurity) |
| 전처리 | 4-class 분류 (BENIGN / PortScan / DDoS / Brute Force) |
| 총 샘플 | 2,134,160개 플로우 |
| 분류기 | Random Forest (n_estimators=100, class_weight='balanced') |

| 클래스 | 샘플 수 | 비율 |
|--------|---------|------|
| BENIGN | 1,831,543 | 85.82% |
| PortScan | 158,804 | 7.44% |
| DDoS | 128,025 | 6.00% |
| Brute Force | 15,788 | 0.74% |

### 사용 피처 (11개)

`Average Packet Size`는 Python/Java CICFlowMeter 간 계산 방식 차이로 인한 도메인 갭 발생 → 제외.


| 피처 | 중요도 |
|------|--------|
| Destination Port | 24.6% |
| Total Length of Fwd Packets | 19.2% |
| Fwd Packet Length Mean | 12.5% |
| Total Fwd Packets | 11.7% |
| Bwd Packet Length Mean | 10.4% |
| Total Length of Bwd Packets | 8.5% |
| PSH Flag Count | 5.0% |
| Total Backward Packets | 5.0% |
| ACK Flag Count | 2.4% |
| SYN Flag Count | 0.7% |
| RST Flag Count | 0.0% |

### 모델 성능 (CIC-IDS2017 테스트셋)

| 클래스 | Precision | Recall | F1-score |
|--------|-----------|--------|----------|
| BENIGN | 0.9995 | 0.9963 | 0.9979 |
| PortScan | 0.9915 | 0.9990 | 0.9952 |
| DDoS | 0.9974 | 0.9996 | **0.9985** |
| Brute Force | 0.7467 | 0.9607 | **0.8403** |
| **전체 정확도** | | | **99.64%** |

---

## 실험 환경

| 컨테이너 | 이미지 | IP | 역할 |
|---------|-------|----|------|
| target | vulnerables/web-dvwa | 172.20.0.10 | 공격 대상 (Apache + MySQL + DVWA) |
| suricata | jasonish/suricata:latest | (target eth0 공유) | 네트워크 감시 · PCAP 캡처 |
| attacker | kalilinux/kali-rolling | 172.20.0.20 | 공격 실행 (Scapy, Hydra, Hping3) |

호스트 환경: Windows 11 + WSL2 Ubuntu

---

## 파이프라인

### 자동화 흐름

```bash
# 1. tcpdump로 공격 트래픽 PCAP 캡처 (suricata 컨테이너 내부)
docker exec suricata bash -c "tcpdump -i eth0 -w /tmp/attack.pcap &"

# 2. 공격 실행 (attacker 컨테이너)
docker exec attacker python3 /tmp/attack.py

# 3. PCAP 추출 → CICFlowMeter로 플로우 피처 추출
cicflowmeter -f attack.pcap -c cicflow.csv

# 4. ML 모델로 탐지
python ml/predict_cicflow.py cicflow.csv
```

### 구현 공격 시나리오

| 시나리오 | 도구 | 방법 |
|---------|------|------|
| PortScan | Scapy (L2 sendp) | TCP SYN / PSH+data, ports 1–1024 |
| DDoS | Python http.client | HTTP GET flood, 500 connections × Connection:close |
| Brute Force | Hydra | SSH credential stuffing, port 22 |

---

## 탐지 결과

### SSH Brute Force 탐지 성공

```
탐지된 공격 플로우: 37건 (100%)

timestamp           src_ip        dst_ip        pred_name  confidence
2026-05-23 19:02    172.20.0.20   172.20.0.10   Brute      0.79
2026-05-23 19:02    172.20.0.20   172.20.0.10   Brute      0.77
2026-05-23 19:02    172.20.0.20   172.20.0.10   Brute      0.77
...
```

| 지표 | 값 |
|------|-----|
| 탐지율 | 37 / 37 (100%) |
| 평균 신뢰도 | 76% |
| 신뢰도 범위 | 65 ~ 79% |
| 오탐(False Positive) | 0건 |

**탐지 근거**: SSH 프로토콜은 표준화되어 있어 어느 환경에서도 동일한 플로우 피처를 생성합니다.  
- dst_port=22, SYN=1, PSH=1, ACK=1
- tot_fwd ≈ 15, tot_bwd ≈ 17 (SSH 핸드셰이크 + 인증 교환)
- totlen_fwd ≈ 1700 bytes, totlen_bwd ≈ 2400 bytes (SSH 배너 + 키 교환)

### PortScan 부분 탐지

| 지표 | 값 |
|------|-----|
| prob_PortScan 평균 | 14% |
| prob_PortScan 최대 | 32% |
| prob_BENIGN | 81% (우세) |

### DDoS  미탐지

| 지표 | 값 |
|------|-----|
| prob_DDoS | 0% |
| 원인 | 도메인 갭 (아래 분석 참고) |

---

## KISTI 파이프라인 & 실패 분석
CIC 이전 실패한 한국과학기술정보원(KISTI)에서 제공받은 데이터셋을 기반으로 한 랜덤 포레스트 머신러닝 모델입니다. 
결과적으로 KISTI 모델은 Suricata의 비정상 트래픽을 100% 정상으로 예측합니다.(예측 실패)  

### KISTI 파이프라인

```
Suricata eve.json
      ↓
convert_evejson_kisti.py   (eve.json → KISTI 6-피처 CSV)
      ↓
model_kisti_rf.pkl         (6-class RF: Normal/Malware/WebAtk/Exploit/Scan)
      ↓
analyze.py / analyze_attack.py   (예측 결과 및 피처 중요도 분석)
```

### KISTI 모델 사용 피처 (6개)

| 피처 | eve.json 매핑 |
|------|---------------|
| sourcePort | `src_port` |
| destinationPort | `dest_port` |
| protocol | `proto` (TCP=6, UDP=17, ICMP=1) |
| eventCount | `flow.pkts_toserver + flow.pkts_toclient` |
| duration | `flow.age` or `flow.end - flow.start` |
| packetSize | `flow.bytes_toserver + flow.bytes_toclient` |

### 실패 원인 요약

| 원인 | 수치 |
|------|------|
| 극심한 클래스 불균형 | 공격 19건 / 전체 66,610건 (0.028%) |
| sourcePort 피처 중요도 | 39.1% (무의미한 노이즈) |
| 공격/정상 피처 분포 차이 | 거의 없음 (6개 피처로 구분 불가) |
| 모델 예측 결과 | 전체 100% Normal 예측 |

자세한 분석은 [kisti/kisti_failure_analysis.md](kisti/kisti_failure_analysis.md) 참고.

### CIC vs KISTI 비교

| 항목 | CIC-IDS2017 | KISTI |
|------|-------------|-------|
| 피처 수 | 11개 | 6개 |
| 클래스 수 | 4개 | 5개 |
| 공격 비율 | 14.2% | 0.028% |
| SSH Brute 탐지 | 성공 (65~79%) | 실패 |
| 구조적 한계 | 도메인 갭 | 데이터 불균형 + 피처 노이즈 |

---

## 도메인 갭 분석

SSH Brute Force는 탐지되지만 DDoS/PortScan은 탐지되지 않습니다.  
이는 버그가 아닌 **CIC-IDS2017 기반 모델의 구조적 한계**입니다.

### 핵심 비교

| 공격 | CIC-IDS2017 학습 데이터 | 우리 Docker 실험 환경 | 갭 원인 |
|------|------------------------|----------------------|---------|
| DDoS | flow_byts_s 중간값 '160 B/s' (서버 과부하로 느린 응답) | flow_byts_s 중간값 '714,145 B/s' (Docker 즉각 응답) | Docker 네트워크가 실제 과부하 환경과 달라 타이밍 피처 분포 완전히 다름 |
| DDoS | tot_bwd_pkts 평균 '3.26' (Java CICFlowMeter) | tot_bwd_pkts 평균 '11' (Python CICFlowMeter) | Java/Python CICFlowMeter 간 순수 ACK 패킷 카운팅 방식 차이 |
| PortScan | bwd_pkt_len_mean 중간값 '6 bytes' (타깃 서비스 응답) | bwd_pkt_len_mean '0 bytes' (RST 응답, 데이터 없음) | CIC 학습 환경 타깃에는 SSH/FTP 등 배너 응답 서비스가 동작 중이었음 |
| Brute Force | SSH 프로토콜 표준 패턴 | SSH 프로토콜 표준 패턴 | 동일 → 탐지 성공 |

자세한 분석은 [docs/domain_gap_analysis.md](docs/domain_gap_analysis.md) 참고.


---

## 파일 구조

```
nids-cic-rf/
├── README.md
│
├── ml/                          # CIC-IDS2017 파이프라인
│   ├── train_rf.py              # Random Forest 학습 스크립트
│   ├── predict_cicflow.py       # CICFlowMeter CSV → 탐지 결과
│   ├── results_summary.py       # 탐지 결과 요약 출력 (데모용)
│   └── demo_benign.py           # 정상 트래픽 BENIGN 탐지 검증 데모
│
├── kisti/                       # KISTI 파이프라인 (실패 분석 포함)
│   ├── convert_evejson_kisti.py # eve.json → KISTI 포맷 CSV 변환
│   ├── analyze.py               # 전체 데이터 모델 예측 및 검증
│   ├── analyze_attack.py        # 공격 트래픽만 집중 분석
│   └── kisti_failure_analysis.md# 실패 원인 구조 분석 문서
│
├── lab/
│   ├── docker-compose.yml       # 실험 환경 구성
│   ├── attack4.py               # PortScan(SYN) + DDoS(HTTP) + Brute(HTTP POST)
│   ├── pipeline4.sh             # attack4 전체 파이프라인 자동화
│   ├── pipeline5.sh             # SSH Brute Force 파이프라인 자동화
│   ├── setup_ssh.sh             # Target 컨테이너 SSH 서버 설치
│   └── cicflowmeter_patch.md    # CICFlowMeter Python 패키지 패치 가이드
│
├── results/
│   └── predictions_cicflow.csv  # 탐지 결과 샘플 (SSH Brute Force 37건)
│
├── docs/
│   └── domain_gap_analysis.md   # 도메인 갭 상세 분석
│
├── .gitignore
└── requirements.txt
```
---

## 참고

- [CIC-IDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html)
- [CICFlowMeter (Python)](https://github.com/hieulw/cicflowmeter)
- [Suricata IDS](https://suricata.io/)
- Sharafaldin, I., et al. "Toward generating a new intrusion detection dataset and intrusion traffic characterization." ICISSP 2018.
