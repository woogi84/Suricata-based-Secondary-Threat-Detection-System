# ML-NIDS: CIC-IDS2017 기반 머신러닝 네트워크 침입 탐지 시스템

> CIC-IDS2017 공개 데이터셋으로 학습한 Random Forest 분류기를 Docker 기반 실험 환경에 적용,  
> 실제 공격 트래픽을 탐지하는 **엔드-투-엔드 NIDS 파이프라인** 구현 프로젝트

---

## 목차

1. [프로젝트 개요](#프로젝트-개요)
2. [시스템 아키텍처](#시스템-아키텍처)
3. [ML 모델](#ml-모델)
4. [실험 환경](#실험-환경)
5. [파이프라인](#파이프라인)
6. [탐지 결과](#탐지-결과)
7. [도메인 갭 분석](#도메인-갭-분석)
8. [파일 구조](#파일-구조)
9. [실행 방법](#실행-방법)

---

## 프로젝트 개요

상용 IDS(Suricata)는 **시그니처 기반** 탐지로 알려진 공격만 잡습니다.  
이 프로젝트는 **공개 데이터셋(CIC-IDS2017)으로 학습한 ML 모델**을 2차 탐지 레이어로 추가해,  
시그니처에 없는 공격 패턴을 통계적 특징(네트워크 플로우 피처)으로 탐지합니다.

```
[Suricata 1차 탐지] → 시그니처 미탐 트래픽
                              ↓
              [CICFlowMeter 피처 추출]
                              ↓
          [Random Forest 2차 탐지] → 공격 분류
```

**핵심 기여**
- CIC-IDS2017 2,134,160개 플로우 → Random Forest 학습 (정확도 **99.64%**)
- Docker 네트워크 공유 방식(`network_mode: service:target`)으로 Suricata가 공격 트래픽 직접 감시
- tcpdump → CICFlowMeter(Python) → ML 예측의 자동화 파이프라인 구현
- **SSH Brute Force 실시간 탐지 성공** (신뢰도 65~79%)
- 도메인 갭(domain gap) 실증 분석 — CIC 기반 모델의 실전 배포 한계 도출

---

## 시스템 아키텍처

```
┌─────────────────────────────────────────────────────┐
│                  Docker Network (172.20.0.0/24)      │
│                                                     │
│  ┌──────────────┐       공격 트래픽        ┌───────────────────────┐
│  │   Attacker   │ ──────────────────────► │       Target          │
│  │  Kali Linux  │                         │    DVWA + Apache      │
│  │ 172.20.0.20  │                         │    172.20.0.10        │
│  └──────────────┘                         └───────────┬───────────┘
│                                                       │ eth0 공유
│                                           ┌───────────▼───────────┐
│                                           │      Suricata IDS      │
│                                           │  (네트워크 네임스페이스  │
│                                           │   network_mode:        │
│                                           │   service:target)      │
│                                           └───────────┬───────────┘
└───────────────────────────────────────────────────────┘
                                                        │ tcpdump PCAP
                                            ┌───────────▼───────────┐
                                            │    CICFlowMeter        │
                                            │    (피처 추출)          │
                                            └───────────┬───────────┘
                                                        │ CSV (11 피처)
                                            ┌───────────▼───────────┐
                                            │   Random Forest 모델   │
                                            │   (CIC-IDS2017 학습)   │
                                            └───────────┬───────────┘
                                                        │
                                            BENIGN / PortScan / DDoS / Brute
```

**설계 포인트**: Suricata 컨테이너가 Target의 네트워크 네임스페이스를 공유(`network_mode: service:target`)하므로,  
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

타이밍 피처(Flow Duration, Flow Bytes/s, Flow Packets/s)는 환경 의존적이므로 제외.  
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

**호스트 환경**: Windows 11 + WSL2 Ubuntu

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

### SSH Brute Force ✅ 탐지 성공

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

### PortScan ⚠️ 부분 탐지

| 지표 | 값 |
|------|-----|
| prob_PortScan 평균 | 14% |
| prob_PortScan 최대 | 32% |
| prob_BENIGN | 81% (우세) |

### DDoS ❌ 미탐지

| 지표 | 값 |
|------|-----|
| prob_DDoS | 0% |
| 원인 | 도메인 갭 (아래 분석 참고) |

---

## 도메인 갭 분석

SSH Brute Force는 탐지되지만 DDoS/PortScan은 탐지되지 않습니다.  
이는 버그가 아닌 **CIC-IDS2017 기반 모델의 구조적 한계**입니다.

### 핵심 비교

| 공격 | CIC-IDS2017 학습 데이터 | 우리 Docker 실험 환경 | 갭 원인 |
|------|------------------------|----------------------|---------|
| DDoS | flow_byts_s 중간값 **160 B/s** (서버 과부하로 느린 응답) | flow_byts_s 중간값 **714,145 B/s** (Docker 즉각 응답) | Docker 네트워크가 실제 과부하 환경과 달라 타이밍 피처 분포 완전히 다름 |
| DDoS | tot_bwd_pkts 평균 **3.26** (Java CICFlowMeter) | tot_bwd_pkts 평균 **11** (Python CICFlowMeter) | Java/Python CICFlowMeter 간 순수 ACK 패킷 카운팅 방식 차이 |
| PortScan | bwd_pkt_len_mean 중간값 **6 bytes** (타깃 서비스 응답) | bwd_pkt_len_mean **0 bytes** (RST 응답, 데이터 없음) | CIC 학습 환경 타깃에는 SSH/FTP 등 배너 응답 서비스가 동작 중이었음 |
| Brute Force | SSH 프로토콜 표준 패턴 | SSH 프로토콜 표준 패턴 | **동일** → 탐지 성공 |

자세한 분석은 [docs/domain_gap_analysis.md](docs/domain_gap_analysis.md) 참고.

### 결론

ML 기반 NIDS의 실전 배포 시 **도메인 적응(Domain Adaptation)** 이 필수입니다.

- **프로토콜 표준화 수준이 높은 공격** (SSH Brute Force): 환경 무관하게 탐지 가능
- **환경 의존적 공격** (DDoS 타이밍, PortScan 응답 패턴): 학습 환경과 실전 환경의 피처 분포가 달라 오탐 발생
- **실무적 함의**: CIC-IDS2017 모델을 새로운 네트워크에 배포할 때는 해당 환경의 레이블된 트래픽으로 Fine-tuning이 필요

이 분석 자체가 ML 기반 보안 솔루션의 **신뢰성 평가 방법론**으로서 의의가 있습니다.

---

## 파일 구조

```
nids-cic-rf/
├── README.md
│
├── ml/
│   ├── train_rf.py              # Random Forest 학습 스크립트
│   ├── predict_cicflow.py       # CICFlowMeter CSV → 탐지 결과
│   └── results_summary.py      # 탐지 결과 요약 출력 (데모용)
│
├── lab/
│   ├── docker-compose.yml       # 실험 환경 구성
│   ├── attack4.py               # PortScan(SYN) + DDoS(HTTP) + Brute(HTTP POST)
│   ├── pipeline4.sh             # attack4 전체 파이프라인 자동화
│   ├── pipeline5.sh             # SSH Brute Force 파이프라인 자동화
│   ├── setup_ssh.sh             # Target 컨테이너 SSH 서버 설치
│   └── cicflowmeter_patch.md   # CICFlowMeter Python 패키지 패치 가이드
│
├── results/
│   └── predictions_cicflow.csv  # 탐지 결과 샘플 (SSH Brute Force 37건)
│
├── docs/
│   └── domain_gap_analysis.md  # 도메인 갭 상세 분석
│
├── .gitignore
└── requirements.txt
```

> `cic_rf_model.pkl` (31 MB) 과 학습 데이터는 용량 문제로 제외.  
> 모델은 CIC-IDS2017 데이터셋으로 `ml/train_rf.py`를 실행해 직접 생성하세요.

---

## 실행 방법

### 1. 환경 준비

```bash
# 의존성 설치
pip install -r requirements.txt

# Docker 실험 환경 시작
cd lab
docker compose up -d

# Python cicflowmeter 패치 (Java CICFlowMeter 피처 호환)
# 패치 내용: lab/cicflowmeter_patch.md 참고
pip show cicflowmeter | grep Location
```

### 2. 모델 학습

```bash
# CIC-IDS2017 전처리 데이터 필요 (unb.ca/cic/datasets/ids-2017.html)
python ml/train_rf.py path/to/CICIDS_Preprocessed_4class.csv
# → cic_rf_model.pkl, cic_label_map.pkl 생성
```

### 3. 공격 실행 + 탐지

```bash
# SSH Brute Force 탐지 파이프라인 (탐지 성공)
bash lab/pipeline5.sh

# 탐지 결과 확인
python ml/predict_cicflow.py         # cicflow_output.csv 자동 탐지
python ml/results_summary.py         # 결과 요약 출력
```

### 4. 결과 확인 (샘플)

```bash
# 포함된 샘플 데이터로 바로 확인
python ml/results_summary.py results/predictions_cicflow.csv
```

---

## 참고

- [CIC-IDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html)
- [CICFlowMeter (Python)](https://github.com/hieulw/cicflowmeter)
- [Suricata IDS](https://suricata.io/)
- Sharafaldin, I., et al. "Toward generating a new intrusion detection dataset and intrusion traffic characterization." ICISSP 2018.
