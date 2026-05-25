# 도메인 갭 분석 — CIC-IDS2017 모델의 실전 배포 한계

## 개요

CIC-IDS2017 데이터셋으로 학습한 Random Forest 모델을 Docker 기반 실험 환경에 배포했을 때,  
SSH Brute Force는 탐지되었지만 DDoS와 PortScan은 탐지에 실패했습니다.

---

## 공격별 탐지 결과

| 공격 | 결과 | 탐지율 | 평균 신뢰도 |
|------|------|--------|------------|
| SSH Brute Force | 탐지 성공 | 37/37 (100%) | 76% |
| PortScan (TCP SYN) | 부분 탐지 | prob_PortScan 최대 32% | — |
| DDoS (HTTP GET flood) | 미탐지 | prob_DDoS ≈ 0% | — |

---

## 핵심 피처 분포 비교

### SSH Brute Force — 탐지 성공

| 피처 | CIC 학습 데이터 (중간값) | Docker 실험 환경 (중간값) | 차이 |
|------|------------------------|--------------------------|------|
| dst_port | 22 | 22 | 동일 |
| tot_fwd_pkts | 15.0 | 15.5 | ≈ 동일 |
| tot_bwd_pkts | 17.0 | 17.5 | ≈ 동일 |
| totlen_fwd_pkts | 1,620 bytes | 1,690 bytes | ≈ 동일 |
| totlen_bwd_pkts | 2,350 bytes | 2,390 bytes | ≈ 동일 |
| SYN=1, PSH=1, ACK=1 | ✓ | ✓ | 동일 |

**결론**: SSH 프로토콜은 RFC 표준이 정형화되어 있어 어느 환경에서도  
핸드셰이크 + 키 교환 + 인증 교환의 패킷 수와 크기가 거의 동일합니다.

---

### DDoS (HTTP GET flood) — 미탐지

| 피처 | CIC 학습 데이터 | Docker 실험 환경 | 갭 원인 |
|------|----------------|-----------------|---------|
| flow_byts_s (제거됨) | 중간값 **160 B/s** | 중간값 **714,145 B/s** | 서버 과부하 상태 차이 |
| tot_bwd_pkts | 평균 **3.26** | 평균 **11** | Java/Python CICFlowMeter 카운팅 방식 차이 |
| totlen_bwd_pkts | 중간값 **0 bytes** | 중간값 **9,088 bytes** | 서버 응답 크기 차이 |

**갭 원인 1 — 서버 과부하 환경 차이:**

CIC-IDS2017의 DDoS 학습 데이터는 실제 서버가 과부하 상태에서 캡처되었습니다.  
서버가 요청을 제때 처리하지 못하므로 `flow_byts_s`가 160 B/s로 낮습니다.  
반면 Docker 환경에서는 서버가 즉시 응답해 714,145 B/s로 4,400배 차이가 납니다.

> 이 피처는 환경 의존성이 너무 강해 모델에서 제거했지만,  
> 제거 후에도 다른 피처들의 분포 차이가 남아 있습니다.

**갭 원인 2 — Java vs Python CICFlowMeter:**

Java CICFlowMeter는 순수 ACK 패킷(페이로드=0)을 플로우 패킷 카운트에서 제외합니다.  
Python cicflowmeter는 ACK 패킷도 카운트합니다.  
그 결과 `tot_bwd_pkts`가 Java에서는 평균 3.26, Python에서는 평균 11로 3배 차이납니다.

---

### PortScan (TCP SYN) — 미탐지

| 피처 | CIC 학습 데이터 | Docker 실험 환경 | 갭 원인 |
|------|----------------|-----------------|---------|
| bwd_pkt_len_mean | 중간값 **6 bytes** | 중간값 **0 bytes** | 타깃 서비스 응답 차이 |
| tot_bwd_pkts | 중간값 **1** | 중간값 **1** | 동일 |
| SYN Flag Count | 1 | 1 | 동일 |

**갭 원인 — 타깃 서비스 응답 패턴:**

CIC 학습 환경의 타깃 서버에는 SSH(포트 22), FTP(포트 21) 등 실제 서비스가 동작 중이었습니다.  
열린 포트에서는 SYN-ACK + 서비스 배너(6바이트 이상)를 응답해  
`bwd_pkt_len_mean` 중간값이 6 bytes입니다.

Docker DVWA 타깃은 대부분의 포트가 닫혀 있어 RST 패킷(페이로드=0 bytes)만 응답합니다.  
따라서 `bwd_pkt_len_mean`이 0으로, 모델은 이를 정상으로 판단합니다.

---

## 도메인 갭 요약표

| 공격 | 학습 환경 | 실험 환경 | 갭 원인 | 탐지 성공 여부 |
|------|-----------|-----------|---------|--------------|
| Brute Force | SSH 표준 패턴 | SSH 표준 패턴 | 없음 | ✅ |
| DDoS | 서버 과부하, ACK 미카운트 | 즉각 응답, ACK 카운트 | 타이밍 + 툴 차이 | ❌ |
| PortScan | 서비스 배너 응답 | RST 응답 | 환경 서비스 구성 차이 | ❌ |

---

## 시사점

### ML 기반 NIDS의 실전 배포 시 고려사항

1. **프로토콜 표준화 수준이 높은 공격**은 환경에 관계없이 잘 탐지됩니다.  
   SSH, TLS 핸드셰이크, DNS 쿼리 등 RFC로 정형화된 프로토콜 기반 공격이 이에 해당합니다.

2. **환경 의존적 공격**은 학습 환경과 실전 환경 사이에 도메인 갭이 발생합니다.  
   - 타이밍 피처(flow_byts_s, flow_duration): 서버 부하, 네트워크 지연에 따라 크게 변함  
   - 응답 패턴 피처(bwd_pkt_len_mean): 타깃 서비스 구성에 따라 달라짐

3. **CICFlowMeter 버전 불일치**는 카운팅 방식 차이로 피처 값에 3배 이상 오차를 낼 수 있습니다.  
   학습에 사용한 툴과 동일한 버전/구현을 배포 환경에서도 사용해야 합니다.

### 실무적 함의

- CIC-IDS2017 기반 모델을 새로운 네트워크에 배포할 때는  
  해당 환경의 레이블된 트래픽으로 **Fine-tuning** 또는 **재학습**이 필요합니다.
- 또는 환경 의존적 피처를 제거하고 프로토콜 불변 피처(flag count, port number 등)만  
  사용하는 **피처 선택**이 효과적인 대안이 될 수 있습니다.
- **도메인 적응(Domain Adaptation)** 연구가 ML 기반 NIDS의 핵심 과제입니다.

---

## 참고: 사용된 피처 (11개)

타이밍 피처(`Flow Duration`, `Flow Bytes/s`, `Flow Packets/s`)는 환경 의존성이 너무 강해 제외했습니다.  
`Average Packet Size`는 Java/Python CICFlowMeter 간 계산 방식 차이(TCP 페이로드 기준 vs. IP 전체 길이)로  
인한 도메인 갭이 크기 때문에 제외했습니다.

| 피처 | 중요도 | 비고 |
|------|--------|------|
| Destination Port | 24.6% | 프로토콜/서비스 식별 |
| Total Length of Fwd Packets | 19.2% | 요청 크기 |
| Fwd Packet Length Mean | 12.5% | 평균 요청 패킷 크기 |
| Total Fwd Packets | 11.7% | 전송 패킷 수 |
| Bwd Packet Length Mean | 10.4% | 평균 응답 패킷 크기 |
| Total Length of Bwd Packets | 8.5% | 응답 크기 |
| PSH Flag Count | 5.0% | 데이터 전송 플래그 |
| Total Backward Packets | 5.0% | 응답 패킷 수 |
| ACK Flag Count | 2.4% | 확인 응답 플래그 |
| SYN Flag Count | 0.7% | 연결 시작 플래그 |
| RST Flag Count | 0.0% | 연결 리셋 플래그 |
