# CICFlowMeter Python 패키지 패치

## 목적

Python `cicflowmeter` 패키지(v0.1.6)의 패킷 길이 계산 방식을 Java CICFlowMeter와 호환시켜  
CIC-IDS2017 학습 데이터와 동일한 피처 값을 추출합니다.

## 패치 위치

```bash
# 설치 경로 확인
pip show cicflowmeter | grep Location
# 예: /home/user/.local/lib/python3.10/site-packages

# 패치 대상 파일
${LOCATION}/cicflowmeter/features/packet_length.py
```

## 패치 내용

### `get_packet_length()` — TCP/UDP 페이로드 기준으로 변경

**원본 (IP 전체 길이 기반):**
```python
def get_packet_length(self, packet_direction=None) -> list:
    ...
    if packet_direction is not None:
        return [len(packet) for packet, direction in ...
                if direction == packet_direction]
    return [len(packet) for packet, _ in ...]
```

**패치 후 (TCP/UDP 페이로드 기반):**
```python
def get_packet_length(self, packet_direction=None) -> list:
    def _payload_len(pkt):
        if "TCP" in pkt:
            return len(pkt["TCP"].payload)
        if "UDP" in pkt:
            return len(pkt["UDP"].payload)
        return len(pkt)

    if packet_direction is not None:
        return [_payload_len(packet) for packet, direction in
                self.feature_extractor.packets
                if direction == packet_direction]
    return [_payload_len(packet) for packet, _ in
            self.feature_extractor.packets]
```

## 패치 이유

CIC-IDS2017 모델은 Java CICFlowMeter로 추출한 피처로 학습되었으므로 
Python 패키지도 동일한 방식으로 계산해야 피처 분포가 일치합니다.

## 검증

패치 후 SSH Brute Force 실험:
- `fwd_pkt_len_mean` ≈ 107~115 bytes (학습 데이터 중간값 113 bytes와 일치)
- `bwd_pkt_len_mean` ≈ 123~147 bytes (학습 데이터 중간값 139 bytes와 일치)
- → **37/37 flows 탐지 성공 (신뢰도 65~79%)**
