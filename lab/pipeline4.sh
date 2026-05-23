#!/bin/bash
# pipeline4.sh - HTTP 기반 공격 파이프라인
# PortScan(SYN) + DDoS(HTTP GET) + Brute Force(HTTP POST)
# → tcpdump → CICFlowMeter → ML 예측

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ATTACK_PY="$SCRIPT_DIR/attack4.py"
OUTPUT="$SCRIPT_DIR/../cicflow_output.csv"

echo "========================================"
echo "[1/5] tcpdump 시작 (suricata eth0)"
echo "========================================"
docker exec suricata bash -c "rm -f /tmp/attack4.pcap; tcpdump -i eth0 -w /tmp/attack4.pcap -q &>/dev/null &"
sleep 2
echo "  캡처 시작됨"

echo ""
echo "========================================"
echo "[2/5] attack4.py 배포 + 실행"
echo "========================================"
docker cp "$ATTACK_PY" attacker:/tmp/attack4.py
docker exec attacker python3 /tmp/attack4.py

echo ""
echo "========================================"
echo "[3/5] tcpdump 중지 + pcap 추출"
echo "========================================"
docker exec suricata bash -c "pkill tcpdump; sleep 2"
docker exec suricata cat /tmp/attack4.pcap > /tmp/attack4_local.pcap
ls -lh /tmp/attack4_local.pcap

echo ""
echo "========================================"
echo "[4/5] CICFlowMeter 변환"
echo "========================================"
cicflowmeter -f /tmp/attack4_local.pcap -c /tmp/cicflow_attack4.csv
echo "  변환 완료"

echo ""
echo "========================================"
echo "[5/5] 복사 + ML 예측"
echo "========================================"
cp /tmp/cicflow_attack4.csv "$OUTPUT"
echo "  cicflow CSV → $OUTPUT"
echo ""
echo "  Windows에서 ML 예측 실행:"
echo "  python ml/predict_cicflow.py"
