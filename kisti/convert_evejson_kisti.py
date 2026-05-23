"""
eve.json -> KISTI 포맷 CSV 매핑

출력 컬럼 (KISTI 10컬럼 + packetSize):
  uid, sourceIP, destinationIP, sourcePort, destinationPort,
  protocol, attackType, eventCount, analyResult, duration, packetSize

제외 컬럼: payload, orgIDX, detectName, jumboPayloadFlag, directionType

Usage:
  python convert_evejson_kisti.py [eve.json] [output.csv]
"""
import csv
import json
import sys
from datetime import datetime
from pathlib import Path

BASE_DIR    = Path(__file__).parent
INPUT_PATH  = Path(sys.argv[1]) if len(sys.argv) > 1 else BASE_DIR / 'eve.json'
OUTPUT_PATH = Path(sys.argv[2]) if len(sys.argv) > 2 else BASE_DIR / 'suricata_kisti_mapped.csv'

PROTO_MAP = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'ICMPv6': 58, 'SCTP': 132}

COLUMNS = [
    'uid', 'sourceIP', 'destinationIP', 'sourcePort', 'destinationPort',
    'protocol', 'attackType', 'eventCount', 'analyResult', 'duration', 'packetSize',
]

def classify_attacktype(signature):
    """Suricata alert signature → KISTI attackType"""
    if not signature:
        return 0
    sig = signature.upper()
    if any(k in sig for k in ['SCAN', 'SWEEP', 'NMAP', 'MASSCAN', 'PORT SCAN']):
        return 4
    if any(k in sig for k in ['MALWARE', 'TROJAN', 'WORM', 'BOTNET', 'VIRUS', 'RANSOMWARE']):
        return 1
    if any(k in sig for k in ['WEB_SERVER', 'WEB_CLIENT', 'SQL', 'XSS', 'LFI', 'RFI',
                               'WEBSHELL', 'PHP', 'CMS', 'WORDPRESS', 'JOOMLA']):
        return 2
    if any(k in sig for k in ['EXPLOIT', 'OVERFLOW', 'RCE', 'CVE', 'DOS', 'DDOS',
                               'SHELLCODE', 'STREAM', 'SMB', 'RDP', 'SSH']):
        return 3
    return 0

def calc_duration(flow, timestamp):
    """flow.age 우선, 없으면 flow.start~end 차이(초)"""
    age = flow.get('age')
    if age is not None:
        return int(age)
    try:
        start = flow.get('start', timestamp)
        end   = flow.get('end')
        if start and end:
            return int((datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds())
    except Exception:
        pass
    return None

def main():
    total   = 0
    written = 0
    errors  = 0

    with open(INPUT_PATH, 'r', encoding='utf-8', errors='replace') as fin, \
         open(OUTPUT_PATH, 'w', newline='', encoding='utf-8') as fout:

        writer = csv.DictWriter(fout, fieldnames=COLUMNS)
        writer.writeheader()

        for line in fin:
            total += 1
            line = line.strip()
            if not line:
                continue

            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                errors += 1
                continue

            event_type = ev.get('event_type', '')
            if event_type not in ('flow', 'alert'):
                continue

            flow  = ev.get('flow')  or {}
            alert = ev.get('alert') or {}

            proto_str = ev.get('proto', '').upper()

            pkts_ts    = flow.get('pkts_toserver') or 0
            pkts_tc    = flow.get('pkts_toclient') or 0
            total_pkts = pkts_ts + pkts_tc

            bytes_ts    = flow.get('bytes_toserver') or 0
            bytes_tc    = flow.get('bytes_toclient') or 0
            total_bytes = bytes_ts + bytes_tc

            attack_type = classify_attacktype(alert.get('signature', ''))

            writer.writerow({
                'uid':             ev.get('flow_id', ''),
                'sourceIP':        ev.get('src_ip', ''),
                'destinationIP':   ev.get('dest_ip', ''),
                'sourcePort':      ev.get('src_port'),
                'destinationPort': ev.get('dest_port'),
                'protocol':        PROTO_MAP.get(proto_str, 0),
                'attackType':      attack_type,
                'eventCount':      total_pkts or None,
                'analyResult':     1 if attack_type > 0 else 0,
                'duration':        calc_duration(flow, ev.get('timestamp', '')),
                'packetSize':      total_bytes or None,
            })
            written += 1

            if total % 100_000 == 0:
                print(f'\r처리: {total:,}줄 | 저장: {written:,}건 | 오류: {errors}건', end='', flush=True)

    print(f'\n완료: 총 {total:,}줄 처리 | {written:,}건 저장 | {errors}건 파싱 오류')
    print(f'출력 파일: {OUTPUT_PATH}')

if __name__ == '__main__':
    main()
