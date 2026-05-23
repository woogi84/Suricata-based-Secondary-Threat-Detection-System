#!/bin/bash
# setup_ssh.sh - Target 컨테이너(DVWA/Debian 9)에 SSH 서버 설치
#
# 사용법:
#   docker exec target bash < lab/setup_ssh.sh
#
# 참고: Debian 9 (stretch) 이므로 archive.debian.org 사용
# apt-get 기본 키 검증 실패 → --allow-unauthenticated 필요

# stretch 아카이브로 소스 교체 (미설정 시 패키지 없음 오류)
cat > /etc/apt/sources.list << 'EOF'
deb http://archive.debian.org/debian stretch main contrib non-free
EOF

apt-get update -qq --allow-unauthenticated 2>&1 | tail -3
apt-get install -y --allow-unauthenticated --no-install-recommends openssh-server 2>&1 | tail -3

mkdir -p /var/run/sshd
echo "root:rootpass" | chpasswd
sed -i 's/#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config

/usr/sbin/sshd -D &
sleep 1
ss -tlnp 2>/dev/null | grep 22 || echo "port 22 status unknown"
echo "SSH 설치 완료 (root / rootpass)"
