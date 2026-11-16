#!/usr/bin/env bash
set -euo pipefail

# Run with root/docker privileges to deploy switch-server container and open 39107/TCP.
cd /home/ai-agent/switch-server

if command -v docker >/dev/null 2>&1; then
  if docker compose version >/dev/null 2>&1; then
    docker compose up -d --build
  else
    docker build -t switch-server:latest .
    docker rm -f switch-server >/dev/null 2>&1 || true
    docker run -d \
      --name switch-server \
      --user 1003:1003 \
      --restart unless-stopped \
      -e TZ=Asia/Shanghai \
      -p 0.0.0.0:39107:39107/tcp \
      -v /home/ai-agent/switch-server/config.json:/home/ai-agent/switch-server/config.json:ro \
      -v /home/ai-agent/switch-server/data:/home/ai-agent/switch-server/data \
      switch-server:latest
  fi
fi

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow 39107/tcp comment "Switch parental heartbeat"
elif command -v iptables >/dev/null 2>&1; then
  if ! iptables -C INPUT -p tcp --dport 39107 -j ACCEPT >/dev/null 2>&1; then
    iptables -I INPUT -p tcp --dport 39107 -j ACCEPT
  fi
fi
