#!/bin/bash

set -e

echo "🔄 Killing existing cloudflared instances..."
pkill -f cloudflared 2>/dev/null || true

echo "🔄 Starting Cloudflare Tunnel in background..."
nohup /usr/bin/cloudflared tunnel run \
  --token "eyJhIjoiZDRmNjVkMDQyNTZjMWRjNzY4ZGI3YmY2NWQzODE0NTEiLCJ0IjoiZWVlNmVkYjUtMjE1MC00YzQxLWE1NTktMDE1YjA5MjkyOTYxIiwicyI6Ik16VTVaamd3T0dZdE1UYzNZaTAwWmpka0xXRTNNMlV0WlRNNU0yWmpZamRpTlRFeiJ9" \
  > tunnel.log 2>&1 &

echo "🔄 Restarting Python Server..."
pkill -f "python3 server.py" 2>/dev/null || true

nohup python3 server.py > server.log 2>&1 &

sleep 2

if pgrep -f "python3 server.py" > /dev/null; then
    echo "✅ Python server started successfully."
else
    echo "❌ Python server failed to start."
    tail -n 30 server.log
    exit 1
fi

if pgrep -f cloudflared > /dev/null; then
    echo "✅ Cloudflare Tunnel started successfully."
else
    echo "❌ Cloudflare Tunnel failed to start."
    tail -n 30 tunnel.log
    exit 1
fi

echo "✅ Done! Visit: https://api.alii.uk"
