#!/bin/bash
echo "🔄 Killing existing cloudflared instances..."
pkill -f cloudflared
echo "🔄 Starting Cloudflare Tunnel in background..."
nohup /usr/bin/cloudflared tunnel run --token eyJhIjoiZDRmNjVkMDQyNTZjMWRjNzY4ZGI3YmY2NWQzODE0NTEiLCJ0IjoiMWY3MDI0ZGEtZmJhMy00ZjkxLWEzMWEtZWZmOWFmN2I3NTg0IiwicyI6Ik56ZG1NbVZoWW1RdFpqZGxNaTAwWkdReExUaG1OemN0W1mFeU1tWmxOakl5TVRjMCJ9 > tunnel.log 2>&1 &
echo "🔄 Restarting Python Server..."
pkill -f server.py
nohup python3 server.py > server.log 2>&1 &
echo "✅ Done! Visit: https://api.alii.uk"