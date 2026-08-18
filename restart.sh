#!/bin/bash
echo "🔄 Killing existing cloudflared instances..."
pkill -f cloudflared
echo "🔄 Starting Cloudflare Tunnel in background..."
nohup /usr/bin/cloudflared tunnel run --token eyJhIjoiZDRmNjVkMDQyNTZjMWRjNzY4ZGI3YmY2NWQzODE0NTEiLCJ0IjoiZWUxNmVkYjUtMjE1MC00YzQxLWE1NTktMDE1YjA5MjkyOTYxIiwicyI6Ik16VTVaamd3T0dZdE1UYzNZaTAwWmpka0xXRTNNMlV0WlRNNU0yWmpZamRpTlRFeiJ9 > tunnel.log 2>&1 &
echo "🔄 Restarting Python Server..."
pkill -f server.py
nohup python3 server.py > server.log 2>&1 &
echo "✅ Done! Visit: https://api.alii.uk"
