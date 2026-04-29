# Deployment Guide

This guide describes end-to-end deployment using singleton runtime profiles.

## 1. Linux/Raspberry Pi Deployment

1. Install Python 3.11+ and system prerequisites:
   - hostapd, dnsmasq, iptables-persistent, cryptsetup
2. Clone the repository and open project root.
3. Create and activate venv:
   - python3 -m venv .venv
   - source .venv/bin/activate
4. Install backend dependencies:
   - pip install -r backend/requirements.txt
5. Set runtime profile and node identity:
   - export RUNTIME_PROFILE=linux-rpi-venv
   - export NODE_ID=node-1
   - export NEIGHBOR_NODES=10.0.0.12:5000
   - export FEDERATION_SHARED_SECRET=<cluster-secret>
6. Configure networking scripts:
   - sudo bash scripts/setup_hotspot.sh
   - sudo bash scripts/setup_iptables.sh setup
7. Start backend:
   - python backend/app.py

## 2. Windows Deployment (Development/Validation)

1. Install Python 3.11+.
2. Create and activate venv:
   - py -m venv .venv
   - .\.venv\Scripts\Activate.ps1
3. Install dependencies:
   - pip install -r backend/requirements.txt
4. Set environment:
   - $env:RUNTIME_PROFILE = "windows-venv"
   - $env:NODE_ID = "node-1"
   - $env:NEIGHBOR_NODES = "127.0.0.1:5001"
   - $env:FEDERATION_SHARED_SECRET = "<cluster-secret>"
5. Start backend:
   - python backend/app.py

## 3. Optional Docker Development Demo

Docker is optional and intended for local multi-node demonstrations only.

- docker compose up --build

## 4. Verification

1. Open portal page.
2. Validate admin dashboard access.
3. Check API status:
   - GET /api/status
4. Confirm membership and federation diagnostics:
   - GET /admin/membership
   - GET /admin/federation/neighbors
   - GET /admin/graph
