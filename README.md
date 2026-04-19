# WiFi Captive Portal with Federated Filesystem Security

> **Integrated project** — Web Programming (WP1) + System Security (SEC-PRJ-2_23)  
> Platform: Raspberry Pi · Python/Flask · SQLite · Optional Docker demo

## Repository Description

Production-minded Raspberry Pi captive portal built with Flask, Docker, and SQLite, enhanced with federated key-shard exchange to gate secure filesystem access. The platform combines user/device access control, administrative operations, and encrypted storage lifecycle management in a single reproducible IoT security lab.

## Repository Topics

`raspberry-pi`, `captive-portal`, `flask`, `python`, `docker`, `sqlite`, `cybersecurity`, `federation`, `edge-computing`, `luks`, `filesystem-encryption`, `iot-security`

---

## Overview

This project implements a **WiFi captive portal** for IoT devices running on a Raspberry Pi.  
Every device that connects to the Pi's hotspot is redirected to a login/register page before it
can access the internet.  The same Pi participates in a **federated edge network** where the
filesystem is LUKS-encrypted and can only be unlocked after the node collects cryptographic key
shards from its trusted neighbours at boot time.

```
Client device
    │
    │ WiFi (wlan0 / hostapd)
    ▼
Raspberry Pi  ─── iptables DNAT ──►  Captive Portal (Flask :5000)
                                              │
                              ┌───────────────┤
                              │               │
                         Register /        Admin
                          Login             Panel
                              │
                    Authorised MAC ──► internet (eth0)
                              │
                  Federation Agent ──► neighbouring nodes
                              │         (shard exchange)
                              ▼
                   LUKS Secure Partition mounted
```

---

## Project Structure

```
Captive_Portal/
├── README.md
├── instructions.txt           # step-by-step setup guide
├── docker-compose.yml         # two-node demo (portal + neighbour)
│
├── backend/
│   ├── app.py                 # Flask application (all routes)
│   ├── federation.py          # Federation agent + crypto key lifecycle
│   ├── schema.sql             # SQLite schema
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── templates/
│   │   ├── base.html
│   │   ├── portal.html        # Captive portal (login / register)
│   │   ├── dashboard.html     # Authenticated user view
│   │   └── admin.html         # Administrator panel
│   └── static/
│       ├── css/style.css
│       └── js/app.js
│
└── scripts/
    ├── setup_hotspot.sh       # Configure hostapd + dnsmasq
    ├── setup_iptables.sh      # Captive-portal iptables rules
    └── mount_secure_fs.sh     # LUKS partition lifecycle
```

---

## Features

### Web Programming (WP1)

| Requirement | Implementation |
|---|---|
| Register & login with SQL database | `POST /portal/register`, `POST /portal/login` — SQLite via Flask |
| Backend API | Python / Flask exposing REST endpoints |
| Frontend | HTML5 + Bootstrap 5 + vanilla JS (no build step needed) |
| Administrator interface | `/admin` — manage users, devices, federation nodes |
| User interface | `/dashboard` — device status, connection info, security status |

### System Security (SEC-PRJ-2_23)

| Requirement | Implementation |
|---|---|
| Encrypted filesystem (not accessible until boot federation) | LUKS AES-256 partition; demo uses AES-GCM marker |
| Edge federation — ask neighbours for key | `FederationAgent.bootstrap()` — POST to `/federation/provide-shard` |
| Trusted neighbour communication | `federation_nodes` DB table; only `is_trusted=1` nodes can exchange shards |
| Docker container-based | `Dockerfile` + `docker-compose.yml` (two-node setup) |
| MPU / Raspberry Pi | Tested on Raspberry Pi OS Bookworm; scripts use `cryptsetup`, `hostapd` |
| Key splitting | Shamir k-of-n threshold scheme with dynamic quorum policy |

---

## Primary Deployment (Singleton Venv Profiles)

Use one runtime profile everywhere instead of split operational paths.

### Linux / Raspberry Pi profile

```bash
cd Captive_Portal
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt

export RUNTIME_PROFILE=linux-rpi-venv
export NODE_ID=node-1
export NEIGHBOR_NODES=10.0.0.12:5000
python backend/app.py
```

### Windows profile

```powershell
cd Captive_Portal
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt

$env:RUNTIME_PROFILE = "windows-venv"
$env:NODE_ID = "node-1"
$env:NEIGHBOR_NODES = "127.0.0.1:5001"
python backend/app.py
```

## Optional Development Demo (Docker)

### Prerequisites

- Docker + Docker Compose installed on your machine

### Run (dev only)

```bash
cd Captive_Portal
docker compose up --build
```

- **Captive portal** → http://localhost:5000
- **Neighbour node** → http://localhost:5001
- **Admin login**: `admin` / `admin123`

The two nodes will automatically exchange key shards on startup and each
will "mount" its simulated secure partition (AES-GCM encrypted marker file).

---

## Raspberry Pi Deployment

See instructions.txt for the complete step-by-step guide. The short version:

```bash
# 1. Flash Raspberry Pi OS on your SD card and boot.

# 2. Clone / copy the project to the Pi.
scp -r Captive_Portal pi@<pi-ip>:~/

# 3. Set up the WiFi hotspot.
sudo bash scripts/setup_hotspot.sh

# 4. Configure captive-portal iptables rules.
sudo bash scripts/setup_iptables.sh

# 5. Start backend in venv profile mode.
cd Captive_Portal
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
export RUNTIME_PROFILE=linux-rpi-venv
python backend/app.py

# 6. (First boot) Initialise the LUKS secure partition.
sudo bash scripts/mount_secure_fs.sh create
```

---

## API Reference

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/portal` | — | Captive portal page |
| POST | `/portal/register` | — | Register & authorise device |
| POST | `/portal/login` | — | Login & authorise device |
| GET | `/logout` | session | Logout |
| GET | `/dashboard` | user | User dashboard |
| GET | `/admin` | admin | Admin panel |
| GET | `/admin/membership` | admin | Membership summary |
| GET | `/admin/membership/epochs` | admin | Current epoch + epoch history |
| GET | `/admin/membership/leader` | admin | Leader/coordinator diagnostics |
| POST | `/admin/membership/rekey` | admin | Coordinated rekey control |
| POST | `/admin/membership/catchup` | admin | Apply remote catch-up state |
| GET | `/admin/federation/neighbors` | admin | Neighbor scoring diagnostics |
| GET | `/admin/graph` | admin | Logical trust/communication graph |
| POST | `/admin/users/<id>/toggle` | admin | Activate / deactivate user |
| POST | `/admin/users/<id>/delete` | admin | Delete user |
| POST | `/admin/devices/<mac>/authorize` | admin | Authorise device |
| POST | `/admin/devices/<mac>/revoke` | admin | Revoke device access |
| POST | `/admin/devices/<mac>/delete` | admin | Delete device record |
| POST | `/admin/nodes` | admin | Add federation node |
| POST | `/admin/nodes/<id>/trust` | admin | Toggle node trust |
| POST | `/admin/nodes/<id>/delete` | admin | Delete federation node |
| GET | `/federation/info` | — | Node public key info |
| POST | `/federation/provide-shard` | node | Receive key shard (boot) |
| POST | `/federation/request-shard` | node | Request shard for a neighbour |
| POST | `/federation/catchup` | node | Rejoin catch-up payload transfer |
| GET | `/api/status` | — | JSON health check |

---

## Documentation Set

- Deployment: docs/deployment-guide.md
- Operations: docs/operations-runbook.md
- Testing: docs/testing-guide.md
- Completion Summary: docs/completion-summary.md

---

## Changelog vs main

This release branch includes the following major upgrades compared to the baseline main branch state before enhancement execution:

1. Membership and epoch coordination
- Leader-coordinated rekey model with pending queue processing.
- Admin APIs for leader diagnostics and rekey controls.

2. Offline catch-up and stale epoch protection
- Catch-up payload export/import flow for rejoining nodes.
- Explicit stale-epoch rejection in membership transitions.

3. Federation resilience and scoring
- Neighbor telemetry, reliability/latency scoring, and ranked exchange order.
- Admin neighbor diagnostics endpoint.

4. Trust hardening and auditability
- Direct-trust-only enforcement (non-transitive payload rejection).
- Federation trust audit persistence and endpoint-level decision logging.

5. Logical topology observability
- Logical graph API and System tab visualization for trust/communication edges.
- No physical distance, angle, or location modeling.

6. Deployment unification
- Runtime profile loader for linux-rpi-venv and windows-venv singleton operation.
- Docker compose retained only as optional development convenience.
- Shared script profile loader and script normalization.

7. Test consolidation and expansion
- Centralized test bootstrap helper under backend/tests.
- Expanded coverage for membership, catch-up, scoring, trust policy, graph contract, and runtime profile behavior.

8. Milestone documentation set
- Added deployment, operations, testing, and completion runbooks under docs/.

---

## Security Considerations

- **Passwords** are stored as bcrypt-compatible hashes via Werkzeug.
- **Sessions** use Flask's signed cookie with a randomly generated `SECRET_KEY`.
- **MAC spoofing** is a known limitation of MAC-based captive portals; combine
  with WPA2 credentials for higher assurance.
- **Key shards** use Shamir k-of-n threshold sharing with dynamic quorum policy,
  enabling recovery when some neighbours are temporarily offline.
- **TLS**: the Flask server should be placed behind an nginx reverse proxy with
  a self-signed or Let's Encrypt certificate for HTTPS.
- **Production** `SECRET_KEY` and `ADMIN_PASSWORD` must be changed via environment
  variables before deployment.

---

## Technologies Used

| Layer | Technology | Reason |
|---|---|---|
| Language | Python 3.11 | Widely available on Pi; rich crypto ecosystem |
| Web framework | Flask 3 | Lightweight, minimal boilerplate |
| Database | SQLite | No separate server process; ideal for embedded |
| Cryptography | `cryptography` library | RSA key pairs, AES-GCM, LUKS-compatible keys |
| Frontend | Bootstrap 5 + Bootstrap Icons | Responsive, no build tooling required |
| Containers | Docker + Compose | Reproducible deployment; multi-node demo |
| Networking | hostapd + dnsmasq + iptables | Standard Raspberry Pi AP stack |
| Filesystem encryption | LUKS (cryptsetup) | Full-disk AES-256 on the Pi |

---

## Testing Location

All automated tests are centralized in backend/tests and executed with:

```bash
python -m unittest discover -s backend/tests
```

---

## License

See repository root for license details.  Datasets and dependencies are subject
to their own licenses.
