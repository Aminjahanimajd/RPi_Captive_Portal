# RPi Captive Portal: 0-100 Professor Guide

This note teaches the project from zero setup to full security demonstration.

It is written to support both course dimensions:

- Web Programming: Flask architecture, templates, session/auth, API design, frontend integration.
- System Security: federation trust model, signature verification, anti-replay controls, threshold secret sharing, encrypted storage lifecycle.

## 1. Project objective

The system is a captive portal running on Raspberry Pi or containerized development nodes.

Functional objective:

- Force users through registration/login before normal access.
- Manage users, devices, and federation nodes from admin panel.

Security objective:

- Protect secure files behind multi-layer policy checks.
- Coordinate trusted federation members for shard exchange.
- Reject forged/replayed/transitive federation messages.

## 2. High-level architecture

Main runtime pieces:

- Flask backend: route handling, auth/session, admin APIs, federation APIs, secure file APIs.
- Membership manager: trusted-node lifecycle, epoch history, leader coordination.
- Federation agent: Shamir shard generation/assignment/exchange/reconstruction, mount backend selection.
- SQLite state: users/devices/nodes/access logs + federation nonce/audit tables.
- Secure store: protected files under data/secure_store.
- Ops scripts: hotspot, firewall, LUKS management for Raspberry Pi deployment.

Boot sequence:

1. Runtime profile is loaded.
2. DB schema/migrations are initialized.
3. Membership state is loaded and synchronized with DB node table.
4. Federation bootstrap thread starts.
5. Node attempts shard exchange with ranked neighbors.
6. If threshold reached, key reconstructs and mount is attempted.
7. If bootstrap cannot complete, local fallback path mounts for availability.

## 3. Security model and controls

Confidentiality controls:

- Secure files are served only when secure partition state is mounted.
- Download API blocks path traversal and hidden marker files.

Integrity/authenticity controls:

- Federation payloads are HMAC-SHA256 signed.
- Canonical JSON serialization is used before signing.
- Signature comparison uses constant-time digest comparison.

Replay controls:

- Each federation payload must include signature, nonce, timestamp.
- Timestamp must be within skew window.
- Nonce must be unique per node_id; duplicates are rejected.

Trust boundary controls:

- Direct-trust-only payload policy rejects transitive fields: via_node, via_path, trust_chain, delegated_by, transitive.
- Sender must be trusted in federation_nodes table and trusted in membership state.
- All accept/reject trust decisions are persisted in federation_trust_audit.

Access policy controls for secure file APIs:

1. Authenticated session.
2. Active user account.
3. Mounted secure partition.
4. Known authorized device for user MAC.
5. Safe validated file path.

## 4. Algorithms and formulas used

## 4.1 Shamir split/recover over GF(2^8)

Implemented in federation engine:

- GF multiply/inverse/division with AES polynomial 0x11B.
- Byte-wise random polynomial generation for each secret byte.
- Lagrange interpolation at x=0 for reconstruction.

Behavior:

- Master key length: 32 bytes.
- Shares: k-of-n.
- Reconstruction requires at least k unique x coordinates.

## 4.2 Threshold selection strategy

Two threshold strategies exist in this codebase:

- Default federation shard generation uses:
  - k = clamp(ceil(0.6 * n), 2, min(7, n))
- Membership key-rotation planning uses strict-majority expression:
  - k = max(2, floor((n + 1) / 2) + 1)

## 4.3 Neighbor ranking algorithm

For each neighbor:

- reliability = (successes + 1) / (attempts + 2)
- latency_factor = 1 - (bounded_latency_ms / 5000)
- score = 0.7 * reliability + 0.3 * latency_factor

Neighbors are sorted by descending score, then by neighbor string.

## 4.4 Signature algorithm

Signing pipeline:

1. Remove signature field from payload if present.
2. Canonicalize JSON with sorted keys and compact separators.
3. Compute HMAC-SHA256 with shared secret.
4. Store hex digest in payload signature.

## 4.5 Anti-replay algorithm

Verification pipeline:

1. Validate signature/nonce/timestamp fields exist.
2. Validate timestamp integer and skew bound.
3. Recompute expected signature and constant-time compare.
4. Insert (node_id, nonce) into unique table.
5. Reject on integrity error (replay).

## 5. Repository walkthrough (file -> role -> strategy)

Root:

- README.md: overall architecture, deployment paths, endpoint list.
- docker-compose.yml: two-node dev topology and environment defaults.

Backend core:

- backend/app.py
  - Role: web entrypoint and route controller.
  - Strategy: decorators for auth/role, trust-validation pipeline, secure file gate algorithm, graph/status APIs.
- backend/federation.py
  - Role: cryptographic lifecycle and mount orchestration.
  - Strategy: GF arithmetic + Shamir, signed exchange payloads, neighbor scoring, LUKS/simulation backends.
- backend/membership.py
  - Role: membership state machine.
  - Strategy: deterministic leader selection, pending rekey queue, epoch rotation/transition checks.
- backend/runtime_profile.py
  - Role: singleton profile default injector.
  - Strategy: profile-specific env defaults for windows-venv and linux-rpi-venv.
- backend/schema.sql
  - Role: relational schema for users/devices/nodes/nonces/audit/logs.
  - Strategy: normalized tables + unique constraints for identity and replay safety.
- backend/requirements.txt
  - Role: runtime dependency list.
- backend/Dockerfile
  - Role: container image build instructions.

Frontend:

- backend/templates/base.html: common layout + Bootstrap assets.
- backend/templates/portal.html: register/login page.
- backend/templates/dashboard.html: authenticated user state and secure files UI.
- backend/templates/admin.html: admin operations across users/devices/nodes/membership/graph.
- backend/static/js/app.js: client-side validation, admin POST wrappers, graph rendering.
- backend/static/css/style.css: visual styling.

Scripts:

- scripts/load_profile.sh: shared shell profile defaults.
- scripts/setup_hotspot.sh: AP setup with idempotency, backup, dry-run, logging.
- scripts/setup_iptables.sh: captive redirect + MAC allowlist chains + persistence.
- scripts/mount_secure_fs.sh: LUKS create/open/close/status with safety checks and key wipe.

Tests:

- backend/tests/test_federation_shamir.py: split/recover and catch-up cases.
- backend/tests/test_federation_signing.py: canonical signing behavior.
- backend/tests/test_federation_neighbor_scoring.py: ranking and diagnostics behavior.
- backend/tests/test_federation_mount_modes.py: mount mode and fallback logic.
- backend/tests/test_membership.py: membership transitions and epoch logic.
- backend/tests/test_app_membership_api.py: trust hardening, catch-up, and API contracts.
- backend/tests/test_runtime_profile.py: profile default behavior.
- backend/tests/test_pi_scripts.py: shell script hardening checks.
- backend/tests/test_support.py: test path bootstrap helper.

Docs:

- docs/deployment-guide.md
- docs/operations-runbook.md
- docs/testing-guide.md
- docs/completion-summary.md
- docs/project-guide-0-100.md

## 6. Complete tools and libraries used

Python runtime and packages:

- Python 3.11: backend runtime.
- Flask: routing, template rendering, session handling.
- Werkzeug: password hashing and verification utilities.
- cryptography: RSA keypair operations and AES-GCM marker encryption.
- requests: federation HTTP communication with neighbors.
- sqlite3 (stdlib): embedded persistence layer.
- hashlib, hmac, secrets, threading, pathlib, subprocess, time, json (stdlib): crypto/signing, randomness, orchestration, serialization.

Frontend libraries:

- Bootstrap 5.3 (CDN): layout/components.
- Bootstrap Icons (CDN): iconography.
- Vanilla JavaScript Fetch API: async admin operations and graph fetch.

Container and OS tools:

- Docker + Docker Compose: reproducible two-node development environment.
- hostapd: WiFi access point service.
- dnsmasq: DHCP/DNS for captive network.
- iptables + iptables-save + iptables-persistent: NAT, redirect, and MAC authorization enforcement.
- cryptsetup: LUKS encryption and unlock operations.
- mkfs.ext4, mount, umount: filesystem provisioning/mount lifecycle.
- shred: secure key-file wipe in tmpfs workflow.
- systemctl, ip, apt-get, curl: service/network/package and diagnostics tooling.

Testing tools:

- Python unittest: automated backend and script behavior checks.

## 7. Setup from zero to working result (sequential)

This section is the full start-to-finish setup path.

## 7.1 Prerequisites

Minimum:

- Git
- Python 3.11+
- Docker Desktop (for easiest two-node professor demo)

Raspberry Pi production path additionally needs:

- hostapd, dnsmasq, iptables-persistent, cryptsetup
- root privileges for scripts

## 7.2 Clone and enter project

```bash
git clone https://github.com/Aminjahanimajd/RPi_Captive_Portal.git
cd RPi_Captive_Portal
```

## 7.3 Two-node Docker run

```bash
docker compose up --build
```

Open both nodes:

- node-1 portal: http://localhost:5000
- node-2 portal: http://localhost:5001

Default admin on each node:

- username: admin
- password: admin123

Important behavior note:

- On fresh start, nodes are not yet mutually trusted in each local DB.
- Federation API calls are therefore rejected until you register/trust neighbors on both nodes.

## 7.4 Configure mutual federation trust (required for shard exchange)

Perform in admin UI on node-1 (localhost:5000):

1. Open Federation Nodes tab.
2. Add node:
   - node_id: node-2
   - hostname: neighbor
   - ip_address: neighbor
   - port: 5000
   - shared_secret: same value as FEDERATION_SHARED_SECRET in compose.
3. Toggle trust to Trusted.

Perform in admin UI on node-2 (localhost:5001):

1. Add node-1 with hostname portal and port 5000.
2. Toggle trust to Trusted.

## 7.5 Re-run bootstrap so ranked exchange executes with trusted peers

Because bootstrap runs at process start, restart both services after trust setup:

```bash
docker compose restart portal neighbor
```

After restart, each node can pass trust + signature checks and exchange shards.

## 7.6 Verify federation state and shard collection

Run:

```bash
curl http://localhost:5000/api/status
curl http://localhost:5001/api/status
```

Look for:

- status = running
- federation.scheme = shamir-k-of-n
- federation.ranked_neighbors populated
- federation.shards_collected >= 1 (after successful exchange)
- federation.is_mounted = true

Also inspect neighbor diagnostics in admin System tab or API:

- GET /admin/federation/neighbors (requires admin session)

## 7.7 Prove secure file access path end-to-end

1. Register a normal user from portal page.
2. Login as that user.
3. Open dashboard and load secure files (GET /api/files).
4. Download shared/welcome.txt (GET /api/files/shared/welcome.txt).

Expected:

- File list and download succeed only after authentication + authorized device + mounted secure state.

## 7.8 Optional audit evidence for professor

Use SQLite inspection on node DB to show trust/replay controls persisted:

- federation_nonce_log contains used nonces.
- federation_trust_audit contains accepted/rejected decisions and reasons.

## 8. Windows venv path (single-node learning mode)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt

$env:RUNTIME_PROFILE = "windows-venv"
$env:NODE_ID = "node-1"
$env:NEIGHBOR_NODES = ""
python backend/app.py
```

Validation:

```powershell
curl http://localhost:5000/api/status
```

Use this path to study web flow and security gates locally.

## 9. Raspberry Pi profile path (hotspot + firewall + LUKS)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt

export RUNTIME_PROFILE=linux-rpi-venv
export NODE_ID=node-1
export NEIGHBOR_NODES=10.0.0.12:5000
export FEDERATION_SHARED_SECRET=<cluster-secret>
```

Configure networking:

```bash
sudo bash scripts/setup_hotspot.sh
sudo bash scripts/setup_iptables.sh setup
```

Initialize encrypted partition once:

```bash
sudo bash scripts/mount_secure_fs.sh create
```

Run backend:

```bash
python backend/app.py
```

## 10. Test execution and what it proves

Run all tests:

```bash
python -m unittest discover -s backend/tests
```

Focused suite examples:

```bash
python -m unittest backend.tests.test_federation_shamir
python -m unittest backend.tests.test_federation_signing
python -m unittest backend.tests.test_federation_neighbor_scoring
python -m unittest backend.tests.test_membership
python -m unittest backend.tests.test_app_membership_api
python -m unittest backend.tests.test_runtime_profile
python -m unittest backend.tests.test_pi_scripts
```

Security confidence gained from passing tests:

- Correct threshold split/recovery behavior.
- Deterministic signature and verification compatibility.
- Direct-trust and anti-replay API enforcement.
- Membership epoch and coordination logic consistency.
- Mount-mode fallback and script hardening checks.

## 11. Demonstration script for professor presentation

Recommended live sequence:

1. Show API health on both nodes (/api/status).
2. Show trusted membership and leader status (/admin/membership, /admin/membership/leader).
3. Show neighbor ranking (/admin/federation/neighbors).
4. Explain direct-trust-only rule and replay rejection pipeline.
5. Login as normal user and open dashboard.
6. Show secure file list and download success.
7. Show audit tables proving trust and nonce tracking.

Main teaching message:

- This project combines web programming and system security into one coordinated pipeline where policy checks, cryptography, and operational controls all contribute to secure access.

## 12. Final conclusion

This repository is a full 0-100 educational implementation of a secure edge captive portal:

- It demonstrates practical Flask web engineering.
- It demonstrates applied cryptographic and trust controls.
- It demonstrates deployment on both development and Raspberry Pi operational contexts.
- It provides testable and auditable evidence for each security strategy used.

It is suitable as an academic project because every major design choice is visible in code, reproducible in setup, and explainable with concrete algorithms.

From zero setup to advanced security behavior, this project teaches a complete lifecycle:

- Build and run a real Flask captive portal.
- Manage users/devices/admin workflows.
- Coordinate trusted federation membership and epoch transitions.
- Exchange and verify signed shard payloads.
- Reconstruct master keys via threshold algorithm.
- Gate secure data access on cryptographic and policy checks.
- Operate and validate the system with scripts, APIs, and tests.

That is the full 0-100 journey for both web programming and system security in one cohesive Raspberry Pi-oriented project.
