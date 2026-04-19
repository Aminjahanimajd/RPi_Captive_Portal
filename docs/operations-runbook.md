# Operations Runbook

## Daily Checks

1. API liveness:
   - GET /api/status
2. Membership state:
   - GET /admin/membership
   - GET /admin/membership/leader
3. Federation health and ranking:
   - GET /admin/federation/neighbors
4. Logical graph consistency:
   - GET /admin/graph

## Key Rotation Operations

1. Trigger coordinated rekey:
   - POST /admin/membership/rekey
2. Process pending rekeys (leader only):
   - POST /admin/membership/rekey {"process_pending": true}

## Offline Node Rejoin

1. Rejoining node requests catch-up:
   - POST /federation/catchup
2. Apply catch-up at local admin endpoint:
   - POST /admin/membership/catchup
3. Confirm stale epoch rejection behavior if replay occurs.

## Trust Policy

Direct trust only is enforced.

Transitive trust hints are rejected when payload contains fields like:
- via_node
- via_path
- trust_chain
- delegated_by
- transitive

Trust decisions are written to federation_trust_audit.

## Backup and Recovery

1. Backup data directory used by profile:
   - Linux profile default: /var/lib/captive-portal
2. Preserve SQLite database and membership/federation state files.
3. Restore from backup and restart backend process.

## Incident Response

1. If signature/replay errors spike:
   - verify shared secret parity across nodes
   - verify node clock skew
2. If mount fails in linux-rpi-venv mode:
   - inspect LUKS prerequisites and script path
3. If rejoin fails:
   - check epoch mismatch and direct trust status
