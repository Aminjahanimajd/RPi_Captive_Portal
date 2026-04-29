# Testing Guide

All tests are centralized under backend/tests.

## Run Full Suite

- python -m unittest discover -s backend/tests

## Run Targeted Suites

- Membership and app integration:
  - python -m unittest backend.tests.test_membership backend.tests.test_app_membership_api
- Federation crypto and scoring:
  - python -m unittest backend.tests.test_federation_shamir backend.tests.test_federation_signing backend.tests.test_federation_neighbor_scoring
- Runtime/deployment behavior:
  - python -m unittest backend.tests.test_runtime_profile backend.tests.test_pi_scripts backend.tests.test_federation_mount_modes

## CI Path

GitHub workflow runs backend test discovery in backend/tests.

## Expected Warnings

Some environments may log simulation fallback warnings when cryptography/LUKS prerequisites are intentionally absent in test environments.
