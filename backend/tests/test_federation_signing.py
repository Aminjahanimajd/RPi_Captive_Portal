import unittest
from backend.tests.test_support import ensure_backend_path

ensure_backend_path()

from federation import federation_payload_signature


class FederationSigningTests(unittest.TestCase):
    def test_signature_is_deterministic_for_same_payload(self):
        payload = {
            "node_id": "node-1",
            "timestamp": 1710000000,
            "nonce": "abc123",
            "share_x": 2,
            "epoch_id": "e1",
            "shard": "ZmFrZQ==",
        }
        secret = "cluster-secret"

        sig1 = federation_payload_signature(payload, secret)
        sig2 = federation_payload_signature(payload, secret)
        self.assertEqual(sig1, sig2)

    def test_signature_ignores_signature_field_when_computing(self):
        base_payload = {
            "node_id": "node-2",
            "timestamp": 1710000001,
            "nonce": "nonce-1",
            "share_x": 3,
        }
        secret = "cluster-secret"

        payload_with_signature = dict(base_payload)
        payload_with_signature["signature"] = "tampered"

        sig_base = federation_payload_signature(base_payload, secret)
        sig_with_sig_field = federation_payload_signature(payload_with_signature, secret)
        self.assertEqual(sig_base, sig_with_sig_field)


if __name__ == "__main__":
    unittest.main()
