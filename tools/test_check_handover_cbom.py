#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PQCA Contributors
"""Synthetic, offline regression tests; never generate or use real secrets."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from check_handover_cbom import check_document

SENTINEL = "SYNTHETIC_VALUE_MUST_NEVER_APPEAR_IN_OUTPUT"
HERE = Path(__file__).resolve().parent


def cbom(material_type="private-key", value=None):
    material = {"type": material_type, "size": 2048}
    if value is not None:
        material["value"] = value
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
        "components": [{"type": "cryptographic-asset", "name": "RSA-2048",
                        "cryptoProperties": {"assetType": "related-crypto-material",
                                             "relatedCryptoMaterialProperties": material},
                        "evidence": {"occurrences": [{"location": "synthetic/server.key"}]}}],
    }


class HandoverTests(unittest.TestCase):
    def run_cli(self, content, expected):
        with tempfile.TemporaryDirectory(prefix="handover-test-", dir=HERE) as directory:
            path = Path(directory) / "synthetic.json"
            path.write_text(content, encoding="utf-8")
            run = subprocess.run([sys.executable, str(HERE / "check_handover_cbom.py"), str(path)],
                                 capture_output=True, text=True, encoding="utf-8", timeout=10)
        self.assertEqual(run.returncode, expected, run.stdout + run.stderr)
        self.assertNotIn(SENTINEL, run.stdout + run.stderr)
        self.assertNotIn("synthetic/server.key", run.stdout + run.stderr)
        self.assertEqual(run.stderr, "")
        return json.loads(run.stdout)

    def test_key_metadata_and_location_are_preserved_without_value(self):
        document = cbom()
        before = deepcopy(document)
        result = check_document(document)
        self.assertEqual(document, before)
        self.assertEqual(result["findings"], {})
        self.assertTrue(result["manual_review_required"])
        self.run_cli(json.dumps(document), 0)

    def test_public_key_value_is_allowed_and_preserved(self):
        document = cbom("public-key", SENTINEL)
        before = deepcopy(document)
        self.assertEqual(check_document(document)["findings"], {})
        self.assertEqual(document, before)
        self.run_cli(json.dumps(document), 0)

    def test_sensitive_material_values_are_rejected(self):
        for kind in ("private-key", "secret-key", "password", "token", "key", "unknown", "seed"):
            with self.subTest(kind=kind):
                result = self.run_cli(json.dumps(cbom(kind, SENTINEL)), 1)
                self.assertEqual(result["findings"]["nonpublic_material_value"], 1)

    def test_capitalized_value_is_checked(self):
        document = cbom()
        document["components"][0]["cryptoProperties"]["relatedCryptoMaterialProperties"]["Value"] = SENTINEL
        self.run_cli(json.dumps(document), 1)

    def test_private_pem_in_nested_escaped_json_string(self):
        for kind in ("PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY"):
            with self.subTest(kind=kind):
                document = cbom("public-key", f"-----BEGIN {kind}-----\n{SENTINEL}\n-----END {kind}-----")
                document["metadata"] = {"properties": [{"value": json.dumps({"nested": document["components"]})}]}
                self.run_cli(json.dumps(document), 1)

    def test_pem_in_property_name_is_detected(self):
        document = cbom()
        document["metadata"] = {"-----BEGIN PRIVATE KEY-----": SENTINEL}
        self.run_cli(json.dumps(document), 1)

    def test_private_jwk_fields_and_encoded_jwk_are_rejected(self):
        for jwk in ({"kty": "RSA", "n": "public", "e": "AQAB", "d": SENTINEL},
                    {"kty": "EC", "crv": "P-256", "x": "public", "d": SENTINEL},
                    {"kty": "OKP", "crv": "Ed25519", "x": "public", "d": SENTINEL},
                    {"kty": "oct", "k": SENTINEL}):
            for encoded in (False, True):
                document = cbom()
                document["metadata"] = {"test_jwk": json.dumps(jwk) if encoded else jwk}
                self.run_cli(json.dumps(document), 1)

    def test_public_jwk_is_allowed(self):
        document = cbom()
        document["metadata"] = {"jwk": {"kty": "RSA", "n": "public", "e": "AQAB"}}
        self.run_cli(json.dumps(document), 0)

    def test_malformed_jwk_is_invalid_not_pass(self):
        for jwk in (None, {}, {"k": SENTINEL}, {"kty": None}, {"kty": "RSA", "d": None}, {"kty": "RSA", "oth": SENTINEL}):
            document = cbom()
            document["metadata"] = {"jwk": jwk}
            self.run_cli(json.dumps(document), 2)

    def test_bad_json_null_duplicate_keys_and_nan_are_invalid(self):
        for content in ("null", "[]", '{"broken":"' + SENTINEL, '{"a":1,"a":2}', '{"n":NaN}'):
            self.run_cli(content, 2)

    def test_malformed_envelopes_and_components_are_invalid(self):
        variants = []
        for field, value in (("specVersion", "1.6"), ("version", True), ("components", []), ("components", [None])):
            document = cbom()
            document[field] = value
            variants.append(document)
        document = cbom()
        document["components"][0]["cryptoProperties"]["relatedCryptoMaterialProperties"]["value"] = None
        variants.append(document)
        for malformed_type in (None, [], {}, "unsupported"):
            document = cbom()
            document["components"][0]["cryptoProperties"]["assetType"] = malformed_type
            variants.append(document)
        for document in variants:
            self.run_cli(json.dumps(document), 2)


if __name__ == "__main__":
    unittest.main()
