#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PQCA Contributors
"""Check known secret-leak patterns before sharing a CycloneDX 1.7 CBOM.

Exit 0: no covered pattern found; manual review is still required.
Exit 1: a covered leak pattern was found; do not share this file.
Exit 2: unreadable JSON or unsupported/malformed input; do not share it.

This is a conservative handover check, not full JSON Schema validation or a
guarantee that every secret is absent. It does not redact or rewrite anything.
Output contains only fixed labels and counts, never input values or locations.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 128
MAX_NODES = 500_000
PRIVATE_PEM = re.compile(
    r"-----\s*(?:BEGIN|END)\s+(?:[A-Z0-9]+[ \t]+)*PRIVATE[ \t]+KEY(?:[ \t]+BLOCK)?\s*-----",
    re.IGNORECASE,
)
PUBLIC_MATERIAL_TYPES = {
    "public-key", "ciphertext", "signature", "digest", "initialization-vector", "nonce", "salt",
}
JWK_TYPES = {"rsa", "ec", "okp", "oct"}
COMPONENT_TYPES = {
    "application", "framework", "library", "container", "platform", "operating-system",
    "device", "device-driver", "firmware", "file", "machine-learning-model", "data", "cryptographic-asset",
}
CRYPTO_ASSET_TYPES = {"algorithm", "certificate", "protocol", "related-crypto-material"}
JWK_PRIVATE_FIELDS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
JWK_STRING_FIELDS = {"kty", "n", "e", "crv", "x", "y", "d", "p", "q", "dp", "dq", "qi", "k"}


class InvalidInput(ValueError):
    """A fixed-message error: never include untrusted input in diagnostics."""


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidInput("duplicate_json_key")
        result[key] = value
    return result


def reject_constant(_value):
    raise InvalidInput("non_json_number")


def parse_json(text):
    return json.loads(text, object_pairs_hook=unique_object, parse_constant=reject_constant)


def check_document(document):
    """Return fixed labels/counts only; leave the input and public values intact."""
    if not isinstance(document, dict):
        raise InvalidInput("object_required")
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.7":
        raise InvalidInput("cyclonedx_1_7_required")
    version = document.get("version")
    if type(version) is not int or version < 1:
        raise InvalidInput("positive_bom_version_required")
    components = document.get("components")
    if not isinstance(components, list) or not components:
        raise InvalidInput("nonempty_components_required")
    for component in components:
        if not isinstance(component, dict):
            raise InvalidInput("component_object_required")
        if not all(isinstance(component.get(field), str) and component[field].strip()
                   for field in ("type", "name")):
            raise InvalidInput("component_type_and_name_required")
        if component["type"] not in COMPONENT_TYPES:
            raise InvalidInput("unsupported_component_type")
        if "cryptoProperties" in component or component["type"] == "cryptographic-asset":
            crypto = component.get("cryptoProperties")
            if (not isinstance(crypto, dict) or not isinstance(crypto.get("assetType"), str)
                    or crypto["assetType"] not in CRYPTO_ASSET_TYPES):
                raise InvalidInput("invalid_crypto_properties")
            if crypto["assetType"] == "related-crypto-material" and "relatedCryptoMaterialProperties" not in crypto:
                raise InvalidInput("related_material_required")

    findings = Counter()
    visited = 0

    def walk(value, depth=0):
        nonlocal visited
        visited += 1
        if depth > MAX_DEPTH or visited > MAX_NODES:
            raise InvalidInput("inspection_limit_exceeded")
        if isinstance(value, str):
            findings["private_key_pem"] += len(PRIVATE_PEM.findall(value))
            # A JWK is sometimes stored as a JSON-encoded string in a property.
            if value.lstrip().startswith(("{", "[")):
                try:
                    decoded = parse_json(value)
                except (ValueError, RecursionError):
                    # Ordinary prose may start with a brace. Malformed JWK text
                    # is still unsafe when it declares a JWK key type.
                    if re.search(r'"kty"\s*:', value):
                        raise InvalidInput("malformed_encoded_jwk") from None
                else:
                    walk(decoded, depth + 1)
        elif isinstance(value, list):
            for item in value:
                walk(item, depth + 1)
        elif isinstance(value, dict):
            if "kty" in value:
                if not isinstance(value["kty"], str) or value["kty"].lower() not in JWK_TYPES:
                    raise InvalidInput("invalid_jwk_type")
                for field in JWK_STRING_FIELDS & value.keys():
                    if not isinstance(value[field], str) or not value[field]:
                        raise InvalidInput("invalid_jwk_field")
                if "oth" in value and not isinstance(value["oth"], list):
                    raise InvalidInput("invalid_jwk_other_primes")
                findings["jwk_private_field"] += sum(bool(value.get(field)) for field in JWK_PRIVATE_FIELDS)
            for key, child in value.items():
                if key.lower() == "relatedcryptomaterialproperties":
                    if not isinstance(child, dict) or not isinstance(child.get("type"), str) or not child["type"].strip():
                        raise InvalidInput("invalid_related_material")
                    material_type = child["type"].lower().replace("_", "-")
                    for field, material_value in child.items():
                        if field.lower() == "value":
                            if not isinstance(material_value, str):
                                raise InvalidInput("invalid_related_material_value")
                            if material_value and material_type not in PUBLIC_MATERIAL_TYPES:
                                findings["nonpublic_material_value"] += 1
                if key.lower() == "jwk" and (not isinstance(child, dict) or "kty" not in child):
                    raise InvalidInput("invalid_jwk_object")
                walk(key, depth + 1)
                walk(child, depth + 1)

    walk(document)
    counts = {name: count for name, count in sorted(findings.items()) if count}
    return {
        "status": "risk_found" if counts else "no_known_leak_pattern_found",
        "components": len(components), "findings": counts,
        "manual_review_required": True,
        "scope": "known_patterns_only_not_a_guarantee_of_secret_absence",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cbom", type=Path, help="local CBOM JSON file to inspect")
    args = parser.parse_args(argv)
    try:
        with args.cbom.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise InvalidInput("input_too_large")
        document = parse_json(raw.decode("utf-8-sig"))
        result = check_document(document)
    except (OSError, UnicodeError, ValueError, RecursionError):
        # Exception text can contain JSON excerpts, filenames, and secret values.
        print(json.dumps({"status": "invalid_input", "manual_review_required": True}))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 1 if result["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
