#!/usr/bin/env bash
# Synthetic inputs only. No keys, input files or scanner logs are published.
set -euo pipefail
umask 077
task_dir="$(mktemp -d)"
trap 'rm -rf -- "$task_dir"' EXIT
mkdir -p "$task_dir/input/state" "$task_dir/output"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$task_dir/input/server.key" 2> "$task_dir/output/keygen.log"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 \
  -out "$task_dir/input/state/k1" 2>> "$task_dir/output/keygen.log"
openssl pkcs8 -topk8 -in "$task_dir/input/server.key" -out "$task_dir/input/encrypted.pem" \
  -passout pass:synthetic-test-only 2>> "$task_dir/output/keygen.log"
openssl pkey -in "$task_dir/input/server.key" -outform DER -out "$task_dir/output/rsa.der"
openssl pkey -in "$task_dir/input/state/k1" -outform DER -out "$task_dir/output/ec.der"
printf 'ignore: []\n' > "$task_dir/output/config.yaml"
if [ -n "${BANK_PACKAGE_DIR:-}" ]; then
  bash "$BANK_PACKAGE_DIR/run-inventory.sh" "$task_dir/input" "$task_dir/output"
else
./cbomkit-theia dir "$task_dir/input" \
  --config "$task_dir/output/config.yaml" \
  --plugins certificates,secrets,opensslconf --log-level error \
  > "$task_dir/output/cbom.json" 2> "$task_dir/output/scan.stderr"
fi
python3 tools/check_handover_cbom.py "$task_dir/output/cbom.json"
python3 tools/test_check_handover_cbom.py
python3 - "$task_dir" <<'PY'
import base64
import copy
import json
import pathlib
import subprocess
import sys

task = pathlib.Path(sys.argv[1])
raw = (task / 'output/cbom.json').read_text(encoding='utf-8')
bom = json.loads(raw)
expected = {'server.key', 'state/k1', 'encrypted.pem'}
found = set()
private_components = []
for component in bom.get('components', []):
    material = component.get('cryptoProperties', {}).get('relatedCryptoMaterialProperties', {})
    if material.get('type') != 'private-key':
        continue
    private_components.append(component)
    assert not material.get('value'), 'Private-key value found'
    for occurrence in component.get('evidence', {}).get('occurrences', []):
        location = occurrence.get('location', '').replace('\\', '/')
        for relative in expected:
            if location == relative or location.endswith('/' + relative):
                found.add(relative)
assert found == expected, 'Expected private-key location missing'

strings = []
def collect(value):
    if isinstance(value, str):
        strings.append(value)
    elif isinstance(value, list):
        for item in value:
            collect(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            collect(key)
            collect(item)
collect(bom)
serialized_strings = '\n'.join(strings)
compact = ''.join(serialized_strings.split())
for relative in expected:
    pem = (task / 'input' / relative).read_text(encoding='ascii')
    body = ''.join(line for line in pem.splitlines() if not line.startswith('-----'))
    der = base64.b64decode(body)
    assert pem not in raw and body not in compact, 'Known PEM payload leaked'
    assert der.hex() not in serialized_strings.lower(), 'Known DER hex leaked'
    assert base64.b64encode(der).decode('ascii') not in compact, 'Known DER base64 leaked'
for name in ('rsa.der', 'ec.der'):
    der = (task / 'output' / name).read_bytes()
    assert der.hex() not in serialized_strings.lower(), 'Re-encoded DER hex leaked'
    assert base64.b64encode(der).decode('ascii') not in compact, 'Re-encoded DER base64 leaked'

for label, value in (('private-value', base64.b64encode((task / 'output/rsa.der').read_bytes()).decode('ascii')),
                     ('private-pem', (task / 'input/server.key').read_text(encoding='ascii'))):
    altered = copy.deepcopy(bom)
    if label == 'private-value':
        item = next(c for c in altered['components'] if c.get('cryptoProperties', {}).get('relatedCryptoMaterialProperties', {}).get('type') == 'private-key')
        item['cryptoProperties']['relatedCryptoMaterialProperties']['value'] = value
    else:
        altered['metadata']['leak-demonstration'] = value
    path = task / 'output' / (label + '.json')
    path.write_text(json.dumps(altered), encoding='utf-8')
    result = subprocess.run([sys.executable, 'tools/check_handover_cbom.py', str(path)], capture_output=True, text=True)
    assert result.returncode == 1, 'Injected private value was not rejected'
    assert value not in result.stdout + result.stderr, 'Checker printed a private value'

summary = {'passed': True, 'synthetic_only': True, 'private_key_locations_expected': 3,
           'private_key_locations_found': len(found), 'private_value_fields': 0,
           'known_pem_der_base64_hex_payloads_absent': True, 'injected_leaks_rejected': 2,
           'model_calls': 0}
pathlib.Path('bank-self-run-validation.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
print(json.dumps(summary, indent=2))
PY
