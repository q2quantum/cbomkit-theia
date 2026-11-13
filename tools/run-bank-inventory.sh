#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PQCA Contributors
set -euo pipefail
umask 077
if [ "$#" -ne 2 ]; then
  echo 'Usage: run-inventory.sh APPROVED_INPUT_DIRECTORY LOCAL_OUTPUT_DIRECTORY' >&2
  exit 2
fi
package_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
command -v python3 >/dev/null
command -v openssl >/dev/null
input_dir="$(realpath -- "$1")"
output_dir="$(realpath -m -- "$2")"
test -d "$input_dir"
python3 - "$input_dir" "$output_dir" <<'PY'
from pathlib import Path
import sys
source, output = map(lambda value: Path(value).resolve(), sys.argv[1:])
if output == source or source in output.parents:
    raise SystemExit('Output must be outside the input directory')
if (output / 'cbom.json').exists():
    raise SystemExit('Existing inventory: choose a new output directory')
PY
mkdir -p -- "$output_dir"
printf 'ignore: []\n' > "$output_dir/config.yaml"
cp -- "$package_dir/REVISION" "$output_dir/scanner-revision.txt"
openssl version > "$output_dir/openssl-version.txt"
"$package_dir/cbomkit-theia" dir "$input_dir" --config "$output_dir/config.yaml" \
  --plugins certificates,secrets,opensslconf --log-level error \
  > "$output_dir/cbom.json" 2> "$output_dir/scan.stderr"
python3 "$package_dir/check_handover_cbom.py" "$output_dir/cbom.json"
echo 'Scan and covered leakage checks passed. Review the JSON and stderr locally before sharing.'
