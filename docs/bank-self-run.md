# Bank pilot: run a local cryptographic inventory

Run this pilot on an approved machine inside your organisation. It inventories
certificates, PEM keys and OpenSSL configuration in an approved local directory.
You return a reviewed CycloneDX JSON file and a short brief; we prepare the
assessment manually. No model, API key or hosted scanning service is needed.

This guide uses the `q2quantum` fork's `bank-self-run-guide` branch. Its scanner
code is based on revision `aad97b30ed2f38bbe451716fb50f99fb851cb932`, with the
OpenSSL Groups and ML-DSA certificate fixes. Record the checkout revision for
each run. Do not substitute an upstream release and assume identical results.

## 1. Build and scan

Requirements: Linux or an already configured WSL environment, Git, Go **1.26.8**
or newer compatible with `go.mod`, and Python **3.11+**. OpenSSL is needed only
for the synthetic demonstration below. Docker is not required for directory
scanning. Building downloads public Go dependencies; plan that access separately
from scanning bank files.

```bash
git clone --branch bank-self-run-guide --single-branch \
  https://github.com/q2quantum/cbomkit-theia.git
cd cbomkit-theia
go mod download
go build -o cbomkit-theia .
umask 077
mkdir -p local-output
git rev-parse HEAD > local-output/scanner-revision.txt
printf 'ignore: []\n' > local-output/config.yaml

# Replace this with an approved absolute directory, outside this checkout.
INPUT_DIR=/absolute/path/to/approved-files
./cbomkit-theia dir "$INPUT_DIR" \
  --config local-output/config.yaml \
  --plugins certificates,secrets,opensslconf --log-level error \
  > local-output/cbom.json 2> local-output/scan.stderr
python3 tools/check_handover_cbom.py local-output/cbom.json
```

Keep the `secrets` plugin enabled: it records where private keys are found.
Do not exclude `*.key` just to hide their values. Do not add `--bom`: imported
BOM fields have not been checked by this recipe. Keep output outside the scanned
directory. Inspect any `.cbomkitignore` file in the input and record exclusions.

A scanner exit code alone is insufficient. Review `scan.stderr` locally for
errors, then require the JSON check to pass. The check accepts a non-empty
CycloneDX 1.7 inventory, rejects known private/secret value fields, private-key
PEM text and private JWK fields, and never prints detected values. A malformed
or empty inventory must be investigated rather than handed over as a clean scan.

## 2. Review and return

The checker is a guard against known leakage patterns, **not proof that arbitrary
free text contains no secrets**. Review the complete JSON locally, including
paths, certificate identities and configuration properties. Public certificates
and public-key values are different from private-key material. If a check fails,
keep the output local and report the checker category without the secret value.

After your information owner approves the content, copy it and check the final
file again (also after any approved redaction):

```bash
cp local-output/cbom.json inventory.share.json
python3 tools/check_handover_cbom.py inventory.share.json
sha256sum inventory.share.json
```

Return only **`inventory.share.json`** and **`brief.md`** through the agreed private
channel. Do not send the source directory, private keys, passwords, raw logs or a
zip of the working folder. Do not use GitHub Actions, issues or a public upload
for bank inputs or results. Keep `local-output/scan.stderr` local; logs may contain
file content.

Copy these five fields into `brief.md`:

1. **Scope:** system alias, scan date, checkout revision, JSON SHA-256, approved
   directories, exclusions and errors. Describe any redaction or anonymisation.
2. **Purpose:** what the application does and where the inventoried cryptography
   is used. Use `unknown` where evidence is missing.
3. **Card data:** does this scope store, process or transmit cardholder data?
   Answer `yes`, `no` or `unknown`, with a short explanation.
4. **Coverage and constraints:** deployment and compatibility requirements,
   external TLS endpoints, HSM/KMS or other components not in the files, planned
   replacements and relevant deadlines. Do not provide access credentials.
5. **Review:** technical contact and confirmation that the information owner has
   approved this exact JSON for transfer.

This is a file inventory, not a source-code algorithm scan (that uses
[sonar-cryptography](https://github.com/cbomkit/sonar-cryptography)), live TLS scan,
trust validation or compliance certification. The secret detector skips files
over 1 MiB; DER-only and base64-only private keys are outside this PEM demonstration.
An absent finding does not establish that a directory contains no keys.

## 3. Reproduce the synthetic key check

From this checkout, after building the binary:

```bash
bash tools/test_bank_self_run.sh
```

The test generates disposable RSA, extensionless EC and encrypted PEM keys,
runs the same scan flags and checks the output. It requires each private-key
location to remain in the inventory and compares the complete JSON against the
known PEM bodies and DER/base64 encodings. It also verifies that deliberately
inserted private values are rejected. Generated keys and logs stay in a temporary
directory and are not uploaded. A successful run writes
`bank-self-run-validation.json` with counts and pass/fail results only.
