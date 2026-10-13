# Security automation

Run Bandit (Python SAST), pip-audit (Python dependency audit), Gitleaks (secret detection) and Checkov (IaC misconfiguration detection). The script aggregates tool-native JSON into one decision. Missing tools, timeouts, and parsing errors result in ERROR, never PASS.

## Prerequisites

Python 3.10+, Bandit, pip-audit, Gitleaks and Checkov installed on PATH. Example Python tool setup:

```bash
python -m pip install bandit pip-audit checkov
```

Install Gitleaks separately from its official release and verify `gitleaks version`. pip-audit's `--path` option audits installed distributions in a directory; it is not a requirements-file parser. For reliable dependency coverage, install project dependencies into a dedicated target directory or extend this adapter to use `pip-audit -r requirements.txt`. A project with no installed packages may produce no dependency findings; this is a known coverage limitation.

## Usage

```bash
python security-automation/security-scan.py --path ./app --format json
python security-automation/security-scan.py --path ./app --format text
```

Exit codes: `0` PASS (all tools completed, zero findings), `1` FAIL (at least one finding), `2` ERROR (tool missing/failed). Use as a CI gate. Findings are not automatically remediated; review false positives and severity manually. This script does not upload source code to a third party.

## Examples / test cases

1. `examples/safe/app.py`: expect no Bandit finding from this file.
2. `examples/insecure/app.py`: Bandit should flag unsafe `subprocess` execution (`shell=True`).
3. `examples/insecure/main.tf`: Checkov should flag an unencrypted public S3 configuration (subject to scanner rule version).

Execute a scan of each directory. Full PASS requires installed tools, compatible versions and adequate dependency scanning inputs. Do not commit real secrets to test the secrets scanner.
