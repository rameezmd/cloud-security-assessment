
#!/usr/bin/env python3
"""Run four security scanners and produce a unified security report."""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def error_result(message, findings=None):
    findings = findings or []
    return {
        "status": "error",
        "findings": findings,
        "count": len(findings),
        "error": str(message)[:500]
    }


def execute(name, directory, report_dir):
    report = report_dir / "gitleaks.json"

    if name == "sast":
        executable = shutil.which("bandit")
        command = [
            executable, "-r", str(directory),
            "-f", "json", "-q"
        ] if executable else None

    elif name == "dependencies":
        executable = shutil.which("pip-audit")
        requirements = directory / "requirements.txt"

        if not requirements.is_file():
            return {
                "status": "skipped",
                "findings": [],
                "count": 0,
                "note": "No requirements.txt at scan root"
            }

        command = [
            executable, "-r", str(requirements),
            "-f", "json"
        ] if executable else None

    elif name == "secrets":
        executable = shutil.which("gitleaks")
        command = [
            executable, "dir", str(directory),
            "--report-format", "json",
            "--report-path", str(report),
            "--no-banner"
        ] if executable else None

    elif name == "iac":
        executable = shutil.which("checkov")
        command = [
            executable, "-d", str(directory),
            "-o", "json", "--quiet"
        ] if executable else None

    else:
        return error_result("Unknown scanner: " + name)

    if not command:
        return error_result(
            f"{name} executable not found in PATH"
        )

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180,
            check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return error_result(exc)

    if name == "secrets":
        if report.is_file():
            raw = report.read_text(encoding="utf-8")
        elif completed.returncode == 0:
            raw = "[]"
        else:
            return error_result(
                f"Gitleaks did not create a report: "
                f"{completed.stderr}"
            )
    else:
        raw = completed.stdout

    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return error_result(
            f"Invalid JSON from {name}: "
            f"{(completed.stderr or raw)[:350]}"
        )

    findings = []
    errors = []

    if name == "sast":
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("results"), list)
            or not isinstance(data.get("errors"), list)
        ):
            return error_result("Invalid Bandit JSON structure")

        errors.extend(str(x) for x in data["errors"])

        for x in data["results"]:
            if not isinstance(x, dict):
                errors.append("Invalid Bandit finding")
                continue

            findings.append({
                "rule": x.get("test_id"),
                "severity": x.get("issue_severity"),
                "file": x.get("filename"),
                "message": x.get("issue_text")
            })

    elif name == "dependencies":
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("dependencies"), list)
        ):
            return error_result(
                "Invalid pip-audit JSON structure"
            )

        for dependency in data["dependencies"]:
            if (
                not isinstance(dependency, dict)
                or not isinstance(dependency.get("vulns"), list)
            ):
                errors.append(
                    "Invalid pip-audit dependency entry"
                )
                continue

            for vuln in dependency["vulns"]:
                if not isinstance(vuln, dict):
                    errors.append(
                        "Invalid pip-audit vulnerability"
                    )
                    continue

                findings.append({
                    "rule": vuln.get("id"),
                    "severity": "UNKNOWN",
                    "file": dependency.get("name"),
                    "message": str(
                        vuln.get("description", "")
                    )[:200]
                })

    elif name == "secrets":
        if not isinstance(data, list):
            return error_result(
                "Invalid Gitleaks JSON structure"
            )

        for x in data:
            if not isinstance(x, dict):
                errors.append("Invalid Gitleaks finding")
                continue

            findings.append({
                "rule": x.get("RuleID"),
                "severity": "HIGH",
                "file": x.get("File"),
                "message": "Potential exposed secret (redacted)"
            })

    elif name == "iac":
        reports = data if isinstance(data, list) else [data]

        if not reports:
            return error_result("Empty Checkov report")

        for item in reports:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("results"), dict)
                or not isinstance(
                    item["results"].get("failed_checks"), list
                )
            ):
                errors.append(
                    "Invalid Checkov JSON structure"
                )
                continue

            if item.get("error"):
                errors.append(str(item["error"]))

            for check in item["results"]["failed_checks"]:
                if not isinstance(check, dict):
                    errors.append("Invalid Checkov finding")
                    continue

                findings.append({
                    "rule": check.get("check_id"),
                    "severity": (
                        check.get("severity") or "UNKNOWN"
                    ),
                    "file": check.get("file_path"),
                    "message": check.get("check_name")
                })

    if completed.returncode not in (0, 1):
        errors.append(
            f"Unexpected exit code "
            f"{completed.returncode}: "
            f"{completed.stderr[:250]}"
        )

    if (
        completed.returncode == 1
        and not findings
        and not errors
    ):
        errors.append(
            "Exit code 1 with no findings; "
            "scanner may have failed"
        )

    if errors:
        return error_result(
            "; ".join(errors), findings
        )

    return {
        "status": "fail" if findings else "pass",
        "findings": findings,
        "count": len(findings)
    }


def main():
    parser = argparse.ArgumentParser(
        description="Unified security scanner"
    )

    parser.add_argument(
        "--path",
        required=True,
        help="Directory to scan"
    )

    parser.add_argument(
        "--format",
        choices=("json", "text"),
        default="json"
    )

    args = parser.parse_args()
    directory = Path(args.path).resolve()

    if not directory.is_dir():
        parser.error(
            "--path must refer to an existing directory"
        )

    with tempfile.TemporaryDirectory() as tmp:
        results = {
            name: execute(
                name, directory, Path(tmp)
            )
            for name in (
                "sast",
                "dependencies",
                "secrets",
                "iac"
            )
        }

    statuses = {
        item["status"]
        for item in results.values()
    }

    if "error" in statuses:
        decision = "ERROR"
    elif "fail" in statuses:
        decision = "FAIL"
    elif "skipped" in statuses:
        decision = "INCOMPLETE"
    else:
        decision = "PASS"

    output = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "path": str(directory),
        "decision": decision,
        "scanners": results,
        "finding_count": sum(
            item["count"]
            for item in results.values()
        )
    }

    if args.format == "json":
        print(json.dumps(output, indent=2))
    else:
        print(
            f"Decision: {decision} | "
            f"Findings: {output['finding_count']}"
        )

        for name, item in results.items():
            detail = ""

            if item.get("error") or item.get("note"):
                detail = (
                    " - " +
                    str(
                        item.get("error")
                        or item.get("note")
                    )
                )

            print(
                f"{name}: {item['status']} "
                f"({item['count']} findings)"
                f"{detail}"
            )

    return {
        "PASS": 0,
        "FAIL": 1,
        "ERROR": 2,
        "INCOMPLETE": 2
    }[decision]


if __name__ == "__main__":
    sys.exit(main())
