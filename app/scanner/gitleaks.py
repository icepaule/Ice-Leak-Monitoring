import json
import subprocess
import logging
import hashlib
import tempfile
import os

from app.config import settings

logger = logging.getLogger(__name__)


def _make_finding_hash(scanner: str, detector: str, repo: str, file_path: str, commit: str, line: int) -> str:
    raw = f"{scanner}:{detector}:{repo}:{file_path}:{commit}:{line}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def scan_cloned_repo(repo_path: str, repo_full_name: str) -> list[dict]:
    """Run Gitleaks against a locally cloned repo. Returns list of finding dicts."""
    findings = []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        report_path = tmp.name

    try:
        result = subprocess.run(
            [
                "gitleaks", "detect",
                f"--source={repo_path}",
                "--report-format=json",
                f"--report-path={report_path}",
                "--no-banner",
            ],
            capture_output=True,
            text=True,
            timeout=settings.gitleaks_timeout,
        )

        # Gitleaks exit code 1 = findings found, 0 = clean
        if os.path.exists(report_path) and os.path.getsize(report_path) > 0:
            with open(report_path) as f:
                try:
                    entries = json.load(f)
                except json.JSONDecodeError:
                    entries = []

            for entry in entries:
                detector_name = entry.get("RuleID", "Unknown")
                file_path = entry.get("File", "")
                commit = entry.get("Commit", "")[:8]
                line_num = entry.get("StartLine", 0)

                finding_hash = _make_finding_hash(
                    "gitleaks", detector_name, repo_full_name, file_path, commit, line_num
                )

                # Map gitleaks tags to severity
                tags = entry.get("Tags", [])
                if "verified" in tags:
                    severity = "critical"
                elif detector_name.lower() in ("privatekey", "aws", "gcp", "azure"):
                    severity = "high"
                else:
                    severity = "medium"

                findings.append({
                    "finding_hash": finding_hash,
                    "scanner": "gitleaks",
                    "detector_name": detector_name,
                    "verified": 0,
                    "file_path": file_path,
                    "commit_hash": commit,
                    "line_number": line_num,
                    "severity": severity,
                })

        logger.info("Gitleaks scan of %s: %d findings", repo_full_name, len(findings))

    except subprocess.TimeoutExpired:
        logger.warning("Gitleaks timeout for %s after %ds", repo_full_name, settings.gitleaks_timeout)
    except FileNotFoundError:
        logger.error("Gitleaks binary not found - is it installed?")
    except Exception:
        logger.exception("Gitleaks error for %s", repo_full_name)
    finally:
        if os.path.exists(report_path):
            os.unlink(report_path)

    return findings
