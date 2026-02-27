import json
import subprocess
import logging
import hashlib
from typing import Optional

from app.config import settings

logger = logging.getLogger(__name__)


def _make_finding_hash(scanner: str, detector: str, repo: str, file_path: str, commit: str, line: int) -> str:
    raw = f"{scanner}:{detector}:{repo}:{file_path}:{commit}:{line}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def scan_repo(repo_url: str, repo_full_name: str) -> list[dict]:
    """Run TruffleHog against a git repo URL. Returns list of finding dicts."""
    findings = []
    try:
        result = subprocess.run(
            ["trufflehog", "git", repo_url, "--json", "--no-update", "--no-verification"],
            capture_output=True,
            text=True,
            timeout=settings.trufflehog_timeout,
        )

        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Extract detector type safely
            detector_type = entry.get("DetectorType", "")
            if isinstance(detector_type, int):
                detector_name = entry.get("DetectorName", f"Detector-{detector_type}")
            else:
                detector_name = str(detector_type) or entry.get("DetectorName", "Unknown")

            source_meta = entry.get("SourceMetadata", {}).get("Data", {}).get("Git", {})
            file_path = source_meta.get("file", "")
            commit = source_meta.get("commit", "")[:8]
            line_num = source_meta.get("line", 0)
            verified = entry.get("Verified", False)

            finding_hash = _make_finding_hash(
                "trufflehog", detector_name, repo_full_name, file_path, commit, line_num
            )

            severity = "critical" if verified else "high"

            findings.append({
                "finding_hash": finding_hash,
                "scanner": "trufflehog",
                "detector_name": detector_name,
                "verified": 1 if verified else 0,
                "file_path": file_path,
                "commit_hash": commit,
                "line_number": line_num,
                "severity": severity,
                "matched_snippet": entry.get("Raw", "")[:500],
            })

        logger.info("TruffleHog scan of %s: %d findings", repo_full_name, len(findings))

    except subprocess.TimeoutExpired:
        logger.warning("TruffleHog timeout for %s after %ds", repo_full_name, settings.trufflehog_timeout)
    except FileNotFoundError:
        logger.error("TruffleHog binary not found - is it installed?")
    except Exception:
        logger.exception("TruffleHog error for %s", repo_full_name)

    return findings
