import re
import os
import logging
import hashlib

logger = logging.getLogger(__name__)

# Built-in patterns for MHB / Orange Cyber Defense
BUILTIN_PATTERNS: list[tuple[str, str, str]] = [
    # (pattern_name, regex, severity)
    ("MHB Domain", r"(?i)muenchener[\-_\s]*hypothekenbank|mhb\.de|muehyp\.de", "high"),
    ("MHB Email", r"[a-zA-Z0-9_.+-]+@mhb\.de", "high"),
    ("MHB IBAN", r"DE\d{2}\s*7002\s*0270\s*\d{4}\s*\d{4}\s*\d{2}", "critical"),
    ("MHB BLZ", r"\b7002\s*0270\b", "medium"),
    ("Orange CD", r"(?i)orangecyberdefense|orange[\-_\s]*cyber[\-_\s]*defense", "medium"),
    ("Internal IP Range", r"\b10\.10\.\d{1,3}\.\d{1,3}\b", "medium"),
    ("Internal IP 172", r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b", "low"),
    ("Private Key Header", r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "critical"),
    ("German ID Number", r"\b[A-Z0-9]{9,10}\b.{0,20}(?i)(personalausweis|ausweisnummer)", "high"),
]

# File extensions to scan
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".sh", ".bash",
    ".yml", ".yaml", ".json", ".xml", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".txt", ".md", ".rst", ".csv", ".sql", ".tf", ".hcl",
    ".dockerfile", ".properties", ".gradle",
}

# Files to always skip
SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "venv"}
MAX_FILE_SIZE = 1_000_000  # 1 MB


def _make_finding_hash(detector: str, repo: str, file_path: str, line: int) -> str:
    raw = f"custom:{detector}:{repo}:{file_path}::{line}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def scan_cloned_repo(repo_path: str, repo_full_name: str, extra_patterns: list[tuple[str, str, str]] | None = None) -> list[dict]:
    """Scan a cloned repo with custom regex patterns. Returns list of finding dicts."""
    findings = []
    patterns = BUILTIN_PATTERNS.copy()
    if extra_patterns:
        patterns.extend(extra_patterns)

    compiled = [(name, re.compile(regex), sev) for name, regex, sev in patterns]

    for root, dirs, files in os.walk(repo_path):
        # Skip irrelevant dirs
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for fname in files:
            _, ext = os.path.splitext(fname)
            if ext.lower() not in SCAN_EXTENSIONS and fname not in (".env", "Dockerfile", "Makefile"):
                continue

            fpath = os.path.join(root, fname)

            try:
                if os.path.getsize(fpath) > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            rel_path = os.path.relpath(fpath, repo_path)

            try:
                with open(fpath, "r", errors="ignore") as f:
                    for line_num, line_text in enumerate(f, start=1):
                        for pattern_name, regex, severity in compiled:
                            if regex.search(line_text):
                                finding_hash = _make_finding_hash(
                                    pattern_name, repo_full_name, rel_path, line_num
                                )
                                findings.append({
                                    "finding_hash": finding_hash,
                                    "scanner": "custom",
                                    "detector_name": pattern_name,
                                    "verified": 0,
                                    "file_path": rel_path,
                                    "commit_hash": "",
                                    "line_number": line_num,
                                    "severity": severity,
                                })
            except Exception:
                continue

    logger.info("Custom scan of %s: %d findings", repo_full_name, len(findings))
    return findings
