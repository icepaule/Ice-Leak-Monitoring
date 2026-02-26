"""Subfinder OSINT module - Subdomain enumeration."""

import logging
import subprocess

logger = logging.getLogger(__name__)


def run_subfinder(domain: str, timeout: int = 120) -> list[str]:
    """Run subfinder against a domain and return discovered subdomains."""
    subdomains = []

    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-timeout", "30"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if line and "." in line:
                subdomains.append(line.lower())

        subdomains = list(set(subdomains))
        logger.info("Subfinder for '%s': %d subdomains found", domain, len(subdomains))

    except FileNotFoundError:
        logger.warning("subfinder binary not found, skipping")
    except subprocess.TimeoutExpired:
        logger.warning("subfinder timeout for '%s'", domain)
    except Exception:
        logger.exception("subfinder error for '%s'", domain)

    return subdomains
