import subprocess
import json
import logging
import tempfile
import os
import glob as globmod

from app.config import settings

logger = logging.getLogger(__name__)

BLACKBIRD_DIR = "/opt/blackbird"
BLACKBIRD_SCRIPT = os.path.join(BLACKBIRD_DIR, "blackbird.py")


def _run_blackbird(args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    """Run blackbird.py from its install directory."""
    return subprocess.run(
        ["python3", BLACKBIRD_SCRIPT] + args,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=BLACKBIRD_DIR,
    )


def search_username(username: str) -> list[dict]:
    """Use Blackbird to search for a username across platforms.
    Returns list of found accounts with platform info."""
    if not settings.blackbird_enabled:
        return []

    if not os.path.isfile(BLACKBIRD_SCRIPT):
        logger.warning("Blackbird not installed at %s, skipping OSINT search", BLACKBIRD_SCRIPT)
        return []

    results = []

    try:
        result = _run_blackbird(
            ["--username", username, "--json", "--no-nsfw", "--no-update", "--timeout", "20"],
            timeout=120,
        )

        # Blackbird writes JSON to results/<username>/...
        results_dir = os.path.join(BLACKBIRD_DIR, "results")
        json_files = globmod.glob(os.path.join(results_dir, "**", "*.json"), recursive=True)

        for fpath in json_files:
            try:
                with open(fpath) as f:
                    data = json.load(f)

                entries = data if isinstance(data, list) else [data]
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    status = entry.get("status", "")
                    if status.upper() == "FOUND":
                        results.append({
                            "platform": entry.get("app", entry.get("name", "Unknown")),
                            "url": entry.get("url", entry.get("uri_check", "")),
                            "username": username,
                        })
            except (json.JSONDecodeError, OSError):
                continue

        # Clean up results dir to avoid stale data
        import shutil
        if os.path.isdir(results_dir):
            shutil.rmtree(results_dir, ignore_errors=True)

        logger.info("Blackbird search for '%s': %d accounts found", username, len(results))

    except subprocess.TimeoutExpired:
        logger.warning("Blackbird timeout for '%s'", username)
    except FileNotFoundError:
        logger.warning("Blackbird not found, skipping OSINT search")
    except Exception:
        logger.exception("Blackbird error for '%s'", username)

    return results


def search_email(email: str) -> list[dict]:
    """Use Blackbird to search for an email across platforms."""
    if not settings.blackbird_enabled or not os.path.isfile(BLACKBIRD_SCRIPT):
        return []

    results = []

    try:
        result = _run_blackbird(
            ["--email", email, "--json", "--no-nsfw", "--no-update", "--timeout", "20"],
            timeout=120,
        )

        results_dir = os.path.join(BLACKBIRD_DIR, "results")
        json_files = globmod.glob(os.path.join(results_dir, "**", "*.json"), recursive=True)

        for fpath in json_files:
            try:
                with open(fpath) as f:
                    data = json.load(f)
                entries = data if isinstance(data, list) else [data]
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    if entry.get("status", "").upper() == "FOUND":
                        results.append({
                            "platform": entry.get("app", entry.get("name", "Unknown")),
                            "url": entry.get("url", entry.get("uri_check", "")),
                            "username": email,
                        })
            except (json.JSONDecodeError, OSError):
                continue

        import shutil
        if os.path.isdir(results_dir):
            shutil.rmtree(results_dir, ignore_errors=True)

        logger.info("Blackbird email search for '%s': %d accounts found", email, len(results))

    except subprocess.TimeoutExpired:
        logger.warning("Blackbird timeout for email '%s'", email)
    except Exception:
        logger.exception("Blackbird error for email '%s'", email)

    return results


def search_keywords_for_accounts(keywords: list[str]) -> dict[str, list[dict]]:
    """Search Blackbird for accounts matching keywords.
    Handles usernames and emails separately."""
    all_results = {}

    for keyword in keywords:
        term = keyword.strip()
        if len(term) < 3 or len(term) > 60:
            continue

        if "@" in term:
            accounts = search_email(term)
        elif " " not in term:
            accounts = search_username(term)
        else:
            continue

        if accounts:
            all_results[term] = accounts

    return all_results
