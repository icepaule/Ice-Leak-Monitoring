"""GitDorker OSINT module - GitHub dork search using existing GitHub API."""

import logging
import time

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# Predefined GitHub dork patterns
DORK_PATTERNS = [
    ('filename:.env', '.env file'),
    ('filename:credentials', 'credentials file'),
    ('filename:config.json', 'config.json'),
    ('filename:secrets', 'secrets file'),
    ('filename:id_rsa', 'SSH private key'),
    ('"password"', 'password reference'),
    ('"secret_key"', 'secret key reference'),
    ('"api_key"', 'API key reference'),
    ('"access_token"', 'access token reference'),
    ('"private_key"', 'private key reference'),
    ('filename:.htpasswd', 'htpasswd file'),
    ('filename:wp-config.php', 'WordPress config'),
]

GITHUB_SEARCH_URL = "https://api.github.com/search/code"


def run_gitdorker(keyword: str, github_token: str = "") -> list[dict]:
    """Run GitHub dork search for a keyword.
    Returns [{"repo": "...", "file": "...", "dork": "...", "url": "..."}]."""
    token = github_token or settings.github_token
    if not token:
        logger.warning("No GitHub token configured, skipping GitDorker")
        return []

    results = []
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    for pattern, description in DORK_PATTERNS:
        query = f'"{keyword}" {pattern}'

        try:
            resp = httpx.get(
                GITHUB_SEARCH_URL,
                params={"q": query, "per_page": 5},
                headers=headers,
                timeout=30,
            )

            if resp.status_code == 403:
                # Rate limited
                logger.warning("GitDorker rate limited, pausing")
                time.sleep(10)
                continue

            if resp.status_code == 422:
                # Validation error (query too complex, etc.)
                continue

            resp.raise_for_status()
            data = resp.json()

            for item in data.get("items", []):
                repo_name = item.get("repository", {}).get("full_name", "")
                file_path = item.get("path", "")
                html_url = item.get("html_url", "")

                results.append({
                    "repo": repo_name,
                    "file": file_path,
                    "dork": description,
                    "url": html_url,
                })

            # Respect rate limits
            time.sleep(2)

        except httpx.HTTPStatusError as e:
            logger.warning("GitDorker API error for dork '%s': %s", pattern, e.response.status_code)
        except Exception:
            logger.exception("GitDorker error for dork '%s'", pattern)

    logger.info("GitDorker for '%s': %d results from %d dorks", keyword, len(results), len(DORK_PATTERNS))
    return results
