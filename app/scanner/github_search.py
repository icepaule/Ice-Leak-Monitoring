import json
import logging
import time
from typing import Optional

import httpx

from app.config import settings
from app.scanner.rate_limiter import TokenBucketRateLimiter

logger = logging.getLogger(__name__)

rate_limiter = TokenBucketRateLimiter(tokens_per_minute=10)

GITHUB_API = "https://api.github.com"


def _headers() -> dict:
    h = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "IceLeakMonitor/1.0",
    }
    if settings.github_token:
        h["Authorization"] = f"Bearer {settings.github_token}"
    return h


def search_code_for_keyword(keyword: str, max_pages: int = 10) -> list[dict]:
    """Search GitHub Code Search API for a keyword. Returns list of unique repos."""
    repos: dict[str, dict] = {}

    for page in range(1, max_pages + 1):
        if not rate_limiter.acquire(timeout=120):
            logger.error("Rate limiter timeout for keyword '%s' page %d", keyword, page)
            break

        try:
            resp = httpx.get(
                f"{GITHUB_API}/search/code",
                params={"q": keyword, "per_page": 100, "page": page},
                headers=_headers(),
                timeout=30.0,
            )

            # Adapt rate limiter from headers
            rl_remaining = resp.headers.get("X-RateLimit-Remaining")
            rl_reset = resp.headers.get("X-RateLimit-Reset")
            if rl_remaining is not None and rl_reset is not None:
                rate_limiter.adapt_from_headers(int(rl_remaining), int(rl_reset))

            if resp.status_code == 403:
                logger.warning("GitHub rate limit hit, waiting...")
                reset = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
                wait = max(1, reset - int(time.time()))
                time.sleep(wait)
                continue

            if resp.status_code == 422:
                logger.warning("GitHub search validation error for '%s'", keyword)
                break

            resp.raise_for_status()
            data = resp.json()

            items = data.get("items", [])
            if not items:
                break

            for item in items:
                repo_data = item.get("repository", {})
                full_name = repo_data.get("full_name", "")
                match_path = item.get("path", "")
                if full_name and full_name not in repos:
                    repos[full_name] = {
                        "full_name": full_name,
                        "html_url": repo_data.get("html_url", ""),
                        "description": repo_data.get("description", ""),
                        "owner_login": repo_data.get("owner", {}).get("login", ""),
                        "owner_type": repo_data.get("owner", {}).get("type", ""),
                        "is_fork": repo_data.get("fork", False),
                        "match_files": [match_path] if match_path else [],
                    }
                elif full_name and match_path:
                    existing_files = repos[full_name].get("match_files", [])
                    if match_path not in existing_files and len(existing_files) < 10:
                        existing_files.append(match_path)

            total_count = data.get("total_count", 0)
            if page * 100 >= total_count:
                break

        except httpx.HTTPStatusError as e:
            logger.error("GitHub API error: %s", e)
            break
        except Exception:
            logger.exception("Unexpected error in GitHub search for '%s'", keyword)
            break

    logger.info("Keyword '%s': found %d unique repos", keyword, len(repos))
    return list(repos.values())


def get_repo_details(full_name: str) -> Optional[dict]:
    """Fetch full repo details from GitHub API."""
    if not rate_limiter.acquire(timeout=60):
        return None

    try:
        resp = httpx.get(
            f"{GITHUB_API}/repos/{full_name}",
            headers=_headers(),
            timeout=30.0,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "full_name": data.get("full_name", full_name),
            "html_url": data.get("html_url", ""),
            "description": data.get("description", ""),
            "owner_login": data.get("owner", {}).get("login", ""),
            "owner_type": data.get("owner", {}).get("type", ""),
            "repo_size_kb": data.get("size", 0),
            "default_branch": data.get("default_branch", "main"),
            "language": data.get("language", ""),
            "is_fork": data.get("fork", False),
            "stargazers": data.get("stargazers_count", 0),
        }
    except Exception:
        logger.exception("Failed to get repo details for %s", full_name)
        return None


def get_repo_readme(full_name: str) -> str:
    """Fetch decoded README content (truncated to 2000 chars)."""
    if not rate_limiter.acquire(timeout=30):
        return ""

    try:
        resp = httpx.get(
            f"{GITHUB_API}/repos/{full_name}/readme",
            headers={**_headers(), "Accept": "application/vnd.github.raw+json"},
            timeout=15.0,
        )
        if resp.status_code == 200:
            return resp.text[:2000]
    except Exception:
        pass
    return ""
