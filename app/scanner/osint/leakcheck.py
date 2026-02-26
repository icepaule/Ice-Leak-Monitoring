"""LeakCheck OSINT module - Email/domain leak checking."""

import logging

import httpx

logger = logging.getLogger(__name__)

LEAKCHECK_API_URL = "https://leakcheck.io/api/v2/query"


def _query_leakcheck(value: str, query_type: str, api_key: str) -> list[dict]:
    """Query LeakCheck API. query_type is 'email' or 'domain'."""
    if not api_key:
        logger.warning("LeakCheck API key not configured, skipping")
        return []

    results = []

    try:
        resp = httpx.get(
            LEAKCHECK_API_URL,
            params={"check": value, "type": query_type},
            headers={"X-API-Key": api_key},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("success"):
            for entry in data.get("result", []):
                results.append({
                    "source": entry.get("source", {}).get("name", "Unknown"),
                    "breach_date": entry.get("source", {}).get("breach_date", ""),
                    "email": entry.get("email", ""),
                    "password": "***" if entry.get("password") else "",
                    "username": entry.get("username", ""),
                })

        logger.info("LeakCheck for '%s' (%s): %d leaks found", value, query_type, len(results))

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            logger.warning("LeakCheck: invalid API key")
        elif e.response.status_code == 429:
            logger.warning("LeakCheck: rate limited")
        else:
            logger.warning("LeakCheck API error: %s", e.response.status_code)
    except Exception:
        logger.exception("LeakCheck error for '%s'", value)

    return results


def check_email(email: str, api_key: str) -> list[dict]:
    """Check if an email appears in known data breaches."""
    return _query_leakcheck(email, "email", api_key)


def check_domain(domain: str, api_key: str) -> list[dict]:
    """Check if a domain appears in known data breaches."""
    return _query_leakcheck(domain, "domain", api_key)
