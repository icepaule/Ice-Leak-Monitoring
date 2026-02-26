"""Hunter.io OSINT module - Email finder per domain."""

import logging

import httpx

logger = logging.getLogger(__name__)

HUNTER_API_URL = "https://api.hunter.io/v2/domain-search"


def search_domain(domain: str, api_key: str) -> dict:
    """Search Hunter.io for emails associated with a domain.
    Returns {"emails": [], "org": "...", "patterns": []}."""
    results = {"emails": [], "org": "", "patterns": []}

    if not api_key:
        logger.warning("Hunter.io API key not configured, skipping")
        return results

    try:
        resp = httpx.get(
            HUNTER_API_URL,
            params={"domain": domain, "api_key": api_key, "limit": 50},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})

        results["org"] = data.get("organization", "")
        results["patterns"] = [
            p.get("value", "") for p in data.get("pattern", []) if p.get("value")
        ]

        for email_obj in data.get("emails", []):
            email = email_obj.get("value", "").strip()
            if email:
                results["emails"].append(email)

        logger.info("Hunter.io for '%s': %d emails found", domain, len(results["emails"]))

    except httpx.HTTPStatusError as e:
        logger.warning("Hunter.io API error for '%s': %s", domain, e.response.status_code)
    except Exception:
        logger.exception("Hunter.io error for '%s'", domain)

    return results
