"""OSINT module runner — unified interface for all OSINT modules."""

import json
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import ModuleSetting, OsintResult
from app.scanner.progress import scan_progress
from app.config import settings

logger = logging.getLogger(__name__)


def _get_config(module: ModuleSetting) -> dict:
    """Parse config_json from a module setting."""
    if not module.config_json:
        return {}
    try:
        return json.loads(module.config_json)
    except (json.JSONDecodeError, TypeError):
        return {}


def _save_result(db: Session, scan_id: int, module_key: str, keyword: str,
                 result_type: str, result_value: str, metadata: dict | None = None):
    """Store a single OSINT result in the database."""
    entry = OsintResult(
        scan_id=scan_id,
        module_key=module_key,
        keyword_used=keyword,
        result_type=result_type,
        result_value=result_value,
        metadata_json=json.dumps(metadata) if metadata else None,
        created_at=datetime.now(timezone.utc).replace(tzinfo=None).isoformat(sep=" ", timespec="seconds"),
    )
    db.add(entry)


def _is_domain_like(term: str) -> bool:
    """Check if a keyword looks like a domain."""
    return "." in term and " " not in term and "@" not in term


def _is_email_like(term: str) -> bool:
    """Check if a keyword looks like an email."""
    return "@" in term and "." in term


def _run_blackbird(db: Session, scan_id: int, keywords: list[str]) -> list[str]:
    """Run Blackbird OSINT module."""
    from app.scanner.blackbird import search_keywords_for_accounts
    new_keywords = []

    try:
        results = search_keywords_for_accounts(keywords)
        for keyword, accounts in results.items():
            for account in accounts:
                _save_result(db, scan_id, "blackbird", keyword,
                             "account", account.get("url", ""),
                             {"platform": account.get("platform"), "username": account.get("username")})
        if results:
            scan_progress.add_log(f"Blackbird: {sum(len(v) for v in results.values())} Accounts gefunden")
    except Exception:
        scan_progress.add_log("Blackbird-Suche fehlgeschlagen (nicht kritisch)")
        logger.exception("Blackbird search failed")

    return new_keywords


def _run_subfinder(db: Session, scan_id: int, keywords: list[str]) -> list[str]:
    """Run Subfinder module on domain-like keywords."""
    from app.scanner.osint.subfinder import run_subfinder
    new_keywords = []

    domains = [k for k in keywords if _is_domain_like(k)]
    for domain in domains:
        scan_progress.update(1, message=f"Subfinder: {domain}")
        subdomains = run_subfinder(domain)
        for sd in subdomains:
            _save_result(db, scan_id, "subfinder", domain, "subdomain", sd)
            if sd not in keywords and sd not in new_keywords:
                new_keywords.append(sd)
        if subdomains:
            scan_progress.add_log(f"Subfinder: {len(subdomains)} Subdomains fuer {domain}")

    return new_keywords


def _run_theharvester(db: Session, scan_id: int, keywords: list[str]) -> list[str]:
    """Run theHarvester module on domain-like keywords."""
    from app.scanner.osint.theharvester import run_theharvester
    new_keywords = []

    domains = [k for k in keywords if _is_domain_like(k)]
    for domain in domains:
        scan_progress.update(1, message=f"theHarvester: {domain}")
        results = run_theharvester(domain)

        for email in results.get("emails", []):
            _save_result(db, scan_id, "theharvester", domain, "email", email)
            if email not in keywords and email not in new_keywords:
                new_keywords.append(email)

        for host in results.get("hosts", []):
            _save_result(db, scan_id, "theharvester", domain, "subdomain", host)
            if host not in keywords and host not in new_keywords:
                new_keywords.append(host)

        for ip in results.get("ips", []):
            _save_result(db, scan_id, "theharvester", domain, "ip", ip)

        total = len(results.get("emails", [])) + len(results.get("hosts", [])) + len(results.get("ips", []))
        if total:
            scan_progress.add_log(f"theHarvester: {total} Ergebnisse fuer {domain}")

    return new_keywords


def _run_crosslinked(db: Session, scan_id: int, keywords: list[str]) -> list[str]:
    """Run CrossLinked module on company-like keywords."""
    from app.scanner.osint.crosslinked import run_crosslinked
    new_keywords = []

    # Use keywords that look like company names (no dots, no @)
    company_terms = [k for k in keywords if " " not in k and "." not in k and "@" not in k and len(k) >= 3]
    for term in company_terms[:3]:  # Limit to avoid excessive queries
        scan_progress.update(1, message=f"CrossLinked: {term}")
        persons = run_crosslinked(term)

        for person in persons:
            name = person.get("name", "")
            _save_result(db, scan_id, "crosslinked", term, "person", name,
                         {"title": person.get("title"), "url": person.get("url")})
            if name and name not in keywords and name not in new_keywords:
                new_keywords.append(name)

        if persons:
            scan_progress.add_log(f"CrossLinked: {len(persons)} Personen fuer {term}")

    return new_keywords


def _run_hunter_io(db: Session, scan_id: int, keywords: list[str], config: dict) -> list[str]:
    """Run Hunter.io module on domain-like keywords."""
    from app.scanner.osint.hunter_io import search_domain
    new_keywords = []
    api_key = config.get("api_key", "")

    if not api_key:
        scan_progress.add_log("Hunter.io: kein API-Key konfiguriert")
        return new_keywords

    domains = [k for k in keywords if _is_domain_like(k)]
    for domain in domains:
        scan_progress.update(1, message=f"Hunter.io: {domain}")
        results = search_domain(domain, api_key)

        for email in results.get("emails", []):
            _save_result(db, scan_id, "hunter_io", domain, "email", email,
                         {"org": results.get("org")})
            if email not in keywords and email not in new_keywords:
                new_keywords.append(email)

        if results.get("emails"):
            scan_progress.add_log(f"Hunter.io: {len(results['emails'])} E-Mails fuer {domain}")

    return new_keywords


def _run_gitdorker(db: Session, scan_id: int, keywords: list[str]) -> list[str]:
    """Run GitDorker module."""
    from app.scanner.osint.gitdorker import run_gitdorker

    for keyword in keywords[:5]:  # Limit to avoid rate limiting
        scan_progress.update(1, message=f"GitDorker: {keyword}")
        results = run_gitdorker(keyword)

        for item in results:
            _save_result(db, scan_id, "gitdorker", keyword, "github_dork", item.get("url", ""),
                         {"repo": item.get("repo"), "file": item.get("file"), "dork": item.get("dork")})

        if results:
            scan_progress.add_log(f"GitDorker: {len(results)} Treffer fuer {keyword}")

    return []  # GitDorker doesn't produce new keywords


def _run_leakcheck(db: Session, scan_id: int, keywords: list[str], config: dict) -> list[str]:
    """Run LeakCheck module."""
    from app.scanner.osint.leakcheck import check_email, check_domain
    api_key = config.get("api_key", "")

    if not api_key:
        scan_progress.add_log("LeakCheck: kein API-Key konfiguriert")
        return []

    for keyword in keywords:
        scan_progress.update(1, message=f"LeakCheck: {keyword}")

        if _is_email_like(keyword):
            results = check_email(keyword, api_key)
        elif _is_domain_like(keyword):
            results = check_domain(keyword, api_key)
        else:
            continue

        for leak in results:
            _save_result(db, scan_id, "leakcheck", keyword, "leak", leak.get("source", ""),
                         {"breach_date": leak.get("breach_date"), "email": leak.get("email")})

        if results:
            scan_progress.add_log(f"LeakCheck: {len(results)} Leaks fuer {keyword}")

    return []  # LeakCheck doesn't produce new search keywords


# Module dispatcher
_MODULE_RUNNERS = {
    "blackbird": lambda db, sid, kw, cfg: _run_blackbird(db, sid, kw),
    "subfinder": lambda db, sid, kw, cfg: _run_subfinder(db, sid, kw),
    "theharvester": lambda db, sid, kw, cfg: _run_theharvester(db, sid, kw),
    "crosslinked": lambda db, sid, kw, cfg: _run_crosslinked(db, sid, kw),
    "hunter_io": lambda db, sid, kw, cfg: _run_hunter_io(db, sid, kw, cfg),
    "gitdorker": lambda db, sid, kw, cfg: _run_gitdorker(db, sid, kw),
    "leakcheck": lambda db, sid, kw, cfg: _run_leakcheck(db, sid, kw, cfg),
}


def run_osint_modules(db: Session, scan_id: int, keywords: list[str],
                      enabled_modules: list[ModuleSetting]) -> list[str]:
    """Run all enabled OSINT modules and return new keywords discovered.

    Args:
        db: Database session
        scan_id: Current scan ID
        keywords: List of search keywords
        enabled_modules: List of enabled ModuleSetting objects

    Returns:
        List of new keywords discovered by OSINT modules (deduplicated)
    """
    all_new_keywords: list[str] = []
    total_modules = len(enabled_modules)

    scan_progress.add_log(f"OSINT: {total_modules} Module aktiviert")

    for idx, module in enumerate(enabled_modules, 1):
        scan_progress.check_cancelled()
        scan_progress.update(
            1,
            message=f"OSINT: {module.display_name}",
            current_item=module.display_name,
            count=idx,
            total=total_modules,
        )
        scan_progress.add_activity("osint", f"OSINT: {module.display_name}")

        runner = _MODULE_RUNNERS.get(module.module_key)
        if not runner:
            scan_progress.add_log(f"OSINT: Unbekanntes Modul '{module.module_key}'")
            continue

        config = _get_config(module)

        try:
            new_kw = runner(db, scan_id, keywords, config)
            all_new_keywords.extend(new_kw)
        except Exception:
            scan_progress.add_log(f"OSINT: {module.display_name} fehlgeschlagen")
            logger.exception("OSINT module '%s' failed", module.module_key)

    db.flush()
    db.commit()

    # Deduplicate and filter
    existing = set(k.lower() for k in keywords)
    unique_new = []
    seen = set()
    for kw in all_new_keywords:
        kw_lower = kw.lower().strip()
        if kw_lower and kw_lower not in existing and kw_lower not in seen:
            unique_new.append(kw)
            seen.add(kw_lower)

    if unique_new:
        scan_progress.add_log(f"OSINT: {len(unique_new)} neue Keywords gefunden")

    return unique_new
