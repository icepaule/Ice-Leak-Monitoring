import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.config import settings
from app.models import Keyword, Scan, DiscoveredRepo, Finding, RepoKeywordMatch, ModuleSetting
from app.scanner.github_search import search_code_for_keyword, get_repo_details, get_repo_readme
from app.scanner.trufflehog import scan_repo as trufflehog_scan
from app.scanner.gitleaks import scan_cloned_repo as gitleaks_scan
from app.scanner.custom_patterns import scan_cloned_repo as custom_scan
from app.scanner.ollama_reviewer import assess_repo_relevance, assess_finding
from app.scanner.osint import run_osint_modules
from app.scanner.progress import scan_progress, ScanCancelled

logger = logging.getLogger(__name__)

# Global flag to track running scan
_scan_running = False


def is_scan_running() -> bool:
    return _scan_running


def _utcnow_str() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat(sep=" ", timespec="seconds")


def _clone_repo(repo_url: str, dest_path: str, timeout: int = 120) -> bool:
    """Shallow-clone a repo. Returns True on success."""
    try:
        subprocess.run(
            ["git", "clone", "--depth=1", "--single-branch", repo_url, dest_path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return os.path.isdir(dest_path)
    except (subprocess.TimeoutExpired, Exception) as e:
        logger.warning("Clone failed for %s: %s", repo_url, e)
        return False


def _upsert_repo(db: Session, repo_data: dict, keyword: str) -> DiscoveredRepo:
    """Insert or update a discovered repo."""
    existing = db.query(DiscoveredRepo).filter_by(full_name=repo_data["full_name"]).first()

    if existing:
        existing.last_seen_at = _utcnow_str()
        # Merge keywords
        try:
            kw_list = json.loads(existing.matched_keywords or "[]")
        except (json.JSONDecodeError, TypeError):
            kw_list = []
        if keyword not in kw_list:
            kw_list.append(keyword)
            existing.matched_keywords = json.dumps(kw_list)
        db.flush()
        return existing

    repo = DiscoveredRepo(
        full_name=repo_data["full_name"],
        html_url=repo_data.get("html_url", f"https://github.com/{repo_data['full_name']}"),
        description=repo_data.get("description", ""),
        owner_login=repo_data.get("owner_login", ""),
        owner_type=repo_data.get("owner_type", ""),
        repo_size_kb=repo_data.get("repo_size_kb", 0),
        default_branch=repo_data.get("default_branch", "main"),
        language=repo_data.get("language", ""),
        is_fork=1 if repo_data.get("is_fork") else 0,
        stargazers=repo_data.get("stargazers", 0),
        matched_keywords=json.dumps([keyword]),
        scan_status="pending",
    )
    db.add(repo)
    db.flush()
    return repo


def _insert_finding(db: Session, finding_data: dict, repo: DiscoveredRepo, scan: Scan) -> bool:
    """Insert a finding if it doesn't exist. Returns True if new."""
    existing = db.query(Finding).filter_by(finding_hash=finding_data["finding_hash"]).first()
    if existing:
        existing.last_seen_at = _utcnow_str()
        db.flush()
        return False

    finding = Finding(
        finding_hash=finding_data["finding_hash"],
        repo_id=repo.id,
        scan_id=scan.id,
        scanner=finding_data["scanner"],
        detector_name=finding_data["detector_name"],
        verified=finding_data.get("verified", 0),
        file_path=finding_data.get("file_path", ""),
        commit_hash=finding_data.get("commit_hash", ""),
        line_number=finding_data.get("line_number", 0),
        severity=finding_data.get("severity", "medium"),
    )
    db.add(finding)
    db.flush()
    return True


def cleanup_stale_scans(db: Session):
    """Mark any scans stuck in 'running' status as failed (e.g. after a crash)."""
    stale = db.query(Scan).filter_by(status="running").all()
    for s in stale:
        s.status = "failed"
        s.error_message = "Abgebrochen (Prozess-Neustart)"
        s.finished_at = _utcnow_str()
        if s.started_at:
            try:
                start = datetime.fromisoformat(s.started_at)
                s.duration_seconds = round((datetime.now(timezone.utc).replace(tzinfo=None) - start).total_seconds(), 1)
            except (ValueError, TypeError):
                s.duration_seconds = 0
    if stale:
        db.commit()
        logger.info("Cleaned up %d stale running scan(s)", len(stale))


def run_scan_pipeline(db: Session, trigger_type: str = "manual"):
    """Execute the full scan pipeline."""
    global _scan_running

    if _scan_running:
        logger.warning("Scan already running, skipping")
        return

    _scan_running = True
    start_time = time.time()

    # Create scan record
    scan = Scan(trigger_type=trigger_type, status="running")
    db.add(scan)
    db.commit()

    new_findings_count = 0
    scanned_count = 0

    try:
        # =====================================================================
        # Stage 0: Get active keywords
        # =====================================================================
        scan_progress.update(0, message="Keywords laden...")
        scan_progress.add_log("Scan gestartet")
        scan_progress.add_activity("start", "Scan gestartet")
        keywords = db.query(Keyword).filter_by(is_active=1).all()
        keyword_terms = [kw.term for kw in keywords]
        scan.keywords_used = len(keyword_terms)
        db.commit()

        if not keyword_terms:
            logger.warning("No active keywords configured, nothing to scan")
            scan_progress.add_log("Keine aktiven Keywords gefunden")
            scan_progress.add_activity("warn", "Keine aktiven Keywords")
            scan.status = "completed"
            scan.finished_at = _utcnow_str()
            scan.duration_seconds = time.time() - start_time
            db.commit()
            _scan_running = False
            return

        scan_progress.update(0, message=f"{len(keyword_terms)} Keywords geladen", count=len(keyword_terms), total=len(keyword_terms))
        scan_progress.add_log(f"{len(keyword_terms)} aktive Keywords geladen")
        scan_progress.add_activity("keyword", f"{len(keyword_terms)} Keywords geladen: {', '.join(keyword_terms[:5])}")
        logger.info("Starting scan with %d keywords", len(keyword_terms))

        # --- Cancel check ---
        scan_progress.check_cancelled()

        # =====================================================================
        # Stage 1: OSINT Reconnaissance (NEW)
        # =====================================================================
        enabled_modules = db.query(ModuleSetting).filter_by(is_enabled=1).all()
        if enabled_modules:
            scan_progress.update(1, message="OSINT-Aufklaerung starten...", total=len(enabled_modules))
            scan_progress.add_log(f"Stage 1: OSINT-Aufklaerung ({len(enabled_modules)} Module)")

            osint_keywords = run_osint_modules(db, scan.id, keyword_terms, enabled_modules)
            if osint_keywords:
                keyword_terms.extend(osint_keywords)
                keyword_terms = list(set(keyword_terms))
                scan_progress.add_log(f"OSINT: Keywords erweitert auf {len(keyword_terms)}")
                scan_progress.add_activity("osint", f"OSINT fertig: {len(osint_keywords)} neue Keywords")
            else:
                scan_progress.add_log("OSINT: Keine neuen Keywords gefunden")
                scan_progress.add_activity("osint", "OSINT-Aufklaerung abgeschlossen")
        else:
            scan_progress.add_log("OSINT: Keine Module aktiviert, ueberspringe")

        # --- Cancel check ---
        scan_progress.check_cancelled()

        # =====================================================================
        # Stage 2: GitHub Code Search (was Stage 1)
        # =====================================================================
        scan_progress.update(2, message="GitHub-Suche starten...", total=len(keyword_terms))
        scan_progress.add_log("Stage 2: GitHub Code Search")
        all_repos: dict[str, dict] = {}
        for ki, term in enumerate(keyword_terms, 1):
            scan_progress.check_cancelled()
            scan_progress.update(2, message=f"Suche: '{term}'", current_item=term, count=ki, total=len(keyword_terms))
            scan_progress.add_log(f"GitHub Search: '{term}'")
            scan_progress.add_activity("github", f"GitHub-Suche: Keyword '{term}'")
            logger.info("Searching GitHub for: %s", term)
            found = search_code_for_keyword(term)
            for repo_data in found:
                fn = repo_data["full_name"]
                match_files = repo_data.get("match_files", [])
                if fn not in all_repos:
                    all_repos[fn] = {"data": repo_data, "keywords": {term: match_files}}
                else:
                    if term in all_repos[fn]["keywords"]:
                        existing = all_repos[fn]["keywords"][term]
                        for mf in match_files:
                            if mf not in existing:
                                existing.append(mf)
                    else:
                        all_repos[fn]["keywords"][term] = match_files

        scan.repos_found = len(all_repos)
        db.commit()
        scan_progress.add_log(f"GitHub-Suche abgeschlossen: {len(all_repos)} Repos gefunden")
        scan_progress.add_activity("github", f"GitHub-Suche fertig: {len(all_repos)} Repos")
        logger.info("Stage 2 complete: %d unique repos found", len(all_repos))

        # Upsert repos into DB and create keyword match records
        repo_objects: dict[str, DiscoveredRepo] = {}
        for full_name, info in all_repos.items():
            for kw, match_files in info["keywords"].items():
                repo_obj = _upsert_repo(db, info["data"], kw)
                repo_objects[full_name] = repo_obj

                # Create or update keyword match record
                existing_match = db.query(RepoKeywordMatch).filter_by(
                    repo_id=repo_obj.id, keyword=kw, match_source="code_search"
                ).first()
                if existing_match:
                    # Merge match_files
                    try:
                        old_files = json.loads(existing_match.match_files or "[]")
                    except (json.JSONDecodeError, TypeError):
                        old_files = []
                    merged = list(set(old_files + match_files))[:10]
                    existing_match.match_files = json.dumps(merged)
                    if merged:
                        existing_match.match_context = f"Keyword in {len(merged)} Datei(en) gefunden"
                else:
                    context = f"Keyword '{kw}' in {len(match_files)} Datei(en) gefunden" if match_files else f"Keyword '{kw}' via GitHub Code Search"
                    match_record = RepoKeywordMatch(
                        repo_id=repo_obj.id,
                        keyword=kw,
                        match_source="code_search",
                        match_files=json.dumps(match_files),
                        match_context=context,
                    )
                    db.add(match_record)
        db.flush()
        db.commit()

        # Fetch additional details for new repos
        detail_repos = [fn for fn, ro in repo_objects.items() if not ro.repo_size_kb]
        for di, full_name in enumerate(detail_repos, 1):
            scan_progress.check_cancelled()
            repo_obj = repo_objects[full_name]
            scan_progress.update(2, message=f"Repo-Details: {full_name}", current_item=full_name, count=di, total=len(detail_repos))
            scan_progress.add_log(f"Repo-Details: {full_name}")
            details = get_repo_details(full_name)
            if details:
                repo_obj.repo_size_kb = details.get("repo_size_kb", 0)
                repo_obj.default_branch = details.get("default_branch", "main")
                repo_obj.language = details.get("language", "")
                repo_obj.stargazers = details.get("stargazers", 0)
                repo_obj.github_pushed_at = details.get("pushed_at", "")
                if not repo_obj.description:
                    repo_obj.description = details.get("description", "")
        db.commit()
        if detail_repos:
            scan_progress.add_log(f"Repo-Details fuer {len(detail_repos)} Repos abgerufen")

        # --- Cancel check ---
        scan_progress.check_cancelled()

        # =====================================================================
        # Stage 3: Repo-Analyse (per-repo: AI-Check → Skip-Check → Deep Scan → Finding-Assessment)
        # =====================================================================
        total = len(repo_objects)
        scan_progress.update(3, message=f"Repo-Analyse starten ({total} Repos)...", total=total)
        scan_progress.add_log(f"Stage 3: Repo-Analyse ({total} Repos)")
        total_findings_count = 0

        for ri, (full_name, repo_obj) in enumerate(repo_objects.items(), 1):
            scan_progress.check_cancelled()
            scan_progress.update(3, message=f"Repo {ri}/{total}: {full_name}", current_item=full_name, count=ri, total=total)

            # === Skip-Check Decision Tree ===

            # 1. Dismissed → skip
            if repo_obj.is_dismissed:
                scan_progress.add_log(f"Uebersprungen (dismissed): {full_name}")
                logger.info("Skipping dismissed repo: %s", full_name)
                continue

            # 2. Too large → skip
            max_size = settings.max_repo_size_mb * 1024
            if repo_obj.repo_size_kb and repo_obj.repo_size_kb > max_size:
                scan_progress.add_log(f"Uebersprungen (zu gross): {full_name}")
                logger.info("Skipping oversized repo %s (%d KB)", full_name, repo_obj.repo_size_kb)
                repo_obj.scan_status = "skipped"
                db.commit()
                continue

            # 3. ai_scan_enabled == 0 → User blocked
            if repo_obj.ai_scan_enabled == 0:
                scan_progress.add_log(f"Uebersprungen (User-gesperrt): {full_name}")
                logger.info("Skipping user-blocked repo: %s", full_name)
                if repo_obj.scan_status == "pending":
                    repo_obj.scan_status = "skipped"
                db.commit()
                continue

            # 4. ai_scan_enabled == 1 → User forced (skip AI check)
            force_scan = repo_obj.ai_scan_enabled == 1
            if force_scan:
                scan_progress.add_log(f"Erzwungen (User-Override): {full_name}")
                logger.info("User-forced scan for: %s", full_name)
            else:
                # 5. ai_scan_enabled is None → Ollama AI-Check
                scan_progress.add_activity("ollama", f"Ollama Relevanz-Check: {full_name}")
                readme = get_repo_readme(full_name)
                score, summary = assess_repo_relevance(
                    full_name,
                    repo_obj.description or "",
                    repo_obj.language or "",
                    readme,
                )
                repo_obj.ai_relevance = score
                repo_obj.ai_summary = summary

                if score < 0.3:
                    repo_obj.scan_status = "low_relevance"
                    scan_progress.add_log(f"Irrelevant ({score:.2f}): {full_name}")
                    logger.info("Repo %s: AI score %.2f - skipping", full_name, score)
                    db.commit()
                    continue
                else:
                    scan_progress.add_log(f"Relevant ({score:.2f}): {full_name}")
                    logger.info("Repo %s: AI score %.2f - will scan", full_name, score)

            # 6. Unchanged check (pushed_at <= last_scanned_at) → skip
            if not force_scan and repo_obj.github_pushed_at and repo_obj.last_scanned_at:
                try:
                    pushed = repo_obj.github_pushed_at.replace("Z", "+00:00")
                    scanned = repo_obj.last_scanned_at
                    if pushed <= scanned:
                        repo_obj.scan_status = "unchanged"
                        scan_progress.add_log(f"Uebersprungen (unveraendert): {full_name}")
                        logger.info("Skipping unchanged repo: %s (pushed=%s, scanned=%s)", full_name, pushed, scanned)
                        db.commit()
                        continue
                except (ValueError, TypeError):
                    pass  # If comparison fails, scan anyway

            # === Deep Scan: TruffleHog + Clone + Gitleaks + Custom ===
            repo_start = time.time()
            repo_url = f"https://github.com/{full_name}.git"
            all_findings: list[dict] = []

            with tempfile.TemporaryDirectory(prefix="ilm_") as clone_dir:
                # TruffleHog (scans remote repo directly)
                scan_progress.update(3, message=f"TruffleHog: {full_name}", current_item=full_name, count=ri, total=total)
                scan_progress.add_log(f"TruffleHog: {full_name}")
                scan_progress.add_activity("trufflehog", f"TruffleHog scannt: {full_name}")
                th_findings = trufflehog_scan(repo_url, full_name)
                all_findings.extend(th_findings)

                scan_progress.check_cancelled()

                # Clone for Gitleaks + Custom scan
                scan_progress.update(3, message=f"Gitleaks: {full_name}", current_item=full_name, count=ri, total=total)
                scan_progress.add_log(f"Gitleaks: {full_name}")
                scan_progress.add_activity("gitleaks", f"Gitleaks scannt: {full_name}")
                cloned = _clone_repo(repo_url, clone_dir)
                if cloned:
                    gl_findings = gitleaks_scan(clone_dir, full_name)
                    all_findings.extend(gl_findings)

                    scan_progress.check_cancelled()

                    # Load custom patterns from DB keywords
                    custom_keywords = db.query(Keyword).filter_by(
                        category="custom", is_active=1
                    ).all()
                    extra_patterns = [
                        (kw.term, kw.term, "medium") for kw in custom_keywords
                    ]
                    scan_progress.update(3, message=f"Custom Patterns: {full_name}", current_item=full_name, count=ri, total=total)
                    scan_progress.add_log(f"Custom Scan: {full_name}")
                    scan_progress.add_activity("custom", f"Custom-Scan: {full_name}")
                    cx_findings = custom_scan(clone_dir, full_name, extra_patterns if extra_patterns else None)
                    all_findings.extend(cx_findings)

            # Deduplicate and insert findings
            repo_new = 0
            for f_data in all_findings:
                is_new = _insert_finding(db, f_data, repo_obj, scan)
                if is_new:
                    repo_new += 1
                total_findings_count += 1

            new_findings_count += repo_new

            # === Finding Assessment: Ollama for each new finding ===
            new_repo_findings = db.query(Finding).filter_by(
                scan_id=scan.id, repo_id=repo_obj.id, ai_assessment=None
            ).all()
            for finding in new_repo_findings:
                scan_progress.add_activity("ollama", f"AI-Assessment: {full_name} / {finding.detector_name}")
                assessment = assess_finding(
                    scanner=finding.scanner,
                    detector_name=finding.detector_name,
                    file_path=finding.file_path or "",
                    repo_name=full_name,
                    repo_description=repo_obj.description or "",
                    verified=bool(finding.verified),
                )
                if assessment:
                    finding.ai_assessment = assessment
                    scan_progress.add_log(f"AI-Bewertung: {full_name} / {finding.detector_name}")

            # Update repo status
            scan_dur = time.time() - repo_start
            repo_obj.last_scanned_at = _utcnow_str()
            repo_obj.scan_duration_s = round(scan_dur, 1)
            repo_findings = db.query(Finding).filter_by(
                repo_id=repo_obj.id, is_resolved=0
            ).count()
            repo_obj.scan_status = "findings" if repo_findings > 0 else "clean"
            scanned_count += 1

            scan_progress.set_findings(new_findings_count)
            scan_progress.set_repos_scanned(scanned_count)
            scan_progress.add_log(f"Fertig: {full_name} ({repo_new} neue Findings, {scan_dur:.1f}s)")
            if repo_new > 0:
                scan_progress.add_activity("finding", f"{repo_new} Findings in {full_name}")

            # Commit after each repo → findings visible immediately
            db.commit()
            logger.info(
                "Scanned %s: %d new findings (%d total from all engines) in %.1fs",
                full_name, repo_new, len(all_findings), scan_dur,
            )

        # Finalize scan
        duration = time.time() - start_time
        scan.repos_scanned = scanned_count
        scan.new_findings = new_findings_count
        scan.total_findings = total_findings_count
        scan.status = "completed"
        scan.finished_at = _utcnow_str()
        scan.duration_seconds = round(duration, 1)
        db.commit()

        logger.info(
            "Scan completed: %d repos scanned, %d new findings, %.1fs total",
            scanned_count, new_findings_count, duration,
        )

        # =====================================================================
        # Stage 4: Abschluss (Notifications)
        # =====================================================================
        scan_progress.update(4, message="Notifications senden...")
        scan_progress.add_log("Stage 4: Abschluss & Benachrichtigungen")

        # Always send notifications (report with all activities)
        try:
            from app.notifications.pushover import send_scan_notification
            from app.notifications.email_notify import send_scan_email
            scan_progress.add_log(f"Sende Scan-Bericht ({new_findings_count} neue Findings, {scanned_count} Repos)")
            send_scan_notification(db, scan)
            send_scan_email(db, scan)
            scan_progress.add_log("Scan-Bericht gesendet")
        except Exception:
            scan_progress.add_log("Scan-Bericht konnte nicht gesendet werden")
            logger.exception("Notification dispatch failed")

        scan_progress.add_log(f"Scan abgeschlossen: {scanned_count} Repos, {new_findings_count} Findings, {duration:.1f}s")
        scan_progress.add_activity("done", f"Scan fertig: {scanned_count} Repos, {new_findings_count} Findings, {duration:.0f}s")

    except ScanCancelled:
        logger.info("Scan cancelled by user")
        duration = time.time() - start_time
        scan_progress.add_log("Scan vom Benutzer abgebrochen")
        scan_progress.add_activity("cancel", f"Scan abgebrochen ({scanned_count} Repos, {new_findings_count} Findings)")
        scan.repos_scanned = scanned_count
        scan.new_findings = new_findings_count
        scan.status = "cancelled"
        scan.error_message = "Vom Benutzer abgebrochen"
        scan.finished_at = _utcnow_str()
        scan.duration_seconds = round(duration, 1)
        db.commit()

    except Exception:
        logger.exception("Scan pipeline failed")
        scan_progress.add_log("FEHLER: Scan-Pipeline abgebrochen!")
        scan_progress.add_activity("error", "Scan fehlgeschlagen!")
        scan.status = "failed"
        scan.error_message = "Pipeline error - check logs"
        scan.finished_at = _utcnow_str()
        scan.duration_seconds = round(time.time() - start_time, 1)
        db.commit()
    finally:
        _scan_running = False
        scan_progress.reset()
