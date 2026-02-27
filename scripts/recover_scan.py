#!/usr/bin/env python3
"""Recovery script: Resume Stage 3 (Repo-Analyse) for a failed scan.

Picks up all pending repos from the DB and runs deep scan + assessment,
then finalizes the scan and sends notifications.

Usage: python3 scripts/recover_scan.py [--scan-id N]
"""
import sys
import time
import re
import logging
import tempfile

# Ensure app is importable
sys.path.insert(0, "/opt/app")

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.models import Keyword, Scan, DiscoveredRepo, Finding
from app.scanner.trufflehog import scan_repo as trufflehog_scan
from app.scanner.gitleaks import scan_cloned_repo as gitleaks_scan
from app.scanner.custom_patterns import scan_cloned_repo as custom_scan
from app.scanner.ollama_reviewer import assess_repo_relevance, assess_finding
from app.scanner.github_search import get_repo_readme
from app.scanner.orchestrator import _clone_repo, _insert_finding, _utcnow_str
from app.scanner.progress import scan_progress

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("recover_scan")


def _make_session():
    """Create a dedicated DB session with high busy_timeout for recovery."""
    engine = create_engine(
        f"sqlite:///{settings.db_path}",
        connect_args={"check_same_thread": False},
        echo=False,
    )

    @event.listens_for(engine, "connect")
    def _set_pragma(dbapi_conn, _rec):
        c = dbapi_conn.cursor()
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=60000")  # 60 seconds
        c.close()

    return sessionmaker(autocommit=False, autoflush=False, bind=engine)()


def _safe_commit(db, max_retries=5):
    """Commit with retry on database lock."""
    for attempt in range(max_retries):
        try:
            db.commit()
            return True
        except Exception as e:
            if "database is locked" in str(e) or "PendingRollback" in type(e).__name__:
                db.rollback()
                wait = 2 * (attempt + 1)
                logger.warning("DB locked, retrying in %ds (attempt %d/%d)", wait, attempt + 1, max_retries)
                time.sleep(wait)
            else:
                raise
    logger.error("Failed to commit after %d retries", max_retries)
    db.rollback()
    return False


def main():
    scan_id = None
    if "--scan-id" in sys.argv:
        idx = sys.argv.index("--scan-id")
        scan_id = int(sys.argv[idx + 1])

    db = _make_session()

    # Find the scan to recover
    if scan_id:
        scan = db.get(Scan, scan_id)
    else:
        scan = db.query(Scan).filter(Scan.status.in_(["failed", "running"])).order_by(Scan.id.desc()).first()

    if not scan:
        logger.error("No failed/running scan found to recover")
        return

    logger.info("Recovering scan #%d (status=%s, repos_found=%s)", scan.id, scan.status, scan.repos_found)

    # Reopen the scan
    scan.status = "running"
    scan.error_message = None
    _safe_commit(db)

    start_time = time.time()
    new_findings_count = 0
    scanned_count = 0

    try:
        # Get all non-dismissed, pending repos
        repos = db.query(DiscoveredRepo).filter(
            DiscoveredRepo.is_dismissed != 1,
            DiscoveredRepo.scan_status.in_(["pending"]),
        ).all()

        total = len(repos)
        logger.info("Found %d pending repos to scan", total)

        scan_progress.update(3, message=f"Recovery: Repo-Analyse ({total} Repos)...", total=total)
        scan_progress.add_log(f"Recovery: Stage 3 fortgesetzt ({total} Repos)")
        scan_progress.add_activity("start", f"Recovery: {total} Repos ab Stage 3")

        # Load custom keywords once
        custom_keywords = db.query(Keyword).filter_by(category="custom", is_active=1).all()
        extra_patterns = [(kw.term, re.escape(kw.term), "medium") for kw in custom_keywords]

        max_size = settings.max_repo_size_mb * 1024

        for ri, repo_obj in enumerate(repos, 1):
            full_name = repo_obj.full_name

            scan_progress.update(3, message=f"Repo {ri}/{total}: {full_name}",
                                 current_item=full_name, count=ri, total=total)

            # === Skip-Check Decision Tree ===

            # 1. Too large → skip
            if repo_obj.repo_size_kb and repo_obj.repo_size_kb > max_size:
                scan_progress.add_log(f"Uebersprungen (zu gross): {full_name}")
                repo_obj.scan_status = "skipped"
                _safe_commit(db)
                continue

            # 2. ai_scan_enabled == 0 → User blocked
            if repo_obj.ai_scan_enabled == 0:
                scan_progress.add_log(f"Uebersprungen (User-gesperrt): {full_name}")
                repo_obj.scan_status = "skipped"
                _safe_commit(db)
                continue

            # 3. ai_scan_enabled == 1 → User forced (skip AI check)
            force_scan = repo_obj.ai_scan_enabled == 1
            if force_scan:
                scan_progress.add_log(f"Erzwungen (User-Override): {full_name}")
            else:
                # 4. AI relevance check
                scan_progress.add_activity("ollama", f"Ollama Relevanz-Check: {full_name}")
                try:
                    readme = get_repo_readme(full_name)
                    score, summary = assess_repo_relevance(
                        full_name,
                        repo_obj.description or "",
                        repo_obj.language or "",
                        readme,
                    )
                    repo_obj.ai_relevance = score
                    repo_obj.ai_summary = summary
                except Exception as e:
                    logger.warning("AI check failed for %s: %s", full_name, e)
                    score = 1.0  # Scan anyway if AI fails

                if score < 0.3:
                    repo_obj.scan_status = "low_relevance"
                    scan_progress.add_log(f"Irrelevant ({score:.2f}): {full_name}")
                    _safe_commit(db)
                    continue
                else:
                    scan_progress.add_log(f"Relevant ({score:.2f}): {full_name}")

            # 5. Unchanged check
            if not force_scan and repo_obj.github_pushed_at and repo_obj.last_scanned_at:
                try:
                    pushed = repo_obj.github_pushed_at.replace("Z", "+00:00")
                    scanned = repo_obj.last_scanned_at
                    if pushed <= scanned:
                        repo_obj.scan_status = "unchanged"
                        scan_progress.add_log(f"Uebersprungen (unveraendert): {full_name}")
                        _safe_commit(db)
                        continue
                except (ValueError, TypeError):
                    pass

            # === Deep Scan ===
            repo_start = time.time()
            repo_url = f"https://github.com/{full_name}.git"
            all_findings: list[dict] = []

            try:
                with tempfile.TemporaryDirectory(prefix="ilm_") as clone_dir:
                    # TruffleHog
                    scan_progress.update(3, message=f"TruffleHog: {full_name}",
                                         current_item=full_name, count=ri, total=total)
                    scan_progress.add_activity("trufflehog", f"TruffleHog: {full_name}")
                    th_findings = trufflehog_scan(repo_url, full_name)
                    all_findings.extend(th_findings)

                    # Clone + Gitleaks + Custom
                    scan_progress.update(3, message=f"Gitleaks: {full_name}",
                                         current_item=full_name, count=ri, total=total)
                    scan_progress.add_activity("gitleaks", f"Gitleaks: {full_name}")
                    cloned = _clone_repo(repo_url, clone_dir)
                    if cloned:
                        gl_findings = gitleaks_scan(clone_dir, full_name)
                        all_findings.extend(gl_findings)

                        scan_progress.update(3, message=f"Custom Patterns: {full_name}",
                                             current_item=full_name, count=ri, total=total)
                        scan_progress.add_activity("custom", f"Custom-Scan: {full_name}")
                        cx_findings = custom_scan(clone_dir, full_name,
                                                  extra_patterns if extra_patterns else None)
                        all_findings.extend(cx_findings)
            except Exception as e:
                logger.warning("Deep scan failed for %s: %s", full_name, e)
                scan_progress.add_log(f"Scan-Fehler bei {full_name}: {e}")
                repo_obj.scan_status = "skipped"
                _safe_commit(db)
                continue

            # Insert findings
            repo_new = 0
            for f_data in all_findings:
                try:
                    is_new = _insert_finding(db, f_data, repo_obj, scan)
                    if is_new:
                        repo_new += 1
                except Exception as e:
                    logger.warning("Finding insert failed: %s", e)
                    db.rollback()

            new_findings_count += repo_new

            # AI Assessment for new findings
            new_repo_findings = db.query(Finding).filter_by(
                scan_id=scan.id, repo_id=repo_obj.id, ai_assessment=None
            ).all()
            for finding in new_repo_findings:
                scan_progress.add_activity("ollama", f"AI-Assessment: {full_name} / {finding.detector_name}")
                try:
                    assessment = assess_finding(
                        scanner=finding.scanner,
                        detector_name=finding.detector_name,
                        file_path=finding.file_path or "",
                        repo_name=full_name,
                        repo_description=repo_obj.description or "",
                        verified=bool(finding.verified),
                        matched_snippet=finding.matched_snippet or "",
                    )
                    if assessment:
                        finding.ai_assessment = assessment
                except Exception as e:
                    logger.warning("AI assessment failed for %s: %s", full_name, e)

            # Update repo status
            scan_dur = time.time() - repo_start
            repo_obj.last_scanned_at = _utcnow_str()
            repo_obj.scan_duration_s = round(scan_dur, 1)
            repo_findings = db.query(Finding).filter_by(repo_id=repo_obj.id, is_resolved=0).count()
            repo_obj.scan_status = "findings" if repo_findings > 0 else "clean"
            scanned_count += 1

            scan_progress.set_findings(new_findings_count)
            scan_progress.set_repos_scanned(scanned_count)
            scan_progress.add_log(f"Fertig: {full_name} ({repo_new} neue, {len(all_findings)} total, {scan_dur:.1f}s)")
            if repo_new > 0:
                scan_progress.add_activity("finding", f"{repo_new} Findings in {full_name}")

            # Commit after each repo
            _safe_commit(db)
            logger.info("Scanned %s: %d new findings (%d total) in %.1fs",
                         full_name, repo_new, len(all_findings), scan_dur)

        # Finalize scan
        duration = time.time() - start_time
        scan.repos_scanned = scanned_count
        scan.new_findings = new_findings_count
        scan.status = "completed"
        scan.finished_at = _utcnow_str()
        scan.duration_seconds = round(duration, 1)
        _safe_commit(db)

        logger.info("Recovery complete: %d repos scanned, %d new findings, %.1fs",
                     scanned_count, new_findings_count, duration)

        # Stage 4: Notifications
        scan_progress.update(4, message="Notifications senden...")
        scan_progress.add_log("Stage 4: Abschluss & Benachrichtigungen")
        try:
            from app.notifications.pushover import send_scan_notification
            from app.notifications.email_notify import send_scan_email
            send_scan_notification(db, scan)
            send_scan_email(db, scan)
            scan_progress.add_log("Scan-Bericht gesendet")
        except Exception:
            logger.exception("Notification dispatch failed")
            scan_progress.add_log("Scan-Bericht konnte nicht gesendet werden")

        scan_progress.add_activity("done", f"Recovery fertig: {scanned_count} Repos, {new_findings_count} Findings, {duration:.0f}s")

    except Exception:
        logger.exception("Recovery failed")
        scan.status = "failed"
        scan.error_message = "Recovery failed - check logs"
        scan.finished_at = _utcnow_str()
        scan.duration_seconds = round(time.time() - start_time, 1)
        try:
            _safe_commit(db)
        except Exception:
            db.rollback()
        scan_progress.add_activity("error", "Recovery fehlgeschlagen!")
    finally:
        scan_progress.reset()
        db.close()


if __name__ == "__main__":
    main()
