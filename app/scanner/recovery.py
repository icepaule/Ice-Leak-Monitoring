"""Recovery module: Resume Stage 3 (Repo-Analyse) for a failed scan,
and re-scan individual findings.

Runs in the same process as the web server so scan_progress updates
are visible in the dashboard immediately.
"""
import re
import time
import logging
import tempfile

from sqlalchemy.orm import Session

from app.config import settings
from app.models import Keyword, Scan, DiscoveredRepo, Finding, RepoKeywordMatch, AppSetting
from app.scanner.trufflehog import scan_repo as trufflehog_scan
from app.scanner.gitleaks import scan_cloned_repo as gitleaks_scan
from app.scanner.custom_patterns import scan_cloned_repo as custom_scan
from app.scanner.ollama_reviewer import assess_repo_relevance, assess_finding
from app.scanner.github_search import get_repo_readme
from app.scanner.orchestrator import _clone_repo, _insert_finding, _utcnow_str, _build_keyword_context, _load_custom_prompt
from app.scanner.progress import scan_progress, ScanCancelled
import app.scanner.orchestrator as _orch

logger = logging.getLogger(__name__)


def _scan_repo_for_findings(db: Session, repo, extra_patterns):
    """Clone a repo, run all 3 scanners, return list of finding dicts.

    Uses TemporaryDirectory so the clone is always cleaned up automatically.
    """
    full_name = repo.full_name
    repo_url = f"https://github.com/{full_name}.git"
    all_findings: list[dict] = []

    with tempfile.TemporaryDirectory(prefix="ilm_rescan_") as clone_dir:
        # TruffleHog (scans remote directly)
        scan_progress.add_activity("trufflehog", f"TruffleHog: {full_name}")
        th_findings = trufflehog_scan(repo_url, full_name)
        all_findings.extend(th_findings)

        # Clone for Gitleaks + Custom
        scan_progress.add_activity("gitleaks", f"Gitleaks: {full_name}")
        cloned = _clone_repo(repo_url, clone_dir)
        if cloned:
            gl_findings = gitleaks_scan(clone_dir, full_name)
            all_findings.extend(gl_findings)

            scan_progress.add_activity("custom", f"Custom-Scan: {full_name}")
            cx_findings = custom_scan(clone_dir, full_name,
                                      extra_patterns if extra_patterns else None)
            all_findings.extend(cx_findings)
        # TemporaryDirectory ensures clone is deleted here

    return all_findings


def _evaluate_finding(db: Session, finding, scan_results: list[dict], full_name: str, repo_description: str,
                      keyword_context: str = "", custom_prompt: str = ""):
    """Check if a finding still exists in scan results and update accordingly.

    Returns 'confirmed' | 'resolved'.
    """
    matched = None
    for f_data in scan_results:
        if f_data.get("finding_hash") == finding.finding_hash:
            matched = f_data
            break

    if matched:
        finding.last_seen_at = _utcnow_str()
        if matched.get("matched_snippet"):
            finding.matched_snippet = matched["matched_snippet"]
        db.flush()

        scan_progress.add_activity("ollama", f"AI-Reassess: Finding #{finding.id}")
        try:
            assessment = assess_finding(
                scanner=finding.scanner,
                detector_name=finding.detector_name,
                file_path=finding.file_path or "",
                repo_name=full_name,
                repo_description=repo_description,
                verified=bool(finding.verified),
                matched_snippet=finding.matched_snippet or "",
                keyword_context=keyword_context,
                custom_prompt=custom_prompt,
            )
            if assessment:
                finding.ai_assessment = assessment
        except Exception as e:
            logger.warning("AI assessment failed for finding #%d: %s", finding.id, e)

        return "confirmed"
    else:
        finding.is_resolved = 1
        finding.notes = "Automatisch verifiziert: Fund nicht mehr vorhanden"
        finding.resolved_at = _utcnow_str()
        return "resolved"


def rescan_finding(db: Session, finding_id: int):
    """Re-scan the repo of a single finding to verify it still exists.

    - If the finding is still present: update last_seen_at, matched_snippet,
      and re-run AI assessment with the snippet.
    - If not found: mark as resolved with an automatic note.
    """
    finding = db.get(Finding, finding_id)
    if not finding:
        logger.error("Re-Scan: Finding #%d not found", finding_id)
        return

    repo = finding.repo
    if not repo:
        logger.error("Re-Scan: No repo for finding #%d", finding_id)
        return

    full_name = repo.full_name
    _orch._scan_running = True

    try:
        scan_progress.update(3, message=f"Re-Scan: {full_name}", total=1)
        scan_progress.add_log(f"Re-Scan gestartet: Finding #{finding_id} in {full_name}")
        scan_progress.add_activity("start", f"Re-Scan: Finding #{finding_id} in {full_name}")

        custom_keywords = db.query(Keyword).filter_by(category="custom", is_active=1).all()
        extra_patterns = [(kw.term, re.escape(kw.term), "medium") for kw in custom_keywords]

        scan_progress.update(3, message=f"Scanning: {full_name}", current_item=full_name, count=1, total=1)
        scan_results = _scan_repo_for_findings(db, repo, extra_patterns)

        kw_context = _build_keyword_context(db, repo.id)
        custom_prompt = _load_custom_prompt(db)
        result = _evaluate_finding(db, finding, scan_results, full_name, repo.description or "",
                                   keyword_context=kw_context, custom_prompt=custom_prompt)

        if result == "confirmed":
            scan_progress.add_log(f"Re-Scan fertig: Finding #{finding_id} bestaetigt (matched_snippet aktualisiert)")
            scan_progress.add_activity("finding", f"Finding #{finding_id} bestaetigt")
        else:
            scan_progress.add_log(f"Re-Scan fertig: Finding #{finding_id} nicht mehr vorhanden — resolved")
            scan_progress.add_activity("done", f"Finding #{finding_id} auto-resolved")

        db.commit()
        scan_progress.add_activity("done", f"Re-Scan abgeschlossen: Finding #{finding_id}")

    except Exception:
        logger.exception("Re-Scan failed for finding #%d", finding_id)
        scan_progress.add_activity("error", f"Re-Scan fehlgeschlagen: Finding #{finding_id}")
        db.rollback()

    finally:
        _orch._scan_running = False
        scan_progress.reset()


def rescan_all_findings(db: Session):
    """Re-scan ALL open findings, grouped by repo to avoid redundant clones.

    For each repo: clone once, run all scanners, then evaluate every open
    finding from that repo against the scan results.
    """
    _orch._scan_running = True

    try:
        findings = db.query(Finding).filter(Finding.is_resolved == 0).all()
        total = len(findings)
        if not total:
            logger.info("Re-Scan All: keine offenen Findings")
            scan_progress.add_log("Re-Scan All: keine offenen Findings")
            return

        # Group findings by repo_id
        by_repo: dict[int, list[Finding]] = {}
        for f in findings:
            by_repo.setdefault(f.repo_id, []).append(f)

        repo_count = len(by_repo)
        scan_progress.update(3, message=f"Re-Scan All: {total} Findings in {repo_count} Repos", total=repo_count)
        scan_progress.add_log(f"Re-Scan All gestartet: {total} Findings in {repo_count} Repos")
        scan_progress.add_activity("start", f"Re-Scan All: {total} Findings, {repo_count} Repos")

        custom_keywords = db.query(Keyword).filter_by(category="custom", is_active=1).all()
        extra_patterns = [(kw.term, re.escape(kw.term), "medium") for kw in custom_keywords]

        confirmed_total = 0
        resolved_total = 0

        for ri, (repo_id, repo_findings) in enumerate(by_repo.items(), 1):
            scan_progress.check_cancelled()

            repo = db.get(DiscoveredRepo, repo_id)
            if not repo:
                logger.warning("Re-Scan All: Repo #%d not found, skipping %d findings", repo_id, len(repo_findings))
                continue

            full_name = repo.full_name
            scan_progress.update(
                3,
                message=f"Re-Scan Repo {ri}/{repo_count}: {full_name} ({len(repo_findings)} Findings)",
                current_item=full_name,
                count=ri,
                total=repo_count,
            )
            scan_progress.add_log(f"Repo {ri}/{repo_count}: {full_name} ({len(repo_findings)} Findings)")

            try:
                scan_results = _scan_repo_for_findings(db, repo, extra_patterns)
            except Exception as e:
                logger.warning("Re-Scan All: scan failed for %s: %s", full_name, e)
                scan_progress.add_log(f"Scan-Fehler bei {full_name}: {e}")
                continue

            kw_context = _build_keyword_context(db, repo_id)
            custom_prompt = _load_custom_prompt(db)
            for finding in repo_findings:
                result = _evaluate_finding(db, finding, scan_results, full_name, repo.description or "",
                                           keyword_context=kw_context, custom_prompt=custom_prompt)
                if result == "confirmed":
                    confirmed_total += 1
                else:
                    resolved_total += 1

            db.commit()
            scan_progress.set_findings(confirmed_total + resolved_total)
            scan_progress.set_repos_scanned(ri)
            scan_progress.add_log(f"Fertig: {full_name}")

        scan_progress.add_log(
            f"Re-Scan All fertig: {confirmed_total} bestaetigt, {resolved_total} auto-resolved"
        )
        scan_progress.add_activity(
            "done",
            f"Re-Scan All fertig: {confirmed_total} bestaetigt, {resolved_total} resolved"
        )
        logger.info("Re-Scan All complete: %d confirmed, %d resolved", confirmed_total, resolved_total)

    except ScanCancelled:
        logger.info("Re-Scan All cancelled by user")
        scan_progress.add_activity("cancel", "Re-Scan All abgebrochen")
        db.commit()

    except Exception:
        logger.exception("Re-Scan All failed")
        scan_progress.add_activity("error", "Re-Scan All fehlgeschlagen!")
        db.commit()

    finally:
        _orch._scan_running = False
        scan_progress.reset()


def reassess_findings(db: Session):
    """Re-run AI assessment on all open findings using the updated prompt.

    Targets findings that either:
    - have no ai_assessment yet, OR
    - were assessed without matched_snippet (old prompt)
    This is safe to call anytime — it does not re-scan repos.
    """
    _orch._scan_running = True

    try:
        findings = db.query(Finding).filter(
            Finding.is_resolved == 0,
        ).all()

        total = len(findings)
        if not total:
            logger.info("Reassess: keine offenen Findings")
            scan_progress.add_log("Reassess: keine offenen Findings")
            return

        reassessed = 0
        custom_prompt = _load_custom_prompt(db)
        scan_progress.update(3, message=f"AI-Reassessment ({total} Findings)...", total=total)
        scan_progress.add_log(f"AI-Reassessment: {total} offene Findings werden neu bewertet")
        scan_progress.add_activity("ollama", f"AI-Reassessment gestartet: {total} Findings")

        for i, finding in enumerate(findings, 1):
            scan_progress.check_cancelled()
            repo = finding.repo
            full_name = repo.full_name if repo else f"repo#{finding.repo_id}"

            scan_progress.update(
                3,
                message=f"AI-Reassess {i}/{total}: {finding.detector_name}",
                current_item=full_name,
                count=i,
                total=total,
            )
            scan_progress.add_activity("ollama", f"Reassess: {full_name} / {finding.detector_name}")

            kw_context = _build_keyword_context(db, finding.repo_id)
            try:
                assessment = assess_finding(
                    scanner=finding.scanner,
                    detector_name=finding.detector_name,
                    file_path=finding.file_path or "",
                    repo_name=full_name,
                    repo_description=(repo.description or "") if repo else "",
                    verified=bool(finding.verified),
                    matched_snippet=finding.matched_snippet or "",
                    keyword_context=kw_context,
                    custom_prompt=custom_prompt,
                )
                if assessment:
                    finding.ai_assessment = assessment
                    reassessed += 1
                    scan_progress.add_log(f"Reassessed: {full_name} / {finding.detector_name}")
            except Exception as e:
                logger.warning("Reassess failed for finding #%d: %s", finding.id, e)

            if i % 5 == 0:
                db.commit()

        db.commit()
        scan_progress.add_log(f"AI-Reassessment fertig: {reassessed}/{total} Findings neu bewertet")
        scan_progress.add_activity("done", f"Reassessment fertig: {reassessed}/{total}")
        logger.info("Reassessment complete: %d/%d findings", reassessed, total)

    except ScanCancelled:
        logger.info("Reassessment cancelled by user")
        scan_progress.add_activity("cancel", "Reassessment abgebrochen")
        db.commit()

    except Exception:
        logger.exception("Reassessment failed")
        scan_progress.add_activity("error", "Reassessment fehlgeschlagen!")
        db.commit()

    finally:
        _orch._scan_running = False
        scan_progress.reset()


def run_recovery(db: Session, scan_id: int):
    """Resume a failed scan from Stage 3."""
    scan = db.get(Scan, scan_id)
    if not scan:
        logger.error("Scan #%d not found", scan_id)
        return

    # Set global running flag so dashboard knows
    _orch._scan_running = True

    logger.info("Recovery: scan #%d (status=%s, repos_found=%s)", scan.id, scan.status, scan.repos_found)

    scan.status = "running"
    scan.error_message = None
    db.commit()

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
        logger.info("Recovery: %d pending repos to process", total)

        scan_progress.update(3, message=f"Recovery: Repo-Analyse ({total} Repos)...", total=total)
        scan_progress.add_log(f"Recovery: Stage 3 fortgesetzt ({total} Repos)")
        scan_progress.add_activity("start", f"Recovery: {total} Repos ab Stage 3")

        # Load custom keywords once
        custom_keywords = db.query(Keyword).filter_by(category="custom", is_active=1).all()
        extra_patterns = [(kw.term, re.escape(kw.term), "medium") for kw in custom_keywords]

        max_size = settings.max_repo_size_mb * 1024

        for ri, repo_obj in enumerate(repos, 1):
            scan_progress.check_cancelled()
            full_name = repo_obj.full_name

            scan_progress.update(3, message=f"Repo {ri}/{total}: {full_name}",
                                 current_item=full_name, count=ri, total=total)

            # === Skip-Check Decision Tree ===

            # 1. Too large → skip
            if repo_obj.repo_size_kb and repo_obj.repo_size_kb > max_size:
                scan_progress.add_log(f"Uebersprungen (zu gross): {full_name}")
                repo_obj.scan_status = "skipped"
                db.commit()
                continue

            # 2. ai_scan_enabled == 0 → User blocked
            if repo_obj.ai_scan_enabled == 0:
                scan_progress.add_log(f"Uebersprungen (User-gesperrt): {full_name}")
                repo_obj.scan_status = "skipped"
                db.commit()
                continue

            # 3. ai_scan_enabled == 1 → User forced
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
                    score = 1.0

                if score < 0.3:
                    repo_obj.scan_status = "low_relevance"
                    scan_progress.add_log(f"Irrelevant ({score:.2f}): {full_name}")
                    db.commit()
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
                        db.commit()
                        continue
                except (ValueError, TypeError):
                    pass

            # === Deep Scan ===
            repo_start = time.time()
            repo_url = f"https://github.com/{full_name}.git"
            all_findings: list[dict] = []

            try:
                with tempfile.TemporaryDirectory(prefix="ilm_") as clone_dir:
                    scan_progress.update(3, message=f"TruffleHog: {full_name}",
                                         current_item=full_name, count=ri, total=total)
                    scan_progress.add_activity("trufflehog", f"TruffleHog: {full_name}")
                    th_findings = trufflehog_scan(repo_url, full_name)
                    all_findings.extend(th_findings)

                    scan_progress.check_cancelled()

                    scan_progress.update(3, message=f"Gitleaks: {full_name}",
                                         current_item=full_name, count=ri, total=total)
                    scan_progress.add_activity("gitleaks", f"Gitleaks: {full_name}")
                    cloned = _clone_repo(repo_url, clone_dir)
                    if cloned:
                        gl_findings = gitleaks_scan(clone_dir, full_name)
                        all_findings.extend(gl_findings)

                        scan_progress.check_cancelled()

                        scan_progress.update(3, message=f"Custom Patterns: {full_name}",
                                             current_item=full_name, count=ri, total=total)
                        scan_progress.add_activity("custom", f"Custom-Scan: {full_name}")
                        cx_findings = custom_scan(clone_dir, full_name,
                                                  extra_patterns if extra_patterns else None)
                        all_findings.extend(cx_findings)
            except ScanCancelled:
                raise  # Re-raise cancellation
            except Exception as e:
                logger.warning("Deep scan failed for %s: %s", full_name, e)
                scan_progress.add_log(f"Scan-Fehler bei {full_name}: {e}")
                repo_obj.scan_status = "skipped"
                db.commit()
                continue

            # Insert findings
            repo_new = 0
            for f_data in all_findings:
                try:
                    is_new = _insert_finding(db, f_data, repo_obj, scan)
                    if is_new:
                        repo_new += 1
                except Exception:
                    db.rollback()

            new_findings_count += repo_new

            # AI Assessment for new findings
            new_repo_findings = db.query(Finding).filter_by(
                scan_id=scan.id, repo_id=repo_obj.id, ai_assessment=None
            ).all()
            if new_repo_findings:
                kw_context = _build_keyword_context(db, repo_obj.id)
                custom_prompt = _load_custom_prompt(db)
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
                        keyword_context=kw_context,
                        custom_prompt=custom_prompt,
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

            db.commit()
            logger.info("Scanned %s: %d new findings (%d total) in %.1fs",
                         full_name, repo_new, len(all_findings), scan_dur)

        # Finalize
        duration = time.time() - start_time
        scan.repos_scanned = scanned_count
        scan.new_findings = new_findings_count
        scan.status = "completed"
        scan.finished_at = _utcnow_str()
        scan.duration_seconds = round(duration, 1)
        db.commit()

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

        scan_progress.add_activity("done",
            f"Recovery fertig: {scanned_count} Repos, {new_findings_count} Findings, {duration:.0f}s")

    except ScanCancelled:
        logger.info("Recovery cancelled by user")
        duration = time.time() - start_time
        scan_progress.add_activity("cancel", "Recovery abgebrochen")
        scan.repos_scanned = scanned_count
        scan.new_findings = new_findings_count
        scan.status = "cancelled"
        scan.error_message = "Vom Benutzer abgebrochen"
        scan.finished_at = _utcnow_str()
        scan.duration_seconds = round(duration, 1)
        db.commit()

    except Exception:
        logger.exception("Recovery pipeline failed")
        scan_progress.add_activity("error", "Recovery fehlgeschlagen!")
        scan.status = "failed"
        scan.error_message = "Recovery failed - check logs"
        scan.finished_at = _utcnow_str()
        scan.duration_seconds = round(time.time() - start_time, 1)
        db.commit()

    finally:
        _orch._scan_running = False
        scan_progress.reset()
