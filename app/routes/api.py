import threading
import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.database import get_db, SessionLocal
from app.models import Keyword, Scan, DiscoveredRepo, Finding
from app.scanner.orchestrator import run_scan_pipeline, is_scan_running, cleanup_stale_scans
from app.scanner.progress import scan_progress

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/scans/trigger")
def trigger_scan(db: Session = Depends(get_db)):
    """Trigger a manual scan in a background thread."""
    if is_scan_running():
        return JSONResponse({"ok": False, "message": "Scan already running"}, status_code=409)

    # Clean up any stale scans from previous crashes
    cleanup_stale_scans(db)

    def _run():
        db = SessionLocal()
        try:
            run_scan_pipeline(db, trigger_type="manual")
        except Exception:
            logger.exception("Manual scan failed")
        finally:
            db.close()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    return JSONResponse({"ok": True, "message": "Scan started"})


@router.post("/scans/recover")
def recover_scan(db: Session = Depends(get_db)):
    """Resume a failed scan from Stage 3 (Repo-Analyse) in a background thread."""
    if is_scan_running():
        return JSONResponse({"ok": False, "message": "Scan already running"}, status_code=409)

    # Find failed/running scan to recover
    from app.models import Scan as ScanModel
    scan = db.query(ScanModel).filter(ScanModel.status.in_(["failed", "running"])).order_by(ScanModel.id.desc()).first()
    if not scan:
        return JSONResponse({"ok": False, "message": "Kein fehlgeschlagener Scan gefunden"}, status_code=404)

    scan_id = scan.id

    def _run_recovery():
        from app.scanner.recovery import run_recovery
        _db = SessionLocal()
        try:
            run_recovery(_db, scan_id)
        except Exception:
            logger.exception("Recovery failed")
        finally:
            _db.close()

    thread = threading.Thread(target=_run_recovery, daemon=True)
    thread.start()

    return JSONResponse({"ok": True, "message": f"Recovery fuer Scan #{scan_id} gestartet"})


@router.post("/scans/reassess")
def reassess_findings_endpoint(db: Session = Depends(get_db)):
    """Re-run AI assessment on all open findings with updated prompt (incl. matched_snippet)."""
    if is_scan_running():
        return JSONResponse({"ok": False, "message": "Scan already running"}, status_code=409)

    def _run_reassess():
        from app.scanner.recovery import reassess_findings
        _db = SessionLocal()
        try:
            reassess_findings(_db)
        except Exception:
            logger.exception("Reassessment failed")
        finally:
            _db.close()

    thread = threading.Thread(target=_run_reassess, daemon=True)
    thread.start()

    return JSONResponse({"ok": True, "message": "AI-Reassessment gestartet"})


@router.post("/findings/{finding_id}/rescan")
def rescan_finding_endpoint(finding_id: int, db: Session = Depends(get_db)):
    """Re-scan a single finding's repo to verify if it still exists."""
    if is_scan_running():
        return JSONResponse({"ok": False, "message": "Scan laeuft bereits"}, status_code=409)

    finding = db.query(Finding).get(finding_id)
    if not finding:
        return JSONResponse({"ok": False, "message": "Finding nicht gefunden"}, status_code=404)

    def _run_rescan():
        from app.scanner.recovery import rescan_finding
        _db = SessionLocal()
        try:
            rescan_finding(_db, finding_id)
        except Exception:
            logger.exception("Re-Scan failed for finding #%d", finding_id)
        finally:
            _db.close()

    thread = threading.Thread(target=_run_rescan, daemon=True)
    thread.start()

    return JSONResponse({"ok": True, "message": f"Re-Scan fuer Finding #{finding_id} gestartet"})


@router.post("/findings/rescan-all")
def rescan_all_findings_endpoint(db: Session = Depends(get_db)):
    """Re-scan ALL open findings to verify they still exist and backfill matched_snippet."""
    if is_scan_running():
        return JSONResponse({"ok": False, "message": "Scan laeuft bereits"}, status_code=409)

    open_count = db.query(Finding).filter_by(is_resolved=0).count()
    if not open_count:
        return JSONResponse({"ok": False, "message": "Keine offenen Findings vorhanden"}, status_code=404)

    def _run_rescan_all():
        from app.scanner.recovery import rescan_all_findings
        _db = SessionLocal()
        try:
            rescan_all_findings(_db)
        except Exception:
            logger.exception("Re-Scan All failed")
        finally:
            _db.close()

    thread = threading.Thread(target=_run_rescan_all, daemon=True)
    thread.start()

    return JSONResponse({"ok": True, "message": f"Re-Scan fuer {open_count} offene Findings gestartet"})


@router.post("/findings/email-report")
async def findings_email_report(request: Request, db: Session = Depends(get_db)):
    """Send email report for selected findings."""
    body = await request.json()
    finding_ids = body.get("finding_ids", [])
    if not finding_ids:
        return JSONResponse({"ok": False, "message": "Keine Findings ausgewaehlt"}, status_code=400)

    from app.notifications.email_notify import send_findings_report_email
    success, message = send_findings_report_email(db, finding_ids)
    if success:
        return JSONResponse({"ok": True, "message": message})
    else:
        return JSONResponse({"ok": False, "message": message}, status_code=500)


@router.post("/scans/cancel")
def cancel_scan():
    """Request cancellation of the running scan."""
    if not is_scan_running():
        return JSONResponse({"ok": False, "message": "Kein Scan aktiv"}, status_code=409)

    scan_progress.request_cancel()
    scan_progress.add_log("Abbruch angefordert...")
    scan_progress.add_activity("cancel", "Scan-Abbruch angefordert")
    return JSONResponse({"ok": True, "message": "Abbruch angefordert"})


@router.get("/scans/status")
def scan_status(db: Session = Depends(get_db)):
    """Current scan status for JS polling."""
    running = is_scan_running()
    last_scan = db.query(Scan).order_by(Scan.id.desc()).first()

    return JSONResponse({
        "running": running,
        "last_scan": {
            "id": last_scan.id,
            "status": last_scan.status,
            "started_at": last_scan.started_at,
            "finished_at": last_scan.finished_at,
            "new_findings": last_scan.new_findings,
            "repos_scanned": last_scan.repos_scanned,
            "duration_seconds": last_scan.duration_seconds,
        } if last_scan else None,
    })


@router.get("/scans/progress")
def scan_progress_endpoint():
    """Detailed scan progress for live monitoring."""
    data = scan_progress.to_dict()
    # Sync running flag with orchestrator
    data["running"] = is_scan_running()
    return JSONResponse(data)


@router.get("/stats")
def stats(db: Session = Depends(get_db)):
    """Health check + stats endpoint."""
    return JSONResponse({
        "status": "ok",
        "keywords": db.query(Keyword).filter_by(is_active=1).count(),
        "repos": db.query(DiscoveredRepo).count(),
        "open_findings": db.query(Finding).filter_by(is_resolved=0).count(),
        "total_scans": db.query(Scan).count(),
        "scan_running": is_scan_running(),
    })
