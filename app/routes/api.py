import threading
import logging

from fastapi import APIRouter, Depends
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
