import json
import logging

import httpx

from sqlalchemy.orm import Session
from app.config import settings
from app.models import Scan, Finding, DiscoveredRepo, NotificationLog

logger = logging.getLogger(__name__)

PUSHOVER_API = "https://api.pushover.net/1/messages.json"


def send_scan_notification(db: Session, scan: Scan):
    """Send Pushover notification for scan results."""
    if not settings.pushover_user_key or not settings.pushover_api_token:
        logger.info("Pushover not configured, skipping")
        _log_notification(db, scan.id, "pushover", "Pushover not configured", "skipped")
        return

    new_findings = db.query(Finding).filter_by(scan_id=scan.id).all()
    if not new_findings:
        return

    # Check for verified findings (critical)
    verified = [f for f in new_findings if f.verified]
    has_verified = len(verified) > 0

    # Build message
    if has_verified:
        title = f"VERIFIED Credentials gefunden! ({len(verified)})"
        priority = 1  # High priority with sound
    else:
        title = f"{len(new_findings)} neue Findings"
        priority = 0

    # Severity breakdown
    critical = sum(1 for f in new_findings if f.severity == "critical")
    high = sum(1 for f in new_findings if f.severity == "high")
    medium = sum(1 for f in new_findings if f.severity == "medium")

    # Repos involved
    repo_ids = {f.repo_id for f in new_findings}
    repos = db.query(DiscoveredRepo).filter(DiscoveredRepo.id.in_(repo_ids)).all()
    repo_names = [r.full_name for r in repos[:5]]

    message = (
        f"Scan #{scan.id} abgeschlossen\n"
        f"Critical: {critical} | High: {high} | Medium: {medium}\n"
        f"Repos: {', '.join(repo_names)}"
    )
    if len(repos) > 5:
        message += f" (+{len(repos) - 5} weitere)"

    try:
        resp = httpx.post(
            PUSHOVER_API,
            data={
                "token": settings.pushover_api_token,
                "user": settings.pushover_user_key,
                "title": f"[IceLeakMonitor] {title}",
                "message": message,
                "priority": priority,
                "sound": "siren" if has_verified else "pushover",
                "html": 0,
            },
            timeout=15.0,
        )
        resp.raise_for_status()
        _log_notification(db, scan.id, "pushover", title, "sent")
        logger.info("Pushover notification sent: %s", title)
    except Exception as e:
        logger.exception("Pushover notification failed")
        _log_notification(db, scan.id, "pushover", title, "failed", str(e))


def _log_notification(db: Session, scan_id: int, channel: str, subject: str,
                      status: str, error: str = None):
    log = NotificationLog(
        scan_id=scan_id,
        channel=channel,
        subject=subject,
        status=status,
        error_message=error,
    )
    db.add(log)
    db.commit()
