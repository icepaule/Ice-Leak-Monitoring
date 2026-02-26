from fastapi import APIRouter, Request, Depends
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models import Keyword, Scan, DiscoveredRepo, Finding

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/")
def dashboard(request: Request, db: Session = Depends(get_db)):
    active_keywords = db.query(Keyword).filter_by(is_active=1).count()
    total_repos = db.query(DiscoveredRepo).filter_by(is_dismissed=0).count()
    open_findings = db.query(Finding).filter_by(is_resolved=0).count()
    last_scan = db.query(Scan).order_by(Scan.id.desc()).first()

    recent_scans = db.query(Scan).order_by(Scan.id.desc()).limit(10).all()
    recent_findings = (
        db.query(Finding)
        .filter_by(is_resolved=0)
        .order_by(Finding.id.desc())
        .limit(5)
        .all()
    )

    # Enrich findings with repo info
    for f in recent_findings:
        f.repo = db.query(DiscoveredRepo).get(f.repo_id)

    # Weekly findings for chart (last 12 weeks)
    weekly_data = (
        db.query(
            func.strftime("%Y-W%W", Finding.first_seen_at).label("week"),
            func.count(Finding.id).label("count"),
        )
        .group_by("week")
        .order_by(func.strftime("%Y-W%W", Finding.first_seen_at).desc())
        .limit(12)
        .all()
    )
    weekly_data = list(reversed(weekly_data))

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "active_keywords": active_keywords,
        "total_repos": total_repos,
        "open_findings": open_findings,
        "last_scan": last_scan,
        "recent_scans": recent_scans,
        "recent_findings": recent_findings,
        "weekly_labels": [w.week for w in weekly_data],
        "weekly_counts": [w.count for w in weekly_data],
    })
