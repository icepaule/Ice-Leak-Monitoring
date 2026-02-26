from fastapi import APIRouter, Request, Depends
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Scan, Finding, DiscoveredRepo, NotificationLog

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/scans")
def scans_page(request: Request, db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.id.desc()).all()
    return templates.TemplateResponse("scans.html", {
        "request": request,
        "scans": scans,
    })


@router.get("/scans/{scan_id}")
def scan_detail(scan_id: int, request: Request, db: Session = Depends(get_db)):
    scan = db.query(Scan).get(scan_id)
    if not scan:
        return templates.TemplateResponse("scans.html", {
            "request": request, "scans": [],
        })

    findings = db.query(Finding).filter_by(scan_id=scan_id).all()
    for f in findings:
        f.repo = db.query(DiscoveredRepo).get(f.repo_id)

    notifications = db.query(NotificationLog).filter_by(scan_id=scan_id).all()

    return templates.TemplateResponse("scan_detail.html", {
        "request": request,
        "scan": scan,
        "findings": findings,
        "notifications": notifications,
    })
