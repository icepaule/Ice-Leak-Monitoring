from datetime import datetime, timezone

from fastapi import APIRouter, Request, Depends, Body
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Finding, DiscoveredRepo, RepoKeywordMatch

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/findings")
def findings_page(
    request: Request,
    scanner: str = "",
    severity: str = "",
    status: str = "open",
    db: Session = Depends(get_db),
):
    query = db.query(Finding)

    if scanner:
        query = query.filter(Finding.scanner == scanner)
    if severity:
        query = query.filter(Finding.severity == severity)
    if status == "open":
        query = query.filter(Finding.is_resolved == 0)
    elif status == "resolved":
        query = query.filter(Finding.is_resolved == 1)

    findings = query.order_by(
        Finding.is_resolved.asc(),
        Finding.severity.asc(),
        Finding.id.desc(),
    ).all()

    # Enrich with repo info
    for f in findings:
        f.repo = db.query(DiscoveredRepo).get(f.repo_id)

    # Load keyword matches grouped by repo_id
    repo_ids = list({f.repo_id for f in findings})
    keyword_map = {}
    if repo_ids:
        kw_matches = db.query(RepoKeywordMatch).filter(RepoKeywordMatch.repo_id.in_(repo_ids)).all()
        for m in kw_matches:
            keyword_map.setdefault(m.repo_id, []).append(m.keyword)
        # Deduplicate keywords per repo
        for rid in keyword_map:
            keyword_map[rid] = list(dict.fromkeys(keyword_map[rid]))

    return templates.TemplateResponse("findings.html", {
        "request": request,
        "findings": findings,
        "current_scanner": scanner,
        "current_severity": severity,
        "current_status": status,
        "keyword_map": keyword_map,
    })


@router.patch("/findings/{finding_id}")
def update_finding(
    finding_id: int,
    notes: str = Body("", embed=True),
    db: Session = Depends(get_db),
):
    finding = db.query(Finding).get(finding_id)
    if not finding:
        return JSONResponse({"ok": False}, status_code=404)

    if finding.is_resolved:
        finding.is_resolved = 0
        finding.resolved_at = None
    else:
        finding.is_resolved = 1
        finding.resolved_at = datetime.now(timezone.utc).replace(tzinfo=None).isoformat(sep=" ", timespec="seconds")

    if notes:
        finding.notes = notes

    db.commit()
    return JSONResponse({
        "ok": True,
        "is_resolved": finding.is_resolved,
    })
