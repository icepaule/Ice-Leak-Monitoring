import json

from fastapi import APIRouter, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import DiscoveredRepo, Finding, RepoKeywordMatch

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/repos")
def repos_page(
    request: Request,
    status: str = "",
    sort: str = "last_seen",
    db: Session = Depends(get_db),
):
    query = db.query(DiscoveredRepo)

    if status:
        query = query.filter(DiscoveredRepo.scan_status == status)

    sort_map = {
        "last_seen": DiscoveredRepo.last_seen_at.desc(),
        "name": DiscoveredRepo.full_name.asc(),
        "size": DiscoveredRepo.repo_size_kb.desc(),
        "ai_score": DiscoveredRepo.ai_relevance.desc(),
        "findings": DiscoveredRepo.scan_status.desc(),
    }
    query = query.order_by(sort_map.get(sort, DiscoveredRepo.last_seen_at.desc()))

    repos = query.all()

    # Enrich with finding counts and keyword match details
    for repo in repos:
        repo.finding_count = db.query(Finding).filter_by(repo_id=repo.id, is_resolved=0).count()
        try:
            repo.keywords_list = json.loads(repo.matched_keywords or "[]")
        except (json.JSONDecodeError, TypeError):
            repo.keywords_list = []

        # Load keyword match records
        matches = db.query(RepoKeywordMatch).filter_by(repo_id=repo.id).all()
        for m in matches:
            try:
                m.files_list = json.loads(m.match_files or "[]")
            except (json.JSONDecodeError, TypeError):
                m.files_list = []
        repo.kw_matches = matches

    return templates.TemplateResponse("repos.html", {
        "request": request,
        "repos": repos,
        "current_status": status,
        "current_sort": sort,
    })


@router.get("/repos/{repo_id}")
def repo_detail(repo_id: int, request: Request, db: Session = Depends(get_db)):
    repo = db.query(DiscoveredRepo).get(repo_id)
    if not repo:
        return templates.TemplateResponse("repos.html", {
            "request": request, "repos": [], "current_status": "", "current_sort": "",
        })

    findings = (
        db.query(Finding)
        .filter_by(repo_id=repo_id)
        .order_by(Finding.is_resolved.asc(), Finding.severity.asc(), Finding.id.desc())
        .all()
    )

    try:
        repo.keywords_list = json.loads(repo.matched_keywords or "[]")
    except (json.JSONDecodeError, TypeError):
        repo.keywords_list = []

    # Load keyword match records
    matches = db.query(RepoKeywordMatch).filter_by(repo_id=repo_id).all()
    for m in matches:
        try:
            m.files_list = json.loads(m.match_files or "[]")
        except (json.JSONDecodeError, TypeError):
            m.files_list = []
    repo.kw_matches = matches

    return templates.TemplateResponse("repo_detail.html", {
        "request": request,
        "repo": repo,
        "findings": findings,
    })


@router.post("/repos/{repo_id}/dismiss")
def dismiss_repo(repo_id: int, db: Session = Depends(get_db)):
    repo = db.query(DiscoveredRepo).get(repo_id)
    if repo:
        repo.is_dismissed = 1 if not repo.is_dismissed else 0
        db.commit()
    return JSONResponse({"ok": True, "is_dismissed": repo.is_dismissed if repo else 0})


# --- Keyword Match Toggle ---
@router.patch("/repos/matches/{match_id}")
def toggle_match(match_id: int, db: Session = Depends(get_db)):
    """Toggle a single keyword match active/inactive."""
    match = db.query(RepoKeywordMatch).get(match_id)
    if not match:
        return JSONResponse({"ok": False, "message": "Match nicht gefunden"}, status_code=404)
    match.is_active = 0 if match.is_active else 1
    db.commit()
    return JSONResponse({"ok": True, "is_active": match.is_active})


class AiOverrideRequest(BaseModel):
    ai_scan_enabled: int | None  # 0=block, 1=force, null=auto


@router.post("/repos/{repo_id}/ai-override")
def ai_override(repo_id: int, payload: AiOverrideRequest, db: Session = Depends(get_db)):
    repo = db.query(DiscoveredRepo).get(repo_id)
    if not repo:
        return JSONResponse({"ok": False, "message": "Repo nicht gefunden"}, status_code=404)

    value = payload.ai_scan_enabled
    repo.ai_scan_enabled = value

    # Side-effects on scan_status
    if value == 0 and repo.scan_status == "pending":
        repo.scan_status = "skipped"
    elif value == 1 and repo.scan_status in ("low_relevance", "skipped", "unchanged"):
        repo.scan_status = "pending"

    db.commit()
    return JSONResponse({"ok": True, "ai_scan_enabled": repo.ai_scan_enabled})


class BulkMatchAction(BaseModel):
    match_ids: list[int]
    action: str  # "activate" or "deactivate"


@router.post("/repos/matches/bulk")
def bulk_toggle_matches(payload: BulkMatchAction, db: Session = Depends(get_db)):
    """Bulk activate/deactivate keyword matches."""
    new_val = 1 if payload.action == "activate" else 0
    count = 0
    for mid in payload.match_ids:
        match = db.query(RepoKeywordMatch).get(mid)
        if match:
            match.is_active = new_val
            count += 1
    db.commit()
    return JSONResponse({"ok": True, "updated": count, "is_active": new_val})
