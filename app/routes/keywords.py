from datetime import datetime, timezone

from fastapi import APIRouter, Request, Depends, Form
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Keyword

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


def _utcnow_str():
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat(sep=" ", timespec="seconds")


@router.get("/keywords")
def keywords_page(request: Request, db: Session = Depends(get_db)):
    keywords = db.query(Keyword).order_by(Keyword.category, Keyword.term).all()
    categories = ["general", "company", "domain", "supplier", "email", "custom"]
    return templates.TemplateResponse("keywords.html", {
        "request": request,
        "keywords": keywords,
        "categories": categories,
    })


@router.post("/keywords")
def add_keyword(
    term: str = Form(...),
    category: str = Form("general"),
    db: Session = Depends(get_db),
):
    existing = db.query(Keyword).filter_by(term=term).first()
    if not existing:
        kw = Keyword(term=term, category=category)
        db.add(kw)
        db.commit()
    return RedirectResponse(url="/keywords", status_code=303)


@router.delete("/keywords/{keyword_id}")
def delete_keyword(keyword_id: int, db: Session = Depends(get_db)):
    kw = db.query(Keyword).get(keyword_id)
    if kw:
        db.delete(kw)
        db.commit()
    return JSONResponse({"ok": True})


@router.patch("/keywords/{keyword_id}")
def toggle_keyword(keyword_id: int, db: Session = Depends(get_db)):
    kw = db.query(Keyword).get(keyword_id)
    if kw:
        kw.is_active = 0 if kw.is_active else 1
        kw.updated_at = _utcnow_str()
        db.commit()
        return JSONResponse({"ok": True, "is_active": kw.is_active})
    return JSONResponse({"ok": False}, status_code=404)
