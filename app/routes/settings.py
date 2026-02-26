"""Settings page for OSINT module configuration."""

import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ModuleSetting, OsintResult

router = APIRouter()
logger = logging.getLogger(__name__)
templates = Jinja2Templates(directory="app/templates")


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, db: Session = Depends(get_db)):
    """Render the settings page with all module settings."""
    modules = db.query(ModuleSetting).order_by(ModuleSetting.id).all()

    # Parse config_json for display
    module_list = []
    for m in modules:
        config = {}
        if m.config_json:
            try:
                config = json.loads(m.config_json)
            except (json.JSONDecodeError, TypeError):
                config = {}

        module_list.append({
            "module_key": m.module_key,
            "display_name": m.display_name,
            "description": m.description,
            "is_enabled": m.is_enabled,
            "has_api_key": bool(config.get("api_key")),
            "api_key_masked": _mask_key(config.get("api_key", "")),
            "needs_api_key": m.module_key in ("hunter_io", "leakcheck"),
            "updated_at": m.updated_at,
        })

    # Recent OSINT results
    recent_results = db.query(OsintResult).order_by(OsintResult.id.desc()).limit(50).all()

    return templates.TemplateResponse("settings.html", {
        "request": request,
        "modules": module_list,
        "recent_results": recent_results,
    })


@router.post("/settings/modules/{module_key}/toggle")
def toggle_module(module_key: str, db: Session = Depends(get_db)):
    """Toggle a module on/off."""
    module = db.query(ModuleSetting).filter_by(module_key=module_key).first()
    if not module:
        return JSONResponse({"ok": False, "message": "Modul nicht gefunden"}, status_code=404)

    module.is_enabled = 0 if module.is_enabled else 1
    module.updated_at = datetime.now(timezone.utc).replace(tzinfo=None).isoformat(sep=" ", timespec="seconds")
    db.commit()

    logger.info("Module '%s' toggled to %s", module_key, "enabled" if module.is_enabled else "disabled")
    return JSONResponse({
        "ok": True,
        "module_key": module_key,
        "is_enabled": module.is_enabled,
    })


@router.post("/settings/modules/{module_key}/config")
async def save_module_config(module_key: str, request: Request, db: Session = Depends(get_db)):
    """Save module configuration (API key etc.)."""
    module = db.query(ModuleSetting).filter_by(module_key=module_key).first()
    if not module:
        return JSONResponse({"ok": False, "message": "Modul nicht gefunden"}, status_code=404)

    body = await request.json()
    api_key = body.get("api_key", "").strip()

    # Merge into existing config
    config = {}
    if module.config_json:
        try:
            config = json.loads(module.config_json)
        except (json.JSONDecodeError, TypeError):
            config = {}

    if api_key:
        config["api_key"] = api_key
    elif "api_key" in config:
        del config["api_key"]

    module.config_json = json.dumps(config) if config else None
    module.updated_at = datetime.now(timezone.utc).replace(tzinfo=None).isoformat(sep=" ", timespec="seconds")
    db.commit()

    logger.info("Module '%s' config updated", module_key)
    return JSONResponse({
        "ok": True,
        "module_key": module_key,
        "has_api_key": bool(config.get("api_key")),
    })


def _mask_key(key: str) -> str:
    """Mask an API key for display."""
    if not key:
        return ""
    if len(key) <= 8:
        return "****"
    return key[:4] + "****" + key[-4:]
