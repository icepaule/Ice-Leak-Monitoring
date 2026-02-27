"""Settings page for OSINT module configuration."""

import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import settings as app_settings
from app.models import ModuleSetting, OsintResult, AppSetting
from app.scanner.ollama_reviewer import FINDING_ASSESSMENT_PROMPT

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

    # Load custom finding prompt
    prompt_setting = db.query(AppSetting).filter_by(key="finding_prompt").first()
    finding_prompt = prompt_setting.value if prompt_setting and prompt_setting.value else FINDING_ASSESSMENT_PROMPT

    # Load email recipients (DB overrides .env)
    email_setting = db.query(AppSetting).filter_by(key="alert_email_to").first()
    email_recipients = email_setting.value if email_setting and email_setting.value else app_settings.alert_email_to

    # Recent OSINT results
    recent_results = db.query(OsintResult).order_by(OsintResult.id.desc()).limit(50).all()

    return templates.TemplateResponse("settings.html", {
        "request": request,
        "modules": module_list,
        "recent_results": recent_results,
        "finding_prompt": finding_prompt,
        "email_recipients": email_recipients,
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


@router.post("/settings/email-recipients")
async def save_email_recipients(request: Request, db: Session = Depends(get_db)):
    """Save email recipients for scan reports."""
    body = await request.json()
    recipients = body.get("recipients", "").strip()
    if not recipients:
        return JSONResponse({"ok": False, "message": "Mindestens eine E-Mail-Adresse angeben"}, status_code=400)

    setting = db.query(AppSetting).filter_by(key="alert_email_to").first()
    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat(sep=" ", timespec="seconds")
    if setting:
        setting.value = recipients
        setting.updated_at = now
    else:
        setting = AppSetting(key="alert_email_to", value=recipients, updated_at=now)
        db.add(setting)
    db.commit()

    logger.info("Email recipients updated to: %s", recipients)
    return JSONResponse({"ok": True})


@router.post("/settings/prompts/finding")
async def save_finding_prompt(request: Request, db: Session = Depends(get_db)):
    """Save custom finding assessment prompt."""
    body = await request.json()
    prompt_text = body.get("prompt", "").strip()
    if not prompt_text:
        return JSONResponse({"ok": False, "message": "Prompt darf nicht leer sein"}, status_code=400)

    setting = db.query(AppSetting).filter_by(key="finding_prompt").first()
    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat(sep=" ", timespec="seconds")
    if setting:
        setting.value = prompt_text
        setting.updated_at = now
    else:
        setting = AppSetting(key="finding_prompt", value=prompt_text, updated_at=now)
        db.add(setting)
    db.commit()

    logger.info("Finding prompt updated")
    return JSONResponse({"ok": True})


@router.post("/settings/prompts/finding/reset")
def reset_finding_prompt(db: Session = Depends(get_db)):
    """Reset finding prompt to default."""
    setting = db.query(AppSetting).filter_by(key="finding_prompt").first()
    if setting:
        db.delete(setting)
        db.commit()

    logger.info("Finding prompt reset to default")
    return JSONResponse({"ok": True, "prompt": FINDING_ASSESSMENT_PROMPT})


def _mask_key(key: str) -> str:
    """Mask an API key for display."""
    if not key:
        return ""
    if len(key) <= 8:
        return "****"
    return key[:4] + "****" + key[-4:]
