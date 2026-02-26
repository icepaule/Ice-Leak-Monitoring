"""Seed default OSINT module settings into the database."""

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import ModuleSetting
from app.config import settings

logger = logging.getLogger(__name__)

DEFAULT_MODULES = [
    {
        "module_key": "blackbird",
        "display_name": "Blackbird",
        "description": "Username/E-Mail OSINT - sucht Accounts auf Plattformen",
        "is_enabled": 1,  # Migrated from settings.blackbird_enabled
    },
    {
        "module_key": "subfinder",
        "display_name": "Subfinder",
        "description": "Subdomain-Enumeration per DNS/CT-Logs (projectdiscovery)",
        "is_enabled": 0,
    },
    {
        "module_key": "theharvester",
        "display_name": "theHarvester",
        "description": "E-Mails, Hosts und IPs per Suchmaschinen sammeln",
        "is_enabled": 0,
    },
    {
        "module_key": "crosslinked",
        "display_name": "CrossLinked",
        "description": "LinkedIn-Personensuche nach Mitarbeitern",
        "is_enabled": 0,
    },
    {
        "module_key": "hunter_io",
        "display_name": "Hunter.io",
        "description": "E-Mail-Finder per Domain (API-Key erforderlich)",
        "is_enabled": 0,
    },
    {
        "module_key": "gitdorker",
        "display_name": "GitDorker",
        "description": "GitHub Dork-Suche nach Secrets und Credentials",
        "is_enabled": 0,
    },
    {
        "module_key": "leakcheck",
        "display_name": "LeakCheck",
        "description": "E-Mail/Domain Leak-Pruefung (API-Key erforderlich)",
        "is_enabled": 0,
    },
]


def seed_default_modules(db: Session):
    """Insert default module settings if they don't exist yet."""
    now_str = datetime.now(timezone.utc).replace(tzinfo=None).isoformat(sep=" ", timespec="seconds")
    added = 0

    for mod in DEFAULT_MODULES:
        existing = db.query(ModuleSetting).filter_by(module_key=mod["module_key"]).first()
        if existing:
            continue

        # Migrate blackbird_enabled from config
        is_enabled = mod["is_enabled"]
        if mod["module_key"] == "blackbird":
            is_enabled = 1 if settings.blackbird_enabled else 0

        entry = ModuleSetting(
            module_key=mod["module_key"],
            display_name=mod["display_name"],
            description=mod["description"],
            is_enabled=is_enabled,
            updated_at=now_str,
        )
        db.add(entry)
        added += 1

    if added:
        db.commit()
        logger.info("Seeded %d default OSINT module settings", added)
