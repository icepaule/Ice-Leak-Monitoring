import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from apscheduler.schedulers.background import BackgroundScheduler

from app.config import settings
from app.database import init_db, SessionLocal
from app.scanner.orchestrator import run_scan_pipeline, cleanup_stale_scans
from app.scanner.seed_modules import seed_default_modules

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("iceleakmonitor")

scheduler = BackgroundScheduler(timezone="UTC")


def scheduled_scan():
    logger.info("Scheduled scan starting...")
    db = SessionLocal()
    try:
        run_scan_pipeline(db, trigger_type="scheduled")
    except Exception:
        logger.exception("Scheduled scan failed")
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    logger.info("Database initialized")

    # Seed default OSINT module settings
    db = SessionLocal()
    try:
        seed_default_modules(db)
    finally:
        db.close()
    logger.info("OSINT module settings seeded")

    # Clean up scans stuck in 'running' from previous crash
    db = SessionLocal()
    try:
        cleanup_stale_scans(db)
    finally:
        db.close()

    scheduler.add_job(
        scheduled_scan,
        "cron",
        hour=settings.scan_schedule_hour,
        minute=settings.scan_schedule_minute,
        id="daily_scan",
        replace_existing=True,
    )
    scheduler.start()
    logger.info(
        "Scheduler started - daily scan at %02d:%02d UTC",
        settings.scan_schedule_hour,
        settings.scan_schedule_minute,
    )

    yield

    # Shutdown
    scheduler.shutdown(wait=False)
    logger.info("Scheduler stopped")


app = FastAPI(
    title="Ice-Leak-Monitor",
    description="Corporate Data Leak Detection Dashboard",
    version="1.0.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory="static"), name="static")

# Register routes
from app.routes.dashboard import router as dashboard_router
from app.routes.keywords import router as keywords_router
from app.routes.repos import router as repos_router
from app.routes.findings import router as findings_router
from app.routes.scans import router as scans_router
from app.routes.api import router as api_router
from app.routes.settings import router as settings_router

app.include_router(dashboard_router)
app.include_router(keywords_router)
app.include_router(repos_router)
app.include_router(findings_router)
app.include_router(scans_router)
app.include_router(api_router, prefix="/api")
app.include_router(settings_router)
