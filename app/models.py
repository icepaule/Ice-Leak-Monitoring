from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, Text, Float, ForeignKey, func
)
from sqlalchemy.orm import relationship

from app.database import Base


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Keyword(Base):
    __tablename__ = "keywords"

    id = Column(Integer, primary_key=True, autoincrement=True)
    term = Column(Text, nullable=False, unique=True)
    category = Column(Text, nullable=False, default="general")
    is_active = Column(Integer, nullable=False, default=1)
    created_at = Column(Text, nullable=False, default=lambda: _utcnow().isoformat(sep=" ", timespec="seconds"))
    updated_at = Column(Text, nullable=False, default=lambda: _utcnow().isoformat(sep=" ", timespec="seconds"))


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    started_at = Column(Text, nullable=False, default=lambda: _utcnow().isoformat(sep=" ", timespec="seconds"))
    finished_at = Column(Text)
    status = Column(Text, nullable=False, default="running")
    trigger_type = Column(Text, nullable=False, default="scheduled")
    keywords_used = Column(Integer, default=0)
    repos_found = Column(Integer, default=0)
    repos_scanned = Column(Integer, default=0)
    new_findings = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    error_message = Column(Text)
    duration_seconds = Column(Float)

    findings = relationship("Finding", back_populates="scan")
    notification_logs = relationship("NotificationLog", back_populates="scan")


class DiscoveredRepo(Base):
    __tablename__ = "discovered_repos"

    id = Column(Integer, primary_key=True, autoincrement=True)
    full_name = Column(Text, nullable=False, unique=True)
    html_url = Column(Text, nullable=False)
    description = Column(Text)
    owner_login = Column(Text)
    owner_type = Column(Text)
    repo_size_kb = Column(Integer)
    default_branch = Column(Text)
    language = Column(Text)
    is_fork = Column(Integer, default=0)
    stargazers = Column(Integer, default=0)
    first_seen_at = Column(Text, nullable=False, default=lambda: _utcnow().isoformat(sep=" ", timespec="seconds"))
    last_seen_at = Column(Text, nullable=False, default=lambda: _utcnow().isoformat(sep=" ", timespec="seconds"))
    last_scanned_at = Column(Text)
    scan_duration_s = Column(Float)
    scan_status = Column(Text, default="pending")
    matched_keywords = Column(Text)  # JSON array
    ai_relevance = Column(Float)
    ai_summary = Column(Text)
    is_dismissed = Column(Integer, default=0)

    findings = relationship("Finding", back_populates="repo")
    keyword_matches = relationship("RepoKeywordMatch", back_populates="repo", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_hash = Column(Text, nullable=False, unique=True)
    repo_id = Column(Integer, ForeignKey("discovered_repos.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    scanner = Column(Text, nullable=False)
    detector_name = Column(Text, nullable=False)
    verified = Column(Integer, default=0)
    file_path = Column(Text)
    commit_hash = Column(Text)
    line_number = Column(Integer)
    severity = Column(Text, default="medium")
    ai_assessment = Column(Text)
    first_seen_at = Column(Text, nullable=False, default=lambda: _utcnow().isoformat(sep=" ", timespec="seconds"))
    last_seen_at = Column(Text, nullable=False, default=lambda: _utcnow().isoformat(sep=" ", timespec="seconds"))
    is_resolved = Column(Integer, default=0)
    resolved_at = Column(Text)
    notes = Column(Text)

    repo = relationship("DiscoveredRepo", back_populates="findings")
    scan = relationship("Scan", back_populates="findings")


class RepoKeywordMatch(Base):
    __tablename__ = "repo_keyword_matches"

    id = Column(Integer, primary_key=True, autoincrement=True)
    repo_id = Column(Integer, ForeignKey("discovered_repos.id"), nullable=False)
    keyword = Column(Text, nullable=False)
    match_source = Column(Text, nullable=False, default="code_search")  # code_search, description, readme, blackbird
    match_files = Column(Text)   # JSON array of file paths where keyword was found
    match_context = Column(Text) # Short description of why this matched
    is_active = Column(Integer, nullable=False, default=1)  # 1=valid, 0=false positive
    created_at = Column(Text, nullable=False, default=lambda: _utcnow().isoformat(sep=" ", timespec="seconds"))

    repo = relationship("DiscoveredRepo", back_populates="keyword_matches")


class NotificationLog(Base):
    __tablename__ = "notifications_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    channel = Column(Text, nullable=False)
    subject = Column(Text)
    status = Column(Text, nullable=False)
    error_message = Column(Text)
    sent_at = Column(Text, nullable=False, default=lambda: _utcnow().isoformat(sep=" ", timespec="seconds"))

    scan = relationship("Scan", back_populates="notification_logs")


class ModuleSetting(Base):
    __tablename__ = "module_settings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    module_key = Column(Text, unique=True, nullable=False)  # e.g. "subfinder"
    display_name = Column(Text, nullable=False)
    description = Column(Text)
    is_enabled = Column(Integer, default=0)  # 0=off, 1=on
    config_json = Column(Text)  # e.g. {"api_key":"..."} for Hunter.io/LeakCheck
    updated_at = Column(Text, default=lambda: _utcnow().isoformat(sep=" ", timespec="seconds"))


class OsintResult(Base):
    __tablename__ = "osint_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    module_key = Column(Text, nullable=False)
    keyword_used = Column(Text, nullable=False)
    result_type = Column(Text)  # "subdomain", "email", "person", "ip", "leak", "github_dork"
    result_value = Column(Text, nullable=False)
    metadata_json = Column(Text)  # Additional info as JSON
    created_at = Column(Text, default=lambda: _utcnow().isoformat(sep=" ", timespec="seconds"))

    scan = relationship("Scan")
