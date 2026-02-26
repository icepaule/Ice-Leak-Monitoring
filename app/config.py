from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # GitHub
    github_token: str = ""

    # Pushover
    pushover_user_key: str = ""
    pushover_api_token: str = ""

    # SMTP
    smtp_host: str = ""
    smtp_port: int = 25
    smtp_username: str = ""
    smtp_password: str = ""
    alert_email_from: str = ""
    alert_email_to: str = ""

    # Ollama
    ollama_base_url: str = "http://10.10.0.210:11434"
    ollama_model: str = "llama3"

    # Blackbird
    blackbird_enabled: bool = True

    # Schedule (local timezone via TZ env var)
    scan_schedule_hour: int = 1
    scan_schedule_minute: int = 0
    tz: str = "Europe/Berlin"

    # Timeouts
    trufflehog_timeout: int = 300
    gitleaks_timeout: int = 300
    max_repo_size_mb: int = 500

    # App
    secret_key: str = "change-me"
    db_path: str = "/data/iceleakmonitor.db"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
