# Ice-Leak-Monitor

Corporate Data Leak Detection System for GitHub.

Automated scanning pipeline that searches GitHub for leaked corporate data, credentials, and sensitive information using multiple detection engines (TruffleHog, Gitleaks, Custom Regex, Blackbird OSINT) with AI-powered relevance assessment via Ollama.

## Features

- **GitHub Code Search** - Keyword-based discovery of potentially leaked repos
- **Multi-Engine Scanning** - TruffleHog + Gitleaks + Custom Regex patterns
- **Blackbird OSINT** - Username/keyword search across platforms
- **AI-Powered Assessment** - Ollama LLM for relevance scoring and finding assessment (MITRE ATT&CK, DORA, BaFin)
- **CISO-Ready Reports** - Email notifications formatted for executive forwarding with full regulatory context
- **Web Dashboard** - Dark-themed UI with real-time scan monitoring
- **Pushover + Email** - Multi-channel alerting with severity-based priority
- **Scheduled Scans** - Daily automated scans via APScheduler
- **Finding Deduplication** - SHA256-based hash dedup across scan runs

## Quick Start

```bash
# Clone
git clone https://github.com/icepaule/Ice-Leak-Monitoring.git
cd Ice-Leak-Monitoring

# Configure
cp .env.example .env
# Edit .env with your credentials

# Run
docker compose up -d

# Open Dashboard
open http://localhost:8080
```

## Configuration

Copy `.env.example` to `.env` and fill in:

| Variable | Required | Description |
|----------|----------|-------------|
| `GITHUB_TOKEN` | Yes | GitHub PAT with `public_repo` scope |
| `PUSHOVER_USER_KEY` | No | Pushover user key |
| `PUSHOVER_API_TOKEN` | No | Pushover app token |
| `SMTP_HOST` | No | SMTP relay host |
| `ALERT_EMAIL_TO` | No | Email recipients (comma-separated) |
| `OLLAMA_BASE_URL` | No | Ollama API URL (default: `http://10.10.0.210:11434`) |
| `OLLAMA_MODEL` | No | Ollama model (default: `llama3`) |
| `BLACKBIRD_ENABLED` | No | Enable Blackbird OSINT (default: `true`) |

## Architecture

```
Docker Container (port 8080)
├── FastAPI Web App
│   ├── Dashboard, Keywords, Repos, Findings, Scans
│   └── REST API for JS frontend
├── APScheduler (daily at 03:00 UTC)
├── Scanner Pipeline
│   ├── GitHub Code Search API
│   ├── Ollama AI Relevance Check
│   ├── TruffleHog (Secret Detection)
│   ├── Gitleaks (Secret Detection)
│   ├── Custom Regex (Company Patterns)
│   └── Blackbird (OSINT)
├── Notifications (Pushover, Email, Dashboard)
└── SQLite Database (/data/iceleakmonitor.db)
```

## Security

- Secret values are **never** stored in the database
- Keywords and credentials only in SQLite (Docker volume) and `.env` (local only)
- GitHub token uses minimal scope (`public_repo` read-only)
- Web UI intended for internal network only
- Ollama requests contain only repo descriptions, never secrets

## License

Internal use only - Muenchener Hypothekenbank eG
