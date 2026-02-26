# Ice-Leak-Monitor - Installationsanleitung

## Voraussetzungen

- **Docker** >= 24.0 und **Docker Compose** >= 2.20
- **GitHub Personal Access Token** (fuer GitHub Code Search API)
- Mindestens 2 GB RAM, 10 GB Speicherplatz
- Internetzugang (fuer GitHub API, OSINT-Module, Tool-Downloads)

### Optional

- **Ollama** Server mit LLM (z.B. llama3) fuer AI-Relevanzpruefung
- **Pushover** Account fuer Push-Benachrichtigungen
- **SMTP** Server fuer E-Mail-Benachrichtigungen
- **Hunter.io** API-Key fuer E-Mail-Finder
- **LeakCheck** API-Key fuer Leak-Pruefung

---

## Schritt 1: Repository klonen

```bash
git clone https://github.com/icepaule/Ice-Leak-Monitoring.git
cd Ice-Leak-Monitoring
```

## Schritt 2: Umgebungsvariablen konfigurieren

```bash
cp .env.example .env
nano .env
```

Folgende Variablen muessen gesetzt werden:

```ini
# === Pflicht ===
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# === Optional: Benachrichtigungen ===
PUSHOVER_USER_KEY=your_user_key
PUSHOVER_API_TOKEN=your_api_token

SMTP_HOST=mail.example.com
SMTP_PORT=25
SMTP_USERNAME=user@example.com
SMTP_PASSWORD=your_password
ALERT_EMAIL_FROM=monitor@example.com
ALERT_EMAIL_TO=admin@example.com

# === Optional: AI-Relevanzpruefung ===
OLLAMA_BASE_URL=http://your-ollama-host:11434
OLLAMA_MODEL=llama3

# === Scan-Zeitplan (UTC) ===
SCAN_SCHEDULE_HOUR=3
SCAN_SCHEDULE_MINUTE=0

# === Timeouts ===
TRUFFLEHOG_TIMEOUT=300
GITLEAKS_TIMEOUT=300
MAX_REPO_SIZE_MB=500

# === App ===
SECRET_KEY=ein-sicherer-zufaelliger-string
TZ=Europe/Berlin
```

### GitHub Token erstellen

1. Oeffne [github.com/settings/tokens](https://github.com/settings/tokens)
2. Klicke "Generate new token (classic)"
3. Benoetigte Scopes: `repo` (vollstaendig), `read:org`
4. Token kopieren und in `.env` eintragen

## Schritt 3: Docker Image bauen und starten

```bash
docker compose up -d --build
```

Beim ersten Start werden automatisch:
- TruffleHog, Gitleaks, Subfinder und Blackbird installiert
- Python-Abhaengigkeiten (theHarvester, CrossLinked) installiert
- SQLite-Datenbank initialisiert
- OSINT-Modul-Einstellungen angelegt

### Build-Ausgabe pruefen

```bash
docker compose logs -f
```

Erwartete Ausgabe:
```
=== Ice-Leak-Monitor Starting ===
Database: /data/iceleakmonitor.db
trufflehog 3.x.x
gitleaks 8.30.0
blackbird OK (/opt/blackbird)
Database initialized
OSINT module settings seeded
Scheduler started - daily scan at 03:00 UTC
Uvicorn running on http://0.0.0.0:8080
```

## Schritt 4: Web-Interface oeffnen

Das Dashboard ist erreichbar unter:

```
http://<server-ip>:8084
```

> **Hinweis:** Der Docker-Container lauscht intern auf Port 8080. In der `docker-compose.yml` wird dieser auf Port 8084 gemappt. Passe den Port bei Bedarf an.

## Schritt 5: Erste Konfiguration

### 5.1 Keywords anlegen

1. Oeffne **Keywords** in der Sidebar
2. Gib Suchbegriffe ein (Firmenname, Domain, E-Mail, etc.)
3. Waehle die passende Kategorie (company, domain, email, supplier, custom)
4. Klicke "Hinzufuegen"

### 5.2 OSINT-Module konfigurieren

1. Oeffne **Einstellungen** in der Sidebar
2. Aktiviere gewuenschte Module per Toggle-Schalter
3. Fuer Hunter.io / LeakCheck: API-Key eingeben und "Speichern" klicken

### 5.3 Ersten Scan starten

1. Oeffne das **Dashboard**
2. Klicke "Scan laeuft..." / "Scan starten"
3. Verfolge den Fortschritt im Live Scan Monitor

---

## Docker Compose Konfiguration

```yaml
services:
  iceleakmonitor:
    build: .
    container_name: iceleakmonitor
    restart: unless-stopped
    ports:
      - "8084:8080"
    env_file:
      - .env
    volumes:
      - ./data:/data
    healthcheck:
      test: ["CMD", "bash", "scripts/healthcheck.sh"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Persistente Daten

Alle Daten werden in `./data/iceleakmonitor.db` gespeichert (SQLite):
- Keywords, Scan-Ergebnisse, Findings, OSINT-Ergebnisse
- Modul-Einstellungen (inklusive API-Keys)

### Backup

```bash
# Datenbank sichern
cp data/iceleakmonitor.db data/iceleakmonitor_backup_$(date +%Y%m%d).db

# Oder mit laufendem Container
docker compose exec iceleakmonitor sqlite3 /data/iceleakmonitor.db ".backup /data/backup.db"
```

---

## Update

```bash
git pull
docker compose up -d --build
```

Die Datenbank wird automatisch migriert (neue Tabellen werden angelegt, bestehende Daten bleiben erhalten).

---

## Fehlerbehebung

### Container startet nicht

```bash
docker compose logs --tail=50
```

### Datenbank-Probleme

```bash
# DB-Integritaet pruefen
docker compose exec iceleakmonitor sqlite3 /data/iceleakmonitor.db "PRAGMA integrity_check"
```

### OSINT-Module funktionieren nicht

- Pruefe ob die Tools installiert sind: `docker compose exec iceleakmonitor which subfinder`
- Pruefe API-Keys auf der Einstellungsseite
- Container-Logs fuer Fehlermeldungen pruefen

### GitHub Rate-Limiting

- Die Anwendung respektiert GitHub API Rate-Limits automatisch
- Bei haueufigen 403-Fehlern: Token-Berechtigungen pruefen
