# Ice-Leak-Monitor - Dokumentation

## Uebersicht

Ice-Leak-Monitor ueberwacht kontinuierlich GitHub auf unbeabsichtigt veroeffentlichte Unternehmensdaten. Das System sucht automatisiert nach Firmennamen, Domains und E-Mail-Adressen in oeffentlichem Quellcode, fuehrt OSINT-Aufklaerung durch und bewertet Funde mittels lokaler KI-Analyse (Ollama). Findings werden in MITRE ATT&CK, DORA und BaFin-Kontext eingeordnet.

**Scan-Pipeline (5 Stages):** Vorbereitung → OSINT → GitHub-Suche → Repo-Analyse (per Repo: Skip-Check, AI-Relevanz, Deep Scan, AI-Assessment) → Abschluss mit Benachrichtigungen.

## Inhaltsverzeichnis

1. [Installationsanleitung](INSTALL.md) - Schritt-fuer-Schritt Setup
2. [Benutzerhandbuch](BENUTZERHANDBUCH.md) - Bedienung des Dashboards
3. [Adminhandbuch](ADMINHANDBUCH.md) - Konfiguration, OSINT-Module, Wartung

## Screenshots

| Seite | Beschreibung |
|-------|-------------|
| ![Dashboard](screenshots/dashboard.png) | Dashboard mit Live Scan Monitor (5 Stages) |
| ![Settings](screenshots/settings.png) | Einstellungen: E-Mail-Empfaenger + OSINT-Module |
| ![Settings Prompt](screenshots/settings_prompt.png) | AI-Bewertungsprompt Editor |
| ![Keywords](screenshots/keywords.png) | Keyword-Verwaltung |
| ![Repos](screenshots/repos.png) | Gefundene Repositories mit AI-Override |
| ![Repo Detail](screenshots/repo_detail.png) | Repository-Detailseite mit Keyword-Matches |
| ![Findings](screenshots/findings.png) | Security Findings mit Mail-Report |
| ![Scans](screenshots/scans.png) | Scan-Verlauf |
