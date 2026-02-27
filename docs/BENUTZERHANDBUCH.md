# Ice-Leak-Monitor - Benutzerhandbuch

## Uebersicht

Der Ice-Leak-Monitor ist ein automatisiertes System zur Erkennung von Datenlecks auf GitHub. Er durchsucht GitHub nach sensiblen Informationen die mit Ihren konfigurierten Keywords (Firmenname, Domain, E-Mail) uebereinstimmen und bewertet Funde mittels KI.

---

## 1. Dashboard

![Dashboard](screenshots/dashboard.png)

Das Dashboard zeigt den aktuellen Status auf einen Blick:

### Statistik-Karten

| Karte | Beschreibung |
|-------|-------------|
| **Keywords aktiv** | Anzahl der aktiven Suchbegriffe |
| **Repos gefunden** | Gesamtanzahl entdeckter Repositories |
| **Offene Findings** | Ungeloeste Security-Findings |
| **Letzter Scan** | Datum des letzten Scan-Durchlaufs |

### Scan starten / abbrechen

- **"Scan starten"** - Startet einen manuellen Scan-Durchlauf
- **"Scan abbrechen"** - Bricht den laufenden Scan ab

### Live Scan Monitor

Waehrend eines Scans zeigt der Monitor den Fortschritt in Echtzeit:

| Stage | Beschreibung |
|-------|-------------|
| **0 Vorbereitung** | Keywords aus der Datenbank laden |
| **1 OSINT** | Aktivierte OSINT-Module ausfuehren (Subfinder, theHarvester, etc.) |
| **2 GitHub-Suche** | GitHub Code Search fuer alle Keywords, Repo-Details abrufen |
| **3 Repo-Analyse** | Per Repo: AI-Check, Skip-Pruefung, Deep Scan, AI-Assessment, DB-Commit |
| **4 Abschluss** | Benachrichtigungen senden, Scan abschliessen |

In Stage 3 wird jedes Repository einzeln komplett abgearbeitet (AI-Relevanzpruefung, Deep Scan, Finding-Bewertung), bevor das naechste drankommt. Findings erscheinen sofort im Dashboard — Sie muessen nicht warten bis alle Repos gescannt sind.

Das **Log-Fenster** zeigt detaillierte Fortschrittsmeldungen. Es ist scrollbar - Sie koennen nach oben scrollen um fruehere Eintraege zu sehen.

### Letzte Scans & Aktivitaeten

- **Letzte Scans**: Tabelle der letzten 10 Scans mit Status, Repos, Findings und Dauer
- **Letzte Aktivitaeten**: Live-Feed der aktuellen Scan-Aktionen

---

## 2. Keywords

![Keywords](screenshots/keywords.png)

Keywords sind die Suchbegriffe, nach denen auf GitHub gesucht wird.

### Keyword hinzufuegen

1. Suchbegriff eingeben
2. Kategorie waehlen:
   - **company** - Firmenname (z.B. "Beispiel GmbH")
   - **domain** - Domain (z.B. "beispiel.de")
   - **email** - E-Mail-Adresse (z.B. "info@beispiel.de")
   - **supplier** - Dienstleister/Lieferant
   - **custom** - Benutzerdefinierter Suchbegriff
3. "Hinzufuegen" klicken

### Keywords verwalten

- **Deaktivieren** - Keyword wird bei naechstem Scan uebersprungen (nicht geloescht)
- **Aktivieren** - Deaktiviertes Keyword wieder aktivieren
- **Loeschen** - Keyword endgueltig entfernen

> **Tipp:** Verwenden Sie spezifische Begriffe. "beispiel.de" ist besser als nur "beispiel", da letzteres zu viele Ergebnisse liefert.

---

## 3. Repositories

![Repos](screenshots/repos.png)

Zeigt alle von GitHub entdeckten Repositories.

### Filter & Sortierung

- **Status-Filter**: Alle, Pending, Clean, Findings, Low Relevance, Unchanged, Skipped
- **Sortierung**: Zuletzt gesehen, Name, Groesse, AI Score

### Spalten

| Spalte | Beschreibung |
|--------|-------------|
| **Repository** | Name mit Link zur Detailseite |
| **Owner** | Repository-Besitzer mit AI-Zusammenfassung (warum das Repo gefunden wurde) |
| **Groesse** | Repository-Groesse in MB |
| **Sprache** | Hauptprogrammiersprache |
| **Keyword-Bezug** | Welche Keywords gematched haben, mit Dateiliste |
| **Status** | pending/clean/findings/low_relevance/skipped/unchanged |
| **AI Score** | KI-Relevanzbewertung (0-100%) |
| **Scan** | AI-Override-Steuerung (Auto/Erzwungen/Gesperrt) |
| **Findings** | Anzahl offener Findings |

### AI-Override pro Repo

In der Spalte "Scan" kann der Scan-Modus pro Repository gesteuert werden:

| Modus | Beschreibung |
|-------|-------------|
| **Auto** | Standard — die KI entscheidet ob das Repo gescannt wird (Score >= 0.3) |
| **Auto (skip)** | KI hat das Repo als irrelevant bewertet (Score < 0.3) |
| **Erzwungen** | Scan wird erzwungen, unabhaengig vom AI-Score. Nuetzlich fuer Repos die die KI faelschlicherweise als irrelevant eingestuft hat |
| **Gesperrt** | Scan wird unterdrueckt. Nuetzlich fuer bekannte False Positives oder interne Repos |

Buttons:
- **Erzwingen** — Setzt den Scan-Modus auf "Erzwungen"
- **Sperren** — Setzt den Scan-Modus auf "Gesperrt"
- **Auto** — Setzt den Scan-Modus zurueck auf automatische KI-Entscheidung

### Keyword-Matches verwalten

Jeder Match kann als **False Positive** markiert werden:
- Einzeln per "FP"-Button
- Mehrere per Checkbox-Auswahl und "Als False Positive markieren"

### Repository-Detailseite

Klicken Sie auf einen Repository-Namen fuer:
- Vollstaendige Repo-Informationen (URL, Owner, Sprache, Stars)
- AI-Relevanzbewertung und Zusammenfassung
- Alle Keyword-Bezuege mit Dateilisten
- Alle Findings mit KI-Bewertung (MITRE/DORA/BaFin)
- "Als False Positive markieren" fuer das gesamte Repo

---

## 4. Findings

![Findings](screenshots/findings.png)

Security-Findings sind potenzielle Datenlecks, die von den Scannern erkannt wurden.

### Scanner-Typen

| Scanner | Erkennung |
|---------|-----------|
| **TruffleHog** | API-Keys, Tokens, Passwoerter in Git-Historie |
| **Gitleaks** | Secrets und Credentials im Quellcode |
| **Custom** | Benutzerdefinierte Patterns basierend auf Keywords |

### Severity-Level

| Level | Bedeutung |
|-------|-----------|
| **critical** | Verifiziertes Secret (z.B. aktiver API-Key) |
| **high** | Hochwahrscheinlich sensitiv (Cloud-Credentials, Keys) |
| **medium** | Moeglicherweise sensitiv (Konfigurationsdateien) |
| **low** | Geringes Risiko, erfordert manuelle Pruefung |

### Findings bearbeiten

- **Resolve** - Finding als behoben markieren
- **Reopen** - Behobenes Finding wieder oeffnen
- **KI-Bewertung** - Aufklappbar, zeigt MITRE ATT&CK, DORA- und BaFin-Relevanz

---

## 5. Scans

![Scans](screenshots/scans.png)

Zeigt die komplette Scan-Historie.

### Scan-Status

| Status | Bedeutung |
|--------|-----------|
| **running** | Scan laeuft gerade |
| **completed** | Scan erfolgreich abgeschlossen |
| **cancelled** | Scan vom Benutzer abgebrochen |
| **failed** | Scan mit Fehler abgebrochen |

### Scan-Details

Klicken Sie auf eine Scan-ID fuer:
- Vollstaendige Scan-Statistiken
- Alle Findings dieses Scans
- Gesendete Benachrichtigungen

### Automatischer Scan

Scans laufen automatisch taeglich (Standard: 03:00 UTC). Der Zeitplan wird in der `.env`-Datei konfiguriert.

---

## 6. Einstellungen

![Settings](screenshots/settings.png)

Hier werden E-Mail-Empfaenger, OSINT-Module und der AI-Bewertungsprompt verwaltet.

### E-Mail-Empfaenger konfigurieren

Im Abschnitt **"E-Mail-Empfaenger"** werden die Empfaenger fuer Scan-Berichte und Finding-Reports festgelegt:

1. E-Mail-Adressen kommagetrennt eingeben (z.B. `ciso@firma.de, itsec@firma.de`)
2. "Speichern" klicken
3. Ab dem naechsten Scan oder Mail-Report werden die neuen Empfaenger verwendet

> **Hinweis:** Dieser Wert ueberschreibt die `ALERT_EMAIL_TO` Einstellung aus der `.env`-Datei. Ist kein Wert in der UI gesetzt, wird der `.env`-Wert als Fallback verwendet.

### AI-Bewertungsprompt (Prompt-Editor)

![Settings Prompt](screenshots/settings_prompt.png)

Der **AI-Bewertungsprompt** steuert, wie das lokale LLM (Ollama) einzelne Findings bewertet:

- **Bearbeiten**: Prompt im Textfeld aendern und "Speichern" klicken
- **Zuruecksetzen**: "Auf Standard zuruecksetzen" stellt den Original-Prompt wieder her
- **Platzhalter**: Folgende Variablen werden automatisch ersetzt:
  - `{scanner}` — Name des Scanners (TruffleHog/Gitleaks/Custom)
  - `{detector_name}` — Erkennungstyp (z.B. "AWS API Key")
  - `{file_path}` — Dateipfad im Repository
  - `{repo_name}` — Repository-Name
  - `{repo_description}` — Repository-Beschreibung
  - `{verified}` — Ob das Secret verifiziert wurde
  - `{matched_snippet}` — Erkannter Code-Ausschnitt
  - `{keyword_context}` — Welche Keywords das Repo identifiziert haben

Der Prompt wird beim naechsten Scan oder bei einem AI-Reassessment verwendet.

### OSINT-Module aktivieren/deaktivieren

Jedes Modul kann per Toggle-Schalter aktiviert oder deaktiviert werden. Nur aktivierte Module werden bei einem Scan ausgefuehrt.

### Verfuegbare Module

| Modul | Funktion | Konfiguration |
|-------|----------|---------------|
| **Blackbird** | Sucht Accounts auf Plattformen per Username/E-Mail | Keine |
| **Subfinder** | Findet Subdomains per DNS/CT-Logs | Keine |
| **theHarvester** | Sammelt E-Mails, Hosts, IPs per Suchmaschinen | Keine |
| **CrossLinked** | LinkedIn-Personensuche nach Mitarbeitern | Keine |
| **Hunter.io** | Findet E-Mail-Adressen per Domain | API-Key erforderlich |
| **GitDorker** | GitHub Dork-Suche nach Secrets | Nutzt GitHub Token |
| **LeakCheck** | Prueft E-Mails/Domains in bekannten Datenlecks | API-Key erforderlich |

### API-Keys konfigurieren

Fuer Module die einen API-Key benoetigen (Hunter.io, LeakCheck):
1. Key in das Eingabefeld eingeben
2. "Speichern" klicken
3. Status wechselt zu "Key konfiguriert"

> **Hinweis:** API-Keys werden verschluesselt in der Datenbank gespeichert und maskiert angezeigt.

### OSINT-Ergebnisse

Am Ende der Einstellungsseite werden die letzten OSINT-Ergebnisse in einer Tabelle angezeigt:
- Modul, Keyword, Typ (subdomain/email/person/ip/leak), Ergebnis, Datum

---

## 7. Finding-Mail-Report

Auf der **Findings-Seite** koennen einzelne Findings per Checkbox ausgewaehlt und als E-Mail-Report versendet werden:

1. Gewuenschte Findings per Checkbox auswaehlen (oder "Alle" ueber den Master-Checkbox)
2. Der Zaehler zeigt die Anzahl der ausgewaehlten Findings
3. "Mail-Report senden" klicken
4. Es wird eine CISO-konforme HTML-Mail an die konfigurierten Empfaenger gesendet

Der Report enthaelt:
- Severity-Zusammenfassung (Critical/High/Medium/Low)
- Detaillierte Findings gruppiert nach Repository
- KI-Bewertung mit MITRE ATT&CK, DORA und BaFin-Kontext
- Regulatorische Hinweise

---

## 8. Keyword-Kette in AI-Bewertungen

Der Ice-Leak-Monitor bildet eine vollstaendige **Erkennungskette** von Keywords bis zu Findings ab:

```
Keyword → GitHub Code Search → Repository gefunden → Deep Scan → Finding entdeckt → AI-Bewertung
```

In der AI-Bewertung jedes Findings wird dokumentiert, **welche Keywords** das Repository identifiziert haben. Dies ermoeglicht:
- **Nachvollziehbarkeit**: Warum wurde dieses Repo gescannt?
- **Kontext fuer den CISO**: Bezug zum Unternehmen (Firmenname, Domain, Dienstleister)
- **Regulatorische Zuordnung**: DORA/BaFin-Relevanz basierend auf dem Keyword-Kontext

---

## Tipps & Best Practices

1. **Spezifische Keywords verwenden** - "firma.de" statt "firma" reduziert False Positives
2. **OSINT-Module gezielt einsetzen** - Nicht alle Module muessen aktiviert sein
3. **False Positives markieren** - Verbessert die Uebersicht bei wiederholten Scans
4. **Regelmaessig pruefen** - Der automatische Scan laeuft taeglich, neue Findings sollten zeitnah bewertet werden
5. **AI-Score beachten** - Repos mit Score unter 30% werden automatisch als "low relevance" markiert
6. **E-Mail-Empfaenger aktuell halten** - Empfaenger koennen direkt in der Settings-UI geaendert werden
7. **Prompt anpassen** - Der AI-Bewertungsprompt kann fuer spezifische Branchen oder Compliance-Anforderungen angepasst werden
