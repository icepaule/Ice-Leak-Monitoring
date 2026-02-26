import logging
import httpx

from app.config import settings

logger = logging.getLogger(__name__)

RELEVANCE_PROMPT = """Du bist ein IT-Security-Analyst der Muenchener Hypothekenbank eG (MHB).
Bewerte ob dieses GitHub-Repository moeglicherweise vertrauliche Daten der MHB,
ihrer Mitarbeiter oder des Dienstleisters Orange Cyber Defense Deutschland enthaelt.

Repository: {repo_name}
Beschreibung: {description}
Sprache: {language}
README-Auszug:
{readme_excerpt}

Antworte NUR mit einem JSON-Objekt:
{{"score": 0.0-1.0, "summary": "Kurze Begruendung auf Deutsch"}}

Score-Leitfaden:
- 0.0-0.2: Kein Bezug zu MHB/OCD
- 0.3-0.5: Moeglicherweise relevant (Bankbegriffe, Security-Tools)
- 0.6-0.8: Wahrscheinlich relevant (MHB-Begriffe, interne Daten)
- 0.9-1.0: Sehr wahrscheinlich vertrauliche Daten"""


FINDING_ASSESSMENT_PROMPT = """Du bist CISO-Berater fuer die Muenchener Hypothekenbank eG.
Bewerte dieses Finding aus einem GitHub Data-Leak-Scan.

Scanner: {scanner}
Detektor: {detector_name}
Datei: {file_path}
Repository: {repo_name}
Repository-Beschreibung: {repo_description}
Verifiziert: {verified}

Erstelle eine strukturierte Bewertung mit folgenden Punkten:

1. **Klassifizierung**: Echtes Datenleck, False Positive, oder unklar?
2. **Schweregrad**: Critical / High / Medium / Low / Info
3. **MITRE ATT&CK**: Zuordnung zu relevanten Techniken (z.B. T1552 - Unsecured Credentials, T1078 - Valid Accounts)
4. **DORA-Relevanz**: Bewertung nach Digital Operational Resilience Act (Artikel 5-15):
   - ICT-Risikomanagement (Art. 5-16)
   - ICT-bezogene Vorfaelle (Art. 17-23)
   - Drittparteien-Risiko (Art. 28-44) falls Lieferant betroffen
5. **BaFin-Meldepflicht**: Einschaetzung ob eine Meldung nach MaRisk/BAIT erforderlich ist
6. **Empfohlene Sofortmassnahmen**: Konkrete naechste Schritte

Antworte auf Deutsch, strukturiert und praezise. Die Bewertung muss fuer den CISO der Bank verstaendlich und weiterleitbar sein."""


def assess_repo_relevance(repo_name: str, description: str, language: str, readme_excerpt: str) -> tuple[float, str]:
    """Ask Ollama to assess repo relevance. Returns (score, summary).
    Falls back to (1.0, 'Ollama unavailable') if Ollama is not reachable."""
    try:
        prompt = RELEVANCE_PROMPT.format(
            repo_name=repo_name,
            description=description or "Keine Beschreibung",
            language=language or "Unbekannt",
            readme_excerpt=readme_excerpt or "Kein README verfuegbar",
        )

        resp = httpx.post(
            f"{settings.ollama_base_url}/api/generate",
            json={
                "model": settings.ollama_model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1},
            },
            timeout=60.0,
        )
        resp.raise_for_status()
        data = resp.json()
        text = data.get("response", "")

        # Parse JSON from response
        import json
        # Try to find JSON in the response
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            parsed = json.loads(text[start:end])
            score = float(parsed.get("score", 1.0))
            summary = parsed.get("summary", text)
            return (min(1.0, max(0.0, score)), summary)

        return (0.5, text[:500])

    except httpx.ConnectError:
        logger.warning("Ollama not reachable at %s - scanning all repos (graceful degradation)", settings.ollama_base_url)
        return (1.0, "Ollama nicht erreichbar - Repo wird vorsichtshalber gescannt")
    except Exception:
        logger.exception("Ollama relevance assessment failed")
        return (1.0, "Bewertung fehlgeschlagen - Repo wird gescannt")


def assess_finding(scanner: str, detector_name: str, file_path: str,
                   repo_name: str, repo_description: str, verified: bool) -> str:
    """Ask Ollama to assess a finding with MITRE/DORA/BaFin context.
    Returns assessment text or empty string on failure."""
    try:
        prompt = FINDING_ASSESSMENT_PROMPT.format(
            scanner=scanner,
            detector_name=detector_name,
            file_path=file_path or "Unbekannt",
            repo_name=repo_name,
            repo_description=repo_description or "Keine Beschreibung",
            verified="Ja" if verified else "Nein",
        )

        resp = httpx.post(
            f"{settings.ollama_base_url}/api/generate",
            json={
                "model": settings.ollama_model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.2},
            },
            timeout=90.0,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("response", "")[:3000]

    except httpx.ConnectError:
        logger.warning("Ollama not reachable for finding assessment")
        return ""
    except Exception:
        logger.exception("Ollama finding assessment failed")
        return ""
