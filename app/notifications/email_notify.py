import json
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

from sqlalchemy.orm import Session
from app.config import settings
from app.models import Scan, Finding, DiscoveredRepo, NotificationLog, OsintResult, AppSetting

logger = logging.getLogger(__name__)


def _severity_color(severity: str) -> str:
    return {
        "critical": "#f47067",
        "high": "#f0883e",
        "medium": "#d29922",
        "low": "#539bf5",
        "info": "#768390",
    }.get(severity, "#768390")


def _severity_badge(severity: str) -> str:
    color = _severity_color(severity)
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;'
        f'border-radius:3px;font-size:12px;font-weight:bold;">'
        f'{severity.upper()}</span>'
    )


def _status_color(status: str) -> str:
    return {
        "clean": "#57ab5a",
        "findings": "#f47067",
        "low_relevance": "#768390",
        "skipped": "#768390",
        "unchanged": "#539bf5",
        "pending": "#d29922",
    }.get(status, "#768390")


def _get_email_recipients(db: Session) -> str:
    """Get email recipients from DB (AppSetting), fallback to .env config."""
    setting = db.query(AppSetting).filter_by(key="alert_email_to").first()
    if setting and setting.value:
        return setting.value.strip()
    return settings.alert_email_to


def _connect_smtp() -> smtplib.SMTP:
    """Create an authenticated SMTP connection.

    Handles SSL (port 465) and STARTTLS (port 587 or any port that
    advertises STARTTLS in its EHLO response, including port 25).
    """
    if settings.smtp_port == 465:
        server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=30)
    else:
        server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30)
        server.ehlo()
        if server.has_extn("STARTTLS"):
            server.starttls()
            server.ehlo()

    if settings.smtp_username:
        server.login(settings.smtp_username, settings.smtp_password)

    return server


def _build_activity_summary_html(db: Session, scan: Scan) -> str:
    """Build the scan activity summary section (repos breakdown, OSINT results)."""

    # Repo status breakdown
    total_repos = scan.repos_found or 0
    scanned = scan.repos_scanned or 0

    # Count repos by scan_status for this scan's timeframe
    all_repos = db.query(DiscoveredRepo).all()
    status_counts = {}
    for r in all_repos:
        s = r.scan_status or "pending"
        status_counts[s] = status_counts.get(s, 0) + 1

    unchanged = status_counts.get("unchanged", 0)
    low_rel = status_counts.get("low_relevance", 0)
    skipped = status_counts.get("skipped", 0)
    clean = status_counts.get("clean", 0)
    with_findings = status_counts.get("findings", 0)
    dismissed_count = sum(1 for r in all_repos if r.is_dismissed)
    forced_count = sum(1 for r in all_repos if r.ai_scan_enabled == 1)
    blocked_count = sum(1 for r in all_repos if r.ai_scan_enabled == 0)

    # OSINT results from this scan
    osint_results = db.query(OsintResult).filter_by(scan_id=scan.id).all()
    osint_by_module: dict[str, list] = {}
    for o in osint_results:
        osint_by_module.setdefault(o.module_key, []).append(o)

    html = """
<!-- Scan-Aktivitaeten -->
<div style="padding:24px 32px;border-bottom:1px solid #d0d7de;">
  <h2 style="margin:0 0 16px;font-size:18px;color:#1c2128;">Scan-Aktivitaeten</h2>

  <!-- Repo Overview -->
  <h3 style="margin:0 0 12px;font-size:15px;color:#1c2128;">Repository-Uebersicht</h3>
  <table style="border-collapse:collapse;width:100%;font-size:13px;margin-bottom:16px;">
    <tr style="background:#f6f8fa;">
      <th style="padding:8px 12px;text-align:left;border-bottom:2px solid #d0d7de;">Kategorie</th>
      <th style="padding:8px 12px;text-align:right;border-bottom:2px solid #d0d7de;">Anzahl</th>
      <th style="padding:8px 12px;text-align:left;border-bottom:2px solid #d0d7de;">Beschreibung</th>
    </tr>
"""

    rows = [
        (total_repos, "Repos in GitHub-Suche gefunden", "#1c2128"),
        (scanned, "Repos deep-gescannt (TruffleHog + Gitleaks + Custom)", "#57ab5a"),
        (with_findings, "Repos mit offenen Findings", "#f47067"),
        (clean, "Repos gescannt, keine Findings", "#57ab5a"),
        (unchanged, "Repos uebersprungen (unveraendert seit letztem Scan)", "#539bf5"),
        (low_rel, "Repos uebersprungen (KI-Score < 30%)", "#768390"),
        (skipped, "Repos uebersprungen (zu gross oder gesperrt)", "#768390"),
        (dismissed_count, "Repos als False Positive markiert", "#768390"),
    ]

    for count, desc, color in rows:
        html += f"""
    <tr>
      <td style="padding:6px 12px;border-bottom:1px solid #d0d7de;font-weight:bold;color:{color};">{count}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #d0d7de;text-align:right;font-weight:bold;color:{color};">{count}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #d0d7de;color:#57606a;">{desc}</td>
    </tr>
"""

    html += "  </table>\n"

    # AI-Override status
    if forced_count or blocked_count:
        html += f"""
  <p style="font-size:13px;color:#57606a;margin-bottom:16px;">
    <strong>AI-Override:</strong>
    {f'{forced_count} Repo(s) manuell zum Scan erzwungen' if forced_count else ''}
    {' | ' if forced_count and blocked_count else ''}
    {f'{blocked_count} Repo(s) manuell gesperrt' if blocked_count else ''}
  </p>
"""

    # OSINT Results
    if osint_results:
        html += """
  <h3 style="margin:16px 0 12px;font-size:15px;color:#1c2128;">OSINT-Aufklaerung</h3>
  <table style="border-collapse:collapse;width:100%;font-size:13px;margin-bottom:16px;">
    <tr style="background:#f6f8fa;">
      <th style="padding:8px 12px;text-align:left;border-bottom:2px solid #d0d7de;">Modul</th>
      <th style="padding:8px 12px;text-align:right;border-bottom:2px solid #d0d7de;">Ergebnisse</th>
      <th style="padding:8px 12px;text-align:left;border-bottom:2px solid #d0d7de;">Typen</th>
      <th style="padding:8px 12px;text-align:left;border-bottom:2px solid #d0d7de;">Beispiele</th>
    </tr>
"""
        for module, results in osint_by_module.items():
            types = set(r.result_type or "unknown" for r in results)
            examples = [r.result_value for r in results[:3]]
            examples_str = ", ".join(examples)
            if len(results) > 3:
                examples_str += f" (+{len(results) - 3} weitere)"
            html += f"""
    <tr>
      <td style="padding:6px 12px;border-bottom:1px solid #d0d7de;font-weight:bold;">{module}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #d0d7de;text-align:right;">{len(results)}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #d0d7de;color:#57606a;">{', '.join(types)}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #d0d7de;color:#57606a;font-size:12px;">{examples_str}</td>
    </tr>
"""
        html += "  </table>\n"
    else:
        html += """
  <p style="font-size:13px;color:#768390;margin:8px 0;">
    OSINT-Aufklaerung: Keine Module aktiviert oder keine Ergebnisse.
  </p>
"""

    # Scan metadata
    duration_min = (scan.duration_seconds or 0) / 60
    html += f"""
  <h3 style="margin:16px 0 12px;font-size:15px;color:#1c2128;">Scan-Details</h3>
  <table style="border-collapse:collapse;font-size:13px;">
    <tr><td style="padding:4px 16px 4px 0;color:#57606a;">Scan-ID:</td><td style="padding:4px 0;font-weight:bold;">#{scan.id}</td></tr>
    <tr><td style="padding:4px 16px 4px 0;color:#57606a;">Typ:</td><td style="padding:4px 0;">{scan.trigger_type.capitalize()}</td></tr>
    <tr><td style="padding:4px 16px 4px 0;color:#57606a;">Gestartet:</td><td style="padding:4px 0;">{scan.started_at}</td></tr>
    <tr><td style="padding:4px 16px 4px 0;color:#57606a;">Beendet:</td><td style="padding:4px 0;">{scan.finished_at}</td></tr>
    <tr><td style="padding:4px 16px 4px 0;color:#57606a;">Dauer:</td><td style="padding:4px 0;">{duration_min:.1f} Minuten ({scan.duration_seconds or 0:.0f}s)</td></tr>
    <tr><td style="padding:4px 16px 4px 0;color:#57606a;">Keywords:</td><td style="padding:4px 0;">{scan.keywords_used}</td></tr>
    <tr><td style="padding:4px 16px 4px 0;color:#57606a;">Status:</td><td style="padding:4px 0;">{scan.status}</td></tr>
  </table>
</div>
"""
    return html


def _build_ciso_email_html(db: Session, scan: Scan, findings: list[Finding]) -> str:
    """Build CISO-ready HTML email with activity summary, findings, and regulatory assessment."""

    now = datetime.utcnow().strftime("%d.%m.%Y %H:%M UTC")

    # Group findings by repo
    repo_findings: dict[int, list[Finding]] = {}
    for f in findings:
        repo_findings.setdefault(f.repo_id, []).append(f)

    # Severity counts
    critical = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")
    low = sum(1 for f in findings if f.severity in ("low", "info"))
    verified_count = sum(1 for f in findings if f.verified)

    # Status line
    if not findings:
        status_line = "Keine neuen Findings &mdash; keine Handlung erforderlich."
        status_bg = "#57ab5a"
    elif verified_count:
        status_line = f'<span style="color:#f47067;font-weight:bold;">{verified_count} verifizierte Credentials gefunden &mdash; sofortige Handlung erforderlich!</span>'
        status_bg = "#f47067"
    else:
        status_line = f"{len(findings)} neue Findings zur Bewertung."
        status_bg = "#d29922"

    # Build HTML
    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:'Segoe UI',Arial,sans-serif;background:#f6f8fa;margin:0;padding:20px;">
<div style="max-width:900px;margin:0 auto;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.12);">

<!-- Header -->
<div style="background:#1c2128;color:#cdd9e5;padding:24px 32px;">
  <h1 style="margin:0;font-size:22px;">Ice-Leak-Monitor &mdash; Scan-Bericht</h1>
  <p style="margin:8px 0 0;color:#768390;font-size:14px;">
    Scan #{scan.id} | {scan.trigger_type.capitalize()} | {now}
    | Dauer: {scan.duration_seconds or 0:.0f}s
    | Keywords: {scan.keywords_used} | Repos gescannt: {scan.repos_scanned}
  </p>
</div>

<!-- Status Banner -->
<div style="background:{status_bg};color:#fff;padding:14px 32px;font-size:15px;font-weight:bold;">
  {status_line}
</div>

<!-- Executive Summary -->
<div style="padding:24px 32px;border-bottom:1px solid #d0d7de;">
  <h2 style="margin:0 0 16px;font-size:18px;color:#1c2128;">Zusammenfassung</h2>
  <table style="border-collapse:collapse;width:100%;">
    <tr>
      <td style="padding:12px;text-align:center;background:#f47067;color:#fff;border-radius:4px 0 0 4px;width:25%;">
        <div style="font-size:28px;font-weight:bold;">{critical}</div>
        <div style="font-size:12px;">CRITICAL</div>
      </td>
      <td style="padding:12px;text-align:center;background:#f0883e;color:#fff;width:25%;">
        <div style="font-size:28px;font-weight:bold;">{high}</div>
        <div style="font-size:12px;">HIGH</div>
      </td>
      <td style="padding:12px;text-align:center;background:#d29922;color:#fff;width:25%;">
        <div style="font-size:28px;font-weight:bold;">{medium}</div>
        <div style="font-size:12px;">MEDIUM</div>
      </td>
      <td style="padding:12px;text-align:center;background:#539bf5;color:#fff;border-radius:0 4px 4px 0;width:25%;">
        <div style="font-size:28px;font-weight:bold;">{low}</div>
        <div style="font-size:12px;">LOW/INFO</div>
      </td>
    </tr>
  </table>
  <p style="margin:16px 0 0;font-size:14px;color:#57606a;">
    <strong>{len(findings)}</strong> neue Findings in
    <strong>{len(repo_findings)}</strong> Repositories.
    | Keywords gesucht: <strong>{scan.keywords_used}</strong>
    | Repos gescannt: <strong>{scan.repos_scanned}</strong>
    | Repos gefunden: <strong>{scan.repos_found}</strong>
  </p>
</div>
"""

    # Activity summary section
    html += _build_activity_summary_html(db, scan)

    # Findings section
    if findings:
        html += """
<!-- Findings by Repository -->
<div style="padding:24px 32px;">
  <h2 style="margin:0 0 16px;font-size:18px;color:#1c2128;">Detaillierte Findings</h2>
"""

        for repo_id, repo_f_list in repo_findings.items():
            repo = db.query(DiscoveredRepo).get(repo_id)
            if not repo:
                continue

            # Keyword traceability
            try:
                matched_kw = json.loads(repo.matched_keywords or "[]")
            except (json.JSONDecodeError, TypeError):
                matched_kw = []

            kw_badges = " ".join(
                f'<span style="background:#2d333b;color:#539bf5;padding:2px 6px;'
                f'border-radius:3px;font-size:11px;margin-right:4px;">{kw}</span>'
                for kw in matched_kw
            )

            ai_score_display = f"{repo.ai_relevance:.1%}" if repo.ai_relevance is not None else "N/A"
            ai_summary_text = repo.ai_summary or ""

            html += f"""
  <div style="border:1px solid #d0d7de;border-radius:6px;margin-bottom:20px;overflow:hidden;">
    <!-- Repo Header -->
    <div style="background:#f6f8fa;padding:16px;border-bottom:1px solid #d0d7de;">
      <h3 style="margin:0;font-size:16px;">
        <a href="{repo.html_url}" style="color:#0969da;text-decoration:none;">{repo.full_name}</a>
        <span style="font-size:12px;color:#57606a;font-weight:normal;margin-left:8px;">
          AI-Relevanz: {ai_score_display}
        </span>
      </h3>
      <p style="margin:8px 0 4px;font-size:13px;color:#57606a;">
        {repo.description or 'Keine Beschreibung'}
      </p>
      {f'<p style="margin:4px 0;font-size:12px;color:#57606a;"><strong>KI-Einschaetzung:</strong> {ai_summary_text}</p>' if ai_summary_text else ''}
      <div style="margin-top:8px;">
        <strong style="font-size:12px;color:#1c2128;">Gefunden durch Keywords:</strong>
        {kw_badges}
      </div>
      <p style="margin:4px 0 0;font-size:12px;color:#57606a;">
        <strong>Herleitung:</strong> Die Keywords {', '.join(f'"{kw}"' for kw in matched_kw)}
        haben dieses Repository in der GitHub Code Search API identifiziert.
        Der Code dieses Repos enthaelt Treffer fuer diese Suchbegriffe,
        die mit der Organisation oder ihren Dienstleistern in Verbindung stehen.
      </p>
    </div>

    <!-- Findings Table -->
    <table style="width:100%;border-collapse:collapse;font-size:13px;">
      <tr style="background:#f6f8fa;">
        <th style="padding:8px 12px;text-align:left;border-bottom:1px solid #d0d7de;">Severity</th>
        <th style="padding:8px 12px;text-align:left;border-bottom:1px solid #d0d7de;">Scanner</th>
        <th style="padding:8px 12px;text-align:left;border-bottom:1px solid #d0d7de;">Detektor</th>
        <th style="padding:8px 12px;text-align:left;border-bottom:1px solid #d0d7de;">Datei</th>
        <th style="padding:8px 12px;text-align:left;border-bottom:1px solid #d0d7de;">Verifiziert</th>
      </tr>
"""

            for f in sorted(repo_f_list, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.severity, 5)):
                verified_icon = "&#x2705; JA" if f.verified else "&#x274C; Nein"
                html += f"""
      <tr>
        <td style="padding:8px 12px;border-bottom:1px solid #d0d7de;">{_severity_badge(f.severity)}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #d0d7de;">{f.scanner}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #d0d7de;"><code>{f.detector_name}</code></td>
        <td style="padding:8px 12px;border-bottom:1px solid #d0d7de;"><code>{f.file_path or 'N/A'}</code></td>
        <td style="padding:8px 12px;border-bottom:1px solid #d0d7de;">{verified_icon}</td>
      </tr>
"""

                # AI Assessment (MITRE/DORA/BaFin) per finding
                if f.ai_assessment:
                    escaped_assessment = f.ai_assessment.replace("\n", "<br>")
                    html += f"""
      <tr>
        <td colspan="5" style="padding:12px 16px;background:#f8f9fb;border-bottom:1px solid #d0d7de;">
          <details open>
            <summary style="font-weight:bold;font-size:12px;color:#1c2128;cursor:pointer;">
              KI-Bewertung (MITRE ATT&amp;CK / DORA / BaFin)
            </summary>
            <div style="margin-top:8px;font-size:12px;color:#57606a;line-height:1.6;">
              {escaped_assessment}
            </div>
          </details>
        </td>
      </tr>
"""

            html += """
    </table>
  </div>
"""

        html += "</div>\n"

    else:
        # No findings section
        html += """
<div style="padding:24px 32px;border-bottom:1px solid #d0d7de;">
  <h2 style="margin:0 0 12px;font-size:18px;color:#1c2128;">Findings</h2>
  <p style="font-size:14px;color:#57ab5a;font-weight:bold;">
    Keine neuen Findings in diesem Scan-Durchlauf. Alle geprueften Repositories sind sauber.
  </p>
</div>
"""

    # Regulatory footer (always show)
    html += """
<!-- Regulatory Note -->
<div style="padding:24px 32px;">
  <div style="background:#fff8c5;border:1px solid #d4a72c;border-radius:6px;padding:16px;">
    <h3 style="margin:0 0 8px;font-size:14px;color:#1c2128;">Regulatorische Hinweise</h3>
    <ul style="margin:0;padding-left:20px;font-size:13px;color:#57606a;line-height:1.8;">
      <li><strong>DORA (Digital Operational Resilience Act):</strong>
        Findings mit verifizierten Credentials koennen einen ICT-bezogenen Vorfall
        gem. Art. 17-23 DORA darstellen. Meldepflicht an BaFin pruefen.</li>
      <li><strong>BaFin MaRisk/BAIT:</strong>
        Datenlecks durch Dienstleister (Auslagerungen) fallen unter AT 9 MaRisk.
        Bewertung der Wesentlichkeit und ggf. Ad-hoc-Meldung erforderlich.</li>
      <li><strong>MITRE ATT&amp;CK:</strong>
        Exponierte Credentials entsprechen typischerweise T1552 (Unsecured Credentials)
        und koennen zu T1078 (Valid Accounts) fuehren.</li>
      <li><strong>DSGVO Art. 33/34:</strong>
        Bei personenbezogenen Daten im Leak: Meldepflicht an Aufsichtsbehoerde
        innerhalb 72 Stunden pruefen.</li>
    </ul>
  </div>
</div>

<!-- Footer -->
<div style="padding:16px 32px;background:#f6f8fa;border-top:1px solid #d0d7de;text-align:center;">
  <p style="margin:0;font-size:12px;color:#768390;">
    Automatisch generiert von Ice-Leak-Monitor |
    Dieser Bericht ist vertraulich und nur fuer den internen Gebrauch bestimmt.
  </p>
</div>

</div>
</body>
</html>"""

    return html


def send_scan_email(db: Session, scan: Scan):
    """Send CISO-ready email report after every scan (with or without findings)."""
    recipients = _get_email_recipients(db)
    if not settings.smtp_host or not recipients:
        logger.info("SMTP not configured, skipping email")
        _log_notification(db, scan.id, "email", "SMTP not configured", "skipped")
        return

    new_findings = db.query(Finding).filter_by(scan_id=scan.id).all()

    verified = [f for f in new_findings if f.verified]
    has_verified = len(verified) > 0

    # Subject line depends on findings
    if has_verified:
        subject = f"[IceLeakMonitor] VERIFIED Credentials gefunden! ({len(verified)} verifiziert, {len(new_findings)} gesamt)"
    elif new_findings:
        subject = f"[IceLeakMonitor] {len(new_findings)} neue Findings - Scan #{scan.id}"
    else:
        subject = f"[IceLeakMonitor] Scan #{scan.id} abgeschlossen - keine neuen Findings"

    html_body = _build_ciso_email_html(db, scan, new_findings)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.alert_email_from or settings.smtp_username or f"iceleakmonitor@{settings.smtp_host}"
    msg["To"] = recipients
    msg["X-Priority"] = "1" if has_verified else "3"

    # Plain text fallback
    if new_findings:
        plain = (
            f"Ice-Leak-Monitor Scan #{scan.id}\n"
            f"{len(new_findings)} neue Findings in {scan.repos_scanned} Repos.\n"
            f"Details im Web-Dashboard oder in der HTML-Version dieser E-Mail."
        )
    else:
        plain = (
            f"Ice-Leak-Monitor Scan #{scan.id} abgeschlossen.\n"
            f"Keine neuen Findings. {scan.repos_scanned} Repos gescannt, "
            f"{scan.repos_found} Repos gefunden.\n"
            f"Dauer: {scan.duration_seconds or 0:.0f}s"
        )
    msg.attach(MIMEText(plain, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        server = _connect_smtp()
        server.sendmail(
            msg["From"],
            [r.strip() for r in recipients.split(",")],
            msg.as_string(),
        )
        server.quit()

        _log_notification(db, scan.id, "email", subject, "sent")
        logger.info("Email sent to %s: %s", recipients, subject)

    except Exception as e:
        logger.exception("Email notification failed")
        _log_notification(db, scan.id, "email", subject, "failed", str(e))


def send_findings_report_email(db: Session, finding_ids: list[int]) -> tuple[bool, str]:
    """Send a CISO-ready email report for specific findings.
    Returns (success, message)."""
    recipients = _get_email_recipients(db)
    if not settings.smtp_host or not recipients:
        return False, "SMTP nicht konfiguriert"

    findings = db.query(Finding).filter(Finding.id.in_(finding_ids)).all()
    if not findings:
        return False, "Keine Findings gefunden"

    verified = [f for f in findings if f.verified]
    has_verified = len(verified) > 0

    # Build subject
    if has_verified:
        subject = f"[IceLeakMonitor] Finding-Report: {len(verified)} verifiziert, {len(findings)} gesamt"
    else:
        subject = f"[IceLeakMonitor] Finding-Report: {len(findings)} Finding(s)"

    # Build HTML
    html_body = _build_findings_report_html(db, findings)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.alert_email_from or settings.smtp_username or f"iceleakmonitor@{settings.smtp_host}"
    msg["To"] = recipients
    msg["X-Priority"] = "1" if has_verified else "3"

    plain = (
        f"Ice-Leak-Monitor Finding-Report\n"
        f"{len(findings)} Finding(s) zur Bewertung.\n"
        f"Details in der HTML-Version dieser E-Mail."
    )
    msg.attach(MIMEText(plain, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        server = _connect_smtp()
        server.sendmail(
            msg["From"],
            [r.strip() for r in recipients.split(",")],
            msg.as_string(),
        )
        server.quit()

        _log_notification(db, None, "email", subject, "sent")
        logger.info("Finding report email sent to %s: %s", recipients, subject)
        return True, f"E-Mail gesendet an {recipients}"

    except Exception as e:
        logger.exception("Finding report email failed")
        _log_notification(db, None, "email", subject, "failed", str(e))
        return False, f"E-Mail-Versand fehlgeschlagen: {e}"


def _build_findings_report_html(db: Session, findings: list[Finding]) -> str:
    """Build HTML email for a selection of findings (no scan context needed)."""
    now = datetime.utcnow().strftime("%d.%m.%Y %H:%M UTC")

    # Group by repo
    repo_findings: dict[int, list[Finding]] = {}
    for f in findings:
        repo_findings.setdefault(f.repo_id, []).append(f)

    critical = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")
    low = sum(1 for f in findings if f.severity in ("low", "info"))
    verified_count = sum(1 for f in findings if f.verified)

    if verified_count:
        status_line = f'<span style="color:#f47067;font-weight:bold;">{verified_count} verifizierte Credentials — sofortige Handlung erforderlich!</span>'
        status_bg = "#f47067"
    else:
        status_line = f"{len(findings)} Finding(s) zur Bewertung."
        status_bg = "#d29922"

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:'Segoe UI',Arial,sans-serif;background:#f6f8fa;margin:0;padding:20px;">
<div style="max-width:900px;margin:0 auto;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.12);">

<!-- Header -->
<div style="background:#1c2128;color:#cdd9e5;padding:24px 32px;">
  <h1 style="margin:0;font-size:22px;">Ice-Leak-Monitor &mdash; Finding-Report</h1>
  <p style="margin:8px 0 0;color:#768390;font-size:14px;">
    Manueller Report | {now} | {len(findings)} Finding(s) in {len(repo_findings)} Repository(s)
  </p>
</div>

<!-- Status Banner -->
<div style="background:{status_bg};color:#fff;padding:14px 32px;font-size:15px;font-weight:bold;">
  {status_line}
</div>

<!-- Summary -->
<div style="padding:24px 32px;border-bottom:1px solid #d0d7de;">
  <h2 style="margin:0 0 16px;font-size:18px;color:#1c2128;">Zusammenfassung</h2>
  <table style="border-collapse:collapse;width:100%;">
    <tr>
      <td style="padding:12px;text-align:center;background:#f47067;color:#fff;border-radius:4px 0 0 4px;width:25%;">
        <div style="font-size:28px;font-weight:bold;">{critical}</div><div style="font-size:12px;">CRITICAL</div>
      </td>
      <td style="padding:12px;text-align:center;background:#f0883e;color:#fff;width:25%;">
        <div style="font-size:28px;font-weight:bold;">{high}</div><div style="font-size:12px;">HIGH</div>
      </td>
      <td style="padding:12px;text-align:center;background:#d29922;color:#fff;width:25%;">
        <div style="font-size:28px;font-weight:bold;">{medium}</div><div style="font-size:12px;">MEDIUM</div>
      </td>
      <td style="padding:12px;text-align:center;background:#539bf5;color:#fff;border-radius:0 4px 4px 0;width:25%;">
        <div style="font-size:28px;font-weight:bold;">{low}</div><div style="font-size:12px;">LOW/INFO</div>
      </td>
    </tr>
  </table>
</div>

<!-- Findings -->
<div style="padding:24px 32px;">
  <h2 style="margin:0 0 16px;font-size:18px;color:#1c2128;">Detaillierte Findings</h2>
"""

    for repo_id, repo_f_list in repo_findings.items():
        repo = db.query(DiscoveredRepo).get(repo_id)
        if not repo:
            continue

        try:
            matched_kw = json.loads(repo.matched_keywords or "[]")
        except (json.JSONDecodeError, TypeError):
            matched_kw = []

        kw_badges = " ".join(
            f'<span style="background:#2d333b;color:#539bf5;padding:2px 6px;'
            f'border-radius:3px;font-size:11px;margin-right:4px;">{kw}</span>'
            for kw in matched_kw
        )

        html += f"""
  <div style="border:1px solid #d0d7de;border-radius:6px;margin-bottom:20px;overflow:hidden;">
    <div style="background:#f6f8fa;padding:16px;border-bottom:1px solid #d0d7de;">
      <h3 style="margin:0;font-size:16px;">
        <a href="{repo.html_url}" style="color:#0969da;text-decoration:none;">{repo.full_name}</a>
      </h3>
      <p style="margin:8px 0 4px;font-size:13px;color:#57606a;">{repo.description or 'Keine Beschreibung'}</p>
      <div style="margin-top:8px;"><strong style="font-size:12px;">Keywords:</strong> {kw_badges}</div>
    </div>
    <table style="width:100%;border-collapse:collapse;font-size:13px;">
      <tr style="background:#f6f8fa;">
        <th style="padding:8px 12px;text-align:left;border-bottom:1px solid #d0d7de;">Severity</th>
        <th style="padding:8px 12px;text-align:left;border-bottom:1px solid #d0d7de;">Scanner</th>
        <th style="padding:8px 12px;text-align:left;border-bottom:1px solid #d0d7de;">Detektor</th>
        <th style="padding:8px 12px;text-align:left;border-bottom:1px solid #d0d7de;">Datei</th>
        <th style="padding:8px 12px;text-align:left;border-bottom:1px solid #d0d7de;">Verifiziert</th>
      </tr>
"""

        for f in sorted(repo_f_list, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.severity, 5)):
            verified_icon = "&#x2705; JA" if f.verified else "&#x274C; Nein"
            file_link = f.file_path or "N/A"
            if f.file_path and repo:
                ref = f.commit_hash if f.commit_hash else (repo.default_branch or "main")
                file_link = f'<a href="https://github.com/{repo.full_name}/blob/{ref}/{f.file_path}" style="color:#0969da;">{f.file_path}</a>'

            html += f"""
      <tr>
        <td style="padding:8px 12px;border-bottom:1px solid #d0d7de;">{_severity_badge(f.severity)}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #d0d7de;">{f.scanner}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #d0d7de;"><code>{f.detector_name}</code></td>
        <td style="padding:8px 12px;border-bottom:1px solid #d0d7de;">{file_link}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #d0d7de;">{verified_icon}</td>
      </tr>
"""
            if f.ai_assessment:
                escaped = f.ai_assessment.replace("\n", "<br>")
                html += f"""
      <tr>
        <td colspan="5" style="padding:12px 16px;background:#f8f9fb;border-bottom:1px solid #d0d7de;">
          <details open>
            <summary style="font-weight:bold;font-size:12px;color:#1c2128;cursor:pointer;">
              KI-Bewertung (MITRE ATT&amp;CK / DORA / BaFin)
            </summary>
            <div style="margin-top:8px;font-size:12px;color:#57606a;line-height:1.6;">{escaped}</div>
          </details>
        </td>
      </tr>
"""

        html += "    </table>\n  </div>\n"

    html += """</div>

<!-- Regulatory Note -->
<div style="padding:24px 32px;">
  <div style="background:#fff8c5;border:1px solid #d4a72c;border-radius:6px;padding:16px;">
    <h3 style="margin:0 0 8px;font-size:14px;color:#1c2128;">Regulatorische Hinweise</h3>
    <ul style="margin:0;padding-left:20px;font-size:13px;color:#57606a;line-height:1.8;">
      <li><strong>DORA:</strong> Findings mit verifizierten Credentials koennen einen ICT-bezogenen Vorfall gem. Art. 17-23 DORA darstellen.</li>
      <li><strong>BaFin MaRisk/BAIT:</strong> Datenlecks durch Dienstleister fallen unter AT 9 MaRisk.</li>
      <li><strong>MITRE ATT&amp;CK:</strong> Exponierte Credentials entsprechen T1552 (Unsecured Credentials).</li>
      <li><strong>DSGVO Art. 33/34:</strong> Bei personenbezogenen Daten: Meldepflicht innerhalb 72 Stunden pruefen.</li>
    </ul>
  </div>
</div>

<div style="padding:16px 32px;background:#f6f8fa;border-top:1px solid #d0d7de;text-align:center;">
  <p style="margin:0;font-size:12px;color:#768390;">
    Automatisch generiert von Ice-Leak-Monitor | Manueller Finding-Report |
    Dieser Bericht ist vertraulich und nur fuer den internen Gebrauch bestimmt.
  </p>
</div>

</div>
</body>
</html>"""

    return html


def _log_notification(db: Session, scan_id: int, channel: str, subject: str,
                      status: str, error: str = None):
    log = NotificationLog(
        scan_id=scan_id,
        channel=channel,
        subject=subject,
        status=status,
        error_message=error,
    )
    db.add(log)
    db.commit()
