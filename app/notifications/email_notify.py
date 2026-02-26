import json
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

from sqlalchemy.orm import Session
from app.config import settings
from app.models import Scan, Finding, DiscoveredRepo, NotificationLog

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


def _build_ciso_email_html(db: Session, scan: Scan, findings: list[Finding]) -> str:
    """Build CISO-ready HTML email with full keyword traceability and regulatory assessment."""

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
  </p>
</div>

<!-- Executive Summary -->
<div style="padding:24px 32px;border-bottom:1px solid #d0d7de;">
  <h2 style="margin:0 0 16px;font-size:18px;color:#1c2128;">Zusammenfassung fuer CISO</h2>
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
    {f'<span style="color:#f47067;font-weight:bold;">{verified_count} verifizierte Credentials!</span>' if verified_count else ''}
    | Keywords gesucht: <strong>{scan.keywords_used}</strong>
    | Repos gescannt: <strong>{scan.repos_scanned}</strong>
  </p>
</div>

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
      <div style="margin-top:8px;">
        <strong style="font-size:12px;color:#1c2128;">Gefunden durch Keywords:</strong>
        {kw_badges}
      </div>
      <p style="margin:4px 0 0;font-size:12px;color:#57606a;">
        <strong>Beweiskette:</strong> Die Keywords {', '.join(f'"{kw}"' for kw in matched_kw)}
        haben dieses Repository in der GitHub Code Search API identifiziert.
        Der Code dieses Repos enthaelt Treffer fuer diese Suchbegriffe,
        die mit der Muenchener Hypothekenbank eG oder ihren Dienstleistern in Verbindung stehen.
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

    # Regulatory footer
    html += """
  <!-- Regulatory Note -->
  <div style="background:#fff8c5;border:1px solid #d4a72c;border-radius:6px;padding:16px;margin-top:24px;">
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
    <br>Muenchener Hypothekenbank eG &mdash; IT-Sicherheit
  </p>
</div>

</div>
</body>
</html>"""

    return html


def send_scan_email(db: Session, scan: Scan):
    """Send CISO-ready email with scan findings."""
    if not settings.smtp_host or not settings.alert_email_to:
        logger.info("SMTP not configured, skipping email")
        _log_notification(db, scan.id, "email", "SMTP not configured", "skipped")
        return

    new_findings = db.query(Finding).filter_by(scan_id=scan.id).all()
    if not new_findings:
        return

    verified = [f for f in new_findings if f.verified]
    has_verified = len(verified) > 0

    if has_verified:
        subject = f"[IceLeakMonitor] VERIFIED Credentials gefunden! ({len(verified)} verifiziert, {len(new_findings)} gesamt)"
    else:
        subject = f"[IceLeakMonitor] {len(new_findings)} neue Findings - Scan #{scan.id}"

    html_body = _build_ciso_email_html(db, scan, new_findings)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.alert_email_from or f"iceleakmonitor@{settings.smtp_host}"
    msg["To"] = settings.alert_email_to
    msg["X-Priority"] = "1" if has_verified else "3"

    # Plain text fallback
    plain = (
        f"Ice-Leak-Monitor Scan #{scan.id}\n"
        f"{len(new_findings)} neue Findings in {scan.repos_scanned} Repos.\n"
        f"Details im Web-Dashboard oder in der HTML-Version dieser E-Mail."
    )
    msg.attach(MIMEText(plain, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        if settings.smtp_port == 465:
            server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=30)
        else:
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30)
            if settings.smtp_port == 587:
                server.starttls()

        if settings.smtp_username:
            server.login(settings.smtp_username, settings.smtp_password)

        server.sendmail(
            msg["From"],
            settings.alert_email_to.split(","),
            msg.as_string(),
        )
        server.quit()

        _log_notification(db, scan.id, "email", subject, "sent")
        logger.info("Email sent to %s: %s", settings.alert_email_to, subject)

    except Exception as e:
        logger.exception("Email notification failed")
        _log_notification(db, scan.id, "email", subject, "failed", str(e))


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
