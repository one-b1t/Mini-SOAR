from __future__ import annotations

"""Automated Incident & Executive SOC Report Generator (Markdown & HTML)."""

import html
from datetime import datetime, timezone

from .models import IncidentCase


def generate_case_markdown_report(case: IncidentCase) -> str:
    """Generates a comprehensive Markdown report for a specific incident case."""
    lines = [
        f"# 🛡️ Incident Investigation Report: {case.case_id}",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        f"- **Title:** {case.title}",
        f"- **Severity:** `{case.severity.upper()}`",
        f"- **Current Status:** `{case.status}`",
        f"- **Attacker Source IP:** `{case.attacker_ip or 'N/A'}`",
        f"- **Target Asset:** `{case.target_asset or 'N/A'}`",
        f"- **Assigned Investigator:** `{case.assigned_to}`",
        f"- **Created At:** {case.created_at}",
        f"- **Updated At:** {case.updated_at}",
        f"- **Closed At:** {case.closed_at or 'In Progress'}",
        "",
        "### Operational SLA Metrics",
        f"- **Mean Time to Detect (MTTD):** `{case.mttd_seconds:.1f}s`",
        f"- **Mean Time to Resolve/Contain (MTTR):** `{case.mttr_seconds:.1f}s` ({case.mttr_seconds / 60.0:.2f} mins)",
        "",
        "---",
        "",
        "## 2. Description & Threat Context",
        case.description or "_No description provided._",
        "",
        "### Tags & Threat Classifications",
        ", ".join([f"`{t}`" for t in case.tags]) if case.tags else "_No tags_",
        "",
        "### External Ticketing References",
    ]

    if case.external_tickets:
        for platform, ticket_id in case.external_tickets.items():
            lines.append(f"- **{platform.capitalize()}:** `{ticket_id}`")
    else:
        lines.append("_No external tickets linked._")

    lines.extend([
        "",
        "---",
        "",
        "## 3. Incident Timeline & Actions",
        "| Timestamp (UTC) | Actor | Action | Details |",
        "| :--- | :--- | :--- | :--- |",
    ])

    for entry in case.timeline:
        ts = entry.get("timestamp", "-")
        actor = entry.get("actor", "-")
        action = entry.get("action", "-")
        note = entry.get("note", "-")
        lines.append(f"| {ts} | `{actor}` | `{action}` | {note} |")

    lines.extend([
        "",
        "---",
        "",
        "## 4. Resolution Notes & Post-Mortem",
        case.resolution_notes or "_Investigation still active or no closing notes added._",
        "",
    ])

    return "\n".join(lines)


def generate_case_html_report(case: IncidentCase) -> str:
    """Generates a professional standalone HTML report for SOC stakeholders."""
    sev_color = {
        "critical": "#d32f2f",
        "high": "#e65100",
        "medium": "#f57c00",
        "low": "#388e3c",
    }.get(case.severity.lower(), "#0288d1")

    timeline_rows = []
    for entry in case.timeline:
        timeline_rows.append(
            f"<tr><td>{html.escape(entry.get('timestamp', ''))}</td>"
            f"<td><code>{html.escape(entry.get('actor', ''))}</code></td>"
            f"<td><b>{html.escape(entry.get('action', ''))}</b></td>"
            f"<td>{html.escape(entry.get('note', ''))}</td></tr>"
        )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SOC Report - {html.escape(case.case_id)}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 40px; background: #f8f9fa; color: #212529; }}
        .container {{ max-width: 900px; margin: auto; background: #ffffff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }}
        .header {{ border-bottom: 2px solid #eee; padding-bottom: 20px; margin-bottom: 20px; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; color: #fff; font-weight: bold; background: {sev_color}; }}
        .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin: 20px 0; }}
        .card {{ background: #f1f3f5; padding: 15px; border-radius: 6px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ border: 1px solid #dee2e6; padding: 10px; text-align: left; }}
        th {{ background: #e9ecef; }}
        code {{ background: #e9ecef; padding: 2px 6px; border-radius: 4px; }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h2>🛡️ MiniSOAR Incident Investigation Report</h2>
        <h3>{html.escape(case.title)}</h3>
        <span class="badge">{html.escape(case.severity.upper())}</span>
        <span style="margin-left: 10px; font-weight: bold;">Status: {html.escape(case.status)}</span>
    </div>

    <div class="grid">
        <div class="card">
            <b>Case ID:</b> <code>{html.escape(case.case_id)}</code><br>
            <b>Attacker IP:</b> <code>{html.escape(case.attacker_ip or 'N/A')}</code><br>
            <b>Target Asset:</b> <code>{html.escape(case.target_asset or 'N/A')}</code>
        </div>
        <div class="card">
            <b>MTTD:</b> {case.mttd_seconds:.1f} seconds<br>
            <b>MTTR:</b> {case.mttr_seconds / 60.0:.2f} minutes<br>
            <b>Investigator:</b> <code>{html.escape(case.assigned_to)}</code>
        </div>
    </div>

    <h4>Threat Details & Context</h4>
    <p>{html.escape(case.description or 'No description.')}</p>

    <h4>Incident Timeline</h4>
    <table>
        <thead>
            <tr><th>Timestamp</th><th>Actor</th><th>Action</th><th>Notes</th></tr>
        </thead>
        <tbody>
            {"".join(timeline_rows)}
        </tbody>
    </table>
</div>
</body>
</html>"""
    return html_content
