"""Report generation for LogAnalyzer.

Generates summary reports in console (text), JSON, and HTML formats.
Reports include alert summaries, statistics, and optional correlation data.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from log_analyzer.detectors import Alert, AlertSeverity
from log_analyzer.parsers import LogEntry


class Reporter:
    """Generates analysis reports in multiple formats.

    Supports console (text), JSON, and HTML output formats with
    alert summaries, log statistics, and correlation data.
    """

    def generate(
        self,
        alerts: List[Alert],
        entries: Optional[List[LogEntry]] = None,
        format: str = "console",
        output_path: Optional[str] = None,
        correlation_summary: Optional[dict] = None,
    ) -> Optional[str]:
        """Generate a report in the specified format.

        Args:
            alerts: List of detected alerts.
            entries: Optional list of parsed log entries for statistics.
            format: Output format ('console', 'json', 'html').
            output_path: File path to write the report. If None, returns
                the report as a string (or prints for console format).
            correlation_summary: Optional correlation engine summary dict.

        Returns:
            Report content as a string for json/html formats, or None
            for console format (which prints directly).

        Raises:
            ValueError: If the format is not recognized.
        """
        if format == "console":
            content = self._generate_console(alerts, entries, correlation_summary)
            if output_path:
                Path(output_path).write_text(content, encoding="utf-8")
            else:
                print(content)
            return content

        elif format == "json":
            content = self._generate_json(alerts, entries, correlation_summary)
            if output_path:
                Path(output_path).write_text(content, encoding="utf-8")
            return content

        elif format == "html":
            content = self._generate_html(alerts, entries, correlation_summary)
            if output_path:
                Path(output_path).write_text(content, encoding="utf-8")
            return content

        else:
            raise ValueError(
                f"Unknown report format '{format}'. "
                "Valid formats: console, json, html"
            )

    def _build_stats(
        self,
        alerts: List[Alert],
        entries: Optional[List[LogEntry]],
    ) -> dict:
        """Build statistics from alerts and entries."""
        stats: dict = {
            "total_alerts": len(alerts),
            "alerts_by_severity": dict(Counter(a.severity.value for a in alerts)),
            "alerts_by_type": dict(Counter(a.alert_type for a in alerts)),
            "generated_at": datetime.now().isoformat(),
        }

        if entries:
            stats["total_entries"] = len(entries)
            stats["sources"] = dict(Counter(e.source for e in entries))
            stats["unique_hosts"] = len(set(e.hostname for e in entries))
            unique_ips: set[str] = set()
            for e in entries:
                ip = e.metadata.get("source_ip")
                if ip:
                    unique_ips.add(ip)
            stats["unique_source_ips"] = len(unique_ips)

            if entries:
                timestamps = sorted(e.timestamp for e in entries)
                stats["time_range"] = {
                    "start": timestamps[0].isoformat(),
                    "end": timestamps[-1].isoformat(),
                }

        return stats

    def _generate_console(
        self,
        alerts: List[Alert],
        entries: Optional[List[LogEntry]],
        correlation_summary: Optional[dict],
    ) -> str:
        """Generate a console-formatted text report."""
        lines: List[str] = []
        separator = "=" * 72

        lines.append(separator)
        lines.append("  LogAnalyzer - Security Analysis Report")
        lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(separator)
        lines.append("")

        # Statistics
        stats = self._build_stats(alerts, entries)

        lines.append("  SUMMARY")
        lines.append("  " + "-" * 40)
        if entries:
            lines.append(f"  Total log entries analyzed: {stats['total_entries']}")
            lines.append(f"  Unique hosts:              {stats['unique_hosts']}")
            lines.append(f"  Unique source IPs:         {stats['unique_source_ips']}")
            if "time_range" in stats:
                lines.append(f"  Time range:                {stats['time_range']['start']}")
                lines.append(f"                             to {stats['time_range']['end']}")
        lines.append(f"  Total alerts:              {stats['total_alerts']}")
        lines.append("")

        # Alerts by severity
        lines.append("  ALERTS BY SEVERITY")
        lines.append("  " + "-" * 40)
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        for sev in severity_order:
            count = stats["alerts_by_severity"].get(sev, 0)
            if count > 0:
                marker = "!!!" if sev == "CRITICAL" else ("!!" if sev == "HIGH" else "")
                lines.append(f"  {marker:>4s} {sev:<12s} {count}")
        lines.append("")

        # Alerts by type
        if stats["alerts_by_type"]:
            lines.append("  ALERTS BY TYPE")
            lines.append("  " + "-" * 40)
            for alert_type, count in sorted(
                stats["alerts_by_type"].items(), key=lambda x: -x[1]
            ):
                lines.append(f"  {alert_type:<30s} {count}")
            lines.append("")

        # Alert details
        if alerts:
            lines.append("  ALERT DETAILS")
            lines.append("  " + "-" * 40)
            for i, alert in enumerate(alerts, 1):
                severity_icon = {
                    "CRITICAL": "[!!!!]",
                    "HIGH": "[!!!]",
                    "MEDIUM": "[!!]",
                    "LOW": "[!]",
                }.get(alert.severity.value, "[?]")

                lines.append(
                    f"  {i:3d}. {severity_icon} [{alert.severity.value}] "
                    f"{alert.alert_type}"
                )
                lines.append(f"       Time:   {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
                if alert.source_ip:
                    lines.append(f"       Source: {alert.source_ip}")
                lines.append(f"       {alert.description}")
                if alert.evidence:
                    lines.append(f"       Evidence ({len(alert.evidence)} log lines):")
                    for ev in alert.evidence[:3]:
                        lines.append(f"         > {ev[:120]}")
                    if len(alert.evidence) > 3:
                        lines.append(f"         ... and {len(alert.evidence) - 3} more")
                lines.append("")

        # Correlation summary
        if correlation_summary:
            lines.append("  CORRELATION SUMMARY")
            lines.append("  " + "-" * 40)
            lines.append(
                f"  Attack chains detected: "
                f"{correlation_summary.get('attack_chains_detected', 0)}"
            )
            chains = correlation_summary.get("chains", [])
            for chain in chains:
                lines.append(f"  Chain {chain['chain_id']}:")
                lines.append(f"    Source IP:  {chain['source_ip']}")
                lines.append(f"    Severity:  {chain['overall_severity']}")
                lines.append(f"    Stages:    {' -> '.join(chain['stages'])}")
                lines.append(f"    Events:    {len(chain['events'])}")
                lines.append(f"    Duration:  {chain['first_seen']} to {chain['last_seen']}")
                lines.append(f"    {chain['description']}")
                lines.append("")

        lines.append(separator)
        lines.append("  End of Report")
        lines.append(separator)

        return "\n".join(lines)

    def _generate_json(
        self,
        alerts: List[Alert],
        entries: Optional[List[LogEntry]],
        correlation_summary: Optional[dict],
    ) -> str:
        """Generate a JSON-formatted report."""
        report: dict = {
            "report": {
                "title": "LogAnalyzer Security Analysis Report",
                "generated_at": datetime.now().isoformat(),
                "version": "1.0",
            },
            "statistics": self._build_stats(alerts, entries),
            "alerts": [a.to_dict() for a in alerts],
        }

        if correlation_summary:
            report["correlation"] = correlation_summary

        return json.dumps(report, indent=2, default=str)

    def _generate_html(
        self,
        alerts: List[Alert],
        entries: Optional[List[LogEntry]],
        correlation_summary: Optional[dict],
    ) -> str:
        """Generate an HTML-formatted report."""
        stats = self._build_stats(alerts, entries)

        severity_colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#17a2b8",
        }

        # Build alert rows
        alert_rows = []
        for alert in alerts:
            color = severity_colors.get(alert.severity.value, "#6c757d")
            evidence_html = ""
            if alert.evidence:
                evidence_items = "".join(
                    f"<li><code>{self._html_escape(ev[:150])}</code></li>"
                    for ev in alert.evidence[:5]
                )
                evidence_html = f"<ul>{evidence_items}</ul>"

            alert_rows.append(
                f"<tr>"
                f'<td>{alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")}</td>'
                f'<td><span class="badge" style="background-color:{color}">'
                f"{alert.severity.value}</span></td>"
                f"<td>{self._html_escape(alert.alert_type)}</td>"
                f"<td>{self._html_escape(alert.source_ip or 'N/A')}</td>"
                f"<td>{self._html_escape(alert.description)}</td>"
                f"<td>{evidence_html}</td>"
                f"</tr>"
            )

        alerts_table = "\n".join(alert_rows)

        # Build severity summary
        severity_summary = ""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = stats["alerts_by_severity"].get(sev, 0)
            color = severity_colors.get(sev, "#6c757d")
            severity_summary += (
                f'<div class="stat-card" style="border-left: 4px solid {color}">'
                f'<div class="stat-value">{count}</div>'
                f'<div class="stat-label">{sev}</div>'
                f"</div>"
            )

        # Correlation section
        correlation_html = ""
        if correlation_summary:
            chains = correlation_summary.get("chains", [])
            chain_items = ""
            for chain in chains:
                stages = " &rarr; ".join(chain["stages"])
                chain_items += (
                    f'<div class="chain-card">'
                    f"<h4>{chain['chain_id']} - {chain['source_ip']}</h4>"
                    f"<p><strong>Severity:</strong> {chain['overall_severity']}</p>"
                    f"<p><strong>Stages:</strong> {stages}</p>"
                    f"<p><strong>Events:</strong> {len(chain['events'])}</p>"
                    f"<p>{self._html_escape(chain['description'])}</p>"
                    f"</div>"
                )

            correlation_html = (
                f'<section class="section">'
                f"<h2>Attack Chains</h2>"
                f"<p>Detected {len(chains)} attack chain(s)</p>"
                f"{chain_items}"
                f"</section>"
            )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LogAnalyzer - Security Analysis Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #1a1a2e; color: #e0e0e0; line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #00d4ff; margin-bottom: 5px; }}
        h2 {{ color: #00d4ff; margin-bottom: 15px; border-bottom: 1px solid #333; padding-bottom: 8px; }}
        .header {{ background: #16213e; padding: 30px; border-radius: 8px; margin-bottom: 20px; }}
        .header p {{ color: #888; }}
        .stats-grid {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px; margin-bottom: 20px;
        }}
        .stat-card {{
            background: #16213e; padding: 20px; border-radius: 8px; text-align: center;
        }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: #00d4ff; }}
        .stat-label {{ color: #888; text-transform: uppercase; font-size: 0.85em; }}
        .section {{ background: #16213e; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th {{ background: #0f3460; color: #00d4ff; padding: 12px 8px; text-align: left; }}
        td {{ padding: 10px 8px; border-bottom: 1px solid #333; vertical-align: top; }}
        tr:hover {{ background: #1a1a3e; }}
        .badge {{
            display: inline-block; padding: 3px 10px; border-radius: 12px;
            color: #fff; font-size: 0.8em; font-weight: bold;
        }}
        code {{ background: #0a0a1a; padding: 2px 6px; border-radius: 3px; font-size: 0.85em; }}
        ul {{ padding-left: 20px; margin-top: 5px; }}
        li {{ font-size: 0.85em; margin-bottom: 3px; }}
        .chain-card {{
            background: #1a1a3e; padding: 15px; border-radius: 6px;
            margin-bottom: 10px; border-left: 3px solid #fd7e14;
        }}
        .chain-card h4 {{ color: #fd7e14; margin-bottom: 8px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>LogAnalyzer - Security Analysis Report</h1>
            <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{stats.get('total_entries', 'N/A')}</div>
                <div class="stat-label">Log Entries</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats['total_alerts']}</div>
                <div class="stat-label">Total Alerts</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats.get('unique_source_ips', 'N/A')}</div>
                <div class="stat-label">Unique IPs</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats.get('unique_hosts', 'N/A')}</div>
                <div class="stat-label">Hosts</div>
            </div>
        </div>

        <div class="stats-grid">
            {severity_summary}
        </div>

        <section class="section">
            <h2>Alert Details</h2>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Severity</th>
                        <th>Type</th>
                        <th>Source IP</th>
                        <th>Description</th>
                        <th>Evidence</th>
                    </tr>
                </thead>
                <tbody>
                    {alerts_table}
                </tbody>
            </table>
        </section>

        {correlation_html}
    </div>
</body>
</html>"""

        return html

    @staticmethod
    def _html_escape(text: str) -> str:
        """Escape HTML special characters."""
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )
