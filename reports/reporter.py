"""
reports/reporter.py
Generate JSON reports and rich CLI summaries from scan findings.
"""

import json
import time
from datetime import datetime
from typing import List
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from utils.config import Finding

console = Console()


class Reporter:
    """
    Formats and saves scan findings.
    Supports:
    - JSON report (machine-readable)
    - CLI table summary (human-readable)
    """

    def __init__(self, findings: List[Finding], targets: list, elapsed: float):
        self.findings = findings
        self.targets  = targets
        self.elapsed  = elapsed
        self.ts       = datetime.utcnow().isoformat() + "Z"

    # ─── JSON Report ─────────────────────────────────────────────────────────

    def save_json(self, path: str) -> str:
        report = {
            "tool":          "XScanner v2.0",
            "timestamp":     self.ts,
            "duration_sec":  round(self.elapsed, 2),
            "targets":       self.targets,
            "total_findings": len(self.findings),
            "severity_summary": self._severity_summary(),
            "findings": [self._finding_to_dict(f) for f in self.findings],
        }
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2))
        return str(out.resolve())

    def _finding_to_dict(self, f: Finding) -> dict:
        return {
            "url":           f.url,
            "param":         f.param,
            "xss_type":      f.xss_type,
            "context":       f.context,
            "severity":      f.severity,
            "confidence":    f.confidence,
            "payload":       f.payload,
            "encoding_used": f.encoding_used,
            "waf_bypassed":  f.waf_bypassed,
            "verified":      f.verified,
            "evidence":      f.evidence,
        }

    def _severity_summary(self) -> dict:
        summary = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in self.findings:
            summary[f.severity] = summary.get(f.severity, 0) + 1
        return summary

    # ─── CLI Summary ─────────────────────────────────────────────────────────

    def print_summary(self):
        console.print()
        console.rule("[bold cyan]SCAN SUMMARY[/bold cyan]")

        # Stats panel
        sev = self._severity_summary()
        stats = (
            f"[bold]Targets:[/bold]  {len(self.targets)}\n"
            f"[bold]Duration:[/bold] {self.elapsed:.1f}s\n"
            f"[bold]Findings:[/bold] {len(self.findings)}\n"
            f"[red]High:[/red]      {sev['High']}  "
            f"[yellow]Medium:[/yellow] {sev['Medium']}  "
            f"[green]Low:[/green]    {sev['Low']}"
        )
        console.print(Panel(stats, title="[bold]Results[/bold]", border_style="cyan", box=box.ROUNDED))

        if not self.findings:
            console.print("\n  [green]✓ No XSS vulnerabilities found.[/green]\n")
            return

        # Findings table
        table = Table(
            title="XSS Findings",
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
        )
        table.add_column("#",       style="dim", width=4)
        table.add_column("Type",    style="bold red", width=10)
        table.add_column("Sev",     width=8)
        table.add_column("Conf",    width=8)
        table.add_column("Param",   style="yellow", width=15)
        table.add_column("Context", style="cyan", width=12)
        table.add_column("WAF?",    width=5)
        table.add_column("URL",     style="dim", max_width=50)

        sev_colors = {"High": "red", "Medium": "yellow", "Low": "green", "Info": "dim"}

        for i, f in enumerate(self.findings, 1):
            color = sev_colors.get(f.severity, "white")
            waf_str = "[green]✓[/green]" if f.waf_bypassed else "-"
            table.add_row(
                str(i),
                f.xss_type,
                f"[{color}]{f.severity}[/{color}]",
                f.confidence,
                f.param[:15],
                f.context[:12],
                waf_str,
                f.url[:60],
            )

        console.print(table)
        console.print()

    def print_finding_details(self):
        """Print full payload + evidence for each finding."""
        for i, f in enumerate(self.findings, 1):
            console.print(Panel(
                f"[bold]URL:[/bold]      {f.url}\n"
                f"[bold]Param:[/bold]    [yellow]{f.param}[/yellow]\n"
                f"[bold]Type:[/bold]     [red]{f.xss_type}[/red]\n"
                f"[bold]Context:[/bold]  [cyan]{f.context}[/cyan]\n"
                f"[bold]Payload:[/bold]  [green]{f.payload}[/green]\n"
                f"[bold]Encoding:[/bold] {f.encoding_used}\n"
                f"[bold]WAF:[/bold]      {'Bypassed ✓' if f.waf_bypassed else 'N/A'}\n"
                f"[bold]Evidence:[/bold] [dim]{f.evidence[:200]}[/dim]",
                title=f"[bold red]Finding #{i}[/bold red]",
                border_style="red",
                box=box.ROUNDED,
            ))
