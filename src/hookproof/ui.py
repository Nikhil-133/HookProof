"""Terminal UI for HookProof (Rich-powered, ASCII-safe).

Everything printed here is plain ASCII so it works in legacy Windows consoles
as well as modern terminals. Colors and layout are still provided by Rich.
The UI is purely presentational: security logic lives in the scanner.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

STATUS_STYLES = {
    "PASS": "bold black on green",
    "FAIL": "bold white on red",
    "ERROR": "bold black on yellow",
}

STATUS_TEXT_STYLES = {
    "PASS": "green",
    "FAIL": "red",
    "ERROR": "yellow",
}

SEVERITY_STYLES = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "cyan",
    "INFO": "dim",
}

MODE_STYLES = {
    "vulnerable": "bold red",
    "secure": "bold green",
    "unknown": "bold yellow",
}

_FONT = {
    "H": ["H   H", "H   H", "HHHHH", "H   H", "H   H"],
    "O": [" OOO ", "O   O", "O   O", "O   O", " OOO "],
    "K": ["K   K", "K  K ", "KKK  ", "K  K ", "K   K"],
    "P": ["PPPP ", "P   P", "PPPP ", "P    ", "P    "],
    "R": ["RRRR ", "R   R", "RRRR ", "R R  ", "R  R "],
    "F": ["FFFFF", "F    ", "FFFF ", "F    ", "F    "],
}


def _logo_lines(word: str = "HOOKPROOF") -> list[str]:
    return ["  ".join(_FONT[char][row] for char in word).rstrip() for row in range(5)]


LOGO = "\n".join(_logo_lines())


def print_banner(subtitle: str = "EffectProof - webhook security testing") -> None:
    """Print the HookProof brand banner."""
    logo = Text(LOGO, style="bold cyan")
    tagline = Text(subtitle, style="dim")
    console.print(
        Panel(
            Align.center(Group(logo, tagline)),
            border_style="cyan",
            box=box.ASCII,
            padding=(0, 2),
        )
    )


def print_scan_intro(suite: str, target: str) -> None:
    """Compact one-line intro shown before a scan."""
    console.print()
    console.print(f"[bold cyan]HookProof[/] [dim]|[/] [bold]{suite}[/] suite")
    console.print(f"[dim]target[/]  {target}")
    console.print()


def print_report(report: dict[str, Any]) -> None:
    """Render a full scan report with color-coded findings."""
    summary = report["summary"]
    target = report["target"]
    mode = report.get("detected_mode", "unknown")

    console.print()
    console.rule("[bold cyan]HookProof scan report[/]", characters="-", style="cyan")

    meta = Table.grid(padding=(0, 3))
    meta.add_column(justify="right", style="dim")
    meta.add_column()
    meta.add_row("target", Text(str(target.get("url", "?")), style="white"))
    meta.add_row("detected", Text(f"{mode} mode", style=MODE_STYLES.get(mode, "white")))
    meta.add_row("suite", Text(str(report.get("suite", "?"))))
    meta.add_row("run id", Text(str(report.get("run_id", "?"))))
    meta.add_row(
        "requests",
        Text(f"{summary['request_count']} in {summary['duration_seconds']}s"),
    )
    console.print(meta)

    counts = Text()
    counts.append("  passed ", style="dim")
    counts.append(str(summary["passed"]), style="bold green")
    counts.append("   failed ", style="dim")
    counts.append(str(summary["failed"]), style="bold red")
    counts.append("   errors ", style="dim")
    counts.append(str(summary["errors"]), style="bold yellow")
    if summary.get("highest_severity"):
        counts.append("   highest ", style="dim")
        counts.append(
            str(summary["highest_severity"]),
            style=SEVERITY_STYLES.get(summary["highest_severity"], ""),
        )
    console.print(counts)
    console.print()

    table = Table(box=box.ASCII, show_edge=False, pad_edge=False, expand=True)
    table.add_column("status", width=7, no_wrap=True)
    table.add_column("test", width=30, overflow="fold")
    table.add_column("sev", width=9, no_wrap=True)
    table.add_column("effectproof", ratio=1, overflow="fold")

    for result in report["results"]:
        status = result["status"]
        test_cell = Text()
        test_cell.append(result["id"] + "\n", style="bold")
        test_cell.append(result["title"], style="dim")

        severity = result.get("severity") if status == "FAIL" else "-"
        severity_cell = Text(str(severity), style=SEVERITY_STYLES.get(str(severity), "dim"))

        table.add_row(
            Text(status, style=STATUS_STYLES.get(status, "")),
            test_cell,
            severity_cell,
            _evidence_cell(result),
        )

    console.print(table)
    console.print()
    console.print(_outcome_panel(report))

    interface_error = report.get("interface_error")
    if interface_error:
        console.print(
            Panel(
                Text(interface_error, style="yellow"),
                title="[bold yellow]EffectProof unavailable[/]",
                border_style="yellow",
                box=box.ASCII,
            )
        )


def _evidence_cell(result: dict[str, Any]) -> Text:
    status = result["status"]
    body = Text()
    rows: list[tuple[str, str, str]] = [
        ("expected", result["expected"], "white"),
        ("observed", result["observed"], STATUS_TEXT_STYLES.get(status, "white")),
    ]
    for note in result.get("notes", []):
        rows.append(("note", note, "italic dim"))
    if status == "FAIL" and result.get("remediation"):
        rows.append(("fix", result["remediation"], "yellow"))
    if result.get("error"):
        rows.append(("error", result["error"], "yellow"))

    for index, (label, value, style) in enumerate(rows):
        if index:
            body.append("\n")
        body.append(f"{label:<9}", style="dim")
        body.append(value, style=style)
    return body


def _outcome_panel(report: dict[str, Any]) -> Panel:
    summary = report["summary"]
    outcome = summary["outcome"]
    if outcome == "PASS":
        text = Text()
        text.append("PASS  ", style="bold green")
        text.append(f"all {summary['total']} core tests passed", style="white")
        return Panel(text, border_style="green", box=box.ASCII)
    if outcome == "FAIL":
        severity = summary.get("highest_severity") or "UNKNOWN"
        text = Text()
        text.append("FAIL  ", style="bold red")
        text.append(f"{summary['failed']} confirmed failure(s)", style="white")
        text.append("  |  highest severity ", style="dim")
        text.append(str(severity), style=SEVERITY_STYLES.get(str(severity), "bold red"))
        text.append("\n")
        text.append("See the 'fix' column for remediation guidance.", style="dim")
        return Panel(text, border_style="red", box=box.ASCII)

    text = Text()
    text.append("INCONCLUSIVE  ", style="bold yellow")
    text.append(f"{summary['errors']} test(s) could not be evaluated", style="white")
    text.append("\n")
    text.append("EffectProof needs a reachable, token-protected state interface.", style="dim")
    return Panel(text, border_style="yellow", box=box.ASCII)


def print_lab_info(
    mode: str,
    host: str,
    port: int,
    secret_marker: str,
    token_marker: str,
    db_path: str | None = None,
) -> None:
    """Render the startup panel for ``hookproof lab serve``."""
    console.print()
    rows = Table.grid(padding=(0, 3))
    rows.add_column(justify="right", style="dim")
    rows.add_column()
    rows.add_row("mode", Text(mode, style=MODE_STYLES.get(mode, "white")))
    rows.add_row("webhook", Text(f"http://{host}:{port}/webhooks/payment", style="cyan"))
    rows.add_row("state", Text(f"http://{host}:{port}/__test__/health", style="cyan"))
    rows.add_row("secret", Text(secret_marker, style="dim"))
    rows.add_row("token", Text(token_marker, style="dim"))
    if db_path:
        rows.add_row("database", Text(db_path, style="dim"))

    border = "red" if mode == "vulnerable" else "green"
    warning = (
        "Vulnerable mode is for an isolated local lab only. Never expose it."
        if mode == "vulnerable"
        else "Secure mode verifies signatures, freshness, payloads and idempotency."
    )
    body = Group(
        Text(f"Starting HookProof lab - {mode} mode", style=f"bold {border}"),
        Text(""),
        rows,
        Text(""),
        Text(warning, style="yellow" if mode == "vulnerable" else "dim"),
    )
    console.print(Panel(body, border_style=border, box=box.ASCII, padding=(0, 1)))
    console.print()


def render_warnings(messages: Iterable[str]) -> None:
    for message in messages:
        console.print(f"[yellow]warning:[/] {message}")


__all__ = [
    "console",
    "print_banner",
    "print_scan_intro",
    "print_report",
    "print_lab_info",
    "render_warnings",
]
