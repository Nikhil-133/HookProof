"""HookProof command line interface (Typer + Rich).

Commands:
    hookproof lab serve --mode vulnerable|secure --host 127.0.0.1 --port 8000
    hookproof scan --target http://127.0.0.1:8000/webhooks/payment --suite core
                   --report reports/report.json
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.progress import (
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
)

from . import __version__, ui
from .config import load_settings, redact
from .html_report import write_html
from .lab.app import LAB_MODES, LOOPBACK_HOSTS, create_app
from .reports import write_json
from .scanner import (
    DEFAULT_ALLOWED_HOSTS,
    DEFAULT_MAX_REQUESTS,
    DEFAULT_TIMEOUT,
    Scanner,
    TargetValidationError,
)

app = typer.Typer(
    add_completion=False,
    help="HookProof - webhook security testing with EffectProof state verification.",
    no_args_is_help=True,
)
lab_app = typer.Typer(help="Run the local webhook security lab.", no_args_is_help=True)
app.add_typer(lab_app, name="lab")


@app.command("version")
def version_cmd() -> None:
    """Print the HookProof version with a banner."""
    ui.print_banner()
    ui.console.print(f"  [bold cyan]HookProof[/] [white]{__version__}[/]")
    ui.console.print("  [dim]local lab | EffectProof | core suite[/]\n")


@lab_app.command("serve")
def lab_serve(
    mode: str = typer.Option("vulnerable", "--mode", help="Lab mode: vulnerable or secure."),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host (loopback only)."),
    port: int = typer.Option(8000, "--port", help="Bind port."),
    db: Path | None = typer.Option(None, "--db", help="SQLite database path."),
) -> None:
    """Start the local webhook lab (isolated, synthetic data only)."""
    import uvicorn

    mode = mode.lower().strip()
    if mode not in LAB_MODES:
        typer.secho(f"Invalid mode {mode!r}. Choose one of {LAB_MODES}.", fg="red", err=True)
        raise typer.Exit(code=2)
    if host not in LOOPBACK_HOSTS:
        typer.secho(
            f"Refusing to bind to {host!r}. The lab (especially vulnerable mode) "
            f"must bind to a loopback address: {', '.join(LOOPBACK_HOSTS)}.",
            fg="red",
            err=True,
        )
        raise typer.Exit(code=2)

    settings = load_settings()
    if settings.uses_dev_webhook_secret or settings.uses_dev_test_token:
        ui.render_warnings(
            [
                "using development-only default secrets. Set HOOKPROOF_WEBHOOK_SECRET "
                "and HOOKPROOF_TEST_TOKEN for anything beyond the demo."
            ]
        )

    ui.print_lab_info(
        mode=mode,
        host=host,
        port=port,
        secret_marker=redact(settings.webhook_secret),
        token_marker=redact(settings.test_token),
        db_path=str(db) if db is not None else None,
    )

    application = create_app(mode=mode, db_path=db, settings=settings)
    try:
        uvicorn.run(application, host=host, port=port, log_level="info")
    except KeyboardInterrupt:  # pragma: no cover - interactive shutdown
        ui.console.print("\n[dim]lab stopped[/]")


@app.command("scan")
def scan_cmd(
    target: str = typer.Option(..., "--target", help="Webhook endpoint URL (loopback only)."),
    suite: str = typer.Option("core", "--suite", help="Test suite to run."),
    report: Path | None = typer.Option(
        None, "--report", help="Path to write the JSON report (e.g. reports/report.json)."
    ),
    html: Path | None = typer.Option(
        None, "--html", help="Path to write a standalone HTML report (e.g. reports/report.html)."
    ),
    timeout: float = typer.Option(DEFAULT_TIMEOUT, "--timeout", help="Per-request timeout (seconds)."),
    max_requests: int = typer.Option(
        DEFAULT_MAX_REQUESTS, "--max-requests", help="Maximum requests for the scan."
    ),
    run_id: str | None = typer.Option(None, "--run-id", help="Override the deterministic run id."),
    allow_host: str | None = typer.Option(
        None,
        "--allow-host",
        help="Additional explicitly allowed host (repeatable). Loopback is always allowed.",
    ),
) -> None:
    """Scan a local webhook handler for security failures with EffectProof."""
    settings = load_settings()
    allowed = list(DEFAULT_ALLOWED_HOSTS)
    if allow_host:
        allowed.append(allow_host.lower())

    try:
        scanner = Scanner(
            target=target,
            settings=settings,
            suite=suite,
            timeout=timeout,
            max_requests=max_requests,
            allowed_hosts=allowed,
            run_id=run_id,
        )
    except TargetValidationError as exc:
        ui.console.print(f"[bold red]Target rejected:[/] {exc}")
        raise typer.Exit(code=2) from None
    except KeyError as exc:
        ui.console.print(f"[bold red]Suite error:[/] {exc}")
        raise typer.Exit(code=2) from None

    ui.print_scan_intro(suite=scanner.suite_name, target=scanner.target.url)

    try:
        with Progress(
            SpinnerColumn(spinner_name="line", style="cyan"),
            TextColumn("[bold]{task.description}"),
            MofNCompleteColumn(),
            console=ui.console,
            transient=True,
        ) as progress:
            task = progress.add_task(f"running {scanner.suite_name} suite", total=len(scanner.scenarios))

            def on_test_start(scenario_id: str) -> None:
                progress.update(task, description=f"testing {scenario_id}")

            def on_test_complete(scenario_id: str, status: str) -> None:
                progress.advance(task)

            outcome = scanner.run(
                on_test_start=on_test_start,
                on_test_complete=on_test_complete,
            )
    finally:
        scanner.close()

    report_doc = outcome.report
    ui.print_report(report_doc)

    if report is not None:
        path = write_json(report_doc, report)
        ui.console.print(f"[green]JSON report:[/] {path.resolve()}")
    if html is not None:
        html_path = write_html(report_doc, html)
        ui.console.print(f"[green]HTML report:[/] {html_path.resolve()}")

    outcome_value = report_doc["summary"]["outcome"]
    if outcome_value == "FAIL":
        raise typer.Exit(code=1)
    if outcome_value == "INCONCLUSIVE":
        raise typer.Exit(code=2)


def main() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
