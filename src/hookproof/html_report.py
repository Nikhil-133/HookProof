"""Self-contained HTML report renderer.

No external assets, scripts or CDNs: the output is a single portable HTML file.
Every value from the scan report is HTML-escaped, so response bodies or target
strings cannot inject markup.
"""

from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Any


def _e(value: Any) -> str:
    return escape(str(value), quote=True)


def _pretty_json(value: Any) -> str:
    try:
        rendered = json.dumps(value, indent=2, sort_keys=True, default=str)
    except (TypeError, ValueError):
        rendered = str(value)
    return _e(rendered)


def _status_class(status: str) -> str:
    return {"PASS": "pass", "FAIL": "fail", "ERROR": "error"}.get(status.upper(), "error")


def _severity_class(severity: str) -> str:
    return severity.lower().strip() if severity else "info"


def _exchange_rows(result: dict[str, Any]) -> str:
    exchanges = (result.get("evidence") or {}).get("exchanges") or []
    if not exchanges:
        return '<p class="empty">No HTTP exchanges recorded.</p>'
    rows = []
    for exchange in exchanges:
        rows.append(
            "<tr>"
            f"<td>{_e(exchange.get('label', 'request'))}</td>"
            f"<td><code>{_e(exchange.get('status_code', '?'))}</code></td>"
            f"<td><pre>{_pretty_json(exchange.get('response_body', ''))}</pre></td>"
            "</tr>"
        )
    return (
        '<table class="exchanges"><thead><tr><th>Exchange</th><th>HTTP</th>'
        f"<th>Response body</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


def _state_block(label: str, state: Any) -> str:
    if state is None:
        return ""
    return f"<h4>{_e(label)}</h4><pre>{_pretty_json(state)}</pre>"


def _finding_html(result: dict[str, Any]) -> str:
    status = str(result.get("status", "ERROR")).upper()
    status_class = _status_class(status)
    severity = str(result.get("severity", "INFO"))
    notes = result.get("notes") or []
    remediation = result.get("remediation")
    error = result.get("error")

    notes_html = ""
    if notes:
        items = "".join(f"<li>{_e(note)}</li>" for note in notes)
        notes_html = f'<ul class="notes">{items}</ul>'

    remediation_html = ""
    if status == "FAIL" and remediation:
        remediation_html = (
            f'<div class="remediation"><strong>Remediation</strong><p>{_e(remediation)}</p></div>'
        )

    error_html = ""
    if error:
        error_html = f'<div class="error-box"><strong>Error</strong><p>{_e(error)}</p></div>'

    return f"""
    <article class="finding {status_class}">
      <header class="finding-head">
        <span class="badge {status_class}">{_e(status)}</span>
        <div class="finding-title">
          <h3>{_e(result.get("title", ""))}</h3>
          <code>{_e(result.get("id", ""))}</code>
        </div>
        <span class="severity {_severity_class(severity)}">{_e(severity)}</span>
      </header>
      <p class="description">{_e(result.get("description", ""))}</p>
      <div class="compare">
        <div class="compare-col"><h4>Expected</h4><p>{_e(result.get("expected", ""))}</p></div>
        <div class="compare-col"><h4>Observed (EffectProof)</h4><p>{_e(result.get("observed", ""))}</p></div>
      </div>
      {notes_html}
      {remediation_html}
      {error_html}
      <details>
        <summary>Evidence</summary>
        {_exchange_rows(result)}
        {_state_block("State before", (result.get("evidence") or {}).get("before_state"))}
        {_state_block("State after", (result.get("evidence") or {}).get("after_state"))}
      </details>
    </article>
    """


def render_html(report: dict[str, Any]) -> str:
    """Render the report document as a standalone HTML string."""
    summary = report.get("summary", {})
    target = report.get("target", {})
    outcome = str(summary.get("outcome", "INCONCLUSIVE"))
    outcome_class = {"PASS": "pass", "FAIL": "fail"}.get(outcome, "error")

    findings = "".join(_finding_html(result) for result in report.get("results", []))
    notes = "".join(f"<li>{_e(note)}</li>" for note in report.get("notes", []))
    limitations = "".join(f"<li>{_e(item)}</li>" for item in report.get("limitations", []))
    highest = summary.get("highest_severity") or "none"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="HookProof {_e(report.get("tool_version", ""))}">
<title>HookProof report - {_e(report.get("run_id", ""))}</title>
<style>
  :root {{
    --bg: #0a0f1e; --panel: #111a2e; --panel-2: #0d1526; --line: #233050;
    --text: #e9eefc; --muted: #93a2bd; --green: #2ecc71; --red: #ff4d5e;
    --yellow: #f5c542; --cyan: #45d6d6; --blue: #5b8cff;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: radial-gradient(1200px 600px at 20% -10%, #15234a 0%, var(--bg) 55%);
    color: var(--text); font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
    line-height: 1.55;
  }}
  .wrap {{ max-width: 1180px; margin: 0 auto; padding: 36px 22px 60px; }}
  .brand {{ font-size: 34px; font-weight: 800; letter-spacing: 1px; }}
  .brand span {{ color: var(--cyan); }}
  .tag {{ color: var(--muted); margin-top: 2px; }}
  .meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
           gap: 10px 22px; margin: 26px 0; }}
  .meta div {{ background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
               padding: 10px 14px; overflow-wrap: anywhere; }}
  .meta dt {{ color: var(--muted); font-size: 11px; text-transform: uppercase;
              letter-spacing: .12em; }}
  .meta dd {{ margin: 2px 0 0; font-size: 14px; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 12px; margin: 22px 0; }}
  .card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 12px;
           padding: 14px; text-align: center; }}
  .card .num {{ font-size: 28px; font-weight: 800; }}
  .card .lbl {{ color: var(--muted); font-size: 12px; text-transform: uppercase;
                letter-spacing: .1em; }}
  .outcome {{ border-radius: 12px; padding: 16px 20px; font-weight: 700; margin: 18px 0 26px; }}
  .outcome.pass {{ background: rgba(46,204,113,.12); border: 1px solid var(--green); color: var(--green); }}
  .outcome.fail {{ background: rgba(255,77,94,.12); border: 1px solid var(--red); color: var(--red); }}
  .outcome.error {{ background: rgba(245,197,66,.12); border: 1px solid var(--yellow); color: var(--yellow); }}
  h2 {{ margin: 30px 0 14px; font-size: 20px; }}
  .finding {{ background: var(--panel); border: 1px solid var(--line); border-left-width: 5px;
              border-radius: 12px; padding: 16px 18px; margin-bottom: 14px; }}
  .finding.pass {{ border-left-color: var(--green); }}
  .finding.fail {{ border-left-color: var(--red); }}
  .finding.error {{ border-left-color: var(--yellow); }}
  .finding-head {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
  .finding-title {{ flex: 1 1 320px; }}
  .finding-title h3 {{ margin: 0; font-size: 16px; }}
  .finding-title code {{ color: var(--muted); font-size: 12px; }}
  .badge {{ font-size: 11px; font-weight: 800; letter-spacing: .1em; padding: 4px 9px;
            border-radius: 999px; }}
  .badge.pass {{ background: var(--green); color: #04140a; }}
  .badge.fail {{ background: var(--red); color: #1a0407; }}
  .badge.error {{ background: var(--yellow); color: #1a1503; }}
  .severity {{ font-size: 11px; font-weight: 800; letter-spacing: .08em;
               border: 1px solid currentColor; border-radius: 999px; padding: 3px 9px; }}
  .severity.critical {{ color: #ff6b7a; background: rgba(255,77,94,.15); }}
  .severity.high {{ color: #ff8a95; }}
  .severity.medium {{ color: var(--yellow); }}
  .severity.low {{ color: var(--cyan); }}
  .severity.info {{ color: var(--muted); }}
  .description {{ color: var(--muted); margin: 10px 0; }}
  .compare {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
              gap: 12px; margin: 12px 0; }}
  .compare-col {{ background: var(--panel-2); border: 1px solid var(--line);
                  border-radius: 10px; padding: 10px 12px; }}
  .compare-col h4 {{ margin: 0 0 4px; font-size: 11px; color: var(--muted);
                     text-transform: uppercase; letter-spacing: .12em; }}
  .compare-col p {{ margin: 0; font-size: 14px; }}
  .notes {{ margin: 8px 0; padding-left: 20px; color: var(--muted); }}
  .remediation {{ border-left: 3px solid var(--yellow); padding: 4px 0 4px 12px; margin: 10px 0; }}
  .remediation strong {{ color: var(--yellow); }}
  .remediation p {{ margin: 4px 0 0; }}
  .error-box {{ border-left: 3px solid var(--yellow); padding: 4px 0 4px 12px; margin: 10px 0; }}
  .error-box strong {{ color: var(--yellow); }}
  details {{ margin-top: 12px; }}
  summary {{ cursor: pointer; color: var(--cyan); font-weight: 600; }}
  pre {{ background: #070c18; border: 1px solid var(--line); border-radius: 8px;
         padding: 10px; overflow-x: auto; font-size: 12px; color: #cfe0ff; }}
  .exchanges {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }}
  .exchanges th, .exchanges td {{ border-bottom: 1px solid var(--line); text-align: left;
                                  padding: 8px; vertical-align: top; }}
  .exchanges th {{ color: var(--muted); font-size: 11px; text-transform: uppercase;
                   letter-spacing: .1em; }}
  .empty {{ color: var(--muted); font-style: italic; }}
  footer {{ margin-top: 40px; border-top: 1px solid var(--line); padding-top: 18px;
            color: var(--muted); font-size: 13px; }}
  footer ul {{ padding-left: 20px; }}
  @media print {{
    body {{ background: #fff; color: #111; }}
    .finding, .card, .meta div, .compare-col {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">Hook<span>Proof</span></div>
    <div class="tag">EffectProof webhook security report</div>
  </header>

  <section class="meta">
    <div><dt>Target</dt><dd>{_e(target.get("url", "?"))}</dd></div>
    <div><dt>Detected mode</dt><dd>{_e(report.get("detected_mode", "unknown"))}</dd></div>
    <div><dt>Suite</dt><dd>{_e(report.get("suite", "?"))}</dd></div>
    <div><dt>Run id</dt><dd>{_e(report.get("run_id", "?"))}</dd></div>
    <div><dt>Requests</dt><dd>{_e(summary.get("request_count", 0))} in {_e(summary.get("duration_seconds", 0))}s</dd></div>
    <div><dt>Generated</dt><dd>{_e(report.get("generated_at", "?"))}</dd></div>
  </section>

  <section class="cards">
    <div class="card"><div class="num">{_e(summary.get("total", 0))}</div><div class="lbl">Tests</div></div>
    <div class="card"><div class="num" style="color:var(--green)">{_e(summary.get("passed", 0))}</div><div class="lbl">Passed</div></div>
    <div class="card"><div class="num" style="color:var(--red)">{_e(summary.get("failed", 0))}</div><div class="lbl">Failed</div></div>
    <div class="card"><div class="num" style="color:var(--yellow)">{_e(summary.get("errors", 0))}</div><div class="lbl">Errors</div></div>
    <div class="card"><div class="num">{_e(highest)}</div><div class="lbl">Highest severity</div></div>
  </section>

  <div class="outcome {outcome_class}">Outcome: {_e(outcome)}</div>

  <main>
    <h2>Findings</h2>
    {findings}
  </main>

  <footer>
    <strong>Notes</strong>
    <ul>{notes}</ul>
    <strong>Limitations</strong>
    <ul>{limitations}</ul>
    <p>Generated by HookProof {_e(report.get("tool_version", ""))} - schema {_e(report.get("schema_version", 1))}.</p>
  </footer>
</div>
</body>
</html>
"""


def write_html(report: dict[str, Any], path: str | Path) -> Path:
    """Write a standalone HTML report and return the resolved path."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_html(report), encoding="utf-8")
    return destination


__all__ = ["render_html", "write_html"]
