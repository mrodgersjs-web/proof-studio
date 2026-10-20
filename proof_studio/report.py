"""Render scenario results as a table or JSON."""

from __future__ import annotations

import json

from .runner import ScenarioResult, summarize


def render_text(results: list[ScenarioResult]) -> str:
    summary = summarize(results)
    lines = []
    lines.append("proof-studio tamper-scenario run")
    lines.append("")
    lines.append(f"{'scenario':<28} {'kind':<24} {'expect':<7} {'actual':<7} {'result':<16} detail")
    lines.append("-" * 110)
    for r in results:
        result = "OK " + r.outcome if r.matched else "FAIL " + r.outcome
        lines.append(
            f"{r.scenario.file:<28} {r.scenario.kind:<24} {r.scenario.expect:<7} "
            f"{r.actual:<7} {result:<16} {r.detail}"
        )
    lines.append("")
    lines.append(f"scenarios              {summary['scenarios']}")
    lines.append(f"forgeries caught       {summary['caught']}/{summary['forgeries']}")
    lines.append(f"controls wrongly held  {summary['wrongly_blocked']}/{summary['controls']}")
    lines.append(f"false-done-caught rate {summary['false_done_caught_rate']:.2f}")
    lines.append(f"false-pass rate        {summary['false_pass_rate']:.2f}")
    lines.append(f"accuracy               {summary['accuracy']:.2f}")
    lines.append("")
    lines.append("ALL EXPECTATIONS MET" if summary["all_matched"] else "MISMATCH: a planted failure did not go red")
    return "\n".join(lines)


def render_json(results: list[ScenarioResult]) -> str:
    return json.dumps(
        {"results": [r.as_dict() for r in results], "summary": summarize(results)},
        indent=2,
    )
