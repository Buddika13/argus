"""DASHBOARD — a small set of focused pages instead of one long page.

    Overview                high-level status only
    Resolver Health         per-resolver metrics, with a detail view
    Cache Poisoning         confirmed events and the evidence behind each
    DNS Query Monitor       every measurement, filterable and paged
    Anomaly Investigation   differences under review and how they were tested
    Independent Verification  a live check against trusted and authoritative sources
    Reports                 summaries for a written report

Public API, unchanged from the single-page version:

    render(storage, vantage)          -> the Overview page as HTML
    generate(storage, output, vantage)-> writes every page beside `output`
    build_server(...) / serve(...)    -> the live, routed server

Reads only. It never writes to the database, and it never re-decides a
classification: `verdict.py` maps what the detection engine already stored.
"""

from __future__ import annotations

from pathlib import Path

from .live import build_server, render_page, run_verification, serve
from .shell import PAGES

__all__ = ["render", "generate", "build_server", "serve", "render_page",
           "run_verification", "PAGES"]


def render(storage, vantage: str = "local", refresh_seconds: int = 0) -> str:
    """The Overview page. Kept for callers that want a single HTML string."""
    return render_page(storage, "overview", vantage, {}, live=False,
                       refresh_seconds=refresh_seconds)


def generate(storage, output, vantage: str = "local") -> Path:
    """Write the whole dashboard as static files.

    `output` names the Overview page (report.html by convention); the remaining
    pages are written beside it under their own names, so the set can be opened
    from the filesystem with the navigation intact.
    """
    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    for key, filename, _path, _title, _blurb in PAGES:
        target = out if key == "overview" else out.parent / filename
        target.write_text(render_page(storage, key, vantage, {}, live=False),
                          encoding="utf-8")
    return out
