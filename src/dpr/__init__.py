"""dpr: deterministic data protection review."""

from dpr.api import discover, review
from dpr.report.json_out import render_json
from dpr.report.markdown import render_markdown
from dpr.report.sarif import render_sarif

__version__ = "0.2.0"
__all__ = ["__version__", "discover", "render_json", "render_markdown", "render_sarif", "review"]
