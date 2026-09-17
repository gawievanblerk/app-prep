"""dpr: deterministic data protection review."""

from dpr.api import discover, review
from dpr.report.json_out import render_json
from dpr.report.markdown import render_markdown

__version__ = "0.1.0"
__all__ = ["__version__", "discover", "render_json", "render_markdown", "review"]
