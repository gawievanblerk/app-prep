"""Terminal prompts for --interactive."""

from __future__ import annotations

from collections.abc import Callable

from dpr.model import Question


def ask_on_terminal(question: Question, options: list[str],
                    input_fn: Callable[[str], str] = input,
                    output: Callable[[str], None] = print) -> str | None:
    output("")
    output(question.text)
    for number, option in enumerate(options, start=1):
        output(f"  {number}. {option}")
    raw = input_fn("Answer (number or text, empty to skip): ").strip()
    if not raw:
        return None
    if raw.isdigit() and 1 <= int(raw) <= len(options):
        return options[int(raw) - 1]
    return raw
