"""Questions the code cannot answer, and how answers are gathered."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path

import yaml

from dpr.data import load
from dpr.model import Detection, Question, QuestionResult, ScanError

MAX_PROMPTS = 8
Ask = Callable[[Question, list[str]], str | None]


def load_questions() -> list[Question]:
    return [
        Question(
            id=q["id"],
            reviews=tuple(q["reviews"]),
            text=q["text"],
            type=q["type"],
            why=q["why"],
            who=q["who"],
            options_from=q.get("options_from"),
            static_options=tuple(q.get("static_options", [])),
            honest_out=tuple(q.get("honest_out", ["Not sure"])),
            answered_by=q.get("answered_by"),
            lawyer=bool(q.get("lawyer", False)),
        )
        for q in load("questions.yaml")["questions"]
    ]


def questions_for(reviews: Iterable[str]) -> list[Question]:
    wanted = set(reviews)
    return [q for q in load_questions() if wanted & set(q.reviews)]


def options(question: Question, detection: Detection) -> list[str]:
    found = [str(v) for v in getattr(detection, question.options_from or "", None) or []]
    found += [o for o in question.static_options if o not in found]
    return found + [o for o in question.honest_out if o not in found]


def _read_answers(source: str | Path | dict | None) -> dict:
    if source is None:
        return {}
    if isinstance(source, dict):
        return source
    path = Path(source)
    if not path.is_file():
        raise ScanError(f"answers file not found: {source}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ScanError(f"answers file is not valid YAML: {source}") from exc
    if not isinstance(data, dict):
        raise ScanError("answers file must be a mapping of question id to answer")
    return data


def _as_text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, list | tuple):
        return ", ".join(str(v) for v in value) or None
    return str(value).strip() or None


def resolve(
    questions: list[Question],
    detection: Detection,
    answers: str | Path | dict | None = None,
    interactive: bool = False,
    ask: Ask | None = None,
) -> tuple[list[QuestionResult], list[str]]:
    data = _read_answers(answers)
    known = {q.id for q in load_questions()} | {q.id for q in questions}
    warnings = [f"unknown answer key ignored: {key}" for key in data if key not in known]
    results: list[QuestionResult] = []
    prompts = 0
    for q in questions:
        detected = getattr(detection, q.answered_by, None) if q.answered_by else None
        if detected:
            results.append(QuestionResult(q, _as_text(detected), "detection", False))
            continue
        text = _as_text(data.get(q.id))
        if text is not None:
            results.append(QuestionResult(q, text, "answers", text in q.honest_out))
            continue
        if interactive and ask is not None and prompts < MAX_PROMPTS:
            prompts += 1
            text = _as_text(ask(q, options(q, detection)))
            if text is not None:
                results.append(QuestionResult(q, text, "interactive", text in q.honest_out))
                continue
        results.append(QuestionResult(q, None, "none", True))
    return results, warnings


def answers_template(questions: list[Question], detection: Detection) -> str:
    lines = [
        "# dpr answers file. Fill in what you know and leave the rest empty.",
        '# Honest answers such as "Not sure" are fine. They are listed as open questions.',
        "",
    ]
    for q in questions:
        lines.append(f"# {q.text}")
        opts = options(q, detection)
        if opts:
            lines.append(f"# Options: {', '.join(opts)}")
        lines.extend([f"{q.id}:", ""])
    return "\n".join(lines)
