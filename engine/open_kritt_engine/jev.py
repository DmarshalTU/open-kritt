"""TypeSafe Jev client for finding decisions.

Jev answers choice, score, and yes/no questions. It does not read a repository
or write a workflow, so it is used only to rank findings that a scan model
already produced.
"""

import json
import urllib.error
import urllib.request
from typing import Any

from .schema import EXTRACTOR_HELPER_FIELD

JEV_ENDPOINT = "https://api.typesafe.ai/v1/systemone"
JEV_MODEL = "jev-latest"
JEV_ENV_KEY = "TYPESAFE_API_KEY"
IMPACT_ORDER = ("critical", "high", "medium", "low", "informational")
_MAX_RULE_CHARS = 4000


class JevError(RuntimeError):
    pass


def jev_api_key(env: dict[str, str] | None = None) -> str:
    from .provider_credentials import provider_environment

    source = provider_environment(env)
    return str(source.get(JEV_ENV_KEY) or "").strip()


def finding_questions(rules: str) -> dict[str, Any]:
    program_rules = rules.strip()[:_MAX_RULE_CHARS]
    severity_instructions: str | dict[str, str] = "Which severity matches this finding?"
    if program_rules:
        severity_instructions = {
            "program_rules": program_rules,
            "question": "Which severity matches this finding under `program_rules`?",
        }
    return {
        "severity": {
            "type": "choice",
            "instructions": severity_instructions,
            "criteria": {
                "critical": "Consensus or integrity corruption, a persistent outage, or unauthorized theft.",
                "high": "Realistic remote impact: a prolonged outage, authentication bypass, or substantial asset impact.",
                "medium": "Bounded availability, authorization, or integrity impact with meaningful prerequisites.",
                "low": "A concrete but minor impact.",
                "informational": "No demonstrated security impact.",
            },
        },
        "in_scope": {
            "type": "noul",
            "instructions": "A remote attacker who is not already trusted can reach this in the production build.",
            "criteria": {
                "true": "An external actor can reach the behavior in production.",
                "false": "The behavior is local-only, trusted-only, or otherwise unreachable.",
            },
        },
        "reportable": {
            "type": "noul",
            "instructions": (
                "This is a concrete vulnerability: attacker-controlled input, a missing or flawed check, "
                "and a security impact. A missing check with no demonstrated effect is not reportable."
            ),
        },
    }


def decide(
    state: str,
    questions: dict[str, Any],
    *,
    api_key: str,
    model: str = JEV_MODEL,
    timeout: float = 30,
    urlopen=urllib.request.urlopen,
) -> dict[str, Any]:
    if not api_key.strip():
        raise JevError("TYPESAFE_API_KEY is not set.")
    if not state.strip() or not questions:
        raise JevError("Jev needs a finding and at least one question.")
    body = json.dumps({"state": state, "model": model, "questions": questions}).encode("utf-8")
    request = urllib.request.Request(
        JEV_ENDPOINT,
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "open-kritt",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise JevError(f"Jev returned HTTP {exc.code}.") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise JevError("Jev request failed.") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("answers"), dict):
        raise JevError("Jev returned an unexpected response.")
    return payload


def ranking_from_answer(row_id: int, answers: dict[str, Any], vulnerability_type: str | None) -> dict[str, Any]:
    severity = answers.get("severity") if isinstance(answers.get("severity"), dict) else {}
    level = str(severity.get("choice") or "")
    if level not in IMPACT_ORDER:
        raise JevError("Jev returned a severity outside the requested choices.")
    try:
        confidence = float(severity.get("confidence") or 0)
    except (TypeError, ValueError) as exc:
        raise JevError("Jev returned an unreadable severity confidence.") from exc
    in_scope = _noul(answers.get("in_scope"), "in_scope")
    reportable = _noul(answers.get("reportable"), "reportable")
    root_bug = (vulnerability_type or "").strip() or "unspecified"
    return {
        "id": row_id,
        "rank": float(IMPACT_ORDER.index(level)) + (1 - max(0.0, min(confidence, 1.0))),
        "impact_level": level,
        "minimum_reward": 0,
        "maximum_reward": 0,
        "reasoning": (
            f"Jev chose {level} with confidence {confidence:.2f}. "
            f"In scope {in_scope:.2f}. Reportable {reportable:.2f}. "
            "Reward amounts are not estimated."
        ),
        "root_bug": root_bug,
    }


def rank_findings(
    findings: list[dict[str, Any]],
    *,
    api_key: str,
    rules: str,
    decide_call=decide,
) -> tuple[dict[str, Any], dict[str, int], str]:
    questions = finding_questions(rules)
    rankings: list[dict[str, Any]] = []
    input_tokens = 0
    output_tokens = 0
    model = JEV_MODEL
    for finding in findings:
        response = decide_call(str(finding.get("state") or ""), questions, api_key=api_key)
        model = str(response.get("model") or model)
        usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
        input_tokens += _token_count(usage.get("input_tokens"))
        output_tokens += _token_count(usage.get("output_tokens"))
        answers = response.get("answers")
        if not isinstance(answers, dict):
            raise JevError("Jev returned an unexpected response.")
        rankings.append(
            ranking_from_answer(
                int(finding["id"]),
                answers,
                finding.get("vulnerability_type") if isinstance(finding.get("vulnerability_type"), str) else None,
            )
        )
    payload = {
        EXTRACTOR_HELPER_FIELD: True,
        "rankings": rankings,
        "summary": "Ordered by Jev severity. Critical sorts before informational.",
        "missing_from_prompt": "",
    }
    return payload, {"input_tokens": input_tokens, "output_tokens": output_tokens}, model


def _noul(answer: Any, name: str) -> float:
    if not isinstance(answer, dict):
        raise JevError(f"Jev omitted the {name} decision.")
    try:
        value = float(answer.get("noul"))
    except (TypeError, ValueError) as exc:
        raise JevError(f"Jev omitted the {name} decision.") from exc
    if value < 0 or value > 1:
        raise JevError(f"Jev omitted the {name} decision.")
    return value


def _token_count(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0
