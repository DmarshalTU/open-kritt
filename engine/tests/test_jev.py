import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from open_kritt_engine.jev import JevError, decide, finding_questions, rank_findings, ranking_from_answer
from open_kritt_engine.post_processing import PostProcessor
from open_kritt_engine.schema import EXTRACTOR_HELPER_FIELD


def _answers():
    return {
        "severity": {"type": "choice", "choice": "high", "confidence": 0.8, "probabilities": {"high": 0.8}},
        "in_scope": {"type": "noul", "noul": 0.91},
        "reportable": {"type": "noul", "noul": 0.22},
    }


def test_finding_questions_keep_program_rules_with_the_decision():
    questions = finding_questions("Unauthenticated remote impact is high.")

    assert questions["severity"]["instructions"]["program_rules"] == "Unauthenticated remote impact is high."
    assert set(questions["severity"]["criteria"]) == {"critical", "high", "medium", "low", "informational"}
    assert questions["in_scope"]["type"] == "noul"
    assert questions["reportable"]["type"] == "noul"


def test_ranking_uses_severity_order_and_does_not_invent_rewards():
    item = ranking_from_answer(7, _answers(), "bounds check")

    assert item["id"] == 7
    assert item["impact_level"] == "high"
    assert item["minimum_reward"] == 0
    assert item["maximum_reward"] == 0
    assert item["root_bug"] == "bounds check"
    assert "In scope 0.91" in item["reasoning"]
    assert "Reportable 0.22" in item["reasoning"]
    lower = ranking_from_answer(
        8,
        {**_answers(), "severity": {**_answers()["severity"], "choice": "low"}},
        None,
    )
    assert item["rank"] < lower["rank"]


def test_ranking_rejects_an_unknown_severity():
    answers = _answers()
    answers["severity"] = {**answers["severity"], "choice": "urgent"}

    with pytest.raises(JevError, match="severity"):
        ranking_from_answer(1, answers, None)


def test_decide_reports_http_status_without_the_api_key():
    class Denied(Exception):
        pass

    def urlopen(_request, timeout):
        assert timeout == 30
        error = urllib_http_error()
        raise error

    with pytest.raises(JevError, match="HTTP 401") as raised:
        decide("finding", finding_questions(""), api_key="super-secret-token", urlopen=urlopen)

    assert "super-secret-token" not in str(raised.value)


def urllib_http_error():
    import urllib.error

    return urllib.error.HTTPError("https://api.typesafe.ai/v1/systemone", 401, "unauthorized", hdrs=None, fp=None)


def test_rank_findings_builds_a_ranker_payload():
    def fake_decide(state, questions, *, api_key):
        assert api_key == "test-key"
        assert "missing length check" in state
        assert "severity" in questions
        return {"model": "jev-1.13.0", "answers": _answers(), "usage": {"input_tokens": 12, "output_tokens": 3}}

    payload, usage, model = rank_findings(
        [{"id": 4, "state": "missing length check", "vulnerability_type": "bounds"}],
        api_key="test-key",
        rules="Remote impact first.",
        decide_call=fake_decide,
    )

    assert model == "jev-1.13.0"
    assert usage == {"input_tokens": 12, "output_tokens": 3}
    assert payload[EXTRACTOR_HELPER_FIELD] is True
    assert payload["rankings"][0]["impact_level"] == "high"


class _Conn:
    def commit(self):
        return None


class _Db:
    def __init__(self):
        self.claims = []
        self.rank_updates = []

    @contextmanager
    def connect(self):
        yield _Conn()

    def count_running_post_process(self, _conn, _scan_id, _kind):
        return 0

    def load_scan(self, _conn, _scan_id):
        return {
            "id": 1,
            "status": "post_processing",
            "workflow_id": 1,
            "repo_full": "example/repo",
            "repo_scope": "network parsing",
            "severity_ranker": "Remote impact first.",
            "model": "qwen2.5-coder:7b",
            "model_provider": "ollama",
            "harness": "codex",
            "thinking_effort": "low",
        }

    def load_vulnerabilities(self, _conn, _scan_id):
        return [
            {
                "id": 4,
                "dedupe_is_canonical": True,
                "dedupe_canonical_id": 4,
                "json_answer": {"summary": "missing length check", "vulnerability_type": "bounds", "file_path": "a.c"},
            }
        ]

    def next_post_process_batch_index(self, _conn, _scan_id, _kind):
        return 0

    def claim_post_process_metadata(self, _conn, **kwargs):
        self.claims.append(kwargs)
        return 9

    def apply_rank_updates(self, _conn, **kwargs):
        self.rank_updates.append(kwargs)

    def update_post_process_metadata(self, _conn, metadata_id, **kwargs):
        self.rank_updates.append({"metadata_id": metadata_id, **kwargs})


def test_ranker_uses_jev_and_does_not_call_the_scan_harness(monkeypatch):
    database = _Db()
    processor = PostProcessor(SimpleNamespace(data_dir="/tmp", github_token=None), database)
    processor._run_harness_with_retries = lambda **_kwargs: (_ for _ in ()).throw(AssertionError("harness called"))
    monkeypatch.setattr("open_kritt_engine.post_processing.jev_api_key", lambda: "test-key")

    def fake_rank(findings, *, api_key, rules):
        assert api_key == "test-key"
        assert rules == "Remote impact first."
        assert json.loads(findings[0]["state"])["finding"]["summary"] == "missing length check"
        payload, usage, model = rank_findings(
            [{"id": 4, "state": "missing length check", "vulnerability_type": "bounds"}],
            api_key=api_key,
            rules=rules,
            decide_call=lambda *_args, **_kwargs: {
                "model": "jev-1.13.0",
                "answers": _answers(),
                "usage": {"input_tokens": 1, "output_tokens": 1},
            },
        )
        return payload, usage, model

    monkeypatch.setattr("open_kritt_engine.post_processing.rank_findings", fake_rank)

    assert processor._run_next_ranker_batch({"id": 1}, object()) is True
    assert database.claims[0]["model_provider"] == "jev"
    assert database.claims[0]["model"] == "jev-latest"
    assert database.rank_updates[0]["updates"][0]["bounty_rank_model"] == "jev-1.13.0"
    assert database.rank_updates[0]["updates"][0]["bounty_rank_impact_level"] == "high"
