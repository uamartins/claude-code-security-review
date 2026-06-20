"""Unit tests for OpenCodeRunner."""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from claudecode.runners.base import SecurityAuditRunner
from claudecode.runners.opencode_runner import OpenCodeRunner


def _jsonl(*events) -> str:
    """Render events as a newline-delimited JSON stream."""
    return "\n".join(json.dumps(e) for e in events) + "\n"


def _text_event(text: str) -> dict:
    return {"type": "text", "part": {"type": "text", "text": text}}


# A realistic OpenCode JSONL stream wrapping a findings JSON answer.
FINDINGS_PAYLOAD = {
    "findings": [
        {"file": "app.py", "severity": "HIGH", "description": "SQL injection"}
    ],
    "analysis_summary": {"files_reviewed": 1, "high_severity": 1},
}
REAL_STREAM = _jsonl(
    {"type": "step_start", "part": {"type": "step-start"}},
    _text_event(json.dumps(FINDINGS_PAYLOAD)),
    {"type": "step_finish", "part": {"type": "step-finish", "tokens": {"total": 100}}},
)


class TestOpenCodeRunnerBasics:
    def test_is_security_audit_runner(self):
        assert issubclass(OpenCodeRunner, SecurityAuditRunner)
        assert isinstance(OpenCodeRunner(), SecurityAuditRunner)

    def test_default_timeout(self):
        from claudecode.constants import SUBPROCESS_TIMEOUT
        assert OpenCodeRunner().timeout_seconds == SUBPROCESS_TIMEOUT
        assert OpenCodeRunner(timeout_minutes=15).timeout_seconds == 15 * 60

    def test_model_defaults_to_constant(self):
        with patch('claudecode.runners.opencode_runner.DEFAULT_OPENCODE_MODEL', 'openai/gpt-x'):
            assert OpenCodeRunner().model == 'openai/gpt-x'

    def test_explicit_model_overrides_default(self):
        assert OpenCodeRunner(model='deepseek/deepseek-chat').model == 'deepseek/deepseek-chat'


class TestJsonlParsing:
    def test_collect_assistant_text_concatenates_text_parts(self):
        runner = OpenCodeRunner()
        stream = _jsonl(
            {"type": "step_start", "part": {}},
            _text_event("Hello "),
            _text_event("world"),
            {"type": "step_finish", "part": {}},
        )
        assert runner._collect_assistant_text(stream) == "Hello world"

    def test_collect_ignores_non_json_and_other_events(self):
        runner = OpenCodeRunner()
        stream = (
            "not json at all\n"
            + json.dumps({"type": "tool", "part": {"text": "should be ignored"}}) + "\n"
            + json.dumps(_text_event("kept")) + "\n"
            + "\n"
        )
        assert runner._collect_assistant_text(stream) == "kept"

    def test_extract_findings_from_text(self):
        runner = OpenCodeRunner()
        result = runner._extract_security_findings(json.dumps(FINDINGS_PAYLOAD))
        assert result == FINDINGS_PAYLOAD

    def test_extract_returns_empty_structure_when_no_findings(self):
        runner = OpenCodeRunner()
        result = runner._extract_security_findings("just some prose, no json")
        assert result['findings'] == []
        assert result['analysis_summary']['review_completed'] is False


class TestPromptTooLongDetection:
    @pytest.mark.parametrize("text", [
        "Error: prompt is too long",
        "request exceeds the maximum context length",
        "too many tokens in input",
    ])
    def test_detects_prompt_too_long(self, text):
        assert OpenCodeRunner._looks_like_prompt_too_long(text) is True

    def test_normal_text_is_not_flagged(self):
        assert OpenCodeRunner._looks_like_prompt_too_long("PONG") is False
        assert OpenCodeRunner._looks_like_prompt_too_long("") is False


class TestRunSecurityAudit:
    def _mock_completed(self, returncode=0, stdout="", stderr=""):
        m = MagicMock()
        m.returncode = returncode
        m.stdout = stdout
        m.stderr = stderr
        return m

    def test_missing_repo_dir(self, tmp_path):
        runner = OpenCodeRunner()
        missing = tmp_path / "nope"
        ok, err, results = runner.run_security_audit(missing, "prompt")
        assert ok is False
        assert "does not exist" in err

    def test_successful_run_parses_findings(self, tmp_path):
        runner = OpenCodeRunner()
        with patch('subprocess.run', return_value=self._mock_completed(stdout=REAL_STREAM)) as mock_run:
            ok, err, results = runner.run_security_audit(tmp_path, "prompt")
        assert ok is True
        assert err == ""
        assert results == FINDINGS_PAYLOAD
        # Prompt passed via stdin, JSON format requested.
        _, kwargs = mock_run.call_args
        assert kwargs['input'] == "prompt"
        assert '--format' in mock_run.call_args[0][0]

    def test_model_flag_included_when_set(self, tmp_path):
        runner = OpenCodeRunner(model='deepseek/deepseek-chat')
        with patch('subprocess.run', return_value=self._mock_completed(stdout=REAL_STREAM)) as mock_run:
            runner.run_security_audit(tmp_path, "prompt")
        cmd = mock_run.call_args[0][0]
        assert '--model' in cmd
        assert 'deepseek/deepseek-chat' in cmd

    def test_model_flag_omitted_when_unset(self, tmp_path):
        runner = OpenCodeRunner(model=None)
        with patch('subprocess.run', return_value=self._mock_completed(stdout=REAL_STREAM)) as mock_run:
            runner.run_security_audit(tmp_path, "prompt")
        cmd = mock_run.call_args[0][0]
        assert '--model' not in cmd

    def test_prompt_too_long_returns_sentinel(self, tmp_path):
        runner = OpenCodeRunner()
        failing = self._mock_completed(returncode=1, stderr="Error: prompt is too long")
        with patch('subprocess.run', return_value=failing):
            ok, err, results = runner.run_security_audit(tmp_path, "prompt")
        assert ok is False
        assert err == "PROMPT_TOO_LONG"

    def test_nonzero_exit_after_retries_returns_error(self, tmp_path):
        runner = OpenCodeRunner()
        failing = self._mock_completed(returncode=2, stderr="boom")
        with patch('subprocess.run', return_value=failing), patch('time.sleep'):
            ok, err, results = runner.run_security_audit(tmp_path, "prompt")
        assert ok is False
        assert "return code 2" in err

    def test_timeout_is_handled(self, tmp_path):
        runner = OpenCodeRunner()
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired(cmd='opencode', timeout=1)):
            ok, err, results = runner.run_security_audit(tmp_path, "prompt")
        assert ok is False
        assert "timed out" in err


class TestValidateAvailable:
    def test_available(self):
        runner = OpenCodeRunner()
        m = MagicMock(returncode=0, stdout="1.17.8", stderr="")
        with patch('subprocess.run', return_value=m):
            ok, err = runner.validate_available()
        assert ok is True
        assert err == ""

    def test_not_installed(self):
        runner = OpenCodeRunner()
        with patch('subprocess.run', side_effect=FileNotFoundError()):
            ok, err = runner.validate_available()
        assert ok is False
        assert "not installed" in err
