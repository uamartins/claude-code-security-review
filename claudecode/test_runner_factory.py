"""Unit tests for the security audit runner abstraction and factory."""

import os
from unittest.mock import patch

import pytest

from claudecode import github_action_audit
from claudecode.github_action_audit import (
    ClaudeCodeRunner,
    ConfigurationError,
    SimpleClaudeRunner,
    _get_timeout_minutes,
    get_runner,
)
from claudecode.runners.base import SecurityAuditRunner


class TestRunnerAbstraction:
    """Tests for the SecurityAuditRunner interface and ClaudeCodeRunner."""

    def test_claude_runner_is_security_audit_runner(self):
        assert issubclass(ClaudeCodeRunner, SecurityAuditRunner)
        assert isinstance(ClaudeCodeRunner(), SecurityAuditRunner)

    def test_simple_claude_runner_is_backwards_compatible_alias(self):
        assert SimpleClaudeRunner is ClaudeCodeRunner

    def test_abstract_base_cannot_be_instantiated(self):
        with pytest.raises(TypeError):
            SecurityAuditRunner()

    def test_validate_claude_available_delegates_to_validate_available(self):
        runner = ClaudeCodeRunner()
        with patch.object(runner, 'validate_available', return_value=(True, "")) as mock_validate:
            result = runner.validate_claude_available()
        assert result == (True, "")
        mock_validate.assert_called_once()


class TestGetRunner:
    """Tests for the configuration-driven runner factory."""

    def test_default_backend_returns_claude_runner(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('SECURITY_REVIEW_BACKEND', None)
            runner = get_runner()
        assert isinstance(runner, ClaudeCodeRunner)

    def test_explicit_claude_backend(self):
        with patch.dict(os.environ, {'SECURITY_REVIEW_BACKEND': 'claude'}):
            runner = get_runner()
        assert isinstance(runner, ClaudeCodeRunner)

    def test_backend_is_case_insensitive_and_trimmed(self):
        with patch.dict(os.environ, {'SECURITY_REVIEW_BACKEND': '  CLAUDE  '}):
            runner = get_runner()
        assert isinstance(runner, ClaudeCodeRunner)

    def test_timeout_is_forwarded(self):
        with patch.dict(os.environ, {'SECURITY_REVIEW_BACKEND': 'claude'}):
            runner = get_runner(timeout_minutes=30)
        assert runner.timeout_seconds == 30 * 60

    def test_opencode_backend_returns_opencode_runner(self):
        from claudecode.runners.opencode_runner import OpenCodeRunner
        with patch.dict(os.environ, {'SECURITY_REVIEW_BACKEND': 'opencode'}):
            runner = get_runner()
        assert isinstance(runner, OpenCodeRunner)

    def test_unknown_backend_raises_configuration_error(self):
        with patch.dict(os.environ, {'SECURITY_REVIEW_BACKEND': 'bogus-engine'}):
            with pytest.raises(ConfigurationError):
                get_runner()

    def test_factory_honors_patched_runner(self):
        """The factory must reference the patchable module-level runner name."""
        with patch.object(github_action_audit, 'SimpleClaudeRunner') as mock_runner:
            with patch.dict(os.environ, {'SECURITY_REVIEW_BACKEND': 'claude'}):
                get_runner()
            mock_runner.assert_called_once()


class TestTimeoutMinutes:
    """Tests for CLAUDECODE_TIMEOUT parsing."""

    def test_unset_returns_none(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('CLAUDECODE_TIMEOUT', None)
            assert _get_timeout_minutes() is None

    def test_valid_value(self):
        with patch.dict(os.environ, {'CLAUDECODE_TIMEOUT': '15'}):
            assert _get_timeout_minutes() == 15

    def test_invalid_value_returns_none(self):
        with patch.dict(os.environ, {'CLAUDECODE_TIMEOUT': 'abc'}):
            assert _get_timeout_minutes() is None

    def test_non_positive_returns_none(self):
        with patch.dict(os.environ, {'CLAUDECODE_TIMEOUT': '0'}):
            assert _get_timeout_minutes() is None

    def test_timeout_propagates_to_runner(self):
        with patch.dict(os.environ, {'SECURITY_REVIEW_BACKEND': 'claude', 'CLAUDECODE_TIMEOUT': '5'}):
            from claudecode.github_action_audit import initialize_clients
            with patch.object(github_action_audit, 'GitHubActionClient'):
                _, runner = initialize_clients()
        assert runner.timeout_seconds == 5 * 60
