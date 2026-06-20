"""Abstract base class for security audit runners.

A runner is responsible for executing an agentic security audit against a
repository directory given a prompt, and returning structured findings. Each
concrete runner wraps a specific engine (e.g. the native Claude Code CLI or
OpenCode) while exposing a uniform interface so the rest of the pipeline does
not need to know which engine is in use.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Tuple


class SecurityAuditRunner(ABC):
    """Interface implemented by every security audit engine."""

    @abstractmethod
    def validate_available(self) -> Tuple[bool, str]:
        """Check that the underlying engine is installed and configured.

        Returns:
            Tuple of (available, error_message). When ``available`` is False,
            ``error_message`` explains what is missing.
        """
        raise NotImplementedError

    @abstractmethod
    def run_security_audit(self, repo_dir: Path, prompt: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Run the security audit.

        Args:
            repo_dir: Path to the repository directory to analyze.
            prompt: The fully rendered security audit prompt.

        Returns:
            Tuple of (success, error_message, parsed_results).
        """
        raise NotImplementedError
