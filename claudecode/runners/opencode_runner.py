"""Security audit runner backed by the OpenCode CLI.

OpenCode (https://opencode.ai) is a provider-agnostic agentic coding CLI. It is
invoked in headless mode via ``opencode run --format json``, reading the prompt
from stdin (mirroring the Claude Code runner). Unlike Claude Code, which emits a
single JSON object with a ``result`` field, OpenCode streams newline-delimited
JSON ("JSONL") events. The assistant's answer is reconstructed by concatenating
the ``text`` parts of those events.
"""

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from claudecode.constants import DEFAULT_OPENCODE_MODEL, SUBPROCESS_TIMEOUT
from claudecode.json_parser import parse_json_with_fallbacks
from claudecode.logger import get_logger
from claudecode.runners.base import SecurityAuditRunner

logger = get_logger(__name__)

# Substrings used to detect context-length / prompt-too-long errors so the
# caller can reuse the existing "retry without diff" path.
_PROMPT_TOO_LONG_MARKERS = (
    "prompt is too long",
    "context length",
    "context window",
    "maximum context",
    "too many tokens",
    "exceeds the maximum",
    "input is too long",
)

# Empty result structure returned when no findings can be extracted.
_EMPTY_RESULTS: Dict[str, Any] = {
    'findings': [],
    'analysis_summary': {
        'files_reviewed': 0,
        'high_severity': 0,
        'medium_severity': 0,
        'low_severity': 0,
        'review_completed': False,
    },
}


class OpenCodeRunner(SecurityAuditRunner):
    """Security audit runner backed by the OpenCode CLI."""

    def __init__(self, timeout_minutes: Optional[int] = None, model: Optional[str] = None):
        """Initialize the OpenCode runner.

        Args:
            timeout_minutes: Timeout for OpenCode execution (defaults to
                SUBPROCESS_TIMEOUT).
            model: OpenCode model in ``provider/model`` format. Defaults to
                ``DEFAULT_OPENCODE_MODEL`` (the ``OPENCODE_MODEL`` env var); when
                None, OpenCode's own configured default is used.
        """
        if timeout_minutes is not None:
            self.timeout_seconds = timeout_minutes * 60
        else:
            self.timeout_seconds = SUBPROCESS_TIMEOUT

        self.model = model if model is not None else DEFAULT_OPENCODE_MODEL

    def run_security_audit(self, repo_dir: Path, prompt: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Run an OpenCode security audit.

        Args:
            repo_dir: Path to repository directory.
            prompt: Security audit prompt.

        Returns:
            Tuple of (success, error_message, parsed_results). On a
            context-length error the error_message is "PROMPT_TOO_LONG" so the
            caller can retry with a smaller prompt.
        """
        if not repo_dir.exists():
            return False, f"Repository directory does not exist: {repo_dir}", {}

        prompt_size = len(prompt.encode('utf-8'))
        if prompt_size > 1024 * 1024:  # 1MB
            print(f"[Warning] Large prompt size: {prompt_size / 1024 / 1024:.2f}MB", file=sys.stderr)

        # Build the OpenCode command. The prompt is passed via stdin to avoid
        # "argument list too long" errors with large diffs.
        cmd = ['opencode', 'run', '--format', 'json']
        if self.model:
            cmd += ['--model', self.model]

        try:
            NUM_RETRIES = 3
            for attempt in range(NUM_RETRIES):
                result = subprocess.run(
                    cmd,
                    input=prompt,
                    cwd=repo_dir,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                )

                if result.returncode != 0:
                    combined = f"{result.stdout}\n{result.stderr}"
                    if self._looks_like_prompt_too_long(combined):
                        return False, "PROMPT_TOO_LONG", {}
                    if attempt == NUM_RETRIES - 1:
                        error_details = (
                            f"OpenCode execution failed with return code {result.returncode}\n"
                            f"Stderr: {result.stderr}\n"
                            f"Stdout: {result.stdout[:500]}..."
                        )
                        return False, error_details, {}
                    time.sleep(5 * attempt)
                    continue  # Retry

                # Reconstruct the assistant's response from the JSONL event stream.
                response_text = self._collect_assistant_text(result.stdout)

                if self._looks_like_prompt_too_long(response_text):
                    return False, "PROMPT_TOO_LONG", {}

                if not response_text.strip():
                    if attempt == 0:
                        continue  # Retry once on empty output
                    return False, "OpenCode returned no assistant text", {}

                parsed_results = self._extract_security_findings(response_text)
                return True, "", parsed_results

            return False, "Unexpected error in retry logic", {}

        except subprocess.TimeoutExpired:
            return False, f"OpenCode execution timed out after {self.timeout_seconds // 60} minutes", {}
        except Exception as e:
            return False, f"OpenCode execution error: {str(e)}", {}

    def _collect_assistant_text(self, stdout: str) -> str:
        """Concatenate ``text`` parts from the OpenCode JSONL event stream.

        Each line is a JSON event. Text output lives in events of
        ``type == "text"`` under ``part.text``. Non-JSON lines and other event
        types are ignored.
        """
        chunks: List[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            if event.get('type') == 'text':
                part = event.get('part', {})
                if isinstance(part, dict):
                    text = part.get('text')
                    if isinstance(text, str):
                        chunks.append(text)
        return ''.join(chunks)

    def _extract_security_findings(self, response_text: str) -> Dict[str, Any]:
        """Extract the findings JSON from the assistant's response text."""
        success, result_json = parse_json_with_fallbacks(response_text, "OpenCode output")
        if success and isinstance(result_json, dict) and 'findings' in result_json:
            return result_json

        # Return empty structure if no findings found.
        return dict(_EMPTY_RESULTS)

    @staticmethod
    def _looks_like_prompt_too_long(text: str) -> bool:
        if not text:
            return False
        lowered = text.lower()
        return any(marker in lowered for marker in _PROMPT_TOO_LONG_MARKERS)

    def validate_available(self) -> Tuple[bool, str]:
        """Validate that the OpenCode CLI is installed."""
        try:
            result = subprocess.run(
                ['opencode', '--version'],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return True, ""
            error_msg = f"OpenCode returned exit code {result.returncode}"
            if result.stderr:
                error_msg += f". Stderr: {result.stderr}"
            if result.stdout:
                error_msg += f". Stdout: {result.stdout}"
            return False, error_msg
        except subprocess.TimeoutExpired:
            return False, "OpenCode command timed out"
        except FileNotFoundError:
            return False, "OpenCode is not installed or not in PATH"
        except Exception as e:
            return False, f"Failed to check OpenCode: {str(e)}"
