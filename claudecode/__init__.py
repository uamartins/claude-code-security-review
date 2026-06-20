"""
ClaudeCode - AI-Powered PR Security Audit Tool

A standalone security audit tool that uses Claude Code for comprehensive
security analysis of GitHub pull requests.
"""

__version__ = "1.0.0"
__author__ = "Anthropic Security Team"

# Import main components for easier access
from claudecode.github_action_audit import (
    GitHubActionClient,
    ClaudeCodeRunner,
    SimpleClaudeRunner,
    get_runner,
    main
)
from claudecode.runners.base import SecurityAuditRunner

__all__ = [
    "GitHubActionClient",
    "SecurityAuditRunner",
    "ClaudeCodeRunner",
    "SimpleClaudeRunner",
    "get_runner",
    "main"
]