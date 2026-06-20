"""Security audit runner backends.

Exposes the abstract :class:`SecurityAuditRunner` interface. Concrete runners
(e.g. the native Claude Code runner) live alongside this package and are wired
together by the factory in ``claudecode.github_action_audit.get_runner``.
"""

from claudecode.runners.base import SecurityAuditRunner

__all__ = ["SecurityAuditRunner"]
