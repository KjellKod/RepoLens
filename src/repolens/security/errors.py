"""Typed exceptions raised by security primitives."""


class SecurityError(Exception):
    """Base class for security guardrail failures."""


class CloneSecurityError(SecurityError):
    """Raised when clone hardening rejects or aborts an operation."""


class CloneAuthRequired(CloneSecurityError):
    """Raised when a clone needs authentication but none was supplied."""


class CloneAccessDenied(CloneSecurityError):
    """Raised when a credential is present but the remote denies access (403)."""


class CloneRateLimited(CloneSecurityError):
    """Raised when the remote rate-limits the clone (HTTP 429 / secondary limit)."""


class CloneTimeout(CloneSecurityError):
    """Raised when the clone subprocess exceeds its configured timeout."""

    def __init__(self, *, configured_seconds: float, elapsed_seconds: float) -> None:
        self.configured_seconds = configured_seconds
        self.elapsed_seconds = elapsed_seconds
        super().__init__(
            f"clone timed out after {configured_seconds:g}s "
            f"(elapsed {elapsed_seconds:.1f}s; repo may be too large or network too slow; "
            "try a higher --clone-timeout)"
        )


class CloneTransient(CloneSecurityError):
    """Raised for retryable network-class clone failures (reset/timeout/5xx)."""


class FetchSecurityError(SecurityError):
    """Raised when a guarded HTTP fetch is unsafe or exceeds limits."""


class ParseSecurityError(SecurityError):
    """Raised when parsing untrusted bytes is unsafe or exceeds limits."""


class SanitizationError(SecurityError):
    """Raised when output sanitization cannot safely render data."""


class ContentSecurityError(SecurityError):
    """Raised when untrusted content violates wrapping or cap rules."""


class ChecksumSecurityError(SecurityError):
    """Raised when checksum verification fails."""


class NameHygieneError(SecurityError):
    """Raised when forbidden runtime-supplied names are found."""
