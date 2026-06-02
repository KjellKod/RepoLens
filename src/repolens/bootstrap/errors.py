"""Exception hierarchy for the tool bootstrap.

All bootstrap failures derive from :class:`BootstrapError` so callers can catch
the whole family while still distinguishing integrity failures (which must fail
closed) from usage/config errors.
"""

from __future__ import annotations


class BootstrapError(Exception):
    """Base class for every bootstrap failure."""


class InvalidPin(BootstrapError):
    """The pins manifest is malformed, incomplete, or uses a forbidden spec.

    Raised for missing required fields, ``latest``/floating versions, or a base
    image lacking an ``@sha256:`` digest.
    """


class IntegrityError(BootstrapError):
    """Base class for fail-closed integrity failures.

    Any subclass means a downloaded artifact could not be trusted; the caller
    must abort before the artifact is made executable, written, or invoked.
    """


class ChecksumMismatch(IntegrityError):
    """A downloaded artifact's sha256 did not match the pinned/trusted value."""


class SignatureVerificationError(IntegrityError):
    """cosign signature/certificate verification of the checksums file failed."""


class ChecksumProvenanceError(IntegrityError):
    """The manifest-pinned sha256 is not vouched for by the signed checksums file.

    Closes the "edit-the-pin" gap: even if a maintainer changes the pinned
    digest, it must still match the entry inside the cosign-verified checksums
    file or the bootstrap fails closed.
    """


class UnhashedRequirement(BootstrapError):
    """A ScanCode requirements line lacks a ``--hash=`` pin."""


class UsageError(BootstrapError):
    """CLI usage or configuration error (maps to exit code 2)."""
