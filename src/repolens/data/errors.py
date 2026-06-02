"""Typed errors for artifact reads and writes."""


class ArtifactError(Exception):
    """Base class for artifact boundary failures."""


class SchemaValidationError(ArtifactError):
    """Raised when an artifact does not match its frozen schema."""


class LimitExceeded(ArtifactError):
    """Raised when an artifact exceeds a configured safety limit."""


class CorruptArtifactError(ArtifactError):
    """Raised when an artifact cannot be decoded or parsed safely."""
