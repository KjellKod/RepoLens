"""Security primitives for untrusted repository inputs and outputs."""

from repolens.security.checksum import compute_sha256, verify_sha256
from repolens.security.clone import (
    CloneInvocation,
    CloneOptions,
    build_hardened_clone_command,
    hardened_clone,
)
from repolens.security.content import (
    ContentScreen,
    cap_text,
    normalize_untrusted_text,
    screen_untrusted_content,
    strip_boundary_tokens,
    wrap_untrusted_content,
)
from repolens.security.errors import (
    ChecksumSecurityError,
    CloneSecurityError,
    ContentSecurityError,
    FetchSecurityError,
    NameHygieneError,
    ParseSecurityError,
    SanitizationError,
    SecurityError,
)
from repolens.security.http_client import FetchResult, HttpFetchOptions, fetch_url
from repolens.security.limits import DEFAULT_LIMITS, SecurityLimits, TimeBudget, TimeBudgetExceeded
from repolens.security.parsers import (
    ArchiveInspection,
    UnsafeArchiveError,
    inspect_archive,
    load_yaml_safe,
    parse_json_bytes,
    parse_xml_bytes,
    parse_xml_safe,
    parse_yaml_bytes,
    validate_archive_limits,
)
from repolens.security.redaction import redact_tokens, redact_tokens_from_structure
from repolens.security.sanitize import (
    markdown_link,
    neutralize_csv_cell,
    render_code_span,
    sanitize_markdown,
    serialize_csv_row,
    serialize_csv_rows,
)

__all__ = [
    "ArchiveInspection",
    "ChecksumSecurityError",
    "CloneInvocation",
    "CloneOptions",
    "CloneSecurityError",
    "ContentScreen",
    "ContentSecurityError",
    "DEFAULT_LIMITS",
    "FetchResult",
    "FetchSecurityError",
    "HttpFetchOptions",
    "NameHygieneError",
    "ParseSecurityError",
    "SanitizationError",
    "SecurityError",
    "SecurityLimits",
    "TimeBudget",
    "TimeBudgetExceeded",
    "UnsafeArchiveError",
    "build_hardened_clone_command",
    "cap_text",
    "compute_sha256",
    "fetch_url",
    "hardened_clone",
    "inspect_archive",
    "load_yaml_safe",
    "markdown_link",
    "neutralize_csv_cell",
    "normalize_untrusted_text",
    "parse_json_bytes",
    "parse_xml_bytes",
    "parse_xml_safe",
    "parse_yaml_bytes",
    "redact_tokens",
    "redact_tokens_from_structure",
    "render_code_span",
    "sanitize_markdown",
    "screen_untrusted_content",
    "serialize_csv_row",
    "serialize_csv_rows",
    "strip_boundary_tokens",
    "validate_archive_limits",
    "verify_sha256",
    "wrap_untrusted_content",
]
