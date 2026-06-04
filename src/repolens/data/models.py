"""Small typed records mirroring the frozen schemas."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Origin = Literal["third-party-oss", "first-party"]
Scope = Literal["runtime", "dev", "build", "test", "unknown"]
Distribution = Literal["server", "client-or-mobile", "not-distributed", "unknown"]
PolicyTier = Literal["ALLOW", "REVIEW", "BLOCK", "UNKNOWN"]
SchemaVersion = Literal["1.0"]
Modified = bool | Literal["unknown"]
DeclaredVersionStatus = Literal["declared-unpinned"]


@dataclass(frozen=True)
class ResolvedItem:
    schema_version: SchemaVersion
    name: str
    version: str
    repo: str
    evidence: dict[str, Any]
    tags: dict[str, str]
    spdx_id: str | None = None
    purl: str | None = None
    declared_license_raw: str | None = None
    modified: Modified = "unknown"
    declared_version_status: DeclaredVersionStatus | None = None

    def to_dict(self) -> dict[str, Any]:
        return {key: value for key, value in self.__dict__.items() if value is not None}


@dataclass(frozen=True)
class InventoryComponent:
    name: str
    license: str
    origin: Origin
    scope: Scope
    distribution: Distribution
    versions: list[str]
    source_url: str
    modified: Modified
    found_in: list[str]
    policy_tier: PolicyTier | None = None
    evidence_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {key: value for key, value in self.__dict__.items() if value is not None}
