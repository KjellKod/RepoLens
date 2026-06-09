"""Typed dependency presence records."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

InstallState = Literal["installed", "not_installed", "lockfile_only", "unknown"]
DeliveryState = Literal["delivered", "not_delivered", "not_scanned", "unknown"]
Relation = Literal[
    "direct",
    "transitive",
    "peer",
    "optional",
    "dev",
    "devOptional",
    "mixed",
    "unknown",
]
PlatformMatch = Literal["target", "host", "cross_platform", "no", "unknown"]


@dataclass(frozen=True, slots=True)
class DeliveryArtifact:
    """Forward-compatible artifact evidence slot for a future scanner."""

    kind: str | None = None
    path: str | None = None
    hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {key: value for key, value in self.__dict__.items() if value is not None}

    @classmethod
    def from_dict(cls, data: object) -> DeliveryArtifact | None:
        if not isinstance(data, dict):
            return None
        return cls(
            kind=_optional_str(data.get("kind")),
            path=_optional_str(data.get("path")),
            hash=_optional_str(data.get("hash")),
        )


@dataclass(frozen=True, slots=True)
class Presence:
    """Schema mirror for resolved/inventory/shortlist presence blocks."""

    install_state: InstallState = "unknown"
    delivery_state: DeliveryState = "unknown"
    relation: Relation = "unknown"
    path: list[str] = field(default_factory=list)
    platform_match: PlatformMatch = "unknown"
    source: str = "unknown"
    target: str = "unknown"
    reopen_on_delivery_change: bool = True
    delivery_artifact: DeliveryArtifact | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "install_state": self.install_state,
            "delivery_state": self.delivery_state,
            "relation": self.relation,
            "path": list(self.path),
            "platform_match": self.platform_match,
            "source": self.source,
            "target": self.target,
            "reopen_on_delivery_change": self.reopen_on_delivery_change,
        }
        if self.delivery_artifact is not None:
            artifact = self.delivery_artifact.to_dict()
            if artifact:
                data["delivery_artifact"] = artifact
        return data

    @classmethod
    def from_dict(cls, data: object) -> Presence | None:
        if not isinstance(data, dict):
            return None
        return cls(
            install_state=_install_state(data.get("install_state")),
            delivery_state=_delivery_state(data.get("delivery_state")),
            relation=_relation(data.get("relation")),
            path=_string_list(data.get("path")),
            platform_match=_platform_match(data.get("platform_match")),
            source=_text_or_unknown(data.get("source")),
            target=_text_or_unknown(data.get("target")),
            reopen_on_delivery_change=bool(data.get("reopen_on_delivery_change", True)),
            delivery_artifact=DeliveryArtifact.from_dict(data.get("delivery_artifact")),
        )


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _text_or_unknown(value: object) -> str:
    return _optional_str(value) or "unknown"


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _install_state(value: object) -> InstallState:
    text = str(value)
    if text in {"installed", "not_installed", "lockfile_only", "unknown"}:
        return text
    return "unknown"


def _delivery_state(value: object) -> DeliveryState:
    text = str(value)
    if text in {"delivered", "not_delivered", "not_scanned", "unknown"}:
        return text
    return "unknown"


def _relation(value: object) -> Relation:
    text = str(value)
    if text in {
        "direct",
        "transitive",
        "peer",
        "optional",
        "dev",
        "devOptional",
        "mixed",
        "unknown",
    }:
        return text
    return "unknown"


def _platform_match(value: object) -> PlatformMatch:
    text = str(value)
    if text in {"target", "host", "cross_platform", "no", "unknown"}:
        return text
    return "unknown"
