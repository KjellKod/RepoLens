"""Conservative dependency presence defaults."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from repolens.presence.models import InstallState, PlatformMatch, Presence, Relation


def build_presence(
    *,
    tags: Mapping[str, str] | None = None,
    install_state: InstallState | None = None,
    relation: Relation = "unknown",
    path: Sequence[str] = (),
    platform_match: PlatformMatch = "unknown",
    source: str = "syft",
    target: str = "unknown",
    artifact_scanned: bool = False,
    artifact_present: bool | None = None,
) -> Presence:
    """Build the only production presence object for resolved records."""

    if artifact_scanned and artifact_present is True:
        delivery_state = "delivered"
    elif artifact_scanned and artifact_present is False:
        delivery_state = "not_delivered"
    elif tags is None and (install_state is None or install_state == "unknown"):
        delivery_state = "unknown"
    else:
        delivery_state = "not_scanned"

    return Presence(
        install_state=install_state or _install_state_from_tags(tags),
        delivery_state=delivery_state,
        relation=relation,
        path=[str(item) for item in path if str(item).strip()],
        platform_match=platform_match,
        source=source,
        target=target,
        reopen_on_delivery_change=True,
    )


def _install_state_from_tags(tags: Mapping[str, str] | None) -> InstallState:
    if tags is None:
        return "unknown"
    scope = str(tags.get("scope") or "")
    distribution = str(tags.get("distribution") or "")
    if scope in {"runtime", "dev", "build", "test"} or distribution in {
        "server",
        "client-or-mobile",
        "not-distributed",
    }:
        return "installed"
    return "unknown"
