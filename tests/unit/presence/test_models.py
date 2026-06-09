from __future__ import annotations

from repolens.presence.models import DeliveryArtifact, Presence


def test_presence_delivery_artifact_round_trips_with_slots_dataclass() -> None:
    presence = Presence(
        install_state="installed",
        delivery_state="delivered",
        relation="direct",
        delivery_artifact=DeliveryArtifact(
            kind="bundle",
            path="dist/app.js",
            hash="sha256:abc123",
        ),
    )

    serialized = presence.to_dict()
    restored = Presence.from_dict(serialized)

    assert serialized["delivery_artifact"] == {
        "kind": "bundle",
        "path": "dist/app.js",
        "hash": "sha256:abc123",
    }
    assert restored == presence
