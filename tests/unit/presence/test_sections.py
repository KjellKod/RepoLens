from __future__ import annotations

from repolens.presence.sections import (
    DELIVERED_SECTION,
    INSTALLED_REVIEW_SECTION,
    LOCKFILE_MONITOR_SECTION,
    NOT_SCANNED_UNKNOWN_SECTION,
    section_for_presence,
)


def test_section_mapping_is_cautious_and_visible() -> None:
    assert section_for_presence({"delivery_state": "delivered"}) == DELIVERED_SECTION
    assert section_for_presence({"install_state": "lockfile_only"}) == LOCKFILE_MONITOR_SECTION
    assert section_for_presence({"relation": "optional"}) == LOCKFILE_MONITOR_SECTION
    assert (
        section_for_presence({"install_state": "installed", "delivery_state": "not_scanned"})
        == INSTALLED_REVIEW_SECTION
    )
    assert section_for_presence(None) == NOT_SCANNED_UNKNOWN_SECTION
