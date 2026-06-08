from __future__ import annotations

from repolens.resolve.descriptions import brief_description, first_brief_description


def test_brief_description_rejects_badge_only_markdown() -> None:
    description = (
        "[![NPM version](https://img.shields.io/npm/v/@smithy/middleware-retry/latest.svg)]"
        "(https://www.npmjs.com/package/@smithy/middleware-retry) "
        "[![NPM downloads](https://img.shields.io/npm/dm/@smithy/middleware-retry.svg)]"
        "(https://www.npmjs.com/package/@smithy/middleware-retry)"
    )

    assert brief_description(description) is None


def test_brief_description_keeps_human_text_after_badges() -> None:
    description = (
        "[![NPM version](https://img.shields.io/npm/v/acme/latest.svg)]"
        "(https://www.npmjs.com/package/acme) Useful runtime helpers."
    )

    assert brief_description(description) == "Useful runtime helpers."


def test_brief_description_rejects_truncated_badge_fragments() -> None:
    assert brief_description("[![NPM version](https://img.shields.io/npm/v/acme/latest.svg") is None


def test_brief_description_preserves_plain_url_bearing_text() -> None:
    assert (
        brief_description("Implements https://w3c.github.io/accname/")
        == "Implements https://w3c.github.io/accname/"
    )


def test_first_brief_description_skips_badge_junk() -> None:
    assert (
        first_brief_description(
            (
                "[![NPM downloads](https://img.shields.io/npm/dm/acme.svg)]"
                "(https://www.npmjs.com/package/acme)",
                "Useful package summary.",
            )
        )
        == "Useful package summary."
    )
