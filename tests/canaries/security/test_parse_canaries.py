from __future__ import annotations

import io
import stat
import zipfile

import pytest

from repolens.security.errors import ParseSecurityError
from repolens.security.limits import SecurityLimits
from repolens.security.parsers import inspect_archive, parse_xml_bytes, parse_yaml_bytes


def test_yaml_billion_laughs_rejected() -> None:
    payload = b"""
a: &a ["lol", "lol", "lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
"""
    with pytest.raises(ParseSecurityError, match="alias"):
        parse_yaml_bytes(payload)


def test_xml_xxe_doctype_rejected() -> None:
    payload = b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///tmp/acme">]><project>&e;</project>'
    with pytest.raises(ParseSecurityError, match="DOCTYPE"):
        parse_xml_bytes(payload)


def test_zip_ratio_bomb_rejected() -> None:
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("acme.txt", b"0" * 200_000)
    with pytest.raises(ParseSecurityError, match="ratio"):
        inspect_archive(raw.getvalue())


def test_zip_high_entry_count_rejected() -> None:
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w") as archive:
        for index in range(6):
            archive.writestr(f"acme-{index}.txt", "x")
    with pytest.raises(ParseSecurityError, match="entry count"):
        inspect_archive(raw.getvalue(), SecurityLimits(max_archive_entries=5))


def test_zip_symlink_entry_rejected() -> None:
    raw = io.BytesIO()
    info = zipfile.ZipInfo("acme-link")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(raw, "w") as archive:
        archive.writestr(info, "target")
    with pytest.raises(ParseSecurityError, match="links"):
        inspect_archive(raw.getvalue())


def test_nested_archive_is_not_expanded() -> None:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("inner.txt", "x")
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as archive:
        archive.writestr("inner.zip", inner.getvalue())
    inspection = inspect_archive(outer.getvalue())
    assert inspection.entries == 1
