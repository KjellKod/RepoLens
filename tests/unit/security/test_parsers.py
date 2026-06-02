from __future__ import annotations

import io
import json
import stat
import tarfile
import threading
import zipfile

import pytest

from repolens.security.errors import ParseSecurityError
from repolens.security.limits import SecurityLimits
from repolens.security.parsers import (
    _deadline,
    inspect_archive,
    parse_json_bytes,
    parse_xml_bytes,
    parse_yaml_bytes,
)


def test_yaml_safe_payload_parses() -> None:
    assert parse_yaml_bytes(b"name: acme\nitems:\n  - one\n") == {"name": "acme", "items": ["one"]}


def test_yaml_alias_abuse_is_rejected() -> None:
    payload = "\n".join([f"k{i}: &a{i} value" for i in range(40)]).encode()
    with pytest.raises(ParseSecurityError, match="alias"):
        parse_yaml_bytes(payload)


def test_yaml_packed_alias_abuse_is_rejected() -> None:
    payload = b"""
a: &a ["lol", "lol", "lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
"""
    with pytest.raises(ParseSecurityError, match="alias"):
        parse_yaml_bytes(payload)


def test_malformed_yaml_raises_parse_security_error() -> None:
    with pytest.raises(ParseSecurityError, match="invalid YAML"):
        parse_yaml_bytes(b"acme: [1")


def test_deeply_nested_yaml_raises_parse_security_error() -> None:
    payload = b"a: " + b"[" * 2000 + b"0" + b"]" * 2000
    with pytest.raises(ParseSecurityError, match="YAML nesting"):
        parse_yaml_bytes(payload)


def test_xml_rejects_doctype_before_parse() -> None:
    with pytest.raises(ParseSecurityError, match="DOCTYPE"):
        parse_xml_bytes(b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///tmp/acme">]><x>&e;</x>')


def test_malformed_xml_raises_parse_security_error() -> None:
    with pytest.raises(ParseSecurityError, match="invalid XML"):
        parse_xml_bytes(b"<acme>")


def test_xml_depth_cap() -> None:
    payload = ("<a>" * 4 + "x" + "</a>" * 4).encode()
    with pytest.raises(ParseSecurityError, match="depth"):
        parse_xml_bytes(payload, SecurityLimits(max_structure_depth=2))


def test_json_depth_cap() -> None:
    payload = json.dumps({"a": {"b": {"c": {"d": "x"}}}}).encode()
    with pytest.raises(ParseSecurityError, match="depth"):
        parse_json_bytes(payload, SecurityLimits(max_structure_depth=2))


def test_malformed_json_raises_parse_security_error() -> None:
    with pytest.raises(ParseSecurityError, match="invalid JSON"):
        parse_json_bytes(b'{"acme":')


def test_parse_byte_cap_before_parser() -> None:
    with pytest.raises(ParseSecurityError, match="byte cap"):
        parse_json_bytes(b'{"acme": true}', SecurityLimits(max_parse_bytes=2))


def test_parse_timeout_contract_rejects_worker_thread_use() -> None:
    errors: list[Exception] = []

    def parse_in_worker() -> None:
        try:
            parse_json_bytes(b'{"acme": true}')
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=parse_in_worker)
    worker.start()
    worker.join()

    assert errors
    assert isinstance(errors[0], ParseSecurityError)
    assert "main-thread" in str(errors[0])


def test_zip_path_traversal_rejected() -> None:
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w") as archive:
        archive.writestr("../escape", "acme")
    with pytest.raises(ParseSecurityError, match="traversal"):
        inspect_archive(raw.getvalue())


def test_zip_backslash_path_traversal_rejected() -> None:
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w") as archive:
        archive.writestr("..\\escape", "acme")
    with pytest.raises(ParseSecurityError, match="traversal"):
        inspect_archive(raw.getvalue())


def test_tar_symlink_rejected() -> None:
    raw = io.BytesIO()
    info = tarfile.TarInfo("acme-link")
    info.type = tarfile.SYMTYPE
    info.linkname = "target"
    with tarfile.open(fileobj=raw, mode="w") as archive:
        archive.addfile(info)
    with pytest.raises(ParseSecurityError, match="links"):
        inspect_archive(raw.getvalue())


def test_deadline_restores_existing_sigalrm_timer(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[float, ...]] = []

    def fake_setitimer(which, *args):
        calls.append(args)
        if args == (2.0,):
            return (0.75, 0.25)
        return (0.0, 0.0)

    monkeypatch.setattr("signal.getsignal", lambda signum: "previous-handler")
    monkeypatch.setattr("signal.signal", lambda signum, handler: None)
    monkeypatch.setattr("signal.setitimer", fake_setitimer)

    with _deadline(2.0):
        pass

    assert calls == [(2.0,), (0.75, 0.25)]


def test_zip_symlink_rejected() -> None:
    raw = io.BytesIO()
    info = zipfile.ZipInfo("acme-link")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(raw, "w") as archive:
        archive.writestr(info, "target")
    with pytest.raises(ParseSecurityError, match="links"):
        inspect_archive(raw.getvalue())
