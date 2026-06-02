from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from repolens.security.parsers import (
    UnsafeArchiveError,
    load_yaml_safe,
    parse_xml_safe,
    validate_archive_limits,
)


pytestmark = [pytest.mark.offline, pytest.mark.security, pytest.mark.canary]


def test_x2_parse_yaml_safe_load() -> None:
    assert load_yaml_safe("name: fixture-alpha\nversion: 1\n") == {
        "name": "fixture-alpha",
        "version": 1,
    }

    with pytest.raises(ValueError, match="unsafe yaml"):
        load_yaml_safe("danger: !!python/object/apply:os.system ['id']")


def test_x2_parse_xml_rejects_doctype() -> None:
    with pytest.raises(ValueError, match="unsafe xml"):
        parse_xml_safe("<!DOCTYPE data [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><data>&xxe;</data>")
    with pytest.raises(ValueError, match="unsafe xml"):
        parse_xml_safe(" " * 300 + "<!DOCTYPE data><data />")

    assert parse_xml_safe("<project><name>fixture-alpha</name></project>").tag == "project"


def test_x2_parse_zip_rejects_high_ratio() -> None:
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("payload.txt", "0" * 4096)

    with pytest.raises(UnsafeArchiveError, match="compression ratio"):
        validate_archive_limits(buffer.getvalue(), max_compression_ratio=2.0)
