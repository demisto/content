from Utils.github_workflow_scripts.parse_junit_per_pack import (
    parse_pack_name,
    parse_xml,
    PackNameParseError,
)
from pathlib import Path
import pytest


def test_parse_xml(tmp_path):
    """
    Given   a junit.xml file
    When    calling parse_xml
    Then    make sure the output is correct
    """
    (xml_path := Path(tmp_path, "foo.xml")).write_text(
        "<?xml version='1.0' encoding='UTF-8'?>"
        '<testsuites><testsuite name="pytest" errors="0" failures="0" skipped="0" tests="3" time="2.158" timestamp="2024-02-20T15:25:31.306846" hostname="0d480f757bd2">'  # noqa: E501
        '<testcase classname="Packs.ipinfo.Integrations.ipinfo_v2.ipinfo_v2_test" name="test_ipinfo_ip_command" time="0.010"/>'
        '<testcase classname="Packs.ipinfo.Integrations.ipinfo_v2.ipinfo_v2_test" name="test_ipinfo_nultiple_ips_command" time="0.008"/>'  # noqa: E501
        '<testcase classname="Packs.ipinfo.Integrations.ipinfo_v2.ipinfo_v2_test" name="test_check_columns_exists" time="0.005"/></testsuite>'  # noqa: E501
        '<testsuite name="pytest" errors="0" failures="0" skipped="0" tests="3" time="1.967" timestamp="2024-02-20T15:25:25.799231" hostname="d190b19a16e8">'  # noqa: E501
        '<testcase classname="Packs.qradar.Integrations.qradar.qradar_test" name="test_ipinfo_ip_command" time="0.210"/>'
        '<testcase classname="Packs.ipinfo.Integrations.qradar.qradar_test" name="test_ipinfo_nultiple_ips_command" time="0.007"/>'  # noqa: E501
        '<testcase classname="Packs.ipinfo.Integrations.qradar.qradar_test" name="test_check_columns_exists" time="0.005"/>'
        "</testsuite></testsuites>"
    )
    result = parse_xml(xml_path)
    assert tuple(result.keys())[0] == "qradar"  # test sort
    assert parse_xml(xml_path) == {"ipinfo": 0.035, "qradar": 0.21}


@pytest.mark.parametrize(
    "value,pack_name",
    (
        ("Packs.pack1.foo", "pack1"),
        ("Packs.pack1.foo.bar", "pack1"),
        ("Packs.pack2.foo.bar.baz", "pack2"),
    ),
)
def test_parse_pack_name(value: str, pack_name: str):
    """
    Given   a string representing a valid junit class_name of a content pack
    When    calling parse_pack_name
    Then    make sure the output is correct
    """
    assert parse_pack_name(value) == pack_name


@pytest.mark.parametrize(
    "value",
    ("", " ", "foo", "Packs.", "Tests.pack1", "Utils.pack1", "Packs.Pack", "Packs.."),
)
def test_parse_pack_name_error(value: str):
    """
    Given   a string representing an INvalid junit class_name of a content pack
    When    calling parse_pack_name
    Then    make sure an appropriate exception is raised
    """
    with pytest.raises(
        PackNameParseError,
        match=f"Cannot parse pack name out of {value}, expected Packs.<pack_name>.more_parts",
    ):
        parse_pack_name(value)
