import json
from typing import Any

import pytest
from pytest_mock import MockerFixture

import DeviceSecurityThreatFrameworkMappings as framework_mappings


@pytest.mark.parametrize("encoding_count", [0, 1, 2, 3])
def test_normalizes_encoded_mappings(encoding_count: int) -> None:
    mapping = {"framework": "Enterprise", "techniqueId": "T1059", "technique": "Command Execution"}
    value: Any = {"mitre_mappings": [mapping]}
    for _ in range(encoding_count):
        value = json.dumps(value)
    assert framework_mappings.normalize_mappings(value) == [mapping]


def test_normalizes_nested_and_individually_encoded_mappings() -> None:
    mapping = {"framework": "ICS", "techniqueId": "T0807", "technique": "Command-Line Interface"}
    value = [None, "invalid JSON", {"unrelated": "ignored"}, [json.dumps(mapping)]]
    assert framework_mappings.normalize_mappings(value) == [mapping]


def test_normalizes_nested_references() -> None:
    value = {"iec_62443_references": [" IEC 62443-3-3 SR 1.1 ", [json.dumps("SR 2.1")], None, "", {"other": "ignored"}]}
    assert framework_mappings.normalize_references(value) == ["IEC 62443-3-3 SR 1.1", "SR 2.1"]


@pytest.mark.parametrize("incidents", [[], [{}], [{"CustomFields": None}], [{"CustomFields": "invalid"}]])
def test_missing_incident_fields(mocker: MockerFixture, incidents: list[dict]) -> None:
    mocker.patch.object(framework_mappings.demisto, "incidents", return_value=incidents)
    assert framework_mappings.get_event_data() == {"mitre_mappings": [], "iec_62443_references": []}


def test_reads_mapped_incident_fields(mocker: MockerFixture) -> None:
    mapping = {"framework": "ICS", "techniqueId": "T0807", "technique": "Command-Line Interface"}
    mocker.patch.object(
        framework_mappings.demisto,
        "incidents",
        return_value=[
            {
                "CustomFields": {
                    "devicesecuritymitremappingsraw": json.dumps([mapping]),
                    "devicesecurityiecreferences": json.dumps(["IEC 62443-3-3 SR 1.1"]),
                }
            }
        ],
    )
    assert framework_mappings.get_event_data() == {
        "mitre_mappings": [mapping],
        "iec_62443_references": ["IEC 62443-3-3 SR 1.1"],
    }


def test_technique_table_filters_deduplicates_and_escapes() -> None:
    mapping = {"framework": " enterprise ", "techniqueId": "T1059", "technique": "Command|Execution\nExample"}
    mappings = [mapping, mapping.copy(), {"framework": "ICS", "techniqueId": "T0807"}, {"framework": "Enterprise"}]
    lines = framework_mappings.create_technique_table("Enterprise", "Enterprise", mappings)
    assert lines == [
        "#### Enterprise",
        "| Technique ID | Technique |",
        "| --- | --- |",
        "| T1059 | Command\\|Execution Example |",
        "| N/A | N/A |",
    ]


def test_iec_section_shortens_and_deduplicates() -> None:
    lines = framework_mappings.create_iec_section(["IEC 62443-3-3 SR 1.1", "SR 1.1", " SR 2.1 "])
    assert lines == ["#### IEC 62443 Security Standards", "SR 1.1 · SR 2.1"]


@pytest.mark.parametrize("event_data", [{}, {"mitre_mappings": None, "iec_62443_references": None}])
def test_empty_output_has_all_sections(event_data: dict) -> None:
    output = framework_mappings.create_readable_output(event_data)
    assert output == (
        "#### MITRE ATT&CK Enterprise Techniques\n| Technique ID | Technique |\n| --- | --- |\n| N/A | N/A |\n\n"
        "#### MITRE ATT&CK ICS Techniques\n| Technique ID | Technique |\n| --- | --- |\n| N/A | N/A |\n\n"
        "#### IEC 62443 Security Standards\nN/A"
    )


def test_main_returns_dynamic_section(mocker: MockerFixture) -> None:
    mocker.patch.object(framework_mappings.demisto, "incidents", return_value=[])
    results = mocker.patch.object(framework_mappings, "return_results")
    framework_mappings.main()
    result = results.call_args.args[0]
    assert isinstance(result, framework_mappings.CommandResults)
    assert result.readable_output == framework_mappings.create_readable_output({})


def test_main_reports_read_failure(mocker: MockerFixture) -> None:
    exception = ValueError("Incident unavailable")
    mocker.patch.object(framework_mappings.demisto, "incidents", side_effect=exception)
    log_error = mocker.patch.object(framework_mappings.demisto, "error")
    error = mocker.patch.object(framework_mappings, "return_error")
    results = mocker.patch.object(framework_mappings, "return_results")
    framework_mappings.main()
    error.assert_called_once_with("Failed to render Device Security framework mappings: Incident unavailable", exception)
    log_error.assert_called_once()
    logged_traceback = log_error.call_args.args[0]
    assert "Traceback (most recent call last)" in logged_traceback
    assert "get_event_data" in logged_traceback
    assert "ValueError: Incident unavailable" in logged_traceback
    results.assert_not_called()
