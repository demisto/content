import json

import SplunkConvertConsolidatedFindingsToMD


def test_render_with_arrays_and_scalars(mocker):
    """
    Given:
        - A `consolidated_findings` JSON string containing both scalar fields
          and array fields.
    When:
        - main() is invoked and the script renders the Markdown output.
    Then:
        - A single flat Field/Value Markdown table is produced where each
          top-level key is one row and array values are joined into a single
          comma-separated cell.
    """
    payload = {
        "search_name": ["Suspicious Login", "Brute Force"],
        "dest": ["host-a", "host-b"],
        "queue_id": "None",
        "threat_category": "threatlist",
    }
    incident = {"CustomFields": {"splunkconsolidatedfindings": json.dumps(payload)}}
    mocker.patch("demistomock.incident", return_value=incident)

    result = SplunkConvertConsolidatedFindingsToMD.main()

    output = result.readable_output
    # Single table title
    assert "### Splunk Consolidated Findings" in output
    # Field/Value column headers
    assert "Field" in output and "Value" in output
    # Scalar rows present
    assert "queue_id" in output and "None" in output
    assert "threat_category" in output and "threatlist" in output
    # Array values joined in a single cell
    assert "Suspicious Login, Brute Force" in output
    assert "host-a, host-b" in output
    # Insertion order preserved (search_name appears before queue_id)
    assert output.index("search_name") < output.index("queue_id")


def test_render_when_payload_already_a_dict(mocker):
    """
    Given:
        - The custom field already contains a dict (not a JSON string).
    When:
        - main() is invoked.
    Then:
        - The script handles the dict gracefully and renders the flat table.
    """
    payload = {"queue_id": "None", "record_weight": "60"}
    incident = {"CustomFields": {"splunkconsolidatedfindings": payload}}
    mocker.patch("demistomock.incident", return_value=incident)

    result = SplunkConvertConsolidatedFindingsToMD.main()

    output = result.readable_output
    assert "### Splunk Consolidated Findings" in output
    assert "queue_id" in output
    assert "record_weight" in output
    assert "60" in output


def test_render_with_arrays_of_different_lengths(mocker):
    """
    Given:
        - A payload where arrays have different lengths.
    When:
        - main() is invoked.
    Then:
        - Each array becomes a single row with comma-joined values, all in the
          same flat Field/Value table.
    """
    payload = {"tags": ["malware"], "ids": ["a", "b", "c"]}
    incident = {"CustomFields": {"splunkconsolidatedfindings": json.dumps(payload)}}
    mocker.patch("demistomock.incident", return_value=incident)

    result = SplunkConvertConsolidatedFindingsToMD.main()

    output = result.readable_output
    assert "### Splunk Consolidated Findings" in output
    assert "tags" in output and "malware" in output
    assert "ids" in output and "a, b, c" in output


def test_render_when_field_is_empty(mocker):
    """
    Given:
        - The consolidated findings field is empty / missing on the incident.
    When:
        - main() is invoked.
    Then:
        - A friendly placeholder message is rendered instead of an error.
    """
    incident = {"CustomFields": {}}
    mocker.patch("demistomock.incident", return_value=incident)

    result = SplunkConvertConsolidatedFindingsToMD.main()

    assert "_No consolidated findings data available._" in result.readable_output


def test_render_when_string_is_invalid_json(mocker):
    """
    Given:
        - The custom field contains a malformed JSON string.
    When:
        - main() is invoked.
    Then:
        - The script does not raise; the empty-payload fallback message is shown.
    """
    incident = {"CustomFields": {"splunkconsolidatedfindings": "{not-json"}}
    mocker.patch("demistomock.incident", return_value=incident)

    result = SplunkConvertConsolidatedFindingsToMD.main()

    assert "_No consolidated findings data available._" in result.readable_output


def test_format_value_handles_empty_and_complex_types():
    """
    Given:
        - Various edge-case values: None, "", [], {}, dict, list of mixed.
    When:
        - _format_value is called on each.
    Then:
        - Empties render as "-", lists join with ", ", dicts JSON-serialize.
    """
    fmt = SplunkConvertConsolidatedFindingsToMD._format_value
    assert fmt(None) == "-"
    assert fmt("") == "-"
    assert fmt([]) == "-"
    assert fmt(["a", "b"]) == "a, b"
    assert fmt({"k": "v"}) == '{"k": "v"}'
    assert fmt(42) == "42"
