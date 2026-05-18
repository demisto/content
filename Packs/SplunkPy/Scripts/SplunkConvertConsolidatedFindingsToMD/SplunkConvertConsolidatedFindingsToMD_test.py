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
        - A Markdown table titled "Splunk Consolidated Findings" is produced
          with header keys transformed by ``string_to_table_header`` and the
          values rendered in the row.
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
    # Table title
    assert "### Splunk Consolidated Findings" in output
    # Headers are produced via string_to_table_header (Title Case, spaces)
    assert "Search Name" in output
    assert "Queue Id" in output
    assert "Threat Category" in output
    assert "Dest" in output
    # Scalar values present
    assert "None" in output
    assert "threatlist" in output
    # Array values rendered (comma-joined by tableToMarkdown)
    assert "Suspicious Login" in output
    assert "Brute Force" in output
    assert "host-a" in output
    assert "host-b" in output


def test_render_when_payload_already_a_dict(mocker):
    """
    Given:
        - The custom field already contains a dict (not a JSON string).
    When:
        - main() is invoked.
    Then:
        - The script handles the dict gracefully and renders the table.
    """
    payload = {"queue_id": "None", "record_weight": "60"}
    incident = {"CustomFields": {"splunkconsolidatedfindings": payload}}
    mocker.patch("demistomock.incident", return_value=incident)

    result = SplunkConvertConsolidatedFindingsToMD.main()

    output = result.readable_output
    assert "### Splunk Consolidated Findings" in output
    assert "Queue Id" in output
    assert "Record Weight" in output
    assert "60" in output


def test_render_with_arrays_of_different_lengths(mocker):
    """
    Given:
        - A payload where arrays have different lengths.
    When:
        - main() is invoked.
    Then:
        - The table renders with each key as a header and the array values in
          the corresponding cell.
    """
    payload = {"tags": ["malware"], "ids": ["a", "b", "c"]}
    incident = {"CustomFields": {"splunkconsolidatedfindings": json.dumps(payload)}}
    mocker.patch("demistomock.incident", return_value=incident)

    result = SplunkConvertConsolidatedFindingsToMD.main()

    output = result.readable_output
    assert "### Splunk Consolidated Findings" in output
    assert "Tags" in output
    assert "malware" in output
    assert "Ids" in output
    assert "a" in output
    assert "b" in output
    assert "c" in output


def test_render_when_field_is_empty(mocker):
    """
    Given:
        - The consolidated findings field is empty / missing on the incident.
    When:
        - main() is invoked.
    Then:
        - The script does not raise and returns a CommandResults object whose
          readable output still contains the table title.
    """
    incident = {"CustomFields": {}}
    mocker.patch("demistomock.incident", return_value=incident)

    result = SplunkConvertConsolidatedFindingsToMD.main()

    assert "Splunk Consolidated Findings" in result.readable_output


def test_render_when_string_is_invalid_json(mocker):
    """
    Given:
        - The custom field contains a malformed JSON string.
    When:
        - main() is invoked.
    Then:
        - The script does not raise; an empty table titled "Splunk Consolidated
          Findings" is rendered.
    """
    incident = {"CustomFields": {"splunkconsolidatedfindings": "{not-json"}}
    mocker.patch("demistomock.incident", return_value=incident)

    result = SplunkConvertConsolidatedFindingsToMD.main()

    assert "Splunk Consolidated Findings" in result.readable_output


def test_coerce_to_dict_variants():
    """
    Given:
        - A variety of raw input values that may appear in the custom field.
    When:
        - _coerce_to_dict is called on each.
    Then:
        - Dicts pass through, valid JSON strings parse to dicts, and any other
          value (empty, malformed, non-dict JSON, unsupported types) returns
          an empty dict.
    """
    coerce = SplunkConvertConsolidatedFindingsToMD._coerce_to_dict
    assert coerce({"a": 1}) == {"a": 1}
    assert coerce('{"a": 1}') == {"a": 1}
    assert coerce("") == {}
    assert coerce(None) == {}
    assert coerce("{not-json") == {}
    assert coerce("[1, 2, 3]") == {}
    assert coerce(123) == {}
