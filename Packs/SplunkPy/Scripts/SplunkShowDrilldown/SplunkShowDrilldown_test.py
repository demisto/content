import json
import pytest

import SplunkShowDrilldown


def test_incident_with_empty_custom_fields(mocker):
    """
    Given:
        incident without CustomFields
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that the output returned is correct
    """
    incident = {"CustomFields": {}}
    mocker.patch("demistomock.incident", return_value=incident)
    res = SplunkShowDrilldown.main()
    assert res.get("Contents") == (
        "#### Drilldown Configuration Status\n\n"
        "⚠️ **Drilldown enrichment is not configured for this integration instance.**\n\n"
        "Enrichment is not enabled, so drilldown results are not available.\n\n"
        "**To enable drilldown enrichment:**\n"
        "1. Go to the integration instance settings\n"
        "2. In the 'Enrichment Types' parameter, select 'Drilldown'\n"
        "3. Save the configuration and fetch new incidents\n\n"
    )


def test_incident_not_notabledrilldown(mocker):
    """
    Given:
        incident without notabledrilldown
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that the output returned is correct
    """
    incident = {"CustomFields": {"notabledrilldown": {}}}
    mocker.patch("demistomock.incident", return_value=incident)
    res = SplunkShowDrilldown.main()
    assert res.get("Contents") == (
        "#### Drilldown Configuration Status\n\n"
        "⚠️ **Drilldown enrichment is not configured for this integration instance.**\n\n"
        "Enrichment is not enabled, so drilldown results are not available.\n\n"
        "**To enable drilldown enrichment:**\n"
        "1. Go to the integration instance settings\n"
        "2. In the 'Enrichment Types' parameter, select 'Drilldown'\n"
        "3. Save the configuration and fetch new incidents\n\n"
    )


def test_incident_not_successful(mocker):
    """
    Given:
        incident with successfuldrilldownenrichment == false
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that the output returned is correct
    """
    incident = {"labels": [{"type": "successful_drilldown_enrichment", "value": "false"}]}
    mocker.patch("demistomock.incident", return_value=incident)
    res = SplunkShowDrilldown.main()
    assert res.get("Contents") == (
        "#### Drilldown Enrichment Not Successful\n\n"
        "**Error:** The drilldown enrichment did not complete successfully. "
        "This could be due to query parsing issues, no results found, or other errors.\n\n"
        "*No drilldown searches data found.*"
    )


def test_json_loads_fails(mocker):
    """
    Given:
        incident with CustomFields that can't be loaded by JSON
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that the output returned is correct
    """
    incident = {"labels": [{"type": "Drilldown", "value": {"not json"}}]}
    mocker.patch("demistomock.incident", return_value=incident)
    res = SplunkShowDrilldown.main()
    assert res.get("Contents") == (
        "#### Drilldown Searches (Invalid JSON)\n\n"
        "⚠️ **Note:** The drilldown_searches data received from Splunk contains invalid JSON formatting.\n\n"
        "The data from Splunk has JSON syntax issues (such as unescaped quotes or malformed structure).\n\n"
        "**Error Details:** JSON Parsing Error: the JSON object must be str, bytes or bytearray, not set\n\n"
        "**Raw Data from Splunk:**\n"
        "```\n"
        "{'not json'}\n"
        "```\n\n"
        "**Recommendation:** Check the drilldown configuration in Splunk to ensure it generates valid JSON."
    )


def test_incident_single_drilldown_search_results(mocker):
    """
    Given:
        incident with results of a single drilldown search
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that the output returned is correct
    """
    incident = {
        "labels": [
            {"type": "successful_drilldown_enrichment", "value": "true"},
            {
                "type": "Drilldown",
                "value": """[
                    {"_bkt": "main~Test1",
                     "_cd": "524:1111111",
                     "_indextime": "1715859867",
                     "_raw": "2024-05-16 11:26:32,Virus found,IP Address: 1.1.1.1,Computer name: Test1",
                     "_serial": "0",
                     "_si": [
                         "ip-1-1-1-1",
                         "main"
                         ],
                     "_sourcetype": "test1",
                     "_time": "2024-05-16T11:26:32.000+00:00",
                     "category": "Other",
                     "dest": "Test_dest1",
                     "signature": "test_signature1"
                     },
                    {"_bkt": "main~Test2",
                     "_cd": "524:2222222",
                     "_indextime": "1715859867",
                     "_raw": "2024-05-16 11:26:32,Virus found,IP Address: 2.2.2.2,Computer name: Test2",
                     "_serial": "0",
                     "_si": [
                         "ip-2-2-2-2",
                         "main"
                         ],
                     "_sourcetype": "test2",
                     "_time": "2024-05-16T11:26:32.000+00:00",
                     "category": "Other",
                     "dest": "Test_dest2",
                     "signature": "test_signature2"
                     }
                    ]""",
            },
        ]
    }
    mocker.patch("demistomock.incident", return_value=incident)
    res = SplunkShowDrilldown.main()
    contents: str = res.get("Contents")
    # Verify that all results are in the markdown table
    assert ("main~Test1" and "test_signature1" and "main~Test2" and "test_signature2") in contents


def test_incident_multiple_drilldown_search_results(mocker):
    """
    Given:
        incident with results of multiple drilldown searches
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that the output returned is correct
    """
    drilldown = [
        {
            "query_name": "query_name1",
            "query_search": "query_search1",
            "enrichment_status": "Enrichment successfully handled",
            "query_results": [
                {
                    "_bkt": "main~Test1",
                    "_cd": "524:1111111",
                    "_indextime": "1715859867",
                    "_raw": "2024-05-16 11:26:32,Virus found,IP Address: 1.1.1.1,Computer name: Test1",
                    "_serial": "0",
                    "_si": ["ip-1-1-1-1", "main"],
                    "_sourcetype": "test1",
                    "_time": "2024-05-16T11:26:32.000+00:00",
                    "category": "Other",
                    "dest": "Test_dest1",
                    "signature": "test_signature1",
                },
                {
                    "_bkt": "main~Test2",
                    "_cd": "524:2222222",
                    "_indextime": "1715859867",
                    "_raw": "2024-05-16 11:26:32,Virus found,IP Address: 2.2.2.2,Computer name: Test2",
                    "_serial": "0",
                    "_si": ["ip-2-2-2-2", "main"],
                    "_sourcetype": "test2",
                    "_time": "2024-05-16T11:26:32.000+00:00",
                    "category": "Other",
                    "dest": "Test_dest2",
                    "signature": "test_signature2",
                },
            ],
        },
        {
            "query_name": "query_name2",
            "query_search": "query_search2",
            "enrichment_status": "Enrichment successfully handled",
            "query_results": [
                {
                    "_bkt": "main~Test3",
                    "_cd": "524:1111111",
                    "_indextime": "1715859867",
                    "_raw": "2024-05-16 11:26:32,Virus found,IP Address: 1.1.1.1,Computer name: Test1",
                    "_serial": "0",
                    "_si": ["ip-1-1-1-1", "main"],
                    "_sourcetype": "test1",
                    "_time": "2024-05-16T11:26:32.000+00:00",
                    "category": "Other",
                    "dest": "Test_dest1",
                    "signature": "test_signature3",
                },
                {
                    "_bkt": "main~Test4",
                    "_cd": "524:2222222",
                    "_indextime": "1715859867",
                    "_raw": "2024-05-16 11:26:32,Virus found,IP Address: 2.2.2.2,Computer name: Test2",
                    "_serial": "0",
                    "_si": ["ip-2-2-2-2", "main"],
                    "_sourcetype": "test2",
                    "_time": "2024-05-16T11:26:32.000+00:00",
                    "category": "Other",
                    "dest": "Test_dest2",
                    "signature": "test_signature4",
                },
            ],
        },
    ]
    str_drilldown = json.dumps(drilldown)
    incident = {
        "labels": [{"type": "successful_drilldown_enrichment", "value": "true"}, {"type": "Drilldown", "value": str_drilldown}]
    }
    mocker.patch("demistomock.incident", return_value=incident)
    res = SplunkShowDrilldown.main()
    contents: str = res.get("Contents")
    # Verify that all results are in the markdown table
    assert ("main~Test1" and "test_signature1" and "main~Test2" and "test_signature2") in contents
    assert ("query_name1" and "query_search1" and "query_name2" and "query_search2") in contents
    assert ("main~Test3" and "test_signature3" and "main~Test4" and "test_signature4") in contents
    assert ("Drilldown Searches Results") in contents


def test_incident_multiple_drilldown_search_no_results(mocker):
    """
    Given:
        incident with results of multiple drilldown searches, one of the drilldown searches returned no results
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that the output returned is correct
    """
    drilldown = [
        {
            "query_name": "query_name1",
            "query_search": "query_search1",
            "enrichment_status": "Enrichment successfully handled",
            "query_results": [
                {
                    "_bkt": "main~Test1",
                    "_cd": "524:1111111",
                    "_indextime": "1715859867",
                    "_raw": "2024-05-16 11:26:32,Virus found,IP Address: 1.1.1.1,Computer name: Test1",
                    "_serial": "0",
                    "_si": ["ip-1-1-1-1", "main"],
                    "_sourcetype": "test1",
                    "_time": "2024-05-16T11:26:32.000+00:00",
                    "category": "Other",
                    "dest": "Test_dest1",
                    "signature": "test_signature1",
                },
                {
                    "_bkt": "main~Test2",
                    "_cd": "524:2222222",
                    "_indextime": "1715859867",
                    "_raw": "2024-05-16 11:26:32,Virus found,IP Address: 2.2.2.2,Computer name: Test2",
                    "_serial": "0",
                    "_si": ["ip-2-2-2-2", "main"],
                    "_sourcetype": "test2",
                    "_time": "2024-05-16T11:26:32.000+00:00",
                    "category": "Other",
                    "dest": "Test_dest2",
                    "signature": "test_signature2",
                },
            ],
        },
        {
            "query_name": "query_name2",
            "query_search": "query_search2",
            "enrichment_status": "Enrichment successfully handled",
            "query_results": [],
        },
    ]
    str_drilldown = json.dumps(drilldown)
    incident = {
        "labels": [{"type": "successful_drilldown_enrichment", "value": "true"}, {"type": "Drilldown", "value": str_drilldown}]
    }
    mocker.patch("demistomock.incident", return_value=incident)
    res = SplunkShowDrilldown.main()
    contents: str = res.get("Contents")
    # Verify that all results are in the markdown table
    assert ("main~Test1" and "test_signature1" and "main~Test2" and "test_signature2") in contents
    assert ("Drilldown Searches Results") in contents
    assert ("query_name1" and "query_search1" and "query_name2" and "query_search2") in contents
    assert ("No results found for drilldown search") in contents


def test_incident_multiple_drilldown_search_enrichment_failed(mocker):
    """
    Given:
        incident with results of multiple drilldown searches, one of the drilldown searches enrichment was failed
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that the output returned is correct
    """
    drilldown = [
        {
            "query_name": "query_name1",
            "query_search": "query_search1",
            "enrichment_status": "Enrichment successfully handled",
            "query_results": [
                {
                    "_bkt": "main~Test1",
                    "_cd": "524:1111111",
                    "_indextime": "1715859867",
                    "_raw": "2024-05-16 11:26:32,Virus found,IP Address: 1.1.1.1,Computer name: Test1",
                    "_serial": "0",
                    "_si": ["ip-1-1-1-1", "main"],
                    "_sourcetype": "test1",
                    "_time": "2024-05-16T11:26:32.000+00:00",
                    "category": "Other",
                    "dest": "Test_dest1",
                    "signature": "test_signature1",
                },
                {
                    "_bkt": "main~Test2",
                    "_cd": "524:2222222",
                    "_indextime": "1715859867",
                    "_raw": "2024-05-16 11:26:32,Virus found,IP Address: 2.2.2.2,Computer name: Test2",
                    "_serial": "0",
                    "_si": ["ip-2-2-2-2", "main"],
                    "_sourcetype": "test2",
                    "_time": "2024-05-16T11:26:32.000+00:00",
                    "category": "Other",
                    "dest": "Test_dest2",
                    "signature": "test_signature2",
                },
            ],
        },
        {
            "query_name": "query_name2",
            "query_search": "query_search2",
            "enrichment_status": "Enrichment failed",
            "query_results": [],
        },
    ]
    str_drilldown = json.dumps(drilldown)
    incident = {
        "labels": [{"type": "successful_drilldown_enrichment", "value": "true"}, {"type": "Drilldown", "value": str_drilldown}]
    }
    mocker.patch("demistomock.incident", return_value=incident)
    res = SplunkShowDrilldown.main()
    contents: str = res.get("Contents")
    # Verify that all results are in the markdown table
    assert ("main~Test1" and "test_signature1" and "main~Test2" and "test_signature2") in contents
    assert ("Drilldown Searches Results") in contents
    assert ("query_name1" and "query_search1" and "query_name2" and "query_search2") in contents
    assert ("Drilldown enrichment failed.") in contents


def test_format_raw_data_with_string():
    """
    Given:
        A JSON-like string with compact formatting
    When:
        Calling format_raw_data
    Then:
        Returns formatted string with newlines
    """
    data = '[{"key":"value"},{"key2":"value2"}]'
    result = SplunkShowDrilldown.format_raw_data(data)
    assert "[\n{" in result
    assert "},\n{" in result
    assert "}\n]" in result


def test_format_raw_data_with_non_string():
    """
    Given:
        A non-string input (e.g., dict)
    When:
        Calling format_raw_data
    Then:
        Returns string representation
    """
    data = {"key": "value"}
    result = SplunkShowDrilldown.format_raw_data(data)
    assert result == "{'key': 'value'}"


def test_display_error_with_raw_data_present():
    """
    Given:
        Error title, message, and raw data
    When:
        Calling display_error_with_raw_data
    Then:
        Returns properly formatted error with raw data
    """
    result = SplunkShowDrilldown.display_error_with_raw_data("Test Error", "Error message", '[{"test":"data"}]')
    assert "#### Test Error" in result["Contents"]
    assert "**Error:** Error message" in result["Contents"]
    assert "**Raw Drilldown Searches Data:**" in result["Contents"]
    assert "[\n{" in result["Contents"]


def test_display_error_with_no_raw_data():
    """
    Given:
        Error title, message, but no raw data
    When:
        Calling display_error_with_raw_data
    Then:
        Returns error message without raw data section
    """
    result = SplunkShowDrilldown.display_error_with_raw_data("Test Error", "Error message", "")
    assert "#### Test Error" in result["Contents"]
    assert "**Error:** Error message" in result["Contents"]
    assert "*No drilldown searches data found.*" in result["Contents"]


def test_display_json_parsing_error_with_raw_data():
    """
    Given:
        JSON parsing error with raw data
    When:
        Calling display_json_parsing_error
    Then:
        Returns detailed JSON error message with raw data
    """
    result = SplunkShowDrilldown.display_json_parsing_error("JSON Error", "Invalid JSON syntax", '{"invalid": json}')
    assert "#### JSON Error" in result["Contents"]
    assert "⚠️ **Note:** The drilldown_searches data received from Splunk contains invalid JSON formatting" in result["Contents"]
    assert "**Error Details:** Invalid JSON syntax" in result["Contents"]
    assert "**Raw Data from Splunk:**" in result["Contents"]
    assert "**Recommendation:** Check the drilldown configuration in Splunk" in result["Contents"]


def test_display_json_parsing_error_without_raw_data():
    """
    Given:
        JSON parsing error without raw data
    When:
        Calling display_json_parsing_error
    Then:
        Returns error message without raw data section
    """
    result = SplunkShowDrilldown.display_json_parsing_error("JSON Error", "Invalid JSON syntax", "")
    assert "#### JSON Error" in result["Contents"]
    assert "*No drilldown searches data found.*" in result["Contents"]


def test_incident_is_none(mocker):
    """
    Given:
        demisto.incident() returns None
    When:
        Calling main()
    Then:
        Raises ValueError
    """
    mocker.patch("demistomock.incident", return_value=None)
    with pytest.raises(ValueError, match="Error - demisto.incident\\(\\) expected to return current incident"):
        SplunkShowDrilldown.main()


def test_incident_with_splunkdrilldown_field(mocker):
    """
    Given:
        incident with splunkdrilldown custom field instead of notabledrilldown
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that the output uses splunkdrilldown field
    """
    drilldown_config = [{"name": "test_query", "search": "index=main"}]
    incident = {"CustomFields": {"splunkdrilldown": json.dumps(drilldown_config)}, "labels": []}
    mocker.patch("demistomock.incident", return_value=incident)
    res = SplunkShowDrilldown.main()
    contents = res.get("Contents")
    assert "Drilldown Configuration Status" in contents
    assert "test_query" in contents


def test_incident_enrichment_not_configured_with_valid_json_config(mocker):
    """
    Given:
        incident without enrichment configured but with valid JSON drilldown configuration
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that raw configuration is displayed as table
    """
    drilldown_config = [{"name": "test_query", "search": "index=main"}]
    incident = {"CustomFields": {"splunkdrilldown": json.dumps(drilldown_config)}, "labels": []}
    mocker.patch("demistomock.incident", return_value=incident)
    res = SplunkShowDrilldown.main()
    contents = res.get("Contents")
    assert "Drilldown Configuration Status" in contents
    assert "Raw Drilldown Searches Configuration (from Splunk)" in contents
    assert "test_query" in contents


def test_incident_enrichment_not_configured_with_invalid_json_config(mocker):
    """
    Given:
        incident without enrichment configured and invalid JSON drilldown configuration
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that error is shown with raw data
    """
    incident = {"CustomFields": {"splunkdrilldown": '{"invalid": json}'}, "labels": []}
    mocker.patch("demistomock.incident", return_value=incident)
    res = SplunkShowDrilldown.main()
    contents = res.get("Contents")
    assert "Drilldown Configuration Status" in contents
    assert "Raw Drilldown Searches Data (Failed to Parse)" in contents
    assert "Failed to parse the raw drilldown configuration" in contents


def test_incident_enrichment_configured_no_results_with_valid_json(mocker):
    """
    Given:
        incident with enrichment configured but no results, with valid JSON configuration
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that configuration is displayed as table
    """
    drilldown_config = [{"name": "test_query", "search": "index=main"}]
    incident = {
        "CustomFields": {"splunkdrilldown": json.dumps(drilldown_config)},
        "labels": [{"type": "successful_drilldown_enrichment", "value": "true"}],
    }
    mocker.patch("demistomock.incident", return_value=incident)
    res = SplunkShowDrilldown.main()
    contents = res.get("Contents")
    assert "Drilldown Enrichment Results" in contents
    assert "Drilldown enrichment results not found" in contents
    assert "Drilldown Searches Configuration" in contents
    assert "test_query" in contents


def test_incident_enrichment_configured_no_results_with_invalid_json(mocker):
    """
    Given:
        incident with enrichment configured but no results, with invalid JSON configuration
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that error is shown with raw data
    """
    incident = {
        "CustomFields": {"splunkdrilldown": '{"invalid": json}'},
        "labels": [{"type": "successful_drilldown_enrichment", "value": "true"}],
    }
    mocker.patch("demistomock.incident", return_value=incident)
    res = SplunkShowDrilldown.main()
    contents = res.get("Contents")
    assert "Drilldown Enrichment Results" in contents
    assert "Raw Drilldown Searches Data (Failed to Parse)" in contents
    assert "Failed to parse the drilldown configuration" in contents


def test_incident_enrichment_configured_no_results_no_config(mocker):
    """
    Given:
        incident with enrichment configured but no results and no configuration data
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that appropriate message is shown
    """
    incident = {"CustomFields": {}, "labels": [{"type": "successful_drilldown_enrichment", "value": "true"}]}
    mocker.patch("demistomock.incident", return_value=incident)
    res = SplunkShowDrilldown.main()
    contents = res.get("Contents")
    assert "Drilldown Enrichment Results" in contents
    assert "*No drilldown searches configuration data found.*" in contents


def test_incident_drilldown_results_as_dict(mocker):
    """
    Given:
        incident with drilldown results as a dict (not a list)
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that the dict is converted to table
    """
    drilldown_dict = {"key1": "value1", "key2": "value2"}
    incident = {
        "labels": [
            {"type": "successful_drilldown_enrichment", "value": "true"},
            {"type": "Drilldown", "value": json.dumps(drilldown_dict)},
        ]
    }
    mocker.patch("demistomock.incident", return_value=incident)
    res = SplunkShowDrilldown.main()
    contents = res.get("Contents")
    # Should create a table from the dict
    assert "key1" in contents or "value1" in contents


def test_main_exception_handling(mocker):
    """
    Given:
        An exception occurs during main execution
    When:
        Running the script
    Then:
        Verifies that return_error is called with proper message
    """
    mocker.patch("demistomock.incident", side_effect=Exception("Test exception"))
    mock_return_error = mocker.patch("SplunkShowDrilldown.return_error")

    # Simulate the __main__ block
    try:
        SplunkShowDrilldown.main()
    except Exception as e:
        SplunkShowDrilldown.return_error(f"Got an error while parsing Splunk events: {e}")

    mock_return_error.assert_called_once()
    assert "Got an error while parsing Splunk events" in str(mock_return_error.call_args)


def test_incident_not_successful_with_raw_data(mocker):
    """
    Given:
        incident with unsuccessful enrichment and raw drilldown data
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that error is displayed with raw data
    """
    drilldown_data = '[{"query": "test"}]'
    incident = {
        "labels": [{"type": "successful_drilldown_enrichment", "value": "false"}],
        "CustomFields": {"splunkdrilldown": drilldown_data},
    }
    mocker.patch("demistomock.incident", return_value=incident)
    res = SplunkShowDrilldown.main()
    contents = res.get("Contents")
    assert "Drilldown Enrichment Not Successful" in contents
    assert "**Raw Drilldown Searches Data:**" in contents
    assert "[\n{" in contents


def test_drilldown_searches_from_label(mocker):
    """
    Given:
        incident without splunkdrilldown in CustomFields but with drilldown_searches in labels
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that drilldown_searches is retrieved from labels and displayed correctly
    """
    drilldown_config = [{"name": "test_query_from_label", "search": "index=main | stats count"}]
    incident = {
        "CustomFields": {},
        "labels": [
            {"type": "drilldown_searches", "value": json.dumps(drilldown_config)},
        ],
    }
    mocker.patch("demistomock.incident", return_value=incident)
    res = SplunkShowDrilldown.main()
    contents = res.get("Contents")
    assert "Drilldown Configuration Status" in contents
    assert "test_query_from_label" in contents
    assert "index=main \\| stats count" in contents


def test_drilldown_searches_priority_custom_fields_over_label(mocker):
    """
    Given:
        incident with splunkdrilldown in CustomFields AND drilldown_searches in labels
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that CustomFields takes priority over labels
    """
    drilldown_config_custom = [{"name": "query_from_custom_field", "search": "index=custom"}]
    drilldown_config_label = [{"name": "query_from_label", "search": "index=label"}]
    incident = {
        "CustomFields": {"splunkdrilldown": json.dumps(drilldown_config_custom)},
        "labels": [
            {"type": "drilldown_searches", "value": json.dumps(drilldown_config_label)},
        ],
    }
    mocker.patch("demistomock.incident", return_value=incident)
    res = SplunkShowDrilldown.main()
    contents = res.get("Contents")
    # Should use custom field, not label
    assert "query_from_custom_field" in contents
    assert "index=custom" in contents
    assert "query_from_label" not in contents
    assert "index=label" not in contents


def test_drilldown_searches_from_label_with_enrichment_results(mocker):
    """
    Given:
        incident with drilldown_searches in labels and successful enrichment results
    When:
        Calling to SplunkShowDrilldown
    Then:
        Verifies that enrichment results are displayed correctly
    """
    drilldown_config = [{"name": "test_query", "search": "index=main"}]
    drilldown_results = [
        {
            "query_name": "test_query",
            "query_search": "index=main",
            "enrichment_status": "Enrichment successfully handled",
            "query_results": [
                {
                    "_bkt": "main~Test1",
                    "_time": "2024-05-16T11:26:32.000+00:00",
                    "signature": "test_signature1",
                }
            ],
        }
    ]
    incident = {
        "CustomFields": {},
        "labels": [
            {"type": "drilldown_searches", "value": json.dumps(drilldown_config)},
            {"type": "successful_drilldown_enrichment", "value": "true"},
            {"type": "Drilldown", "value": json.dumps(drilldown_results)},
        ],
    }
    mocker.patch("demistomock.incident", return_value=incident)
    res = SplunkShowDrilldown.main()
    contents = res.get("Contents")
    assert "Drilldown Searches Results" in contents
    assert "test_query" in contents
    assert "test_signature1" in contents
