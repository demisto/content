import json

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
