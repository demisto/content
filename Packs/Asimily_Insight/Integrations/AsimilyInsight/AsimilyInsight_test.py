import pytest


@pytest.fixture(autouse=True)
def patch_missing_modules(mocker):
    mocker.patch.dict("sys.modules", {"DemistoClassApiModule": mocker.MagicMock()})


@pytest.fixture
def mock_params():
    return {
        "url": "test_url",
        "asimilycred": {"identifier": "user", "password": "pass"},
        "insecure": False,
        "proxy": False,
        "iffetchanomalies": True,
        "iffetchcves": True,
        "isFetch": True,
    }


@pytest.fixture
def mock_context_data():
    return {"asimilydeviceid": "12345", "asimilydevicemacaddress": "00:11:22:33:44:55", "asimilydeviceipv4address": "192.168.1.1"}


def test_get_asset_details_command(mocker, mock_params):
    mocker.patch("AsimilyInsight.demisto.command", return_value="asimily-get-asset-details")
    mocker.patch("AsimilyInsight.demisto.args", return_value={"limit": "1"})
    mocker.patch("AsimilyInsight.demisto.params", return_value=mock_params)

    mocker.patch("AsimilyInsight.Client.get_asset_applications_by_mac_addr", return_value=["App1"])
    mocker.patch(
        "AsimilyInsight.Client.force_get_asset_details",
        return_value=(1, [{"deviceID": "123", "macAddr": "00:11:22:33:44:55", "hostName": "host", "v4IpAddrs": ["1.2.3.4"]}]),
    )
    mock_return = mocker.patch("AsimilyInsight.return_results")

    from AsimilyInsight import main

    main()

    result = mock_return.call_args[0][0]
    assert result.outputs_prefix == "AsimilyInsight.Asset"
    assert any("asimilydeviceid" in d for d in result.outputs)


def test_get_asset_anomalies_command(mocker, mock_params):
    mocker.patch("AsimilyInsight.demisto.command", return_value="asimily-get-asset-anomalies")
    mocker.patch("AsimilyInsight.demisto.args", return_value={"limit": "1"})
    mocker.patch("AsimilyInsight.demisto.params", return_value=mock_params)

    mocker.patch(
        "AsimilyInsight.Client.force_get_asset_anomalies",
        return_value=(
            1,
            [{"deviceId": "1", "anomalies": [{"anomaly": "AnomalyX", "alertId": "123", "domainDeviceOrIpDevice": "domain.com"}]}],
        ),
    )
    mock_return = mocker.patch("AsimilyInsight.return_results")

    from AsimilyInsight import main

    main()
    assert mock_return.call_args[0][0].outputs_prefix == "AsimilyInsight.Anomaly"


def test_get_asset_vulnerabilities_command(mocker, mock_params):
    mocker.patch("AsimilyInsight.demisto.command", return_value="asimily-get-asset-vulnerabilities")
    mocker.patch("AsimilyInsight.demisto.args", return_value={"limit": "1"})
    mocker.patch("AsimilyInsight.demisto.params", return_value=mock_params)

    mocker.patch(
        "AsimilyInsight.Client.force_get_asset_cves",
        return_value=(1, [{"deviceId": "1", "cves": [{"cveName": "CVE-123", "description": "desc"}]}]),
    )
    mock_return = mocker.patch("AsimilyInsight.return_results")

    from AsimilyInsight import main

    main()
    assert mock_return.call_args[0][0].outputs_prefix == "AsimilyInsight.CVE"


def test_fetch_incidents_command(mocker, mock_params):
    mocker.patch("AsimilyInsight.demisto.command", return_value="fetch-incidents")
    mocker.patch("AsimilyInsight.demisto.args", return_value={})
    mocker.patch("AsimilyInsight.demisto.params", return_value=mock_params)
    mocker.patch("AsimilyInsight.demisto.getLastRun", return_value={})
    mocker.patch("AsimilyInsight.demisto.setLastRun")
    mocker.patch("AsimilyInsight.demisto.incidents")

    mocker.patch(
        "AsimilyInsight.Client.force_get_asset_anomalies",
        return_value=(1, [{"deviceId": 1, "anomalies": [{"anomaly": "A", "alertId": "ID123"}]}]),
    )
    mocker.patch(
        "AsimilyInsight.Client.force_get_asset_cves",
        return_value=(1, [{"deviceId": "1", "cves": [{"cveName": "CVE-123", "description": "desc"}]}]),
    )

    from AsimilyInsight import main

    main()


def test_get_asset_details_command_with_empty_response(mocker, mock_params):
    mocker.patch("AsimilyInsight.demisto.command", return_value="asimily-get-asset-details")
    mocker.patch("AsimilyInsight.demisto.args", return_value={})
    mocker.patch("AsimilyInsight.demisto.params", return_value=mock_params)

    mocker.patch("AsimilyInsight.Client.force_get_asset_details", return_value=(0, []))
    mock_return = mocker.patch("AsimilyInsight.return_results")

    from AsimilyInsight import main

    main()

    result = mock_return.call_args[0][0]
    assert "0 assets" in result.readable_output


def test_http_request_mocking(mocker):
    from AsimilyInsight import Client

    mocker.patch(
        "AsimilyInsight.BaseClient._http_request",
        return_value={"content": [{"deviceId": "1"}], "totalPages": 1, "totalElements": 1},
    )
    client = Client(base_url="https://example.com", verify=False, auth=("user", "pass"), proxy=False)
    total, data = client.force_get_asset_details()
    assert total == 1
    assert data[0]["deviceId"] == "1"


def test_test_module_invalid_credentials(mocker, mock_params):
    mock_params["isFetch"] = False
    mocker.patch("AsimilyInsight.demisto.command", return_value="test-module")
    mocker.patch("AsimilyInsight.demisto.args", return_value={})
    mocker.patch("AsimilyInsight.demisto.params", return_value=mock_params)
    mocker.patch("AsimilyInsight.Client.get_asset_details_call", return_value="loginStyle")
    mock_return = mocker.patch("AsimilyInsight.return_results")

    from AsimilyInsight import main

    main()
    assert "Authentication Error" in mock_return.call_args[0][0]


def test_create_filter_json_basic_fields(mocker):
    mocker.patch("AsimilyInsight.argToList", side_effect=lambda x: [x])
    mock_debug = mocker.patch("AsimilyInsight.print_debug_msg")

    from AsimilyInsight import create_filter_json

    input_dict = {
        "deviceFamily": "X-Ray",
        "deviceTag": "critical",
        "ipAddr": "10.0.0.1",
        "macAddr": "aa:bb:cc:dd:ee:ff",
        "deviceRangeId": 10,
        "cvesLastUpdatedSince": "2023-01-01",
        "anomaliesLastUpdatedSince": "2024-01-01",
        "limit": 100,
    }

    result = create_filter_json(input_dict)

    assert "filters" in result
    assert result["filters"]["deviceFamily"] == [{"operator": ":", "value": "X-Ray"}]
    assert "limit" not in result["filters"]
    mock_debug.assert_called()


def test_create_filter_json_with_criticality(mocker):
    mocker.patch("AsimilyInsight.print_debug_msg")
    from AsimilyInsight import create_filter_json, ASIMILY_INSIGHT_FETCH_DEVICE_ANOMALIES_API

    input_dict = {"criticality": "High Only"}
    result = create_filter_json(input_dict, api=ASIMILY_INSIGHT_FETCH_DEVICE_ANOMALIES_API)
    assert "anomaliesCriticality" in result["filters"]


def test_create_filter_json_invalid_criticality_and_cvescore_variants(mocker):
    from AsimilyInsight import (
        create_filter_json,
        ASIMILY_INSIGHT_FETCH_DEVICE_ANOMALIES_API,
        ASIMILY_INSIGHT_FETCH_DEVICE_CVES_API,
    )

    mock_debug = mocker.patch("AsimilyInsight.print_debug_msg")

    # Case 1: unsupported criticality value (string not in map)
    input_dict_unsupported = {"criticality": "InvalidCriticality"}
    result1 = create_filter_json(input_dict_unsupported, api=ASIMILY_INSIGHT_FETCH_DEVICE_ANOMALIES_API)
    assert result1 == {"filters": {}}
    mock_debug.assert_any_call("Unsupported criticality value InvalidCriticality")

    # Case 2: criticality as list (invalid type)
    input_dict_list_type = {"criticality": ["High Only"]}
    result2 = create_filter_json(input_dict_list_type, api=ASIMILY_INSIGHT_FETCH_DEVICE_ANOMALIES_API)
    assert result2 == {"filters": {}}
    mock_debug.assert_any_call("criticality must be a string, not a list")

    # Case 3: unsupported cveScore value (numeric)
    input_dict_bad_cve_score = {"cveScore": 99}
    result3 = create_filter_json(input_dict_bad_cve_score, api=ASIMILY_INSIGHT_FETCH_DEVICE_CVES_API)
    assert result3 == {"filters": {}}
    # No warning expected — it silently skips invalid values


def test_create_filter_json_with_cve_score(mocker):
    mocker.patch("AsimilyInsight.print_debug_msg")
    from AsimilyInsight import create_filter_json, ASIMILY_INSIGHT_FETCH_DEVICE_CVES_API

    input_dict = {"cveScore": "Medium and High"}
    result = create_filter_json(input_dict, api=ASIMILY_INSIGHT_FETCH_DEVICE_CVES_API)
    assert result["filters"]["cveScore"] == [{"operator": "Gte", "value": 3.5}]


def test_create_filter_json_all_limit_and_argtolist_behavior(mocker):
    from AsimilyInsight import create_filter_json, ASIMILY_INSIGHT_FETCH_DEVICE_CVES_API

    mock_argtolist = mocker.patch("AsimilyInsight.argToList", side_effect=lambda x: [x])
    mock_debug = mocker.patch("AsimilyInsight.print_debug_msg")

    # Case 1: 'All' values and 'limit' should be skipped, even though argToList("All") is called
    input_dict_all_skipped = {
        "deviceTag": "All",
        "deviceFamily": "All",  # triggers argToList("All")
        "cveScore": "All",
        "criticality": "All",
        "limit": 50,
    }
    result1 = create_filter_json(input_dict_all_skipped, api=ASIMILY_INSIGHT_FETCH_DEVICE_CVES_API)
    assert result1 == {"filters": {}}
    mock_debug.assert_called_with({"filters": {}})

    # Both deviceFamily and deviceTag were "All", and both passed to argToList before skipping
    assert mock_argtolist.call_count == 2
    mock_argtolist.assert_has_calls([mocker.call("All"), mocker.call("All")])

    mock_argtolist.reset_mock()
    mock_debug.reset_mock()

    # Case 2: deviceFamily/deviceTag already lists — argToList should NOT be called
    input_dict_list = {
        "deviceFamily": ["X-Ray"],
        "deviceTag": ["critical"],
        "ipAddr": "10.0.0.1",
        "macAddr": ["aa:bb:cc"],
    }
    result2 = create_filter_json(input_dict_list)
    assert result2 == {
        "filters": {
            "deviceFamily": [{"operator": ":", "value": "X-Ray"}],
            "deviceTag": [{"operator": ":", "value": "critical"}],
            "ipAddr": [{"operator": ":", "value": "10.0.0.1"}],
            "macAddr": [{"operator": ":", "value": "aa:bb:cc"}],
        }
    }
    mock_argtolist.assert_not_called()
    mock_debug.assert_called_with(result2)

    mock_argtolist.reset_mock()
    mock_debug.reset_mock()

    # Case 3: deviceFamily/deviceTag as strings — argToList SHOULD be called
    input_dict_str = {"deviceFamily": "X-Ray", "deviceTag": "critical", "ipAddr": "192.168.0.1"}
    result3 = create_filter_json(input_dict_str)
    assert "deviceFamily" in result3["filters"]
    assert "deviceTag" in result3["filters"]
    assert result3["filters"]["ipAddr"] == [{"operator": ":", "value": "192.168.0.1"}]
    assert mock_argtolist.call_count == 2
    mock_debug.assert_called_with(result3)


def test_get_asset_applications_by_mac_addr_realistic_response(mocker):
    from AsimilyInsight import Client

    mock_response = [
        {
            "macAddr": "aa:bb:cc:dd:ee:ff",
            "ipAddr": "10.0.0.1",
            "applications": [
                {"application": "endpoint security", "version": "*"},
                {"application": "Wireless_Access", "version": "*"},
            ],
        }
    ]

    mocker.patch("AsimilyInsight.BaseClient._http_request", return_value=mock_response)
    mock_debug = mocker.patch("AsimilyInsight.print_debug_msg")

    client = Client(base_url="test_url", verify=False, auth=("user", "pass"), proxy=False)
    apps = client.get_asset_applications_by_mac_addr("dc:46:28:73:03:16")

    assert apps == ["endpoint security", "Wireless_Access"]
    mock_debug.assert_called_once_with("Fetching applications for device with mac dc:46:28:73:03:16")


def test_get_asset_applications_by_mac_addr_empty_response(mocker):
    from AsimilyInsight import Client

    mocker.patch("AsimilyInsight.BaseClient._http_request", return_value=None)
    client = Client(base_url="test_url", verify=False, auth=("user", "pass"), proxy=False)

    apps = client.get_asset_applications_by_mac_addr("00:11:22:33:44:55")
    assert apps == []


def test_test_module_missing_anomaly_content(mocker, mock_params):
    from AsimilyInsight import test_module, Client

    mock_params["isFetch"] = True
    mock_params["iffetchanomalies"] = True
    mock_params["iffetchcves"] = False

    client = Client(base_url="test_url", verify=False, auth=("user", "pass"), proxy=False)

    mocker.patch.object(client, "get_asset_details_call", return_value="ok")
    mocker.patch.object(client, "get_asset_anomalies_call", return_value={"not_content": []})

    result = test_module(client, mock_params)
    assert result == "Exception occured when validating fetch anomalies, no content in response."


def test_test_module_missing_cves_content(mocker, mock_params):
    from AsimilyInsight import test_module, Client

    mock_params["isFetch"] = True
    mock_params["iffetchanomalies"] = False
    mock_params["iffetchcves"] = True

    client = Client(base_url="test_url", verify=False, auth=("user", "pass"), proxy=False)

    mocker.patch.object(client, "get_asset_details_call", return_value="ok")
    mocker.patch.object(client, "get_asset_cves_call", return_value={"something_else": []})

    result = test_module(client, mock_params)
    assert result == "Exception occured when validating fetch cves, no content in response."


def test_test_module_forbidden_exception(mocker, mock_params):
    from AsimilyInsight import test_module, Client, DemistoException

    mock_params["isFetch"] = False
    client = Client(base_url="test_url", verify=False, auth=("user", "pass"), proxy=False)

    mocker.patch.object(client, "get_asset_details_call", side_effect=DemistoException("403 Forbidden"))

    result = test_module(client, mock_params)
    assert result == "Authentication Error: The specified API username and password are not correct."


def test_test_module_general_exception(mocker, mock_params):
    from AsimilyInsight import test_module, Client, DemistoException

    mock_params["isFetch"] = False
    client = Client(base_url="test_url", verify=False, auth=("user", "pass"), proxy=False)

    mocker.patch.object(client, "get_asset_details_call", side_effect=DemistoException("500 Internal Server Error"))

    result = test_module(client, mock_params)
    assert result.startswith("Exception occured: 500 Internal Server Error")


def test_get_asset_cves_call(mocker):
    from AsimilyInsight import Client, ASIMILY_INSIGHT_FETCH_DEVICE_CVES_API, CVES_API_SORT_DEVICE_ID

    # Mock internals
    mock_create_filter = mocker.patch("AsimilyInsight.create_filter_json", return_value={"filters": {"dummy": "yes"}})
    mock_add_cve_filter = mocker.patch("AsimilyInsight.add_non_fixed_cve_filter")

    mock_response = {"content": "test-cve-data"}
    mock_request = mocker.patch("AsimilyInsight.BaseClient._http_request", return_value=mock_response)

    client = Client(base_url="https://example.com", verify=False, auth=("user", "pass"), proxy=False)

    result = client.get_asset_cves_call(args={"macAddr": "aa:bb"}, page=3, size=50)

    # Assert actual output returned
    assert result == mock_response

    # Validate that filter creation and modifier were called
    mock_create_filter.assert_called_once_with({"macAddr": "aa:bb"}, ASIMILY_INSIGHT_FETCH_DEVICE_CVES_API)
    mock_add_cve_filter.assert_called_once_with({"filters": {"dummy": "yes"}})

    # Validate HTTP call
    mock_request.assert_called_once_with(
        method="POST",
        url_suffix=ASIMILY_INSIGHT_FETCH_DEVICE_CVES_API,
        params={
            "size": 50,
            "page": 3,
            "sort": CVES_API_SORT_DEVICE_ID,
        },
        json_data={"filters": {"dummy": "yes"}},
        retries=mocker.ANY,
        status_list_to_retry=mocker.ANY,
        backoff_factor=mocker.ANY,
        timeout=mocker.ANY,
    )
