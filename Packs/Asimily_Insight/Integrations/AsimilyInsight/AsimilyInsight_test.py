import pytest
import datetime


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
    mocker.patch("AsimilyInsight.demisto.command", return_value="asimily-get-assetdetails")
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
    mocker.patch("AsimilyInsight.datetime.datetime", mocker.Mock(wraps=datetime.datetime))

    mocker.patch(
        "AsimilyInsight.Client.force_get_asset_anomalies",
        return_value=(1, [{"deviceId": 1, "anomalies": [{"anomaly": "A", "alertId": "ID123"}]}]),
    )

    from AsimilyInsight import main

    main()


def test_get_asset_details_command_with_empty_response(mocker, mock_params):
    mocker.patch("AsimilyInsight.demisto.command", return_value="asimily-get-assetdetails")
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
