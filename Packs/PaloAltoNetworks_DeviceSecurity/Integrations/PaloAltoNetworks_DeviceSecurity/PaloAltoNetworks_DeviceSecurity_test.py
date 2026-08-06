import sys
import pytest
from pytest_mock import MockerFixture
from typing import TYPE_CHECKING

sys.path.insert(
    0,
    "/root/content/Packs/ApiModules/Scripts/ContentClientApiModule",
)

if TYPE_CHECKING:
    from PaloAltoNetworks_DeviceSecurity import Client


@pytest.fixture(autouse=True)
def mock_support_multithreading(mocker: MockerFixture) -> None:
    """
    Mock support_multithreading to prevent demistomock attribute errors
    during ContentClient initialization.
    """
    mocker.patch("ContentClientApiModule.support_multithreading")


@pytest.fixture
def client() -> "Client":
    """
    Pytest fixture that initializes and returns a Device Security Client instance for testing.
    """
    from PaloAltoNetworks_DeviceSecurity import Client

    return Client(
        base_url="https://test.api.strata.paloaltonetworks.com",
        first_fetch="-1",
        max_fetch=10,
        api_timeout=60,
        verify=False,
        proxy=False,
        headers={
            "Authorization": "Bearer test-token",
            "Content-Type": "application/json",
        },
    )


def test_device_security_get_device(
    mocker: MockerFixture,
    client: "Client",
) -> None:
    """
    Scenario: Get a device details from Device Security Portal by device ID

    Given:
        - Device ID arguments.

    When:
        - Calling the device_security_get_device

    Then:
        - Assert the client's get_device method is called.
        - Assert the response is correctly processed into CommandResults with expected outputs and prefix.
    """
    from PaloAltoNetworks_DeviceSecurity import device_security_get_device

    mock_response = {"hostname": "00:0a:e4:1c:62:26", "ip_address": "10.10.65.96", "profile_type": "Non_IoT"}

    get_device_mock = mocker.patch.object(
        client,
        "get_device",
        return_value=mock_response,
    )

    args = {"id": "00:0a:e4:1c:62:26"}

    response = device_security_get_device(client, args)

    get_device_mock.assert_called_once_with("00:0a:e4:1c:62:26")

    assert response.outputs_prefix == "PaloAltoNetworksDeviceSecurity.Device"
    assert response.outputs_key_field == "deviceid"
    assert response.outputs == mock_response


def test_fetch_incidents(
    mocker: MockerFixture,
    client: "Client",
) -> None:
    """
    Scenario: Fetch incidents normally

    Given:
        - lastRun without alert/vulnerability fetch timestamps.
        - mocked alert and vulnerability responses.

    When:
        - Calling fetch_incidents.

    Then:
        - Assert the client's list_alerts and list_vulns methods are called.
        - Assert the lastRun timestamps are updated correctly.
        - Assert incidents are created from alerts and vulnerabilities.
    """
    from PaloAltoNetworks_DeviceSecurity import fetch_incidents

    mock_alert_response = [
        {
            "date": "2020-01-15T05:06:50.540Z",
            "name": "foo",
            "description": "The baseline",
            "zb_ticketid": "alert-Ob81iwWe",
        },
        {
            "date": "2020-01-15T05:06:50.540Z",
            "name": "bar",
            "description": "x",
            "zb_ticketid": "alert-Lqy4ikEz",
        },
    ]

    mock_vuln_response = [
        {
            "name": "HPD41936",
            "ip": "10.55.132.114",
            "deviceid": "a0:d3:c1:d4:19:36",
            "detected_date": "2020-05-31T23:59:59.000Z",
            "vulnerability_name": "SMB v1 Usage",
            "zb_ticketid": "vuln-1",
        },
        {
            "name": "HPD41936",
            "ip": "10.55.132.114",
            "deviceid": "a0:d3:c1:d4:19:36",
            "detected_date": ["2020-05-31T23:59:59.000Z"],
            "vulnerability_name": "SMB v1 Usage",
            "zb_ticketid": "vuln-2",
        },
    ]

    list_alerts_mock = mocker.patch.object(
        client,
        "list_alerts",
        return_value=mock_alert_response,
    )
    list_vulns_mock = mocker.patch.object(
        client,
        "list_vulns",
        return_value=mock_vuln_response,
    )

    next_run, incidents = fetch_incidents(
        client,
        {},
        fetch_alerts=True,
        fetch_vulns=True,
    )

    list_alerts_mock.assert_called_once()
    list_vulns_mock.assert_called_once()

    assert next_run == {
        "last_alerts_fetch": "2020-01-15T05:06:50.540Z",
        "last_alerts_seen_ids": ["Ob81iwWe", "Lqy4ikEz"],
        "last_vulns_fetch": "2020-05-31T23:59:59.000Z",
        "last_vulns_seen_ids": ["vuln-1", "vuln-2"],
    }

    assert len(incidents) == 4
    for incident in incidents:
        assert isinstance(incident.get("occurred"), str)


def test_fetch_incidents_special(
    mocker: MockerFixture,
    client: "Client",
) -> None:
    """
    Scenario: Fetch incidents corner cases due to the same timestamps

    Given:
        - A few incidents with the same timestamps.

    When:
        - Calling fetch_incidents.

    Then:
        - Assert same-timestamp seen IDs are accumulated correctly.
        - Assert the lastRun timestamps are updated correctly.
        - Assert correct number of incidents are created correctly.
    """
    from PaloAltoNetworks_DeviceSecurity import fetch_incidents

    mock_alerts = [
        {
            "name": "alert1",
            "date": "2019-11-07T23:11:30.509Z",
            "zb_ticketid": "zb_ticketid1",
            "deviceid": "zb_ticketid1",
        },
        {
            "name": "alert2",
            "date": "2019-11-07T23:11:31.509Z",
            "zb_ticketid": "zb_ticketid2",
        },
        {
            "name": "alert3",
            "date": "2019-11-07T23:11:31.509Z",
            "zb_ticketid": "zb_ticketid3",
        },
        {
            "name": "alert4",
            "date": "2019-11-07T23:11:31.509Z",
            "zb_ticketid": "zb_ticketid4",
        },
        {
            "name": "alert5",
            "date": "2019-11-07T23:11:31.509Z",
            "zb_ticketid": "zb_ticketid5",
        },
    ]

    mock_vulns = [
        {
            "name": "vuln1",
            "detected_date": "2019-11-07T23:11:30.509Z",
            "ip": "ip1",
            "vulnerability_name": "vname1",
            "deviceid": "deviceid1",
            "zb_ticketid": "vuln1",
        },
        {
            "name": "vuln2",
            "detected_date": "2019-11-07T23:11:31.509Z",
            "ip": "ip2",
            "vulnerability_name": "vname2",
            "deviceid": "deviceid2",
            "zb_ticketid": "vuln2",
        },
    ]

    list_alerts_mock = mocker.patch.object(
        client,
        "list_alerts",
        return_value=mock_alerts,
    )
    list_vulns_mock = mocker.patch.object(
        client,
        "list_vulns",
        return_value=mock_vulns,
    )

    next_run, incidents = fetch_incidents(
        client,
        {},
        fetch_alerts=True,
        fetch_vulns=True,
    )

    list_alerts_mock.assert_called_once()
    list_vulns_mock.assert_called_once()

    assert next_run == {
        "last_alerts_fetch": "2019-11-07T23:11:31.509Z",
        "last_alerts_seen_ids": [
            "zb_ticketid2",
            "zb_ticketid3",
            "zb_ticketid4",
            "zb_ticketid5",
        ],
        "last_vulns_fetch": "2019-11-07T23:11:31.509Z",
        "last_vulns_seen_ids": ["vuln2"],
    }

    assert len(incidents) == 7


def test_device_security_list_devices(
    mocker: MockerFixture,
    client: "Client",
) -> None:
    """
    Scenario: Listing devices

    Given:
        - offset and limit parameters.

    When:
        - Calling device_security_list_devices.

    Then:
        - Assert the client's list_devices method is called.
        - Assert the response is correctly processed into CommandResults.
    """
    from PaloAltoNetworks_DeviceSecurity import device_security_list_devices

    mock_response = {
        "devices": [
            {},
            {},
        ],
        "total": 2,
    }

    list_devices_mock = mocker.patch.object(
        client,
        "list_devices",
        return_value=mock_response,
    )

    args = {"offset": "1", "limit": "2"}

    response = device_security_list_devices(client, args)

    list_devices_mock.assert_called_once_with(1, 2)

    assert response.outputs_prefix == "PaloAltoNetworksDeviceSecurity.DeviceList"
    assert response.outputs_key_field == "deviceid"
    assert response.outputs == {
        "devices": [
            {},
            {},
        ],
        "total": 2,
    }
    assert len(response.outputs) == 2


def test_device_security_list_alerts(
    mocker: MockerFixture,
    client: "Client",
) -> None:
    """
    Scenario: Listing alerts

    Given:
        - offset and limit parameters.

    When:
        - Calling device_security_list_alerts.

    Then:
        - Assert the client's list_alerts method is called.
        - Assert the response is returned in context.
    """
    from PaloAltoNetworks_DeviceSecurity import device_security_list_alerts

    mock_alerts = [
        {
            "id": "alert-id",
            "zb_ticketid": "alert-ticket",
            "name": "Alert name",
        }
    ]

    list_alerts_mock = mocker.patch.object(
        client,
        "list_alerts",
        return_value=mock_alerts,
    )

    args = {"offset": "1", "limit": "2"}

    results = device_security_list_alerts(client, args)

    list_alerts_mock.assert_called_once()

    assert results.outputs == mock_alerts
    assert results.outputs_prefix == "PaloAltoNetworksDeviceSecurity.Alerts"
    assert "Device Security Alerts" in results.readable_output


def test_device_security_list_vulns(
    mocker: MockerFixture,
    client: "Client",
) -> None:
    """
    Scenario: Listing vulnerabilities

    Given:
        - offset and limit parameters.

    When:
        - Calling device_security_list_vulns.

    Then:
        - Assert the client's list_vulns method is called.
        - Assert the response is returned in context.
    """
    from PaloAltoNetworks_DeviceSecurity import device_security_list_vulns

    mock_vulns = [
        {
            "zb_ticketid": "vuln-ticket",
            "name": "Device name",
            "vulnerability_name": "Vuln name",
        }
    ]

    list_vulns_mock = mocker.patch.object(
        client,
        "list_vulns",
        return_value=mock_vulns,
    )

    args = {"offset": "1", "limit": "2"}

    results = device_security_list_vulns(client, args)

    list_vulns_mock.assert_called_once()

    assert results.outputs == mock_vulns
    assert results.outputs_prefix == "PaloAltoNetworksDeviceSecurity.Vulns"
    assert "Device Security Vulnerabilities" in results.readable_output


def test_device_security_resolve_alert(
    mocker: MockerFixture,
    client: "Client",
) -> None:
    """
    Scenario: resolving alerts

    Given:
        - An alert ID, reason and reason type.

    When:
        - Calling device_security_resolve_alert.

    Then:
        - Assert the client's resolve_alert method is called.
        - Assert the readable output reports success.
    """
    from PaloAltoNetworks_DeviceSecurity import device_security_resolve_alert

    mock_response = {
        "api": "/pub/v4.0/alert/update",
        "ver": "v0.3",
    }

    resolve_alert_mock = mocker.patch.object(
        client,
        "resolve_alert",
        return_value=mock_response,
    )

    args = {
        "id": "123",
        "reason": "test",
        "reason_type": ["Issue Mitigated"],
    }

    result = device_security_resolve_alert(client, args)

    resolve_alert_mock.assert_called_once()

    assert result.readable_output == "Alert 123 was resolved successfully"


def test_device_security_resolve_vuln(
    mocker: MockerFixture,
    client: "Client",
) -> None:
    """
    Scenario: resolving vulnerabilities

    Given:
        - A vulnerability ID, reason and full vulnerability name.

    When:
        - Calling device_security_resolve_vuln.

    Then:
        - Assert the client's resolve_vuln method is called.
        - Assert the readable output reports success.
    """
    from PaloAltoNetworks_DeviceSecurity import device_security_resolve_vuln

    mock_response = {
        "api": "/vulnerability/update",
        "ver": "v4.0",
        "updatedVulnerInstanceList": [
            {
                "newScore": 10,
                "newLevel": "Low",
                "newAnomalyMap": {
                    "application": 0,
                    "protocol": 0,
                    "payload": 0,
                    "external": 0,
                    "internal": 0,
                },
            }
        ],
    }

    resolve_vuln_mock = mocker.patch.object(
        client,
        "resolve_vuln",
        return_value=mock_response,
    )

    args = {
        "id": "123",
        "full_name": "vuln_full_name",
        "reason": "test",
    }

    result = device_security_resolve_vuln(client, args)

    resolve_vuln_mock.assert_called_once()

    assert result.readable_output == "Vulnerability 123 was resolved successfully"


def test_get_device_by_ip(
    mocker: MockerFixture,
    client: "Client",
) -> None:
    """
    Scenario: Getting device by IP

    Given:
        - IP address argument.

    When:
        - Calling device_security_get_device_by_ip.

    Then:
        - Assert the client's get_device_by_ip method is called.
        - Assert the device values are returned in context.
    """
    from PaloAltoNetworks_DeviceSecurity import device_security_get_device_by_ip

    mock_response = {
        "devices": {
            "hostname": "00:0a:e4:1c:62:26",
            "ip_address": "1.1.1.1",
            "profile_type": "Non_IoT",
        }
    }

    get_device_by_ip_mock = mocker.patch.object(
        client,
        "get_device_by_ip",
        return_value=mock_response,
    )

    args = {"ip": "1.1.1.1"}

    response = device_security_get_device_by_ip(client, args)

    get_device_by_ip_mock.assert_called_once_with("1.1.1.1")

    assert response.outputs == {
        "hostname": "00:0a:e4:1c:62:26",
        "ip_address": "1.1.1.1",
        "profile_type": "Non_IoT",
    }
