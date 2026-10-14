from copy import deepcopy
import json
from typing import Any
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


def test_incident_links_use_production_environment() -> None:
    from PaloAltoNetworks_DeviceSecurity import get_scm_alert_url, get_scm_vuln_url

    expected_base_url = "https://stratacloudmanager.paloaltonetworks.com"
    assert get_scm_alert_url("alert-123") == (
        f"{expected_base_url}/insights/iot-security/alerts/security-alerts/alert-detail?id=alert-123"
    )
    assert get_scm_vuln_url({"deviceid": "device-123", "vulnerability_name": "Test vulnerability"}) == (
        f"{expected_base_url}/insights/iot-security/assets/assets/overview/device-123"
        "?vulnerabilityname=Test%20vulnerability"
    )


@pytest.mark.parametrize("client_secret", ["test-secret", {"identifier": "", "password": "test-secret"}])
def test_main_routes_authentication_and_api(mocker: MockerFixture, client_secret: Any) -> None:
    from PaloAltoNetworks_DeviceSecurity import main

    mocker.patch("PaloAltoNetworks_DeviceSecurity.demisto.params", return_value={"client_secret": client_secret})
    mocker.patch("PaloAltoNetworks_DeviceSecurity.demisto.args", return_value={})
    mocker.patch("PaloAltoNetworks_DeviceSecurity.demisto.command", return_value="test-module")
    token_mock = mocker.patch("PaloAltoNetworks_DeviceSecurity.get_scm_access_token", return_value="test-token")
    client_mock = mocker.patch("PaloAltoNetworks_DeviceSecurity.Client")
    mocker.patch("PaloAltoNetworks_DeviceSecurity.test_module", return_value="ok")
    mocker.patch("PaloAltoNetworks_DeviceSecurity.return_results")
    error_mock = mocker.patch("PaloAltoNetworks_DeviceSecurity.return_error")
    main()
    error_mock.assert_not_called()
    assert token_mock.call_args.args[0] == "https://auth.apps.paloaltonetworks.com"
    assert token_mock.call_args.args[3] == "test-secret"
    assert client_mock.call_args.kwargs["base_url"] == "https://api.strata.paloaltonetworks.com/iot/pub/v1"


@pytest.mark.parametrize("client_secret", [None, "", {}, {"password": ""}, {"identifier": "secret"}])
def test_main_rejects_missing_client_secret(mocker: MockerFixture, client_secret: Any) -> None:
    from PaloAltoNetworks_DeviceSecurity import main

    mocker.patch("PaloAltoNetworks_DeviceSecurity.demisto.params", return_value={"client_secret": client_secret})
    mocker.patch("PaloAltoNetworks_DeviceSecurity.demisto.args", return_value={})
    mocker.patch("PaloAltoNetworks_DeviceSecurity.demisto.command", return_value="test-module")
    token_mock = mocker.patch("PaloAltoNetworks_DeviceSecurity.get_scm_access_token")
    error_mock = mocker.patch("PaloAltoNetworks_DeviceSecurity.return_error")

    main()

    token_mock.assert_not_called()
    error_mock.assert_called_once_with(
        "Client Secret is required. Enter the secret in the integration's Client Secret password field."
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
        "list_vulns_page",
        return_value={"items": mock_vuln_response, "total": len(mock_vuln_response)},
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
        "list_vulns_page",
        return_value={"items": mock_vulns, "total": len(mock_vulns)},
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


# Regression scenarios originally reproduced in investigation 04239316.

FETCH_CURSOR = "2026-09-14T23:59:59.000Z"
FETCH_OLDER = "2026-09-13T23:59:59.000Z"
FETCH_NEWER = "2026-09-16T23:59:59.000Z"


def vulnerability_record(identifier: str, detected: Any = FETCH_CURSOR) -> dict:
    return {
        "zb_ticketid": identifier,
        "detected_date": detected,
        "name": "test-device",
        "deviceid": "test-device-id",
        "ip": "192.0.2.10",
        "vulnerability_name": "Test vulnerability",
    }


def incident_identifiers(incidents: list[dict]) -> list[str]:
    return [json.loads(incident["rawJSON"])["zb_ticketid"] for incident in incidents]


def mock_vulnerability_inventory(mocker: MockerFixture, client: "Client", rows: list[dict | None]) -> Any:
    def response(**kwargs: Any) -> dict:
        params = kwargs["params"]
        selected = rows[params["offset"]: params["offset"] + params["pagelength"]]
        return {"items": [record for record in selected if record is not None], "total": len(rows)}

    return mocker.patch.object(client, "_http_request", side_effect=response)


def fetch_vulnerabilities(client: "Client", state: dict) -> tuple[dict, list[dict]]:
    from PaloAltoNetworks_DeviceSecurity import fetch_incidents

    next_run, incidents = fetch_incidents(client, state, fetch_alerts=False, fetch_vulns=True)
    assert next_run is not None
    assert incidents is not None
    return next_run, incidents


def test_older_record_does_not_repeat_over_twenty_cycles(mocker: MockerFixture, client: "Client") -> None:
    mock_vulnerability_inventory(mocker, client, [vulnerability_record("old", [FETCH_OLDER])])
    state = {"last_vulns_fetch": FETCH_CURSOR, "last_vulns_seen_ids": ["known"]}
    for _ in range(20):
        state, incidents = fetch_vulnerabilities(client, state)
        assert incidents == []
        assert state["last_vulns_fetch"] == FETCH_CURSOR
        assert state["last_vulns_seen_ids"] == ["known"]


def test_old_full_page_does_not_starve_new_records(mocker: MockerFixture, client: "Client") -> None:
    rows = [vulnerability_record(f"old-{index}", FETCH_OLDER) for index in range(10)]
    request = mock_vulnerability_inventory(mocker, client, rows + [vulnerability_record("new", FETCH_NEWER)])
    state, incidents = fetch_vulnerabilities(client, {"last_vulns_fetch": FETCH_CURSOR})
    assert incidents == []
    assert state["last_vulns_fetch"] == FETCH_CURSOR
    assert state["vulnerability_scan"]["offset"] == 10
    state, incidents = fetch_vulnerabilities(client, state)
    assert incident_identifiers(incidents) == ["new"]
    assert state["last_vulns_fetch"] == FETCH_NEWER
    assert [call.kwargs["params"]["offset"] for call in request.call_args_list] == [0, 10]


def test_short_and_empty_pages_do_not_end_scan(mocker: MockerFixture, client: "Client") -> None:
    # Page 0 is short; the next page is empty but the following page contains data.
    rows = [vulnerability_record("first")] + [None] * 19 + [vulnerability_record("later", FETCH_NEWER)]
    request = mock_vulnerability_inventory(mocker, client, rows)
    state = {"last_vulns_fetch": FETCH_CURSOR}
    emitted = []
    for _ in range(3):
        state, incidents = fetch_vulnerabilities(client, state)
        emitted.extend(incident_identifiers(incidents))
    assert emitted == ["first", "later"]
    assert [call.kwargs["params"]["offset"] for call in request.call_args_list] == [0, 10, 20]
    assert "vulnerability_scan" not in state


def test_unordered_pages_keep_fixed_query_start(mocker: MockerFixture, client: "Client") -> None:
    client.max_fetch = 1
    request = mock_vulnerability_inventory(
        mocker,
        client,
        [
            vulnerability_record("newest", FETCH_NEWER),
            vulnerability_record("earlier", FETCH_CURSOR),
            vulnerability_record("middle", "2026-09-15T12:00:00.000Z"),
        ],
    )
    state = {"last_vulns_fetch": FETCH_CURSOR}
    emitted = []
    for _ in range(3):
        state, incidents = fetch_vulnerabilities(client, state)
        emitted.extend(incident_identifiers(incidents))
    assert emitted == ["newest", "earlier", "middle"]
    assert all(call.kwargs["params"]["stime"] == FETCH_CURSOR for call in request.call_args_list)
    assert state["last_vulns_fetch"] == FETCH_NEWER
    assert state["last_vulns_seen_ids"] == ["newest"]
    assert "vulnerability_scan" not in state


def test_more_than_one_thousand_boundary_ids_are_preserved(mocker: MockerFixture, client: "Client") -> None:
    client.max_fetch = 100
    rows = [vulnerability_record(f"boundary-{index}") for index in range(1005)]
    mock_vulnerability_inventory(mocker, client, rows)
    state = {"last_vulns_fetch": FETCH_CURSOR}
    emitted = []
    for _ in range(11):
        state, incidents = fetch_vulnerabilities(client, state)
        emitted.extend(incident_identifiers(incidents))
    assert len(emitted) == len(set(emitted)) == 1005
    assert state["last_vulns_seen_ids"] == [record["zb_ticketid"] for record in rows]
    for _ in range(4):
        state, incidents = fetch_vulnerabilities(client, state)
        assert incidents == []


def test_cross_page_and_same_page_duplicates_are_suppressed(mocker: MockerFixture, client: "Client") -> None:
    client.max_fetch = 2
    record = vulnerability_record("repeated")
    mock_vulnerability_inventory(mocker, client, [record, record, record, vulnerability_record("second")])
    state, incidents = fetch_vulnerabilities(client, {"last_vulns_fetch": FETCH_CURSOR})
    assert incident_identifiers(incidents) == ["repeated"]
    state, incidents = fetch_vulnerabilities(client, state)
    assert incident_identifiers(incidents) == ["second"]
    state, incidents = fetch_vulnerabilities(client, state)
    assert incidents == []


@pytest.mark.parametrize(
    "value,expected",
    [
        ([FETCH_NEWER, FETCH_OLDER], FETCH_OLDER),
        ([FETCH_OLDER, FETCH_NEWER], FETCH_OLDER),
        ([None, "not-a-date", FETCH_CURSOR], FETCH_CURSOR),
        ("2026-09-15T01:59:59+02:00", FETCH_CURSOR),
        ("2026-09-14T23:59:59.000001Z", "2026-09-14T23:59:59.000001Z"),
        ([], None),
        (None, None),
        ("invalid", None),
    ],
)
def test_detected_date_normalization(value: Any, expected: str | None) -> None:
    from PaloAltoNetworks_DeviceSecurity import normalize_detected_date

    assert normalize_detected_date(value) == expected


def test_equivalent_cursor_timestamps_are_deduplicated(mocker: MockerFixture, client: "Client") -> None:
    mock_vulnerability_inventory(mocker, client, [vulnerability_record("seen", "2026-09-15T01:59:59+02:00")])
    _, incidents = fetch_vulnerabilities(client, {"last_vulns_fetch": FETCH_CURSOR, "last_vulns_seen_ids": ["seen"]})
    assert incidents == []


def test_api_failure_does_not_mutate_input_checkpoint(mocker: MockerFixture, client: "Client") -> None:
    from CommonServerPython import DemistoException

    state = {
        "last_vulns_fetch": FETCH_CURSOR,
        "last_vulns_seen_ids": ["known"],
        "vulnerability_scan": {"version": 1, "stime": FETCH_CURSOR, "offset": 10, "seen_ids": ["known"]},
    }
    original = deepcopy(state)
    mocker.patch.object(
        client,
        "_http_request",
        side_effect=DemistoException("Simulated API failure"),
    )
    with pytest.raises(DemistoException, match="Simulated API failure"):
        fetch_vulnerabilities(client, state)
    assert state == original


@pytest.mark.parametrize(
    "page",
    [
        {"items": []},
        {"items": [], "total": "10"},
        {"items": [], "total": -1},
        {"items": "invalid", "total": 1},
        {"items": [None], "total": 1},
    ],
)
def test_malformed_page_does_not_advance_cursor(mocker: MockerFixture, client: "Client", page: dict) -> None:
    from CommonServerPython import DemistoException

    mocker.patch.object(client, "_http_request", return_value=page)
    with pytest.raises(DemistoException, match="Invalid vulnerability page"):
        fetch_vulnerabilities(client, {"last_vulns_fetch": FETCH_CURSOR})


def test_fetch_disabled_preserves_checkpoint(client: "Client") -> None:
    from PaloAltoNetworks_DeviceSecurity import fetch_incidents

    checkpoint = {"version": 1, "stime": FETCH_CURSOR, "offset": 30, "seen_ids": ["known"]}
    state, incidents = fetch_incidents(client, {"vulnerability_scan": checkpoint}, False, False)
    assert state["vulnerability_scan"] == checkpoint
    assert incidents == []


def test_no_unsupported_sorting_parameters(mocker: MockerFixture, client: "Client") -> None:
    request = mocker.patch.object(client, "_http_request", return_value={"items": [], "total": 0})
    assert client.list_vulns(FETCH_CURSOR) == []
    assert "sortfield" not in request.call_args.kwargs["params"]
    assert "sortdirection" not in request.call_args.kwargs["params"]


@pytest.mark.parametrize(
    "checkpoint",
    [
        "invalid",
        {"version": 999},
        {"version": 1, "stime": FETCH_CURSOR, "offset": -1, "seen_ids": []},
        {"version": 1, "stime": FETCH_CURSOR, "offset": True, "seen_ids": []},
        {"version": 1, "stime": FETCH_CURSOR, "offset": "10", "seen_ids": []},
        {"version": 1, "stime": "invalid", "offset": 10, "seen_ids": []},
        {"version": 1, "stime": FETCH_CURSOR, "offset": 10, "seen_ids": [None]},
        {"version": 2, "stime": FETCH_CURSOR, "offset": 10, "seen_ids": [], "latest_fetch": None},
        {
            "version": 2, "stime": FETCH_CURSOR, "offset": 10, "seen_ids": [],
            "latest_fetch": "invalid", "boundary_ids": [],
        },
        {
            "version": 2, "stime": FETCH_CURSOR, "offset": 10, "seen_ids": [],
            "latest_fetch": FETCH_NEWER, "boundary_ids": [None],
        },
    ],
)
def test_invalid_checkpoint_is_logged_and_skipped(mocker: MockerFixture, client: "Client", checkpoint: Any) -> None:
    request = mock_vulnerability_inventory(
        mocker, client, [vulnerability_record("known"), vulnerability_record("new", FETCH_NEWER)]
    )
    debug_mock = mocker.patch("PaloAltoNetworks_DeviceSecurity.demisto.debug")
    last_run = {"last_vulns_fetch": FETCH_CURSOR, "last_vulns_seen_ids": ["known"], "vulnerability_scan": checkpoint}
    original = deepcopy(last_run)

    state, incidents = fetch_vulnerabilities(client, last_run)

    assert request.call_args.kwargs["params"]["stime"] == FETCH_CURSOR
    assert request.call_args.kwargs["params"]["offset"] == 0
    assert incident_identifiers(incidents) == ["new"]
    assert state["last_vulns_fetch"] == FETCH_NEWER
    assert "vulnerability_scan" not in state
    assert last_run == original
    assert any("Skipping" in call.args[0] and "checkpoint" in call.args[0] for call in debug_mock.call_args_list)
