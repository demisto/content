from datetime import datetime, timedelta
import json
from typing import cast, Any
from unittest.mock import MagicMock
import pytest


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def _client():
    from decyfir import Client

    return Client(base_url="test_url", verify=False, proxy=False)


def test_fetch_incidents(mocker):
    from decyfir import Client, fetch_incidents

    date_format = "%Y-%m-%dT%H:%M:%SZ"
    raw_mock_response = util_load_json("test_data/raw_alerts.json")

    client = _client()
    mocker.patch.object(Client, "request_decyfir_api", return_value=raw_mock_response["alerts"])
    last_fetch = (datetime.now() - timedelta(days=80)).strftime(date_format)
    last_run = {"last_fetch": last_fetch}

    _, new_incidents = fetch_incidents(
        client=client,
        last_run=last_run,
        first_fetch="90 days",
        decyfir_api_key="api_key",
        incident_type="Attack Surface",
        max_fetch="1",
    )

    assert ("rawJSON" in new_incidents[0]) is True
    incident = cast(dict[str, Any], new_incidents[0])
    custom_fields: dict = dict(incident.get("customFields") or {})
    assert ("decyfirdatadetails" in custom_fields) is True


def test_get_take_down_list(mocker):
    from decyfir import Client, get_take_down_list

    mock_response = util_load_json("test_data/take_down_list.json")

    raw_mock_response = util_load_json("test_data/raw_take_down_list.json")
    client = _client()
    mocker.patch.object(Client, "take_down_list_data", return_value=raw_mock_response)
    da = get_take_down_list(client=client, decyfir_api_key="api_key", args={"size": "1"})
    assert da[0] == mock_response["take_down_list"]


def test_initiate_take_down_request(mocker):
    from decyfir import Client, initiate_take_down_request

    mock_response = util_load_json("test_data/raw_init_take_down.json")
    client = _client()

    mocker.patch.object(Client, "initiate_take_down", return_value=mock_response)
    da = initiate_take_down_request(client=client, decyfir_api_key="api_key", args={"uid": "63ac266713b0752aa7865100"})

    assert ("Error" in da) is False


def test_get_severity_critical():
    from decyfir import IncidentSeverity

    client = _client()
    assert client.get_severity(9) == IncidentSeverity.CRITICAL


def test_get_severity_high():
    from decyfir import IncidentSeverity

    client = _client()
    assert client.get_severity(6) == IncidentSeverity.HIGH


def test_get_severity_medium():
    from decyfir import IncidentSeverity

    client = _client()
    assert client.get_severity(4) == IncidentSeverity.MEDIUM


def test_get_severity_low():
    from decyfir import IncidentSeverity

    client = _client()
    assert client.get_severity(1) == IncidentSeverity.LOW


def test_get_severity_unknown():
    from decyfir import IncidentSeverity

    client = _client()
    assert client.get_severity(0) == IncidentSeverity.UNKNOWN


def test_decyfir_api_request_200(mocker):
    client = _client()
    resp = MagicMock(status_code=200, content=b'[{"id":1}]')
    resp.json.return_value = [{"id": 1}]
    mocker.patch.object(client, "_http_request", return_value=resp)
    result = client.decyfir_api_request("/some/path")
    assert result == [{"id": 1}]


def test_decyfir_api_request_non_200(mocker):
    client = _client()
    resp = MagicMock(status_code=403, content=b"forbidden")
    mocker.patch.object(client, "_http_request", return_value=resp)
    assert client.decyfir_api_request("/some/path") == []


def test_decyfir_api_request_empty_content(mocker):
    client = _client()
    resp = MagicMock(status_code=200, content=b"")
    mocker.patch.object(client, "_http_request", return_value=resp)
    assert client.decyfir_api_request("/some/path") == []


def test_request_decyfir_api_200(mocker):
    client = _client()
    resp = MagicMock(status_code=200, content=b'[{"alert":"data"}]')
    resp.json.return_value = [{"alert": "data"}]
    mocker.patch.object(client, "_http_request", return_value=resp)
    result = client.request_decyfir_api("attack-surface", "open-ports", "&key=k")
    assert result == [{"alert": "data"}]


def test_request_decyfir_api_non_200(mocker):
    client = _client()
    resp = MagicMock(status_code=401, content=b"unauth")
    mocker.patch.object(client, "_http_request", return_value=resp)
    assert client.request_decyfir_api("attack-surface", "open-ports", "&key=k") == []


def test_request_decyfir_api_empty_content(mocker):
    client = _client()
    resp = MagicMock(status_code=200, content=b"")
    mocker.patch.object(client, "_http_request", return_value=resp)
    assert client.request_decyfir_api("attack-surface", "open-ports", "&key=k") == []


def test_initiate_take_down_200(mocker):
    client = _client()
    resp = MagicMock(status_code=200, content=b'{"response":{"ticketName":"T001"}}')
    resp.json.return_value = {"response": {"ticketName": "T001"}}
    mocker.patch.object(client, "_http_request", return_value=resp)
    result = client.initiate_take_down("api_key", "alert-001")
    assert result == {"response": {"ticketName": "T001"}}


def test_initiate_take_down_non_200(mocker):
    client = _client()
    resp = MagicMock(status_code=400, content=b"bad request")
    mocker.patch.object(client, "_http_request", return_value=resp)
    result = client.initiate_take_down("api_key", "alert-001")
    assert result == {}


def test_initiate_take_down_empty_content(mocker):
    client = _client()
    resp = MagicMock(status_code=200, content=b"")
    mocker.patch.object(client, "_http_request", return_value=resp)
    result = client.initiate_take_down("api_key", "alert-001")
    assert result == {}


def test_initiate_take_down_request_no_data(mocker):
    from decyfir import initiate_take_down_request

    client = _client()
    mocker.patch.object(client, "initiate_take_down", return_value={})
    result = initiate_take_down_request(client, "api_key", {"alert_id": "a1"})
    assert "no data" in result.lower()


def test_initiate_take_down_request_error_flag(mocker):
    from decyfir import initiate_take_down_request

    client = _client()
    mocker.patch.object(client, "initiate_take_down", return_value={"error": True, "response": {}})
    result = initiate_take_down_request(client, "api_key", {"alert_id": "a1"})
    assert "Error" in result


def test_initiate_take_down_request_empty_response_key(mocker):
    from decyfir import initiate_take_down_request

    client = _client()
    mocker.patch.object(client, "initiate_take_down", return_value={"error": False, "response": {}})
    result = initiate_take_down_request(client, "api_key", {"alert_id": "a1"})
    assert "Error" in result


def test_initiate_take_down_request_success(mocker):
    from decyfir import initiate_take_down_request

    client = _client()
    mocker.patch.object(
        client,
        "initiate_take_down",
        return_value={"error": False, "response": {"ticketName": "T00001"}},
    )
    result = initiate_take_down_request(client, "api_key", {"alert_id": "a1"})
    assert "T00001" in result
    assert "Successfully" in result


def test_get_take_down_list_empty(mocker):
    from decyfir import get_take_down_list

    client = _client()
    mocker.patch.object(client, "take_down_list_data", return_value=[])
    result = get_take_down_list(client, "api_key", {})
    assert result == []


def test_fetch_incidents_no_last_run(mocker):
    from decyfir import Client, fetch_incidents

    client = _client()
    mocker.patch.object(Client, "request_decyfir_api", return_value=[])
    last_fetch, incidents = fetch_incidents(
        client=client,
        last_run=None,
        first_fetch="30 days",
        decyfir_api_key="api_key",
        incident_type="Attack Surface",
        max_fetch="10",
    )
    assert "last_fetch" in last_fetch
    assert incidents == []


def test_fetch_incidents_with_last_run(mocker):
    from decyfir import Client, fetch_incidents

    client = _client()
    mocker.patch.object(Client, "request_decyfir_api", return_value=[])
    last_run = {"last_fetch": "2024-01-01T00:00:00Z"}
    last_fetch, incidents = fetch_incidents(
        client=client,
        last_run=last_run,
        first_fetch="30 days",
        decyfir_api_key="api_key",
        incident_type="Attack Surface",
        max_fetch="5",
    )
    assert "last_fetch" in last_fetch
    assert incidents == []


def test_fetch_incidents_forbidden_exception(mocker):
    from decyfir import Client, fetch_incidents

    client = _client()
    mocker.patch.object(Client, "get_decyfir_data", side_effect=Exception("403 Forbidden access denied"))
    result = fetch_incidents(
        client=client,
        last_run={"last_fetch": "2024-01-01T00:00:00Z"},
        first_fetch="30 days",
        decyfir_api_key="api_key",
        incident_type="Attack Surface",
        max_fetch="10",
    )
    assert "Authorization Error" in result


def test_fetch_incidents_generic_exception(mocker):
    from decyfir import Client, fetch_incidents

    client = _client()
    mocker.patch.object(Client, "get_decyfir_data", side_effect=Exception("network timeout"))
    with pytest.raises(Exception, match="network timeout"):
        fetch_incidents(
            client=client,
            last_run={"last_fetch": "2024-01-01T00:00:00Z"},
            first_fetch="30 days",
            decyfir_api_key="api_key",
            incident_type="Attack Surface",
            max_fetch="10",
        )


def test_fetch_incidents_all_incident_types(mocker):
    from decyfir import Client, fetch_incidents

    client = _client()
    mock_req = mocker.patch.object(Client, "request_decyfir_api", return_value=[])
    fetch_incidents(
        client=client,
        last_run=None,
        first_fetch="7 days",
        decyfir_api_key="api_key",
        incident_type=None,
        max_fetch=None,
    )
    # 6 AS + 4 II + 3 DB + 5 SPE = 18 calls
    assert mock_req.call_count == 18


def test_take_down_list_data_none_sub_category(mocker):
    client = _client()
    mocker.patch.object(client, "decyfir_api_request", return_value=[])
    result = client.take_down_list_data("api_key", None, "0", "50")
    assert result == []


def test_get_decyfir_data_attack_surface(mocker):
    from decyfir import LABEL_ATTACK_SURFACE

    client = _client()
    mocker.patch.object(client, "request_decyfir_api", return_value=[])
    result = client.get_decyfir_data(0, "api_key", LABEL_ATTACK_SURFACE, "10")
    # All 6 attack surface sub-types should be keys
    assert "open-ports" in result
    assert "ip-vulnerability" in result
    assert "configuration" in result
    assert "cloud-weakness" in result
    assert "ip-reputation" in result
    assert "certificates" in result


def test_get_decyfir_data_impersonation(mocker):
    from decyfir import LABEL_DIGITAL_RISK_IM_IN

    client = _client()
    mocker.patch.object(client, "request_decyfir_api", return_value=[])
    result = client.get_decyfir_data(0, "api_key", LABEL_DIGITAL_RISK_IM_IN, "10")
    assert "domain-it-asset" in result
    assert "executive-people" in result
    assert "product-solution" in result
    assert "social-handlers" in result


def test_get_decyfir_data_data_breach(mocker):
    from decyfir import LABEL_DIGITAL_RISK_DB_WM

    client = _client()
    mocker.patch.object(client, "request_decyfir_api", return_value=[])
    result = client.get_decyfir_data(0, "api_key", LABEL_DIGITAL_RISK_DB_WM, "10")
    assert "phishing" in result
    assert "ransomware" in result
    assert "dark-web" in result


def test_get_decyfir_data_social_exposure(mocker):
    from decyfir import LABEL_DIGITAL_RISK_S_PE

    client = _client()
    mocker.patch.object(client, "request_decyfir_api", return_value=[])
    result = client.get_decyfir_data(0, "api_key", LABEL_DIGITAL_RISK_S_PE, "10")
    assert "source-code" in result
    assert "malicious-mobile-apps" in result
    assert "confidential-files" in result
    assert "dumps-pii-cii" in result
    assert "social-threat" in result


def test_get_decyfir_data_no_incident_type_fetches_all(mocker):
    client = _client()
    mock_req = mocker.patch.object(client, "request_decyfir_api", return_value=[])
    client.get_decyfir_data(0, "api_key", "", None)
    # 6 AS + 4 II + 3 DBWM + 5 SPE = 18 total calls
    assert mock_req.call_count == 18


def test_get_decyfir_data_uses_max_fetch(mocker):
    client = _client()
    from decyfir import LABEL_ATTACK_SURFACE

    mock_req = mocker.patch.object(client, "request_decyfir_api", return_value=[])
    client.get_decyfir_data(12345, "api_key", LABEL_ATTACK_SURFACE, "42")
    # Verify that the api_param_query contains size=42 and after=12345
    call_args = mock_req.call_args_list[0]
    query_str = call_args[0][2]  # third positional arg
    assert "size=42" in query_str
    assert "after=12345" in query_str
