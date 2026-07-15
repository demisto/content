"""Axonius Integration for Cortex XSOAR - Unit Tests file."""

import json
import warnings
from unittest.mock import MagicMock, patch

import pytest

from Axonius import (
    _fetch_all_pages,
    _flatten_instance,
    _handle_api_response,
    get_assets,
    get_asset_types,
    get_custom_data,
    create_custom_data,
    delete_custom_data,
    get_enforcements,
    run_enforcement,
    get_queries,
    create_query,
    delete_query,
    get_grouped_vulnerabilities,
    run_command,
)
from CommonServerPython import DemistoException
from marshmallow.warnings import RemovedInMarshmallow4Warning

from TestData.Expected_data import EXPECTED_DEVICE, EXPECTED_DEVICE_TAGS, EXPECTED_USERS_SQS
from TestData.Raw_data import (
    DUMMY_ASSET_TYPES,
    DUMMY_CUSTOM_DATA,
    DUMMY_DEVICES,
    DUMMY_DEVICES_IDS,
    DUMMY_ENFORCEMENTS,
    DUMMY_QUERIES,
    DUMMY_TAGS,
    DUMMY_USER_IDS,
    DUMMY_V2_ASSETS_RESPONSE,
    DUMMY_V2_ASSETS_RESPONSE_WITH_CURSOR,
    DUMMY_VULNERABILITY_INSTANCES,
    USERS_SQS,
)

warnings.filterwarnings("ignore", category=RemovedInMarshmallow4Warning)


class DummyDevices:
    def __init__(self):
        self.saved_query = DummyDevicesSavedQueries()
        self.labels = DummyDevicesLabels()
        self.LAST_GET = {}

    @staticmethod
    def get_by_hostname(value: str, max_rows: int, fields: list):
        return DUMMY_DEVICES

    @staticmethod
    def get(query: str, max_rows: int, fields: list):
        return DUMMY_DEVICES


class DummyDevicesSavedQueries:
    @staticmethod
    def get():
        return USERS_SQS


class DummyDevicesLabels:
    @staticmethod
    def get():
        return DUMMY_TAGS

    @staticmethod
    def add(rows: list, labels: list):
        return len(DUMMY_DEVICES_IDS)


class DummyUsers:
    def __init__(self):
        self.saved_query = DummyUsersSavedQueries()
        self.labels = DummyUsersLabels()
        self.LAST_GET = {}


class DummyUsersSavedQueries:
    @staticmethod
    def get():
        return USERS_SQS


class DummyUsersLabels:
    @staticmethod
    def get():
        return DUMMY_TAGS

    @staticmethod
    def remove(rows: list, labels: list):
        return len(DUMMY_USER_IDS)


class DummyConnect:
    def __init__(self):
        self.devices = DummyDevices()
        self.users = DummyUsers()

    @staticmethod
    def start():
        return True


def test_client():
    """Pass."""

    client = DummyConnect()
    expected = "ok"
    args: dict = {}
    result = run_command(client=client, args=args, command="test-module")
    assert expected == result


def test_get_saved_queries():
    client = DummyConnect()
    args: dict = {"type": "users"}
    result = run_command(client=client, args=args, command="axonius-get-saved-queries")
    assert len(EXPECTED_USERS_SQS) == len(result.outputs)


def test_get_tags():
    client = DummyConnect()
    args: dict = {"type": "devices"}
    result = run_command(client=client, args=args, command="axonius-get-tags")
    assert result.outputs == EXPECTED_DEVICE_TAGS


def test_add_tags():
    client = DummyConnect()
    args: dict = {"type": "devices", "ids": DUMMY_DEVICES_IDS, "tag_name": "test"}
    result = run_command(client=client, args=args, command="axonius-add-tag")
    assert len(DUMMY_DEVICES_IDS) == result.outputs


def test_remove_tags():
    client = DummyConnect()
    args: dict = {"type": "users", "ids": DUMMY_USER_IDS, "tag_name": "test"}
    result = run_command(client=client, args=args, command="axonius-remove-tag")
    assert len(DUMMY_USER_IDS) == result.outputs


def test_get_device():
    client = DummyConnect()
    args: dict = {"value": "DESKTOP-Gary-Gaither"}
    result = run_command(client=client, args=args, command="axonius-get-devices-by-hostname")
    assert EXPECTED_DEVICE["internal_axon_id"] == result.outputs["internal_axon_id"]


def test_get_by_aql():
    client = DummyConnect()
    args: dict = {"query": '("specific_data.data.name" == regex("john", "i"))'}
    result = run_command(client=client, args=args, command="axonius-get-devices-by-aql")
    assert EXPECTED_DEVICE["internal_axon_id"] == result.outputs["internal_axon_id"]


def test_add_note():
    client = DummyConnect()
    args: dict = {"type": "devices", "ids": DUMMY_DEVICES_IDS, "note": "note1"}
    result = run_command(client=client, args=args, command="axonius-add-note")
    assert result.outputs == 0


# ---------------------------------------------------------------------------
# _handle_api_response tests
# ---------------------------------------------------------------------------


def test_handle_api_response_none_raises():
    with pytest.raises(DemistoException, match="No URL configured"):
        _handle_api_response(None, "api/v2/test")


def test_handle_api_response_non_ok_raises():
    mock_resp = MagicMock()
    mock_resp.ok = False
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error"
    with pytest.raises(DemistoException, match="HTTP 500"):
        _handle_api_response(mock_resp, "api/v2/test")


def test_handle_api_response_empty_content_returns_empty_dict():
    mock_resp = MagicMock()
    mock_resp.ok = True
    mock_resp.content = b""
    result = _handle_api_response(mock_resp, "api/v2/test")
    assert result == {}


def test_handle_api_response_valid_json():
    mock_resp = MagicMock()
    mock_resp.ok = True
    mock_resp.content = b'{"data": [1, 2, 3]}'
    mock_resp.json.return_value = {"data": [1, 2, 3]}
    result = _handle_api_response(mock_resp, "api/v2/test")
    assert result == {"data": [1, 2, 3]}


# ---------------------------------------------------------------------------
# axonius-get-assets tests
# ---------------------------------------------------------------------------


def _make_ok_response(body: dict) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.ok = True
    mock_resp.status_code = 200
    mock_resp.content = json.dumps(body).encode()
    mock_resp.json.return_value = body
    return mock_resp


def test_get_assets_basic():
    with patch("Axonius.make_api_call", return_value=_make_ok_response(DUMMY_V2_ASSETS_RESPONSE)):
        result = get_assets({"asset_type": "vulnerability_instances", "page_limit": "2"})
    assert result.outputs["asset_type"] == "vulnerability_instances"
    assert len(result.outputs["assets"]) == 2
    assert result.outputs["count"] == 2
    assert "next_page" not in result.outputs


def test_get_assets_with_cursor():
    with patch("Axonius.make_api_call", return_value=_make_ok_response(DUMMY_V2_ASSETS_RESPONSE_WITH_CURSOR)):
        result = get_assets({"asset_type": "devices"})
    assert result.outputs["next_page"] == "cursor_token_xyz"


def test_get_assets_no_results():
    empty_resp = {"assets": [], "meta": {"page": {}, "next_page": None}}
    with patch("Axonius.make_api_call", return_value=_make_ok_response(empty_resp)):
        result = get_assets({"asset_type": "security_findings"})
    assert result.outputs["assets"] == []
    assert "No" in result.readable_output


def test_get_assets_api_error_raises():
    mock_resp = MagicMock()
    mock_resp.ok = False
    mock_resp.status_code = 403
    mock_resp.text = "Forbidden"
    with (
        patch("Axonius.make_api_call", return_value=mock_resp),
        pytest.raises(DemistoException, match="HTTP 403")
    ):
        get_assets({"asset_type": "devices"})


# ---------------------------------------------------------------------------
# axonius-get-asset-types tests
# ---------------------------------------------------------------------------


def test_get_asset_types():
    body = {"asset_types": DUMMY_ASSET_TYPES}
    with patch("Axonius.make_api_call", return_value=_make_ok_response(body)):
        result = get_asset_types()
    assert "devices" in result.outputs


# ---------------------------------------------------------------------------
# Custom Data Management tests
# ---------------------------------------------------------------------------


def test_get_custom_data():
    body = {"custom_fields": DUMMY_CUSTOM_DATA}
    with patch("Axonius.make_api_call", return_value=_make_ok_response(body)):
        result = get_custom_data({})
    assert len(result.outputs) == 2


def test_create_custom_data_valid():
    payload = json.dumps({"name": "new_field", "value": "new_value"})
    body = {"id": "cd-003", "name": "new_field", "value": "new_value"}
    with patch("Axonius.make_api_call", return_value=_make_ok_response(body)):
        result = create_custom_data({"payload": payload})
    assert "created" in result.readable_output


def test_create_custom_data_no_payload_raises():
    with pytest.raises(DemistoException, match="'payload' argument is required"):
        create_custom_data({})


def test_create_custom_data_invalid_json_raises():
    with pytest.raises(DemistoException, match="Invalid JSON"):
        create_custom_data({"payload": "not-json"})


def test_delete_custom_data():
    mock_resp = MagicMock()
    mock_resp.ok = True
    mock_resp.content = b""
    with patch("Axonius.make_api_call", return_value=mock_resp):
        result = delete_custom_data({"id": "cd-001"})
    assert result.outputs["deleted"] is True
    assert result.outputs["id"] == "cd-001"


def test_delete_custom_data_no_id_raises():
    with pytest.raises(DemistoException, match="'id' argument is required"):
        delete_custom_data({})


# ---------------------------------------------------------------------------
# Enforcements tests
# ---------------------------------------------------------------------------


def test_get_enforcements():
    body = {"enforcements": DUMMY_ENFORCEMENTS}
    with patch("Axonius.make_api_call", return_value=_make_ok_response(body)):
        result = get_enforcements({})
    assert len(result.outputs) == 2


def test_run_enforcement():
    body = {"status": "triggered"}
    with patch("Axonius.make_api_call", return_value=_make_ok_response(body)):
        result = run_enforcement({"enforcement_id": "enf-001"})
    assert result.outputs["triggered"] is True
    assert result.outputs["enforcement_id"] == "enf-001"


def test_run_enforcement_no_id_raises():
    with pytest.raises(DemistoException, match="'enforcement_id' argument is required"):
        run_enforcement({})


# ---------------------------------------------------------------------------
# Queries tests
# ---------------------------------------------------------------------------


def test_get_queries():
    body = {"queries": DUMMY_QUERIES}
    with patch("Axonius.make_api_call", return_value=_make_ok_response(body)):
        result = get_queries({})
    assert len(result.outputs) == 2


def test_create_query():
    body = {"uuid": "q-new", "name": "My Query", "asset_type": "devices"}
    with patch("Axonius.make_api_call", return_value=_make_ok_response(body)):
        result = create_query({"name": "My Query", "query": '("specific_data.data.name" == "test")', "asset_type": "devices"})
    assert "created" in result.readable_output


def test_create_query_missing_name_raises():
    with pytest.raises(DemistoException, match="'name' argument is required"):
        create_query({"query": "some query"})


def test_create_query_missing_query_raises():
    with pytest.raises(DemistoException, match="'query' argument is required"):
        create_query({"name": "my query"})


def test_delete_query():
    mock_resp = MagicMock()
    mock_resp.ok = True
    mock_resp.content = b""
    with patch("Axonius.make_api_call", return_value=mock_resp):
        result = delete_query({"query_id": "q-001"})
    assert result.outputs["deleted"] is True


def test_delete_query_no_id_raises():
    with pytest.raises(DemistoException, match="'query_id' argument is required"):
        delete_query({})


# ---------------------------------------------------------------------------
# _flatten_instance tests
# ---------------------------------------------------------------------------


def test_flatten_instance_single_element_list():
    inst = {"hostname": ["my-host"], "cvss_score": 9.8}
    flat = _flatten_instance(inst)
    assert flat["hostname"] == "my-host"
    assert flat["cvss_score"] == 9.8


def test_flatten_instance_multi_element_list_unchanged():
    inst = {"ips": ["1.1.1.1", "2.2.2.2"]}
    flat = _flatten_instance(inst)
    assert flat["ips"] == ["1.1.1.1", "2.2.2.2"]


# ---------------------------------------------------------------------------
# axonius-get-grouped-vulnerabilities tests
# ---------------------------------------------------------------------------


def _make_vi_page(assets: list, cursor: str = None) -> dict:
    return {
        "assets": assets,
        "meta": {"page": {"totalResources": len(assets)}, "next_page": cursor},
    }


def test_get_grouped_vulnerabilities_groups_correctly():
    page = _make_vi_page(DUMMY_VULNERABILITY_INSTANCES)
    with patch("Axonius.make_api_call", return_value=_make_ok_response(page)):
        result = get_grouped_vulnerabilities({"top_n": "10"})

    outputs = result.outputs
    cve_map = {r["cve_id"]: r for r in outputs}

    # CVE-2023-1111 has 3 instances, CVE-2023-2222 has 2
    assert cve_map["CVE-2023-1111"]["affected_hosts_count"] == 3
    assert cve_map["CVE-2023-2222"]["affected_hosts_count"] == 2

    # Sorted descending by affected_hosts_count
    assert outputs[0]["cve_id"] == "CVE-2023-1111"


def test_get_grouped_vulnerabilities_average_cvss():
    page = _make_vi_page(DUMMY_VULNERABILITY_INSTANCES)
    with patch("Axonius.make_api_call", return_value=_make_ok_response(page)):
        result = get_grouped_vulnerabilities({"top_n": "10"})

    cve_map = {r["cve_id"]: r for r in result.outputs}
    # CVE-2023-1111: scores [9.8, 9.8, 9.5] → avg = 9.7
    assert abs(cve_map["CVE-2023-1111"]["average_cvss_score"] - 9.7) < 0.01


def test_get_grouped_vulnerabilities_top_n():
    """Verify top_n slicing — mock get_int_arg to return 1 for top_n."""
    page = _make_vi_page(DUMMY_VULNERABILITY_INSTANCES)
    # get_int_arg reads from demisto.args() (XSOAR runtime pattern); patch it to
    # return 1 for top_n and the default page_size for the page_size call.
    call_count = {"n": 0}

    def mock_get_int_arg(key, default=None, required=False):
        call_count["n"] += 1
        if key == "top_n":
            return 1
        return default

    with patch("Axonius.make_api_call", return_value=_make_ok_response(page)), \
         patch("Axonius.get_int_arg", side_effect=mock_get_int_arg):
        result = get_grouped_vulnerabilities({})
    assert len(result.outputs) == 1


def test_get_grouped_vulnerabilities_no_instances():
    page = _make_vi_page([])
    with patch("Axonius.make_api_call", return_value=_make_ok_response(page)):
        result = get_grouped_vulnerabilities({})
    assert result.outputs == []
    assert "No vulnerability" in result.readable_output


def test_fetch_all_pages_pagination():
    """Verify _fetch_all_pages follows cursors until exhausted."""
    page1 = _make_vi_page(DUMMY_VULNERABILITY_INSTANCES[:2], cursor="page2")
    page2 = _make_vi_page(DUMMY_VULNERABILITY_INSTANCES[2:], cursor=None)

    with patch("Axonius.make_api_call", side_effect=[
        _make_ok_response(page1),
        _make_ok_response(page2),
    ]):
        all_assets = _fetch_all_pages("vulnerability_instances")

    assert len(all_assets) == len(DUMMY_VULNERABILITY_INSTANCES)
