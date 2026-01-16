from datetime import datetime, timedelta
import pytest
import urllib3

from CommonServerPython import date_to_timestamp
from ProofpointThreatProtection import *

urllib3.disable_warnings()

""" CONSTANTS """

TEST_SERVER_IP_BINDING = "127.0.0.1"
TEST_SERVER_TCP_PORT = 8000
TEST_SERVER_BASE_URL = f"http://{TEST_SERVER_IP_BINDING}:{TEST_SERVER_TCP_PORT}/api/v1"
TEST_AUTH_HOST = f"http://{TEST_SERVER_IP_BINDING}:{TEST_SERVER_TCP_PORT}/v1"

ACCESS_TOKEN_VALUE = "TOKEN"

GOOD_ACCESS_TOKEN = {"access_token": ACCESS_TOKEN_VALUE, "expiry_time": date_to_timestamp(datetime.now() + timedelta(hours=1))}

EXPIRED_ACCESS_TOKEN = {
    "access_token": ACCESS_TOKEN_VALUE,
    "expiry_time": date_to_timestamp(datetime.now() + timedelta(hours=-1)),
}

GOOD_ACCESS_TOKEN_FROM_API = {"access_token": ACCESS_TOKEN_VALUE, "expires_in": 3600}

MOCK_SAFEBLOCK_ADD_ENTRY = {
    "action": "add",
    "attribute": "$hfrom",
    "operator": "equal",
    "value": "test@mydomain.com",
    "comment": "comment 1",
}

MOCK_SAFEBLOCK_LIST_API_RETURN = [
    {"attribute": "$hfrom", "operator": "equal", "value": "test@mydomain.com", "comment": "comment 1"},
    {"attribute": "$from", "operator": "equal", "value": "sample@example.com", "comment": "comment B"},
]

""" HELPER FUNCTIONS """


def mock_main(mocker, command, args={}):
    rc = Client(base_url=TEST_SERVER_BASE_URL, verify=False, proxy=False)

    # Prevent any accidental real HTTP calls
    mocker.patch.object(rc, "_http_request", return_value={})
    mocker.patch.object(rc, "get_access_token", return_value=ACCESS_TOKEN_VALUE)
    mocker.patch.object(rc, "get_args", return_value=args)

    mocker.patch.object(rc, "get_safelist", return_value={"entries": MOCK_SAFEBLOCK_LIST_API_RETURN})
    mocker.patch.object(rc, "get_blocklist", return_value={"entries": MOCK_SAFEBLOCK_LIST_API_RETURN})
    mocker.patch.object(rc, "safelist_add_delete", return_value={"status": "success"})
    mocker.patch.object(rc, "blocklist_add_delete", return_value={"status": "success"})

    return COMMANDS[command](rc, "CLUSTERID1")


""" TEST FUNCTIONS """


def test_non_expired_access_token_present(mocker):
    c = Client(base_url=TEST_SERVER_BASE_URL, verify=False)
    mocker.patch.object(c, "get_shared_integration_context", return_value=GOOD_ACCESS_TOKEN)
    obtained_token = c.get_access_token("CLID1", "CLSECRET1")
    assert obtained_token == ACCESS_TOKEN_VALUE


def test_expired_access_token(mocker):
    c = Client(base_url=TEST_SERVER_BASE_URL, verify=False)

    fixed_now_dt = datetime(2025, 6, 8, 10, 0, 0)
    expired_time = date_to_timestamp(fixed_now_dt - timedelta(hours=1), date_format="%Y-%m-%dT%H:%M:%S")
    expired_token_context = {"access_token": ACCESS_TOKEN_VALUE, "expiry_time": expired_time}

    mocker.patch.object(c, "get_shared_integration_context", return_value=expired_token_context)
    mocker.patch.object(c, "_http_request", return_value=GOOD_ACCESS_TOKEN_FROM_API)

    mocker.patch("ProofpointThreatProtection.datetime", wraps=datetime)
    mocker.patch("ProofpointThreatProtection.datetime.now", return_value=fixed_now_dt)

    expected_expiry_time = date_to_timestamp(fixed_now_dt, date_format="%Y-%m-%dT%H:%M:%S")
    expected_expiry_time += GOOD_ACCESS_TOKEN_FROM_API["expires_in"] * 1000 - 10
    expected_context_to_set = {"access_token": ACCESS_TOKEN_VALUE, "expiry_time": expected_expiry_time}

    mock_set_context = mocker.patch("ProofpointThreatProtection.set_integration_context")
    mocker.patch("ProofpointThreatProtection.get_integration_context", return_value=expected_context_to_set)

    obtained_token = c.get_access_token("CLID1", "CLSECRET1")

    mock_set_context.assert_called_once_with(expected_context_to_set)
    assert obtained_token == ACCESS_TOKEN_VALUE


def test_non_existent_access_token(mocker):
    c = Client(base_url=TEST_SERVER_BASE_URL, verify=False)
    mocker.patch.object(c, "get_shared_integration_context", return_value={})
    mocker.patch.object(c, "_http_request", return_value=GOOD_ACCESS_TOKEN_FROM_API)

    # Fixed datetime object
    fixed_now_dt = datetime(2025, 6, 8, 10, 0, 0)

    # Mock datetime.datetime.now() correctly
    mocked_datetime = mocker.patch("ProofpointThreatProtection.datetime")
    mocked_datetime.now.return_value = fixed_now_dt
    mocked_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)  # still allow datetime(…) calls

    expected_expiry_time = date_to_timestamp(fixed_now_dt, date_format="%Y-%m-%dT%H:%M:%S")
    expected_expiry_time += GOOD_ACCESS_TOKEN_FROM_API.get("expires_in", 0) * 1000 - 10
    expected_context_to_set = {"access_token": ACCESS_TOKEN_VALUE, "expiry_time": expected_expiry_time}

    mock_set_context = mocker.patch.object(c, "set_shared_integration_context")
    mocker.patch("CommonServerPython.get_integration_context", return_value=expected_context_to_set)

    obtained_token = c.get_access_token("CLID1", "CLSECRET1")

    mock_set_context.assert_called_once_with(expected_context_to_set)
    assert obtained_token == ACCESS_TOKEN_VALUE


def test_bad_get_access_token_request(mocker):
    c = Client(base_url=TEST_SERVER_BASE_URL, verify=False)
    mocker.patch.object(c, "get_shared_integration_context", return_value={})
    mocker.patch.object(c, "get_auth_host", return_value=TEST_AUTH_HOST)
    mocker.patch.object(
        c,
        "_http_request",
        side_effect=Exception("Error occurred while creating an access token. Please check the instance configuration."),
    )
    mock_set_context = mocker.patch.object(c, "set_shared_integration_context")

    with pytest.raises(Exception) as error_info:
        c.get_access_token("CLID1", "CLSECRET1")

    assert str(error_info.value).startswith("Error occurred while creating an access token")
    mock_set_context.assert_not_called()


def test_list_safelist(mocker):
    return_obj = mock_main(mocker, "proofpoint-tp-safelist-list").outputs["Safelist"]
    assert return_obj == MOCK_SAFEBLOCK_LIST_API_RETURN


def test_list_blocklist(mocker):
    return_obj = mock_main(mocker, "proofpoint-tp-blocklist-list").outputs["Blocklist"]
    assert return_obj == MOCK_SAFEBLOCK_LIST_API_RETURN


def test_add_to_safelist(mocker):
    return_obj = mock_main(mocker, "proofpoint-tp-safelist-add-entry", args=MOCK_SAFEBLOCK_ADD_ENTRY)
    assert return_obj.outputs["Safelist Entry Added"] == "Success"


def test_add_to_blocklist(mocker):
    return_obj = mock_main(mocker, "proofpoint-tp-blocklist-add-entry", args=MOCK_SAFEBLOCK_ADD_ENTRY)
    assert return_obj.outputs["Blocklist Entry Added"] == "Success"


def test_delete_from_safelist(mocker):
    return_obj = mock_main(mocker, "proofpoint-tp-safelist-delete-entry", args=MOCK_SAFEBLOCK_ADD_ENTRY)
    assert return_obj.outputs["Safelist Entry Deleted"] == "Success"


def test_delete_from_blocklist(mocker):
    return_obj = mock_main(mocker, "proofpoint-tp-blocklist-delete-entry", args=MOCK_SAFEBLOCK_ADD_ENTRY)
    assert return_obj.outputs["Blocklist Entry Deleted"] == "Success"


def test_parse_params(mocker):
    client_id, client_secret, base_url, cluster_id, verify_certificate, proxy = parse_params(
        {
            "credentials": {"username": "client_id", "password": "client_secret"},
            "url": "base_url",
            "cluster_id": "cluster_id",
            "verify_certificate": True,
            "proxy": True,
        }
    )

    assert client_id == "client_id"
    assert client_secret == "client_secret"
    assert base_url == "base_url"
    assert cluster_id == "cluster_id"
    assert verify_certificate is True
    assert proxy is True
