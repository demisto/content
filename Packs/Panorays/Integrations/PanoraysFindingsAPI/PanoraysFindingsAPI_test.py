import json
import os
import pytest
import PanoraysFindingsAPI
from PanoraysFindingsAPI import Client, finding_list_command, verify_module, fetch_incidents_command


def load_test_data(filename: str) -> dict:
    """Load mock data from test_data directory."""
    with open(os.path.join(os.path.dirname(__file__), "test_data", filename)) as f:
        return json.load(f)


def get_client():
    return Client(base_url="https://test.com", verify=False, proxy=False, headers={})


def test_verify_module_success(mocker):
    client = get_client()
    mocker.patch.object(client, "_http_request", return_value={})
    assert verify_module(client) == "ok"


def test_verify_module_unauthorized(mocker):
    client = get_client()
    mocker.patch.object(client, '_http_request', side_effect=Exception("Unauthorized"))
    with pytest.raises(Exception, match="Authorization Error"):
        verify_module(client)


def test_finding_list_command_success(mocker):
    mock_response = load_test_data("findings.json")
    client = get_client()
    mocker.patch.object(client, "get_company_findings", return_value=mock_response)
    results = finding_list_command(client, {"limit": "1"})
    assert results.outputs[0]["id"] == "123"


def test_fetch_incidents_first_run(mocker):
    mock_response = load_test_data("findings.json")
    client = get_client()
    mocker.patch.object(client, "get_company_findings", return_value=mock_response)
    next_run, incidents = fetch_incidents_command(client=client, last_run={}, first_fetch_time="3 days", max_fetch=10)
    assert len(incidents) == 1


def test_fetch_incidents_no_new_data(mocker):
    mock_response = load_test_data("findings.json")
    client = get_client()
    mocker.patch.object(client, "get_company_findings", return_value=mock_response)
    # last_fetch is after the finding's insert_ts so nothing should be returned
    last_run = {"last_fetch": "2099-06-01T00:00:00Z"}
    next_run, incidents = fetch_incidents_command(client=client, last_run=last_run, first_fetch_time="3 days", max_fetch=10)
    assert len(incidents) == 0


def test_main_test_module_branch(mocker):
    """Tests the 'test-module' branch inside main() to boost coverage."""
    mocker.patch.object(PanoraysFindingsAPI.demisto, 'params', return_value={
        "apikey": "123",
        "url": "https://test.com",
        "insecure": False,
        "proxy": False
    })
    mocker.patch.object(PanoraysFindingsAPI.demisto, 'command', return_value="test-module")
    mocker.patch.object(PanoraysFindingsAPI, 'verify_module', return_value="ok")
    mock_results = mocker.patch.object(PanoraysFindingsAPI, 'return_results')

    PanoraysFindingsAPI.main()
    assert mock_results.called


def test_main_failure(mocker):
    """Tests the global error handler in main()."""
    mocker.patch.object(PanoraysFindingsAPI.demisto, 'params', side_effect=Exception("Global Error"))
    mock_error = mocker.patch.object(PanoraysFindingsAPI, 'return_error')

    PanoraysFindingsAPI.main()
    assert mock_error.called