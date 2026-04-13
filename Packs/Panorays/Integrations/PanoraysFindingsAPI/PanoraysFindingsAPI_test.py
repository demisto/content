import PanoraysFindingsAPI
from PanoraysFindingsAPI import Client, finding_list_command, verify_module, fetch_incidents_command
def get_client():
    return Client(base_url="https://test.com", verify=False, proxy=False, headers={})

def test_verify_module_success(mocker):
    client = get_client()
    mocker.patch.object(client, "_http_request", return_value={})
    assert verify_module(client) == "ok"

def test_verify_module_unauthorized(mocker):
    client = get_client()
    mocker.patch.object(client, '_http_request', side_effect=Exception("Unauthorized"))
    result = verify_module(client)
    assert "Authorization Error" in result

def test_finding_list_command_success(mocker):
    mock_response = {"data": [{"id": "123", "asset_name": "test", "status": "OPEN", "severity": "LOW", "category": "Human"}]}
    client = get_client()
    mocker.patch.object(client, "get_company_findings", return_value=mock_response)
    results = finding_list_command(client, {"limit": "1"})
    assert results.outputs[0]["id"] == "123"

def test_fetch_incidents_first_run(mocker):
    mock_response = {"data": [{"id": "1", "asset_name": "asset1", "insert_ts": "2026-04-10T10:00:00Z"}]}
    client = get_client()
    mocker.patch.object(client, "get_company_findings", return_value=mock_response)
    next_run, incidents = fetch_incidents_command(client=client, last_run={}, first_fetch_time="3 days", max_fetch=10)
    assert len(incidents) == 1

def test_fetch_incidents_no_new_data(mocker):
    mock_response = {"data": [{"id": "1", "asset_name": "old", "insert_ts": "2026-04-01T10:00:00Z"}]}
    client = get_client()
    mocker.patch.object(client, "get_company_findings", return_value=mock_response)
    last_run = {"last_fetch": "2026-04-05T00:00:00Z"}
    next_run, incidents = fetch_incidents_command(client=client, last_run=last_run, first_fetch_time="3 days", max_fetch=10)
    assert len(incidents) == 0

def test_main_test_module_branch(mocker):
    """Tests the 'test-module' branch inside main() to boost coverage."""
    mocker.patch.object(PanoraysFindingsAPI.demisto, 'params', return_value={"apikey": "123"})
    mocker.patch.object(PanoraysFindingsAPI.demisto, 'command', return_value="test-module")
    mocker.patch.object(PanoraysFindingsAPI, 'verify_module', return_value="ok")
    mock_results = mocker.patch.object(PanoraysFindingsAPI, 'return_results')
    
    PanoraysFindingsAPI.main()
    assert mock_results.called

def test_main_failure(mocker):
    """Tests the global error handler in main()."""
    # Now that the try block is at the top, this will be caught correctly
    mocker.patch.object(PanoraysFindingsAPI.demisto, 'params', side_effect=Exception("Global Error"))
    mock_error = mocker.patch.object(PanoraysFindingsAPI, 'return_error')
    
    PanoraysFindingsAPI.main()
    assert mock_error.called