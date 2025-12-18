import ShadowxSOCAI as mod
import demistomock as demisto


# === HELPER FUNCTION TESTS (from your original file) ===

def test_extract_task_id_variants():
    """Test the Task ID extraction helper."""
    assert mod._extract_task_id({"TaskId": "a"}) == "a"
    assert mod._extract_task_id({"taskId": "b"}) == "b"
    assert mod._extract_task_id({"data": {"taskID": "c"}}) == "c"
    assert mod._extract_task_id({"x": 1}) is None

def test_ensure_json_like_passthrough():
    """Test the JSON helper."""
    d = {"k": 1}
    assert mod._ensure_json_like(d) is d
    assert mod._ensure_json_like('{"k": 1}') == {"k": 1}
    assert mod._ensure_json_like("not json") == {"raw": "not json"}

# === MOCKER-BASED COMMAND TESTS (what the reviewer wants) ===

# Mock data for a successful API response
MOCK_SUBMIT_RESPONSE = {
    "TaskId": "f3f46d7e-4932-4b4a-9220-9fd9a6a4ad02",
    "Status": "Submitted"
}

MOCK_GET_RESPONSE = {
    "data": {
        "taskId": "f3f46d7e-4932-4b4a-9220-9fd9a6a4ad02",
        "taskName": "XSOAR submit",
        "status": "Completed",
        "response": "AI analysis complete.",
        "recommendation": "Block IP.",
        "riskSeverity": "High",
        "predictionScore": 95
    }
}

MOCK_PARAMS = {
    "url": "https://example.com",
    "credentials_api": {"password": "test_api_key"},
    "task_name": "Test Task"
}

def test_submit_command(mocker):
    """
    GIVEN:
       - User args for the submit command.
    WHEN:
       - shadowx-submit-task is called (without polling).
    THEN:
       - Ensure the API is called correctly.
       - Ensure the task ID and URL are returned to the context.
    """
    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={
        "log": "failed login",
        "ip_addr": "1.1.1.1",
        "user_name": "test-user"
    })
    
    # Mock the requests.Session object
    mock_session = mocker.MagicMock()
    mock_post = mocker.MagicMock()
    mock_post.status_code = 200
    mock_post.json.return_value = MOCK_SUBMIT_RESPONSE
    mock_session.post.return_value = mock_post
    mocker.patch.object(mod, '_new_session', return_value=mock_session)

    # Mock return_results
    mock_results = mocker.patch.object(demisto, 'results')

    # Run the command
    mod.shadowx_submit_task_command()

    # Verify API call
    expected_url = "https://example.com/Api/SecurityTasks/Create"
    expected_payload = {
        'SearchText': 'failed login',
        'IpAddr': '1.1.1.1',
        'UserName': 'test-user',
        'PolicyId': '',
        'TaskName': 'Test Task',
        'AssignedUserID': '',
        'AIDriverID': '',
        'PolicyID': '',
        'Subject': 'test-user',
        'SecurityLog': 'failed login [ip:1.1.1.1]',
        'Status': 1
    }
    mock_session.post.assert_called_with(
        expected_url,
        json=expected_payload,
        headers=mocker.ANY,  # We don't need to check headers as thoroughly
        verify=mocker.ANY,
        timeout=mocker.ANY
    )

    # Verify output
    # The command function calls return_results, it does not return the result itself.
    # We inspect what was passed to return_results.
    assert mock_results.call_count == 1
    results = mock_results.call_args[0][0]

    # results is a CommandResults object
    assert results.outputs_prefix == "ShadowxSOCAI"
    assert results.outputs['TaskSubmit']['TaskId'] == "f3f46d7e-4932-4b4a-9220-9fd9a6a4ad02"
    assert "SecurityTasks/Details?taskID=" in results.outputs['TaskSubmit']['TaskURL']

def test_get_task_command(mocker):
    """
    GIVEN:
       - A task_id arg.
    WHEN:
       - shadowx-get-task is called.
    THEN:
       - Ensure the API is called correctly.
       - Ensure the full task details are parsed and returned.
    """
    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={
        "task_id": "f3f46d7e-4932-4b4a-9220-9fd9a6a4ad02"
    })

    # Mock the requests.Session object
    mock_session = mocker.MagicMock()
    mock_get = mocker.MagicMock()
    mock_get.status_code = 200
    mock_get.json.return_value = MOCK_GET_RESPONSE
    mock_session.get.return_value = mock_get
    mocker.patch.object(mod, '_new_session', return_value=mock_session)

    # Mock return_results
    mock_results = mocker.patch.object(demisto, 'results')

    # Run the command
    mod.shadowx_get_task_command()

    # Verify API call
    expected_url = "https://example.com/Api/SecurityTasks/Details?taskID=f3f46d7e-4932-4b4a-9220-9fd9a6a4ad02"
    mock_session.get.assert_called_with(
        expected_url,
        headers=mocker.ANY,
        verify=mocker.ANY,
        timeout=mocker.ANY
    )

    # Verify output
    assert mock_results.call_count == 1
    results = mock_results.call_args[0][0]

    # results is a CommandResults object
    assert results.outputs_prefix == "ShadowxSOCAI.TaskResult"
    contents = results.outputs

    assert contents["TaskId"] == "f3f46d7e-4932-4b4a-9220-9fd9a6a4ad02"
    assert contents["RiskSeverity"] == "High"
    assert contents["PredictionScore"] == 95
    assert contents["Response"] == "AI analysis complete."