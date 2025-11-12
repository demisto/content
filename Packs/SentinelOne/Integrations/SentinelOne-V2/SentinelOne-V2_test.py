import json
import pytest
import demistomock as demisto
from importlib import import_module
import os
import sys

sentinelone_v2 = import_module("SentinelOne-V2")
main = sentinelone_v2.main


def util_load_json(path):
    # Always resolve path relative to this test file's directory
    base = os.path.dirname(__file__)
    with open(os.path.join(base, path), encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture()
def demisto_mocker_2_1(mocker):
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "token": "token",
            "url": "https://usea1.sentinelone.net",
            "api_version": "2.1",
            "fetch_threat_rank": "4",
            "fetch_type": "Threats",
        },
    )
    mocker.patch.object(demisto, "getLastRun", return_value={"time": 1558541949000})
    mocker.patch.object(demisto, "incidents")


@pytest.fixture()
def demisto_mocker_2_0(mocker):
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "token": "token",
            "url": "https://usea1.sentinelone.net",
            "api_version": "2.0",
            "fetch_threat_rank": "4",
            "fetch_type": "Threats",
        },
    )
    mocker.patch.object(demisto, "getLastRun", return_value={"time": 1558541949000})
    mocker.patch.object(demisto, "incidents")
    mocker.patch.object(demisto, "results")


def test_fetch_incidents__2_1(mocker, requests_mock, demisto_mocker_2_1):
    """
    When:
        fetch-incident and API version is 2.1
    Returns:
        All the threats received by the API as incidents regardless to the rank.
    """
    raw_threat_response = util_load_json("test_data/get_threats_2_1_raw_response.json")
    incidents_for_fetch = util_load_json("test_data/incidents_2_1.json")
    mocker.patch.object(demisto, "command", return_value="fetch-incidents")
    requests_mock.get("https://usea1.sentinelone.net/web/api/v2.1/threats", json=raw_threat_response)

    main()

    assert demisto.incidents.call_count == 1
    incidents = demisto.incidents.call_args[0][0]
    assert len(incidents) == 4
    assert incidents[0]["occurred"] == "2019-09-15T12:05:49.095889Z"
    assert incidents[1]["occurred"] == "2019-09-15T12:14:42.440985Z"
    assert incidents[2]["occurred"] == "2019-09-15T12:14:43.349807Z"
    assert incidents[3]["occurred"] == "2019-09-15T12:14:44.069617Z"
    assert incidents_for_fetch == incidents


def test_fetch_incidents__2_0(mocker, requests_mock, demisto_mocker_2_0):
    """
    When:
        fetch-incident and API version is 2.0
    Returns:
        List of incidents with rank threshold matches to the fetch_threat_rank.
    """
    raw_threat_response = util_load_json("test_data/get_threats_2_0_raw_response.json")
    incidents_for_fetch = util_load_json("test_data/incidents_2_0.json")
    mocker.patch.object(demisto, "command", return_value="fetch-incidents")
    requests_mock.get("https://usea1.sentinelone.net/web/api/v2.0/threats", json=raw_threat_response)

    main()

    assert demisto.incidents.call_count == 1
    incidents = demisto.incidents.call_args[0][0]
    assert len(incidents) == 2
    assert incidents[0]["occurred"] == "2019-09-15T12:05:49.095889Z"
    assert incidents[1]["occurred"] == "2019-09-15T12:14:42.440985Z"
    assert incidents_for_fetch == incidents


def test_get_threats_outputs():
    """
    When:
        parsing raw response from the API to XSOAR output
    Returns:
        List of threat outputs.
    """
    raw_threat_response = util_load_json("test_data/get_threats_2_1_raw_response.json")["data"]
    expected = util_load_json("test_data/threats_outputs.json")
    threats_output = list(sentinelone_v2.get_threats_outputs(raw_threat_response))
    assert expected == threats_output


def test_get_agents_outputs():
    """
    When:
        parsing raw response of agents from the API to XSOAR output
    Returns:
        List of agents.
    """
    raw_agent_response = util_load_json("test_data/agents_raw_response.json")
    expected = util_load_json("test_data/agent_outputs.json")
    agent_output = list(sentinelone_v2.get_agents_outputs(raw_agent_response))
    assert expected == agent_output


def test_fetch_file(mocker, requests_mock):
    """
    When:
        fetch file request submitted
    Returns
        "String that it was successfully initiated"
    """
    agent_id = 1
    requests_mock.post(f"https://usea1.sentinelone.net/web/api/v2.1/agents/{agent_id}/actions/fetch-files", json={})

    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-fetch-file")
    mocker.patch.object(
        demisto,
        "args",
        return_value={"agent_id": agent_id, "file_path": "/does/not/matter/for/test", "password": "doesnotmatterfortest"},
    )
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    sentinelone_v2.return_results.assert_called_once_with(
        f"Intiated fetch-file action for /does/not/matter/for/test on Agent {agent_id}"
    )


def test_download_fetched_file(mocker, requests_mock, capfd):
    """
    When:
        request sent to retrieve a downloaded file
    Return:
        File entry of the file downloaded
    """
    agent_id = 1
    test_data_path = os.path.join(os.path.dirname(__file__), "test_data", "download_fetched_file.zip")
    with open(test_data_path, "rb") as f:
        dffzip_contents = f.read()

    requests_mock.get(f"https://usea1.sentinelone.net/web/api/v2.1/agents/{agent_id}/uploads/1", content=dffzip_contents)

    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-download-fetched-file")
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "agent_id": agent_id,
            "activity_id": "1",
            "password": "password",  # This matches the password of the `download_fetched_file.zip` file in test_data
        },
    )
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results, file_result = call[0].args[0]

    assert command_results.outputs["Path"] == "download_fetched_file/"


def test_get_blocklist(mocker, requests_mock):
    """
    When:
        Request is made to retrieve the blocklist
    Return:
        The blocklist
    """
    raw_blockist_response = util_load_json("test_data/get_blocklist.json")
    blocklist_results = util_load_json("test_data/get_blocklist_results.json")
    requests_mock.get(
        "https://usea1.sentinelone.net/web/api/v2.1/restrictions?tenant=True&groupIds=group_id&siteIds=site_id"
        "&accountIds=account_id&skip=0&limit=1&sortBy=updatedAt&sortOrder=desc",
        json=raw_blockist_response,
    )

    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-get-blocklist")
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "offset": "0",
            "limit": "1",
            "group_ids": ["group_id"],
            "site_ids": ["site_id"],
            "account_ids": ["account_id"],
            "global": "true",
        },
    )

    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]

    assert command_results.outputs == blocklist_results


def test_remove_hash_from_blocklist_global(mocker, requests_mock):
    """
    When:
        A hash is removed from the blocklist globally (no scope)
    Return:
        Status that it has been removed from the blocklist
    """
    sha1 = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"
    url = (
        "https://usea1.sentinelone.net/web/api/v2.1/restrictions"
        "?tenant=True&skip=0&limit=4&sortBy=updatedAt&sortOrder=asc&value__contains=" + sha1
    )
    raw_blockist_response = util_load_json("test_data/remove_hash_from_blocklist.json")
    requests_mock.get(url, json=raw_blockist_response)
    requests_mock.delete("https://usea1.sentinelone.net/web/api/v2.1/restrictions", json={"data": []})

    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-remove-hash-from-blocklist")
    mocker.patch.object(demisto, "args", return_value={"sha1": sha1})

    mock_return_results = mocker.patch.object(sentinelone_v2, "return_results")

    main()

    call = mock_return_results.call_args_list
    outputs = call[0].args[0].outputs

    assert outputs["hash"] == sha1
    assert outputs["status"] == "Removed 1 entries from blocklist"


def test_remove_hash_from_blocklist_global_sha256(mocker, requests_mock):
    """
    When:
        A SHA256 hash is removed from the blocklist globally (no scope)
    Return:
        Status that it has been removed from the blocklist
    """
    sha256 = "3a7bd3e2360a3d5bca2c7e6f3c4d7b1a2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8"
    url = (
        "https://usea1.sentinelone.net/web/api/v2.1/restrictions"
        "?tenant=True&skip=0&limit=4&sortBy=updatedAt&sortOrder=asc&value__contains=" + sha256
    )
    raw_blockist_response = util_load_json("test_data/remove_hash_from_blocklist_sha256.json")
    requests_mock.get(url, json=raw_blockist_response)
    requests_mock.delete("https://usea1.sentinelone.net/web/api/v2.1/restrictions", json={"data": []})

    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-remove-hash-from-blocklist")
    mocker.patch.object(demisto, "args", return_value={"sha256Value": sha256})

    mock_return_results = mocker.patch.object(sentinelone_v2, "return_results")

    main()

    call = mock_return_results.call_args_list
    outputs = call[0].args[0].outputs

    assert outputs["hash"] == sha256
    assert outputs["status"] == "Removed 1 entries from blocklist"


def test_remove_hash_from_blocklist_multiple_site_scope(mocker, requests_mock):
    mocker.patch.object(sys, "exit")
    """
    When:
        A hash is removed from the blocklist for multiple sites
    Return:
        Status that it has been removed from the blocklist
    """
    sha1 = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"
    raw_blockist_response = util_load_json("test_data/remove_hash_from_blocklist.json")
    requests_mock.get(
        "https://usea1.sentinelone.net/web/api/v2.1/restrictions",
        json=raw_blockist_response,
        request_headers={"Authorization": "ApiToken token"},
        complete_qs=False,  # ignore exact query string match
    )

    requests_mock.delete("https://usea1.sentinelone.net/web/api/v2.1/restrictions", json={"data": []})

    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-remove-hash-from-blocklist")
    mocker.patch.object(
        demisto, "args", return_value={"sha1": sha1, "os_type": "WINDOWS", "site_ids": "2134673222384,2144637475766"}
    )

    mock_return_results = mocker.patch.object(sentinelone_v2, "return_results")

    main()

    call = mock_return_results.call_args_list
    outputs = call[0].args[0].outputs

    assert outputs["hash"] == sha1
    assert outputs["status"] == "Removed 1 entries from blocklist"


def test_remove_hash_from_blocklist_single_site_scope(mocker, requests_mock):
    """
    When:
        A hash is removed from the blocklist for a specific site
    Return:
        Status that it has been removed from the blocklist
    """
    sha1 = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"
    url = (
        "https://usea1.sentinelone.net/web/api/v2.1/restrictions"
        "?tenant=False&siteIds=2134673222384&skip=0&limit=20&osTypes=WINDOWS&sortBy=updatedAt&sortOrder=asc&value__contains="
        + sha1
    )
    raw_blockist_response = util_load_json("test_data/remove_hash_from_blocklist.json")
    requests_mock.get(url, json=raw_blockist_response)
    requests_mock.delete("https://usea1.sentinelone.net/web/api/v2.1/restrictions", json={"data": []})

    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-remove-hash-from-blocklist")
    mocker.patch.object(demisto, "args", return_value={"sha1": sha1, "os_type": "WINDOWS", "site_ids": "2134673222384"})

    mock_return_results = mocker.patch.object(sentinelone_v2, "return_results")

    main()

    call = mock_return_results.call_args_list
    outputs = call[0].args[0].outputs

    assert outputs["hash"] == sha1
    assert outputs["status"] == "Removed 1 entries from blocklist"


def test_remove_hash_from_blocklist_wrong_site_scope(mocker, requests_mock):
    """
    When:
        An invalid site_id is provided, the response should indicate that the hash is not on the blocklist.
    Return:
        Status indicating the hash is not found on the blocklist.
    """
    sha1 = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"

    # Construct the URL with the invalid site ID
    url = (
        f"https://usea1.sentinelone.net/web/api/v2.1/restrictions"
        f"?tenant=False&siteIds=2134673222300&skip=0&limit=20&osTypes=WINDOWS&sortBy=updatedAt&sortOrder=asc&value__contains={sha1}"
    )

    # Simulate the hash not being on the blocklist (empty list)
    raw_blocklist_response = {"data": []}  # Empty response indicates hash not found

    # Mock the GET request to return the blocklist response indicating the hash is not on the blocklist
    requests_mock.get(url, json=raw_blocklist_response)

    # Mock the DELETE request (this should not be called as the hash is not found)
    requests_mock.delete("https://usea1.sentinelone.net/web/api/v2.1/restrictions", json={"data": []})

    # Mocking the 'demisto' environment as in the reference test
    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-remove-hash-from-blocklist")
    mocker.patch.object(demisto, "args", return_value={"sha1": sha1, "os_type": "WINDOWS", "site_ids": "2134673222300"})

    # Patch the return_results function to capture the result of the command execution
    mock_return_results = mocker.patch.object(sentinelone_v2, "return_results")

    # Run the main function which triggers the integration logic
    main()

    # Capture the call and assert the correct outputs
    call = mock_return_results.call_args_list
    outputs = call[0].args[0].outputs

    # Assertions for the test
    assert outputs["hash"] == sha1
    assert outputs["status"] == "Not on blocklist"  # Status should indicate hash is not on blocklist

    # Ensure that the GET and DELETE requests were called
    assert len(requests_mock.request_history) == 1  # Only one GET request, no DELETE since hash is not found
    assert requests_mock.request_history[0].method == "GET"  # First request is GET

    # Ensure the GET request was called with the correct URL (with the invalid site_id)
    assert requests_mock.request_history[0].url == url


def test_remove_hash_from_blocklist_invalid_site_id(mocker, requests_mock):
    """
    When:
        An invalid site_id (e.g., site_id = 0) is provided, the response should indicate that the site_id is invalid.
    Return:
        Status indicating an invalid site_id error.
    """
    sha1 = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"

    # Construct the URL with an invalid site ID (0)
    url = (
        f"https://usea1.sentinelone.net/web/api/v2.1/restrictions"
        f"?tenant=False&siteIds=0&skip=0&limit=20&osTypes=WINDOWS&sortBy=updatedAt&sortOrder=asc&value__contains={sha1}"
    )

    # Mocking the error response from SentinelOne API for invalid siteId
    error_response = {
        "errors": [
            {
                "code": 4000010,
                "detail": "siteIds: 0: Must be greater than or equal to 100000000000000000.",
                "title": "Validation Error",
            }
        ]
    }

    # Mock the GET request to return the error response for invalid siteId
    requests_mock.get(url, json=error_response, status_code=400)

    # Mock the DELETE request (this should not be called due to the error)
    requests_mock.delete("https://usea1.sentinelone.net/web/api/v2.1/restrictions", json={"data": []})

    # Mocking the 'demisto' environment as in the reference test
    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-remove-hash-from-blocklist")
    mocker.patch.object(demisto, "args", return_value={"sha1": sha1, "os_type": "WINDOWS", "site_ids": "0"})

    # Patch the return_results function to capture the result of the command execution
    mock_return_results = mocker.patch.object(sentinelone_v2, "return_results")

    # Run the main function which triggers the integration logic
    main()

    # Capture the call and assert the correct outputs
    call = mock_return_results.call_args_list
    outputs = call[0].args[0].outputs

    # Assertions for the test
    assert outputs["hash"] == sha1
    assert outputs["status"] == "Error: Invalid siteId - siteIds: 0: Must be greater than or equal to 100000000000000000."

    # Ensure that the GET request was called with the correct URL (with invalid site_id)
    assert len(requests_mock.request_history) == 1  # Only one GET request due to the error
    assert requests_mock.request_history[0].method == "GET"  # First request is GET

    # Ensure the GET request was called with the correct URL (with the invalid site_id)
    assert requests_mock.request_history[0].url == url


def test_remove_hash_from_blocklist_multiple_group_scope(mocker, requests_mock):
    """
    When:
        A hash is removed from the blocklist for multiple group
    Return:
        Status that it has been removed from the blocklist
    """
    sha1 = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"
    url = (
        "https://usea1.sentinelone.net/web/api/v2.1/restrictions"
        "?tenant=False&groupIds=3327473684756,3365722136475&skip=0&limit=20&osTypes=WINDOWS&sortBy=updatedAt&sortOrder=asc&value__contains="
        + sha1
    )
    raw_blockist_response = util_load_json("test_data/remove_hash_from_blocklist.json")
    requests_mock.get(url, json=raw_blockist_response)
    requests_mock.delete("https://usea1.sentinelone.net/web/api/v2.1/restrictions", json={"data": []})

    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-remove-hash-from-blocklist")
    mocker.patch.object(
        demisto, "args", return_value={"sha1": sha1, "os_type": "WINDOWS", "group_ids": "3327473684756,3365722136475"}
    )

    mock_return_results = mocker.patch.object(sentinelone_v2, "return_results")

    main()

    call = mock_return_results.call_args_list
    outputs = call[0].args[0].outputs

    assert outputs["hash"] == sha1
    assert outputs["status"] == "Removed 1 entries from blocklist"


def test_remove_hash_from_blocklist_single_group_scope(mocker, requests_mock):
    """
    When:
        A hash is removed from the blocklist for a specific group
    Return:
        Status that it has been removed from the blocklist
    """
    sha1 = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"
    url = (
        "https://usea1.sentinelone.net/web/api/v2.1/restrictions"
        "?tenant=False&groupIds=3327473684756&skip=0&limit=20&osTypes=WINDOWS&sortBy=updatedAt&sortOrder=asc&value__contains="
        + sha1
    )
    raw_blockist_response = util_load_json("test_data/remove_hash_from_blocklist.json")
    requests_mock.get(url, json=raw_blockist_response)
    requests_mock.delete("https://usea1.sentinelone.net/web/api/v2.1/restrictions", json={"data": []})

    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-remove-hash-from-blocklist")
    mocker.patch.object(demisto, "args", return_value={"sha1": sha1, "os_type": "WINDOWS", "group_ids": "3327473684756"})

    mock_return_results = mocker.patch.object(sentinelone_v2, "return_results")

    main()

    call = mock_return_results.call_args_list
    outputs = call[0].args[0].outputs

    assert outputs["hash"] == sha1
    assert outputs["status"] == "Removed 1 entries from blocklist"


def test_remove_hash_from_blocklist_multiple_account_scope(mocker, requests_mock):
    """
    When:
        A hash is removed from the blocklist for multiple account
    Return:
        Status that it has been removed from the blocklist
    """
    sha1 = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"
    url = (
        "https://usea1.sentinelone.net/web/api/v2.1/restrictions"
        "?tenant=False&accountIds=4437562837465,4467983212746&skip=0&limit=20&osTypes=WINDOWS&sortBy=updatedAt&sortOrder=asc&value__contains="
        + sha1
    )
    raw_blockist_response = util_load_json("test_data/remove_hash_from_blocklist.json")
    requests_mock.get(url, json=raw_blockist_response)
    requests_mock.delete("https://usea1.sentinelone.net/web/api/v2.1/restrictions", json={"data": []})

    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-remove-hash-from-blocklist")
    mocker.patch.object(
        demisto, "args", return_value={"sha1": sha1, "os_type": "WINDOWS", "account_ids": "4437562837465,4467983212746"}
    )

    mock_return_results = mocker.patch.object(sentinelone_v2, "return_results")

    main()

    call = mock_return_results.call_args_list
    outputs = call[0].args[0].outputs

    assert outputs["hash"] == sha1
    assert outputs["status"] == "Removed 1 entries from blocklist"


def test_remove_hash_from_blocklist_single_account_scope(mocker, requests_mock):
    """
    When:
        A hash is removed from the blocklist for a specific account
    Return:
        Status that it has been removed from the blocklist
    """
    sha1 = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"
    url = (
        "https://usea1.sentinelone.net/web/api/v2.1/restrictions"
        "?tenant=False&accountIds=4437562837465&skip=0&limit=20&osTypes=WINDOWS&sortBy=updatedAt&sortOrder=asc&value__contains="
        + sha1
    )
    raw_blockist_response = util_load_json("test_data/remove_hash_from_blocklist.json")
    requests_mock.get(url, json=raw_blockist_response)
    requests_mock.delete("https://usea1.sentinelone.net/web/api/v2.1/restrictions", json={"data": []})

    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-remove-hash-from-blocklist")
    mocker.patch.object(demisto, "args", return_value={"sha1": sha1, "os_type": "WINDOWS", "account_ids": "4437562837465"})

    mock_return_results = mocker.patch.object(sentinelone_v2, "return_results")

    main()

    call = mock_return_results.call_args_list
    outputs = call[0].args[0].outputs

    assert outputs["hash"] == sha1
    assert outputs["status"] == "Removed 1 entries from blocklist"


def test_add_hash_to_blocklist_args_multiple_site_ids(mocker, requests_mock):
    """
    Test: args multiple site_ids
    """
    sha1 = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"
    url = "https://usea1.sentinelone.net/web/api/v2.1/restrictions"
    requests_mock.post(url, json={"data": []})

    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "token": "token",
            "url": "https://usea1.sentinelone.net",
            "api_version": "2.1",
            "fetch_threat_rank": "4",
        },
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-add-hash-to-blocklist")
    args = {"sha1": sha1, "os_type": "WINDOWS", "site_ids": "2134673222384,2144637475766"}
    mocker.patch.object(demisto, "args", return_value=args)
    mock_return_results = mocker.patch.object(sentinelone_v2, "return_results")

    main()

    request_body = requests_mock.last_request.json()
    request_filter = request_body.get("filter")

    assert sorted(request_filter.get("siteIds").split(",")) == sorted(["2134673222384", "2144637475766"])

    call = mock_return_results.call_args_list
    assert call, "return_results not called"

    result = call[0].args[0]
    outputs = result.outputs

    assert outputs["hash"] == sha1

    actual_sites = sorted(outputs["status"].replace("Added to site: ", "").replace(" blocklist", "").split(","))
    expected_sites = sorted(["2134673222384", "2144637475766"])
    assert actual_sites == expected_sites

    assert sorted(outputs["site_ids"].split(",")) == expected_sites


def test_add_hash_to_blocklist_args_single_site_id(mocker, requests_mock):
    """
    Test: arg single site_id
    """
    sha1 = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"
    url = "https://usea1.sentinelone.net/web/api/v2.1/restrictions"
    requests_mock.post(url, json={"data": []})
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "token": "token",
            "url": "https://usea1.sentinelone.net",
            "api_version": "2.1",
            "fetch_threat_rank": "4",
        },
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-add-hash-to-blocklist")
    args = {"sha1": sha1, "os_type": "WINDOWS", "site_ids": "2134673222384"}
    mocker.patch.object(demisto, "args", return_value=args)
    mock_return_results = mocker.patch.object(sentinelone_v2, "return_results")

    main()

    request_body = requests_mock.last_request.json()
    request_filter = request_body.get("filter")
    assert request_filter.get("siteIds") == "2134673222384"

    call = mock_return_results.call_args_list
    assert call, "return_results not called"

    result = call[0].args[0]
    outputs = result.outputs

    assert outputs["hash"] == sha1
    assert outputs["status"] == "Added to site: 2134673222384 blocklist"
    assert outputs.get("site_ids") == "2134673222384"


def test_add_hash_to_blocklist_invalid_site_id(mocker, requests_mock):
    sha1 = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"

    error_response = {
        "errors": [
            {
                "code": 4000010,
                "detail": "siteIds: 0: Must be greater than or equal to 100000000000000000.",
                "title": "Validation Error",
            }
        ]
    }

    # Mock the POST request to the SentinelOne API to return validation error
    requests_mock.post(
        "https://usea1.sentinelone.net/web/api/v2.1/restrictions",
        json=error_response,
        status_code=400,
    )

    # Patch demisto.args() to provide inputs
    mocker.patch.object(demisto, "args", return_value={"sha1": sha1, "os_type": "WINDOWS", "site_ids": "0"})

    # Patch demisto.params() to provide integration params
    mocker.patch.object(
        demisto, "params", return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1"}
    )

    # Patch demisto.command() to simulate command name
    mocker.patch.object(demisto, "command", return_value="sentinelone-add-hash-to-blocklist")

    # Patch return_results to capture the output
    mock_return_results = mocker.patch.object(sentinelone_v2, "return_results")

    # Run main() which will call add_hash_to_blocklist internally
    main()

    # Check what was returned
    call_args = mock_return_results.call_args[0][0]
    outputs = call_args.outputs

    assert outputs["hash"] == sha1
    assert "Invalid siteId" in outputs["status"] or "Validation Error" in outputs["status"]

    # You can also assert the requests_mock history to confirm one POST call with the invalid site id
    assert len(requests_mock.request_history) == 1
    assert requests_mock.request_history[0].method == "POST"


def test_add_hash_to_blocklist_wrong_site_id(mocker, requests_mock):
    sha1 = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"

    error_response = {
        "errors": [
            {
                "code": 4000010,
                "detail": "Cannot find blocklist or exclusion for the requested scope [2163822726089822800]",
                "title": "Validation Error",
            }
        ]
    }

    # Mock the POST request to the SentinelOne API to return validation error
    requests_mock.post(
        "https://usea1.sentinelone.net/web/api/v2.1/restrictions",
        json=error_response,
        status_code=400,
    )

    # Patch demisto.args() to provide inputs
    mocker.patch.object(demisto, "args", return_value={"sha1": sha1, "os_type": "WINDOWS", "site_ids": "2163822726089822800"})

    # Patch demisto.params() to provide integration params
    mocker.patch.object(
        demisto, "params", return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1"}
    )

    # Patch demisto.command() to simulate command name
    mocker.patch.object(demisto, "command", return_value="sentinelone-add-hash-to-blocklist")

    # Patch return_results to capture the output
    mock_return_results = mocker.patch.object(sentinelone_v2, "return_results")

    # Run main() which will call add_hash_to_blocklist internally
    main()

    # Get what was returned by return_results()
    call_args = mock_return_results.call_args[0][0]

    outputs = call_args.outputs
    readable = call_args.readable_output

    assert outputs["hash"] == sha1
    assert "Invalid siteId" in outputs["status"] or "Validation Error" in outputs["status"]
    assert "Cannot find blocklist or exclusion for the requested scope" in readable

    # Confirm one POST call with the invalid site id was made
    assert len(requests_mock.request_history) == 1
    assert requests_mock.request_history[0].method == "POST"


def test_add_hash_to_blocklist_args_multiple_group_ids(mocker, requests_mock):
    """
    Test: args multiple group_ids
    """
    sha1 = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"
    url = "https://usea1.sentinelone.net/web/api/v2.1/restrictions"
    requests_mock.post(url, json={"data": []})
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "token": "token",
            "url": "https://usea1.sentinelone.net",
            "api_version": "2.1",
            "fetch_threat_rank": "4",
        },
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-add-hash-to-blocklist")
    args = {"sha1": sha1, "os_type": "WINDOWS", "group_ids": "3327473684756,3365722136475"}
    mocker.patch.object(demisto, "args", return_value=args)
    mock_return_results = mocker.patch.object(sentinelone_v2, "return_results")

    main()

    request_body = requests_mock.last_request.json()
    request_filter = request_body.get("filter")
    assert request_filter.get("groupIds") == "3327473684756,3365722136475"

    call = mock_return_results.call_args_list
    assert call, "return_results not called"

    result = call[0].args[0]
    outputs = result.outputs

    assert outputs["hash"] == sha1
    assert outputs["status"] == "Added to group: 3327473684756,3365722136475 blocklist"
    assert outputs.get("group_ids") == "3327473684756,3365722136475"


def test_add_hash_to_blocklist_args_single_group_id(mocker, requests_mock):
    """
    Test: args single group_id
    """
    sha1 = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"
    url = "https://usea1.sentinelone.net/web/api/v2.1/restrictions"
    requests_mock.post(url, json={"data": []})
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "token": "token",
            "url": "https://usea1.sentinelone.net",
            "api_version": "2.1",
            "fetch_threat_rank": "4",
        },
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-add-hash-to-blocklist")
    args = {"sha1": sha1, "os_type": "WINDOWS", "group_ids": "3327473684756"}
    mocker.patch.object(demisto, "args", return_value=args)
    mock_return_results = mocker.patch.object(sentinelone_v2, "return_results")

    main()

    request_body = requests_mock.last_request.json()
    request_filter = request_body.get("filter")
    assert request_filter.get("groupIds") == "3327473684756"

    call = mock_return_results.call_args_list
    assert call, "return_results not called"

    result = call[0].args[0]
    outputs = result.outputs

    assert outputs["hash"] == sha1
    assert outputs["status"] == "Added to group: 3327473684756 blocklist"
    assert outputs.get("group_ids") == "3327473684756"


def test_add_hash_to_blocklist_args_multiple_account_ids(mocker, requests_mock):
    """
    Test: args multiple account_ids
    """
    sha1 = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"
    url = "https://usea1.sentinelone.net/web/api/v2.1/restrictions"
    requests_mock.post(url, json={"data": []})
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "token": "token",
            "url": "https://usea1.sentinelone.net",
            "api_version": "2.1",
            "fetch_threat_rank": "4",
        },
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-add-hash-to-blocklist")
    args = {"sha1": sha1, "os_type": "WINDOWS", "account_ids": "4437562837465,4467983212746"}
    mocker.patch.object(demisto, "args", return_value=args)
    mock_return_results = mocker.patch.object(sentinelone_v2, "return_results")

    main()

    request_body = requests_mock.last_request.json()
    request_filter = request_body.get("filter")
    assert request_filter.get("accountIds") == "4437562837465,4467983212746"

    call = mock_return_results.call_args_list
    assert call, "return_results not called"

    result = call[0].args[0]
    outputs = result.outputs

    assert outputs["hash"] == sha1
    assert outputs["status"] == "Added to account: 4437562837465,4467983212746 blocklist"
    assert outputs.get("account_ids") == "4437562837465,4467983212746"


def test_add_hash_to_blocklist_args_single_account_id(mocker, requests_mock):
    """
    Test: args single account_id
    """
    sha1 = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"
    url = "https://usea1.sentinelone.net/web/api/v2.1/restrictions"
    requests_mock.post(url, json={"data": []})
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "token": "token",
            "url": "https://usea1.sentinelone.net",
            "api_version": "2.1",
            "fetch_threat_rank": "4",
        },
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-add-hash-to-blocklist")
    args = {"sha1": sha1, "os_type": "WINDOWS", "account_ids": "4437562837465"}
    mocker.patch.object(demisto, "args", return_value=args)
    mock_return_results = mocker.patch.object(sentinelone_v2, "return_results")

    main()

    request_body = requests_mock.last_request.json()
    request_filter = request_body.get("filter")
    assert request_filter.get("accountIds") == "4437562837465"

    call = mock_return_results.call_args_list
    assert call, "return_results not called"

    result = call[0].args[0]
    outputs = result.outputs

    assert outputs["hash"] == sha1
    assert outputs["status"] == "Added to account: 4437562837465 blocklist"
    assert outputs.get("account_ids") == "4437562837465"


def test_add_hash_to_blocklist_global_fallback(mocker, requests_mock):
    """
    Test: No args, global fallback
    """
    sha1 = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"
    url = "https://usea1.sentinelone.net/web/api/v2.1/restrictions"
    requests_mock.post(url, json={"data": []})
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "token": "token",
            "url": "https://usea1.sentinelone.net",
            "api_version": "2.1",
            "fetch_threat_rank": "4",
        },
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-add-hash-to-blocklist")
    args = {"sha1": sha1, "os_type": "WINDOWS"}
    mocker.patch.object(demisto, "args", return_value=args)
    mock_return_results = mocker.patch.object(sentinelone_v2, "return_results")

    main()

    request_body = requests_mock.last_request.json()
    request_filter = request_body.get("filter")
    assert request_filter.get("tenant") is True

    call = mock_return_results.call_args_list
    assert call, "return_results not called"

    result = call[0].args[0]
    outputs = result.outputs

    assert outputs["hash"] == sha1
    assert outputs["status"] == "Added to global blocklist"


def test_remove_item_from_whitelist(mocker, requests_mock):
    """
    When:
        A hash is removed from the whitelist
    Return:
        Status that it has been removed from the whitelist
    """
    raw_whitelist_response = util_load_json("test_data/remove_item_from_whitelist.json")
    requests_mock.get(
        "https://usea1.sentinelone.net/web/api/v2.1/exclusions?osTypes=windows&type=white_hash"
        "&value__contains=f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2&"
        "includeChildren=True&includeParents=True&limit=5",
        json=raw_whitelist_response,
    )
    requests_mock.delete("https://usea1.sentinelone.net/web/api/v2.1/exclusions", json={"data": []})

    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-remove-item-from-whitelist")
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            # 'sha1': 'f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2'
            "item": "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2",
            "exclusion_type": "white_hash",
            "os_type": "windows",
        },
    )

    mocker.patch.object(sentinelone_v2, "return_results")

    main()

    call = sentinelone_v2.return_results.call_args_list
    outputs = call[0].args[0].outputs

    assert outputs["item"] == "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"
    assert outputs["status"] == "Removed 1 entries from whitelist"


def test_update_threat_analyst_verdict(mocker, requests_mock):
    requests_mock.post("https://usea1.sentinelone.net/web/api/v2.1/threats/analyst-verdict", json={"data": {"affected": 1}})
    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-update-threats-verdict")
    mocker.patch.object(demisto, "args", return_value={"threat_ids": "1234567890", "verdict": "true_positive"})
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == [{"ID": "1234567890", "Updated": True, "Update": {"Action": "true_positive"}}]


def test_update_alert_analyst_verdict(mocker, requests_mock):
    requests_mock.post(
        "https://usea1.sentinelone.net/web/api/v2.1/cloud-detection/alerts/analyst-verdict", json={"data": {"affected": 1}}
    )
    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-update-alerts-verdict")
    mocker.patch.object(demisto, "args", return_value={"alert_ids": "1234567890", "verdict": "true_positive"})
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == [{"ID": "1234567890", "Updated": True, "Update": {"Action": "true_positive"}}]


def test_update_threat_status(mocker, requests_mock):
    requests_mock.post("https://usea1.sentinelone.net/web/api/v2.1/threats/incident", json={"data": {"affected": 1}})
    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-update-threats-status")
    mocker.patch.object(demisto, "args", return_value={"threat_ids": "1234567890", "status": "in_progress"})
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == [{"ID": "1234567890", "Updated": True, "Status": "in_progress"}]


def test_update_alert_status(mocker, requests_mock):
    requests_mock.post(
        "https://usea1.sentinelone.net/web/api/v2.1/cloud-detection/alerts/incident", json={"data": {"affected": 1}}
    )
    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-update-alerts-status")
    mocker.patch.object(demisto, "args", return_value={"alert_ids": "1234567890", "status": "in_progress"})
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == [{"ID": "1234567890", "Updated": True, "Status": "in_progress"}]


def test_create_star_rule(mocker, requests_mock):
    raw_star_rule_response = util_load_json("test_data/create_star_rule_response.json")
    requests_mock.post("https://usea1.sentinelone.net/web/api/v2.1/cloud-detection/rules", json=raw_star_rule_response)
    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-create-star-rule")
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "name": "sample",
            "description": "description",
            "query": "sample query",
            "query_type": "events",
            "rule_severity": "Low",
            "account_ids": "1234567890",
            "group_ids": "1234567890",
            "site_ids": "123456789",
            "expiration_mode": "Permanent",
            "expiration_date": "",
            "network_quarantine": "true",
            "treatAsThreat": "suspicious",
        },
    )
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == {}


def test_enable_star_rules(mocker, requests_mock):
    requests_mock.put("https://usea1.sentinelone.net/web/api/v2.1/cloud-detection/rules/enable", json={"data": {"affected": 1}})
    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-enable-star-rules")
    mocker.patch.object(demisto, "args", return_value={"rule_ids": "1234567890"})
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == [{"ID": "1234567890", "Enabled": True}]


def test_disable_star_rules(mocker, requests_mock):
    requests_mock.put("https://usea1.sentinelone.net/web/api/v2.1/cloud-detection/rules/disable", json={"data": {"affected": 1}})
    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-disable-star-rules")
    mocker.patch.object(demisto, "args", return_value={"rule_ids": "1234567890"})
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == [{"ID": "1234567890", "Disabled": True}]


def test_delete_star_rule(mocker, requests_mock):
    requests_mock.delete("https://usea1.sentinelone.net/web/api/v2.1/cloud-detection/rules", json={"data": {"affected": 1}})
    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-delete-star-rule")
    mocker.patch.object(demisto, "args", return_value={"rule_ids": "1234567890"})
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == [{"ID": "1234567890", "Deleted": True}]


def test_get_events(mocker, requests_mock):
    """
    Given:
    When: run get events
    Then: ensure the context output are as expected and contained the 'ProcessID' and 'EventID' as id keys
    """
    from CommonServerPython import CommandResults

    requests_mock.get(
        "https://usea1.sentinelone.net/web/api/v2.1/dv/events",
        json={
            "data": [{"ProcessID": "ProcessID_1", "EventID": "EventID_1"}, {"ProcessID": "ProcessID_2", "EventID": "EventID_2"}]
        },
    )
    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-get-events")
    mocker.patch.object(demisto, "args", return_value={"query_id": "1234567890"})
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    expected_context = (
        CommandResults(outputs_prefix="SentinelOne.Event", outputs_key_field=["ProcessID", "EventID"], outputs=[{}])
        .to_context()
        .get("EntryContext", {})
    )

    call = sentinelone_v2.return_results.call_args_list
    context_outputs = call[0].args[0].outputs
    assert all(key in context_outputs for key in expected_context)


def test_run_remote_script(mocker, requests_mock):
    """
    Given
        - required arguments i.e account_id, script_id, output_description, task_description, agent_ids and output_directory
    When
        - running sentinelone-run-remote-script command
    Then
        - returns a table of result had the affected process details
    """
    requests_mock.post("https://usea1.sentinelone.net/web/api/v2.1/remote-scripts/execute", json={"data": {"affected": 1}})
    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-run-remote-script")
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "account_ids": "1234567890",
            "script_id": "1",
            "output_destination": "test",
            "task_description": "test",
            "output_directory": "file",
            "agent_ids": "2",
        },
    )
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == {"affected": 1}


def test_initiate_endpoint_scan(mocker, requests_mock):
    """
    Given
        - required agent_ids argument
    When
        - running sentinelone-initiate-endpoint-scan command
    Then
        - returns a table of result had the details, like agent id and status of the scan
    """
    requests_mock.post("https://usea1.sentinelone.net/web/api/v2.1/agents/actions/initiate-scan", json={"data": {"affected": 1}})
    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-initiate-endpoint-scan")
    mocker.patch.object(demisto, "args", return_value={"agent_ids": "123456"})
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == [{"Agent ID": "123456", "Initiated": True}]


def test_get_installed_applications(mocker, requests_mock):
    """
    Given
        - required agent_ids argument
    When
        - running sentinelone-get-installed-applications command
    Then
        - returns a table of result had the list of installed applications on the provided agent
    """
    requests_mock.get(
        "https://usea1.sentinelone.net/web/api/v2.1/agents/applications",
        json={"data": [{"name": "test", "publisher": "abc", "size": 50, "version": "2.1", "installedDate": "2023-02-10"}]},
    )
    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-get-installed-applications")
    mocker.patch.object(demisto, "args", return_value={"agent_ids": "123456"})
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs == [
        {"InstalledOn": "2023-02-10", "Name": "test", "Publisher": "abc", "Size": 50, "Version": "2.1"}
    ]  # noqa


def test_get_remote_script_status(mocker, requests_mock):
    """
    Given
        - required parentTaskId argument
    When
        - running sentinelone-get-remote-script-task-status command
    Then
        - returns a table of result had the list of taskIds which are available on ParentTaskIds
    """
    json_output = {
        "data": [
            {
                "accountId": "1234567890",
                "accountName": "Metron Team",
                "agentComputerName": "MSEDGEWIN10",
                "agentId": "0987654321",
                "agentIsActive": True,
                "agentIsDecommissioned": False,
                "agentMachineType": "desktop",
                "agentOsType": "windows",
                "agentUuid": "25682583752987932878722323",
                "createdAt": "2024-07-30T06:43:22.938877Z",
                "description": "A test get cloud services",
                "detailedStatus": "Execution completed successfully",
                "groupId": "12334654321",
                "groupName": "Default Group",
                "id": "123456",
                "initiatedBy": "user",
                "initiatedById": "099999",
                "parentTaskId": "123456789",
                "scriptResultsSignature": "34324324324324235r24fe2r2333432",
                "siteId": "99999999",
                "siteName": "Default site",
                "status": "completed",
                "statusCode": None,
                "statusDescription": "Completed",
                "type": "script_execution",
                "updatedAt": "2024-07-30T06:44:50.881432Z",
            }
        ]
    }
    requests_mock.get("https://usea1.sentinelone.net/web/api/v2.1/remote-scripts/status", json=json_output)
    mocker.patch.object(
        demisto, "params", return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1"}
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-get-remote-script-task-status")
    mocker.patch.object(demisto, "args", return_value={"parent_task_id": "123456789"})
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert_response = util_load_json("test_data/get_remote_script_task_status.json")
    assert command_results.outputs == assert_response


def test_remote_script_results(mocker, requests_mock):
    """
    Given
        - required taskIds argument
    When
        - running sentinelone-get-remote-script-task-results command
    Then
        - returns file details
    """
    task_ids = "1234566"
    output_json = {
        "data": {"download_links": [{"downloadUrl": "https://url/1", "fileName": "file1.zip", "taskId": task_ids}], "errors": []}
    }
    requests_mock.post("https://usea1.sentinelone.net/web/api/v2.1/remote-scripts/fetch-files", json=output_json)
    requests_mock.get("https://url/1", json={})
    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-get-remote-script-task-results")
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "task_ids": task_ids,
        },
    )
    mocker.patch.object(sentinelone_v2, "return_results")
    main()
    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    outputs = command_results[0].outputs
    assert outputs[0].get("taskId") == task_ids
    assert outputs[0].get("fileName") == "file1.zip"
    assert outputs[0].get("downloadUrl") == "https://url/1"


def test_get_power_query_results(mocker, requests_mock):
    """
    Given
        - required query, from_date and to_date arguments
    When
        - running sentinelone-get-power-query-results command
    Then
        - returns a table of result if data present
    """
    json_output = util_load_json("test_data/get_power_query_response.json")
    requests_mock.get("https://usea1.sentinelone.net/web/api/v2.1/dv/events/pq-ping", json=json_output)
    mocker.patch.object(
        demisto, "params", return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1"}
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-get-power-query-results")
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "query_id": "pq123456789",
            "from_date": "2024-08-20T04:49:26.257525Z",
            "to_date": "2024-08-21T04:49:26.257525Z",
            "query": "event.time = * | columns eventTime = event.time, agentUuid = agent.uuid, siteId = site.id",
        },
    )
    mocker.patch.object(sentinelone_v2, "return_results")
    main()
    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    readable_output = (
        "### SentinelOne - Get Power Query Results for ID pqe5a4cbb0a0f0981f4125976b49fb0ebb"
        "\nRecommendation: Result set limited to 1000 rows by default. To display more rows, add"
        ' a command like "| limit 10000".\n\nSummary information and details about the power query'
        "\n|Agent Uuid|Event Time|Site Id|\n|---|---|---|\n"
        "| ed8f14f1-f35b-0eca-1c1e-e31e97aefc71 | 1724151854609 | 123456789 |\n"
        "| ed8f14f1-f35b-0eca-1c1e-e31e97aefc71 | 1724151823332 | 123456789 |\n"
    )
    assert command_results.readable_output == readable_output


def test_get_power_query_results_without_query_id(mocker, requests_mock):
    """
    Given
        - required query, from_date and to_date arguments
    When
        - running sentinelone-get-power-query-results command
    Then
        - returns a table of result if data present
    """
    json_output = util_load_json("test_data/get_power_query_response.json")
    requests_mock.post("https://usea1.sentinelone.net/web/api/v2.1/dv/events/pq", json=json_output)
    mocker.patch.object(
        demisto, "params", return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1"}
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-get-power-query-results")
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "from_date": "2024-08-20T04:49:26.257525Z",
            "to_date": "2024-08-21T04:49:26.257525Z",
            "query": "event.time = * | columns eventTime = event.time, agentUuid = agent.uuid, siteId = site.id",
        },
    )
    mocker.patch.object(sentinelone_v2, "return_results")
    main()
    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    readable_output = (
        "### SentinelOne - Get Power Query Results for ID pqe5a4cbb0a0f0981f4125976b49fb0ebb"
        "\nRecommendation: Result set limited to 1000 rows by default. To display more rows, add"
        ' a command like "| limit 10000".\n\nSummary information and details about the power query'
        "\n|Agent Uuid|Event Time|Site Id|\n|---|---|---|\n"
        "| ed8f14f1-f35b-0eca-1c1e-e31e97aefc71 | 1724151854609 | 123456789 |\n"
        "| ed8f14f1-f35b-0eca-1c1e-e31e97aefc71 | 1724151823332 | 123456789 |\n"
    )
    assert command_results.readable_output == readable_output


def test_get_remote_data_command(mocker, requests_mock):
    """
    Given
        - an incident ID on the remote system
    When
        - running get_remote_data_command with changes to make on an incident
    Then
        - returns the relevant incident entity from the remote system with the relevant incoming mirroring fields
    """
    requests_mock.get("https://usea1.sentinelone.net/web/api/v2.1/threats", json={"data": [{"name": "test", "id": "123456"}]})
    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="get-remote-data")
    mocker.patch.object(demisto, "args", return_value={"id": "123456", "lastUpdate": "321456"})
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = vars(call[0].args[0])
    assert command_results == {
        "mirrored_object": {"name": "test", "id": "123456", "incident_type": "SentinelOne Incident"},
        "entries": [],
    }


def test_list_installed_singularity_mark_apps(mocker, requests_mock):
    """
    Given
        - all of these are optional arguments, but for this case, providing the id argument
    When
        - running sentinelone-list-installed-singularity-marketplace-applications command
    Then
        - returns a table of result had the list of installed singularity marketplace applications
    """
    json_page_1 = util_load_json("test_data/get_singularity_marketplace_apps_page_1_response.json")

    json_page_2 = util_load_json("test_data/get_singularity_marketplace_apps_page_2_response.json")

    requests_mock.get("https://usea1.sentinelone.net/web/api/v2.1/singularity-marketplace/applications", json=json_page_1)
    requests_mock.get(
        "https://usea1.sentinelone.net/web/api/v2.1/singularity-marketplace/applications?cursor=1234", json=json_page_2
    )

    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-list-installed-singularity-marketplace-applications")
    mocker.patch.object(demisto, "args", return_value={"id": "123456"})
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]

    expected_outputs = expected_outputs = [
        {
            "ID": "123456",
            "Account": "SentinelOne",
            "AccountId": "1234567890",
            "ApplicationCatalogId": "90909090909090",
            "ApplicationCatalogName": "SentinelOne Threat Intelligence IOC Ingestion",
            "AlertMessage": "",
            "CreatedAt": "2025-01-23T13:11:23.12758",
            "Creator": "admin@user.sentinelone.net",
            "CreatorId": "212212121211212",
            "DesiredStatus": "active",
            "HasAlert": False,
            "LastEntityCreatedAt": "2025-01-23T13:11:23.127579",
            "Modifier": "admin@user.sentinelone.net",
            "ModifierId": "212212121211212",
            "ScopeId": "1230123012301230",
            "ScopeLevel": "account",
            "Status": "active",
            "UpdatedAt": "2025-01-23T13:11:25.96604",
            "ApplicationInstanceName": "SentinelOne Threat Intelligence IOC Ingestion",
        },
        {
            "ID": "123457",
            "Account": "SentinelOne",
            "AccountId": "1234567890",
            "ApplicationCatalogId": "90909090909090",
            "ApplicationCatalogName": "SentinelOne Threat Intelligence IOC Ingestion",
            "AlertMessage": "",
            "CreatedAt": "2025-01-23T13:11:23.12758",
            "Creator": "admin@user.sentinelone.net",
            "CreatorId": "212212121211212",
            "DesiredStatus": "active",
            "HasAlert": False,
            "LastEntityCreatedAt": "2025-01-23T13:11:23.127579",
            "Modifier": "admin@user.sentinelone.net",
            "ModifierId": "212212121211212",
            "ScopeId": "1230123012301230",
            "ScopeLevel": "account",
            "Status": "active",
            "UpdatedAt": "2025-01-23T13:11:25.96604",
            "ApplicationInstanceName": "SentinelOne Threat Intelligence IOC Ingestion",
        },
    ]
    assert command_results.outputs == expected_outputs
    assert requests_mock.call_count == 2, f"Expected 2 API calls, but got {requests_mock.call_count}"


def test_get_service_users(mocker, requests_mock):
    """
    Given
        - all of these are optional arguments, but for this case, providing the ids argument
    When
        - running sentinelone-get-service-users command
    Then
        - returns a table of result had the list of service users
    """
    json_page_1 = util_load_json("test_data/get_service_users_page_1_response.json")
    json_page_2 = util_load_json("test_data/get_service_users_page_2_response.json")
    requests_mock.get("https://usea1.sentinelone.net/web/api/v2.1/service-users", json=json_page_1)
    requests_mock.get("https://usea1.sentinelone.net/web/api/v2.1/service-users?cursor=1234", json=json_page_2)
    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-get-service-users")
    mocker.patch.object(demisto, "args", return_value={"ids": "123456"})
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    expected_outputs = [
        {
            "ID": "123456",
            "ApiTokenCreatedAt": "2025-01-30T10:12:09.458490Z",
            "ApiTokenExpiresAt": "2025-03-01T10:12:08Z",
            "CreatedAt": "2025-01-30T10:12:09.407923Z",
            "CreatedById": "123456789099",
            "CreatedByName": "sentinelone",
            "Description": None,
            "LastActivation": "2025-02-04T10:00:07.637184Z",
            "Name": "Service user for SentinelOne Alert Ingestion app for 0101010101010 site id",
            "Scope": "site",
            "UpdatedAt": "2025-01-30T10:12:09.405748Z",
            "UpdatedById": "2323232323232323",
            "UpdatedByName": "sentinelone",
            "ScopeRolesRoleId": "999999999",
            "ScopeRolesRoleName": "Admin",
            "ScopeRolesAccountName": "SentinelOne",
            "ScopeRolesId": "0101010101010",
        },
        {
            "ID": "123457",
            "ApiTokenCreatedAt": "2025-01-30T10:12:09.458490Z",
            "ApiTokenExpiresAt": "2025-03-01T10:12:08Z",
            "CreatedAt": "2025-01-30T10:12:09.407923Z",
            "CreatedById": "123456789099",
            "CreatedByName": "sentinelone",
            "Description": None,
            "LastActivation": "2025-02-04T10:00:07.637184Z",
            "Name": "Service user for SentinelOne Alert Ingestion app for 0101010101010 site id",
            "Scope": "site",
            "UpdatedAt": "2025-01-30T10:12:09.405748Z",
            "UpdatedById": "2323232323232323",
            "UpdatedByName": "sentinelone",
            "ScopeRolesRoleId": "999999999",
            "ScopeRolesRoleName": "Admin",
            "ScopeRolesAccountName": "SentinelOne",
            "ScopeRolesId": "0101010101010",
        },
    ]

    assert command_results.outputs == expected_outputs
    assert requests_mock.call_count == 2, f"Expected 2 API calls, but got {requests_mock.call_count}"


def test_get_modified_remote_data_command(mocker, requests_mock):
    """
    Given
        - arguments - lastUpdate time
        - raw incidents (results of get_incidents_ids and get_fetch_detections)
    When
        - running get_modified_remote_data_command
    Then
        - returns a list of incidents and detections IDs that were modified since the lastUpdate time
    """
    requests_mock.get("https://usea1.sentinelone.net/web/api/v2.1/threats", json={"data": [{"name": "test", "id": "123456"}]})
    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="get-modified-remote-data")
    mocker.patch.object(demisto, "args", return_value={"id": "123456", "lastUpdate": "2023-02-16 09:35:40.020660+00:00"})
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = vars(call[0].args[0])
    assert command_results == {"modified_incident_ids": ["123456"]}


def test_update_remote_system_command(requests_mock):
    """
    Given
        - incident changes (one of the mirroring field changed or it was closed in XSOAR)
    When
        - outgoing mirroring triggered by a change in the incident
    Then
        - the relevant incident is updated with the corresponding fields in the remote system
        - the returned result corresponds to the incident ID
    """
    args = {
        "delta": {"sentinelonethreatanalystverdict": "", "sentinelonethreatstatus": "", "closeNotes": "a test"},
        "incidentChanged": True,
        "remoteId": "123456",
    }
    command_result = sentinelone_v2.update_remote_system_command(requests_mock, args)
    assert command_result == "123456"


def test_get_mapping_fields_command():
    """
    Given
        - nothing
    When
        - running get_mapping_fields_command
    Then
        - the result fits the expected mapping scheme
    """
    result = sentinelone_v2.get_mapping_fields_command()
    assert result.scheme_types_mappings[0].type_name == "SentinelOne Incident"
    assert list(result.scheme_types_mappings[0].fields.keys()) == ["analystVerdict", "incidentStatus"]


def test_get_dv_query_status(mocker, requests_mock):
    """
    Given: queryId
    When: run get_status
    Then: ensure the context output are as expected and contained the Query Status
    """
    requests_mock.get(
        "https://usea1.sentinelone.net/web/api/v2.1/dv/query-status",
        json={
            "data": {
                "QueryID": "1234567890",
                "progressStatus": 100,
                "queryModeInfo": {"lastActivatedAt": "2022-07-19T21:20:54+00:00", "mode": "scalyr"},
                "responseState": "FINISHED",
                "warnings": None,
            }
        },
    )
    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-get-dv-query-status")
    mocker.patch.object(demisto, "args", return_value={"query_id": "1234567890"})
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs.get("QueryID") == "1234567890"
    assert command_results.outputs.get("responseState") == "FINISHED"


def test_get_agent_request(mocker, requests_mock):
    """
    Test get_agent_request returns agent details for a valid agent_id.
    """
    # Arrange
    agent_id = "1234567890"
    api_response = {
        "data": [
            {
                "id": agent_id,
                "computerName": "test-computer",
                "networkInterfaces": [{"int_name": "eth0", "inet": "192.168.1.10", "physical": "00:11:22:33:44:55"}],
            }
        ]
    }
    # Patch the GET request to the agents endpoint
    requests_mock.get(
        f"https://usea1.sentinelone.net/web/api/v2.1/agents?ids={agent_id}",
        json=api_response,
    )

    # Patch demisto params and command context
    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1"},
    )
    client = sentinelone_v2.Client(base_url="https://usea1.sentinelone.net/web/api/v2.1", verify=False, proxy=False, headers={})

    # Act
    result = client.get_agent_request(agent_id)

    # Assert
    assert isinstance(result, list)
    assert result[0]["id"] == agent_id
    assert result[0]["computerName"] == "test-computer"
    assert result[0]["networkInterfaces"][0]["inet"] == "192.168.1.10"


def test_get_agent_request_multiple_ids(mocker, requests_mock):
    """
    Test get_agent_request returns agent details for multiple agent_ids.
    """
    # Arrange
    agent_ids = "1234567890,1475812345"
    api_response = {
        "data": [
            {
                "id": "1234567890",
                "computerName": "test-computer-1",
                "networkInterfaces": [{"int_name": "eth0", "inet": "192.168.1.10", "physical": "00:11:22:33:44:55"}],
            },
            {
                "id": "1475812345",
                "computerName": "test-computer-2",
                "networkInterfaces": [{"int_name": "eth1", "inet": "10.0.0.5", "physical": "66:77:88:99:AA:BB"}],
            },
        ]
    }
    # Patch the GET request to the agents endpoint
    requests_mock.get(
        f"https://usea1.sentinelone.net/web/api/v2.1/agents?ids={agent_ids}",
        json=api_response,
    )

    # Patch demisto params and command context
    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1"},
    )
    client = sentinelone_v2.Client(base_url="https://usea1.sentinelone.net/web/api/v2.1", verify=False, proxy=False, headers={})

    # Act
    result = client.get_agent_request(agent_ids)

    # Assert
    assert isinstance(result, list)
    assert len(result) == 2
    assert result[0]["id"] == "1234567890"
    assert result[1]["id"] == "1475812345"
    assert result[0]["computerName"] == "test-computer-1"
    assert result[1]["computerName"] == "test-computer-2"
    assert result[0]["networkInterfaces"][0]["inet"] == "192.168.1.10"
    assert result[1]["networkInterfaces"][0]["inet"] == "10.0.0.5"


def test_get_agent_mac(mocker, requests_mock):
    """
    Given: agentId
    When: run get_status
    Then: ensures returned context details are as expected
    """

    requests_mock.get(
        "https://usea1.sentinelone.net/web/api/v2.1/agents",
        json={
            "data": [
                {
                    "computerName": "computerName_test",
                    "id": "agentId_test",
                    "networkInterfaces": [{"int_name": "int_name_test", "inet": "ip_test", "physical": "mac_test"}],
                }
            ]
        },
    )
    mocker.patch.object(
        demisto,
        "params",
        return_value={"token": "token", "url": "https://usea1.sentinelone.net", "api_version": "2.1", "fetch_threat_rank": "4"},
    )
    mocker.patch.object(demisto, "command", return_value="sentinelone-get-agent-mac")
    mocker.patch.object(demisto, "args", return_value={"agent_id": "1234567890"})
    mocker.patch.object(sentinelone_v2, "return_results")
    main()

    call = sentinelone_v2.return_results.call_args_list
    command_results = call[0].args[0]
    assert command_results.outputs[0].get("agent_id") == "agentId_test"
    assert command_results.outputs[0].get("ip") == "ip_test"
    assert command_results.outputs[0].get("mac") == "mac_test"
