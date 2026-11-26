import demistomock as demisto
import pytest
from CommonServerPython import DemistoException
from FortiManager import Client


def setup_testing_client(mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"session": "some_token"})
    return Client(
        url="my_url", credentials={"identifier": "username", "password": "password"}, verify=False, proxy=False, adom="MyADOM"
    )


def set_adom_to_global(client):
    client.adom = "global"


def set_adom_to_non_global(client):
    client.adom = "MyADOM"


def test_get_global_or_adom__use_client_non_global(mocker):
    from FortiManager import get_global_or_adom

    client = setup_testing_client(mocker)
    set_adom_to_non_global(client)
    args = {}
    result = get_global_or_adom(client, args)
    assert result == "adom/MyADOM"


def test_get_global_or_adom__use_client_global(mocker):
    from FortiManager import get_global_or_adom

    client = setup_testing_client(mocker)
    set_adom_to_global(client)
    args = {}
    result = get_global_or_adom(client, args)
    assert result == "global"


def test_get_global_or_adom__use_arg_non_global(mocker):
    from FortiManager import get_global_or_adom

    client = setup_testing_client(mocker)
    set_adom_to_global(client)
    args = {"adom": "MyArgADOM"}
    result = get_global_or_adom(client, args)
    assert result == "adom/MyArgADOM"


def test_get_global_or_adom__use_arg_global(mocker):
    from FortiManager import get_global_or_adom

    client = setup_testing_client(mocker)
    set_adom_to_non_global(client)
    args = {"adom": "global"}
    result = get_global_or_adom(client, args)
    assert result == "global"


def test_setup_request_data():
    from FortiManager import setup_request_data

    args = {"adom": "MyADOM", "name": "some_name", "variable": "value", "ignore": "this"}
    expected_res = {"name": "some_name", "variable": "value"}
    assert expected_res == setup_request_data(args, ["adom", "ignore"])


def test_get_range_for_list_command__only_from():
    from FortiManager import get_range_for_list_command

    args = {"offset": 1}
    assert get_range_for_list_command(args) == [1, 49]


def test_get_range_for_list_command__only_to():
    from FortiManager import get_range_for_list_command

    args = {"limit": 1}
    assert get_range_for_list_command(args) == [0, 1]


def test_get_range_for_list_command__from_and_to():
    from FortiManager import get_range_for_list_command

    args = {"limit": 1, "offset": 0}
    assert get_range_for_list_command(args) == [0, 1]


def test_get_range_for_list_command__no_from_and_to():
    from FortiManager import get_range_for_list_command

    args = {}
    assert get_range_for_list_command(args) == [0, 50]


""" Workspace Mode """

ADDRESS_URL = "/pm/config/adom/MyADOM/obj/firewall/address"
LOCK_URL = "/dvmdb/adom/MyADOM/workspace/lock"
COMMIT_URL = "/dvmdb/adom/MyADOM/workspace/commit"
UNLOCK_URL = "/dvmdb/adom/MyADOM/workspace/unlock"


def json_rpc_response(code: int = 0, message: str = "OK", data=None) -> dict:
    return {"id": 1, "result": [{"status": {"code": code, "message": message}, "data": data}]}


def mock_fortimanager(mocker, client, failing_urls: dict | None = None):
    """Mocks the JSON-RPC requests of the client.

    Returns the list of (method, url) calls. A url listed in failing_urls returns the given error message.
    """
    failing_urls = failing_urls or {}
    calls: list = []

    def fake_http_request(method, url, **kwargs):
        calls.append((method, url))
        if url in failing_urls:
            return json_rpc_response(code=-20, message=failing_urls[url])
        return json_rpc_response(data={"name": "test"})

    mocker.patch.object(client, "fortimanager_http_request", side_effect=fake_http_request)
    return calls


@pytest.mark.parametrize(
    "url, expected_scope",
    [
        ("/pm/config/adom/MyADOM/obj/firewall/address", "adom/MyADOM"),
        ("/pm/config/global/obj/firewall/address/my_address", "global"),
        ("pm/pkg/adom/MyADOM/my_package", "adom/MyADOM"),
        ("/pm/config/adom/MyADOM/pkg/my_package/firewall/policy", "adom/MyADOM"),
        ("/securityconsole/install/package", None),
        ("/sys/login/user", None),
    ],
)
def test_get_workspace_scope(url, expected_scope):
    """
    Given: A FortiManager JSON-RPC URL.
    When: Extracting the workspace scope from it.
    Then: The ADOM scope ("adom/<name>" or "global") is returned, or None for URLs outside an ADOM config.
    """
    from FortiManager import get_workspace_scope

    assert get_workspace_scope(url) == expected_scope


def test_api_call_workspace_mode_disabled_sends_only_the_request(mocker):
    """
    Given: A client with Workspace Mode disabled.
    When: Running a write request.
    Then: Only the write request is sent, with no lock, commit or unlock.
    """
    client = setup_testing_client(mocker)
    calls = mock_fortimanager(mocker, client)

    client.fortimanager_api_call("add", ADDRESS_URL, data_in_list={"name": "test"})

    assert calls == [("add", ADDRESS_URL)]


def test_api_call_workspace_mode_write_locks_commits_and_unlocks(mocker):
    """
    Given: A client with Workspace Mode enabled.
    When: Running a write request in an ADOM.
    Then: The ADOM is locked, the change is sent, committed, and the ADOM is unlocked, in that order.
    """
    client = setup_testing_client(mocker)
    client.workspace_mode = True
    calls = mock_fortimanager(mocker, client)

    result = client.fortimanager_api_call("add", ADDRESS_URL, data_in_list={"name": "test"})

    assert calls == [("exec", LOCK_URL), ("add", ADDRESS_URL), ("exec", COMMIT_URL), ("exec", UNLOCK_URL)]
    assert result == {"name": "test"}


def test_api_call_workspace_mode_global_scope(mocker):
    """
    Given: A client with Workspace Mode enabled.
    When: Deleting an object in the global ADOM.
    Then: The global workspace is locked, committed and unlocked.
    """
    client = setup_testing_client(mocker)
    client.workspace_mode = True
    calls = mock_fortimanager(mocker, client)

    client.fortimanager_api_call("delete", "/pm/config/global/obj/firewall/address/test")

    assert [url for _, url in calls] == [
        "/dvmdb/global/workspace/lock",
        "/pm/config/global/obj/firewall/address/test",
        "/dvmdb/global/workspace/commit",
        "/dvmdb/global/workspace/unlock",
    ]


@pytest.mark.parametrize(
    "method, url",
    [("get", ADDRESS_URL), ("exec", "/securityconsole/install/package")],
)
def test_api_call_workspace_mode_read_and_exec_are_not_locked(mocker, method, url):
    """
    Given: A client with Workspace Mode enabled.
    When: Running a read request, or an exec request that doesn't change ADOM config.
    Then: No lock, commit or unlock is sent.
    """
    client = setup_testing_client(mocker)
    client.workspace_mode = True
    calls = mock_fortimanager(mocker, client)

    client.fortimanager_api_call(method, url)

    assert calls == [(method, url)]


def test_api_call_workspace_mode_failed_write_unlocks_without_commit(mocker):
    """
    Given: A client with Workspace Mode enabled, and FortiManager rejecting the change.
    When: Running a write request.
    Then: The FortiManager error is raised, nothing is committed, and the ADOM is still unlocked.
    """
    client = setup_testing_client(mocker)
    client.workspace_mode = True
    calls = mock_fortimanager(mocker, client, failing_urls={ADDRESS_URL: "Object already exists"})

    with pytest.raises(DemistoException, match="Object already exists"):
        client.fortimanager_api_call("add", ADDRESS_URL, data_in_list={"name": "test"})

    assert calls == [("exec", LOCK_URL), ("add", ADDRESS_URL), ("exec", UNLOCK_URL)]


def test_api_call_workspace_mode_lock_taken(mocker):
    """
    Given: A client with Workspace Mode enabled, and the ADOM locked by another administrator.
    When: Running a write request.
    Then: A clear error is raised, and the change, commit and unlock are not sent.
    """
    client = setup_testing_client(mocker)
    client.workspace_mode = True
    calls = mock_fortimanager(mocker, client, failing_urls={LOCK_URL: "Workspace is locked by other user"})

    with pytest.raises(DemistoException, match="may be locked by another administrator.*Workspace is locked by other user"):
        client.fortimanager_api_call("add", ADDRESS_URL, data_in_list={"name": "test"})

    assert calls == [("exec", LOCK_URL)]


def test_api_call_workspace_mode_commit_failure_unlocks(mocker):
    """
    Given: A client with Workspace Mode enabled, and the commit failing.
    When: Running a write request.
    Then: A commit error is raised and the ADOM is still unlocked.
    """
    client = setup_testing_client(mocker)
    client.workspace_mode = True
    calls = mock_fortimanager(mocker, client, failing_urls={COMMIT_URL: "commit failed"})

    with pytest.raises(DemistoException, match="committing adom/MyADOM failed.*commit failed"):
        client.fortimanager_api_call("add", ADDRESS_URL, data_in_list={"name": "test"})

    assert calls[-1] == ("exec", UNLOCK_URL)


def test_api_call_workspace_mode_unlock_failure_does_not_hide_result(mocker):
    """
    Given: A client with Workspace Mode enabled, and the unlock failing.
    When: Running a write request that succeeds.
    Then: The command still returns its result, and the unlock error is only logged.
    """
    client = setup_testing_client(mocker)
    client.workspace_mode = True
    mock_fortimanager(mocker, client, failing_urls={UNLOCK_URL: "unlock failed"})
    error_log = mocker.patch.object(demisto, "error")

    result = client.fortimanager_api_call("add", ADDRESS_URL, data_in_list={"name": "test"})

    assert result == {"name": "test"}
    assert "unlock failed" in error_log.call_args[0][0]


""" Workspace Mode - policy package install """

INSTALL_URL = "/securityconsole/install/package"
TASK_URL = "/task/task/7659"


def mock_install_flow(mocker, client, task_states: list[dict], failing_urls: dict | None = None):
    """Mocks the JSON-RPC requests of a policy package install.

    The install returns task 7659, and each task status request returns the next item of task_states.
    """
    failing_urls = failing_urls or {}
    calls: list = []
    remaining_states = list(task_states)

    def fake_http_request(method, url, **kwargs):
        calls.append((method, url))
        if url in failing_urls:
            return json_rpc_response(code=-20, message=failing_urls[url])
        if url == INSTALL_URL:
            return json_rpc_response(data={"task": 7659})
        if url == TASK_URL:
            return json_rpc_response(data=remaining_states.pop(0))
        return json_rpc_response()

    mocker.patch.object(client, "fortimanager_http_request", side_effect=fake_http_request)
    mocker.patch("FortiManager.time.sleep")
    return calls


INSTALL_ARGS = {"package": "my_package", "name": "my_device", "vdom": "root"}


def test_install_workspace_mode_disabled_is_not_locked(mocker):
    """
    Given: A client with Workspace Mode disabled.
    When: Installing a policy package.
    Then: Only the install request is sent, and the task ID is returned.
    """
    from FortiManager import install_policy_package_command

    client = setup_testing_client(mocker)
    calls = mock_install_flow(mocker, client, task_states=[])

    result = install_policy_package_command(client, INSTALL_ARGS)

    assert calls == [("exec", INSTALL_URL)]
    assert result.outputs == {"id": 7659}


def test_install_workspace_mode_locks_until_task_finishes(mocker):
    """
    Given: A client with Workspace Mode enabled.
    When: Installing a policy package whose task finishes on the second status check.
    Then: The ADOM is locked, the install runs, the task is polled until it finishes, and then the ADOM is unlocked.
    """
    from FortiManager import install_policy_package_command

    client = setup_testing_client(mocker)
    client.workspace_mode = True
    calls = mock_install_flow(
        mocker, client, task_states=[{"state": "running", "percent": 50}, {"state": "done", "percent": 100}]
    )

    result = install_policy_package_command(client, INSTALL_ARGS)

    assert calls == [
        ("exec", LOCK_URL),
        ("exec", INSTALL_URL),
        ("get", TASK_URL),
        ("get", TASK_URL),
        ("exec", UNLOCK_URL),
    ]
    assert result.outputs == {"id": 7659}
    assert "The task finished (state: done, percent: 100)" in result.readable_output


def test_install_workspace_mode_failed_install_unlocks(mocker):
    """
    Given: A client with Workspace Mode enabled, and FortiManager rejecting the install.
    When: Installing a policy package.
    Then: The FortiManager error is raised, no task is polled, and the ADOM is unlocked.
    """
    from FortiManager import install_policy_package_command

    client = setup_testing_client(mocker)
    client.workspace_mode = True
    calls = mock_install_flow(mocker, client, task_states=[], failing_urls={INSTALL_URL: "Package not found"})

    with pytest.raises(DemistoException, match="Package not found"):
        install_policy_package_command(client, INSTALL_ARGS)

    assert calls == [("exec", LOCK_URL), ("exec", INSTALL_URL), ("exec", UNLOCK_URL)]


def test_install_workspace_mode_task_timeout_unlocks(mocker):
    """
    Given: A client with Workspace Mode enabled, and an install task that doesn't finish in time.
    When: Installing a policy package.
    Then: The ADOM is unlocked after the timeout, and the output says the task was still running.
    """
    import FortiManager

    client = setup_testing_client(mocker)
    client.workspace_mode = True
    calls = mock_install_flow(mocker, client, task_states=[{"state": "running", "percent": 10}] * 3)
    # time.time() calls: deadline calculation, then one per loop check. The 4th call is past the deadline.
    mocker.patch("FortiManager.time.time", side_effect=[0, 0, 0, FortiManager.INSTALL_TASK_TIMEOUT_SECONDS + 1])

    result = FortiManager.install_policy_package_command(client, INSTALL_ARGS)

    assert calls[-1] == ("exec", UNLOCK_URL)
    assert calls.count(("get", TASK_URL)) == 2
    assert "The task was still running" in result.readable_output


@pytest.mark.parametrize(
    "task_data, expected",
    [
        ({"state": "done", "percent": 100}, True),
        ({"state": "error", "percent": 30}, True),
        ({"state": 4, "percent": "100"}, True),
        ({"state": "running", "percent": 50}, False),
        ({}, False),
    ],
)
def test_is_task_finished(task_data, expected):
    """
    Given: FortiManager task data.
    When: Checking whether the task finished.
    Then: A task at 100 percent, or in a final state, is finished.
    """
    from FortiManager import is_task_finished

    assert is_task_finished(task_data) == expected
