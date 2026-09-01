import demistomock as demisto
import pytest


def test_OSQueryBasicQuery_error(mocker):
    """
    Given:
        - The script args with a valid query that triggers a RemoteExec error.
    When:
        - Running the OSQueryBasicQuery script.
    Then:
        - The error entry is returned in results.
    """
    from OSQueryBasicQuery import main

    mocker.patch.object(demisto, "args", return_value={"system": "system", "query": "query"})
    execute_command_res = [{"Type": 4, "Contents": "Error", "Brand": "brand"}]
    execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=execute_command_res)
    results_mock = mocker.patch.object(demisto, "results")
    main()

    assert execute_mock.call_count == 1
    assert "An Error occurred on remote system" in results_mock.call_args[0][0][0]["Contents"]


@pytest.mark.parametrize(
    "injection_payload",
    [
        '"; id > /tmp/pwned_xsoar; #',
        "'; rm -rf /; '",
        "$(whoami)",
        "`id`",
        "query | cat /etc/passwd",
        "query && curl http://test.com",
    ],
)
def test_OSQueryBasicQuery_injection_payloads_are_quoted(mocker, injection_payload):
    """
    Given:
        - A query argument containing shell metacharacters (injection payload).
    When:
        - Running the OSQueryBasicQuery script.
    Then:
        - The command passed to RemoteExec, when parsed by a POSIX shell, yields the
          payload as a single literal argument to osqueryi — no metacharacter expansion.
    """
    import shlex
    from OSQueryBasicQuery import main

    mocker.patch.object(demisto, "args", return_value={"system": "target-host", "query": injection_payload})
    execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1, "Contents": "[]"}])
    mocker.patch.object(demisto, "results")
    main()

    assert execute_mock.call_count == 1
    called_cmd = execute_mock.call_args[0][1]["cmd"]

    # Parse the command exactly as a POSIX shell would: the third token (index 2)
    # must equal the raw payload — proving shlex.quote neutralised all metacharacters
    # and the shell would treat the entire payload as one literal argument.
    parsed_args = shlex.split(called_cmd)
    assert len(parsed_args) == 3, f"Expected 3 shell tokens (osqueryi --json <query>), got {parsed_args!r}"
    assert parsed_args[2] == injection_payload, (
        f"Shell would not receive the payload as a single literal argument. "
        f"cmd={called_cmd!r}, parsed arg={parsed_args[2]!r}, expected={injection_payload!r}"
    )


def test_OSQueryBasicQuery_normal_query_format(mocker):
    """
    Given:
        - A benign SQL query.
    When:
        - Running the OSQueryBasicQuery script.
    Then:
        - The command sent to RemoteExec matches the expected safe format.
    """
    import shlex
    from OSQueryBasicQuery import main, COMMAND

    query = "SELECT * FROM users"
    mocker.patch.object(demisto, "args", return_value={"system": "host1", "query": query})
    execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1, "Contents": "[]"}])
    mocker.patch.object(demisto, "results")
    main()

    expected_cmd = COMMAND.format(shlex.quote(query))
    assert execute_mock.call_args[0][1]["cmd"] == expected_cmd
