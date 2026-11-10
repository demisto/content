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
    "query_with_special_chars",
    [
        'SELECT * FROM users WHERE name = "admin"',
        "SELECT path FROM file WHERE path LIKE '/etc/%'",
        "SELECT $(echo test) FROM processes",
        "SELECT `id` FROM users",
        "SELECT pid, name FROM processes | head",
        "SELECT * FROM users WHERE uid > 0 && uid < 100",
    ],
)
def test_OSQueryBasicQuery_injection_payloads_are_quoted(mocker, query_with_special_chars):
    """
    Given:
        - A query argument containing shell special characters.
    When:
        - Running the OSQueryBasicQuery script.
    Then:
        - The command passed to RemoteExec, when parsed by a POSIX shell, yields the
          query as a single literal argument to osqueryi — no shell interpretation.
    """
    import shlex
    from OSQueryBasicQuery import main

    mocker.patch.object(demisto, "args", return_value={"system": "target-host", "query": query_with_special_chars})
    execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1, "Contents": "[]"}])
    mocker.patch.object(demisto, "results")
    main()

    assert execute_mock.call_count == 1
    called_cmd = execute_mock.call_args[0][1]["cmd"]

    # Parse the command exactly as a POSIX shell would: the third token (index 2)
    # must equal the raw query — proving shlex.quote neutralised all special characters
    # and the shell would treat the entire query as one literal argument.
    parsed_args = shlex.split(called_cmd)
    assert len(parsed_args) == 3, f"Expected 3 shell tokens (osqueryi --json <query>), got {parsed_args!r}"
    assert parsed_args[2] == query_with_special_chars, (
        f"Shell would not receive the query as a single literal argument. "
        f"cmd={called_cmd!r}, parsed arg={parsed_args[2]!r}, expected={query_with_special_chars!r}"
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
