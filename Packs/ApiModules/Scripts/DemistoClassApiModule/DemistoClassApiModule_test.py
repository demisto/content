import types
import pytest

from DemistoClassApiModule import *

TEST_SKIP_REASON = "DemistoWrapper is not supported for python 2"


def prepare_demistomock(
    mocker,
    exec_type,
    version=MIN_SUPPORTED_VERSION,
    is_debug=False,
    mock_cmd=None,
    mock_val=None,
):
    mocker.patch.object(demisto, "demistoVersion", return_value={"version": version})
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")
    if exec_type == "script":
        demisto.callingContext = {
            "command": "",
            "context": {
                "ScriptName": "script",
                "CommandsExecuted": {"CurrLevel": 0},
                "ExecutedCommands": []
            },
        }
    else:
        demisto.callingContext = {
            "command": "cmd",
            "context": {
                "IntegrationBrand": "int",
                "CommandsExecuted": {"CurrLevel": 1},
                "ExecutedCommands": [{"name": "caller"}]
            },
        }
    demisto.is_debug = is_debug
    if mock_cmd:
        return mocker.patch.object(demisto, mock_cmd, return_value=mock_val)
    return None


def debug_logs_sent(demisto, msgs):
    res = True
    for msg in msgs:
        res = res and any(
            msg in mock_call[1][0]
            for mock_call in demisto.debug.mock_calls
        )
    return res


@pytest.mark.skipif(not IS_PY3, reason=TEST_SKIP_REASON)
def test_set_demisto_class_script_context(mocker):
    """
    Given:
    - A mock `demisto` object with a script context, version = 8.9.0
    When:
    - Setting the appropriate class for `demisto` based on the calling context.
    Then:
    - Ensure a DemistoScript class is set for `demisto`.
    """
    import demistomock as demisto
    prepare_demistomock(mocker, exec_type="script")
    assert type(demisto) == types.ModuleType  # demistomock is a module
    demisto = set_demisto_class()
    assert type(demisto) == DemistoScript


@pytest.mark.skipif(not IS_PY3, reason=TEST_SKIP_REASON)
def test_set_demisto_class_command_context(mocker):
    """
    Given:
    - A mock `demisto` object with a command context, version = 8.9.0.
    When:
    - Setting the appropriate class for `demisto` based on the calling context.
    Then:
    - Ensure a DemistoIntegration class is set for `demisto`.
    """
    import demistomock as demisto
    prepare_demistomock(mocker, exec_type="command")
    assert type(demisto) == types.ModuleType  # demistomock is a module
    demisto = set_demisto_class()
    assert type(demisto) == DemistoIntegration


@pytest.mark.skipif(not IS_PY3, reason=TEST_SKIP_REASON)
def test_set_demisto_class_is_debug(mocker):
    """
    Given:
    - A `demisto` object on debug mode.
    When:
    - Setting the appropriate class for `demisto` based on the calling context.
    Then:
    - Ensure the `is_debug` attribute is available from the `demisto` object.
    """
    import demistomock as demisto
    prepare_demistomock(mocker, exec_type="command", is_debug=True)
    assert type(demisto) == types.ModuleType  # demistomock is a module
    demisto = set_demisto_class()
    assert type(demisto) == DemistoIntegration
    assert demisto.is_debug


@pytest.mark.skipif(IS_PY3, reason=TEST_SKIP_REASON)
def test_set_demisto_class_python_2(mocker):
    """
    Given:
    - Python 2
    - A mock `demisto` object with a command context, version = 8.9.0
    When:
    - Importing the API module.
    Then:
    - Ensure set_demisto_class() is not defined, thus demisto class is not changed.
    """
    import demistomock as demisto
    prepare_demistomock(mocker, exec_type="command")
    assert type(demisto) == types.ModuleType  # demistomock is a module
    with pytest.raises(NameError):
        demisto = set_demisto_class()
    assert type(demisto) == types.ModuleType


@pytest.mark.skipif(not IS_PY3, reason=TEST_SKIP_REASON)
@pytest.mark.parametrize(
    "platform_version, is_supported",
    [
        ("6.10.0", False),
        ("8.5.0", False),
        ("8.9.0", True),
        ("8.10.0", True),
        ("61.0.0", True),
    ]
)
def test_is_supported_version(mocker, platform_version, is_supported):
    """
    Given:
    - Different platform versions
    When:
    - Running is_supported_version()
    Then:
    - Ensure the response is as expected
    """
    prepare_demistomock(mocker, exec_type="command", version=platform_version)
    assert is_supported_version() == is_supported


@pytest.mark.skipif(not IS_PY3, reason=TEST_SKIP_REASON)
def test_set_demisto_class_not_supported_version(mocker):
    """
    Given:
    - A mock `demisto` object with version = 8.5.0
    When:
    - Setting the appropriate class for `demisto` based on the calling context.
    Then:
    - Ensure the demisto class is not changed.
    """
    import demistomock as demisto
    prepare_demistomock(mocker, exec_type="command", version="8.5.0")
    assert type(demisto) == types.ModuleType  # demistomock is a module
    demisto = set_demisto_class()
    assert type(demisto) == types.ModuleType


@pytest.mark.skipif(not IS_PY3, reason=TEST_SKIP_REASON)
def test_set_demisto_class_malformed_version(mocker):
    """
    Given:
    - A `demisto` object with a malformed version from the server.
    When:
    - Setting the appropriate class for `demisto` based on the calling context.
    Then:
    - Ensure the `demisto` class is not changed.
    - Ensure the warning debug log message is sent.
    """
    import demistomock as demisto
    prepare_demistomock(mocker, exec_type="command", version="asdsadasdsad")
    assert type(demisto) == types.ModuleType  # demistomock is a module
    demisto = set_demisto_class()
    assert type(demisto) == types.ModuleType
    assert debug_logs_sent(demisto, [DEMISTO_WRAPPER_FAILED])


@pytest.mark.skipif(not IS_PY3, reason=TEST_SKIP_REASON)
def test_init_log_execution_details(mocker):
    """
    Given:
    - A `demisto` object with a command context.
    When:
    - Logging execution details.
    Then:
    - Ensure the execution details log is sent.
    """
    import demistomock as demisto
    prepare_demistomock(mocker, exec_type="command")
    demisto = set_demisto_class()
    demisto.info.assert_called_with(
        "{}{}".format(
            EXECUTING_LOG.format(demisto.exec_type, demisto.exec_name),
            EXECUTING_ROOT_CALLER_SUFFIX.format(demisto.root_caller)
        )
    )


@pytest.mark.skipif(not IS_PY3, reason=TEST_SKIP_REASON)
def test_set_demisto_class_init_error(mocker):
    """
    Given:
    - A `demisto` object and a malformed command context with a missing `context.command` field.
    When:
    - Setting the appropriate class for `demisto` based on the calling context.
    Then:
    - Ensure a DemistoIntegration class is set for `demisto`.
    - Ensure the warning debug log message is sent during __init__(), but no exception is returned.
    """
    import demistomock as demisto
    prepare_demistomock(mocker, exec_type="command")
    demisto.callingContext = {"context": {"IntegrationBrand": "hello"}}
    demisto = set_demisto_class()
    assert type(demisto) == DemistoIntegration
    assert debug_logs_sent(demisto, [DEMISTO_WRAPPER_FAILED])


@pytest.mark.skipif(not IS_PY3, reason=TEST_SKIP_REASON)
@pytest.mark.parametrize(
    "get_fp_response, expected_log",
    [
        # good response
        ({"path": "a/b/c"}, FILE_PATH_LOG.format("test", '{"path": "a/b/c"}')),

        # bad response - not json serializable
        (set(), DEMISTO_WRAPPER_FAILED)
    ]
)
def test_get_file_path(mocker, get_fp_response, expected_log):
    """
    Given:
    - A `demisto` object with mocked `getFilePath` results.
    When:
    - Fetching the file path for an entry ID.
    Then:
    - Case 1: Ensure the file path is returned correctly and debug logs are sent.
    - Case 2: Ensure that if an error occurs in DemistoScript.getFilePath(), log the error and skip it.
    """
    import demistomock as demisto
    get_fp_cmd = prepare_demistomock(mocker, exec_type="script", mock_cmd="getFilePath", mock_val=get_fp_response)
    demisto = set_demisto_class()

    res = demisto.getFilePath("test")
    assert res == get_fp_response
    assert get_fp_cmd.called_once()
    assert debug_logs_sent(demisto, [expected_log])


@pytest.mark.skipif(not IS_PY3, reason=TEST_SKIP_REASON)
@pytest.mark.parametrize("is_debug, expected_entries_length", [(False, 2), (True, 1)])
def test_execute_command(mocker, is_debug, expected_entries_length):
    """
    Given:
    - A `demisto` object with debug mode either enabled or disabled.
    When:
    - Executing a command using `executeCommand`.
    Then:
    - Ensure the correct number of entries is returned:
        - Case 1: Two entries are returned when debug mode is disabled.
        - Case 2: One entry is returned when debug mode is enabled.
    """
    import demistomock as demisto
    prepare_demistomock(mocker, exec_type="script", is_debug=is_debug)
    demisto = set_demisto_class()
    res = demisto.executeCommand("cmdWithDebugFile", {})
    assert len(res) == expected_entries_length
    assert demisto.is_debug or any(entry["Type"] == 16 for entry in res)


@pytest.mark.skipif(not IS_PY3, reason=TEST_SKIP_REASON)
def test_execute_command_without_debug_log_output(mocker):
    """
    Given:
    - A `demisto` object with debug_mode True.
    When:
    - Executing a command using `executeCommand`.
        - Case 1: A list with one entry is returned.
        - Case 2: one entry dict is returned.
    - In both cases, no debug log file is returned
    Then:
    - Ensure the result is still returned as expected.
    """
    import demistomock as demisto

    entries = demisto.executeCommand("cmdWithoutDebugFile", {})
    res = demisto.executeCommand("cmdWithoutDebugFile_DictResult", {})
    assert res == entries[0]

    prepare_demistomock(mocker, exec_type="script", is_debug=True)
    demisto = set_demisto_class()

    res = demisto.executeCommand("cmdWithoutDebugFile", {})
    assert res == entries
    res = demisto.executeCommand("cmdWithoutDebugFile_DictResult", {})
    assert res == entries[0]


@pytest.mark.skipif(not IS_PY3, reason=TEST_SKIP_REASON)
def test_execute_command_bad(mocker):
    """
    Given:
    - A `demisto` object with mocked `executeCommand` returning invalid entries.
    When:
    - Executing a command using `executeCommand`.
    Then:
    - Ensure that:
        - Two entries are returned.
        - Debug logs include failure information when invalid entries are encountered.
    """
    import demistomock as demisto
    entries = [{"Contents": "oy vey no entry type"}, {"Type": 16}]
    exec_cmd_func = prepare_demistomock(mocker, exec_type="script", is_debug=True, mock_cmd="executeCommand", mock_val=entries)
    demisto = set_demisto_class()

    res = demisto.executeCommand("cmdWithDebugFile", {})
    assert len(res) == 2
    assert exec_cmd_func.called_once()
    assert debug_logs_sent(demisto, [DEMISTO_WRAPPER_FAILED])


@pytest.mark.skipif(not IS_PY3, reason=TEST_SKIP_REASON)
@pytest.mark.parametrize(
    "last_run, expected_log",
    [
        ("lastRun", LAST_RUN_IS_LOG.format("\"lastRun\"")),
        (set(), DEMISTO_WRAPPER_FAILED)
    ]
)
def test_get_last_run(mocker, last_run, expected_log):
    """
    Given:
    - A `demisto` object with mocked `getLastRun` results.
    When:
    - Fetching the last run data using `getLastRun`.
    Then:
    - Case 1: Ensure the correct last run value is returned and logged.
    - Case 2: Log an error if fetching the last run fails.
    """
    import demistomock as demisto
    get_lr_cmd = prepare_demistomock(mocker, exec_type="command", mock_cmd="getLastRun", mock_val=last_run)
    demisto = set_demisto_class()

    res = demisto.getLastRun()
    assert res == last_run
    assert get_lr_cmd.called_once()
    assert debug_logs_sent(demisto, [expected_log])


@pytest.mark.skipif(not IS_PY3, reason=TEST_SKIP_REASON)
@pytest.mark.parametrize(
    "last_run, expected_log",
    [
        ("lastRun", SET_LAST_RUN_LOG.format('"lastRun"')),
        (set(), DEMISTO_WRAPPER_FAILED)
    ]
)
def test_set_last_run(mocker, last_run, expected_log):
    """
    Given:
    - A `demisto` object with mocked `setLastRun`.
    When:
    - Setting the last run data using `setLastRun`.
    Then:
    - Case 1: Ensure the last run data is set correctly and logged.
    - Case 2: Log an error if setting the last run fails.
    """
    import demistomock as demisto
    set_last_run_cmd = prepare_demistomock(mocker, exec_type="command", mock_cmd="setLastRun")
    demisto = set_demisto_class()

    demisto.setLastRun(last_run)
    assert set_last_run_cmd.called_once()
    assert debug_logs_sent(demisto, [expected_log])


@pytest.mark.skipif(not IS_PY3, reason=TEST_SKIP_REASON)
def test_set_last_run_truncated(mocker):
    """
    Given:
    - A `demisto` object with a very large last run value.
    When:
    - Setting the last run data using `setLastRun`.
    Then:
    - Ensure the last run data is truncated and the truncation is logged.
    """
    import demistomock as demisto
    prepare_demistomock(mocker, exec_type="command")
    demisto = set_demisto_class()

    last_run = "aa" * 1024
    demisto.setLastRun(last_run)
    assert debug_logs_sent(demisto, [TRUNCATED_SUFFIX])


@pytest.mark.skipif(not IS_PY3, reason=TEST_SKIP_REASON)
def test_set_last_run_exceeds_recommendation(mocker):
    """
    Given:
    - A `demisto` object with a very large last run value exceeding the recommended size.
    When:
    - Setting the last run data using `setLastRun`.
    Then:
    - Ensure a warning is logged indicating the size exceeds the recommendation.
    """
    import demistomock as demisto
    prepare_demistomock(mocker, exec_type="command")
    demisto = set_demisto_class()

    last_run = "aa" * 1024 ** 2
    last_run_size = round(
        len(json.dumps(last_run, indent=4).encode('utf-8')) / LAST_RUN_SIZE_RECOMMENDATION,
        1,
    )

    demisto.setLastRun(last_run)
    assert debug_logs_sent(demisto, [LAST_RUN_SIZE_LOG.format(last_run_size)])


@pytest.mark.skipif(not IS_PY3, reason=TEST_SKIP_REASON)
@pytest.mark.parametrize(
    "incidents, expected_log",
    [
        (
            # no source IDs
            [{}, {}],
            CREATING_INCIDENTS_LOG.format(2),
        ),
        (
            # should include source IDs
            [{"dbotMirrorId": "1"}, {"dbotMirrorId": 2}, {"dbotMirrorId": None}],
            CREATING_INCIDENTS_LOG.format(3) + CREATING_INCIDENTS_SUFFIX.format("1, 2, None"),
        ),
        (
            # invalid dict - should skip
            [1, 2],
            DEMISTO_WRAPPER_FAILED,
        )
    ]
)
def test_incidents(mocker, incidents, expected_log):
    """
    Given:
    - A `demisto` object with mocked `incidents` method and various incident inputs.
    When:
    - Adding incidents using `incidents`.
    Then:
    - Case 1: Log the number of incidents added.
    - Case 2: Include source IDs in the log if present in the incidents.
    - Case 3: Log an error if invalid data is encountered.
    """
    import demistomock as demisto
    incidents_cmd = prepare_demistomock(mocker, exec_type="command", mock_cmd="incidents")
    demisto = set_demisto_class()

    demisto.incidents(incidents)
    assert incidents_cmd.called_once()
    assert debug_logs_sent(demisto, [expected_log])


@pytest.mark.skipif(not IS_PY3, reason=TEST_SKIP_REASON)
def test_create_indicators(mocker):
    """
    Given:
    - A `demisto` object with mocked `createIndicators` method.
    When:
    - Creating indicators using `createIndicators`.
    Then:
    - Ensure the method is called and debug logs include the correct number of indicators.
    """
    import demistomock as demisto
    create_indciators_cmd = prepare_demistomock(mocker, exec_type="command", is_debug=True, mock_cmd="createIndicators")
    demisto = set_demisto_class()

    demisto.createIndicators([])
    assert create_indciators_cmd.called_once()
    assert debug_logs_sent(demisto, [CREATING_INDICATORS_LOG.format(0), "createIndicators took"])


@pytest.mark.skipif(not IS_PY3, reason=TEST_SKIP_REASON)
def test_create_indicators_failure(mocker):
    """
    Given:
    - A `demisto` object with mocked `createIndicators` method.
    When:
    - Creating indicators using `createIndicators` with bad input
      that should raise an exception in the DemistoIntegration implementation.
    Then:
    - Ensure the method is called and debug logs include the correct number of indicators.
    """
    import demistomock as demisto
    create_indciators_cmd = prepare_demistomock(mocker, exec_type="command", is_debug=True, mock_cmd="createIndicators")
    demisto = set_demisto_class()

    demisto.createIndicators(None)
    assert create_indciators_cmd.called_once()
    assert debug_logs_sent(demisto, [DEMISTO_WRAPPER_FAILED])
