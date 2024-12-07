import types
import pytest

from DemistoClassApiModule import *


def command_context(
    version="8.5.0",
):
    return {
        "command": "cmd",
        "context": {
            "IntegrationBrand": "int",
            "CommandsExecuted": {"CurrLevel": 1},
            "ExecutedCommands": [{"name": "caller"}]
        },
        "version": version,
    }


def script_context(
    version="8.5.0",
):
    return {
        "command": "",
        "context": {
            "ScriptName": "script",
            "CommandsExecuted": {"CurrLevel": 0},
            "ExecutedCommands": []
        },
        "version": version,
    }


def debug_logs_sent(demisto, msgs):
    res = True
    for msg in msgs:
        res = res and any(
            msg in mock_call[1][0]
            for mock_call in demisto.debug.mock_calls
        )
    return res


@pytest.mark.parametrize(
    "callingContext, expected_class",
    [(command_context(), DemistoIntegration), (script_context(), DemistoScript)]
)
def test_set_demisto_class(callingContext, expected_class):
    """
    Given:
    - A mock `demisto` object with varying calling contexts.
    When:
    - Setting the appropriate class for `demisto` based on the calling context.
    Then:
    - Ensure the correct class (DemistoIntegration or DemistoScript) is set for `demisto`.
    """
    import demistomock as demisto
    demisto.callingContext = callingContext
    assert type(demisto) == types.ModuleType  # demistomock is a module
    demisto = set_demisto_class()
    assert type(demisto) == expected_class


def test_log_execution_details(mocker):
    """
    Given:
    - A `demisto` object with debug mode enabled and a command context.
    When:
    - Logging execution details using the `debug` method.
    Then:
    - Ensure the correct debug log message is sent.
    """
    import demistomock as demisto
    mocker.patch.object(demisto, "debug")
    demisto.callingContext = command_context()
    demisto.is_debug = True
    demisto = set_demisto_class()
    assert demisto.is_debug
    demisto.debug.assert_called_with(
        "{}{}".format(
            EXECUTING_LOG.format(demisto.exec_type, demisto.exec_name),
            EXECUTING_ROOT_CALLER_SUFFIX.format(demisto.root_caller)
        )
    )


@pytest.mark.parametrize(
    "get_fp_result, expected_log",
    [
        ({"path": "a/b/c"}, FILE_PATH_LOG.format("test", "{\"path\": \"a/b/c\"}")),
        (set(), DEMISTO_WRAPPER_FAILED)
    ]
)
def test_get_file_path(mocker, get_fp_result, expected_log):
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
    mocker.patch.object(demisto, "debug")
    get_fp_cmd = mocker.patch.object(demisto, "getFilePath", return_value=get_fp_result)

    demisto.callingContext = script_context()
    demisto = set_demisto_class()

    res = demisto.getFilePath("test")
    assert res == get_fp_result
    assert get_fp_cmd.called_once()
    assert debug_logs_sent(demisto, [expected_log])


@pytest.mark.parametrize("is_debug, expected_entries_length", [(False, 2), (True, 1)])
def test_execute_command(is_debug, expected_entries_length):
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
    demisto.callingContext = script_context()
    demisto.is_debug = is_debug
    demisto = set_demisto_class()
    res = demisto.executeCommand("debugCmd", {})
    assert len(res) == expected_entries_length
    assert demisto.is_debug or any(entry["Type"] == 16 for entry in res)


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
    mocker.patch.object(demisto, "debug")
    entries = [{"Contents": "oy vey no entry type"}, {"Type": 16}]
    exec_cmd_func = mocker.patch.object(demisto, "executeCommand", return_value=entries)

    demisto.callingContext = script_context()
    demisto.is_debug = True
    demisto = set_demisto_class()

    res = demisto.executeCommand("debugCmd", {})
    assert len(res) == 2
    assert exec_cmd_func.called_once()
    assert debug_logs_sent(demisto, [DEMISTO_WRAPPER_FAILED])


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
    mocker.patch.object(demisto, "debug")
    get_lr_cmd = mocker.patch.object(demisto, "getLastRun", return_value=last_run)

    demisto.callingContext = command_context()
    demisto = set_demisto_class()

    res = demisto.getLastRun()
    assert res == last_run
    assert get_lr_cmd.called_once()
    assert debug_logs_sent(demisto, [expected_log])


@pytest.mark.parametrize(
    "last_run, expected_log",
    [
        ("lastRun", SET_LAST_RUN_LOG.format("\"lastRun\"")),
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
    mocker.patch.object(demisto, "debug")
    set_last_run_cmd = mocker.patch.object(demisto, "setLastRun")

    demisto.callingContext = command_context()
    demisto = set_demisto_class()

    demisto.setLastRun(last_run)
    assert set_last_run_cmd.called_once()
    assert debug_logs_sent(demisto, [expected_log])


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
    mocker.patch.object(demisto, "debug")

    demisto.callingContext = command_context()
    demisto = set_demisto_class()

    last_run = "aa" * 1024
    demisto.setLastRun(last_run)
    assert debug_logs_sent(demisto, [TRUNCATED_SUFFIX])


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
    mocker.patch.object(demisto, "debug")

    demisto.callingContext = command_context()
    demisto = set_demisto_class()

    last_run = "aa" * 1024 ** 2
    last_run_size = round(
        len(json.dumps(last_run, indent=4).encode('utf-8')) / LAST_RUN_SIZE_RECOMMENDATION,
        1,
    )
    demisto.setLastRun(last_run)
    assert debug_logs_sent(demisto, [LAST_RUN_SIZE_LOG.format(last_run_size)])


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
    mocker.patch.object(demisto, "debug")
    create_incidents = mocker.patch.object(demisto, "incidents")

    demisto.callingContext = command_context()
    demisto = set_demisto_class()
    demisto.incidents(incidents)
    assert create_incidents.called_once()
    assert debug_logs_sent(demisto, [expected_log])


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
    mocker.patch.object(demisto, "debug")
    create_indciators = mocker.patch.object(demisto, "createIndicators")
    demisto.is_debug = True

    demisto.callingContext = command_context()
    demisto = set_demisto_class()
    demisto.createIndicators([])
    assert create_indciators.called_once()

    assert debug_logs_sent(demisto, [CREATING_INDICATORS_LOG.format(0), "createIndicators took"])
