import pytest

import demistomock as demisto
import NetskopeSetXsoarListContentWithRetry
from NetskopeSetXsoarListContentWithRetry import main, set_list_with_retry


def test_set_list_with_retry_succeeds_first_try(mocker):
    """
    Given:
        - setList succeeds on the first attempt.
    When:
        - Running set_list_with_retry.
    Then:
        - It returns without retrying.
    """
    execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1, "Contents": "ok"}])
    sleep_mock = mocker.patch("NetskopeSetXsoarListContentWithRetry.time.sleep")

    set_list_with_retry("MyList", "a,b")

    assert execute_mock.call_count == 1
    sleep_mock.assert_not_called()


def test_set_list_with_retry_retries_on_version_conflict_then_succeeds(mocker):
    """
    Given:
        - setList fails once with a "version conflict" error, then succeeds.
    When:
        - Running set_list_with_retry.
    Then:
        - It retries once (sleeping between attempts) and succeeds without raising.
    """
    responses = [
        [{"Type": 4, "Contents": "version conflict, retry the operation"}],
        [{"Type": 1, "Contents": "ok"}],
    ]
    execute_mock = mocker.patch.object(demisto, "executeCommand", side_effect=responses)
    sleep_mock = mocker.patch("NetskopeSetXsoarListContentWithRetry.time.sleep")

    set_list_with_retry("MyList", "a,b")

    assert execute_mock.call_count == 2
    sleep_mock.assert_called_once_with(3)


def test_set_list_with_retry_gives_up_after_max_attempts(mocker):
    """
    Given:
        - setList fails with "version conflict" on every attempt.
    When:
        - Running set_list_with_retry.
    Then:
        - It raises after MAX_ATTEMPTS tries, not indefinitely.
    """
    mocker.patch.object(
        demisto, "executeCommand", return_value=[{"Type": 4, "Contents": "version conflict"}]
    )
    mocker.patch("NetskopeSetXsoarListContentWithRetry.time.sleep")

    with pytest.raises(Exception, match="Failed to save list"):
        set_list_with_retry("MyList", "a,b")


def test_set_list_with_retry_raises_immediately_on_non_conflict_error(mocker):
    """
    Given:
        - setList fails with an error that isn't a version conflict.
    When:
        - Running set_list_with_retry.
    Then:
        - It raises immediately without retrying.
    """
    execute_mock = mocker.patch.object(
        demisto, "executeCommand", return_value=[{"Type": 4, "Contents": "permission denied"}]
    )
    sleep_mock = mocker.patch("NetskopeSetXsoarListContentWithRetry.time.sleep")

    with pytest.raises(Exception, match="permission denied"):
        set_list_with_retry("MyList", "a,b")

    assert execute_mock.call_count == 1
    sleep_mock.assert_not_called()


def test_main_requires_list_name(mocker):
    """
    Given:
        - listName is not provided.
    When:
        - Running main.
    Then:
        - return_error is called with a clear message.
    """
    mocker.patch.object(demisto, "args", return_value={})
    return_error_mock = mocker.patch.object(
        NetskopeSetXsoarListContentWithRetry, "return_error", side_effect=SystemExit
    )

    with pytest.raises(SystemExit):
        main()

    return_error_mock.assert_called_once_with("listName is required")


def test_main_saves_list_content(mocker):
    """
    Given:
        - listName and listData are provided and setList succeeds.
    When:
        - Running main.
    Then:
        - XsoarList.name/content reflect what was saved.
    """
    mocker.patch.object(demisto, "args", return_value={"listName": "MyList", "listData": "a,b"})
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1, "Contents": "ok"}])
    results_mock = mocker.patch.object(demisto, "results")

    main()

    outputs = results_mock.call_args[0][0]["EntryContext"]["XsoarList(val.name && val.name == obj.name)"]
    assert outputs["name"] == "MyList"
    assert outputs["content"] == "a,b"
