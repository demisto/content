import demistomock as demisto
import pytest


def test_ssdeep_reputation_test_not_found(mocker):
    """
    Given:
        - The script args.
    When:
        - Running the command.
    Then:
        - Validating the outputs as expected.
    """
    from SSDeepReputation import main

    args = {"input": "1"}
    mocker.patch.object(demisto, "args", return_value=args)
    execute_command_res = [{"Contents": []}]
    execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=execute_command_res)
    main()
    assert execute_mock.call_count == 3


def test_get_investigation_ids_with_plural_key():
    """
    Given:
        - An indicator with investigationIDs key (plural).
    When:
        - Calling get_investigation_ids.
    Then:
        - Returns the list of investigation IDs.
    """
    from SSDeepReputation import get_investigation_ids

    indicator = {"investigationIDs": ["123", "456"]}
    result = get_investigation_ids(indicator)
    assert result == ["123", "456"]


def test_get_investigation_ids_with_singular_key():
    """
    Given:
        - An indicator with investigationID key (singular).
    When:
        - Calling get_investigation_ids.
    Then:
        - Returns the investigation ID as a list.
    """
    from SSDeepReputation import get_investigation_ids

    indicator = {"investigationID": "123"}
    result = get_investigation_ids(indicator)
    assert result == ["123"]


def test_get_investigation_ids_with_singular_key_as_list():
    """
    Given:
        - An indicator with investigationID key containing a list.
    When:
        - Calling get_investigation_ids.
    Then:
        - Returns the list as-is.
    """
    from SSDeepReputation import get_investigation_ids

    indicator = {"investigationID": ["123", "456"]}
    result = get_investigation_ids(indicator)
    assert result == ["123", "456"]


def test_get_investigation_ids_with_no_keys():
    """
    Given:
        - An indicator with neither investigationIDs nor investigationID.
    When:
        - Calling get_investigation_ids.
    Then:
        - Returns an empty list.
    """
    from SSDeepReputation import get_investigation_ids

    indicator = {"score": 0}
    result = get_investigation_ids(indicator)
    assert result == []


def test_get_investigation_ids_with_plural_non_list():
    """
    Given:
        - An indicator with investigationIDs as a single value (not a list).
    When:
        - Calling get_investigation_ids.
    Then:
        - Returns the value as a list.
    """
    from SSDeepReputation import get_investigation_ids

    indicator = {"investigationIDs": "123"}
    result = get_investigation_ids(indicator)
    assert result == ["123"]


def test_get_indicator_from_value_success(mocker):
    """
    Given:
        - A valid indicator value.
    When:
        - Calling get_indicator_from_value.
    Then:
        - Returns the indicator object.
    """
    from SSDeepReputation import get_indicator_from_value

    mock_response = [{"Contents": [{"id": "123", "value": "test", "score": 2}]}]
    mocker.patch.object(demisto, "executeCommand", return_value=mock_response)

    result = get_indicator_from_value("test")
    assert result == {"id": "123", "value": "test", "score": 2}


def test_get_indicator_from_value_not_found(mocker):
    """
    Given:
        - An indicator value that doesn't exist.
    When:
        - Calling get_indicator_from_value.
    Then:
        - Returns None.
    """
    from SSDeepReputation import get_indicator_from_value

    mock_response = [{"Contents": []}]
    mocker.patch.object(demisto, "executeCommand", return_value=mock_response)

    result = get_indicator_from_value("test")
    assert result is None


def test_get_indicator_from_value_empty_input():
    """
    Given:
        - An empty indicator value.
    When:
        - Calling get_indicator_from_value.
    Then:
        - Returns None without calling executeCommand.
    """
    from SSDeepReputation import get_indicator_from_value

    result = get_indicator_from_value("")
    assert result is None

    result = get_indicator_from_value(None)
    assert result is None


def test_get_indicator_from_value_exception(mocker):
    """
    Given:
        - executeCommand raises an exception.
    When:
        - Calling get_indicator_from_value.
    Then:
        - Returns None gracefully.
    """
    from SSDeepReputation import get_indicator_from_value

    mocker.patch.object(demisto, "executeCommand", side_effect=Exception("API Error"))

    result = get_indicator_from_value("test")
    assert result is None


def test_ssdeep_value_sanitization(mocker):
    """
    Given:
        - An ssdeep value containing single quotes.
    When:
        - Processing related indicators.
    Then:
        - The value is properly escaped in the DT query.
    """
    from SSDeepReputation import get_ssdeep_related_indicators

    ssdeep_indicator = {"value": "test'value", "investigationIDs": ["123"]}

    mock_context_response = [{"Contents": {"context": {"File": [{"SSDeep": "test'value", "MD5": "abc123"}]}}}]

    mocker.patch.object(demisto, "executeCommand", return_value=mock_context_response)
    mocker.patch.object(demisto, "dt", return_value={"MD5": "abc123"})

    # Should not raise an exception due to quote in value
    result = get_ssdeep_related_indicators(ssdeep_indicator)
    assert len(result) >= 1


@pytest.mark.parametrize(
    "indicator,expected_ids",
    [
        ({"investigationIDs": ["1", "2"]}, ["1", "2"]),
        ({"investigationID": "1"}, ["1"]),
        ({"investigationID": ["1", "2"]}, ["1", "2"]),
        ({"investigationIDs": "1"}, ["1"]),
        ({}, []),
        ({"score": 0}, []),
    ],
)
def test_get_investigation_ids_parametrized(indicator, expected_ids):
    """
    Parametrized test for get_investigation_ids with various inputs.
    """
    from SSDeepReputation import get_investigation_ids

    result = get_investigation_ids(indicator)
    assert result == expected_ids
