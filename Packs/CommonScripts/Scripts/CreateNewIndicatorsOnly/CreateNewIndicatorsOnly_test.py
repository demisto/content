from typing import Any

import CreateNewIndicatorsOnly
import demistomock as demisto
import pytest
from CommonServerPython import *  # noqa: F401


def equals_object(obj1, obj2) -> bool:
    if not isinstance(obj1, type(obj2)):
        return False
    elif isinstance(obj1, dict):
        for k1, v1 in obj1.items():
            if k1 not in obj2:
                return False
            if not equals_object(v1, obj2[k1]):
                return False
        return not (set(obj1.keys()) ^ set(obj2.keys()))
    elif isinstance(obj1, list):
        # Compare lists (ignore order)
        list2 = list(obj2)
        for _i1, v1 in enumerate(obj1):
            for i2, v2 in enumerate(list2):
                if equals_object(v1, v2):
                    list2.pop(i2)
                    break
            else:
                return False
        return not list2
    else:
        return obj1 == obj2


def test_no_values(mocker):
    """
    Given:
        No values are given to the 'indicator_values'.

    When:
        Running the script

    Then:
        Validate the right response returns.
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "indicator_values": [],
        },
    )

    expected_entry_context = {}

    mocker.patch.object(demisto, "results")
    CreateNewIndicatorsOnly.main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert "0 new indicators have been added" in results.get("HumanReadable")
    assert equals_object(expected_entry_context, results.get("EntryContext"))


def test_all_indicators_exist_with_single_value(mocker):
    """
    Given:
        A single indicator existing in the threat intel is given to the 'indicator_values'.

    When:
        Running the script

    Then:
        Validate the right response returns.
    """

    def mock_search_indicators(query=None, size=100, **kwargs):
        if query and 'value:"1.1.1.1"' in query:
            return {
                "iocs": [{"id": "0", "value": "1.1.1.1", "score": 0, "indicator_type": "Unknown"}],
                "total": 1,
                "searchAfter": None,
            }
        return {"iocs": [], "total": 0, "searchAfter": None}

    mocker.patch.object(demisto, "searchIndicators", side_effect=mock_search_indicators)

    def __execute_command(cmd, args) -> Any:
        if cmd == "associateIndicatorToIncident":
            return "done"
        raise ValueError("Unexpected calls")

    mocker.patch("CreateNewIndicatorsOnly.execute_command", side_effect=__execute_command)

    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "indicator_values": "1.1.1.1",
            "associate_to_current": "true",
        },
    )

    expected_entry_context = {
        "CreateNewIndicatorsOnly(val.Value && val.Value == obj.Value && val.Type && val.Type == obj.Type)": [
            {"CreationStatus": "existing", "ID": "0", "Score": 0, "Type": "Unknown", "Value": "1.1.1.1"}
        ]
    }

    mocker.patch.object(demisto, "results")
    CreateNewIndicatorsOnly.main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert "0 new indicators have been added" in results.get("HumanReadable")
    assert equals_object(expected_entry_context, results.get("EntryContext"))


def test_all_indicators_exist_with_multiple_value(mocker):
    """
    Given:
        All indicators existing in the threat intel are given to the 'indicator_values'.

    When:
        Running the script

    Then:
        Validate the right response returns.
    """

    def mock_search_indicators(query=None, size=100, **kwargs):
        iocs = []
        if query and 'value:"1.1.1.1"' in query:
            iocs.append({"id": "0", "value": "1.1.1.1", "score": 0, "indicator_type": "Unknown"})
        if query and 'value:"2.2.2.2"' in query:
            iocs.append({"id": "0", "value": "2.2.2.2", "score": 0, "indicator_type": "Unknown"})
        return {"iocs": iocs, "total": len(iocs), "searchAfter": None}

    mocker.patch.object(demisto, "searchIndicators", side_effect=mock_search_indicators)

    def __execute_command(cmd, args) -> Any:
        if cmd == "associateIndicatorToIncident":
            return "done"
        raise ValueError("Unexpected calls")

    mocker.patch("CreateNewIndicatorsOnly.execute_command", side_effect=__execute_command)

    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "indicator_values": ["1.1.1.1", "2.2.2.2"],
            "associate_to_current": "true",
        },
    )

    expected_entry_context = {
        "CreateNewIndicatorsOnly(val.Value && val.Value == obj.Value && val.Type && val.Type == obj.Type)": [
            {"CreationStatus": "existing", "ID": "0", "Score": 0, "Type": "Unknown", "Value": "1.1.1.1"},
            {"CreationStatus": "existing", "ID": "0", "Score": 0, "Type": "Unknown", "Value": "2.2.2.2"},
        ]
    }

    mocker.patch.object(demisto, "results")
    CreateNewIndicatorsOnly.main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert "0 new indicators have been added" in results.get("HumanReadable")
    assert equals_object(expected_entry_context, results.get("EntryContext"))


def test_some_indicators_exist_with_multiple_value(mocker):
    """
    Given:
        Some indicators existing in the threat intel are given to the 'indicator_values'.

    When:
        Running the script

    Then:
        Validate the right response returns.
    """

    def mock_search_indicators(query=None, size=100, **kwargs):
        iocs = []
        if query and 'value:"1.1.1.1"' in query:
            iocs.append({"id": "0", "value": "1.1.1.1", "score": 0, "indicator_type": "Unknown"})
        # 2.2.2.2 is NOT in the system, so we don't add it
        return {"iocs": iocs, "total": len(iocs), "searchAfter": None}

    mocker.patch.object(demisto, "searchIndicators", side_effect=mock_search_indicators)

    def __execute_command(cmd, args) -> Any:
        if cmd == "createNewIndicator":
            return {"id": "0", "value": args.get("value"), "score": 0, "indicator_type": args.get("type", "Unknown")}
        elif cmd == "associateIndicatorToIncident":
            return "done"
        raise ValueError("Unexpected calls")

    mocker.patch("CreateNewIndicatorsOnly.execute_command", side_effect=__execute_command)

    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "indicator_values": ["1.1.1.1", "2.2.2.2"],
            "associate_to_current": "true",
        },
    )

    expected_entry_context = {
        "CreateNewIndicatorsOnly(val.Value && val.Value == obj.Value && val.Type && val.Type == obj.Type)": [
            {"CreationStatus": "existing", "ID": "0", "Score": 0, "Type": "Unknown", "Value": "1.1.1.1"},
            {"CreationStatus": "new", "ID": "0", "Score": 0, "Type": "Unknown", "Value": "2.2.2.2"},
        ]
    }

    mocker.patch.object(demisto, "results")
    CreateNewIndicatorsOnly.main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert "1 new indicators have been added" in results.get("HumanReadable")
    assert equals_object(expected_entry_context, results.get("EntryContext"))


def test_some_indicators_are_excluded(mocker):
    """
    Given:
        Some indicators given to the 'indicator_values' are in the exclusion list.

    When:
        Running the script

    Then:
        Validate the right response returns.
    """

    mocker.patch.object(
        demisto,
        "searchIndicators",
        return_value={"iocs": [], "total": 0, "searchAfter": None},
    )

    def __execute_command(cmd, args) -> Any:
        if cmd == "createNewIndicator":
            value = args.get("value")
            if value == "1.1.1.1":
                return "done - Indicator was not created"
            else:
                return {"id": "0", "value": args.get("value"), "score": 0, "indicator_type": args.get("type", "Unknown")}
        elif cmd == "associateIndicatorToIncident":
            return "done"
        raise ValueError("Unexpected calls")

    mocker.patch("CreateNewIndicatorsOnly.execute_command", side_effect=__execute_command)

    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "indicator_values": ["1.1.1.1", "2.2.2.2"],
            "associate_to_current": "true",
        },
    )

    expected_entry_context = {
        "CreateNewIndicatorsOnly(val.Value && val.Value == obj.Value && val.Type && val.Type == obj.Type)": [
            {"CreationStatus": "unavailable", "Type": "Unknown", "Value": "1.1.1.1"},
            {"CreationStatus": "new", "ID": "0", "Score": 0, "Type": "Unknown", "Value": "2.2.2.2"},
        ]
    }

    mocker.patch.object(demisto, "results")
    CreateNewIndicatorsOnly.main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert "1 new indicators have been added" in results.get("HumanReadable")
    assert equals_object(expected_entry_context, results.get("EntryContext"))


def test_indicator_including_commas(mocker):
    """
    Given:
        An indicator given to the 'indicator_values' contains commas

    When:
        Running the script

    Then:
        Validate the right response returns.
    """

    mocker.patch.object(
        demisto,
        "searchIndicators",
        return_value={"iocs": [], "total": 0, "searchAfter": None},
    )

    def __execute_command(cmd, args) -> Any:
        if cmd == "createNewIndicator":
            return {"id": "0", "value": args.get("value"), "score": 0, "indicator_type": args.get("type", "Unknown")}
        elif cmd == "associateIndicatorToIncident":
            return "done"
        raise ValueError("Unexpected calls")

    mocker.patch("CreateNewIndicatorsOnly.execute_command", side_effect=__execute_command)

    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "indicator_values": "http://www.paloaltonetworks.com/?q=,123",
            "associate_to_current": "true",
        },
    )

    expected_entry_context = {
        "CreateNewIndicatorsOnly(val.Value && val.Value == obj.Value && val.Type && val.Type == obj.Type)": [
            {
                "CreationStatus": "new",
                "ID": "0",
                "Score": 0,
                "Type": "Unknown",
                "Value": "http://www.paloaltonetworks.com/?q=,123",
            }
        ]
    }

    mocker.patch.object(demisto, "results")
    CreateNewIndicatorsOnly.main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert "1 new indicators have been added" in results.get("HumanReadable")
    assert equals_object(expected_entry_context, results.get("EntryContext"))


def test_print_verbose(mocker):
    """
    Given:
        `verbose=true` is given to the argument parameters

    When:
        Running the script

    Then:
        Validate the right response returns.
    """

    mocker.patch.object(
        demisto,
        "searchIndicators",
        return_value={"iocs": [], "total": 0, "searchAfter": None},
    )

    def __execute_command(cmd, args) -> Any:
        if cmd == "createNewIndicator":
            return {"id": "0", "value": args.get("value"), "score": 0, "indicator_type": args.get("type", "Unknown")}
        elif cmd == "associateIndicatorToIncident":
            return "done"
        raise ValueError("Unexpected calls")

    mocker.patch("CreateNewIndicatorsOnly.execute_command", side_effect=__execute_command)

    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "indicator_values": "1.1.1.1",
            "verbose": "true",
            "associate_to_current": "true",
        },
    )

    expected_entry_context = {
        "CreateNewIndicatorsOnly(val.Value && val.Value == obj.Value && val.Type && val.Type == obj.Type)": [
            {"CreationStatus": "new", "ID": "0", "Score": 0, "Type": "Unknown", "Value": "1.1.1.1"}
        ]
    }

    mocker.patch.object(demisto, "results")
    CreateNewIndicatorsOnly.main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert "|ID|Score|CreationStatus|Type|Value" in results.get("HumanReadable")
    assert equals_object(expected_entry_context, results.get("EntryContext"))


def test_findIndicators_called_with_escaped_quotes(mocker):
    """
    Given:
        indicator_value = "(External):Test \"test2 test (unsigned)\""
    When:
        The 'find_existing_indicators_by_value' function is called with the indicator_value containing quotes
        (when the user runs in cli:!CreateNewIndicatorsOnlyTest indicator_values=`(External):Test "test2 test (unsigned)"`)
    Then:
        1. The 'demisto.searchIndicators' function should be called with the correct escaped value in the query.
        2. The 'add_new_indicator' function should return the expected result as a dictionary when given the pre-fetched lookup.
    """
    from CreateNewIndicatorsOnly import add_new_indicator, find_existing_indicators_by_value

    indicator_value = '(External):Test "test2 test (unsigned)"'
    escaped_value = indicator_value.replace('"', r"\"")

    def mock_search_indicators(query=None, size=100, **kwargs):
        assert query is not None
        assert f'value:"{escaped_value}"' in query
        return {
            "iocs": [
                {
                    "id": "0",
                    "value": '(External):Test "test2 test (unsigned)"',
                    "score": 0,
                    "indicator_type": "Unknown",
                }
            ],
            "total": 1,
            "searchAfter": None,
        }

    mocker.patch.object(demisto, "searchIndicators", side_effect=mock_search_indicators)

    # Test that find_existing_indicators_by_value builds the query with escaped quotes
    existing = find_existing_indicators_by_value([indicator_value])
    assert indicator_value.casefold() in existing

    # Test that add_new_indicator correctly looks up from the pre-fetched dict
    result = add_new_indicator(indicator_value, {}, existing_indicators_by_value=existing)
    assert result == {
        "id": "0",
        "value": '(External):Test "test2 test (unsigned)"',
        "score": 0,
        "indicator_type": "Unknown",
        "CreationStatus": "existing",
    }


class TestAssociateFailures:
    def test_add_new_indicator_associate_failed_once(self, mocker):
        """
        Given:
            - An indicator that was not indexed in the system the first time associateIndicatorToIncident is called.
        When:
            - Running add_new_indicator
        Then:
            - Assert 'add_new_indicator' returns the indicator.
        """
        import CreateNewIndicatorsOnly

        indicator_value = "test"
        new_indicator = {"id": "0", "value": "test", "score": 0, "indicator_type": "Unknown", "CreationStatus": "new"}
        global tries
        tries = 1

        def __execute_command(cmd, args) -> Any:
            global tries
            if cmd == "createNewIndicator":
                return new_indicator
            elif cmd == "associateIndicatorToIncident":
                if tries == 1:
                    tries += 1
                    raise Exception("For associateIndicatorToIncident found no indicatores with value: %s")
                else:
                    return "done"

            return None

        mocker.patch("CreateNewIndicatorsOnly.execute_command", side_effect=__execute_command)
        mocker.patch.object(demisto, "incidents", return_value=[{"id": "1"}])
        mocker.patch.object(time, "sleep", return_value=None)
        CreateNewIndicatorsOnly.SLEEP_TIME = 0

        result = CreateNewIndicatorsOnly.add_new_indicator(indicator_value, {}, True)
        assert result == new_indicator

    def test_add_new_indicator_associate_failed_always(self, mocker):
        """
        Given:
            - An indicator that is never indexed in the system.
        When:
            - Running add_new_indicator with associate_to_incident=true
        Then:
            - Assert 'add_new_indicator' returns an error.
        """
        import CreateNewIndicatorsOnly

        indicator_value = "test"
        new_indicator = {"id": "0", "value": "test", "score": 0, "indicator_type": "Unknown", "CreationStatus": "new"}

        def __execute_command(cmd, args) -> Any:
            if cmd == "createNewIndicator":
                return new_indicator
            elif cmd == "associateIndicatorToIncident":
                raise Exception("For associateIndicatorToIncident found no indicatores with value: %s")

            return None

        mocker.patch("CreateNewIndicatorsOnly.execute_command", side_effect=__execute_command)
        mocker.patch.object(time, "sleep", return_value=None)
        CreateNewIndicatorsOnly.MAX_FIND_INDICATOR_RETRIES = 2
        CreateNewIndicatorsOnly.SLEEP_TIME = 0
        mocker.patch.object(demisto, "incidents", return_value=[{"id": "1"}])

        with pytest.raises(Exception) as err:
            CreateNewIndicatorsOnly.add_new_indicator(indicator_value, {}, True)

        assert "Failed to associate test with incident 1" in str(err)


# =====================================================================
# Group 1: find_existing_indicators_by_value() unit tests
# =====================================================================


def test_find_existing_indicators_duplicate_inputs(mocker):
    """
    Given:
        A list with duplicate indicator values ["1.1.1.1", "1.1.1.1"].

    When:
        Calling find_existing_indicators_by_value.

    Then:
        - The query contains value:"1.1.1.1" only once (not duplicated).
        - The returned dict has one entry.
    """
    from CreateNewIndicatorsOnly import find_existing_indicators_by_value

    def mock_search_indicators(query=None, **kwargs):
        # Assert the query contains value:"1.1.1.1" only once
        assert query is not None
        assert query.count('value:"1.1.1.1"') == 1
        return {
            "iocs": [{"value": "1.1.1.1", "id": "1"}],
            "total": 1,
            "searchAfter": None,
        }

    mocker.patch.object(demisto, "searchIndicators", side_effect=mock_search_indicators)
    result = find_existing_indicators_by_value(["1.1.1.1", "1.1.1.1"])
    assert len(result) == 1
    assert "1.1.1.1" in result


def test_find_existing_indicators_case_insensitive(mocker):
    """
    Given:
        An indicator value "TEST.COM" in uppercase.

    When:
        Calling find_existing_indicators_by_value with ["TEST.COM"].

    Then:
        - The returned dict has key "test.com" (casefolded).
        - result.get("test.com") returns the indicator dict.
    """
    from CreateNewIndicatorsOnly import find_existing_indicators_by_value

    mocker.patch.object(
        demisto,
        "searchIndicators",
        return_value={"iocs": [{"value": "test.com", "id": "1"}], "total": 1, "searchAfter": None},
    )
    result = find_existing_indicators_by_value(["TEST.COM"])
    assert "test.com" in result
    assert result.get("test.com") == {"value": "test.com", "id": "1"}


def test_find_existing_indicators_pagination(mocker):
    """
    Given:
        Two indicators spread across two pages of search results.

    When:
        Calling find_existing_indicators_by_value with ["1.1.1.1", "2.2.2.2"].

    Then:
        - The returned dict has both entries.
        - demisto.searchIndicators was called twice (two pages).
    """
    from CreateNewIndicatorsOnly import find_existing_indicators_by_value

    call_count = 0

    def mock_search_indicators(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return {"iocs": [{"value": "1.1.1.1", "id": "1"}], "total": 2, "searchAfter": "token123"}
        else:
            return {"iocs": [{"value": "2.2.2.2", "id": "2"}], "total": 2, "searchAfter": None}

    mock_search = mocker.patch.object(demisto, "searchIndicators", side_effect=mock_search_indicators)
    result = find_existing_indicators_by_value(["1.1.1.1", "2.2.2.2"])
    assert "1.1.1.1" in result
    assert "2.2.2.2" in result
    assert len(result) == 2
    assert mock_search.call_count == 2


def test_find_existing_indicators_iocs_none(mocker):
    """
    Given:
        A search result where "iocs" is None.

    When:
        Calling find_existing_indicators_by_value with ["1.1.1.1"].

    Then:
        - The returned dict is empty (no crash).
    """
    from CreateNewIndicatorsOnly import find_existing_indicators_by_value

    mocker.patch.object(
        demisto,
        "searchIndicators",
        return_value={"iocs": None, "total": 0, "searchAfter": None},
    )
    result = find_existing_indicators_by_value(["1.1.1.1"])
    assert result == {}


# =====================================================================
# Group 2: add_new_indicator() edge cases
# =====================================================================


def test_add_new_indicator_case_insensitive_existing(mocker):
    """
    Given:
        An indicator value "TEST.COM" and an existing_indicators_by_value dict
        with key "test.com" (casefolded).

    When:
        Calling add_new_indicator with "TEST.COM".

    Then:
        - The returned indicator has CreationStatus == "existing".
        - associateIndicatorToIncident was called with "test.com" (the stored value, not "TEST.COM").
    """
    from CreateNewIndicatorsOnly import KEY_CREATION_STATUS, STATUS_EXISTING, add_new_indicator

    existing_indicators_by_value = {"test.com": {"value": "test.com", "id": "1"}}

    execute_command_mock = mocker.patch("CreateNewIndicatorsOnly.execute_command", return_value="done")
    mocker.patch.object(demisto, "incidents", return_value=[{"id": "100"}])

    result = add_new_indicator(
        "TEST.COM",
        create_new_indicator_args={},
        associate_to_incident=True,
        existing_indicators_by_value=existing_indicators_by_value,
    )

    assert result[KEY_CREATION_STATUS] == STATUS_EXISTING
    # Verify associateIndicatorToIncident was called with the stored value "test.com"
    execute_command_mock.assert_called_once_with(
        "associateIndicatorToIncident",
        {"incidentId": "100", "value": "test.com"},
    )


def test_add_new_indicator_without_existing_dict_creates_new(mocker):
    """
    Given:
        An indicator value "new.com" and existing_indicators_by_value is None (default).

    When:
        Calling add_new_indicator with "new.com".

    Then:
        - The returned indicator has CreationStatus == "new".
        - This tests backward compatibility when no pre-fetched lookup is provided.
    """
    from CreateNewIndicatorsOnly import KEY_CREATION_STATUS, STATUS_NEW, add_new_indicator

    new_indicator = {"id": "1", "value": "new.com", "score": 0, "indicator_type": "Unknown"}

    def __execute_command(cmd, args) -> Any:
        if cmd == "createNewIndicator":
            return dict(new_indicator)
        raise ValueError("Unexpected calls")

    mocker.patch("CreateNewIndicatorsOnly.execute_command", side_effect=__execute_command)

    result = add_new_indicator(
        "new.com",
        create_new_indicator_args={},
        existing_indicators_by_value=None,
    )

    assert result[KEY_CREATION_STATUS] == STATUS_NEW
