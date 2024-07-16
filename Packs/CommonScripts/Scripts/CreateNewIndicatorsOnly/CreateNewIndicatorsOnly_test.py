import demistomock as demisto
from CommonServerPython import *  # noqa: F401
import CreateNewIndicatorsOnly
from typing import Any
import pytest


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
    mocker.patch.object(demisto, 'args', return_value={
        'indicator_values': [],
    })

    expected_entry_context = {}

    mocker.patch.object(demisto, 'results')
    CreateNewIndicatorsOnly.main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert '0 new indicators have been added' in results.get('HumanReadable')
    assert equals_object(expected_entry_context, results.get('EntryContext'))


def test_all_indicators_exist_with_single_value(mocker):
    """
        Given:
            A single indicator existing in the threat intel is given to the 'indicator_values'.

        When:
            Running the script

        Then:
            Validate the right response returns.
    """
    def __execute_command(cmd, args) -> Any:
        if cmd == 'findIndicators':
            return [{
                'id': '0',
                'value': args.get('value'),
                'score': 0,
                'indicator_type': args.get('type', 'Unknown')
            }]
        elif cmd == 'associateIndicatorToIncident':
            return 'done'
        raise ValueError('Unexpected calls')

    mocker.patch('CreateNewIndicatorsOnly.execute_command', side_effect=__execute_command)

    mocker.patch.object(demisto, 'args', return_value={
        'indicator_values': '1.1.1.1',
        'associate_to_current': 'true',
    })

    expected_entry_context = {
        'CreateNewIndicatorsOnly(val.Value && val.Value == obj.Value && val.Type && val.Type == obj.Type)': [{
            'CreationStatus': 'existing',
            'ID': '0',
            'Score': 0,
            'Type': 'Unknown',
            'Value': '1.1.1.1'
        }
        ]
    }

    mocker.patch.object(demisto, 'results')
    CreateNewIndicatorsOnly.main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert '0 new indicators have been added' in results.get('HumanReadable')
    assert equals_object(expected_entry_context, results.get('EntryContext'))


def test_all_indicators_exist_with_multiple_value(mocker):
    """
        Given:
            All indicators existing in the threat intel are given to the 'indicator_values'.

        When:
            Running the script

        Then:
            Validate the right response returns.
    """
    def __execute_command(cmd, args) -> Any:
        if cmd == 'findIndicators':
            return [{
                'id': '0',
                'value': args.get('value'),
                'score': 0,
                'indicator_type': args.get('type', 'Unknown')
            }]
        elif cmd == 'associateIndicatorToIncident':
            return 'done'
        raise ValueError('Unexpected calls')

    mocker.patch('CreateNewIndicatorsOnly.execute_command', side_effect=__execute_command)

    mocker.patch.object(demisto, 'args', return_value={
        'indicator_values': [
            '1.1.1.1',
            '2.2.2.2'
        ],
        'associate_to_current': 'true',
    })

    expected_entry_context = {
        'CreateNewIndicatorsOnly(val.Value && val.Value == obj.Value && val.Type && val.Type == obj.Type)': [{
            'CreationStatus': 'existing',
            'ID': '0',
            'Score': 0,
            'Type': 'Unknown',
            'Value': '1.1.1.1'
        }, {
            'CreationStatus': 'existing',
            'ID': '0',
            'Score': 0,
            'Type': 'Unknown',
            'Value': '2.2.2.2'
        }
        ]
    }

    mocker.patch.object(demisto, 'results')
    CreateNewIndicatorsOnly.main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert '0 new indicators have been added' in results.get('HumanReadable')
    assert equals_object(expected_entry_context, results.get('EntryContext'))


def test_some_indicators_exist_with_multiple_value(mocker):
    """
        Given:
            Some indicators existing in the threat intel are given to the 'indicator_values'.

        When:
            Running the script

        Then:
            Validate the right response returns.
    """
    def __execute_command(cmd, args) -> Any:
        if cmd == 'findIndicators':
            value = args.get('value')
            if value != '1.1.1.1':
                return []
            else:
                return [{
                    'id': '0',
                    'value': args.get('value'),
                    'score': 0,
                    'indicator_type': args.get('type', 'Unknown')
                }]
        elif cmd == 'createNewIndicator':
            return {
                'id': '0',
                'value': args.get('value'),
                'score': 0,
                'indicator_type': args.get('type', 'Unknown')
            }
        elif cmd == 'associateIndicatorToIncident':
            return 'done'
        raise ValueError('Unexpected calls')

    mocker.patch('CreateNewIndicatorsOnly.execute_command', side_effect=__execute_command)

    mocker.patch.object(demisto, 'args', return_value={
        'indicator_values': [
            '1.1.1.1',
            '2.2.2.2'
        ],
        'associate_to_current': 'true',
    })

    expected_entry_context = {
        'CreateNewIndicatorsOnly(val.Value && val.Value == obj.Value && val.Type && val.Type == obj.Type)': [{
            'CreationStatus': 'existing',
            'ID': '0',
            'Score': 0,
            'Type': 'Unknown',
            'Value': '1.1.1.1'
        }, {
            'CreationStatus': 'new',
            'ID': '0',
            'Score': 0,
            'Type': 'Unknown',
            'Value': '2.2.2.2'
        }
        ]
    }

    mocker.patch.object(demisto, 'results')
    CreateNewIndicatorsOnly.main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert '1 new indicators have been added' in results.get('HumanReadable')
    assert equals_object(expected_entry_context, results.get('EntryContext'))


def test_some_indicators_are_excluded(mocker):
    """
        Given:
            Some indicators given to the 'indicator_values' are in the exclusion list.

        When:
            Running the script

        Then:
            Validate the right response returns.
    """
    def __execute_command(cmd, args) -> Any:
        if cmd == 'findIndicators':
            return []
        elif cmd == 'createNewIndicator':
            value = args.get('value')
            if value == '1.1.1.1':
                return 'done - Indicator was not created'
            else:
                return {
                    'id': '0',
                    'value': args.get('value'),
                    'score': 0,
                    'indicator_type': args.get('type', 'Unknown')
                }
        elif cmd == 'associateIndicatorToIncident':
            return 'done'
        raise ValueError('Unexpected calls')

    mocker.patch('CreateNewIndicatorsOnly.execute_command', side_effect=__execute_command)

    mocker.patch.object(demisto, 'args', return_value={
        'indicator_values': [
            '1.1.1.1',
            '2.2.2.2'
        ],
        'associate_to_current': 'true',
    })

    expected_entry_context = {
        'CreateNewIndicatorsOnly(val.Value && val.Value == obj.Value && val.Type && val.Type == obj.Type)': [{
            'CreationStatus': 'unavailable',
            'Type': 'Unknown',
            'Value': '1.1.1.1'
        }, {
            'CreationStatus': 'new',
            'ID': '0',
            'Score': 0,
            'Type': 'Unknown',
            'Value': '2.2.2.2'
        }
        ]
    }

    mocker.patch.object(demisto, 'results')
    CreateNewIndicatorsOnly.main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert '1 new indicators have been added' in results.get('HumanReadable')
    assert equals_object(expected_entry_context, results.get('EntryContext'))


def test_indicator_including_commas(mocker):
    """
        Given:
            An indicator given to the 'indicator_values' contains commas

        When:
            Running the script

        Then:
            Validate the right response returns.
    """
    def __execute_command(cmd, args) -> Any:
        if cmd == 'findIndicators':
            return []
        elif cmd == 'createNewIndicator':
            return {
                'id': '0',
                'value': args.get('value'),
                'score': 0,
                'indicator_type': args.get('type', 'Unknown')
            }
        elif cmd == 'associateIndicatorToIncident':
            return 'done'
        raise ValueError('Unexpected calls')

    mocker.patch('CreateNewIndicatorsOnly.execute_command', side_effect=__execute_command)

    mocker.patch.object(demisto, 'args', return_value={
        'indicator_values': 'http://www.paloaltonetworks.com/?q=,123',
        'associate_to_current': 'true',
    })

    expected_entry_context = {
        'CreateNewIndicatorsOnly(val.Value && val.Value == obj.Value && val.Type && val.Type == obj.Type)': [{
            'CreationStatus': 'new',
            'ID': '0',
            'Score': 0,
            'Type': 'Unknown',
            'Value': 'http://www.paloaltonetworks.com/?q=,123'
        }
        ]
    }

    mocker.patch.object(demisto, 'results')
    CreateNewIndicatorsOnly.main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert '1 new indicators have been added' in results.get('HumanReadable')
    assert equals_object(expected_entry_context, results.get('EntryContext'))


def test_print_verbose(mocker):
    """
        Given:
            `verbose=true` is given to the argument parameters

        When:
            Running the script

        Then:
            Validate the right response returns.
    """
    def __execute_command(cmd, args) -> Any:
        if cmd == 'findIndicators':
            return []
        elif cmd == 'createNewIndicator':
            return {
                'id': '0',
                'value': args.get('value'),
                'score': 0,
                'indicator_type': args.get('type', 'Unknown')
            }
        elif cmd == 'associateIndicatorToIncident':
            return 'done'
        raise ValueError('Unexpected calls')

    mocker.patch('CreateNewIndicatorsOnly.execute_command', side_effect=__execute_command)

    mocker.patch.object(demisto, 'args', return_value={
        'indicator_values': '1.1.1.1',
        'verbose': 'true',
        'associate_to_current': 'true',
    })

    expected_entry_context = {
        'CreateNewIndicatorsOnly(val.Value && val.Value == obj.Value && val.Type && val.Type == obj.Type)': [{
            'CreationStatus': 'new',
            'ID': '0',
            'Score': 0,
            'Type': 'Unknown',
            'Value': '1.1.1.1'
        }
        ]
    }

    mocker.patch.object(demisto, 'results')
    CreateNewIndicatorsOnly.main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert '|ID|Score|CreationStatus|Type|Value' in results.get('HumanReadable')
    assert equals_object(expected_entry_context, results.get('EntryContext'))


def test_findIndicators_called_with_escaped_quotes(mocker):
    """
    Given:
        indicator_value = "(External):Test \"test2 test (unsigned)\""
    When:
        The 'add_new_indicator' function is called with the indicator_value = "(External):Test \"test2 test (unsigned)\""
        (when the user runs in cli:!CreateNewIndicatorsOnlyTest indicator_values=`(External):Test "test2 test (unsigned)"`)
    Then:
        1. The 'execute_command' function should be called with the correct escaped value.
        2. The 'add_new_indicator' function should return the expected result as a dictionary.
    """
    from CreateNewIndicatorsOnly import add_new_indicator
    indicator_value = "(External):Test \"test2 test (unsigned)\""
    expected_value = indicator_value.replace('"', r"\"")

    def __execute_command(cmd, args) -> Any:
        if cmd == 'findIndicators':
            assert args == {'value': expected_value}
            return [{
                'id': '0',
                'value': '(External):Test "test2 test (unsigned)"',
                'score': 0,
                'indicator_type': args.get('type', 'Unknown')
            }]
        elif cmd == 'associateIndicatorToIncident':
            assert args == {'incidentId': '1', 'value': indicator_value}
            return 'done'
        return None

    mocker.patch('CreateNewIndicatorsOnly.execute_command', side_effect=__execute_command)

    result = add_new_indicator(indicator_value, {})
    assert result == {'id': '0', 'value': '(External):Test "test2 test (unsigned)"',
                      'score': 0, 'indicator_type': 'Unknown', 'CreationStatus': 'existing'}


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
        new_indicator = {'id': '0', 'value': 'test', 'score': 0, 'indicator_type': 'Unknown', 'CreationStatus': 'new'}
        global tries
        tries = 1

        def __execute_command(cmd, args) -> Any:
            global tries
            if cmd == 'findIndicators':
                assert args == {'value': indicator_value}
                return None
            if cmd == 'createNewIndicator':
                return new_indicator
            elif cmd == 'associateIndicatorToIncident':
                if tries == 1:
                    tries += 1
                    raise Exception("For associateIndicatorToIncident found no indicatores with value: %s")
                else:
                    return 'done'

            return None

        mocker.patch('CreateNewIndicatorsOnly.execute_command', side_effect=__execute_command)
        mocker.patch.object(demisto, 'incidents', return_value=[{'id': '1'}])
        mocker.patch.object(time, 'sleep', return_value=None)
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
        new_indicator = {'id': '0', 'value': 'test', 'score': 0, 'indicator_type': 'Unknown', 'CreationStatus': 'new'}

        def __execute_command(cmd, args) -> Any:
            if cmd == 'findIndicators':
                assert args == {'value': indicator_value}
                return None
            if cmd == 'createNewIndicator':
                return new_indicator
            elif cmd == 'associateIndicatorToIncident':
                raise Exception("For associateIndicatorToIncident found no indicatores with value: %s")

            return None

        mocker.patch('CreateNewIndicatorsOnly.execute_command', side_effect=__execute_command)
        mocker.patch.object(time, 'sleep', return_value=None)
        CreateNewIndicatorsOnly.MAX_FIND_INDICATOR_RETRIES = 2
        CreateNewIndicatorsOnly.SLEEP_TIME = 0
        mocker.patch.object(demisto, 'incidents', return_value=[{'id': '1'}])

        with pytest.raises(Exception) as err:
            CreateNewIndicatorsOnly.add_new_indicator(indicator_value, {}, True)

        assert "Failed to associate test with incident 1" in str(err)
