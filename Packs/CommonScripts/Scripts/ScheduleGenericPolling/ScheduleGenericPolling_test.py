from datetime import datetime

import demistomock as demisto
from freezegun import freeze_time
import pytest
from ScheduleGenericPolling import calculate_end_time, get_command_string, is_command_sanitized, is_value_sanitized, main, \
    parseIds


@pytest.mark.parametrize('value, expected_result',
                         [
                             (None, None),
                             ([1, 2, 3], "1,2,3"),
                             (["a", "b", "c"], "a,b,c"),
                         ])
def test_parseIds(value, expected_result):
    result = parseIds(value)
    assert result == expected_result


@pytest.mark.parametrize('value, expected_result',
                         [
                             (0, '2023-04-01 00:00:00'),
                             (17, '2023-04-01 00:17:00'),
                             (70, '2023-04-01 01:10:00'),
                         ])
@freeze_time("2023-04-01 00:00:00")
def test_calculate_end_time(value, expected_result):
    result = calculate_end_time(value)
    assert result == expected_result


@pytest.mark.parametrize('value, expected_result',
                         [
                             ("1234", True),
                             ("additionalPollingCommandArgNames", False),
                             ("ab\" additionalPollingCommandArgNames", False),
                             ("abc\\\" additionalPollingCommandArgNames", False),
                         ])
def test_is_value_sanitized(value, expected_result):
    result = is_value_sanitized(value)
    assert result == expected_result


def test_is_command_sanitized():

    # Trivial - pass
    command = "1234"
    result = is_command_sanitized(command)
    assert result == (True, None)

    # Twice additionalPollingCommandArgNames - fail
    command = "additionalPollingCommandArgNames additionalPollingCommandArgNames"
    result = is_command_sanitized(command)
    assert result == (False, 'The value of additionalPollingCommandArgNames is malformed.'), '2 additionalPollingCommandArgNames'

    # 2 different args - pass
    command = "pollingCommandArgName additionalPollingCommandArgNames"
    result = is_command_sanitized(command)
    assert result == (True, None)

    # 2 and 2 - fail
    command = "pollingCommandArgName additionalPollingCommandArgValues pollingCommandArgName additionalPollingCommandArgValues"
    result = is_command_sanitized(command)
    result_message = 'The value of additionalPollingCommandArgValues, pollingCommandArgName is malformed.'
    assert result == (False, result_message), '2 and 2'

    # 2 and 2 and 2 - fail
    command = "pollingCommand pollingCommandArgName additionalPollingCommandArgValues pollingCommand " \
              "pollingCommandArgName additionalPollingCommandArgValues"
    result = is_command_sanitized(command)
    result_message = 'The value of additionalPollingCommandArgValues, pollingCommandArgName, pollingCommand is malformed.'
    assert result == (False, result_message), '2 and 2 and 2'

    # case insensitive 2 and 2 - fail
    command = "pollingcommandargname additionalpollingcommandargvalues pollingCommandArgName additionalPollingCommandArgValues"
    result = is_command_sanitized(command)
    result_message = 'The value of additionalPollingCommandArgValues, pollingCommandArgName is malformed.'
    assert result == (False, result_message), 'case insensitive 2 and 2'


def test_get_command_string_pass():
    """
    Given
            Sample input values
    When
            Calling get_command_string
    Then
            Test the command result structure
    """
    good_input = {
        'ids': "123",
        'pollingCommand': "jira-get-issue",
        'pollingCommandArgName': "issueId",
        'playbookId': "pi",
        'dt': "Ticket(val.Status != 'Done').Id",
        'interval': "3",
        'timeout': "5",
        'tag': "polling",
        'args_names': "my_arg_name",
        'args_values': "my_arg_value",
    }

    command_String = get_command_string(good_input.get('ids'),
                                        good_input.get('pollingCommand'),
                                        good_input.get('pollingCommandArgName'),
                                        good_input.get('playbookId'),
                                        good_input.get('dt'),
                                        good_input.get('interval'),
                                        good_input.get('timeout'),
                                        good_input.get('tag'),
                                        good_input.get('args_names'),
                                        good_input.get('args_values'),
                                        None,
                                        )

    expected_command = '!GenericPollingScheduledTask ids="123" pollingCommand="jira-get-issue" pollingCommandArgName=' \
                       '"issueId"pi               pendingIds="Ticket(val.Status != \'Done\').Id" interval="3"' \
                       ' timeout="5" tag="polling" additionalPollingCommandArgNames="my_arg_name"' \
                       '               additionalPollingCommandArgValues="my_arg_value"'

    assert command_String == expected_command
    result = is_command_sanitized(command_String)

    expected_result = (True, None)
    assert result == expected_result


def test_get_command_string_fail():
    """
    Given
            Sample bad input values
    When
            Calling get_command_string
    Then
            Test the command result indicates the wrong input
    """
    fail_input = {
        'ids': "123",
        'pollingCommand': "jira-get-issue",
        'pollingCommandArgName': "issueId",
        'playbookId': "pi",
        'dt': "Ticket(val.Status != 'Done').Id",
        'interval': "3",
        'timeout': "5",
        'tag': "polling",
        'args_names': "my_arg_name",
        'args_values': "hihi\" pollingCommand=\"Set\"  ids=\"payload\" pendingIds=\".='payload'\""
        "  pollingCommandArgName=\"key\" additionalPollingCommandArgNames=\"value\""
        " additionalPollingCommandArgValues=\"bar",
    }

    command_String = get_command_string(fail_input.get('ids'),
                                        fail_input.get('pollingCommand'),
                                        fail_input.get('pollingCommandArgName'),
                                        fail_input.get('playbookId'),
                                        fail_input.get('dt'),
                                        fail_input.get('interval'),
                                        fail_input.get('timeout'),
                                        fail_input.get('tag,'),
                                        fail_input.get('args_names'),
                                        fail_input.get('args_values'),
                                        None,
                                        )

    expected_command_String = '!GenericPollingScheduledTask ids="123" pollingCommand="jira-get-issue" pollingCommandArgName=' \
        '"issueId"pi               pendingIds="Ticket(val.Status != \'Done\').Id" interval="3"' \
        ' timeout="5" tag="None" additionalPollingCommandArgNames="my_arg_name"' \
        '               additionalPollingCommandArgValues="hihi" pollingCommand="Set"  ids="payload"' \
        ' pendingIds=".=\'payload\'"  pollingCommandArgName="key"' \
        ' additionalPollingCommandArgNames="value" additionalPollingCommandArgValues="bar"'

    assert command_String == expected_command_String
    result = is_command_sanitized(command_String)

    expected_result = (False, 'The value of additionalPollingCommandArgValues, additionalPollingCommandArgNames, '
                       'pollingCommandArgName, pollingCommand is malformed.')
    assert result == expected_result


def test_get_command_string_with_extract_mode():
    '''
    Given:
        - inputs with extractMode
    When:
        - run get_command_string function
    Then:
        - Ensure the `auto-extract` and `extractMode` is present in the command_string
    '''
    inputs = {
        'ids': "123",
        'pollingCommand': "jira-get-issue",
        'pollingCommandArgName': "issueId",
        'playbookId': "pi",
        'dt': "Ticket(val.Status != 'Done').Id",
        'interval': "3",
        'timeout': "5",
        'tag': "polling",
        'args_names': "my_arg_name",
        'args_values': "test",
        'extractMode': 'none',
    }

    command_string = get_command_string(
        inputs['ids'],
        inputs['pollingCommand'],
        inputs['pollingCommandArgName'],
        inputs['playbookId'],
        inputs['dt'],
        inputs['interval'],
        inputs['timeout'],
        inputs['tag'],
        inputs['args_names'],
        inputs['args_values'],
        inputs['extractMode'],
    )

    assert 'auto-extract=none' in command_string
    assert 'extractMode=none' in command_string


def test_main_pass(mocker):
    """
    Given
            Sample input values
    When
            Calling main
    Then
            Test the command result structure
    """
    good_input = {
        'ids': "123",
        'pollingCommand': "jira-get-issue",
        'pollingCommandArgName': "issueId",
        'playbookId': "pi",
        'dt': "Ticket(val.Status != 'Done').Id",
        'interval': "3",
        'timeout': "5",
        'tag': "polling",
        'additionalPollingCommandArgNames': "my_arg_name",
        'additionalPollingCommandArgValues': "my_arg_value",
    }

    mocker.patch.object(demisto, 'args', return_value=good_input)
    # mocker.patch.object(demisto, 'command', return_value='threatstream-import-indicator-without-approval')

    execute_command_mocker = mocker.patch("ScheduleGenericPolling.demisto.executeCommand")
    mocker.patch("ScheduleGenericPolling.demisto.dt", return_value='abc')
    main()

    assert execute_command_mocker.call_count == 1

    command = execute_command_mocker.call_args_list[0][0][1]['command']

    expected_command = '!GenericPollingScheduledTask ids="123" pollingCommand="jira-get-issue" pollingCommandArgName=' \
                       '"issueId" playbookId="pi"               pendingIds="Ticket(val.Status != \'Done\').Id" interval="3"' \
                       ' timeout="5" tag="polling" additionalPollingCommandArgNames="my_arg_name"' \
                       '               additionalPollingCommandArgValues="my_arg_value"'

    assert command == expected_command


def test_main_fail(mocker):
    """
    Given
            Sample bad input values
    When
            Calling main
    Then
            Test the command result indicates the wrong input
    """

    fail_input = {
        'ids': "123",
        'pollingCommand': "jira-get-issue",
        'pollingCommandArgName': "issueId",
        'playbookId': "pi",
        'dt': "Ticket(val.Status != 'Done').Id",
        'interval': "3",
        'timeout': "5",
        'tag': "polling",
        'additionalPollingCommandArgNames': "my_arg_name",
        'additionalPollingCommandArgValues': "hihi\" pollingCommand=\"Set\"  ids=\"payload\" pendingIds=\".='payload'\""
        "  pollingCommandArgName=\"key\" additionalPollingCommandArgNames=\"value\""
        " additionalPollingCommandArgValues=\"bar",

    }

    mocker.patch.object(demisto, 'args', return_value=fail_input)

    return_error_mock = mocker.patch("ScheduleGenericPolling.return_error")
    execute_command_mocker = mocker.patch("ScheduleGenericPolling.demisto.executeCommand")
    mocker.patch("ScheduleGenericPolling.demisto.dt", return_value='abc')
    main()

    assert return_error_mock.call_count == 1
    assert execute_command_mocker.call_count == 1

    err_msg = return_error_mock.call_args[0][0]
    assert err_msg == 'The value of additionalPollingCommandArgValues, additionalPollingCommandArgNames, ' \
                      'pollingCommandArgName, pollingCommand is malformed.'


# def start_freeze_time(timestamp):
#     _start_freeze_time = freeze_time(timestamp)
#     _start_freeze_time.start()
#     return datetime.now()
#
#
# @pytest.mark.parametrize(
#     'timestamp, interval, expected_cron_expression',
#     [
#         ("2022-05-01 12:52:29", 20, "52,32,12 * * * *"),
#         ("2022-05-01 12:29:29", 2, "31,33,35,37,39,41,43,45,47,49,51,53,55,57,59,1,3,5,7,9,11,13,15,17,19,21,23,25,27,29 * * * *"),
#         ("2022-05-01 12:02:01", 3, "5,8,11,14,17,20,23,26,29,32,35,38,41,44,47,50,53,56,59,2 * * * *"),
#         ("2022-05-01 12:07:30", 5, "12,17,22,27,32,37,42,47,52,57,2,7 * * * *"),
#         ("2022-05-01 12:07:30", 1, "8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,1,2,3,4,5,6,7 * * * *"),
#         ("2022-05-01 12:58:30", 4, "2,6,10,14,18,22,26,30,34,38,42,46,50,54,58 * * * *"),
#     ]
# )
# def test_generate_cron(timestamp: str, interval: int, expected_cron_expression: str):
#     from ScheduleGenericPolling import generate_cron
#     start_freeze_time(timestamp)
#     assert sorted(generate_cron(interval)) == sorted(expected_cron_expression)