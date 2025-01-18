
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
        ' timeout="5" tag="None" additionalPollingCommandArgNames="my_arg_name"               ' \
                              'additionalPollingCommandArgValues="hihi\\" pollingCommand=\\"Set\\"  ' \
                              'ids=\\"payload\\" pendingIds=\\".=\'payload\'\\"  ' \
                              'pollingCommandArgName=\\"key\\" additionalPollingCommandArgNames=\\"value\\" ' \
                              'additionalPollingCommandArgValues=\\"bar"'

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
