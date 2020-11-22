import json
from unittest.mock import patch

from CommonServerPython import *
from BMCHelixRemedyforceCreateIncident import remove_extra_space_from_args, main,\
    ERROR_MESSAGES, get_field_id

DUMMY_COMMAND_RESPONSE = [{"Contents": {}}]


def fetch_dummy_incidents():
    """
    To fetch dummy response of incident.

    :return: dummy incident response
    :rtype: ``dict``
    """
    with open('./TestData/Incident.json', encoding='utf-8') as f:
        data = json.load(f)
    return data


def test_get_field_id_with_id():
    """
    Test-case to check field_id is passed then it should return that field_id.

    :return: None
    """
    actual_result = get_field_id("id", "name", "", {}, "ins")
    assert actual_result == "id"


@patch('demistomock.executeCommand')
def test_get_field_id_positive_scenario(mocker_execute_command):
    """
    When field_id is not passed and field_name passed as argument
    Then method should return field_id.

    :param mocker_execute_command: mocker object for executeCommand
    :return: None
    """
    mocker_execute_command.return_value = [{"Contents": {"records": [{"Id": "abc"}]}}]
    actual_result = get_field_id(None, "name", "", {}, "ins")
    assert actual_result == "abc"


@patch('BMCHelixRemedyforceCreateIncident.return_error')
@patch('demistomock.executeCommand')
def test_get_field_id_null_results(mocker_execute_command, mocker_return_error):
    """
    When field_id is not passed and field_id not found on given name
    Then method should return error as expected.

    :param mocker_execute_command: mocker object for executeCommand
    :param mocker_return_error: mocker object for return_error
    :return: None
    """
    mocker_execute_command.return_value = DUMMY_COMMAND_RESPONSE
    get_field_id(None, "name", "", {}, "ins")
    assert mocker_return_error.called
    for call in mocker_return_error.call_args_list:
        args, _ = call
        assert args[0] == ERROR_MESSAGES + json.dumps(DUMMY_COMMAND_RESPONSE)


@patch('demistomock.executeCommand')
def test_get_field_id_records_as_list(mocker_execute_command):
    """
    Get field id from name when api response will be a list.

    :param mocker_execute_command: mocker object for executeCommand
    :return: None
    """
    mocker_execute_command.return_value = [{"Contents": [{"Id": "abc"}]}]
    actual_result = get_field_id(None, "name", "", {}, "ins")
    assert actual_result == "abc"


@patch('demistomock.results')
@patch('sys.exit')
@patch('demistomock.executeCommand')
def test_get_field_id_no_records_found(mocker_execute_command, mocker_exit, mocker_results):
    """
    When field_id could not be found for mentioned name in args then verfying demisto.results and
    system will exit with field 0.

    :param mocker_execute_command: mocker object for executeCommand
    :param mocker_exit: mocker object for sys.exit
    :param mocker_results: mocker object for results
    :return: None
    """
    mocker_execute_command.return_value = [{"Contents": "abc"}]
    get_field_id(None, "name", "", {}, "ins")
    assert mocker_exit.called
    assert mocker_results.called
    for call in mocker_exit.call_args_list:
        args, _ = call
        assert args[0] == 0


def test_remove_extra_space_from_args():
    """
    Given a dictionary of arguments
    When remove_extra_space_from_args is called upon them
    Then returned arguments dictionary should not contain any argument value with leading or trailing whitespaces
        and the ones with NoneType should be removed
    :return:
    """

    sample_args = {"bad_1": "", "bad_2": "      ", "can_be_better": " good  ", "good": "good", "very_bad": None}
    sanitized_args = {"can_be_better": "good", "good": "good"}
    assert sanitized_args == remove_extra_space_from_args(sample_args)


@patch('BMCHelixRemedyforceCreateIncident.return_error')
@patch('demistomock.executeCommand')
@patch('demistomock.args')
def test_main_fail(demisto_args, mocker_execute_command, mocker_return_error):
    """
    Testcase of main method in failure scenarios.

    :param demisto_args: mocker object for args
    :param mocker_execute_command: mocker object for executeCommand
    :param mocker_return_error: mocker object for return_error
    :return: None
    """
    args = fetch_dummy_incidents()['args']
    demisto_args.return_value = args
    mocker_execute_command.return_value = [{"Contents": "No records found.", "Type": entryTypes['error']}]
    main()
    assert mocker_return_error.called
    for call in mocker_return_error.call_args_list:
        args, _ = call
        assert args[0] == 'No records found.'


@patch('BMCHelixRemedyforceCreateIncident.return_error')
@patch('demistomock.executeCommand')
@patch('demistomock.args')
def test_main_exception(demisto_args, mocker_execute_command, mocker_return_error):
    """
    Testcase of main method while any exception will be raised.

    :param demisto_args: mocker object for args
    :param mocker_execute_command: mocker object for executeCommand
    :param mocker_return_error: mocker object for return_error
    :return: None
    """
    args = fetch_dummy_incidents()["args"]
    demisto_args.return_value = args
    mocker_execute_command.return_value = [{"Type": entryTypes['error']}]
    main()
    assert mocker_return_error.called
    for call in mocker_return_error.call_args_list:
        args, _ = call
        assert args[0] == "'Contents'"


@patch('BMCHelixRemedyforceCreateIncident.return_error')
@patch('demistomock.executeCommand')
@patch('demistomock.args')
def test_main_fail_to_execute_command(demisto_args, mocker_execute_command, mocker_return_error):
    """
    Testcase of main method when command: 'bmc-remedy-incident-create' will be failed to execute.

    :param demisto_args: mocker object for args
    :param mocker_execute_command: mocker object for executeCommand
    :param mocker_return_error: mocker object for return_error
    :return: None
    """
    args = fetch_dummy_incidents()["args"]
    demisto_args.return_value = args
    mocker_execute_command.return_value = [{"Contents": [], "Type": "abc"}]
    main()
    assert mocker_return_error.called
    for call in mocker_return_error.call_args_list:
        args, _ = call
        assert args[0] == ERROR_MESSAGES + '{"Contents": [], "Type": "abc"}'


@patch('demistomock.results')
@patch('demistomock.executeCommand')
@patch('demistomock.args')
def test_main_success(demisto_args, mocker_execute_command, mocker_results):
    """
    Testcase of main method in positive scenario.

    :param demisto_args: mocker object for args
    :param mocker_execute_command: mocker object for executeCommand
    :param mocker_results: mocker object for results
    :return: None
    """
    args = fetch_dummy_incidents()["args"]
    demisto_args.return_value = args
    expected_args = fetch_dummy_incidents()["expected_args"]
    command_name = 'bmc-remedy-incident-create'
    mocker_execute_command.return_value = [
        {"Contents": {"Result": {"Number": 123}}, "Type": "abc", "HumanReadable": "abc"}]
    main()
    assert mocker_results.called
    for call in mocker_results.call_args_list:
        args, _ = call
        assert args[0]['HumanReadable'] == 'abc'
    for call in mocker_execute_command.call_args_list:
        command_args, _ = call
        assert command_args[0] == command_name
        assert command_args[1] == expected_args
