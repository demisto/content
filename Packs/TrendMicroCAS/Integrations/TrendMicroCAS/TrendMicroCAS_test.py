import pytest
from TrendMicroCAS import Client, security_events_list_command, email_sweep_command, parse_date_to_isoformat,\
    user_take_action_command, email_take_action_command, user_action_result_command, blocked_lists_get_command,\
    blocked_lists_update_command
import datetime
import test_data.commands_raw_response as data
from CommonServerPython import CommandResults

client = Client(base_url='https://test.com', verify=False, headers={'Authorization': f'Bearer {"1243545"}'})


args_test_security_events_list = [
    {'service': 'onedrive', 'event_type': 'securityrisk'},
    {'service': 'onedrive', 'event_type': 'securityrisk', 'start': '1 day'},
    {'service': 'onedrive', 'event_type': 'securityrisk', 'start': '2020-01-01T00:00Z', 'end': '3 days'}]


@pytest.mark.parametrize('args', args_test_security_events_list)
def test_security_events_list_command(mocker, args):
    """Tests security_events_list_command function
    Given
        1. service=onedrive and event_type=securityrisk in arguments
        2. service=onedrive and event_type=securityrisk and start=1 day
        3. service=onedrive and event_type=securityrisk and start=1 day and end=now

    When
        - Calling `security_events_list_command`
    Then
        - convert the result to human readable table
        - create the context
        - validate the context data, the key, and the prefix.
    """
    mocker.patch.object(client, '_http_request', return_value=data.SECURITY_EVENTS_LIST_RESULT)
    results = security_events_list_command(client, args)
    assert results[0].outputs == data.SECURITY_EVENTS_LIST_OUTPUT['security_risk']
    assert results[0].outputs_key_field == 'log_item_id'
    assert results[0].outputs_prefix == 'TrendMicroCAS.Events'


args_test_security_events_list = [
    {'limit': '1'},
    {'limit': '1', 'start': '12 days', 'end': '10 days'},
    {'limit': '1', 'start': '2020-01-01', 'end': '1 day'}]


@pytest.mark.parametrize('args', args_test_security_events_list)
def test_email_sweep_command(mocker, args):
    """Tests email_sweep_command function
   Given
        1. limit=1 in arguments
        2. limit=1 and start=12 days and end=10 days
        3. limit=1 start=2020-01-01 and end=now

    When
        - Calling `email_sweep_command`
    Then
        - convert the result to human readable table
        - create the context
        - validate the context data, the key, and the prefix.
    """
    mocker.patch.object(client, '_http_request', return_value=data.EMAIL_SWEEP_RESULT)
    results: CommandResults = email_sweep_command(client, args)
    assert results.outputs == data.EMAIL_SWEEP_RESULT
    assert results.outputs_key_field == 'traceId'
    assert results.outputs_prefix == 'TrendMicroCAS.EmailSweep'


def test_user_take_action_command(mocker):
    """Tests user_take_action_command  function
    Given
        args = action_type=action_type and account_user_email=account_user_email1,account_user_email2'
    When
        - Calling `user_take_action_command`
    Then
        - convert the result to human readable table
        - create the context
        - validate the context data, the key, and the prefix.
    """
    mocker.patch.object(client, '_http_request', return_value=data.USER_TAKE_ACTION_RESULT)
    args = {
        'action_type': 'action_type',
        'account_user_email': 'account_user_email1, account_user_email2'
    }
    results: CommandResults = user_take_action_command(client, args)
    assert results.outputs == data.USER_TAKE_ACTION_OUTPUT
    assert results.outputs_key_field == 'batch_id'
    assert results.outputs_prefix == 'TrendMicroCAS.UserTakeAction'


def test_email_take_action_command(mocker):
    """Tests email_take_action_command  function
    Given
        args = action_type=action_type and mailbox=mailbox and mail_message_id=mail_message_id and
        mail_unique_id=mail_unique_id and mail_message_delivery_time=2020-07-13T01:52:50.000Z
    When
        - Calling `email_take_action_command`
    Then
        - convert the result to human readable table
        - create the context
        - validate the context data, the key, and the prefix.
    """
    mocker.patch.object(client, '_http_request', return_value=data.EMAIL_TAKE_ACTION_RESULT)
    args = {
        'action_type': 'action_type',
        'mailbox': 'mailbox',
        'mail_message_id': 'mail_message_id',
        'mail_unique_id': 'mail_unique_id',
        'mail_message_delivery_time': '2020-07-13T01:52:50.000Z'
    }
    results: CommandResults = email_take_action_command(client, args)
    assert results.outputs == data.EMAIL_TAKE_ACTION_OUTPUT
    assert results.outputs_key_field == 'batch_id'
    assert results.outputs_prefix == 'TrendMicroCAS.EmailTakeAction'


args_test_user_action_result = [
    {'limit': '5'},
    {'start': '12 hours', 'end': '10 hours'},
    {'batch_id': 'batch_id'}]


@pytest.mark.parametrize('args', args_test_user_action_result)
def test_user_action_result_command(mocker, args):
    """Tests user_action_result_command function
   Given
        1. limit=r in arguments
        2. start=12 hours and end=10 hours
        3. batch_id=batch_id'

    When
        - Calling `email_sweep_command`
    Then
        - convert the result to human readable table
        - create the context
        - validate the context data, the key, and the prefix.
    """
    mocker.patch.object(client, '_http_request', return_value=data.USER_ACTION_RESULT_RESULT)
    results: CommandResults = user_action_result_command(client, args)
    assert results.outputs == data.USER_ACTION_RESULT_OUTPUT
    assert results.outputs_key_field == 'batch_id'
    assert results.outputs_prefix == 'TrendMicroCAS.UserActionResult'


def test_blocked_lists_get_command(mocker):
    """Tests blocked_lists_get_command function
    When
        - Calling `blocked_lists_get_command`
    Then
        - convert the result to human readable table
        - create the context
        - validate the context data, the key, and the prefix.
    """
    mocker.patch.object(client, '_http_request', return_value=data.BLOCKED_LISTS_GET_RESULT)
    results: CommandResults = blocked_lists_get_command(client)
    assert results.outputs == data.BLOCKED_LISTS_OUTPUT
    assert results.outputs_key_field == 'BlockedList'
    assert results.outputs_prefix == 'TrendMicroCAS.BlockedList'


def test_blocked_lists_update_command(mocker):
    """Tests blocked_lists_update_command function
    Given
        args = action_type=action_type and senders=456@gmail.com,123@gmail.com and urls=123.com,456.com,789.com and
         filehashes=f3cdddb37f6a933d6a256bd98b4bc703a448c621'
    When
        - Calling `blocked_lists_update_command`
    Then
        - convert the result to human readable table
        - create the context
        - validate the context data, the key, and the prefix.
    """
    args = {
        'action_type': 'action_type',
        'senders': '456@gmail.com,123@gmail.com',
        'urls': '123.com,456.com,789.com',
        'filehashes': 'f3cdddb37f6a933d6a256bd98b4bc703a448c621'
    }
    mocker.patch.object(client, '_http_request', return_value=data.BLOCKED_LISTS_UPDATE_RESULT)
    results: CommandResults = blocked_lists_update_command(client, args)
    assert results.outputs == data.BLOCKED_LISTS_OUTPUT
    assert results.outputs_key_field == 'BlockedList'
    assert results.outputs_prefix == 'TrendMicroCAS.BlockedList'


DATA_TEST_PARSE_DATE_TO_ISOFORMAT = [
    ('08/09/10', '2010-08-09T00:00:00Z'),
    ('08.09.10', '2010-08-09T00:00:00Z'),
    ('08-09-10', '2010-08-09T00:00:00Z'),
    ('9/10/11 09:45:33', '2011-09-10T09:45:33Z'),

]


@pytest.mark.parametrize('date_input, fan_result', DATA_TEST_PARSE_DATE_TO_ISOFORMAT)
def test_parse_date_to_isoformat(date_input, fan_result):
    """Tests parse_date_to_isoformat function
    Given
        1. 08/09/10
        2. 08.09.10
        3. 08-09-10
        4. 9/10/11
    When
        - Calling `parse_date_to_isoformat function`
    Then
        - convert the date to isoformat string
        - validate result are in isoformat string %Y-%m-%dT%H:%M:%SZ:
        1. = 2010-08-09T00:00:00Z
        2. = 2010-08-09T00:00:00Z
        3. = 2010-08-09T00:00:00Z
        4. = 2011-09-10T09:45:33Z
    """
    result = parse_date_to_isoformat(date_input, 'test')
    assert result == fan_result


DATA_TEST_PARSE_DATE_TO_ISOFORMAT_FREE_TEXT = [
    '1 day',
    '3 months',
    '1 week and 1 day'
]


@pytest.mark.parametrize('date_input', DATA_TEST_PARSE_DATE_TO_ISOFORMAT_FREE_TEXT)
def test_parse_date_to_isoformat_on_free_text(date_input):
    """Tests parse_date_to_isoformat function
    Given
        free text:
        1. 1 day
        2. 3 months
        3. 1 week and 1 day
    When
        - Calling `parse_date_to_isoformat function`
    Then
        - convert the date to isoformat string
        - validate result are in isoformat string %Y-%m-%dT%H:%M:%SZ:
    """
    result = parse_date_to_isoformat(date_input, 'test')
    try:
        datetime.datetime.strptime(result, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        its_not_isoformat = True
    assert its_not_isoformat
