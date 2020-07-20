import pytest
import datetime
from TrendMicroCAS import Client, security_events_list_command, parse_date_to_isoformat, email_sweep_command, user_take_action_command, email_take_action_command, user_action_result_command, blocked_lists_get_command, blocked_lists_update_command

from CommonServerPython import CommandResults

client = Client(base_url='https://test.com', verify=False, headers={'Authorization': f'Bearer {"1243545"}'})


def test_security_events_list_command(mocker):
    """Tests security_events_list_command function
    Given
    - args
    - raw response of the database
    When
    - mock the client's http_request
    Then
    - convert the result to human readable table
    - create the context
    - validate the expected_result and the created context
    """
    mocker.patch.object(client, '_http_request', return_value=SECURITY_EVENTS_LIST_RESULT)
    args = {
        'service': 'onedrive',
        'event_type': 'securityrisk'
    }
    results: CommandResults = security_events_list_command(client, args)
    assert results.outputs == SECURITY_EVENTS_LIST_RESULT
    assert results.outputs_key_field == 'traceId'
    assert results.outputs_prefix == 'TrendMicroCAS.Events'


def test_email_sweep_command(mocker):
    """Tests email_sweep_command function
    Given
    - args
    - raw response of the database
    When
    - mock the client's http_request
    Then
    - convert the result to human readable table
    - create the context
    - validate the expected_result and the created context
    """
    mocker.patch.object(client, '_http_request', return_value=EMAIL_SWEEP_RESULT)
    args = {
        'limit': '1',
        'start': '1 day'
    }
    results: CommandResults = email_sweep_command(client, args)
    assert results.outputs == EMAIL_SWEEP_RESULT
    assert results.outputs_key_field == 'traceId'
    assert results.outputs_prefix == 'TrendMicroCAS.EmailSweep'


def test_user_take_action_command(mocker):
    """Tests user_take_action_command  function
    Given
    - args
    - raw response of the database
    When
    - mock the client's http_request
    Then
    - convert the result to human readable table
    - create the context
    - validate the expected_result and the created context
    """
    mocker.patch.object(client, '_http_request', return_value=USER_TAKE_ACTION_RESULT)
    args = {
        'action_type': 'action_type',
        'account_user_email': 'account_user_email'
    }
    results: CommandResults = user_take_action_command(client, args)
    assert results.outputs == USER_TAKE_ACTION_OUTPUT
    assert results.outputs_key_field == 'batch_id'
    assert results.outputs_prefix == 'TrendMicroCAS.UserTakeAction'


def test_email_take_action_command(mocker):
    """Tests email_take_action_command  function
    Given
    - args
    - raw response of the database
    When
    - mock the client's http_request
    Then
    - convert the result to human readable table
    - create the context
    - validate the expected_result and the created context
    """
    mocker.patch.object(client, '_http_request', return_value=EMAIL_TAKE_ACTION_RESULT)
    args = {
        'action_type': 'action_type',
        'mailbox': 'mailbox',
        'mail_message_id': 'mail_message_id',
        'mail_unique_id': 'mail_unique_id',
        'mail_message_delivery_time': '2020-07-13T01:52:50.000Z'
    }
    results: CommandResults = email_take_action_command(client, args)
    assert results.outputs == EMAIL_TAKE_ACTION_OUTPUT
    assert results.outputs_key_field == 'batch_id'
    assert results.outputs_prefix == 'TrendMicroCAS.EmailTakeAction'


def test_user_action_result_command(mocker):
    """Tests user_action_result_command function
    Given
    - args
    - raw response
    When
    - mock the client's http_request
    Then
    - convert the result to human readable table
    - create the context
    - validate the expected_result and the created context
    """
    mocker.patch.object(client, '_http_request', return_value=USER_ACTION_RESULT_RESULT)
    args = {
        'batch_id': 'batch_id',
        'start': '2020-07-13T01:52:50.000Z',
        'end': '2020-07-14T01:52:50.000Z',
        'limit': '5'
    }
    results: CommandResults = user_action_result_command(client, args)
    assert results.outputs == USER_ACTION_RESULT_OUTPUT
    assert results.outputs_key_field == 'batch_id'
    assert results.outputs_prefix == 'TrendMicroCAS.UserActionResult'


def test_blocked_lists_get_command(mocker):
    """Tests blocked_lists_get_command function
    Given
    - raw response
    When
    - mock the client's http_request
    Then
    - convert the result to human readable table
    - create the context
    - validate the expected_result and the created context
    """
    mocker.patch.object(client, '_http_request', return_value=BLOCKED_LISTS_GET_RESULT)
    results: CommandResults = blocked_lists_get_command(client)
    assert results.outputs == BLOCKED_LISTS_OUTPUT
    assert results.outputs_key_field == 'BlockedList'
    assert results.outputs_prefix == 'TrendMicroCAS.BlockedList'


def test_blocked_lists_update_command(mocker):
    """Tests blocked_lists_update_command function
    Given
    - raw response
    When
    - mock the client's http_request
    Then
    - convert the result to human readable table
    - create the context
    - validate the expected_result and the created context
    """
    args = {
        'action_type': 'action_type',
        'senders': '456@gmail.com,123@gmail.com',
        'urls': '123.com,456.com,789.com',
        'filehashes': 'f3cdddb37f6a933d6a256bd98b4bc703a448c621'
    }
    mocker.patch.object(client, '_http_request', return_value=BLOCKED_LISTS_UPDATE_RESULT)
    results: CommandResults = blocked_lists_update_command(client, args)
    assert results.outputs == BLOCKED_LISTS_OUTPUT
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
    """input few date formats and checks if "parse_date_to_isoformat" returns iso ˚format string(%Y-%m-%dT%H:%M:%SZ)"""
    result = parse_date_to_isoformat(date_input, 'test')
    assert result == fan_result


DATA_TEST_PARSE_DATE_TO_ISOFORMAT_FREE_TEXT = [
    ('1 day'),
    ('3 months'),
    ('1 week and 1 day')
]
@pytest.mark.parametrize('date_input', DATA_TEST_PARSE_DATE_TO_ISOFORMAT_FREE_TEXT)
def test_parse_date_to_isoformat_on_free_text(date_input):
    """input a free text date and checks if "parse_date_to_isoformat" returns iso format string(%Y-%m-%dT%H:%M:%SZ)"""
    result = parse_date_to_isoformat(date_input, 'test')
    try:
        datetime.datetime.strptime(result, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as err:
        its_not_isoformat = True
    assert its_not_isoformat


SECURITY_EVENTS_LIST_RESULT = {
    "current_link": "",
    "last_log_item_generation_time": "2020-07-19T22:51:40.000Z",
    "next_link": "",
    "security_events": [
        {
            "event": "security_risk_scan",
            "log_item_id": "a9e2990a-8d7c-45e9-84a8-84b59087b2dd",
            "message": {
                "action": "Quarantine",
                "action_result": "success",
                "affected_user": "",
                "detected_by": "",
                "detection_time": "2020-07-19T22:51:30.000Z",
                "file_name": "20200325_100518.jpg",
                "file_upload_time": "2020-07-19T10:51:12.000Z",
                "location": "",
                "log_item_id": "a9e2990a-8d7c-45e9-84a8-84b59087b2dd",
                "risk_level": "",
                "scan_type": "Real-time scan",
                "security_risk_name": "20200325_100518.jpg",
                "triggered_policy_name": "Default OneDrive Policy ATP",
                "triggered_security_filter": "File Blocking"
            },
            "service": "OneDrive"
        }
    ],
    "traceId": "634810de-341e-4f33-b94e-09fc356ab408"
}

EMAIL_SWEEP_RESULT = {
    "current_link": "",
    "next_link": "",
    "traceId": "80674f37-480d-4f37-862f-2f842ad8e732",
    "value": [
        {
            "mail_attachments": [],
            "mail_internet_headers": [
                {
                    "HeaderName": "Return-Path",
                    "Value": ""
                }
            ],
            "mail_message_delivery_time": "2020-07-13T01:52:50.000Z",
            "mail_message_id": "",
            "mail_message_recipient": [
                ""
            ],
            "mail_message_sender": "",
            "mail_message_subject": "Test mail from Demisto",
            "mail_unique_id": "",
            "mail_urls": [],
            "mailbox": "",
            "source_domain": "",
            "source_ip": "0.0.0.0"
        }
    ]
}

USER_TAKE_ACTION_RESULT = {
    "batch_id": "02bc9a41-f5ac-47b8-8fd6-4fcc038d5578",
    "code": 0,
    "msg": "",
    "traceId": "9c06c712-3f0a-4d08-be5c-e504295dc570"
}

USER_TAKE_ACTION_OUTPUT = {
    'action_type': 'action_type',
    'account_user_email': ['account_user_email'],
    'batch_id': '02bc9a41-f5ac-47b8-8fd6-4fcc038d5578',
    'traceId': '9c06c712-3f0a-4d08-be5c-e504295dc570'
}

EMAIL_TAKE_ACTION_RESULT = {
    "batch_id": "02bc9a41-f5ac-47b8-8fd6-4fcc038d5578",
    "code": 0,
    "msg": "",
    "traceId": "9c06c712-3f0a-4d08-be5c-e504295dc570"
}

EMAIL_TAKE_ACTION_OUTPUT = {
    'action_type': 'action_type',
    'mailbox': 'mailbox',
    'batch_id': '02bc9a41-f5ac-47b8-8fd6-4fcc038d5578',
    'traceId': '9c06c712-3f0a-4d08-be5c-e504295dc570'
}

USER_ACTION_RESULT_RESULT = {
    "actions": [
        {
            "account_provider": "office365",
            "account_user_email": "avishai@demistodev.onmicrosoft.com",
            "action_executed_at": "2020-07-16T06:58:41.346Z",
            "action_id": "2cc933d7-2ca7-45b0-ac9a-c2e0cb0674b3",
            "action_requested_at": "2020-07-16T06:58:42.236Z",
            "action_type": "MAIL_DELETE",
            "batch_id": "e371b88f-1b23-4cf1-b372-1144a9af08fa",
            "error_code": -999,
            "error_message": "The action for these mails failed.",
            "mail_message_id": "\u003cDB7PR07MB5769F7ECC5AA5BAE27713D0399640@DB7PR07MB5769.eurprd07.prod.outlook.com\u003e",
            "mail_unique_id": "AAMkAGY3OTQyMzMzLWYxNjktNDE0My05NmZhLWQ5MGY1YjIyNzBkNABGAAAAAACYCKjWAnXBTrnhgWJCcLX7BwDrxRwRjq-zTrN6vWSzK4OWAAAAAAEJAADrxRwRjq-zTrN6vWSzK4OWAAOT6DZIAAA=",
            "mailbox": "avishai@demistodev.onmicrosoft.com",
            "service": "exchange",
            "status": "Failed"
        }
    ],
    "code": 0,
    "count": 1,
    "current_link": "https://api.tmcas.trendmicro.com/v1/mitigation/mails?batch_id=e371b88f-1b23-4cf1-b372-1144a9af08fa",
    "msg": "",
    "next_link": 'null',
    "traceId": "d395a759-976c-45b7-a8d8-35708bbd0fb8"
}

USER_ACTION_RESULT_OUTPUT = [
    {
        "account_provider": "office365",
        "account_user_email": "avishai@demistodev.onmicrosoft.com",
        "action_executed_at": "2020-07-16T06:58:41.346Z",
        "action_id": "2cc933d7-2ca7-45b0-ac9a-c2e0cb0674b3",
        "action_requested_at": "2020-07-16T06:58:42.236Z",
        "action_type": "MAIL_DELETE",
        "batch_id": "e371b88f-1b23-4cf1-b372-1144a9af08fa",
        "error_code": -999,
        "error_message": "The action for these mails failed.",
        "mail_message_id": "\u003cDB7PR07MB5769F7ECC5AA5BAE27713D0399640@DB7PR07MB5769.eurprd07.prod.outlook.com\u003e",
        "mail_unique_id": "AAMkAGY3OTQyMzMzLWYxNjktNDE0My05NmZhLWQ5MGY1YjIyNzBkNABGAAAAAACYCKjWAnXBTrnhgWJCcLX7BwDrxRwRjq-zTrN6vWSzK4OWAAAAAAEJAADrxRwRjq-zTrN6vWSzK4OWAAOT6DZIAAA=",
        "mailbox": "avishai@demistodev.onmicrosoft.com",
        "service": "exchange",
        "status": "Failed"
    }]

BLOCKED_LISTS_GET_RESULT = {
    "code": 0,
    "message": "Get rules successfully.",
    "rules": {
        "filehashes": [
            "f3cdddb37f6a933d6a256bd98b4bc703a448c621"
        ],
        "senders": [
            "456@gmail.com",
            "123@gmail.com"
        ],
        "urls": [
            "123.com",
            "456.com",
            "789.com"
        ]
    }
}

BLOCKED_LISTS_OUTPUT = {
    "filehashes": [
        "f3cdddb37f6a933d6a256bd98b4bc703a448c621"
    ],
    "senders": [
        "456@gmail.com",
        "123@gmail.com"
    ],
    "urls": [
        "123.com",
        "456.com",
        "789.com"
    ]
}

BLOCKED_LISTS_UPDATE_RESULT = {
    "code": 0,
    "message": "Add rules successfully."
}