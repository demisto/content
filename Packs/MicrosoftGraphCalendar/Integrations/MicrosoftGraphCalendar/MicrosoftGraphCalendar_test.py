import pytest

from MicrosoftGraphCalendar import *


def test_snakecase_to_camelcase():
    assert snakecase_to_camelcase('snake_case_snake_case') == 'SnakeCaseSnakeCase'


def test_camel_case_to_readable():
    assert camel_case_to_readable('id') == 'ID'
    assert camel_case_to_readable('createdDateTime') == 'Created Date Time'


def test_parse_calendar():
    parsed_readable, parsed_outputs = parse_calendar(MOCK_CALENDAR_JSON)

    expected_readable = [{'Name': None, 'Owner Name': None, 'Owner Address': None, 'ID': 'some_id'}]
    expected_outputs = [
        {
            '@Odata.Etag': '',
            'Attendees': [
                {
                    'emailAddress': {'address': 'someemail@test.com', 'name': 'someemail@test.com'},
                    'status': {'response': 'none', 'time': '0001-01-01T00:00:00Z'},
                    'type': 'required'
                }
            ],
            'Body': {'content': '<html>', 'contentType': 'html'},
            'BodyPreview': '',
            'Categories': [],
            'ChangeKey': '',
            'CreatedDateTime': '2019-11-25T14:20:50.7017675Z',
            'End': {'dateTime': '2019-11-25T15:30:00.0000000', 'timeZone': 'UTC'},
            'HasAttachments': False,
            'ICalUId': '',
            'ID': 'some_id',
            'Importance': 'normal',
            'IsAllDay': False,
            'IsCancelled': False,
            'IsOrganizer': True,
            'IsReminderOn': True,
            'LastModifiedDateTime': '2019-11-25T19:17:12.9656678Z',
            'Location': {'address': {}, 'coordinates': {}, 'displayName': '', 'locationType': 'default',
                         'uniqueIdType': 'unknown'},
            'Locations': [],
            'OnlineMeetingUrl': None,
            'Organizer': {'emailAddress': {'address': 'someemail@test.com', 'name': 'Some Name'}},
            'OriginalEndTimeZone': 'Israel Standard Time',
            'OriginalStartTimeZone': 'Israel Standard Time',
            'Recurrence': None,
            'ReminderMinutesBeforeStart': 15,
            'ResponseRequested': True,
            'ResponseStatus': {'response': 'organizer', 'time': '0001-01-01T00:00:00Z'},
            'Sensitivity': 'normal',
            'SeriesMasterId': None,
            'ShowAs': 'busy',
            'Start': {'dateTime': '2019-11-25T15:00:00.0000000', 'timeZone': 'UTC'},
            'Subject': 'Some Subject ', 'Type': 'singleInstance', 'WebLink': ''
        }
    ]
    assert parsed_readable == expected_readable
    assert parsed_outputs == expected_outputs


def test_parse_event():
    parsed_readable, parsed_outputs = parse_events(MOCK_EVENT_JSON)

    expected_readable = [
        {'Subject': 'Some Subject ', 'ID': 'some_id', 'Organizer': 'Some Name', 'Attendees': ['somemail@test.com'],
         'Start': '2019-11-25T15:00:00.0000000', 'End': '2019-11-25T15:30:00.0000000'}]
    expected_outputs = [{'Attendees': [{'emailAddress': {'address': 'somemail@test.com', 'name': 'somemail@test.com'},
                                        'status': {'response': 'none', 'time': '0001-01-01T00:00:00Z'},
                                        'type': 'required'}], 'Body': {'content': '<html>', 'contentType': 'html'},
                         'BodyPreview': '', 'Categories': [], 'ChangeKey': '',
                         'CreatedDateTime': '2019-11-25T14:20:50.7017675Z',
                         'End': {'dateTime': '2019-11-25T15:30:00.0000000', 'timeZone': 'UTC'}, 'HasAttachments': False,
                         'ICalUId': '', 'ID': 'some_id', 'Importance': 'normal', 'IsAllDay': False,
                         'IsCancelled': False,
                         'IsOrganizer': True, 'IsReminderOn': True,
                         'LastModifiedDateTime': '2019-11-25T19:17:12.9656678Z',
                         'Location': {'address': {}, 'coordinates': {}, 'displayName': '', 'locationType': 'default',
                                      'uniqueIdType': 'unknown'}, 'Locations': [], 'OnlineMeetingUrl': None,
                         'Organizer': {'emailAddress': {'address': 'somemail@test.com', 'name': 'Some Name'}},
                         'OriginalEndTimeZone': 'Israel Standard Time', 'OriginalStartTimeZone': 'Israel Standard Time',
                         'Recurrence': None, 'ReminderMinutesBeforeStart': 15, 'ResponseRequested': True,
                         'ResponseStatus': {'response': 'organizer', 'time': '0001-01-01T00:00:00Z'},
                         'Sensitivity': 'normal', 'SeriesMasterId': None, 'ShowAs': 'busy',
                         'Start': {'dateTime': '2019-11-25T15:00:00.0000000', 'timeZone': 'UTC'},
                         'Subject': 'Some Subject ', 'Type': 'singleInstance', 'WebLink': ''}]
    assert parsed_readable == expected_readable
    assert parsed_outputs == expected_outputs


@pytest.mark.parametrize(argnames='client_id', argvalues=['test_client_id', None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
        Given:
            - Managed Identities client id for authentication.
        When:
            - Calling test_module.
        Then:
            - Ensure the output are as expected.
    """

    from MicrosoftGraphCalendar import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
    import demistomock as demisto
    import re

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    requests_mock.get(re.compile(f'^{Resources.graph}.*'), json={})

    params = {
        'managed_identities_client_id': {'password': client_id},
        'use_managed_identities': 'True',
        'url': Resources.graph
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results', return_value=params)
    mocker.patch('MicrosoftApiModule.get_integration_context', return_value={})

    main()

    assert 'ok' in demisto.results.call_args[0][0]['Contents']
    qs = get_mock.last_request.qs
    assert qs['resource'] == [Resources.graph]
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs


MOCK_CALENDAR_JSON = [{
    "@odata.context": "",
    "@odata.etag": "",
    "attendees": [
        {
            "emailAddress": {
                "address": "someemail@test.com",
                "name": "someemail@test.com"
            },
            "status": {
                "response": "none",
                "time": "0001-01-01T00:00:00Z"
            },
            "type": "required"
        }
    ],
    "body": {
        "content": "<html>",
        "contentType": "html"
    },
    "bodyPreview": "",
    "categories": [],
    "changeKey": "",
    "createdDateTime": "2019-11-25T14:20:50.7017675Z",
    "end": {
        "dateTime": "2019-11-25T15:30:00.0000000",
        "timeZone": "UTC"
    },
    "hasAttachments": False,
    "iCalUId": "",
    "id": "some_id",
    "importance": "normal",
    "isAllDay": False,
    "isCancelled": False,
    "isOrganizer": True,
    "isReminderOn": True,
    "lastModifiedDateTime": "2019-11-25T19:17:12.9656678Z",
    "location": {
        "address": {},
        "coordinates": {},
        "displayName": "",
        "locationType": "default",
        "uniqueIdType": "unknown"
    },
    "locations": [],
    "onlineMeetingUrl": None,
    "organizer": {
        "emailAddress": {
            "address": "someemail@test.com",
            "name": "Some Name"
        }
    },
    "originalEndTimeZone": "Israel Standard Time",
    "originalStartTimeZone": "Israel Standard Time",
    "recurrence": None,
    "reminderMinutesBeforeStart": 15,
    "responseRequested": True,
    "responseStatus": {
        "response": "organizer",
        "time": "0001-01-01T00:00:00Z"
    },
    "sensitivity": "normal",
    "seriesMasterId": None,
    "showAs": "busy",
    "start": {
        "dateTime": "2019-11-25T15:00:00.0000000",
        "timeZone": "UTC"
    },
    "subject": "Some Subject ",
    "type": "singleInstance",
    "webLink": ""
}]

MOCK_EVENT_JSON = {
    "@odata.etag": "",
    "attendees": [
        {
            "emailAddress": {
                "address": "somemail@test.com",
                "name": "somemail@test.com"
            },
            "status": {
                "response": "none",
                "time": "0001-01-01T00:00:00Z"
            },
            "type": "required"
        }
    ],
    "body": {
        "content": "<html>",
        "contentType": "html"
    },
    "bodyPreview": "",
    "categories": [],
    "changeKey": "",
    "createdDateTime": "2019-11-25T14:20:50.7017675Z",
    "end": {
        "dateTime": "2019-11-25T15:30:00.0000000",
        "timeZone": "UTC"
    },
    "hasAttachments": False,
    "iCalUId": "",
    "id": "some_id",
    "importance": "normal",
    "isAllDay": False,
    "isCancelled": False,
    "isOrganizer": True,
    "isReminderOn": True,
    "lastModifiedDateTime": "2019-11-25T19:17:12.9656678Z",
    "location": {
        "address": {},
        "coordinates": {},
        "displayName": "",
        "locationType": "default",
        "uniqueIdType": "unknown"
    },
    "locations": [],
    "onlineMeetingUrl": None,
    "organizer": {
        "emailAddress": {
            "address": "somemail@test.com",
            "name": "Some Name"
        }
    },
    "originalEndTimeZone": "Israel Standard Time",
    "originalStartTimeZone": "Israel Standard Time",
    "recurrence": None,
    "reminderMinutesBeforeStart": 15,
    "responseRequested": True,
    "responseStatus": {
        "response": "organizer",
        "time": "0001-01-01T00:00:00Z"
    },
    "sensitivity": "normal",
    "seriesMasterId": None,
    "showAs": "busy",
    "start": {
        "dateTime": "2019-11-25T15:00:00.0000000",
        "timeZone": "UTC"
    },
    "subject": "Some Subject ",
    "type": "singleInstance",
    "webLink": ""
}
