from unittest.mock import Mock
import demistomock as demisto


MOCK_URL = "http://123-fake-api.com"
MOCK_API_URL = MOCK_URL + "/api"

MOCK_PARAMS = {
    "credentials": {
        "identifier": "mock_email",
        "password": "mock_pass"
    },
    "insecure": True,
    "proxy": False,
    "serverUrl": MOCK_URL,
    "client_id": "mock_cliend_id",
    "threshold": 6
}

MOCK_ACCESS_TOKEN = {
    'expires_in': 3600,
    'access_token': '3220879210'
}

MOCK_GET_ALL_OBJS_ARGUMENTS = {'limit': '2', 'page': '0'}

MOCK_EMAIL_REPUTATION_ARGUMENTS = {'email': 'foo@demisto.com'}

MOCK_SEARCH_BY_ID_ARGUMENTS = {'obj_id': 2019, 'obj_type': 'event'}

MOCK_RELATED_OBJS_ARGUMENTS = {'obj_type': 'adversary', 'obj_id': '1'}

MOCK_SEARCH_BY_NAME_ARGUMENTS = {'name': 'foo@demisto', 'limit': '10'}

MOCK_FILE_INFO = {'name': 'TestTitle', 'path': 'test_data/testfile.txt'}

MOCK_EDIT_EVENT_ARGUMENTS = {'id': 2019, 'date': '2019-03-01', 'description': '<b>test</b>', 'type': 'Spearphish'}

MOCK_UPLOAD_FILE_ARGUMENTS = {
    'entry_id': 'mock',
    'title': 'TestTitle',
    'malware_safety_lock': 'off',
    'file_category': 'Cuckoo'
}

MOCK_CREATE_INDICATOR_ARGUMENTS = {
    'type': 'Email Address',
    'status': 'Active',
    'value': 'foo@demisto.com',
    'sources': 'test_source1,test_source2',
    'attributes_names': 'test_attribute1,test_attribute2',
    'attributes_values': 'test_value1,test_value2'
}

MOCK_FILE_UPLOAD_RESPONSE = {
    'data': {
        'type_id': 1,
        'name': 'testfile.txt',
        'title': 'TestTitle',
        'malware_locked': 0,
        'content_type_id': 1
    }
}

MOCK_INDICATOR_CREATION_RESPONSE = {
    'data': [{
        'id': 2019,
        'type_id': 4,  # 'Email Address'
        'value': 'foo@demisto.com',
        'status_id': 1,  # 'Active'
        'sources': [
            {'name': 'test_source1', 'pivot': {'id': 2017}},
            {'name': 'test_source2', 'pivot': {'id': 2018}}
        ],
        'attributes': [
            {'name': 'test_attribute1', 'value': 'test_value1', 'id': 2019},
            {'name': 'test_attribute2', 'value': 'test_value2', 'id': 2020}
        ],
        'score': 6
    }]
}

MOCK_GET_INDICATOR_RESPONSE = {
    'data': {
        'id': 2019,
        'type_id': 4,  # 'Email Address'
        'value': 'foo@demisto.com',
        'score': 6,
        'status_id': 1  # 'Active'
    }
}

MOCK_SEARCH_BY_NAME_RESPONSE = {
    'data': [
        {'id': 2017, 'value': 'foo@demisto.com', 'object': 'event'},
        {'id': 2018, 'value': 'foo@demisto.com', 'object': 'adversary'},
        {'id': 2019, 'value': 'foo@demisto.com', 'object': 'indicator'}
    ]
}

MOCK_SEARCH_BY_EMAIL_RESPONSE = {
    'total': 1,
    'data': [
        {'class': 'network', 'score': 0, 'value': 'foo@demisto.com', 'touched_at': '2019-11-20 08:23:21', 'id': 2019,
         'updated_at': '2019-11-20 08:22:51', 'published_at': '2019-11-20 08:22:51', 'created_at': '2019-11-20 08:22:51',
         'status_id': 5, 'type_id': 4, 'adversaries': [], 'type': {'name': 'Email Address', 'id': 4, 'class': 'network'},
         'status': {'name': 'Whitelisted', 'id': 5, 'description': 'Poses NO risk and should never be deployed.'},
         'sources': [{'indicator_id': 20, 'indicator_status_id': 5, 'published_at': '2019-11-20 08:22:51', 'source_id': 8,
                      'id': 22, 'created_at': '2019-11-20 08:22:51', 'source_type': 'users', 'creator_source_id': 8,
                      'indicator_type_id': 4, 'reference_id': 1, 'updated_at': '2019-11-20 08:22:51',
                      'name': 'foo@demisto.com'}]}], 'limit': 500, 'offset': 0}

MOCK_GET_EVENT_RESPONSE = {
    'data': {
        'id': 2019,
        'happened_at': '2019-03-01 00:00:00',
        'description': 'test',
        'type_id': 1
    }
}

MOCK_INDICATOR_LIST_RESPONSE = {
    'data': [
        {'id': 10, 'value': 'foo@demisto.com', 'type_id': 4, 'status_id': 2},
        {'id': 11, 'value': '8.8.8.8', 'type_id': 14, 'status_id': 1},
        {'id': 12, 'value': '1.2.3.4', 'type_id': 14, 'status_id': 2}
    ]
}

MOCK_ERROR_RESPONSES = [
    {
        "data": {
            "errors": {
                "name": ["The name has already been taken."],
                "test": ["test_error1", "test_error2"]
            }
        }
    },
    {
        "errors": [
            'First Error',
            ['Second error - part 1', 'Second error - part 2']
        ]
    }
]

EXPECTED_ERROR_STRINGS = [
    "Errors from service:\n\n"
    "Error #1. In 'name':\nThe name has already been taken.\n\n"
    "Error #2. In 'test':\ntest_error1\ntest_error2\n\n",

    "Errors from service:\n\n"
    "Error #1: First Error\n"
    "Error #2.0: Second error - part 1\n"
    "Error #2.1: Second error - part 2\n"
]

MOCK_GET_INDICATOR_STATUS_RESPONSE_1 = {
    "data": {
        "id": 1,
        "name": "Active",
        "description": "Poses a threat and is being exported to detection tools.",
        "user_editable": "N",
        "visible": "Y",
        "include_in_export": "Y",
        "protected": "Y",
        "created_at": "2017-04-17 04:35:21",
        "updated_at": "2017-04-17 04:35:21"
    }
}

MOCK_GET_INDICATOR_STATUS_RESPONSE_2 = {
    "data": {
        "id": 2,
        "name": "Expired",
        "description": "No longer poses a serious threat.",
        "user_editable": "N",
        "visible": "Y",
        "include_in_export": "Y",
        "protected": "Y",
        "created_at": "2017-04-17 04:35:21",
        "updated_at": "2017-04-17 04:35:21"
    }
}

MOCK_GET_INDICATOR_TYPE_RESPONSE_1 = {
    "data": {
        "id": 4,
        "name": "Email Address",
        "class": "network",
        "score": None,
        "wildcard_matching": "Y",
        "created_at": "2017-04-17 04:34:56",
        "updated_at": "2017-04-17 04:34:56"
    }
}

MOCK_GET_INDICATOR_TYPE_RESPONSE_2 = {
    "data": {
        "id": 14,
        "name": "IP Address",
        "class": "network",
        "score": None,
        "wildcard_matching": "Y",
        "created_at": "2017-04-17 04:34:56",
        "updated_at": "2017-04-17 04:34:56"
    }
}

MOCK_GET_EVENT_TYPE_RESPONSE = {
    "data": {
        "id": 1,
        "name": "Spearphish",
        "user_editable": "N",
        "created_at": "2017-03-20 13:28:23",
        "updated_at": "2017-03-20 13:28:23"
    }
}

MOCK_GET_FILE_TYPE_RESPONSE = {
    "data": {
        "id": 1,
        "name": "Cuckoo",
        "is_parsable": "Y",
        "parser_class": "Cuckoo",
        "created_at": "2017-03-16 13:03:46",
        "updated_at": "2017-03-16 13:03:46"
    }
}


def mock_demisto(mocker, mock_args):
    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, 'args', return_value=mock_args)
    mocker.patch.object(demisto, 'results')


def test_create_indicator_command(mocker, requests_mock):
    mock_demisto(mocker, MOCK_CREATE_INDICATOR_ARGUMENTS)
    requests_mock.post(MOCK_API_URL + '/indicators', json=MOCK_INDICATOR_CREATION_RESPONSE)
    requests_mock.post(MOCK_API_URL + '/token', json=MOCK_ACCESS_TOKEN)
    requests_mock.get(MOCK_API_URL + '/indicator/statuses/1', json=MOCK_GET_INDICATOR_STATUS_RESPONSE_1)
    requests_mock.get(MOCK_API_URL + '/indicator/types/4', json=MOCK_GET_INDICATOR_TYPE_RESPONSE_1)
    from ThreatQ_v2 import create_indicator_command
    create_indicator_command()

    results = demisto.results.call_args[0]
    entry_context = results[0]['EntryContext'][
        'ThreatQ.Indicator((val.ID && val.ID === obj.ID) || (val.Value && val.Value === obj.Value))']

    assert 'Indicator was successfully created.' in results[0]['HumanReadable']
    assert entry_context['Value'] == 'foo@demisto.com'
    assert entry_context['Type'] == 'Email Address'
    assert entry_context['Status'] == 'Active'
    assert entry_context['Source'][0]['ID'] == 2017
    assert entry_context['Source'][1]['Name'] == 'test_source2'
    assert entry_context['Attribute'][0]['Name'] == 'test_attribute1'
    assert entry_context['Attribute'][1]['Value'] == 'test_value2'


def test_edit_event_command(mocker, requests_mock):
    mock_demisto(mocker, MOCK_EDIT_EVENT_ARGUMENTS)
    requests_mock.put(MOCK_API_URL + '/events/2019', json=MOCK_GET_EVENT_RESPONSE)
    requests_mock.post(MOCK_API_URL + '/token', json=MOCK_ACCESS_TOKEN)
    requests_mock.get(MOCK_API_URL + '/event/types/1', json=MOCK_GET_EVENT_TYPE_RESPONSE)

    from ThreatQ_v2 import edit_event_command
    edit_event_command()

    results = demisto.results.call_args[0]
    entry_context = results[0]['EntryContext']['ThreatQ.Event(val.ID === obj.ID)']

    assert 'Successfully edited event with ID 2019' in results[0]['HumanReadable']
    assert entry_context['Occurred'] == '2019-03-01 00:00:00'  # date format should be changed
    assert entry_context['Description'] == 'test'  # html markups should be cleaned
    assert entry_context['Type'] == 'Spearphish'


def test_upload_file_command(mocker, requests_mock):
    mock_demisto(mocker, MOCK_UPLOAD_FILE_ARGUMENTS)
    mocker.patch.object(demisto, 'getFilePath', return_value=MOCK_FILE_INFO)
    requests_mock.post(MOCK_API_URL + '/token', json=MOCK_ACCESS_TOKEN)
    requests_mock.post(MOCK_API_URL + '/attachments', json=MOCK_FILE_UPLOAD_RESPONSE)
    requests_mock.get(MOCK_API_URL + '/attachments/types/1', json=MOCK_GET_FILE_TYPE_RESPONSE)

    from ThreatQ_v2 import upload_file_command
    upload_file_command()

    results = demisto.results.call_args[0]
    entry_context = results[0]['EntryContext']['ThreatQ.File(val.ID === obj.ID)']

    assert 'Successfully uploaded file TestTitle.' in results[0]['HumanReadable']
    assert entry_context['MalwareLocked'] == 'off'
    assert entry_context['Type'] == 'Cuckoo'
    assert entry_context['ContentType'] == 'text/plain'
    assert entry_context['Title'] == 'TestTitle'
    assert entry_context['Name'] == 'testfile.txt'


def test_get_email_reputation(mocker, requests_mock):
    mock_demisto(mocker, MOCK_EMAIL_REPUTATION_ARGUMENTS)
    requests_mock.post(MOCK_API_URL + '/token', json=MOCK_ACCESS_TOKEN)
    requests_mock.post(MOCK_API_URL + '/indicators/query?limit=500&offset=0&sort=id', json=MOCK_SEARCH_BY_EMAIL_RESPONSE)
    requests_mock.get(MOCK_API_URL + '/indicators/2019?with=attributes,sources,score,type',
                      json=MOCK_GET_INDICATOR_RESPONSE)
    requests_mock.get(MOCK_API_URL + '/indicator/statuses/1', json=MOCK_GET_INDICATOR_STATUS_RESPONSE_1)
    requests_mock.get(MOCK_API_URL + '/indicator/types/4', json=MOCK_GET_INDICATOR_TYPE_RESPONSE_1)

    from ThreatQ_v2 import get_email_reputation
    get_email_reputation()

    results = demisto.results.call_args[0]
    entry_context = results[0]['EntryContext'][
        'ThreatQ.Indicator((val.ID && val.ID === obj.ID) || (val.Value && val.Value === obj.Value))']
    generic_context = results[0]['EntryContext']['Account.Email(val.Address && val.Address == obj.Address)']

    assert 'Search results for email foo@demisto.com' in results[0]['HumanReadable']
    assert entry_context[0]['Value'] == 'foo@demisto.com'
    assert generic_context[0]['Address'] == 'foo@demisto.com'
    assert generic_context[0]['Malicious']['Vendor'] == 'ThreatQ v2'  # indicator should be marked a malicious
    assert results[0]['EntryContext']['DBotScore'][0]['Score'] == 3


def test_get_related_objs_command(mocker, requests_mock):
    mock_demisto(mocker, MOCK_RELATED_OBJS_ARGUMENTS)
    requests_mock.post(MOCK_API_URL + '/token', json=MOCK_ACCESS_TOKEN)
    requests_mock.get(MOCK_API_URL + '/adversaries/1/indicators?with=sources,score', json=MOCK_INDICATOR_LIST_RESPONSE)
    requests_mock.get(MOCK_API_URL + '/indicator/statuses/2', json=MOCK_GET_INDICATOR_STATUS_RESPONSE_2)
    requests_mock.get(MOCK_API_URL + '/indicator/statuses/1', json=MOCK_GET_INDICATOR_STATUS_RESPONSE_1)
    requests_mock.get(MOCK_API_URL + '/indicator/types/4', json=MOCK_GET_INDICATOR_TYPE_RESPONSE_1)
    requests_mock.get(MOCK_API_URL + '/indicator/types/14', json=MOCK_GET_INDICATOR_TYPE_RESPONSE_2)

    from ThreatQ_v2 import get_related_objs_command
    get_related_objs_command('indicator')

    results = demisto.results.call_args[0]
    entry_context = results[0]['EntryContext']['ThreatQ.Adversary(val.ID === obj.ID)']

    assert 'Related indicator type objects of adversary with ID 1' in results[0]['HumanReadable']

    assert len(entry_context['RelatedIndicator']) == 3
    assert entry_context['RelatedIndicator'][0]['Type'] == 'Email Address'
    assert entry_context['RelatedIndicator'][1]['Type'] == 'IP Address'
    assert entry_context['RelatedIndicator'][2]['Status'] == 'Expired'


def test_get_all_objs_command(mocker, requests_mock):
    mock_demisto(mocker, MOCK_GET_ALL_OBJS_ARGUMENTS)
    requests_mock.post(MOCK_API_URL + '/token', json=MOCK_ACCESS_TOKEN)
    requests_mock.get(MOCK_API_URL + '/indicators?with=attributes,sources,score', json=MOCK_INDICATOR_LIST_RESPONSE)
    requests_mock.get(MOCK_API_URL + '/indicator/statuses/2', json=MOCK_GET_INDICATOR_STATUS_RESPONSE_2)
    requests_mock.get(MOCK_API_URL + '/indicator/statuses/1', json=MOCK_GET_INDICATOR_STATUS_RESPONSE_1)
    requests_mock.get(MOCK_API_URL + '/indicator/types/4', json=MOCK_GET_INDICATOR_TYPE_RESPONSE_1)
    requests_mock.get(MOCK_API_URL + '/indicator/types/14', json=MOCK_GET_INDICATOR_TYPE_RESPONSE_2)

    from ThreatQ_v2 import get_all_objs_command
    get_all_objs_command('indicator')

    results = demisto.results.call_args[0]
    entry_context = results[0]['EntryContext'][
        'ThreatQ.Indicator((val.ID && val.ID === obj.ID) || (val.Value && val.Value === obj.Value))']
    assert 'List of all objects of type indicator - 0-1' in results[0]['HumanReadable']
    assert len(entry_context) == 2
    assert entry_context[0]['Type'] == 'Email Address'
    assert entry_context[0]['Status'] == 'Expired'
    assert entry_context[1]['Type'] == 'IP Address'
    assert entry_context[1]['Status'] == 'Active'


def test_search_by_name_command(mocker, requests_mock):
    mock_demisto(mocker, MOCK_SEARCH_BY_NAME_ARGUMENTS)
    requests_mock.post(MOCK_API_URL + '/token', json=MOCK_ACCESS_TOKEN)
    requests_mock.get(MOCK_API_URL + '/search?query=foo@demisto&limit=10', json=MOCK_SEARCH_BY_NAME_RESPONSE)

    from ThreatQ_v2 import search_by_name_command
    search_by_name_command()

    results = demisto.results.call_args[0]

    assert 'Search Results - Indicators' in results[0]['HumanReadable']
    assert 'Search Results - Adversaries' in results[0]['HumanReadable']
    assert 'Search Results - Events' in results[0]['HumanReadable']
    assert 'Search Results - Files' not in results[0]['HumanReadable']
    assert len(results[0]['EntryContext']) == 3


def test_search_by_id_command(mocker, requests_mock):
    mock_demisto(mocker, MOCK_SEARCH_BY_ID_ARGUMENTS)
    requests_mock.post(MOCK_API_URL + '/token', json=MOCK_ACCESS_TOKEN)
    requests_mock.get(MOCK_API_URL + '/events/2019?with=attributes,sources', json=MOCK_GET_EVENT_RESPONSE)
    requests_mock.get(MOCK_API_URL + '/event/types/1', json=MOCK_GET_EVENT_TYPE_RESPONSE)

    from ThreatQ_v2 import search_by_id_command
    search_by_id_command()

    results = demisto.results.call_args[0]
    entry_context = results[0]['EntryContext']['ThreatQ.Event(val.ID === obj.ID)']

    assert 'Search results for event with ID 2019' in results[0]['HumanReadable']
    assert entry_context['Description'] == 'test'
    assert entry_context['Occurred'] == '2019-03-01 00:00:00'
    assert entry_context['Type'] == 'Spearphish'


def test_get_errors_string_from_bad_request():
    from ThreatQ_v2 import get_errors_string_from_bad_request
    from requests.models import Response
    res = Mock(spec=Response)

    for error_response, expected_result in zip(MOCK_ERROR_RESPONSES, EXPECTED_ERROR_STRINGS):
        res.json.return_value = error_response
        actual_result = get_errors_string_from_bad_request(res, 400)
        assert expected_result in actual_result


def test_second_attempt_for_reputation_requests(mocker):
    """
        Given:
            - An old format ThreatQ request body.
        When:
            - run tq_request to send a request
        Then:
            - Verify that a request with the new format body was sent and returned a response as expected.
    """
    mock_demisto(mocker, MOCK_EMAIL_REPUTATION_ARGUMENTS)

    import requests
    from ThreatQ_v2 import tq_request

    class MockResponse:
        def __init__(self, status_code, data={}) -> None:
            self.status_code = status_code
            self.data = data

        def json(self):
            return self.data

    def get_response(
        method, url, data=None, headers=None, verify=False, files=None, allow_redirects=True
    ):
        if url.endswith('/token'):
            return MockResponse(status_code=200, data=MOCK_ACCESS_TOKEN)
        return MockResponse(status_code=200, data=MOCK_SEARCH_BY_EMAIL_RESPONSE)

    mocker.patch.object(requests, "request", side_effect=get_response)

    results = tq_request('post', '', params={"criteria": {"value": "foo@demisto.com"}},
                         retrieve_entire_response=True)
    assert results.status_code == 200
    assert results.json()['data'][0]['value'] == 'foo@demisto.com'
