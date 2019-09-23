import demistomock as demisto

MOCK_URL = "http://123-fake-api.com"

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
        'status_id': '1',  # 'Active'
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
        'score': 6
    }
}

MOCK_SEARCH_BY_NAME_RESPONSE = {
    'data': [
        {'id': 2017, 'value': 'foo@demisto.com', 'object': 'event'},
        {'id': 2018, 'value': 'foo@demisto.com', 'object': 'adversary'},
        {'id': 2019, 'value': 'foo@demisto.com', 'object': 'indicator'}
    ]
}

MOCK_GET_EVENT_RESPONSE = {
        'data': {
            'id': 2019,
            'Occurred': '2019-03-01 00:00:00',
            'Description': 'test'
        }
    }

MOCK_INDICATOR_LIST_RESPONSE = {
    'data': [
        {'id': 10, 'value': 'foo@demisto.com', 'type_id': 4, 'status_id': 2},
        {'id': 11, 'value': '8.8.8.8', 'type_id': 14, 'status_id': 3}
    ]
}

MOCK_ERROR = b'{"data": {"errors": [{"name": "The name has already been taken."}, {"test": "test_error"}]}}'


def test_create_indicator_command(mocker, requests_mock):
    from ThreatQ_v2 import create_indicator_command
    args = {
        'type': 'Email Address',
        'status': 'Active',
        'value': 'foo@demisto.com',
        'sources': 'test_source1,test_source2',
        'attributes_names': 'test_attribute1,test_attribute2',
        'attributes_values': 'test_value1,test_value2'
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'results')
    requests_mock.get(MOCK_URL + '/indicators', json=MOCK_INDICATOR_CREATION_RESPONSE)

    create_indicator_command()

    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]

    assert len(results) == 1
    assert 'Indicator was successfully created.' in results[0]['HumanReadable']
    entry_context = results[0]['EntryContext']['ThreatQ.Indicator(val.ID === obj.ID)']
    assert entry_context['Value'] == 'foo@demisto.com'
    assert entry_context['Type'] == 'Email Address'
    assert entry_context['Status'] == 'Active'
    assert entry_context['Source'][0]['ID'] == 2017
    assert entry_context['Source'][1]['Name'] == 'test_source2'
    assert entry_context['Attribute'][0]['Name'] == 'test_attribute1'
    assert entry_context['Attribute'][1]['Value'] == 'test_value2'


def test_edit_event_command(mocker, requests_mock):
    from ThreatQ_v2 import edit_event_command

    args = {
        'id': 2019,
        'date': '2019-03-01',
        'description': '<b>test</b>'
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'results')

    requests_mock.put(MOCK_URL + '/events/2019', json=MOCK_FILE_UPLOAD_RESPONSE)

    edit_event_command()

    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]

    assert len(results) == 1
    assert 'Successfully edited event with ID 2019' in results[0]['HumanReadable']
    entry_context = results[0]['EntryContext']['ThreatQ.Event(val.ID === obj.ID)']
    assert entry_context['Description'] == 'test'  # should clean the html markups
    assert entry_context['Occurred'] == '2019-03-01 00:00:00'  # should change the date format


def test_upload_file_command(mocker, requests_mock):
    from ThreatQ_v2 import upload_file_command

    args = {'entry_id': 'mock', 'title': 'TestTitle', 'malware_safety_lock': 'off', 'file_category': 'Cuckoo'}
    mocker.patch.object(demisto, 'args', return_value=args)
    file_info = {'name': 'TestTitle', 'path': 'test_data/testfile.txt'}
    mocker.patch.object(demisto, 'getFilePath', return_value=file_info)
    mocker.patch.object(demisto, 'results')

    requests_mock.post(MOCK_URL + '/attachments', json=MOCK_FILE_UPLOAD_RESPONSE)

    upload_file_command()

    assert demisto.args()['entry_id'] == 'mock'
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]

    assert len(results) == 1
    assert 'Successfully uploaded file TestTitle.' in results[0]['HumanReadable']
    entry_context = results[0]['EntryContext']['ThreatQ.Indicator(val.ID === obj.ID)']
    assert entry_context['MalwareLocked'] == 'off'
    assert entry_context['Type'] == 'Cuckoo'
    assert entry_context['ContentType'] == 'text/plain'
    assert entry_context['Title'] == 'TestTitle'
    assert entry_context['Name'] == 'testfile.txt'


def test_get_email_reputation(mocker, requests_mock):
    from ThreatQ_v2 import get_email_reputation
    args = {'email': 'foo@demisto.com'}
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'results')

    requests_mock.get(MOCK_URL + '/search?query=foo@demisto.com&limit=1', json=MOCK_SEARCH_BY_NAME_RESPONSE)
    requests_mock.get(MOCK_URL + '/indicators/2019?with=attributes,sources,score,type', json=MOCK_GET_INDICATOR_RESPONSE)

    get_email_reputation()

    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]

    assert len(results) == 1
    assert 'Search results for email foo@demisto.com' in results[0]['HumanReadable']
    entry_context = results[0]['EntryContext']['ThreatQ.Indicator(val.ID === obj.ID)']
    assert entry_context['Value'] == 'foo@demisto.com'

    # Because threshold is 6 and TQ score is 6, indicator is marked as malicious
    generic_context = results[0]['EntryContext']['Account.Email(val.Address && val.Address == obj.Address)']
    assert generic_context['Address'] == 'foo@demisto.com'
    assert generic_context['Malicious']['Vendor'] == 'ThreatQ v2'
    assert results[0]['EntryContext']['DBotScore']['Score'] == 3


def test_get_related_objs_command(mocker, requests_mock):
    from ThreatQ_v2 import get_related_objs_command
    args = {'obj_type': 'adversary', 'obj_id': '1'}
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'results')

    requests_mock.get(MOCK_URL + '/adversaries/1/indicators?with=sources,score', json=MOCK_INDICATOR_LIST_RESPONSE)

    get_related_objs_command('indicator')

    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]

    assert len(results) == 1
    assert 'Related indicator type objects of adversary with ID 1' in results[0]['HumanReadable']
    entry_context = results[0]['EntryContext']['ThreatQ.Adversary(val.ID === obj.ID)']
    assert len(entry_context['RelatedIndicator']) == 2
    assert entry_context['RelatedIndicator'][0]['Type'] == 'Email Address'
    assert entry_context['RelatedIndicator'][1]['Type'] == 'IP Address'


def test_get_all_objs_command(mocker, requests_mock):
    from ThreatQ_v2 import get_all_objs_command
    args = {'limit': '2', 'page': '10'}
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'results')

    requests_mock.get(MOCK_URL + '/indicators?with=attributes,sources,score', json=MOCK_INDICATOR_LIST_RESPONSE)

    get_all_objs_command('indicator')

    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]

    assert len(results) == 1
    assert 'List of all objects of type indicator - 10-11' in results[0]['HumanReadable']
    entry_context = results[0]['EntryContext']['ThreatQ.Indicator(val.ID === obj.ID)']
    assert len(entry_context) == 2
    assert entry_context[0]['Type'] == 'Email Address'
    assert entry_context[1]['Type'] == 'IP Address'


def test_search_by_name_command(mocker, requests_mock):
    from ThreatQ_v2 import search_by_name_command
    args = {
        'name': 'foo@demisto'
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'results')

    requests_mock.get(MOCK_URL + '/search?query=foo@demisto&limit=10', json=MOCK_SEARCH_BY_NAME_RESPONSE)

    search_by_name_command()

    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]

    assert len(results) == 1
    assert 'Search Results - Indicators' in results[0]['HumanReadable']
    assert 'Search Results - Adversaries' in results[0]['HumanReadable']
    assert 'Search Results - Events' in results[0]['HumanReadable']
    assert 'Search Results - Files' not in results[0]['HumanReadable']
    assert len(results[0]['EntryContext']) == 3


def test_search_by_id_command(mocker, requests_mock):
    from ThreatQ_v2 import search_by_id_command
    args = {
        'obj_id': 2019,
        'obj_type': 'event'
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'results')

    requests_mock.get(MOCK_URL + '/events/2019?with=attributes,sources', json=MOCK_GET_EVENT_RESPONSE)

    search_by_id_command()

    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]

    assert len(results) == 1
    assert 'Search results for event with ID 2019' in results[0]['HumanReadable']
    entry_context = results[0]['EntryContext']['ThreatQ.Event(val.ID === obj.ID)']
    assert entry_context['Description'] == 'test'
    assert entry_context['Occurred'] == '2019-03-01 00:00:00'


def test_get_errors_string_from_bad_request():
    from ThreatQ_v2 import get_errors_string_from_bad_request
    from requests.models import Response

    res = Response()
    res._content = MOCK_ERROR

    expected_result = '''Received an error - status code [400].\n
    Errors from service:\n\n
    Error #1. In 'name':\n
    The name has already been taken.\n\n
    Error #2. In 'test':
    test_error'''

    assert expected_result in get_errors_string_from_bad_request(res, 400)

