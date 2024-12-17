import json
from collections import namedtuple
from CommonServerPython import DemistoException
import CreateIncidents
import demistomock as demisto
import pytest

Attachment = namedtuple('Attachment', ['name', 'content'])


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def util_loaf_file(path):
    with open(path, mode='rb') as f:
        return f.read()


incident_list = util_load_json('test_data/incidents_examples.json')
incident = util_loaf_file('test_data/incidents.json')
context_list = util_load_json('test_data/context_examples.json')
attachment_content = util_loaf_file('test_data/YOU HAVE WON 10000$.eml')
CLIENT_MOCK = CreateIncidents.Client('example_url.com', False, False)

CONTEXT_EXAMPLES = [
    (
        context_list.get("CONTEXT_WITH_LABEL_WITH_FILE"), [
            {'name': 'Potential phishing I received', 'occurred': '0001-01-01T00:00:00Z',
             'labels': [{'type': 'Email/subject', 'value': 'Potential phishing I received'},
                        {'type': 'Email', 'value': 'example@example.com'}],
             'attachment': [{'path': 'example_id', 'name': 'example_path.eml'}]}]
    ),
    (
        context_list.get("CONTEXT_WITHOUT_LABEL_WITH_FILES"), [
            {'name': 'Potential phishing I received', 'occurred': '0001-01-01T00:00:00Z',
             'attachment': [{'path': 'example_id', 'name': 'example_path.eml'},
                            {'path': 'example_id', 'name': 'example_path2.eml'}]}]
    ),
    (
        context_list.get("CONTEXT_MULTIPLE"), [
            {'name': 'Potential phishing I received', 'occurred': '0001-01-01T00:00:00Z',
             'attachment': [{'path': 'example_id', 'name': 'example_path.eml'}]},
            {'name': 'Potential phishing I received', 'occurred': '0001-01-01T00:00:00Z'}]
    ),
    (
        context_list.get("CONTEXT_EMPTY_WITHOUT_INCIDENTS"), []
    ),
    (
        context_list.get("CONTEXT_EMPTY_WITH_INCIDENTS"), []
    ),

]


@pytest.mark.parametrize('context, expected', CONTEXT_EXAMPLES)
def test_fetch_incident_command(mocker, context, expected):
    """
    Given:  a list of valid incident with labels and attachment,
            a list of valid incidents without labels but with attachment,
            a list of 2 valid incidents without labels, one with attachment,
            a list without incidents
    When:   running fetch-incident flow using the instance context
    Then:   validates the integration remain empty after reading the incidents
            validates the incident list was read properly and files where attached if needed to.

    """

    def http_mock(file_path, response_type):
        if file_path == 'example_path.eml':
            res = attachment_content
            return res
        else:
            return ''

    set_context_mock = mocker.patch.object(CreateIncidents, 'set_integration_context')
    mocker.patch.object(CreateIncidents, 'get_integration_context', return_value=context)
    mocker.patch.object(CreateIncidents.Client, 'http_request', side_effect=http_mock)
    mocker.patch.object(CreateIncidents, 'fileResult', return_value={'FileID': 'example_id'})

    incidents = CreateIncidents.fetch_incidents_command(CLIENT_MOCK)
    assert set_context_mock.call_args[0][0] == {"incidents": []}
    assert incidents == expected


PARSED_INCIDENT = [(context_list.get("CONTEXT_WITH_ATTACHMENT_AS_ENTRY_ID"), [
    {'name': 'Potential phishing I received', 'occurred': '0001-01-01T00:00:00Z',
     'attachment': [{'path': 'example_id', 'name': 'name'}]}])
]


@pytest.mark.parametrize('context, expected', PARSED_INCIDENT)
def test_fetch_incident_command_with_file(mocker, context, expected):
    """
    Given:  a list of valid incident with one attachment
    When:   running fetch-incident flow using the instance context
    Then:   validates the file result method is being executed to create a file in XSOAR

    """

    mocker.patch.object(CreateIncidents, 'set_integration_context')
    mocker.patch.object(CreateIncidents, 'get_integration_context', return_value=context)
    file_result_mock = mocker.patch.object(CreateIncidents, 'fileResult', return_value={'FileID': 'example_id'})

    CreateIncidents.fetch_incidents_command(CLIENT_MOCK)
    assert file_result_mock.call_count == 1


CASES = [
    (
        incident_list.get('WITH_LABEL'), None, [{'name': 'Potential phishing I received',
                                                 'occurred': '0001-01-01T00:00:00Z',
                                                 'labels': [{'type': 'Email/subject',
                                                             'value': 'Potential phishing I received'},
                                                            {'type': 'Email', 'value': 'example@example.com'}]
                                                 }]

    ),
    (
        incident_list.get('WITHOUT_LABEL'), None, [{'name': 'Potential phishing I received',
                                                    'occurred': '0001-01-01T00:00:00Z'}]
    ),
    (
        incident_list.get('WITH_LABEL'), ["example_path.eml"],
        [{'name': 'Potential phishing I received',
          'occurred': '0001-01-01T00:00:00Z',
          'labels': [{'type': 'Email/subject',
                      'value': 'Potential phishing I received'},
                     {'type': 'Email', 'value': 'example@example.com'}],
          "attachment": ["example_path.eml"]
          }]
    ),
    (
        incident_list.get('WITHOUT_LABEL'), ["example_path.eml", "example_path2.eml"],
        [{'name': 'Potential phishing I received',
          'occurred': '0001-01-01T00:00:00Z',
          "attachment": ["example_path.eml", "example_path2.eml"]
          }]
    ),
    (
        incident_list.get('MULTIPLE_INCIDENTS'), ["example_path.eml"],
        [{'name': 'Potential phishing I received', 'occurred': '0001-01-01T00:00:00Z',
          "attachment": ["example_path.eml"]},
         {'name': 'Potential phishing I received 2', 'occurred': '0001-01-01T00:00:00Z',
          "attachment": ["example_path.eml"]}]
    ),
    (
        incident_list.get('EMPTY_INCIDENTS'), 'example_path.eml', []
    )
]


@pytest.mark.parametrize('incidents, attachment, expected', CASES)
def test_parse_incidents_happy(mocker, incidents, attachment, expected):
    """
    Given:  a list of valid incidents with labels without attachment,
            a list of valid incidents without labels without attachment,
            a list of valid incidents with labels with attachment,
            a list of valid incidents without labels with attachment,
            a list of multiple incidents,
            an empty list
    When:   creating an incident object from the incident retrieved
    Then:   Makes sure the incident object containing only the relevant fields
    """

    def http_mock(file_path, response_type):
        if file_path == 'example_path.eml':
            res = attachment_content
            return res
        else:
            return ''

    mocker.patch.object(CreateIncidents, 'fileResult', return_value={'FileID': 'example_id'} if attachment else None)
    mocker.patch.object(CreateIncidents.Client, 'http_request', side_effect=http_mock)
    res = CreateIncidents.parse_incidents(incidents, attachment)
    # removing raw json for reading comfortability
    for item in res:
        item.pop('rawJSON')

    assert res == expected


INCIDENT_PATH_CASES_BAD = [
    (
        ''
    ),
    (
        None
    ),
]


@pytest.mark.parametrize('incident_path', INCIDENT_PATH_CASES_BAD)
def test_create_test_incident_command_bad(incident_path):
    """
    Given: missing incident_path argument
    When: creating a new incident from file
    Then: Makes sure client fails with correct error
    """

    with pytest.raises(ValueError) as e:
        CreateIncidents.create_test_incident_from_file_command(
            CreateIncidents.Client('example_base_url.com', False, False),
            {'incidents_path': incident_path})
    assert str(e.value) == 'Incidents were not specified'


def test_http_request(mocker):
    http_mock = mocker.patch.object(CreateIncidents.Client, '_http_request')
    CLIENT_MOCK.http_request('file.json', response_type='json')
    assert http_mock.call_args[1]['url_suffix'] == 'file.json'
    assert http_mock.call_args[1]['resp_type'] == 'json'
    assert http_mock.call_args[1]['return_empty_response'] is True


LOAD_INCIDENT_CASES = [
    (
        incident_list.get('SINGLE_WITH_LABEL'), None, 1
    ),
    (
        incident_list.get('SINGLE_WITHOUT_LABEL'), None, 1
    ),
    (
        incident_list.get('MULTIPLE_INCIDENTS'), "example_path.eml", 2
    ),
    (
        incident_list.get('EMPTY_INCIDENTS'), 'example_path.eml', 0
    )
]


@pytest.mark.parametrize('incidents, attachment, expected', LOAD_INCIDENT_CASES)
def test_create_test_incident_command_happy(mocker, incidents, attachment, expected):
    """
     Given: a file with list-format of valid incidents with labels
            a file with single valid incident without labels
            a list of valid incidents with labels with attachment,
            an empty file without incidents
    When:   creating an incident object from the incident retrieved
    Then:   Makes sure the incidents we read are in correct format (list)
    """

    def http_mock(file_path, response_type):
        if file_path == 'example.json':
            res = incidents
            return res
        else:
            return ''

    parse_mock = mocker.patch.object(CreateIncidents, 'parse_incidents')
    mocker.patch.object(CreateIncidents.Client, 'http_request', side_effect=http_mock)
    CreateIncidents.create_test_incident_from_file_command(CLIENT_MOCK,
                                                           {'incidents_path': 'example.json',
                                                            'attachment_paths': attachment})
    assert type(parse_mock.call_args[0][0]) is list
    assert len(parse_mock.call_args[0][0]) == expected


ARGS = [{'incident_entry_id': 'entry_id', 'incident_raw_json': '{"name": "incident"}'},
        {'incident_entry_id': '', 'incident_raw_json': ''}]


@pytest.mark.parametrize('args', ARGS)
def test_create_test_incident_from_json_command_raise_error(args):
    """
    Given: Invalid command arguments
    When: creating a new incident from file
    Then: Makes sure client fails with correct error
    """

    with pytest.raises(DemistoException) as e:
        CreateIncidents.create_test_incident_from_json_command(args)
    assert str(e.value) == 'Please insert entry_id or incident_raw_json, and not both'


def test_create_test_incident_from_json_command(mocker):
    """
    Given: Raw json that represents incident
           Entry id represents incident attachment
    When: creating a new incident from file
    Then: Makes sure attachments are added
    """
    args = {'incident_raw_json': incident, 'attachment_entry_ids': 'entry_id'}
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': 'test_data/YOU HAVE WON 10000$.eml', 'name': 'fileName'})
    set_context_mock = mocker.patch.object(CreateIncidents, 'set_integration_context')
    CreateIncidents.create_test_incident_from_json_command(args)
    assert 'content' in set_context_mock.call_args_list[0][0][0]['incidents'][0]['entry_id_attachment'][0]
