import pytest
import json
import time
from QuestKace import Client, get_machines_list_command, \
    get_assets_list_command, get_queues_list_command, get_tickets_list_command, \
    parse_response, fetch_incidents, create_body_from_args, shaping_by_fields, convert_specific_keys, \
    delete_ticket_command, demisto, get_fields_by_queue, shaping_fetch

from test_module.RawData import MACHINES_LIST_COMMAND_RESPONSE, \
    ASSETS_LIST_COMMAND_RESPONSE, QUEUES_LIST_COMMAND_RESPONSE, \
    TICKETS_LIST_COMMAND_RESPONSE, LIST_BEFORE_PARSE, FIRST_FETCH_INCIDENTS_RAW_RESPONSE, \
    SECOND_FETCH_INCIDENTS_RAW_RESPONSE, NO_RESULTS_FETCH_INCIDENTS_RAW_RESPONSE, DEMISTO_DT_RESPONSE, FIELDS_RESPONSE

from test_module.ExpectedResult import MACHINES_LIST_COMMAND_EXPECTED, \
    ASSETS_LIST_COMMAND_EXPECTED, QUEUES_LIST_COMMAND_EXPECTED, \
    TICKETS_LIST_COMMAND_EXPECTED, LIST_EXPECTED_AFTER_PARSE, DELETE_COMMAND_RESPONSE, FIELDS_EXPECTED


@pytest.mark.parametrize('command, args, response, expected_result', [
    (get_machines_list_command, {}, MACHINES_LIST_COMMAND_RESPONSE, MACHINES_LIST_COMMAND_EXPECTED),
    (get_assets_list_command, {}, ASSETS_LIST_COMMAND_RESPONSE, ASSETS_LIST_COMMAND_EXPECTED),
    (get_queues_list_command, {}, QUEUES_LIST_COMMAND_RESPONSE, QUEUES_LIST_COMMAND_EXPECTED),
    (get_tickets_list_command,
     {'custom_fields': "hd_ticket all,submitter limited,owner limited, asset limited,machine limited,"
                       "priority limited,category limited, impact limited,status limited, related_tickets limited"},
     TICKETS_LIST_COMMAND_RESPONSE, TICKETS_LIST_COMMAND_EXPECTED)
])
def test_commands(command, args, response, expected_result, mocker):
    """ Unit test
    Given
        - 4 main commands of the integration.
        - command args
        - command raw response
    When
        - mock the Clients's get token function.
    Check if all commands with given arguments run correctly according to expected result.
    """
    mocker.patch.object(Client, 'get_token', return_value=(1, 1))
    mocker.patch('QuestKace.set_shaping', return_value=[])
    client = Client(url='https://demisto', username='admin', password='admin', verify=True,
                    proxy=True)
    mocker.patch.object(client, '_http_request', return_value=response)
    result = command(client, args)
    assert expected_result == result[1]


@pytest.mark.parametrize('list_before_parse, expected_lst_of_dict', [(LIST_BEFORE_PARSE, LIST_EXPECTED_AFTER_PARSE)])
def test_parse_response(list_before_parse, expected_lst_of_dict):
    """ Unit test
    Check if the parser function of snake case to camel case works corretcly.
    """
    assert parse_response(list_before_parse) == expected_lst_of_dict


def test_first_fetch(mocker):
    """Unit test
        Given
        - fetch incidents command
        - command args
        - command raw response
        When
        - mock the Clients's get token function.
        - mock the Clients's tickets_list_request.
        - mock the parse_date_range function.
        Then
        - run the fetch incidents command using the Client
        Validate The length of the results.
        Validate that the first run of fetch incidents runs correctly.
        """
    mocker.patch('QuestKace.parse_date_range', return_value=("2020-03-11T08:30:41Z", 'never mind'))
    mocker.patch('QuestKace.set_shaping', return_value=[])
    mocker.patch.object(Client, 'tickets_list_request', return_value=FIRST_FETCH_INCIDENTS_RAW_RESPONSE)
    mocker.patch.object(Client, 'get_token', return_value=(1, 1))
    mocker.patch.object(Client, 'queues_list_request', return_value={'Queues': []})
    client = Client(url="http://test.com", username="admin", password="123", verify=False, proxy=False)
    incidents = fetch_incidents(client=client, last_run={}, fetch_time="3 years", fetch_shaping="", fetch_limit="3")
    assert len(incidents) == 3


def test_delete_command(mocker):
    mocker.patch.object(Client, 'delete_ticket_request', return_value={'Result': 'Success'})
    mocker.patch.object(demisto, 'dt', return_value=DEMISTO_DT_RESPONSE)
    mocker.patch.object(Client, 'get_token', return_value=(1, 1))
    client = Client(url="http://test.com", username="admin", password="123", verify=False, proxy=False)
    deleted_ticket = delete_ticket_command(client=client, args={'ticket_id': '1'})
    assert deleted_ticket[1] == DELETE_COMMAND_RESPONSE


def test_second_fetch(mocker):
    """Unit test
        Given
        - fetch incidents command
        - command args
        - command raw response
        When
        - mock the Clients's get token function.
        - mock the Clients's tickets_list_request.
        - mock the parse_date_range function.
        Then
        - run the fetch incidents command using the Client
        Validate that the second run of fetch incidents runs correctly from last fetch time.
        Validate The length of the results.
        Validate That the name and occurred exist in the created incidents.
        Validate The id of returned incidents.
        """
    mocker.patch('QuestKace.set_shaping', return_value=[])
    mocker.patch.object(Client, 'tickets_list_request', return_value=SECOND_FETCH_INCIDENTS_RAW_RESPONSE)
    mocker.patch.object(Client, 'get_token', return_value=(1, 1))
    mocker.patch.object(Client, 'queues_list_request', return_value={'Queues': []})
    client = Client(url="http://test.com", username="admin", password="123", verify=False, proxy=False)
    incidents = fetch_incidents(client=client, last_run={'last_fetch': '2020-04-12T02:28:02Z'},
                                fetch_time="1 day", fetch_shaping="", fetch_limit="5")
    assert len(incidents) == 5
    assert incidents[4]['name']
    assert incidents[4]['occurred']
    assert json.loads(incidents[4]['rawJSON'])['id'] == 10


def test_fetch_no_Results(mocker):
    """Unit test
        Given
        - fetch incidents command
        - command args
        - command raw response
        When
        - mock the Clients's get token function.
        - mock the Clients's tickets_list_request.
        - mock the parse_date_range function.
        Then
        - run the fetch incidents command using the Client
        - Check that no incidents are created falsely.
        """
    mocker.patch('QuestKace.parse_date_range', return_value=("2020-03-11 08:30:41", 'never mind'))
    mocker.patch('QuestKace.set_shaping', return_value=[])
    mocker.patch.object(Client, 'tickets_list_request', return_value=NO_RESULTS_FETCH_INCIDENTS_RAW_RESPONSE)
    mocker.patch.object(Client, 'get_token', return_value=(1, 1))
    mocker.patch.object(Client, 'queues_list_request', return_value={'Queues': []})
    client = Client(url="http://test.com", username="admin", password="123", verify=False, proxy=False)
    incidents = fetch_incidents(client=client, last_run={'last_fetch': '2020-04-12T02:28:02Z'},
                                fetch_time="1 day", fetch_shaping="", fetch_limit="5")
    assert incidents == []


def test_create_body_from_args():
    """Unit test
        Given
        - Different fields as arguments to function
        Then
        - run the create_body_from_args command .
        Validate that the function returns a correct string
    """
    body = create_body_from_args(hd_queue_id=1, title="test from unit testing",
                                 category=1, status=2)
    assert body == {'hd_queue_id': 1, 'title': 'test from unit testing',
                    'category': 1,
                    'status': 2}


def test_shaping_by_fields():
    """Unit test
        Given
        - List of string of names of fields
        Then
        - run the shaping_by_fields command .
        Validate the returned string, which should be correct shaping string.
        Validate that when no fields are given then it returns only hd_ticket all string
    """
    fields = shaping_by_fields(['title', 'summary', 'impact', 'status'])
    assert fields == 'hd_ticket all,title limited,summary limited,impact limited,status limited'
    fields = shaping_by_fields([])
    assert fields == 'hd_ticket all'


def test_convert_specific_keys():
    """Unit test
        Given
        - String
        Then
        - run the convert_specific_keys command .
        Validate that for all special keys, the function converts them to correct convention.
    """
    converted = convert_specific_keys('OsName')
    assert converted == 'OSName'
    converted = convert_specific_keys('OsNumber')
    assert converted == 'OSNumber'
    converted = convert_specific_keys('Ram total')
    assert converted == 'RamTotal'
    converted = convert_specific_keys('AssetDataId')
    assert converted == 'AssetDataID'
    converted = convert_specific_keys('AssetClassId')
    assert converted == 'AssetClassID'
    converted = convert_specific_keys('AssetStatusId')
    assert converted == 'AssetStatusID'
    converted = convert_specific_keys('AssetTypeId')
    assert converted == 'AssetTypeID'
    converted = convert_specific_keys('MappedId')
    assert converted == 'MappedID'
    converted = convert_specific_keys('OwnerId')
    assert converted == 'OwnerID'
    converted = convert_specific_keys('HdQueueId')
    assert converted == 'HdQueueID'
    converted = convert_specific_keys('Ip')
    assert converted == 'IP'


def test_get_fields_by_queue(mocker):
    """Unit test
        Given
        - List of queues
        - Client
        When
        - mock the Clients's get token function.
        - mock the Clients's queues_list_request function.
        - mock the Clients's queues_list_fields_request function.
        Then
        - run the get_fields_by_queue command .
        Validate that when 1 queue is given then a list of its fields is returned.
        Validate that when no queue is given then a list of all fields of all available queues are returned.
        """
    mocker.patch.object(Client, 'queues_list_request', return_value=QUEUES_LIST_COMMAND_RESPONSE)
    mocker.patch.object(Client, 'queues_list_fields_request', return_value=FIELDS_RESPONSE)
    mocker.patch.object(Client, 'get_token', return_value=(1, 1))
    client = Client(url="http://test.com", username="admin", password="123", verify=False, proxy=False)
    fields = get_fields_by_queue(client, [1])
    assert fields == FIELDS_EXPECTED
    fields = get_fields_by_queue(client, [])
    assert fields == FIELDS_EXPECTED


def test_shaping_fetch_no_previous_integration_context(mocker):
    """Unit test
        Given
        - fetch incidents command
        - command args
        When
        - mock the Clients's get token function.
        - mock the Demisto's getIntegrationContext.
        - mock the set_shaping function.
        Then
        - run the fetch incidents command using the Client
        Validate when no integration context is saved, Then new shaping will be created and saved.
        """
    mocker.patch('QuestKace.set_shaping', return_value='Test shaping default')
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={})
    mocker.patch.object(Client, 'get_token', return_value=(1, 1))
    client = Client(url="http://test.com", username="admin", password="123", verify=False, proxy=False)
    shaping = shaping_fetch(client, [])
    assert shaping == 'Test shaping default'


def test_shaping_fetch_with_previous_integration_context_valid(mocker):
    """Unit test
        Given
        - fetch incidents command
        - command args
        When
        - mock the Clients's get token function.
        - mock the Demisto's getIntegrationContext.
        - mock the set_shaping function.
        Then
        - run the fetch incidents command using the Client
        Validate when a day has not passed since the last update of shaping, then return last shaping available.
        Validate that the shaping was not changed.
        """
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={
        'shaping_fields': 'Tests shpaing',
        'valid_until': int(time.time()) + 3600 * 24
    })
    mocker.patch.object(Client, 'get_token', return_value=(1, 1))
    client = Client(url="http://test.com", username="admin", password="123", verify=False, proxy=False)

    mocker.patch('QuestKace.set_shaping', return_value='Test shaping not default default')
    shaping = shaping_fetch(client, [])
    assert shaping == 'Tests shpaing'


def test_shaping_fetch_with_previous_integration_context_not_valid(mocker):
    """Unit test
        Given
        - fetch incidents command
        - command args
        When
        - mock the Clients's get token function.
        - mock the Demisto's getIntegrationContext.
        - mock the set_shaping function.
        Then
        - run the fetch incidents command using the Client
        Validate when a day has passed since last update of shaping, Then the shaping will be checked again.
        Validate That the shaping is set to new shaping.
        """
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={
        'shaping_fields': 'Tests shpaing',
        'valid_until': int(time.time())
    })
    mocker.patch.object(Client, 'get_token', return_value=(1, 1))
    client = Client(url="http://test.com", username="admin", password="123", verify=False, proxy=False)
    mocker.patch('QuestKace.set_shaping', return_value='Test shaping not default default')
    shaping = shaping_fetch(client, [])
    assert shaping == 'Test shaping not default default'
