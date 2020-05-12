import pytest
import json
from QuestKace import Client, get_machines_list_command, \
    get_assets_list_command, get_queues_list_command, get_tickets_list_command, \
    parse_response, fetch_incidents, create_body_from_args, shaping_by_fields, convert_specific_keys, \
    delete_ticket_command, demisto, get_fields_by_queue

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
    client = Client(url="http://test.com", username="admin", password="123", verify=False, proxy=False)
    incidents = fetch_incidents(client=client, last_run={'last_fetch': '2020-04-12T02:28:02Z'},
                                fetch_time="1 day", fetch_shaping="", fetch_limit="5")
    assert len(incidents) == 5
    assert incidents[4]['name']
    assert incidents[4]['occurred']
    assert json.loads(incidents[4]['rawJSON'])['id'] == 10


def test_fetch_No_Results(mocker):
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
    client = Client(url="http://test.com", username="admin", password="123", verify=False, proxy=False)
    incidents = fetch_incidents(client=client, last_run={'last_fetch': '2020-04-12T02:28:02Z'},
                                fetch_time="1 day", fetch_shaping="", fetch_limit="5")
    assert incidents == []


def test_create_body_from_args():
    body = create_body_from_args(hd_queue_id=1, title="test from unit testing",
                                 category={'name': 'test from unittesting'}, status={'name': ' test unit'})
    assert body == {'hd_queue_id': 1, 'title': 'test from unit testing',
                    'category': {'name': 'test from unittesting'},
                    'status': {'name': ' test unit'}}


def test_shaping_by_fields():
    fields = shaping_by_fields(['title', 'summary', 'impact', 'status'])
    assert fields == 'hd_ticket all,title limited,summary limited,impact limited,status limited'
    fields = shaping_by_fields([])
    assert fields == 'hd_ticket all'


def test_convert_specific_keys():
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
    mocker.patch.object(Client, 'queues_list_request', return_value=QUEUES_LIST_COMMAND_RESPONSE)
    mocker.patch.object(Client, 'queues_list_fields_request', return_value=FIELDS_RESPONSE)
    mocker.patch.object(Client, 'get_token', return_value=(1, 1))
    client = Client(url="http://test.com", username="admin", password="123", verify=False, proxy=False)
    fields = get_fields_by_queue(client, [1])
    assert fields == FIELDS_EXPECTED
    fields = get_fields_by_queue(client, [])
    assert fields == FIELDS_EXPECTED
