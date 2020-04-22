import pytest
from QuestKace import Client, get_machines_list_command, \
    get_assets_list_command, get_queues_list_command, get_queues_fields_list_command, get_tickets_list_command, \
    parse_response

from test_module.RawData import MACHINES_LIST_COMMAND_RESPONSE, \
    ASSETS_LIST_COMMAND_RESPONSE, QUEUES_LIST_COMMAND_RESPONSE, QUEUES_FIELDS_LIST_COMMAND_RESPONSE, \
    TICKETS_LIST_COMMAND_RESPONSE, LIST_BEFORE_PARSE

from test_module.ExpectedResult import MACHINES_LIST_COMMAND_EXPECTED, \
    ASSETS_LIST_COMMAND_EXPECTED, QUEUES_LIST_COMMAND_EXPECTED, QUEUES_FIELDS_LIST_COMMAND_EXPECTED, \
    TICKETS_LIST_COMMAND_EXPECTED, LIST_EXPECTED_AFTER_PARSE


@pytest.mark.parametrize('command, args, response, expected_result', [
    (get_machines_list_command, {}, MACHINES_LIST_COMMAND_RESPONSE, MACHINES_LIST_COMMAND_EXPECTED),
    (get_assets_list_command, {}, ASSETS_LIST_COMMAND_RESPONSE, ASSETS_LIST_COMMAND_EXPECTED),
    (get_queues_list_command, {}, QUEUES_LIST_COMMAND_RESPONSE, QUEUES_LIST_COMMAND_EXPECTED),
    (get_queues_fields_list_command, {"queue_number": "1"}, QUEUES_FIELDS_LIST_COMMAND_RESPONSE,
     QUEUES_FIELDS_LIST_COMMAND_EXPECTED),
    (get_tickets_list_command,
     {'custom_fields': "hd_ticket all,submitter limited,owner limited, asset limited,machine limited,"
                       "priority limited,category limited, impact limited,status limited, related_tickets limited"},
     TICKETS_LIST_COMMAND_RESPONSE, TICKETS_LIST_COMMAND_EXPECTED),
])
def test_commands(command, args, response, expected_result, mocker):
    mocker.patch.object(Client, 'get_token', return_value=(1, 1))
    client = Client(url='https://demisto', username='admin', password='admin', verify=True,
                    proxy=True)
    mocker.patch.object(client, '_http_request', return_value=response)
    result = command(client, args)
    assert expected_result == result[1]


@pytest.mark.parametrize('list_before_parse, expected_lst_of_dict', [(LIST_BEFORE_PARSE, LIST_EXPECTED_AFTER_PARSE)])
def test_parse_response(list_before_parse, expected_lst_of_dict):
    assert parse_response(list_before_parse) == expected_lst_of_dict
