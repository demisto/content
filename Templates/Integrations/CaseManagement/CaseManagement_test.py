import copy
import json

import pytest
from CaseManagement import Client
from pytest import raises

from CommonServerPython import urljoin, DemistoException

url = 'https://example.com/'
client = Client(url, 50)


class TestModule:
    response = {'version': '111'}
    suffix = 'version'

    def test_module_positive(self, requests_mock):
        from CaseManagement import test_module_command
        requests_mock.get(urljoin(url, self.suffix), json=self.response)
        assert 'ok' == test_module_command(client)

    def test_module_negative(self, requests_mock):
        from CaseManagement import test_module_command
        requests_mock.get(urljoin(url, self.suffix), json={})
        with raises(DemistoException, match='Unexpected response'):
            test_module_command(client)


class TestInputs:
    TICKET_MOCK = {
        'ticket': [
            {
                'id': '111',
                'timestamp': '2010-01-01T00:00:00',
                'name': 'nameofticket',
                'category': 'ticketCategory',
                'description': 'This is a description',
                'isOpen': True,
                'assignee': [
                    {
                        'id': 'user1',
                        'name': 'User Name1',
                    },
                    {
                        'id': 'user2',
                        'name': 'User Name2',
                    }
                ],
            }
        ]
    }
    EXCEPTED_CONTEXT_ONE_TICKET = {
        'CaseManagement.Ticket(val.ID && val.ID === obj.ID)': [
            {
                'ID': '111',
                'Name': 'nameofticket',
                'Category': 'ticketCategory',
                'Description': 'This is a description',
                'Timestamp': '2010-01-01T00:00:00',
                'IsOpen': True,
                'Assignee': [
                    {'ID': 'user1', 'Name': 'User Name1'}, {'ID': 'user2', 'Name': 'User Name2'}]
            }
        ]
    }

    EXCEPTED_CONTEXT_TICKET_LIST = {
        'CaseManagement.Ticket(val.ID && val.Name ==== obj.ID)':
            [
                {
                    'ID': '111',
                    'Name': 'nameofticket',
                    'Category': 'ticketCategory',
                    'Description': 'This is a description',
                    'Timestamp': '2010-01-01T00:00:00',
                    'IsOpen': True,
                    'Assignee': [
                        {'ID': 'user1', 'Name': 'User Name1'}, {'ID': 'user2', 'Name': 'User Name2'}
                    ]
                }
            ]
    }
    GET_TICKET_INPUT = [
        (TICKET_MOCK, 'Case Management Integration - Ticket ID: `111`', EXCEPTED_CONTEXT_ONE_TICKET),
        ({}, 'Could not find ticket ID: `111`', {},)
    ]

    LIST_TICKETS_INPUT = [
        (TICKET_MOCK, 'Case Management Integration - Tickets list:', EXCEPTED_CONTEXT_TICKET_LIST),
        ({}, 'Could not find any tickets.', {},)
    ]

    CREATE_TICKET_INPUT = [
        (TICKET_MOCK, 'Ticket has been successfully created', EXCEPTED_CONTEXT_ONE_TICKET)
    ]

    ASSIGN_USERS_INPUT = [
        (TICKET_MOCK, 'Users has been assigned to ', EXCEPTED_CONTEXT_ONE_TICKET),
        ({}, 'Could not assign users to ticket ID', {})
    ]

    USER_LIST = {'user': [{'username': 'user1ftw', 'id': '111'}, {'username': 'dasIstMe', 'id': '1337'}]}
    EXCEPTED_CONTEXT_USER_LIST = {
        'CaseManagement.User(val.ID && val.ID === obj.ID)': [{'Username': 'user1ftw', 'ID': '111'},
                                                             {'Username': 'dasIstMe', 'ID': '1337'}]}
    LIST_USERS_INPUT = [
        (USER_LIST, 'Users list', EXCEPTED_CONTEXT_USER_LIST),
        ({}, 'Could not find', {})
    ]
    INCIDENT = [{
        'name': 'Case Management Integration - ticket number: 111',
        'rawJSON': json.dumps(TICKET_MOCK)
    }]
    FETCH_INCIDENTS_INPUT = [
        (TICKET_MOCK, {'timestamp': '2010-01-01T00:00:00'}, '3 days', INCIDENT),
        (TICKET_MOCK, None, None, INCIDENT),
        ({'ticket': []}, None, None, [])
    ]


class TestTickets:
    create_ticket_args = {
        'timestamp': '2010-01-01T00:00:00',
        'name': 'nameofticket',
        'category': 'ticketCategory',
        'description': 'This is a description',
        'assignee': 'user1,user2',
    }

    @pytest.mark.parametrize('req_input,expected_md,expected_context', TestInputs.GET_TICKET_INPUT)
    def test_get_ticket(self, requests_mock, req_input, expected_md, expected_context):
        from CaseManagement import get_ticket_command
        requests_mock.get(urljoin(url, 'ticket?id=111'), json=req_input)
        human_readable, context, _ = get_ticket_command(client, {'ticket_id': '111'})
        assert expected_md in human_readable
        assert expected_context == context

    @pytest.mark.parametrize('req_input,expected_md,expected_context', TestInputs.LIST_TICKETS_INPUT)
    def test_list_tickets(self, requests_mock, req_input, expected_md, expected_context):
        from CaseManagement import list_tickets_command
        requests_mock.get(urljoin(url, 'ticket'), json=req_input)
        human_readable, context, _ = list_tickets_command(client, {'ticket_id': '111'})
        assert expected_md in human_readable
        assert expected_context == context

    @pytest.mark.parametrize('req_input,expected_md,expected_context', TestInputs.CREATE_TICKET_INPUT)
    def test_create_ticket(self, requests_mock, req_input, expected_md, expected_context):
        from CaseManagement import create_ticket_command
        requests_mock.post(urljoin(url, 'ticket'), json=req_input)
        human_readable, context, _ = create_ticket_command(client, self.create_ticket_args)
        assert expected_md in human_readable
        assert expected_context == context

    def test_create_ticket_negative(self, requests_mock):
        from CaseManagement import create_ticket_command
        requests_mock.post(urljoin(url, 'ticket'), json={})
        with raises(DemistoException, match='Could not create new ticket'):
            create_ticket_command(client, self.create_ticket_args)

    def test_close_ticket_command(self, requests_mock):
        from CaseManagement import close_ticket_command
        ticket = copy.deepcopy(TestInputs.TICKET_MOCK)
        ticket['ticket'][0]['isOpen'] = False
        requests_mock.post(urljoin(url, 'ticket/close'), json=ticket)
        close_ticket_command(client, {'ticket_id': '111'})

    def test_close_ticket_command_negative(self, requests_mock):
        from CaseManagement import close_ticket_command
        ticket = copy.deepcopy(TestInputs.TICKET_MOCK)
        ticket['ticket'][0]['isOpen'] = False
        requests_mock.post(urljoin(url, 'ticket/close'), json={})
        with raises(DemistoException, match='Could not close ticket'):
            close_ticket_command(client, {'ticket_id': '111'})

    @pytest.mark.parametrize('req_input,expected_md,expected_context', TestInputs.ASSIGN_USERS_INPUT)
    def test_assign_users(self, requests_mock, req_input, expected_md, expected_context):
        from CaseManagement import assign_users_command
        requests_mock.post(urljoin(url, 'ticket/assign'), json=req_input)
        human_readable, context, _ = assign_users_command(client, {'ticket_id': '111', 'users': ['user1, user2']})
        assert expected_md in human_readable
        assert expected_context == context

    @pytest.mark.parametrize('req_input,expected_md,expected_context', TestInputs.LIST_USERS_INPUT)
    def test_list_users(self, requests_mock, req_input, expected_md, expected_context):
        from CaseManagement import list_users_command
        requests_mock.get(urljoin(url, 'user'), json=req_input)
        human_readable, context, _ = list_users_command(client, {'ticket_id': '111', 'users': ['user1, user2']})
        assert expected_md in human_readable
        assert expected_context == context


class TestFetchIncidents:
    @pytest.mark.parametrize('req_input,last_run,fetch_time,incidents', TestInputs.FETCH_INCIDENTS_INPUT)
    def test_fetch_incidents(self, requests_mock, req_input, last_run, fetch_time, incidents):
        from CaseManagement import fetch_incidents_command
        requests_mock.get(urljoin(url, 'ticket'), json=req_input)
        incidents_res, timestamp = fetch_incidents_command(client, last_run, fetch_time)
        if incidents:
            assert incidents_res[0].get('name') == incidents[0].get('name')
        else:
            assert not incidents and not incidents_res
