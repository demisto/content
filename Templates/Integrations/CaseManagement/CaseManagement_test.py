import pytest
from CaseManagement import Client
from pytest import raises

from CommonServerPython import urljoin, DemistoException

url = 'https://example.com/'
client = Client(url, 50)
TICKET_MOCK = {
    'ticket': [
        {
            'id': '111',
            'timestamp': '2010-01-01T00:00:00',
            'name': 'nameofticket',
            'category': 'ticketCategory',
            'description': 'This is a description',
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
EXCEPTED_CONTEXT_ONE_TICKET = {'CaseManagement(val.ID && val.ID === obj.ID)': [
    {'ID': '111', 'Name': 'nameofticket', 'Category': 'ticketCategory', 'Description': 'This is a description',
     'Timestamp': '2010-01-01T00:00:00', 'Assignee': [
        {'ID': 'user1', 'Name': 'User Name1'}, {'ID': 'user2', 'Name': 'User Name2'}]}]
}

EXCEPTED_CONTEXT_TICKET_LIST = {'CaseManagement.Ticket(val.ID && val.Name ==== obj.ID)': [
    {'ID': '111', 'Name': 'nameofticket', 'Category': 'ticketCategory', 'Description': 'This is a description',
     'Timestamp': '2010-01-01T00:00:00', 'Assignee': [
        {'ID': 'user1', 'Name': 'User Name1'}, {'ID': 'user2', 'Name': 'User Name2'}]}]
}


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
        with raises(DemistoException):
            test_module_command(client)


GET_TICKET_INPUT = [
    (TICKET_MOCK, 'Case Management Integration - Ticket ID: `111`', EXCEPTED_CONTEXT_ONE_TICKET),
    ({}, 'Could not find ticket ID: `111`', {},)
]

LIST_TICKETS_INPUT = [
    (TICKET_MOCK, 'Case Management Integration - Tickets list:', EXCEPTED_CONTEXT_TICKET_LIST),
    ({}, 'Case Management Integration - Could not find any tickets.', {},)
]

CREATE_TICKET_INPUT = [
    (TICKET_MOCK, '11', '')
]


class TestTickets:
    create_ticket_args = {
        'timestamp': '2010-01-01T00:00:00',
        'name': 'nameofticket',
        'category': 'ticketCategory',
        'description': 'This is a description',
        'assignee': 'user1,user2',
    }

    @pytest.mark.parametrize('req_input,expected_md,expected_context', GET_TICKET_INPUT)
    def test_get_ticket(self, requests_mock, req_input, expected_md, expected_context):
        from CaseManagement import get_ticket_command
        requests_mock.get(urljoin(url, 'ticket?ticketId=111'), json=req_input)
        human_readable, context, _ = get_ticket_command(client, {'ticket_id': '111'})
        assert expected_md in human_readable
        assert expected_context == context

    @pytest.mark.parametrize('req_input,expected_md,expected_context', LIST_TICKETS_INPUT)
    def test_list_tickets(self, requests_mock, req_input, expected_md, expected_context):
        from CaseManagement import list_tickets_command
        requests_mock.get(urljoin(url, 'ticket'), json=req_input)
        human_readable, context, _ = list_tickets_command(client, {'ticket_id': '111'})
        assert expected_md in human_readable
        assert expected_context == context

    @pytest.mark.parametrize('req_input,expected_md,expected_context', CREATE_TICKET_INPUT)
    def test_create_ticket(self, requests_mock, req_input, expected_md, expected_context):
        from CaseManagement import create_ticket_command
        requests_mock.post(urljoin(url, 'ticket'), json=req_input)
        human_readable, context, _ = create_ticket_command(client, self.create_ticket_args)
        assert expected_md in human_readable
        assert expected_context == context
