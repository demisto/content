import requests
import demistomock as demisto


class DotDict(dict):
    """dot.notation access to dictionary attributes"""
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


def test_query_formatting(mocker):
    args = {
        'ticket-id': 1111
    }
    params = {
        'server': 'test',
        'credentials': {
            'identifier': 'test',
            'password': 'test'
        },
        'fetch_priority': 1,
        'fetch_status': 'test',
        'fetch_queue': 'test',
        'proxy': True
    }

    mocker.patch.object(requests, 'session', return_value=DotDict({}))
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'params', return_value=params)

    from RTIR import build_search_query
    query = build_search_query()
    assert not (query.endswith('+OR+') or query.endswith('+AND+'))


RAW_HISTORY = """
RT/4.4.2 200 Ok

# 24/24 (id/80/total)

id: 80
Ticket: 5
TimeTaken: 0
Type: Create
Field:
OldValue:
NewValue: some new value
Data:
Description: Ticket created by root
Content: Some
Multi line
Content
Creator: root
Created: 2018-07-09 11:25:59
Attachments:

"""


def test_parse_history_response():
    from RTIR import parse_history_response
    parsed_history = parse_history_response(RAW_HISTORY)
    assert parsed_history == {'ID': '80',
                              'Ticket': '5',
                              'TimeTaken': '0',
                              'Type': 'Create',
                              'Field': '',
                              'OldValue': '',
                              'NewValue': 'some new value',
                              'Data': '',
                              'Description': 'Ticket created by root',
                              'Content': 'Some\nMulti line\nContent',
                              'Creator': 'root',
                              'Created': '2018-07-09 11:25:59',
                              'Attachments': ''}


RAW_LINKS = """RT/4.4.4 200 Ok

id: ticket/68315/links

Members: some-url.com/ticket/65461,
         some-url.com/ticket/65462,
         some-url.com/ticket/65463"""


def test_parse_ticket_links():
    from RTIR import parse_ticket_links
    response = parse_ticket_links(RAW_LINKS)
    expected = [{'ID': '65461'}, {'ID': '65462'}, {'ID': '65463'}]
    assert response == expected
