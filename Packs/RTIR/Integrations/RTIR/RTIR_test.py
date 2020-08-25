import requests
import demistomock as demisto


class DotDict(dict):
    """dot.notation access to dictionary attributes"""
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__  # noqa: type: ignore[assignment]
    __delattr__ = dict.__delitem__  # noqa: type: ignore[assignment]


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


def test_build_ticket_id_in_headers():
    """

    Given:
    - A ticket containing 'ID' in its keys

    When:
    - building a search ticket

    Then:
    - Validate the ticket ID parsed correctly

    """
    from RTIR import build_ticket
    ticket = build_ticket(['ID: ticket/1'])
    expected = {'ID': 1}
    assert expected == ticket


def test_build_ticket_contains_id_in_headers():
    """

    Given:
    - A ticket contains a key with 'ID' substring.

    When:
    - building a search ticket

    Then:
    - Validate nothing returns

    """
    from RTIR import build_ticket
    ticket = build_ticket(['ThisIsAID: ofNotID'])
    assert {} == ticket


RAW_ATTACHMENTS_LIST = """
RT/4.4.2 200 Ok

id: ticket/6325/attachments
Attachments: 504: mimecast-get-remediation-incident.log (text/plain / 3.5k)
505: mimecast-get-remediation-incident2.log (text/plain / 3.6k)"""


def test_parse_attachments_list():
    """
        Test attachment list parsing
        Given:
            - Attachment list raw response
        When:
            - Trying to parse that response
        Then:
            - Ensure response is parsed into a list of tuples with id, name, type, size
    """
    from RTIR import parse_attachments_list
    response = parse_attachments_list(RAW_ATTACHMENTS_LIST)
    expected = [('504', 'mimecast-get-remediation-incident.log', 'text/plain', '3.5k'),
                ('505', 'mimecast-get-remediation-incident2.log', 'text/plain', '3.6k')]
    assert response == expected


RAW_ATTACHMENT_CONTENT = """From: root@localhost
Subject: <ticket subject>
X-RT-Interface: REST
Content-Type: text/plain
Content-Disposition: form-data;
name="attachment_1";
filename="mimecast-get-remediation-incident.log";
filename="mimecast-get-remediation-incident.log"
Content-Transfer-Encoding: binary
Content-Length: <length of the content>

Content: some multiline
attachment content"""


def test_parse_attachment_content():
    """
        Test attachment content
        Given:
            - Attachment content raw response
        When:
            - Trying to parse that response
        Then:
            - Ensure response is parsed into a string with all that comes after the "Content: "
    """
    from RTIR import parse_attachment_content
    response = parse_attachment_content('1234', RAW_ATTACHMENT_CONTENT)
    expected = 'some multiline\nattachment content'
    assert response == expected
