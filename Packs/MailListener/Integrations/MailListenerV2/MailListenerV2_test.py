from datetime import datetime

import pytest

MAIL_STRING = """Delivered-To: to@test1.com
MIME-Version: 1.0
From: John Smith <from@test1.com>
Date: Mon, 10 Aug 2020 10:17:16 +0300
Subject: Testing email for mail listener
To: to@test1.com
Content-Type: multipart/alternative; boundary="0000000000002b271405ac80bf8b"


--0000000000002b271405ac80bf8b
Content-Type: text/plain; charset="UTF-8"



--0000000000002b271405ac80bf8b
Content-Type: text/html; charset="UTF-8"

<div dir="ltr"><br></div>

--0000000000002b271405ac80bf8b--
"""

EXPECTED_LABELS = [
    {'type': 'Email/from', 'value': 'from@test1.com'},
    {'type': 'Email/format', 'value': 'multipart/alternative'}, {'type': 'Email/text', 'value': ''},
    {'type': 'Email/subject', 'value': 'Testing email for mail listener'},
    {'type': 'Email/headers/Delivered-To', 'value': 'to@test1.com'},
    {'type': 'Email/headers/MIME-Version', 'value': '1.0'},
    {'type': 'Email/headers/From', 'value': 'John Smith <from@test1.com>'},
    {'type': 'Email/headers/Date', 'value': 'Mon, 10 Aug 2020 10:17:16 +0300'},
    {'type': 'Email/headers/Subject', 'value': 'Testing email for mail listener'},
    {'type': 'Email/headers/To', 'value': 'to@test1.com'},
    {'type': 'Email/headers/Content-Type',
     'value': 'multipart/alternative; boundary="0000000000002b271405ac80bf8b"'},
    {'type': 'Email', 'value': 'to@test1.com'},
    {'type': 'Email/html', 'value': '<div dir="ltr"><br></div>'}]


def test_convert_to_incident():
    """
    Given:
        - Bytes representation of a mail

        When:
        - Parsing it to incidents

        Then:
        - Validate the 'attachments', 'occurred', 'details' and 'name' fields are parsed as expected
    """
    from MailListenerV2 import Email
    email = Email(MAIL_STRING.encode(), False, False, 0)
    incident = email.convert_to_incident()
    assert incident['attachment'] == []
    assert incident['occurred'] == email.date.isoformat()
    assert incident['details'] == email.text or email.html
    assert incident['name'] == email.subject


@pytest.mark.parametrize(
    'time_to_fetch_from, permitted_from_addresses, permitted_from_domains, uid_to_fetch_from, expected_query',
    [
        (
            datetime(year=2020, month=10, day=1),
            ['test1@mail.com', 'test2@mail.com'],
            ['test1.com', 'domain2.com'],
            4,
            [
                'OR',
                'OR',
                'OR',
                'FROM',
                'test1@mail.com',
                'FROM',
                'test2@mail.com',
                'FROM',
                'test1.com',
                'FROM',
                'domain2.com',
                'SINCE',
                datetime(year=2020, month=10, day=1),
                'UID',
                '4:*'
            ]
        ),
        (
            None,
            [],
            [],
            1,
            [
                'UID',
                '1:*'
            ]
        )
    ]
)
def test_generate_search_query(
        time_to_fetch_from, permitted_from_addresses, permitted_from_domains, uid_to_fetch_from, expected_query
):
    """
    Given:
        - The date from which mails should be queried
        - A list of email addresses from which mails should be queried
        - A list of domains from which mails should be queried

        When:
        - Generating search query from these arguments

        Then:
        - Validate the search query as enough 'OR's in the beginning (Σ(from n=0to(len(addresses)+len(domains)))s^(n-1))
        - Validate the search query has FROM before each address or domain
        - Validate query has SINCE before the datetime object
    """
    from MailListenerV2 import generate_search_query
    assert generate_search_query(
        time_to_fetch_from, permitted_from_addresses, permitted_from_domains, uid_to_fetch_from
    ) == expected_query


def test_generate_labels():
    """
        Given:
        - Bytes representation of a mail

        When:
        - Generating mail labels

        Then:
        - Validate all expected labels are in the generated labels
    """
    from MailListenerV2 import Email
    email = Email(MAIL_STRING.encode(), False, False, 0)
    labels = email._generate_labels()
    for label in EXPECTED_LABELS:
        assert label in labels, f'Label {label} was not found in the generated labels, {labels}'
