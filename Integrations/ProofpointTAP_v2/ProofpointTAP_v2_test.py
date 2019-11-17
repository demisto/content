import json
from datetime import datetime

import pytest
from ProofpointTAP_v2 import fetch_incidents, Client, ALL_EVENTS, ISSUES_EVENTS, get_events_command

MOCK_URL = "http://123-fake-api.com"
MOCK_DELIVERED_MESSAGE = {
    "GUID": "1111",
    "QID": "r2FNwRHF004109",
    "ccAddresses": [
        "bruce.wayne@university-of-education.zz"
    ],
    "clusterId": "pharmtech_hosted",
    "fromAddress": "badguy@evil.zz",
    "headerCC": "\"Bruce Wayne\" <bruce.wayne@university-of-education.zz>",
    "headerFrom": "\"A. Badguy\" <badguy@evil.zz>",
    "headerReplyTo": None,
    "headerTo": "\"Clark Kent\" <clark.kent@pharmtech.zz>; \"Diana Prince\" <diana.prince@pharmtech.zz>",
    "impostorScore": 0,
    "malwareScore": 100,
    "messageID": "1111@evil.zz",
    "threatsInfoMap": [
        {
            "campaignId": "46e01b8a-c899-404d-bcd9-189bb393d1a7",
            "classification": "MALWARE",
            "threat": "2fab740f143fc1aa4c1cd0146d334c5593b1428f6d062b2c406e5efe8abe95ca",
            "threatId": "2fab740f143fc1aa4c1cd0146d334c5593b1428f6d062b2c406e5efe8abe95ca",
            "threatStatus": "active",
            "threatTime": "2010-01-30T00:00:40.000Z",
            "threatType": "ATTACHMENT",
            "threatUrl": "https://threatinsight.proofpoint.com/43fc1aa4c1cd0146d334c5593b1428f6d062b2c406e5efe8abe95ca"
        },
        {
            "campaignId": "46e01b8a-c899-404d-bcd9-189bb393d1a7",
            "classification": "MALWARE",
            "threat": "badsite.zz",
            "threatId": "3ba97fc852c66a7ba761450edfdfb9f4ffab74715b591294f78b5e37a76481aa",
            "threatTime": "2010-01-30T00:00:30.000Z",
            "threatType": "URL",
            "threatUrl": "https://threatinsight.proofpoint.com/a7ba761450edfdfb9f4ffab74715b591294f78b5e37a76481aa"
        }
    ],
    "messageTime": "2010-01-30T00:00:59.000Z",
    "modulesRun": [
        "pdr",
        "sandbox",
        "spam",
        "urldefense"
    ],
    "phishScore": 46,
    "policyRoutes": [
        "default_inbound",
        "executives"
    ],
    "quarantineFolder": "Attachment Defense",
    "quarantineRule": "module.sandbox.threat",
    "recipient": [
        "clark.kent@pharmtech.zz",
        "diana.prince@pharmtech.zz"
    ],
    "replyToAddress": None,
    "sender": "e99d7ed5580193f36a51f597bc2c0210@evil.zz",
    "senderIP": "192.0.2.255",
    "spamScore": 4,
    "subject": "Please find a totally safe invoice attached."
}

MOCK_BLOCKED_MESSAGE = {
    "GUID": "2222",
    "QID": "r2FNwRHF004109",
    "ccAddresses": [
        "bruce.wayne@university-of-education.zz"
    ],
    "clusterId": "pharmtech_hosted",
    "fromAddress": "badguy@evil.zz",
    "headerCC": "\"Bruce Wayne\" <bruce.wayne@university-of-education.zz>",
    "headerFrom": "\"A. Badguy\" <badguy@evil.zz>",
    "headerReplyTo": None,
    "headerTo": "\"Clark Kent\" <clark.kent@pharmtech.zz>; \"Diana Prince\" <diana.prince@pharmtech.zz>",
    "impostorScore": 0,
    "malwareScore": 100,
    "messageID": "2222@evil.zz",
    "threatsInfoMap": [
        {
            "campaignId": "46e01b8a-c899-404d-bcd9-189bb393d1a7",
            "classification": "MALWARE",
            "threat": "2fab740f143fc1aa4c1cd0146d334c5593b1428f6d062b2c406e5efe8abe95ca",
            "threatId": "2fab740f143fc1aa4c1cd0146d334c5593b1428f6d062b2c406e5efe8abe95ca",
            "threatStatus": "active",
            "threatTime": "2010-01-25T00:00:40.000Z",
            "threatType": "ATTACHMENT",
            "threatUrl": "https://threatinsight.proofpoint.com/43fc1aa4c1cd0146d334c5593b1428f6d062b2c406e5efe8abe95ca"
        },
        {
            "campaignId": "46e01b8a-c899-404d-bcd9-189bb393d1a7",
            "classification": "MALWARE",
            "threat": "badsite.zz",
            "threatId": "3ba97fc852c66a7ba761450edfdfb9f4ffab74715b591294f78b5e37a76481aa",
            "threatTime": "2010-01-25T00:00:30.000Z",
            "threatType": "URL",
            "threatUrl": "https://threatinsight.proofpoint.com/a7ba761450edfdfb9f4ffab74715b591294f78b5e37a76481aa"
        }
    ],
    "messageTime": "2010-01-25T00:00:10.000Z",
    "modulesRun": [
        "pdr",
        "sandbox",
        "spam",
        "urldefense"
    ],
    "phishScore": 46,
    "policyRoutes": [
        "default_inbound",
        "executives"
    ],
    "quarantineFolder": "Attachment Defense",
    "quarantineRule": "module.sandbox.threat",
    "recipient": [
        "clark.kent@pharmtech.zz",
        "diana.prince@pharmtech.zz"
    ],
    "replyToAddress": None,
    "sender": "e99d7ed5580193f36a51f597bc2c0210@evil.zz",
    "senderIP": "192.0.2.255",
    "spamScore": 4,
    "subject": "Please find a totally safe invoice attached."
}

MOCK_PERMITTED_CLICK = {
    "campaignId": "46e01b8a-c899-404d-bcd9-189bb393d1a7",
    "classification": "MALWARE",
    "clickIP": "192.0.2.1",
    "clickTime": "2010-01-11T00:00:20.000Z",
    "messageID": "3333",
    "recipient": "bruce.wayne@pharmtech.zz",
    "sender": "9facbf452def2d7efc5b5c48cdb837fa@badguy.zz",
    "senderIP": "192.0.2.255",
    "threatID": "61f7622167144dba5e3ae4480eeee78b23d66f7dfed970cfc3d086cc0dabdf50",
    "threatTime": "2010-01-11T00:00:10.000Z",
    "threatURL": "https://threatinsight.proofpoint.com/#/f7622167144dba5e3ae4480eeee78b23d66f7dfed970cfc3d086cc0dabdf50",
    "url": "http://badguy.zz/",
    "userAgent": "Mozilla/5.0(WindowsNT6.1;WOW64;rv:27.0)Gecko/20100101Firefox/27.0"
}

MOCK_BLOCKED_CLICK = {
    "campaignId": "46e01b8a-c899-404d-bcd9-189bb393d1a7",
    "classification": "MALWARE",
    "clickIP": "192.0.2.2",
    "clickTime": "2010-01-22T00:00:10.000Z",
    "messageID": "4444",
    "recipient": "bruce.wayne@pharmtech.zz",
    "sender": "9facbf452def2d7efc5b5c48cdb837fa@badguy.zz",
    "senderIP": "192.0.2.255",
    "threatID": "61f7622167144dba5e3ae4480eeee78b23d66f7dfed970cfc3d086cc0dabdf50",
    "threatTime": "2010-01-22T00:00:20.000Z",
    "threatURL": "https://threatinsight.proofpoint.com/#/f7622167144dba5e3ae4480eeee78b23d66f7dfed970cfc3d086cc0dabdf50",
    "url": "http://badguy.zz/",
    "userAgent": "Mozilla/5.0(WindowsNT6.1;WOW64;rv:27.0)Gecko/20100101Firefox/27.0"
}

MOCK_ISSUES = {
    "messagesDelivered": [
        MOCK_DELIVERED_MESSAGE
    ],
    "clicksPermitted": [
        MOCK_PERMITTED_CLICK
    ]
}

MOCK_ALL_EVENTS = {
    "messagesDelivered": [
        MOCK_DELIVERED_MESSAGE
    ],
    "clicksPermitted": [
        MOCK_PERMITTED_CLICK
    ],
    "clicksBlocked": [
        MOCK_BLOCKED_CLICK
    ],
    "messagesBlocked": [
        MOCK_BLOCKED_MESSAGE
    ]
}


def get_mocked_time():
    return datetime.strptime("2010-01-01T00:00:00Z", "%Y-%m-%dT%H:%M:%SZ")


def test_command(requests_mock):
    requests_mock.get(MOCK_URL + "/v2/siem/issues?format=json&sinceSeconds=100&threatType=url&threatType=attachment",
                      json=MOCK_ISSUES)

    client = Client(
        proofpoint_url=MOCK_URL,
        api_version="v2",
        service_principal="user1",
        secret="123",
        verify=False,
        proxies=None
    )

    args = {
        "threatType": "url,attachment",
        "sinceSeconds": "100",
        "eventTypes": ISSUES_EVENTS
    }
    _, outputs, _ = get_events_command(client, args)

    assert len(outputs["Proofpoint.MessagesDelivered(val.GUID == obj.GUID)"]) == 1
    assert len(outputs["Proofpoint.ClicksPermitted(val.GUID == obj.GUID)"]) == 1


def return_self(return_date):
    return return_date


def test_first_fetch_incidents(requests_mock, mocker):
    mocker.patch('ProofpointTAP_v2.get_now',
                 return_value=get_mocked_time())
    mocker.patch('ProofpointTAP_v2.parse_date_range', return_value=("2010-01-01T00:00:00Z", 'never mind'))
    requests_mock.get(
        MOCK_URL + '/v2/siem/all?format=json&interval=2010-01-01T00%3A00%3A00Z%2F2010-01-01T00%3A00%3A00Z',
        json=MOCK_ALL_EVENTS)

    client = Client(
        proofpoint_url=MOCK_URL,
        api_version="v2",
        service_principal="user1",
        secret="123",
        verify=False,
        proxies=None
    )

    next_run, incidents, _ = fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time="3 month",
        event_type_filter=ALL_EVENTS,
        threat_status="",
        threat_type=""
    )

    assert len(incidents) == 4
    assert json.loads(incidents[3]['rawJSON'])["messageID"] == "4444"


def test_next_fetch(requests_mock, mocker):
    mock_date = "2010-01-01T00:00:00Z"
    mocker.patch('ProofpointTAP_v2.get_now', return_value=datetime.strptime(mock_date, "%Y-%m-%dT%H:%M:%SZ"))
    requests_mock.get(MOCK_URL + '/v2/siem/all?format=json&interval=2010-01-01T00%3A00%3A00Z%'
                                 '2F2010-01-01T00%3A00%3A00Z&threatStatus=active&threatStatus=cleared',
                      json=MOCK_ALL_EVENTS)

    client = Client(
        proofpoint_url=MOCK_URL,
        api_version="v2",
        service_principal="user1",
        secret="123",
        verify=False,
        proxies=None
    )

    next_run, incidents, _ = fetch_incidents(
        client=client,
        last_run={"last_fetch": mock_date},
        first_fetch_time="3 month",
        event_type_filter=ALL_EVENTS,
        threat_status=["active", "cleared"],
        threat_type="",
        limit=50
    )

    assert len(incidents) == 4
    assert json.loads(incidents[3]['rawJSON'])["messageID"] == "4444"


def test_fetch_limit(requests_mock, mocker):
    mock_date = "2010-01-01T00:00:00Z"
    this_run = {"last_fetch": "2010-01-01T00:00:00Z"}
    mocker.patch('ProofpointTAP_v2.get_now', return_value=datetime.strptime(mock_date, "%Y-%m-%dT%H:%M:%SZ"))
    requests_mock.get(MOCK_URL + '/v2/siem/all', json=MOCK_ALL_EVENTS)

    client = Client(
        proofpoint_url=MOCK_URL,
        api_version="v2",
        service_principal="user1",
        secret="123",
        verify=False,
        proxies=None
    )

    next_run, incidents, remained = fetch_incidents(
        client=client,
        last_run=this_run,
        first_fetch_time="3 days",
        event_type_filter=ALL_EVENTS,
        threat_status=["active", "cleared"],
        threat_type="",
        limit=3
    )

    assert next_run['last_fetch'] == '2010-01-01T00:00:00Z'
    assert len(incidents) == 3
    assert len(remained) == 1
    # test another run
    next_run, incidents, remained = fetch_incidents(
        client=client,
        last_run=this_run,
        first_fetch_time="3 days",
        event_type_filter=ALL_EVENTS,
        threat_status=["active", "cleared"],
        threat_type="",
        limit=3,
        integration_context={'incidents': remained}
    )
    assert next_run['last_fetch'] == '2010-01-01T00:00:00Z'
    assert len(incidents) == 1
    assert not remained


FETCH_TIMES_MOCK = [
    ("2010-01-01T00:00:00Z", "2010-01-01T03:00:00Z", 5),
    ("2010-01-01T00:00:00Z", "2010-01-01T00:03:00Z", 2)
]


@pytest.mark.parametrize('mock_past, mock_now, expected', FETCH_TIMES_MOCK)
def test_get_fetch_times(mocker, mock_past, mock_now, expected):
    from ProofpointTAP_v2 import get_fetch_times
    mocker.patch('ProofpointTAP_v2.get_now', return_value=datetime.strptime(mock_now, "%Y-%m-%dT%H:%M:%SZ"))
    times = get_fetch_times(mock_past)
    assert len(times) == expected
