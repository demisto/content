import json
import pytest
from datetime import datetime
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
            "threat": "threat_num",
            "threatId": "threat_num",
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
    "subject": "Please find a totally safe invoice attached.",
    "toAddresses": "xx@xxx.com",
    "xmailer": None
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
            "threat": "threat_num",
            "threatId": "threat_num",
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
    "subject": "Please find a totally safe invoice attached.",
    "toAddresses": "xx@xxx.com",
    "xmailer": None

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
    "threatID": "threat_num2",
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
    "threatID": "threat_num2",
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


def test_fetch_incidents_with_encoding(requests_mock, mocker):
    """
    Given:
        - Message with latin chars in its subject
        - Raw JSON encoding param set to latin-1

    When:
        - Running fetch incidents

    Then:
        - Ensure subject is returned properly in the raw JSON
    """
    mocker.patch(
        'ProofpointTAP_v2.get_now',
        return_value=get_mocked_time()
    )
    mocker.patch(
        'ProofpointTAP_v2.parse_date_range',
        return_value=("2010-01-01T00:00:00Z", 'never mind')
    )
    requests_mock.get(
        MOCK_URL + '/v2/siem/all?format=json&interval=2010-01-01T00%3A00%3A00Z%2F2010-01-01T00%3A00%3A00Z',
        json={
            "messagesDelivered": [
                {
                    'subject': 'p\u00c3\u00a9rdida',
                    'messageTime': '2010-01-30T00:00:59.000Z',
                },
            ],
        },
    )

    client = Client(
        proofpoint_url=MOCK_URL,
        api_version='v2',
        service_principal='user1',
        secret='123',
        verify=False,
        proxies=None,
    )

    _, incidents, _ = fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time='3 month',
        event_type_filter=ALL_EVENTS,
        threat_status='',
        threat_type='',
        raw_json_encoding='latin-1',
    )

    assert json.loads(incidents[0]['rawJSON'])['subject'] == 'pérdida'


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


class TestGetForensics:
    PLATFORMS_OBJECT = [
        {
            "name": "windows 7 sp1",
            "os": "windows 7",
            "version": "4.5.661",
        }
    ]
    EVIDENCE_OBJECT_URL = {
        "type": "url",
        "display": "string",
        "time": "string",
        "malicious": "string",
        "what": {
            "url": "string",
            "blacklisted": "boolean",
            "ip": "string",
            "httpStatus": "string",
            "md5": "string",
            "offset": "integer",
            "rule": "string",
            "sha256": "string",
            "size": "integer",
        },
        "platforms": PLATFORMS_OBJECT
    }
    EVIDENCE_OBJECT_REGISTRY = {
        "type": "registry",
        "display": "string",
        "time": "string",
        "malicious": "string",
        "what": {
            "action": "string",
            "key": "string",
            "name": "string",
            "rule": "string",
            "value": "string",
        },
        "platforms": PLATFORMS_OBJECT
    }
    EVIDENCE_OBJECT_PROCESS = {
        "type": "process",
        "display": "string",
        "time": "string",
        "malicious": "string",
        "what": {
            "action": "string",
            "path": "string",
        },
        "platforms": PLATFORMS_OBJECT
    }
    EVIDENCE_OBJECT_NETWORK = {
        "type": "network",
        "display": "string",
        "time": "string",
        "malicious": "string",
        "what": {
            "action": "string",
            "ip": "string",
            "port": "string",
            "type": "string",
        },
        "platforms": PLATFORMS_OBJECT
    }
    EVIDENCE_OBJECT_MUTEX = {
        "type": "mutex",
        "display": "string",
        "time": "string",
        "malicious": "string",
        "what": {
            "name": "string",
            "path": "string",
        },
        "platforms": PLATFORMS_OBJECT
    }
    EVIDENCE_OBJECT_IDS = {
        "type": "ids",
        "display": "string",
        "time": "string",
        "malicious": "string",
        "what": {
            "name": "string",
            "signatureId": "integer",
        },
        "platforms": PLATFORMS_OBJECT
    }
    EVIDENCE_OBJECT_FILE = {
        "type": "file",
        "display": "string",
        "time": "string",
        "malicious": "string",
        "what": {
            "action": "string",
            "md5": "string",
            "path": "string",
            "rule": "string",
            "sha256": "string",
            "size": "integer"
        },
        "platforms": PLATFORMS_OBJECT
    }
    EVIDENCE_OBJECT_DROPPER = {
        "type": "dropper",
        "display": "string",
        "time": "string",
        "malicious": "string",
        "what": {
            "path": "string",
            "rule": "string",
            "url": "string"
        },
        "platforms": PLATFORMS_OBJECT
    }
    EVIDENCE_OBJECT_DNS = {
        "type": "dns",
        "display": "string",
        "time": "string",
        "malicious": "string",
        "what": {
            "host": "string",
            "cnames": ["string1", "string2"],
            "ips": ["string1", "string2"],
            "nameservers": ["string1", "string2"],
            "nameserversList": ["string1", "string2"]
        },
        "platforms": PLATFORMS_OBJECT
    }
    EVIDENCE_OBJECT_COOKIE = {
        "type": "cookie",
        "display": "string",
        "time": "string",
        "malicious": "string",
        "what": {
            "action": "string",
            "domain": "string",
            "key": "string",
            "value": "string"
        },
        "platforms": PLATFORMS_OBJECT
    }
    EVIDENCE_OBJECT_ATTACHMENT = {
        "type": "attachment",
        "display": "string",
        "time": "string",
        "malicious": "string",
        "what": {
            "sha256": "string",
            "md5": "string",
            "offset": "integer",
            "rule": "string",
            "size": "integer"
        },
        "platforms": PLATFORMS_OBJECT
    }
    EVIDENCE_LIST = [
        EVIDENCE_OBJECT_ATTACHMENT,
        EVIDENCE_OBJECT_COOKIE,
        EVIDENCE_OBJECT_DNS,
        EVIDENCE_OBJECT_DROPPER,
        EVIDENCE_OBJECT_FILE,
        EVIDENCE_OBJECT_IDS,
        EVIDENCE_OBJECT_MUTEX,
        EVIDENCE_OBJECT_NETWORK,
        EVIDENCE_OBJECT_PROCESS,
        EVIDENCE_OBJECT_REGISTRY,
        EVIDENCE_OBJECT_URL,
    ]
    REPORT_OBJECT = [{
        'name': 'string',
        'scope': 'string',
        'type': 'string',
        'id': 'string',
        'forensics': EVIDENCE_LIST,
    }]

    REPORT = {
        'generated': 'string',
        'reports': REPORT_OBJECT * 2,
    }

    FORENSICS_REPORT = {
        "Scope": "string",
        "Type": "string",
        "ID": "string",
        "Attachment": [
            {
                "Time": "string",
                "Display": "string",
                "Malicious": "string",
                "Platform": [
                    {
                        "Name": "windows 7 sp1",
                        "OS": "windows 7",
                        "Version": "4.5.661"
                    }
                ],
                "SHA256": "string",
                "MD5": "string",
                "Offset": "integer",
                "Size": "integer"
            }
        ],
        "Cookie": [
            {
                "Time": "string",
                "Display": "string",
                "Malicious": "string",
                "Platform": [
                    {
                        "Name": "windows 7 sp1",
                        "OS": "windows 7",
                        "Version": "4.5.661"
                    }
                ],
                "Action": "string",
                "Domain": "string",
                "Key": "string",
                "Value": "string"
            }
        ],
        "DNS": [
            {
                "Time": "string",
                "Display": "string",
                "Malicious": "string",
                "Platform": [
                    {
                        "Name": "windows 7 sp1",
                        "OS": "windows 7",
                        "Version": "4.5.661"
                    }
                ],
                "Host": "string",
                "CNames": [
                    "string1",
                    "string2"
                ],
                "IP": [
                    "string1",
                    "string2"
                ],
                "NameServers": [
                    "string1",
                    "string2"
                ],
                "NameServersList": [
                    "string1",
                    "string2"
                ]
            }
        ],
        "Dropper": [
            {
                "Time": "string",
                "Display": "string",
                "Malicious": "string",
                "Platform": [
                    {
                        "Name": "windows 7 sp1",
                        "OS": "windows 7",
                        "Version": "4.5.661"
                    }
                ],
                "Path": "string",
                "URL": "string",
                "Rule": "string"
            }
        ],
        "File": [
            {
                "Time": "string",
                "Display": "string",
                "Malicious": "string",
                "Platform": [
                    {
                        "Name": "windows 7 sp1",
                        "OS": "windows 7",
                        "Version": "4.5.661"
                    }
                ],
                "Path": "string",
                "Action": "string",
                "SHA256": "string",
                "MD5": "string",
                "Size": "integer"
            }
        ],
        "IDS": [
            {
                "Time": "string",
                "Display": "string",
                "Malicious": "string",
                "Platform": [
                    {
                        "Name": "windows 7 sp1",
                        "OS": "windows 7",
                        "Version": "4.5.661"
                    }
                ],
                "Name": "string",
                "SignatureID": "integer"
            }
        ],
        "Mutex": [
            {
                "Time": "string",
                "Display": "string",
                "Malicious": "string",
                "Platform": [
                    {
                        "Name": "windows 7 sp1",
                        "OS": "windows 7",
                        "Version": "4.5.661"
                    }
                ],
                "Name": "string",
                "Path": "string"
            }
        ],
        "Network": [
            {
                "Time": "string",
                "Display": "string",
                "Malicious": "string",
                "Platform": [
                    {
                        "Name": "windows 7 sp1",
                        "OS": "windows 7",
                        "Version": "4.5.661"
                    }
                ],
                "Action": "string",
                "IP": "string",
                "Port": "string",
                "Protocol": "string"
            }
        ],
        "Process": [
            {
                "Time": "string",
                "Display": "string",
                "Malicious": "string",
                "Platform": [
                    {
                        "Name": "windows 7 sp1",
                        "OS": "windows 7",
                        "Version": "4.5.661"
                    }
                ],
                "Action": "string",
                "Path": "string"
            }
        ],
        "Registry": [
            {
                "Time": "string",
                "Display": "string",
                "Malicious": "string",
                "Platform": [
                    {
                        "Name": "windows 7 sp1",
                        "OS": "windows 7",
                        "Version": "4.5.661"
                    }
                ],
                "Name": "string",
                "Action": "string",
                "Key": "string",
                "Value": "string"
            }
        ],
        "URL": [
            {
                "Time": "string",
                "Display": "string",
                "Malicious": "string",
                "Platform": [
                    {
                        "Name": "windows 7 sp1",
                        "OS": "windows 7",
                        "Version": "4.5.661"
                    }
                ],
                "URL": "string",
                "Blacklisted": "boolean",
                "SHA256": "string",
                "MD5": "string",
                "Size": "integer",
                "HTTPStatus": "string",
                "IP": "string"
            }
        ]
    }

    client = Client(
        proofpoint_url=MOCK_URL,
        api_version="v2",
        service_principal="user1",
        secret="123",
        verify=False,
        proxies=None
    )

    def test_get_forensics(self, requests_mock):
        from ProofpointTAP_v2 import get_forensic_command
        requests_mock.get('http://123-fake-api.com/v2/forensics?threatId=1256', json=self.REPORT)
        _, output, _ = get_forensic_command(self.client, {'threatId': '1256'})
        reports = output['Proofpoint.Report(var.ID === obj.ID)']
        assert len(reports) == 2
        report = reports[0]
        assert all(report)
        assert self.FORENSICS_REPORT == report


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.

    Args:
        file_name (str): Name of the mock response JSON file to return.

    Returns:
        str: Mock file content.

    """
    with open(f'test_data/{file_name}', mode='r', encoding='utf-8') as mock_file:
        return mock_file.read()


def test_get_clicks_command(requests_mock):
    """
        Scenario: Retrieves clicks to malicious URLs blocked and permitted in the specified time period.
        Given:
         - User has provided valid credentials and arguments.
        When:
         - A get-clicks command is called and there is clicks in the response.
        Then:
         - Ensure number of items is correct.
         - Ensure outputs prefix is correct.
         - Ensure a sample value from the API matches what is generated in the context.

    """
    from ProofpointTAP_v2 import Client, get_clicks_command
    requests_mock.get(f'{MOCK_URL}/v2/siem/clicks/blocked',
                      json={'queryEndTime': '2021-03-23T14:00:00Z', 'clicksBlocked': [MOCK_BLOCKED_CLICK]})
    requests_mock.get(f'{MOCK_URL}/v2/siem/clicks/permitted',
                      json={'queryEndTime': '2021-03-23T14:00:00Z', 'clicksPermitted': [MOCK_PERMITTED_CLICK]})

    client = Client(
        proofpoint_url=MOCK_URL,
        api_version="v2",
        service_principal="user1",
        secret="123",
        verify=False,
        proxies=None
    )
    blocked_result = get_clicks_command(client, True, "3 days")
    permitted_result = get_clicks_command(client, False, "3 days")
    assert len(blocked_result.outputs) == 1
    assert blocked_result.outputs_prefix == 'Proofpoint.ClicksBlocked'
    assert blocked_result.outputs[0].get('messageID') == '4444'
    assert len(permitted_result.outputs) == 1
    assert permitted_result.outputs_prefix == 'Proofpoint.ClicksPermitted'
    assert permitted_result.outputs[0].get('messageID') == '3333'


def test_get_messages_command(requests_mock):
    """
        Scenario: Retrieves messages to malicious URLs blocked and delivered in the specified time period.
        Given:
         - User has provided valid credentials and arguments.
        When:
         - A get-messages command is called and there is messages in the response.
        Then:
         - Ensure number of items is correct.
         - Ensure outputs prefix is correct.
         - Ensure a sample value from the API matches what is generated in the context.

    """
    from ProofpointTAP_v2 import Client, get_messages_command
    requests_mock.get(f'{MOCK_URL}/v2/siem/messages/blocked',
                      json={'queryEndTime': '2021-03-23T14:00:00Z', 'messagesBlocked': [MOCK_BLOCKED_MESSAGE]})
    requests_mock.get(f'{MOCK_URL}/v2/siem/messages/delivered',
                      json={'queryEndTime': '2021-03-23T14:00:00Z', 'messagesDelivered': [MOCK_DELIVERED_MESSAGE]})

    client = Client(
        proofpoint_url=MOCK_URL,
        api_version="v2",
        service_principal="user1",
        secret="123",
        verify=False,
        proxies=None
    )
    blocked_result = get_messages_command(client, True, "3 days")
    delivered_result = get_messages_command(client, False, "3 days")
    assert len(blocked_result.outputs) == 1
    assert blocked_result.outputs_prefix == 'Proofpoint.MessagesBlocked'
    assert blocked_result.outputs[0].get('messageID') == "2222@evil.zz"
    assert len(delivered_result.outputs) == 1
    assert delivered_result.outputs_prefix == 'Proofpoint.MessagesDelivered'
    assert delivered_result.outputs[0].get('messageID') == "1111@evil.zz"


def test_list_campaigns_command(requests_mock):
    """
        Scenario: Retrieves a list of IDs of campaigns active in a time window.
        Given:
         - User has provided valid credentials.
        When:
         - A list-campaign-ids command is called and there is campaigns in the response.
        Then:
         - Ensure number of items is correct.
         - Ensure outputs prefix is correct.
         - Ensure a sample value from the API matches what is generated in the context.

    """
    from ProofpointTAP_v2 import Client, list_campaigns_command
    mock_response = json.loads(load_mock_response('campaigns.json'))
    requests_mock.get(f'{MOCK_URL}/v2/campaign/ids', json=mock_response)
    client = Client(
        proofpoint_url=MOCK_URL,
        api_version="v2",
        service_principal="user1",
        secret="123",
        verify=False,
        proxies=None
    )
    result = list_campaigns_command(client, "3 days")
    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'Proofpoint.Campaign'
    assert result.outputs[0].get('id') == "f3ff0874-85ef-475e-b3fe-d05f97b2ed3f"
    assert result.outputs[0].get('lastUpdatedAt') == "2021-03-25T10:37:46.000Z"


def test_get_campaign(requests_mock):
    """
        Scenario: Retrieves information for a given campaign.
        Given:
         - User has provided valid credentials and argument.
        When:
         - A get-campaign command is called and there is a campaign in the response.
        Then:
         - Ensure number of items is correct.
         - Ensure outputs prefix is correct.
         - Ensure a sample value from the API matches what is generated in the context.

    """
    from ProofpointTAP_v2 import Client, get_campaign_command
    mock_response = json.loads(load_mock_response('campaign_information.json'))
    requests_mock.get(f'{MOCK_URL}/v2/campaign/1', json=mock_response)
    client = Client(
        proofpoint_url=MOCK_URL,
        api_version="v2",
        service_principal="user1",
        secret="123",
        verify=False,
        proxies=None
    )
    result = get_campaign_command(client, "1")
    assert len(result.outputs) == 7
    assert result.outputs_prefix == 'Proofpoint.Campaign'
    assert result.outputs.get('info').get('id') == "aa9b3d62-4d72-4ebc-8f39-3da3833e7038"


def test_list_most_attacked_users_command(requests_mock):
    """
        Scenario: Retrieves a list of the most attacked users in the organization for a given period.
        Given:
         - User has provided valid credentials and argument.
        When:
         - A get-vap command is called and there is a attacked people in the response.
        Then:
         - Ensure number of items is correct.
         - Ensure outputs prefix is correct.
         - Ensure a sample value from the API matches what is generated in the context.

    """
    from ProofpointTAP_v2 import Client, list_most_attacked_users_command
    mock_response = json.loads(load_mock_response('most_attacked_users.json'))
    requests_mock.get(f'{MOCK_URL}/v2/people/vap', json=mock_response)
    client = Client(
        proofpoint_url=MOCK_URL,
        api_version="v2",
        service_principal="user1",
        secret="123",
        verify=False,
        proxies=None
    )
    result = list_most_attacked_users_command(client, "")
    assert len(result.outputs) == 5
    assert result.outputs_prefix == 'Proofpoint.Vap'
    assert result.outputs.get('users')[0].get('identity').get('guid') == "88e36bf359-99e8-7e53-f58a-6df8b430be6d"
    assert result.outputs.get('totalVapUsers') == 2


def test_get_top_clickers_command(requests_mock):
    """
        Scenario: Retrieves a list of the top clickers in the organization for a given period.
        Given:
         - User has provided valid credentials and argument.
        When:
         - A get_top_clickers command is called and there is clickers in the response.
        Then:
         - Ensure number of items is correct.
         - Ensure outputs prefix is correct.
         - Ensure a sample value from the API matches what is generated in the context.

    """
    from ProofpointTAP_v2 import Client, get_top_clickers_command
    mock_response = json.loads(load_mock_response('top_clickers.json'))
    requests_mock.get(f'{MOCK_URL}/v2/people/top-clickers', json=mock_response)
    client = Client(
        proofpoint_url=MOCK_URL,
        api_version="v2",
        service_principal="user1",
        secret="123",
        verify=False,
        proxies=None
    )
    result = get_top_clickers_command(client, "")
    assert len(result.outputs) == 3
    assert result.outputs_prefix == 'Proofpoint.Topclickers'
    assert result.outputs.get('users')[1].get('identity').get('guid') == "b4077fsv0e-3a2e-767f-7315-c049f831cc95"
    assert result.outputs.get('totalTopClickers') == 2


def test_url_decode(requests_mock):
    """
        Scenario: Decode URLs that have been rewritten by TAP to their original, target URL.
        Given:
         - User has provided valid credentials and arguments.
        When:
         - A url-decode command is called.
        Then:
         - Ensure number of items is correct.
         - Ensure outputs prefix is correct.
         - Ensure a sample value from the API matches what is generated in the context.

    """
    from ProofpointTAP_v2 import Client, url_decode_command
    mock_response = json.loads(load_mock_response('url_decode.json'))
    requests_mock.post(f'{MOCK_URL}/v2/url/decode', json=mock_response)
    client = Client(
        proofpoint_url=MOCK_URL,
        api_version="v2",
        service_principal="user1",
        secret="123",
        verify=False,
        proxies=None
    )
    result = url_decode_command(client, "")
    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'Proofpoint.URL'
    assert result.outputs[1].get('decodedUrl') == "http://www.bouncycastle.org/"


def test_list_issues_command(requests_mock):
    """
        Scenario: Retrieves events for clicks to malicious URLs permitted and messages delivered in the specified time period.
        Given:
         - User has provided valid credentials and arguments.
        When:
         - A list_issues command is called and there is clicks and messages in the response.
        Then:
         - Ensure number of items is correct.
         - Ensure outputs prefix is correct.
         - Ensure a sample value from the API matches what is generated in the context.

    """
    from ProofpointTAP_v2 import Client, list_issues_command
    requests_mock.get(f'{MOCK_URL}/v2/siem/issues',
                      json={"queryEndTime": "2021-04-16T14:00:00Z", "messagesDelivered": [MOCK_DELIVERED_MESSAGE],
                            "clicksPermitted": [MOCK_PERMITTED_CLICK]})
    client = Client(
        proofpoint_url=MOCK_URL,
        api_version="v2",
        service_principal="user1",
        secret="123",
        verify=False,
        proxies=None
    )
    result = list_issues_command(client, "3 days")
    messages_result = result[0]
    clicks_result = result[1]

    assert len(clicks_result.outputs) == 1
    assert clicks_result.outputs_prefix == 'Proofpoint.ClicksPermitted'
    assert clicks_result.outputs[0].get('messageID') == '3333'

    assert len(messages_result.outputs) == 1
    assert messages_result.outputs_prefix == 'Proofpoint.MessagesDelivered'
    assert messages_result.outputs[0].get('messageID') == "1111@evil.zz"
