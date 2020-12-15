import pytest
from PaloAltoNetworks_PrismaCloudCompute import Client, camel_case_transformer, fetch_incidents, get_headers, \
    HEADERS_BY_NAME

from CommonServerPython import DemistoException


def test_camel_case_transformer(requests_mock):
    test_strings = ['camelCase', 'camelCaSe', 'camelCaseString', 'camelcase', 'CAMELCASE', 'cve', 'id', 4]
    expected_results = ['Camel Case', 'Camel Ca Se', 'Camel Case String', 'Camelcase', 'Camelcase', 'CVE', 'ID', '4']

    results = []
    for string in test_strings:
        results.append(camel_case_transformer(string))

    assert results == expected_results


def test_api_fallback(requests_mock):
    test_url = 'https://test.com'
    xsoar_endpoint = test_url + '/xsoar-alerts'
    demisto_endpoint = test_url + '/demisto-alerts'
    test_response = {'foo': 'bar'}
    client = Client(base_url=test_url, verify='False', project='', auth=('test', 'test'))

    # Validate new API
    requests_mock.get(xsoar_endpoint, json=test_response)
    assert client.list_incidents() == test_response

    # Validate fallback to previous API (backward compatibility)
    requests_mock.get(xsoar_endpoint, status_code=404)
    requests_mock.get(demisto_endpoint, json=test_response)
    assert client.list_incidents() == test_response

    # Validate error from new API is returned without fallback
    requests_mock.get(xsoar_endpoint, status_code=500)
    with pytest.raises(DemistoException, match='500'):
        client.list_incidents()

    # Validate error on previous API
    requests_mock.get(xsoar_endpoint, status_code=404)
    requests_mock.get(demisto_endpoint, status_code=504)
    with pytest.raises(DemistoException, match='504'):
        client.list_incidents()


def test_fetch_incidents(requests_mock):
    json_incidents_mock_response = [
        {
            "_id": "5e170534776710d48a0812f5",
            "activityType": "",
            "appID": "",
            "category": "customRule",
            "command": "",
            "container": "",
            "forensicLink": "",
            "fqdn": "devbox",
            "function": "",
            "host": "devbox",
            "image": "",
            "interactive": False,
            "kind": "audit",
            "kubernetesResource": "",
            "labels": {},
            "line": "",
            "logfile": "",
            "message": "unexpected ls was spawned",
            "region": "",
            "rule": "koko",
            "runtime": "",
            "service": "",
            "time": "2020-01-09T10:49:24.675Z",
            "type": "hostRuntime",
            "user": ""
        },
        {
            "_id": "5e170535776710d48a0812ff",
            "activityType": "",
            "appID": "",
            "category": "customRule",
            "command": "",
            "container": "",
            "forensicLink": "https://test.com",
            "fqdn": "devbox",
            "function": "",
            "host": "devbox",
            "image": "",
            "interactive": False,
            "kind": "audit",
            "kubernetesResource": "",
            "labels": {},
            "line": "",
            "logfile": "",
            "message": "Audit #1: unexpected ls was spawned\n\n",
            "region": "",
            "rule": "",
            "runtime": "",
            "service": "",
            "time": "2020-01-09T10:49:24.675Z",
            "type": "incident",
            "user": ""
        },
        {
            "_id": "5e170560776710d48a081321",
            "accountID": "123456789",
            "credentialId": "koko",
            "entities": [
                {
                    "arn": "arn:aws:ecr:us-east-1:123456789:repository/test1",
                    "createdAt": "2018-08-09T07:11:12Z",
                    "name": "test1",
                    "protected": True
                },
                {
                    "arn": "arn:aws:ecr:us-east-1:123456789:repository/test2",
                    "createdAt": "2018-11-11T19:25:40Z",
                    "name": "test2",
                    "protected": False
                },
                {
                    "arn": "arn:aws:ecr:us-east-1:123456789:repository/test3",
                    "createdAt": "2018-08-02T10:43:24Z",
                    "name": "test3",
                    "protected": True
                },
                {
                    "arn": "arn:aws:ecr:us-east-1:123456789:repository/test4",
                    "createdAt": "2019-03-05T10:53:07Z",
                    "name": "test4",
                    "protected": False,
                    "test": "testing",
                },
            ],
            "kind": "cloudDiscovery",
            "protected": 0,
            "provider": "aws",
            "region": "us-east-1",
            "registry": "123456789.dkr.ecr.us-east-1.amazonaws.com",
            "serviceType": "aws-ecr",
            "time": "2020-01-09T10:50:08.115Z",
            "total": 4
        },
        {
            "_id": "5e1705ef776710d48a0813b4",
            "compliance": [
                {
                    "description": "(CIS_Docker_CE_v1.1.0 - 5.28) Use PIDs cgroup limit",
                    "id": "528",
                    "type": "container"
                },
                {
                    "description": "(CIS_Docker_CE_v1.1.0 - 5.25) Restrict container from acquiring additional "
                                   "privileges",
                    "id": "525",
                    "type": "container"
                },
                {
                    "description": "(CIS_Docker_CE_v1.1.0 - 5.9) Do not share the host's network namespace",
                    "id": "59",
                    "type": "container"
                },
            ],
            "kind": "compliance",
            "time": "2020-01-09T10:52:31.185Z",
            "type": "container"
        },
        {
            "_id": "5e1705ef776710d48a0813b5",
            "compliance": [
                {
                    "description": "(CIS_Docker_CE_v1.1.0 - 4.1) Image should be created with a non-root user",
                    "id": "41",
                    "type": "image"
                }
            ],
            "kind": "compliance",
            "time": "2020-01-09T10:52:31.185Z",
            "type": "image"
        },
        {
            "_id": "5e170623776710d48a081440",
            "distroName": "BusyBox 1.21.1",
            "imageName": "library/alpine:2.6",
            "kind": "vulnerability",
            "labels": {},
            "time": "2020-01-09T10:53:23.865Z",
            "vulnerabilities": [
                {
                    "cve": "CVE-2019-5747",
                    "link": "https://test.com",
                    "packageVersion": "1.21.1",
                    "packages": "busybox",
                    "severity": "high",
                    "sourcePackage": "",
                    "status": ""
                },
                {
                    "cve": "CVE-2017-16544",
                    "link": "https://test.com",
                    "packageVersion": "1.21.1",
                    "packages": "busybox",
                    "severity": "high",
                    "sourcePackage": "",
                    "status": ""
                },
                {
                    "cve": "CVE-2016-2147",
                    "link": "https://test.com",
                    "packageVersion": "1.21.1",
                    "packages": "busybox",
                    "severity": "high",
                    "sourcePackage": "",
                    "status": "fixed in 1.25.0"
                },
                {
                    "cve": "ALAS-2018-1065",
                    "link": "",
                    "packageVersion": "1.0.1m-r0",
                    "packages": "libcrypto1.0",
                    "severity": "medium",
                    "sourcePackage": "openssl",
                    "status": "fixed in 1.0.2k-12.110.amzn1"
                },
                {
                    "cve": "ALAS-2019-1188",
                    "link": "",
                    "packageVersion": "1.0.1m-r0",
                    "packages": "libcrypto1.0",
                    "severity": "medium",
                    "sourcePackage": "openssl",
                    "status": "fixed in 1.0.2k-16.150.amzn1"
                }
            ]
        }
    ]

    expected_incidents = [
        {'name': 'Prisma Cloud Compute Alert - Host Runtime Audit', 'occurred': '2020-01-09T10:49:24.675Z',
         'severity': 0,
         'rawJSON': '{"_id": "5e170534776710d48a0812f5", "activityType": "", "appID": "", "category": "Custom Rule", '
                    '"command": "", "container": "", "forensicLink": "", "fqdn": "devbox", "function": "", '
                    '"host": "devbox", "image": "", "interactive": false, "kind": "audit", "kubernetesResource": "", '
                    '"labels": {}, "line": "", "logfile": "", "message": "unexpected ls was spawned", "region": "", '
                    '"rule": "koko", "runtime": "", "service": "", "time": "2020-01-09T10:49:24.675Z", '
                    '"type": "hostRuntime", "user": "", "rawJSONAlert": "{\\"_id\\": \\"5e170534776710d48a0812f5\\", '
                    '\\"activityType\\": \\"\\", \\"appID\\": \\"\\", \\"category\\": \\"Custom Rule\\", '
                    '\\"command\\": \\"\\", \\"container\\": \\"\\", \\"forensicLink\\": \\"\\", \\"fqdn\\": '
                    '\\"devbox\\", \\"function\\": \\"\\", \\"host\\": \\"devbox\\", \\"image\\": \\"\\", '
                    '\\"interactive\\": false, \\"kind\\": \\"audit\\", \\"kubernetesResource\\": \\"\\", '
                    '\\"labels\\": {}, \\"line\\": \\"\\", \\"logfile\\": \\"\\", \\"message\\": \\"unexpected ls was '
                    'spawned\\", \\"region\\": \\"\\", \\"rule\\": \\"koko\\", \\"runtime\\": \\"\\", \\"service\\": '
                    '\\"\\", \\"time\\": \\"2020-01-09T10:49:24.675Z\\", \\"type\\": \\"hostRuntime\\", \\"user\\": '
                    '\\"\\"}"}'},
        {'name': 'Prisma Cloud Compute Alert - Incident', 'occurred': '2020-01-09T10:49:24.675Z', 'severity': 0,
         'rawJSON': '{"_id": "5e170535776710d48a0812ff", "activityType": "", "appID": "", "category": "Custom Rule", '
                    '"command": "", "container": "", "forensicLink": "https://test.com", "fqdn": "devbox", '
                    '"function": "", "host": "devbox", "image": "", "interactive": false, "kind": "audit", '
                    '"kubernetesResource": "", "labels": {}, "line": "", "logfile": "", "message": "Audit #1: '
                    'unexpected ls was spawned\\n\\n", "region": "", "rule": "", "runtime": "", "service": "", '
                    '"time": "2020-01-09T10:49:24.675Z", "type": "incident", "user": "", "rawJSONAlert": "{\\"_id\\": '
                    '\\"5e170535776710d48a0812ff\\", \\"activityType\\": \\"\\", \\"appID\\": \\"\\", \\"category\\": '
                    '\\"Custom Rule\\", \\"command\\": \\"\\", \\"container\\": \\"\\", \\"forensicLink\\": '
                    '\\"https://test.com\\", \\"fqdn\\": \\"devbox\\", \\"function\\": \\"\\", \\"host\\": '
                    '\\"devbox\\", \\"image\\": \\"\\", \\"interactive\\": false, \\"kind\\": \\"audit\\", '
                    '\\"kubernetesResource\\": \\"\\", \\"labels\\": {}, \\"line\\": \\"\\", \\"logfile\\": \\"\\", '
                    '\\"message\\": \\"Audit #1: unexpected ls was spawned\\\\n\\\\n\\", \\"region\\": \\"\\", '
                    '\\"rule\\": \\"\\", \\"runtime\\": \\"\\", \\"service\\": \\"\\", \\"time\\": '
                    '\\"2020-01-09T10:49:24.675Z\\", \\"type\\": \\"incident\\", \\"user\\": \\"\\"}"}'},
        {'name': 'Prisma Cloud Compute Alert - Cloud Discovery', 'occurred': '2020-01-09T10:50:08.115Z', 'severity': 0,
         'rawJSON': '{"_id": "5e170560776710d48a081321", "accountID": "123456789", "credentialId": "koko", '
                    '"entities": [{"arn": "arn:aws:ecr:us-east-1:123456789:repository/test1", "createdAt": '
                    '"2018-08-09T07:11:12Z", "name": "test1", "protected": true}, '
                    '{"arn": "arn:aws:ecr:us-east-1:123456789:repository/test2", "createdAt": "2018-11-11T19:25:40Z", '
                    '"name": "test2", "protected": false}, {"arn": '
                    '"arn:aws:ecr:us-east-1:123456789:repository/test3", "createdAt": "2018-08-02T10:43:24Z", '
                    '"name": "test3", "protected": true}, {"arn": "arn:aws:ecr:us-east-1:123456789:repository/test4", '
                    '"createdAt": "2019-03-05T10:53:07Z", "name": "test4", "protected": false, "test": "testing"}], '
                    '"kind": "cloudDiscovery", "protected": 0, "provider": "aws", "region": "us-east-1", "registry": '
                    '"123456789.dkr.ecr.us-east-1.amazonaws.com", "serviceType": "aws-ecr", '
                    '"time": "2020-01-09T10:50:08.115Z", "total": 4, "rawJSONAlert": "{\\"_id\\": '
                    '\\"5e170560776710d48a081321\\", \\"accountID\\": \\"123456789\\", \\"credentialId\\": '
                    '\\"koko\\", \\"entities\\": [{\\"arn\\": \\"arn:aws:ecr:us-east-1:123456789:repository/test1\\", '
                    '\\"createdAt\\": \\"2018-08-09T07:11:12Z\\", \\"name\\": \\"test1\\", \\"protected\\": true}, '
                    '{\\"arn\\": \\"arn:aws:ecr:us-east-1:123456789:repository/test2\\", \\"createdAt\\": '
                    '\\"2018-11-11T19:25:40Z\\", \\"name\\": \\"test2\\", \\"protected\\": false}, {\\"arn\\": '
                    '\\"arn:aws:ecr:us-east-1:123456789:repository/test3\\", \\"createdAt\\": '
                    '\\"2018-08-02T10:43:24Z\\", \\"name\\": \\"test3\\", \\"protected\\": true}, {\\"arn\\": '
                    '\\"arn:aws:ecr:us-east-1:123456789:repository/test4\\", \\"createdAt\\": '
                    '\\"2019-03-05T10:53:07Z\\", \\"name\\": \\"test4\\", \\"protected\\": false, \\"test\\": '
                    '\\"testing\\"}], \\"kind\\": \\"cloudDiscovery\\", \\"protected\\": 0, \\"provider\\": '
                    '\\"aws\\", \\"region\\": \\"us-east-1\\", \\"registry\\": '
                    '\\"123456789.dkr.ecr.us-east-1.amazonaws.com\\", \\"serviceType\\": \\"aws-ecr\\", \\"time\\": '
                    '\\"2020-01-09T10:50:08.115Z\\", \\"total\\": 4}", "entitiesMarkdownTable": "### Entities '
                    'Table\\n|Name|Created At|ARN|Protected|Test|\\n|---|---|---|---|---|\\n| test1 | '
                    '2018-08-09T07:11:12Z | arn:aws:ecr:us-east-1:123456789:repository/test1 | true |  |\\n| test2 | '
                    '2018-11-11T19:25:40Z | arn:aws:ecr:us-east-1:123456789:repository/test2 | false |  |\\n| test3 | '
                    '2018-08-02T10:43:24Z | arn:aws:ecr:us-east-1:123456789:repository/test3 | true |  |\\n| test4 | '
                    '2019-03-05T10:53:07Z | arn:aws:ecr:us-east-1:123456789:repository/test4 | false | testing '
                    '|\\n"}'},
        {'name': 'Prisma Cloud Compute Alert - Container Compliance', 'occurred': '2020-01-09T10:52:31.185Z',
         'severity': 0,
         'rawJSON': '{"_id": "5e1705ef776710d48a0813b4", "compliance": [{"description": "(CIS_Docker_CE_v1.1.0 - '
                    '5.28) Use PIDs cgroup limit", "id": "528", "type": "container"}, {"description": "('
                    'CIS_Docker_CE_v1.1.0 - 5.25) Restrict container from acquiring additional privileges", '
                    '"id": "525", "type": "container"}, {"description": "(CIS_Docker_CE_v1.1.0 - 5.9) Do not share '
                    'the host\'s network namespace", "id": "59", "type": "container"}], "kind": "compliance", '
                    '"time": "2020-01-09T10:52:31.185Z", "type": "container", "rawJSONAlert": "{\\"_id\\": '
                    '\\"5e1705ef776710d48a0813b4\\", \\"compliance\\": [{\\"description\\": \\"(CIS_Docker_CE_v1.1.0 '
                    '- 5.28) Use PIDs cgroup limit\\", \\"id\\": \\"528\\", \\"type\\": \\"container\\"}, '
                    '{\\"description\\": \\"(CIS_Docker_CE_v1.1.0 - 5.25) Restrict container from acquiring '
                    'additional privileges\\", \\"id\\": \\"525\\", \\"type\\": \\"container\\"}, {\\"description\\": '
                    '\\"(CIS_Docker_CE_v1.1.0 - 5.9) Do not share the host\'s network namespace\\", \\"id\\": '
                    '\\"59\\", \\"type\\": \\"container\\"}], \\"kind\\": \\"compliance\\", \\"time\\": '
                    '\\"2020-01-09T10:52:31.185Z\\", \\"type\\": \\"container\\"}", "complianceMarkdownTable": "### '
                    'Compliance Table\\n|Type|ID|Description|\\n|---|---|---|\\n| container | 528 | ('
                    'CIS_Docker_CE_v1.1.0 - 5.28) Use PIDs cgroup limit |\\n| container | 525 | (CIS_Docker_CE_v1.1.0 '
                    '- 5.25) Restrict container from acquiring additional privileges |\\n| container | 59 | ('
                    'CIS_Docker_CE_v1.1.0 - 5.9) Do not share the host\'s network namespace |\\n"}'},
        {'name': 'Prisma Cloud Compute Alert - Image Compliance', 'occurred': '2020-01-09T10:52:31.185Z', 'severity': 0,
         'rawJSON': '{"_id": "5e1705ef776710d48a0813b5", "compliance": [{"description": "(CIS_Docker_CE_v1.1.0 - 4.1) '
                    'Image should be created with a non-root user", "id": "41", "type": "image"}], '
                    '"kind": "compliance", "time": "2020-01-09T10:52:31.185Z", "type": "image", "rawJSONAlert": "{'
                    '\\"_id\\": \\"5e1705ef776710d48a0813b5\\", \\"compliance\\": [{\\"description\\": \\"('
                    'CIS_Docker_CE_v1.1.0 - 4.1) Image should be created with a non-root user\\", \\"id\\": \\"41\\", '
                    '\\"type\\": \\"image\\"}], \\"kind\\": \\"compliance\\", \\"time\\": '
                    '\\"2020-01-09T10:52:31.185Z\\", \\"type\\": \\"image\\"}", "complianceMarkdownTable": "### '
                    'Compliance Table\\n|Type|ID|Description|\\n|---|---|---|\\n| image | 41 | (CIS_Docker_CE_v1.1.0 '
                    '- 4.1) Image should be created with a non-root user |\\n"}'},
        {'name': 'Prisma Cloud Compute Alert - library/alpine:2.6 Vulnerabilities',
         'occurred': '2020-01-09T10:53:23.865Z', 'severity': 3,
         'rawJSON': '{"_id": "5e170623776710d48a081440", "distroName": "BusyBox 1.21.1", "imageName": '
                    '"library/alpine:2.6", "kind": "vulnerability", "labels": {}, "time": "2020-01-09T10:53:23.865Z", '
                    '"vulnerabilities": [{"cve": "CVE-2019-5747", "link": "https://test.com", "packageVersion": '
                    '"1.21.1", "packages": "busybox", "severity": "high", "sourcePackage": "", "status": ""}, '
                    '{"cve": "CVE-2017-16544", "link": "https://test.com", "packageVersion": "1.21.1", "packages": '
                    '"busybox", "severity": "high", "sourcePackage": "", "status": ""}, {"cve": "CVE-2016-2147", '
                    '"link": "https://test.com", "packageVersion": "1.21.1", "packages": "busybox", "severity": '
                    '"high", "sourcePackage": "", "status": "fixed in 1.25.0"}, {"cve": "ALAS-2018-1065", "link": "", '
                    '"packageVersion": "1.0.1m-r0", "packages": "libcrypto1.0", "severity": "medium", '
                    '"sourcePackage": "openssl", "status": "fixed in 1.0.2k-12.110.amzn1"}, {"cve": "ALAS-2019-1188", '
                    '"link": "", "packageVersion": "1.0.1m-r0", "packages": "libcrypto1.0", "severity": "medium", '
                    '"sourcePackage": "openssl", "status": "fixed in 1.0.2k-16.150.amzn1"}], "rawJSONAlert": "{'
                    '\\"_id\\": \\"5e170623776710d48a081440\\", \\"distroName\\": \\"BusyBox 1.21.1\\", '
                    '\\"imageName\\": \\"library/alpine:2.6\\", \\"kind\\": \\"vulnerability\\", \\"labels\\": {}, '
                    '\\"time\\": \\"2020-01-09T10:53:23.865Z\\", \\"vulnerabilities\\": [{\\"cve\\": '
                    '\\"CVE-2019-5747\\", \\"link\\": \\"https://test.com\\", \\"packageVersion\\": \\"1.21.1\\", '
                    '\\"packages\\": \\"busybox\\", \\"severity\\": \\"high\\", \\"sourcePackage\\": \\"\\", '
                    '\\"status\\": \\"\\"}, {\\"cve\\": \\"CVE-2017-16544\\", \\"link\\": \\"https://test.com\\", '
                    '\\"packageVersion\\": \\"1.21.1\\", \\"packages\\": \\"busybox\\", \\"severity\\": \\"high\\", '
                    '\\"sourcePackage\\": \\"\\", \\"status\\": \\"\\"}, {\\"cve\\": \\"CVE-2016-2147\\", \\"link\\": '
                    '\\"https://test.com\\", \\"packageVersion\\": \\"1.21.1\\", \\"packages\\": \\"busybox\\", '
                    '\\"severity\\": \\"high\\", \\"sourcePackage\\": \\"\\", \\"status\\": \\"fixed in 1.25.0\\"}, '
                    '{\\"cve\\": \\"ALAS-2018-1065\\", \\"link\\": \\"\\", \\"packageVersion\\": \\"1.0.1m-r0\\", '
                    '\\"packages\\": \\"libcrypto1.0\\", \\"severity\\": \\"medium\\", \\"sourcePackage\\": '
                    '\\"openssl\\", \\"status\\": \\"fixed in 1.0.2k-12.110.amzn1\\"}, {\\"cve\\": '
                    '\\"ALAS-2019-1188\\", \\"link\\": \\"\\", \\"packageVersion\\": \\"1.0.1m-r0\\", \\"packages\\": '
                    '\\"libcrypto1.0\\", \\"severity\\": \\"medium\\", \\"sourcePackage\\": \\"openssl\\", '
                    '\\"status\\": \\"fixed in 1.0.2k-16.150.amzn1\\"}]}", "vulnerabilitiesMarkdownTable": "### '
                    'Vulnerabilities Table\\n|Severity|CVE|Status|Packages|Source Package|Package '
                    'Version|Link|\\n|---|---|---|---|---|---|---|\\n| high | CVE-2019-5747 |  | busybox |  | 1.21.1 '
                    '| https://test.com |\\n| high | CVE-2017-16544 |  | busybox |  | 1.21.1 | https://test.com |\\n| '
                    'high | CVE-2016-2147 | fixed in 1.25.0 | busybox |  | 1.21.1 | https://test.com |\\n| medium | '
                    'ALAS-2018-1065 | fixed in 1.0.2k-12.110.amzn1 | libcrypto1.0 | openssl | 1.0.1m-r0 |  |\\n| '
                    'medium | ALAS-2019-1188 | fixed in 1.0.2k-16.150.amzn1 | libcrypto1.0 | openssl | 1.0.1m-r0 |  '
                    '|\\n"}'}]

    requests_mock.get('https://test.com/xsoar-alerts', json=json_incidents_mock_response)
    client = Client(base_url='https://test.com', verify='False', project='', auth=('test', 'test'))
    assert fetch_incidents(client) == expected_incidents


def test_get_headers():
    # verify empty headers list when input is an empty list
    assert get_headers('unknownType', []) == []

    # verify correct headers returned for a known type
    assert get_headers('vulnerabilities', [
        {
            "cve": "",
            "link": "",
            "packageVersion": "",
            "packages": "",
            "severity": "",
            "sourcePackage": "",
            "status": ""
        }]) == HEADERS_BY_NAME.get('vulnerabilities')

    # verify known type with new headers is returned correctly
    expected = HEADERS_BY_NAME.get('vulnerabilities')
    expected.append("newField")
    assert get_headers('vulnerabilities', [
        {
            "cve": "",
            "link": "",
            "packageVersion": "",
            "packages": "",
            "severity": "",
            "sourcePackage": "",
            "status": "",
            "newField": ""
        }]) == expected

    # verify headers returned for an unknown type
    data = [
        {
            "cve": "",
            "link": "",
            "packageVersion": "",
            "packages": "",
            "severity": "",
            "sourcePackage": "",
            "status": ""
        }]
    assert get_headers('unknownType', data) == list(data[0].keys())
