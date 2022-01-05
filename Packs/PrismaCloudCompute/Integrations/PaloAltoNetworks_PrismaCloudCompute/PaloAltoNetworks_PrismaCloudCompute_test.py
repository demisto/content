import pytest
from collections import OrderedDict
from PaloAltoNetworks_PrismaCloudCompute import (
    PrismaCloudComputeClient, camel_case_transformer, fetch_incidents, get_headers,
    HEADERS_BY_NAME, get_profile_host_list, get_container_profile_list, get_container_hosts_list,
    get_profile_container_forensic_list, get_profile_host_forensic_list, get_console_version, get_custom_feeds_ip_list,
    add_custom_ip_feeds, filter_api_response, parse_date_string_format, get_custom_malware_feeds,
    add_custom_malware_feeds, get_cves, get_defenders, get_collections, get_namespaces, get_images_scan_list,
    get_hosts_scan_list, get_impacted_resources
)

from CommonServerPython import DemistoException


BASE_URL = 'https://test.com'


@pytest.fixture
def client() -> PrismaCloudComputeClient:
    return PrismaCloudComputeClient(
        base_url=BASE_URL, verify='False', project='', auth=('test', 'test')
    )


def test_camel_case_transformer():
    test_strings = ['camelCase', 'camelCaSe', 'camelCaseString', 'camelcase', 'CAMELCASE', 'cve', 'id', 4]
    expected_results = ['Camel Case', 'Camel Ca Se', 'Camel Case String', 'Camelcase', 'Camelcase', 'CVE', 'ID', '4']

    results = []
    for string in test_strings:
        results.append(camel_case_transformer(string))

    assert results == expected_results


def test_api_fallback(requests_mock):
    xsoar_endpoint = BASE_URL + '/xsoar-alerts'
    demisto_endpoint = BASE_URL + '/demisto-alerts'
    test_response = {'foo': 'bar'}
    client = PrismaCloudComputeClient(base_url=BASE_URL, verify='False', project='', auth=('test', 'test'))

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
    client = PrismaCloudComputeClient(base_url=BASE_URL, verify='False', project='', auth=('test', 'test'))
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


HTTP_REQUEST_URL_WITH_QUERY_PARAMS = [
    (
        OrderedDict(cluster="cluster", hostname="hostname", limit="10", offset="0"),
        get_profile_host_list,
        "/profiles/host",
        "https://test.com/profiles/host?cluster=cluster&limit=10&offset=0&hostname=hostname"
    ),
    (
        OrderedDict(
            cluster="cluster", id="1", image="image", image_id="1", namespace="namespace", os="os",
            state="state", limit="10", offset="0"
        ),
        get_container_profile_list,
        "/profiles/container",
        "https://test.com/profiles/container?cluster=cluster&id=1&image=image"
        "&namespace=namespace&os=os&state=state&limit=10&offset=0&imageid=1"
    ),
    (
        OrderedDict(limit="10", offset="0", id="123"),
        get_container_hosts_list,
        "/profiles/container/123/hosts",
        "https://test.com/profiles/container/123/hosts"
    ),
    (
        OrderedDict(
            collections="collections", hostname="hostname", limit="15", offset="2", id="123"
        ),
        get_profile_container_forensic_list,
        "/profiles/container/123/forensic",
        "https://test.com/profiles/container/123/forensic?collections=collections&hostname=hostname&limit=17"
    ),
    (
        OrderedDict(
            collections="collections", limit="10", offset="3", id="123"
        ),
        get_profile_host_forensic_list,
        "/profiles/host/123/forensic",
        "https://test.com/profiles/host/123/forensic?collections=collections&limit=13"
    ),
    (
        OrderedDict(),
        get_console_version,
        "/version",
        "https://test.com/version"
    ),
    (
        OrderedDict(),
        get_custom_feeds_ip_list,
        "/feeds/custom/ips",
        "https://test.com/feeds/custom/ips"
    ),
    (
        OrderedDict(cve_id="cve-2104"),
        get_cves,
        "/cves",
        "https://test.com/cves?id=cve-2104"
    ),
    (
        OrderedDict(cluster="cluster", hostname="hostname", type="type", offset="0", limit="20", connected=True),
        get_defenders,
        "/defenders",
        "https://test.com/defenders?cluster=cluster&connected=true&hostname=hostname&type=type&limit=20&offset=0"
    ),
    (
        OrderedDict(limit="20"),
        get_collections,
        "/collections",
        "https://test.com/collections"
    ),
    (
        OrderedDict(limit="20", cluster="cluster", collections="collections"),
        get_namespaces,
        "/radar/container/namespaces",
        "https://test.com/radar/container/namespaces?cluster=cluster&collections=collections"
    ),
    (
        OrderedDict(
            clusters="clusters", compact="true", fields="fields", hostname="hostname", id="123", name="name",
            registry="registry", repository="repository", offset="1", limit_record="3", limit_stats="3"
        ),
        get_images_scan_list,
        "/images",
        "https://test.com/images?limit=3&offset=1&compact=true&clusters=clusters&fields=fields&"
        "hostname=hostname&id=123&name=name&registry=registry&repository=repository"
    ),
    (
        OrderedDict(
            clusters="clusters", compact="true", fields="fields",
            hostname="hostname", provider="provider", offset="1", limit_record="8", limit_stats="2"
        ),
        get_hosts_scan_list,
        "/hosts",
        "https://test.com/hosts?limit=8&offset=1&compact=true&clusters=clusters&fields=fields"
        "&hostname=hostname&provider=provider"
    ),
    (
        OrderedDict(cve="cve"),
        get_impacted_resources,
        "/stats/vulnerabilities/impacted-resources",
        "https://test.com/stats/vulnerabilities/impacted-resources?cve=cve"
    )
]


@pytest.mark.parametrize("args, func, url_suffix, expected_url", HTTP_REQUEST_URL_WITH_QUERY_PARAMS)
def test_http_request_url_is_valid(requests_mock, args, func, url_suffix, expected_url, client):
    """
    Given:
        - query command arguments.

    When:
        - Calling the http-request for the command endpoint.

    Then:
        - Verify that the full URL of the http request is sent with the correct query/uri params.
    """
    mocker = requests_mock.get(url=BASE_URL + url_suffix, json=[])
    func(client=client, args=args) if args else func(client=client)

    assert expected_url == mocker.last_request._url_parts.geturl()


INVALID_LIMIT_OFFSET_ARGS = [
    (
        {"limit": "100", "offset": "0"},
        get_profile_host_list,
    ),
    (
        {"limit": "not_a_number", "offset": "0"},
        get_profile_host_list,
    ),
    (
        {"limit": "30", "offset": "not_a_number"},
        get_container_profile_list,
    ),
    (
        {"limit": "-2", "offset": "-5"},
        get_container_profile_list,
    ),
    (
        {"limit": "0", "offset": "-1", "id": "123"},
        get_container_hosts_list,
    ),
    (
        {"limit": "-50", "offset": "3", "id": "123"},
        get_profile_host_forensic_list,
    ),
    (
        {"limit": "-51", "offset": "0", "id": "123"},
        get_profile_container_forensic_list,
    ),
    (
        {"limit": "51", "offset": "0", "id": "123"},
        get_profile_container_forensic_list,
    ),
    (
        {"limit": "51", "offset": "100", "id": "123"},
        get_profile_host_forensic_list,
    ),
    (
        {"limit": "0", "offset": "0", "id": "123"},
        get_container_hosts_list,
    ),
    (
        {"limit": "-1"},
        get_custom_malware_feeds
    )
]


@pytest.mark.parametrize("args, func", INVALID_LIMIT_OFFSET_ARGS)
def test_invalid_offset_and_limit(args, func, client):
    """
    Given:
        - invalid offset/limit as command arguments.

    When:
        - executing a function for a specific api endpoint.

    Then:
        - Verify that ValueError is raised.
    """
    with pytest.raises((AssertionError, ValueError)):
        func(client=client, args=args)


HTTP_BODY_REQUEST_PARAMS = [
    (
        add_custom_ip_feeds,
        "/feeds/custom/ips",
        {
            "ip": "1.1.1.1"
        },
        {
            "feed": ["1.1.1.1"]
        }
    ),
    (
        add_custom_malware_feeds,
        "/feeds/custom/malware",
        {
            "name": "test",
            "md5": "1,2,3"
        },
        {
            "feed": [
                {
                    "name": "test",
                    "md5": "1"
                },
                {
                    "name": "test",
                    "md5": "2"
                },
                {
                    "name": "test",
                    "md5": "3"
                }
            ]
        }
    )
]


@pytest.mark.parametrize("func, url_suffix, args, expected_response", HTTP_BODY_REQUEST_PARAMS)
def test_http_body_request_is_valid(requests_mock, func, url_suffix, args, expected_response, client):
    """
    Given:
        - http body request to an api endpoint.

    When:
        - Calling the http-request for the command endpoint.

    Then:
        - Verify that the http body request that was sent is correct.
    """
    full_url = BASE_URL + url_suffix

    requests_mock.get(url=full_url, json={})
    mocker = requests_mock.put(url=full_url, json={})

    func(client=client, args=args)

    assert expected_response == mocker.last_request.json()


HTTP_FILTERING_BODY_RESPONSE_PARAMS = [
    (
        4, 2, ["host1", "host2", "host3", "host4", "host5"], ["host3", "host4", "host5"]
    ),
    (
        4, 2, ["host1"], []
    ),
    (
        5, 1, ["host1", "host2"], ["host2"]
    ),
    (
        3, 1, ["host1", "host2", "host3", "host4", "host5"], ["host2", "host3", "host4"]
    ),
    (
        1, 4, ["host1", "host2", "host3"], []
    ),
    (
        1, 4, ["host1", "host2", "host3", "host4", "host5", "host6", "host7"], ["host5"]
    ),
    (
        5, 3, ["host1", "host2", "host3", "host4", "host5", "host6", "host7"], ["host4", "host5", "host6", "host7"]
    ),
    (
        2, 8, ["host1", "host2", "host3", "host4", "host5", "host6", "host7"], []
    ),
    (
        7, 4, ["host1", "host2", "host3", "host4", "host5", "host6", "host7"], ["host5", "host6", "host7"]
    ),
    (
        4, 0, ["host1", "host2", "host3"], ["host1", "host2", "host3"]
    ),
    (
        1, 1, ["host1", "host2", "host3"], ["host2"]
    ),
]


@pytest.mark.parametrize("limit, offset, full_response, expected_response", HTTP_FILTERING_BODY_RESPONSE_PARAMS)
def test_http_body_response_filtering_is_valid(limit, offset, full_response, expected_response, client):
    """
    Given:
        - api response.

    When:
        - calling the function to filter the response

    Then:
        - Verify that the http body response is filtered correctly.
    """

    body_response = filter_api_response(api_response=full_response, limit=limit, offset=offset)

    assert len(body_response) == len(expected_response)
    assert body_response == expected_response


def test_date_string_format_conversion_is_successful():
    """
    Given:
        - a valid date string

    When:
        - trying to parse the date string into a different format

    Then:
        - verify that the format parsing was successful.
    """
    assert parse_date_string_format(date_string='2020-11-10T09:37:42.301Z') == 'November 10, 2020 09:37:42 AM'


def test_date_string_conversion_is_failing():
    """
    Given:
        - invalid date string format

    When:
        - trying to parse the date string into a different format

    Then:
        - verify that the format does not succeed.
    """
    assert parse_date_string_format(date_string='2020-11-10T09:37:42.301Z-341') == '2020-11-10T09:37:42.301Z-341'


EXPECTED_CONTEXT_OUTPUT_DATA = [
    (
        {
            "limit": "15",
            "offset": "0"
        },
        get_profile_host_list,
        "/profiles/host",
        [
            {
                "_id": "1",
                "hash": 1
            },
            {
                "_id": "2",
                "hash": 2
            }
        ],
        ""
    ),
    (
        {
            "limit": "15",
            "offset": "0"
        },
        get_container_profile_list,
        "/profiles/container",
        [
            {
                "state": "active",
                "_id": "1",
                "created": "2021-09-02T11:05:08.931Z"
            },
            {
                "state": "down",
                "_id": "2",
                "created": "2020-09-02T11:05:08.931Z"
            },
            {
                "state": "active",
                "_id": "3",
                "created": "2019-09-02T11:05:08.931Z"
            }
        ],
        ""
    ),
    (
        {
            "limit": "10",
            "offset": "0",
            "id": "123"
        },
        get_container_hosts_list,
        "/profiles/container/123/hosts",
        ["host1", "host2"],
        {
            "containerID": "123",
            "hostsIDs": ["host1", "host2"]
        }
    ),
    (
        {
            "limit": "10",
            "offset": "0",
            "id": "123",
            "hostname": "hostname"
        },
        get_profile_container_forensic_list,
        "/profiles/container/123/forensic?hostname=hostname",
        [
            {
                "type": "Runtime profile networking",
                "containerId": "1234",
                "port": 8000,
                "outbound": True
            },
            {
                "type": "Runtime profile networking",
                "containerId": "1234",
                "port": 6789,
                "process": "some_process"
            }
        ],
        {
            "containerID": "123",
            "hostname": "hostname",
            "Forensics": [
                {
                    "type": "Runtime profile networking",
                    "containerId": "1234",
                    "port": 8000,
                    "outbound": True
                },
                {
                    "type": "Runtime profile networking",
                    "containerId": "1234",
                    "port": 6789,
                    "process": "some_process"
                }
            ],
        }
    ),
    (
        {
            "limit": "10",
            "offset": "0",
            "id": "123"
        },
        get_profile_host_forensic_list,
        "/profiles/host/123/forensic",
        [
            {
                "type": "Process spawned",
                "command": "docker-runc --version",
            },
            {
                "type": "Process spawned",
                "command": "docker ps -a",
            }
        ],
        {
            "hostID": "123",
            "Forensics": [
                {
                    "type": "Process spawned",
                    "command": "docker-runc --version",
                },
                {
                    "type": "Process spawned",
                    "command": "docker ps -a",
                }
            ]
        }
    ),
    (
        {},
        get_console_version,
        "/version",
        "21.04",
        ""
    ),
    (
        {},
        get_custom_feeds_ip_list,
        "/feeds/custom/ips",
        {
            "_id": "",
            "modified": "2021-12-01T11:50:50.882Z",
            "feed": [
                "1.1.1.1",
                "5.5.5.5",
                "2.2.2.2",
                "4.4.4.4",
                "3.3.3.3"
            ],
            "digest": "1234"
        },
        {
            "modified": "December 01, 2021 11:50:50 AM",
            "feed": [
                "1.1.1.1",
                "5.5.5.5",
                "2.2.2.2",
                "4.4.4.4",
                "3.3.3.3"
            ],
            "digest": "1234"
        }
    ),
    (
        {"limit": "1"},
        get_custom_malware_feeds,
        "/feeds/custom/malware",
        {
            "_id": "",
            "modified": "2021-12-09T13:31:38.851Z",
            "feed": [
                {
                    "md5": "1234",
                    "name": "test",
                    "modified": 0,
                    "allowed": False
                },
                {
                    "md5": "12345",
                    "name": "test1",
                    "modified": 0,
                    "allowed": False
                },
            ],
            "digest": "1234"
        },
        {
            "modified": "December 09, 2021 13:31:38 PM",
            "feed": [
                {
                    "md5": "1234",
                    "name": "test",
                    "allowed": False
                }
            ],
            "digest": "1234"
        }
    ),
    (
        {"cve_id": "cve_id"},
        get_cves,
        "/cves",
        [
            {
                "cve": "cve1",
                "distro": "distro",
                "distro_release": "distro_release",
                "type": "type",
                "package": "package",
                "severity": "unimportant",
                "status": "fixed in 2.22-15",
                "cvss": 5,
                "rules": [
                    "<2.22-15"
                ],
                "conditions": None,
                "modified": 1606135803,
                "fixDate": 0,
                "link_id": "",
                "description": "description1"
            },
            {
                "cve": "cve2",
                "distro": "distro",
                "distro_release": "distro_release",
                "type": "type",
                "package": "package",
                "severity": "severity",
                "status": "fixed in 2.22-100.15",
                "cvss": 7,
                "rules": [
                    "<2.22-100.15"
                ],
                "conditions": None,
                "modified": 1606135803,
                "fixDate": 0,
                "link_id": "",
                "description": "description2"
            },
        ],
        [
            {
                "ID": "cve1",
                "Description": "description1",
                "CVSS": 5,
                "Modified": "November 23, 2020 12:50:03 PM"
            },
            {
                "ID": "cve2",
                "Description": "description2",
                "CVSS": 7,
                "Modified": "November 23, 2020 12:50:03 PM"
            }
        ]
    ),
    (
        {"limit": "20", "offset": "0"},
        get_defenders,
        "/defenders",
        [
            {
                "hostname": "host1",
                "version": "24.04",
                "connected": True,
                "features": {
                    "proxyListenerType": "none"
                },
                "category": "docker",
                "lastModified": "2021-09-02T11:05:08.8Z",
            },
            {
                "hostname": "host2",
                "version": "24.04",
                "connected": False,
                "features": {
                    "proxyListenerType": "none"
                },
                "category": "docker",
                "lastModified": "2021-09-02T11:05:08.8Z",
            }
        ],
        [
            {
                "hostname": "host1",
                "version": "24.04",
                "connected": True,
                "features": {
                    "proxyListenerType": "none"
                },
                "category": "docker",
                "lastModified": "September 02, 2021 11:05:08 AM",
            },
            {
                "hostname": "host2",
                "version": "24.04",
                "connected": False,
                "features": {
                    "proxyListenerType": "none"
                },
                "category": "docker",
                "lastModified": "September 02, 2021 11:05:08 AM",
            }
        ],
    ),
    (
        {"limit": "20"},
        get_collections,
        "/collections",
        [
            {
                "hosts": ["*"],
                "images": ["*"],
                "labels": ["*"],
                "containers": ["*"],
                "functions": ["*"],
                "namespaces": ["*"],
                "appIDs": ["*"],
                "accountIDs": ["*"],
                "codeRepos": ["*"],
                "clusters": ["*"],
                "name": "All",
                "owner": "system",
                "modified": "2021-12-02T07:54:42.517Z",
                "color": "#3FA2F7",
                "description": "System - all resources collection",
                "system": True,
            }
        ],
        [
            {
                "hosts": ["*"],
                "images": ["*"],
                "labels": ["*"],
                "containers": ["*"],
                "functions": ["*"],
                "namespaces": ["*"],
                "appIDs": ["*"],
                "accountIDs": ["*"],
                "codeRepos": ["*"],
                "clusters": ["*"],
                "name": "All",
                "owner": "system",
                "modified": "December 02, 2021 07:54:42 AM",
                "color": "#3FA2F7",
                "description": "System - all resources collection",
                "system": True,
            }
        ]
    ),
    (
        {"limit": "20"},
        get_namespaces,
        "/radar/container/namespaces",
        ["namespace1", "namespace2", "namespace3"],
        ""
    ),
    (
        {"limit_stats": "1", "limit_records": "20"},
        get_images_scan_list,
        "/images",
        [
            {
                "id": "123",
                "osDistro": "alpine",
                "vulnerabilities": [
                    {
                        "cvss": 7.5,
                        "status": "fixed in 1.30.1-r5",
                        "cve": "CVE-2018-20679",
                        "packageName": "busybox",
                        "fixDate": 1547051340,
                    },
                    {
                        "cvss": 8.5,
                        "status": "fixed in 1.30.1-r5",
                        "cve": "CVE-2019-20679",
                        "packageName": "busybox2",
                        "fixDate": 1547059999,
                    },
                ]
            }
        ],
        [
            {
                "id": "123",
                "osDistro": "alpine",
                "vulnerabilities": [
                    {
                        "cvss": 7.5,
                        "status": "fixed in 1.30.1-r5",
                        "cve": "CVE-2018-20679",
                        "packageName": "busybox",
                        "fixDate": "January 09, 2019 16:29:00 PM",
                    }
                ]
            }
        ]
    ),
    (
        {"limit_stats": "1", "limit_records": "20"},
        get_hosts_scan_list,
        "/hosts",
        [
            {
                "id": "123",
                "osDistro": "alpine",
                "vulnerabilities": [
                    {
                        "cvss": 7.5,
                        "status": "fixed in 1.30.1-r5",
                        "cve": "CVE-2018-20679",
                        "packageName": "busybox",
                        "fixDate": 1547051340,
                    },
                    {
                        "cvss": 8.5,
                        "status": "fixed in 1.30.1-r5",
                        "cve": "CVE-2019-20679",
                        "packageName": "busybox2",
                        "fixDate": 1547059999,
                    },
                ]
            }
        ],
        [
            {
                "id": "123",
                "osDistro": "alpine",
                "vulnerabilities": [
                    {
                        "cvss": 7.5,
                        "status": "fixed in 1.30.1-r5",
                        "cve": "CVE-2018-20679",
                        "packageName": "busybox",
                        "fixDate": "January 09, 2019 16:29:00 PM",
                    }
                ]
            }
        ]
    ),
    (
        {"limit": "2", "cve": "CVE-2018-14600"},
        get_impacted_resources,
        "/stats/vulnerabilities/impacted-resources",
        {
            "_id": "CVE-2018-1270",
            "riskTree": {
                "1": [
                    {
                        "image": "image1",
                        "container": "container1",
                        "host": "host1",
                        "namespace": "namespace1",
                        "factors": {
                            "network": True,
                            "noSecurityProfile": True
                        }
                    }
                ],
            },
        },
        [
            {
                "_id": "CVE-2018-1270",
                "riskTree": {
                    "1": [
                        {
                            "image": "image1",
                            "container": "container1",
                            "host": "host1",
                            "namespace": "namespace1",
                            "factors": {
                                "network": True,
                                "noSecurityProfile": True
                            }
                        }
                    ],
                },
            },
        ]
    )
]


@pytest.mark.parametrize("args, func, url_suffix, json, expected_context_output", EXPECTED_CONTEXT_OUTPUT_DATA)
def test_context_data_output_is_valid(requests_mock, args, func, url_suffix, json, expected_context_output, client):
    """
    Given:
        - command arguments

    When:
        - building the context output

    Then:
        - verify that the context output is created as expected.

    Note:
        if expected_context_output is empty string,
        it means we expect the context output to be the same as the raw response.
    """
    if not expected_context_output:
        expected_context_output = json

    full_url = BASE_URL + url_suffix

    requests_mock.get(url=full_url, json=json)
    command_results = func(client=client, args=args) if args else func(client=client)

    if isinstance(command_results, list):
        for result, expected_output in zip(command_results, expected_context_output):
            assert result.outputs == expected_output
    else:
        assert command_results.outputs == expected_context_output
