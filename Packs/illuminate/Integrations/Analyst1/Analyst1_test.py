import pytest
from Analyst1 import *

MOCK_SERVER: str = 'mock.com'
MOCK_USER: str = 'mock'
MOCK_PASS: str = 'mock'
MOCK_INDICATOR: str = 'mock-indicator'

BASE_MOCK_NOTFOUND: dict = {"message": "The requested resource was not found."}
BASE_MOCK_JSON: dict = {
    'type': 'domain',
    'value': {
        'name': f'{MOCK_INDICATOR}',
        'classification': 'U'
    },
    'description': None,
    'activityDates': [
        {
            'date': '2020-01-20',
            'classification': 'U'
        }
    ],
    'reportedDates': [
        {
            'date': '2020-01-31',
            'classification': 'U'
        }
    ],
    'targets': [
        {
            'name': 'Mock Target',
            'id': 1,
            'classification': 'U'
        }
    ],
    'attackPatterns': [
        {
            'name': 'Mock Attack Pattern',
            'id': 1,
            'classification': 'U'
        }
    ],
    'actors': [
        {
            'name': 'Mock Actor',
            'id': 1,
            'classification': 'U'
        }
    ],
    'malwares': [],
    'status': 'aw',
    'hashes': None,
    'fileNames': None,
    'fileSize': None,
    'path': None,
    'ports': [],
    'ipRegistration': None,
    'domainRegistration': None,
    'ipResolution': None,
    'originatingIps': None,
    'subjects': None,
    'requestMethods': None,
    'tlp': 'mocktlp',
    'tlpJustification': None,
    'tlpCaveats': None,
    'tlpResolution': 'resolved',
    'tlpHighestAssociated': 'mocktlp',
    'tlpLowestAssociated': 'mocktlp',
    'active': True,
    'benign': {
        'value': False,
        'classification': 'U'
    },
    'confidenceLevel': None,
    'exploitStage': None,
    'lastHit': None,
    'firstHit': None,
    'hitCount': None,
    'reportCount': 1,
    'verified': False,
    'tasked': False,
    'links': [
        {
            'rel': 'self',
            'href': f'https://{MOCK_SERVER}.com/api/1_0/indicator/1',
            'hreflang': None,
            'media': None,
            'title': None,
            'type': None,
            'deprecation': None
        },
        {
            'rel': 'evidence',
            'href': f'https://{MOCK_SERVER}.com/api/1_0/indicator/1/evidence',
            'hreflang': None,
            'media': None,
            'title': None,
            'type': None,
            'deprecation': None
        },
        {
            'rel': 'stix',
            'href': f'https://{MOCK_SERVER}.com/api/1_0/indicator/1/stix',
            'hreflang': None,
            'media': None,
            'title': None,
            'type': None,
            'deprecation': None
        }
    ],
    'id': 1
}
MOCK_BATCH_RESPONSE: dict = {
    "results": [
        {
            "searchedValue": "google.com",
            "matchedValue": "google.com",
            "id": 10336,
            "other-attributes": "redacted"
        },
        {
            "searchedValue": "1.2.3.4",
            "matchedValue": "1.2.3.4",
            "id": 146950461,
            "other-attributes": "redacted"
        },
        {
            "searchedValue": "conimes.com",
            "matchedValue": "conimes.com",
            "id": 983,
            "other-attributes": "redacted"
        }
    ]
}
MOCK_SENSOR_IOCS: list = [
    {
        "id": 1,
        "type": "Domain",
        "value": "example.com",
        "classification": "U",
        "fileHashes": {},
        "links": [
            {
                "rel": "self",
                "href": "https://mock.com/api/1_0/indicator/1"
            }
        ]
    },
    {
        "id": 2,
        "type": "IPv4",
        "value": "0.154.17.105",
        "classification": "U",
        "fileHashes": {},
        "links": [
            {
                "rel": "self",
                "href": "https://mock.com/api/1_0/indicator/2"
            }
        ]
    },
    {
        "id": 3,
        "type": "File",
        "value": "F5A64DE9087B138608CCF036B067D91A47302259269FB05B3349964CA4060E7A",
        "classification": "U",
        "fileHashes": {
            "SHA256": "F5A64DE9087B138608CCF036B067D91A47302259269FB05B3349964CA4060E7A",
            "SHA1": "D8474A07411C6400E47C13D73700DC602F90262A",
            "MD5": "6318E219B7F6E7F96192E0CDFEA1742A"
        },
        "links": [
            {
                "rel": "self",
                "href": "https://mock.com/api/1_0/indicator/3"
            }
        ]
    }
]
MOCK_SENSOR_RULES: list = [
    {
        "id": 1,
        "versionNumber": 1,
        "signature": "text goes here",
        "classification": "U",
        "links": [
            {
                "rel": "self",
                "href": "https://training.cloud.analyst1.com/api/1_0/rules/1"
            }
        ]
    }, {
        "id": 2,
        "versionNumber": 1,
        "signature": "other text goes here",
        "classification": "U",
        "links": [
            {
                "rel": "self",
                "href": "https://training.cloud.analyst1.com/api/1_0/rules/2"
            }
        ]
    }
]
MOCK_SENSOR_DIFF_RESPONSE_CONTENT: dict = {
    "id": 1,
    "version": 2,
    "latestVersion": 10,
    "indicatorsAdded": MOCK_SENSOR_IOCS,
    "indicatorsRemoved": MOCK_SENSOR_IOCS,
    "rulesAdded": MOCK_SENSOR_RULES,
    "rulesRemoved": MOCK_SENSOR_RULES,
    "links": [
        {
            "rel": "self",
            "href": "https://mock.com/api/1_0/sensors/1/taskings/diff/2"
        },
        {
            "rel": "sensor",
            "href": "https://mock.com/api/1_0/sensors/2"
        }
    ]
}
MOCK_SENSOR_DIFF_RESPONSE_EMPTY: dict = {
    "id": 1,
    "version": 2,
    "latestVersion": 10
}
MOCK_SENSOR_TASKINGS_RESPONSE_CONTENT: dict = {
    "id": 1,
    "version": 10,
    "indicators": MOCK_SENSOR_IOCS,
    "rules": MOCK_SENSOR_RULES,
    "links": [
        {
            "rel": "self",
            "href": "https://mock.com/api/1_0/sensors/1/taskings/diff/2"
        },
        {
            "rel": "sensor",
            "href": "https://mock.com/api/1_0/sensors/2"
        }
    ]
}
MOCK_SENSOR_TASKINGS_RESPONSE_EMPTY: dict = {
    "id": 1,
    "version": 10
}
MOCK_SENSORS: dict = {
    "results": [
        {
            "id": 1,
            "name": "sensor 1",
            "logicalLocation": None,
            "org": None,
            "type": "OTHER_AUTO",
            "currentVersionNumber": 5,
            "latestConfigVersionNumber": 5,
            "links": [
                {
                    "rel": "details",
                    "href": "https://mock.com/api/1_0/sensors/1"
                }
            ]
        },
        {
            "id": 2,
            "name": "sensor 2",
            "logicalLocation": None,
            "org": None,
            "type": "OTHER_AUTO",
            "currentVersionNumber": 26,
            "latestConfigVersionNumber": 26,
            "links": [
                {
                    "rel": "details",
                    "href": "https://mock.com/api/1_0/sensors/2"
                }
            ]
        }
    ],
    "pageSize": 50,
    "page": 1,
    "totalResults": 2,
    "totalPages": 1,
    "links": [
        {
            "rel": "first",
            "href": "https://mock.com/api/1_0/sensors?page=1&pageSize=10"
        },
        {
            "rel": "last",
            "href": "https://mock.com/api/1_0/sensors?page=1&pageSize=10"
        },
        {
            "rel": "self",
            "href": "https://mock.com/api/1_0/sensors?page=1&pageSize=10"
        }
    ]
}
MOCK_TEST_REQUEST_GOOD = {
    "links": [
        {
            "rel": "self",
            "href": "https://mock.com/api/1_0"
        }
    ]
}
MOCK_TEST_REQUEST_INVALID = {
    "cannotfindme": [
        {
            "rel": "self",
            "href": "https://mock.com/api/1_0"
        }
    ]
}


MOCK_CLIENT_PARAMS = {
    'server': MOCK_SERVER,
    'proxy': 'false',
    'insecure': 'true',
    'credentials': {
        'identifier': MOCK_USER,
        'password': MOCK_PASS
    }
}


@pytest.fixture
def mock_client():
    return build_client(MOCK_CLIENT_PARAMS)


def mock_indicator_search(indicator_type: str, requests_mock):
    requests_mock.get(
        f'https://{MOCK_SERVER}/api/1_0/indicator/match?type={indicator_type}&value={MOCK_INDICATOR}',
        json=BASE_MOCK_JSON
    )


def test_domain_command(requests_mock, mock_client):
    mock_indicator_search('domain', requests_mock)
    args: dict = {'domain': f'{MOCK_INDICATOR}'}

    enrichment_output: EnrichmentOutput = domain_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get('ID') == BASE_MOCK_JSON.get('id')


def test_email_command(requests_mock, mock_client):
    mock_indicator_search('email', requests_mock)
    args: dict = {'email': f'{MOCK_INDICATOR}'}

    enrichment_output: EnrichmentOutput = email_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get('ID') == BASE_MOCK_JSON.get('id')


def test_ip_command(requests_mock, mock_client):
    mock_indicator_search('ip', requests_mock)
    args: dict = {'ip': f'{MOCK_INDICATOR}'}

    enrichment_output: EnrichmentOutput = ip_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get('ID') == BASE_MOCK_JSON.get('id')


def test_file_command(requests_mock, mock_client):
    mock_indicator_search('file', requests_mock)
    args: dict = {'file': f'{MOCK_INDICATOR}'}

    enrichment_output: EnrichmentOutput = file_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get('ID') == BASE_MOCK_JSON.get('id')


def test_url_command(requests_mock, mock_client):
    mock_indicator_search('url', requests_mock)
    args: dict = {'url': f'{MOCK_INDICATOR}'}

    enrichment_output: EnrichmentOutput = url_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get('ID') == BASE_MOCK_JSON.get('id')


def test_analyst1_enrich_string_command(requests_mock, mock_client):
    mock_indicator_search('string', requests_mock)
    args: dict = {'string': f'{MOCK_INDICATOR}'}

    enrichment_output: EnrichmentOutput = analyst1_enrich_string_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get('ID') == BASE_MOCK_JSON.get('id')


def test_analyst1_enrich_ipv6_command(requests_mock, mock_client):
    mock_indicator_search('ipv6', requests_mock)
    args: dict = {'ip': f'{MOCK_INDICATOR}'}

    enrichment_output: EnrichmentOutput = analyst1_enrich_ipv6_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get('ID') == BASE_MOCK_JSON.get('id')


def test_analyst1_enrich_mutex_command(requests_mock, mock_client):
    mock_indicator_search('mutex', requests_mock)
    args: dict = {'mutex': f'{MOCK_INDICATOR}'}

    enrichment_output: EnrichmentOutput = analyst1_enrich_mutex_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get('ID') == BASE_MOCK_JSON.get('id')


def test_analyst1_enrich_http_request_command(requests_mock, mock_client):
    mock_indicator_search('httpRequest', requests_mock)
    args: dict = {'http-request': f'{MOCK_INDICATOR}'}

    enrichment_output: EnrichmentOutput = analyst1_enrich_http_request_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get('ID') == BASE_MOCK_JSON.get('id')


def test_malicious_indicator_check_empty(mock_client):
    data = {}
    assert mock_client.is_indicator_malicious(data) is False


def test_malicious_indicator_check_benign_false(mock_client):
    data = {
        "benign": {
            "value": False
        }
    }
    assert mock_client.is_indicator_malicious(data) is True


def test_malicious_indicator_check_benign_true(mock_client):
    data = {
        "benign": {
            "value": True
        }
    }
    assert mock_client.is_indicator_malicious(data) is False


def test_analyst1_get_indicator_found_normal_ioc(requests_mock, mock_client):
    requests_mock.get(
        f'https://{MOCK_SERVER}/api/1_0/indicator/1',
        json=BASE_MOCK_JSON
    )
    args: dict = {'indicator_id': 1}
    command_results = analyst1_get_indicator(mock_client, args)
    assert command_results is not None
    assert command_results.outputs_prefix == 'Analyst1.Indicator'
    assert command_results.outputs.get('id') == BASE_MOCK_JSON.get('id')


def test_analyst1_get_indicator_found_hash_ioc(requests_mock, mock_client):
    requests_mock.get(
        f'https://{MOCK_SERVER}/api/1_0/indicator/1',
        json=BASE_MOCK_JSON
    )
    args: dict = {'indicator_id': '1-igetignored'}
    command_results = analyst1_get_indicator(mock_client, args)
    assert command_results is not None
    assert command_results.outputs_prefix == 'Analyst1.Indicator'
    assert command_results.outputs.get('id') == BASE_MOCK_JSON.get('id')


def test_analyst1_get_indicator_ioc_not_found(requests_mock, mock_client):
    requests_mock.get(
        f'https://{MOCK_SERVER}/api/1_0/indicator/2345',
        json=BASE_MOCK_NOTFOUND
    )
    args: dict = {'indicator_id': '2345'}
    command_results = analyst1_get_indicator(mock_client, args)
    assert command_results is not None
    assert command_results.outputs_prefix == 'Analyst1.Indicator'
    assert command_results.outputs.get('message') is not None


def test_analyst1_batch_check_command(requests_mock, mock_client):
    requests_mock.get(
        f'https://{MOCK_SERVER}/api/1_0/batchCheck?values=ioc1,ioc2,ioc3,ioc4',
        json=MOCK_BATCH_RESPONSE
    )
    args: dict = {'values': 'ioc1,ioc2,ioc3,ioc4'}
    command_results = analyst1_batch_check_command(mock_client, args)
    assert command_results is not None
    assert command_results.outputs_prefix == 'Analyst1.BatchResults'
    assert command_results.outputs_key_field == 'ID'
    assert command_results.outputs == MOCK_BATCH_RESPONSE.get('results')


HELPER_MOCK_NEWLINEVALUES: str = """ioc1
ioc2
ioc3
ioc4"""


def helper_mock_batch_check_post(requests_mock) -> dict:
    # unclear how to mock the actual post content in requests_mock
    # values_to_submit = {'values': HELPER_MOCK_NEWLINEVALUES}
    requests_mock.post(
        f'https://{MOCK_SERVER}/api/1_0/batchCheck',
        json=MOCK_BATCH_RESPONSE
    )
    args: dict = {'values': HELPER_MOCK_NEWLINEVALUES}
    return args


def assert_batch_check_post(output_check):
    assert output_check is not None
    assert output_check['command_results'].outputs_prefix == 'Analyst1.BatchResults'
    assert output_check['command_results'].outputs_key_field == 'ID'
    assert output_check['command_results'].outputs == MOCK_BATCH_RESPONSE.get('results')
    assert output_check['submitted_values'] == HELPER_MOCK_NEWLINEVALUES


def test_analyst1_batch_check_post_values_str(requests_mock, mock_client):
    args: dict = helper_mock_batch_check_post(requests_mock)
    output_check = analyst1_batch_check_post(mock_client, args)
    assert_batch_check_post(output_check)


def test_analyst1_batch_check_post_values_array_str(requests_mock, mock_client):
    helper_mock_batch_check_post(requests_mock)
    args: dict = {'values_array': '"ioc1","ioc2","ioc3","ioc4"'}
    output_check = analyst1_batch_check_post(mock_client, args)
    assert_batch_check_post(output_check)


def test_analyst1_batch_check_post_values_array_list(requests_mock, mock_client):
    helper_mock_batch_check_post(requests_mock)
    args: dict = {'values_array': ["ioc1", "ioc2", "ioc3", "ioc4"]}
    output_check = analyst1_batch_check_post(mock_client, args)
    assert_batch_check_post(output_check)


def test_analyst1_batch_check_post_values_array_json(requests_mock, mock_client):
    helper_mock_batch_check_post(requests_mock)
    args: dict = {'values_array': {'values': ["ioc1", "ioc2", "ioc3", "ioc4"]}}
    output_check = analyst1_batch_check_post(mock_client, args)
    assert_batch_check_post(output_check)


def test_analyst1_evidence_submit(requests_mock, mock_client):
    requests_mock.post(
        f'https://{MOCK_SERVER}/api/1_0/evidence',
        json={'uuid': 'uuid_value'}
    )
    args: dict = {
        'fileName': 'name.txt', 'fileContent': 'string of content',
        'sourceId': '1', 'tlp': 'clear', 'fileClassification': 'u'
    }
    command_results = analyst1_evidence_submit(mock_client, args)
    assert command_results.outputs_prefix == 'Analyst1.EvidenceSubmit'
    assert command_results.outputs_key_field == 'uuid'
    assert command_results.outputs.get('uuid') == 'uuid_value'


def test_analyst1_evidence_submit_error(requests_mock, mock_client):
    args: dict = {
        'fileName': 'name.txt', 'sourceId': '1', 'tlp': 'clear', 'fileClassification': 'u'
    }
    try:
        analyst1_evidence_submit(mock_client, args)
    except DemistoException:
        return
    raise AssertionError


def test_analyst1_evidence_status_200_emptyid(requests_mock, mock_client):
    requests_mock.get(
        f'https://{MOCK_SERVER}/api/1_0/evidence/uploadStatus/uuid_value',
        json={'id': ''}
    )
    args: dict = {'uuid': 'uuid_value'}
    command_results = analyst1_evidence_status(mock_client, args)
    assert command_results.outputs_prefix == 'Analyst1.EvidenceStatus'
    assert command_results.outputs_key_field == 'id'
    assert command_results.outputs.get('id') == ''
    assert command_results.outputs.get('processingComplete') is False


def test_analyst1_evidence_status_200_knownstrid(requests_mock, mock_client):
    requests_mock.get(
        f'https://{MOCK_SERVER}/api/1_0/evidence/uploadStatus/uuid_value',
        json={'id': 'finished'}
    )
    args: dict = {'uuid': 'uuid_value'}
    command_results = analyst1_evidence_status(mock_client, args)
    assert command_results.outputs_prefix == 'Analyst1.EvidenceStatus'
    assert command_results.outputs_key_field == 'id'
    assert command_results.outputs.get('id') == 'finished'
    assert command_results.outputs.get('processingComplete') is True


def test_analyst1_evidence_status_200_knownintid(requests_mock, mock_client):
    requests_mock.get(
        f'https://{MOCK_SERVER}/api/1_0/evidence/uploadStatus/uuid_value',
        json={'id': 1}
    )
    args: dict = {'uuid': 'uuid_value'}
    command_results = analyst1_evidence_status(mock_client, args)
    assert command_results.outputs_prefix == 'Analyst1.EvidenceStatus'
    assert command_results.outputs_key_field == 'id'
    assert command_results.outputs.get('id') == 1
    assert command_results.outputs.get('processingComplete') is True


def test_analyst1_get_sensors_command(requests_mock, mock_client):
    requests_mock.get(
        f'https://{MOCK_SERVER}/api/1_0/sensors?page=1&pageSize=50',
        json=MOCK_SENSORS
    )
    args: dict = {'page': 1, 'pageSize': 50}
    command_results = analyst1_get_sensors_command(mock_client, args)
    assert command_results is not None
    assert command_results.outputs_prefix == 'Analyst1.SensorList'
    assert command_results.outputs_key_field == 'id'
    assert command_results.outputs == MOCK_SENSORS.get('results')


def test_analyst1_get_sensors_command_defaultsOfArgsToInt(requests_mock, mock_client):
    requests_mock.get(
        f'https://{MOCK_SERVER}/api/1_0/sensors?page=1&pageSize=50',
        json=MOCK_SENSORS
    )
    # empty args to test defaults
    args: dict = {}
    command_results = analyst1_get_sensors_command(mock_client, args)
    assert command_results is not None
    assert command_results.outputs_prefix == 'Analyst1.SensorList'
    assert command_results.outputs_key_field == 'id'
    assert command_results.outputs == MOCK_SENSORS.get('results')


def assert_sensor_taskings(command_results_list: list):
    assert len(command_results_list) == 3
    assert command_results_list[0].outputs_prefix == 'Analyst1.SensorTaskings'
    assert command_results_list[1].outputs_prefix == 'Analyst1.SensorTaskings.Indicators'
    assert command_results_list[2].outputs_prefix == 'Analyst1.SensorTaskings.Rules'
    assert command_results_list[0].outputs['id'] == 1
    assert command_results_list[0].outputs['version'] == 10


def assert_sensor_diff(command_results_list: list):
    assert command_results_list is not None
    # one entry for context and the rest for added/removed
    assert len(command_results_list) == 5
    assert command_results_list[0].outputs_prefix == 'Analyst1.SensorTaskings'
    assert command_results_list[1].outputs_prefix == 'Analyst1.SensorTaskings.IndicatorsAdded'
    assert command_results_list[2].outputs_prefix == 'Analyst1.SensorTaskings.IndicatorsRemoved'
    assert command_results_list[3].outputs_prefix == 'Analyst1.SensorTaskings.RulesAdded'
    assert command_results_list[4].outputs_prefix == 'Analyst1.SensorTaskings.RulesRemoved'
    # check json pass through
    assert command_results_list[0].outputs['id'] == 1
    assert command_results_list[0].outputs['version'] == 2
    assert command_results_list[0].outputs['latestVersion'] == 10


def assert_sensor_iocs(output_list: list):
    # one for each IOC or hash found
    assert len(output_list) == 5
    assert output_list[0]['category'] == 'indicator'
    assert output_list[0]['id'] == '1'
    assert output_list[0]['value'] == 'example.com'
    assert output_list[1]['id'] == '2'
    assert output_list[1]['value'] == '0.154.17.105'
    assert output_list[2]['id'] == '3-SHA256'
    assert output_list[2]['value'] == 'F5A64DE9087B138608CCF036B067D91A47302259269FB05B3349964CA4060E7A'
    assert output_list[3]['id'] == '3-SHA1'
    assert output_list[3]['value'] == 'D8474A07411C6400E47C13D73700DC602F90262A'
    assert output_list[4]['id'] == '3-MD5'
    assert output_list[4]['value'] == '6318E219B7F6E7F96192E0CDFEA1742A'


def assert_sensor_rules(output_list: list):
    assert len(output_list) == 2
    assert output_list[0]['category'] == 'rule'
    assert output_list[0]['id'] == '1'
    assert output_list[0]['signature'] == 'text goes here'
    assert output_list[1]['id'] == '2'
    assert output_list[1]['signature'] == 'other text goes here'


def test_analyst1_get_sensor_taskings_command_content(requests_mock, mock_client):
    requests_mock.get(
        f'https://{MOCK_SERVER}/api/1_0/sensors/1/taskings',
        json=MOCK_SENSOR_TASKINGS_RESPONSE_CONTENT
    )
    args: dict = {'sensor_id': '1', 'timeout': '200'}
    command_results_list = analyst1_get_sensor_taskings_command(mock_client, args)
    assert_sensor_taskings(command_results_list)
    assert_sensor_iocs(command_results_list[1].outputs)
    assert_sensor_rules(command_results_list[2].outputs)


def test_analyst1_get_sensor_taskings_command_empty(requests_mock, mock_client):
    requests_mock.get(
        f'https://{MOCK_SERVER}/api/1_0/sensors/1/taskings',
        json=MOCK_SENSOR_TASKINGS_RESPONSE_EMPTY
    )
    args: dict = {'sensor_id': '1', 'timeout': '200'}
    command_results_list = analyst1_get_sensor_taskings_command(mock_client, args)
    assert len(command_results_list) == 3
    assert_sensor_taskings(command_results_list)
    assert len(command_results_list[1].outputs) == 0
    assert len(command_results_list[2].outputs) == 0


def test_analyst1_get_sensor_diff_content(requests_mock, mock_client):
    requests_mock.get(
        f'https://{MOCK_SERVER}/api/1_0/sensors/1/taskings/diff/2',
        json=MOCK_SENSOR_DIFF_RESPONSE_CONTENT
    )
    args: dict = {'sensor_id': '1', 'version': '2', 'timeout': '200'}
    command_results_list = analyst1_get_sensor_diff(mock_client, args)
    assert_sensor_diff(command_results_list)
    # confirm IOC conversion succeeds
    assert_sensor_iocs(command_results_list[1].outputs)
    assert_sensor_iocs(command_results_list[2].outputs)
    # confirm rule conversion succeeds
    assert_sensor_rules(command_results_list[3].outputs)
    assert_sensor_rules(command_results_list[4].outputs)


def test_analyst1_get_sensor_diff_empty(requests_mock, mock_client):
    requests_mock.get(
        f'https://{MOCK_SERVER}/api/1_0/sensors/1/taskings/diff/2',
        json=MOCK_SENSOR_DIFF_RESPONSE_EMPTY
    )
    args: dict = {'sensor_id': '1', 'version': '2', 'timeout': '200'}
    command_results_list = analyst1_get_sensor_diff(mock_client, args)
    assert command_results_list is not None
    # one entry for context and the rest for added/removed
    assert_sensor_diff(command_results_list)
    # one for each IOC or hash found
    assert len(command_results_list[1].outputs) == 0
    assert len(command_results_list[2].outputs) == 0
    assert len(command_results_list[3].outputs) == 0
    assert len(command_results_list[4].outputs) == 0


def test_analyst1_get_sensor_config_command(requests_mock, mock_client):
    requests_mock.get(
        f'https://{MOCK_SERVER}/api/1_0/sensors/1/taskings/config',
        text='response text goes here'
    )
    args: dict = {'sensor_id': '1'}
    command_results = analyst1_get_sensor_config_command(mock_client, args)
    assert command_results is not None
    assert command_results.outputs_prefix == 'Analyst1.SensorTaskings.ConfigFile'
    assert command_results.outputs.get('warRoomEntry') is not None
    # json expectation adds quotes, anomaly of unit testing
    assert command_results.outputs.get('config_text') == 'response text goes here'


def test_perform_test_request_good(requests_mock, mock_client):
    requests_mock.get(
        f'https://{MOCK_SERVER}/api/1_0/',
        json=MOCK_TEST_REQUEST_GOOD
    )
    try:
        perform_test_module(mock_client)
    except DemistoException as e:
        raise AssertionError from e


def test_perform_test_request_invalid(requests_mock, mock_client):
    requests_mock.get(
        f'https://{MOCK_SERVER}/api/1_0/',
        json=MOCK_TEST_REQUEST_INVALID
    )
    try:
        perform_test_module(mock_client)
    except DemistoException as e:
        assert str(e) == 'Invalid URL or Credentials. JSON structure not recognized.'


def test_argsToStr():
    args: dict = {'sensor_id': '1'}
    assert argsToStr(args, 'sensor_id') == '1'
    assert argsToStr(args, 'unknown') == ''
