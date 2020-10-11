import pytest
from Analyst1 import *

MOCK_SERVER: str = 'mock.com'
MOCK_USER: str = 'mock'
MOCK_PASS: str = 'mock'
MOCK_INDICATOR: str = 'mock-indicator'

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
