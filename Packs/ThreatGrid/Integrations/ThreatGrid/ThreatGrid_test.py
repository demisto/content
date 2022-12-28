import hashlib
import json
import os
import pytest
from ThreatGrid import Client
from datetime import datetime
from CommonServerPython import *  # noqa: F401
'''MOCK PARAMETERS '''
API_TOKEN = "api_token"
'''CONSTANTS'''
BASE_URL = 'https://panacea.threatgrid.com'
API_VERSION2_URL = 'api/v2'
API_VERSION3_URL = 'api/v3'
URL_SHA256 = hashlib.sha256('url'.encode('utf-8')).hexdigest()


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """

    with open(os.path.join('test_data', file_name), mode='r', encoding='utf-8') as mock_file:
        return json.loads(mock_file.read())


@pytest.fixture(autouse=True)
def mock_client():

    return Client(base_url=BASE_URL, api_token=API_TOKEN, proxy=False, verify=True)


@pytest.mark.parametrize('url, args, outputs', [
    (f'/{API_VERSION2_URL}/samples/sample_id', {
        'sample_id': 'sample_id',
        'command_name': 'threat-grid-sample-list'
    }, 'ThreatGrid.Sample'),
    (f'/{API_VERSION2_URL}/samples/sample_id/report.html', {
        'sample_id': 'sample_id',
        'artifact': 'report.html',
        'command_name': 'threat-grid-sample-list'
    }, 'ThreatGrid.Sample'),
    (f'/{API_VERSION2_URL}/samples/sample_id/summary', {
        'sample_id': 'sample_id',
        'command_name': 'threat-grid-sample-summary-get'
    }, 'ThreatGrid.SampleAnalysisSummary'),
    (f'/{API_VERSION2_URL}/samples', {
        'offset': 1,
        'limit': 2,
        'command_name': 'threat-grid-sample-list'
    }, 'ThreatGrid.Sample'),
])
def test_sample_get_command(requests_mock, mock_client, url, args, outputs):
    """
    Scenario: Retrieves the Sample Info record of a submission by sample ID.
    Given:
     - User has provided valid credentials.
    When:
     - threat-grid-sample-list called.
     - threat-grid-sample-summary-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from ThreatGrid import sample_get_command

    mock_response = load_mock_response('sample_get.json')

    requests_mock.get(url=url, json=mock_response)

    result = sample_get_command(mock_client, args)

    if isinstance(result, dict):
        assert result.get('File') == f'sample_id-{args["artifact"]}'
    else:
        assert result.outputs_prefix == outputs
        assert result.outputs['id'] == 'data_id'  # type: ignore[assignment]


@pytest.mark.parametrize('url, args, outputs_prefix', [
    (f'/{API_VERSION2_URL}/ips/ip/samples', {
        'ip': 'ip',
        'command_name': 'threat-grid-ip-samples-list',
    }, 'ThreatGrid.IpAssociatedSample'),
    (f"/{API_VERSION2_URL}/urls/{URL_SHA256}/samples", {
        'url': 'url',
        'command_name': 'threat-grid-url-samples-list',
    }, 'ThreatGrid.UrlAssociatedSample'),
    (f'/{API_VERSION2_URL}/domains/domain/samples', {
        'domain': 'domain',
        'command_name': 'threat-grid-domain-samples-list'
    }, 'ThreatGrid.DomainAssociatedSample'),
    (f'/{API_VERSION2_URL}/registry_keys/registry_key/samples', {
        'registry_key': 'registry_key',
        'command_name': 'threat-grid-registry-key-samples-list'
    }, 'ThreatGrid.RegistryKeyAssociatedSample'),
    (f'/{API_VERSION2_URL}/paths/path/samples', {
        'offset': 1,
        'limit': 2,
        'path': 'path',
        'command_name': 'threat-grid-path-samples-list'
    }, 'ThreatGrid.PathAssociatedSample'),
])
def test_associated_samples_list_command(requests_mock, mock_client, url, args, outputs_prefix):
    """
    Scenario: Returns a list of samples associated to the
        domain / IP / URL / path / artifact / registry key that specified.
    Given:
     - User has provided valid credentials.
    When:
     - threat-grid-domain-samples-list called.
     - threat-grid-ip-samples-list called.
     - threat-grid-url-samples-list called.
     - threat-grid-registry-key-samples-list called.
     - threat-grid-path-samples-list called.

    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from ThreatGrid import associated_samples_list_command

    mock_response = load_mock_response('associated_samples_list.json')

    requests_mock.get(url=url, json=mock_response)

    result = associated_samples_list_command(mock_client, args)

    assert result.outputs_prefix == outputs_prefix
    assert result.outputs['samples'][0]['sha256'] == 'sha256'  # type: ignore[assignment]


@pytest.mark.parametrize('url, args,outputs_prefix', [
    (f'/{API_VERSION2_URL}/samples/sample_id/analysis/annotations', {
        'sample_id': 'sample_id',
        'command_name': 'threat-grid-analysis-annotations-get'
    }, 'SampleAnnotations'),
    (f'/{API_VERSION2_URL}/samples/sample_id/analysis/artifacts/artifact', {
        'sample_id': 'sample_id',
        'artifact_id': 'artifact',
        'command_name': 'threat-grid-analysis-artifacts-get'
    }, 'ArtifactAnalysis'),
    (f'/{API_VERSION2_URL}/samples/sample_id/analysis/iocs', {
        'sample_id': 'sample_id',
        'ioc': 'ioc',
        'command_name': 'threat-grid-analysis-iocs-get'
    }, 'IOCAnalysis'),
    (f'/{API_VERSION2_URL}/samples/sample_id/analysis/metadata', {
        'sample_id': 'sample_id',
        'command_name': 'threat-grid-analysis-metadata-get'
    }, 'AnalysisMetadata'),
    (f'/{API_VERSION2_URL}/samples/sample_id/analysis/network_streams/network_stream', {
        'sample_id': 'sample_id',
        'network_stream_id': 'network_stream',
        'command_name': 'threat-grid-analysis-network-streams-get'
    }, 'NetworkAnalysis'),
    (f'/{API_VERSION2_URL}/samples/sample_id/analysis/processes/process_id', {
        'sample_id': 'sample_id',
        'process_id': 'process_id',
        'command_name': 'threat-grid-analysis-processes-get'
    }, 'ProcessAnalysis'),
])
def test_sample_analysis_command(requests_mock, mock_client, url, args, outputs_prefix):
    """
    Scenario: Get data about a specific IOC / processes / artifact / network-stream
        from the relevant section of the sample's analysis.json.
    Given:
     - User has provided valid credentials.
    When:
     - threat-grid-analysis-annotations-get called.
     - threat-grid-analysis-artifacts-get called.
     - threat-grid-analysis-iocs-get called.
     - threat-grid-analysis-metadata-get called.
     - threat-grid-analysis-network-streams-get called.
     - threat-grid-analysis-processes-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from ThreatGrid import sample_analysis_command

    mock_response = load_mock_response('sample_analysis.json')

    requests_mock.get(url=url, json=mock_response)

    result = sample_analysis_command(mock_client, args)

    assert result.outputs_prefix == f'ThreatGrid.{outputs_prefix}'


def test_rate_limit_get_command(requests_mock, mock_client):
    """
    Scenario: Get rate limit for a specific user name.
    Given:
     - User has provided valid credentials.
    When:
     - threat-grid-rate-limit-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from ThreatGrid import rate_limit_get_command

    mock_response = load_mock_response('rate_limit.json')
    login = 'login'
    entity_type = 'user'
    url = f'/{API_VERSION3_URL}/users/{login}/rate-limit'

    requests_mock.get(url=url, json=mock_response)

    result = rate_limit_get_command(mock_client, {
        'login': login,
        'entity_type': entity_type,
    })

    assert result.outputs_prefix == 'ThreatGrid.RateLimit'
    assert result.outputs[
        'submissions-available'] == 'user_submissions-available'  # type: ignore[assignment]


def test_who_am_i_command(requests_mock, mock_client):
    """
    Scenario: Get all access lease.
    Given:
     - User has provided valid credentials.
    When:
     - dome9-access-lease-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from ThreatGrid import who_am_i_command

    mock_response = load_mock_response('whoami.json')
    url = f'/{API_VERSION3_URL}/session/whoami'
    requests_mock.get(url=url, json=mock_response)
    result = who_am_i_command(mock_client, {})

    assert result.outputs_prefix == 'ThreatGrid.User'
    assert result.outputs['email'] == 'data_email'  # type: ignore[assignment]


def test_specific_feed_get_command(requests_mock, mock_client):
    """
    Scenario: Gets a specific threat feed.
    Given:
     - User has provided valid credentials.
    When:
     - threat-grid-feed-specific-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from ThreatGrid import specific_feed_get_command

    mock_response = load_mock_response('specific_feed.json')
    feed_name = 'feed_name'
    output_type = 'output_type'
    url = f'/{API_VERSION3_URL}/feeds/{feed_name}.{output_type}'

    requests_mock.get(url=url, json=mock_response)

    result = specific_feed_get_command(mock_client, {
        'feed_name': feed_name,
        'output_type': output_type,
        'before': 'before',
        'after': 'after',
    })

    assert result.outputs_prefix == 'ThreatGrid.Feed'
    assert result.outputs[0]['sample'] == 'sample'  # type: ignore[assignment]


@pytest.mark.parametrize('url, args, outputs_prefix', [
    (f'/{API_VERSION2_URL}/domains/domain/ips', {
        'domain': 'domain',
        'command_name': 'threat-grid-domain-associated-ips'
    }, 'DomainAssociatedIp'),
    (f'/{API_VERSION2_URL}/domains/domain/urls', {
        'domain': 'domain',
        'command_name': 'threat-grid-domain-associated-urls'
    }, 'DomainAssociatedUrl'),
    (f'/{API_VERSION2_URL}/ips/ip/domains', {
        'ip': 'ip',
        'command_name': 'threat-grid-ip-associated-domains',
    }, 'IpAssociatedDomain'),
    (f'/{API_VERSION2_URL}/ips/ip/urls', {
        'ip': 'ip',
        'command_name': 'threat-grid-ip-associated-urls',
    }, 'IpAssociatedUrl'),
])
def test_associated_command(requests_mock, mock_client, url, args, outputs_prefix):
    """
    Scenario: Returns a list of domains / URLs associated with the IP or
        list of IPs / URLs associated with the domain.
    Given:
     - User has provided valid credentials.
    When:
     - threat-grid-domain-associated-ips called.
     - threat-grid-domain-associated-urls called.
     - threat-grid-ip-associated-domains called.
     - threat-grid-ip-associated-urls called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from ThreatGrid import associated_command

    json_data = args['command_name'][12:].replace("-", "_")
    arg_name = args['command_name'].split('-')[2]

    mock_response = load_mock_response(f'{json_data}.json')

    requests_mock.get(url=url, json=mock_response)

    result = associated_command(mock_client, args)

    assert result.outputs_prefix == f'ThreatGrid.{outputs_prefix}'
    assert result.outputs[arg_name] == f'data_{arg_name}'  # type: ignore[assignment]


@pytest.mark.parametrize('url, args, outputs_prefix', [
    (f'/{API_VERSION2_URL}/iocs/feeds/urls', {
        'url': 'url',
        'command_name': 'threat-grid-feeds-url',
        'limit': 2,
    }, 'Url'),
    (f'/{API_VERSION2_URL}/iocs/feeds/network_streams', {
        'network_stream': 'network_stream',
        'command_name': 'threat-grid-feeds-network-stream'
    }, 'NetworkStreams'),
    (f'/{API_VERSION2_URL}/iocs/feeds/paths', {
        'path': 'path',
        'command_name': 'threat-grid-feeds-path',
    }, 'Path'),
    (f'/{API_VERSION2_URL}/iocs/feeds/ips', {
        'ip': 'ip',
        'command_name': 'threat-grid-feeds-ip'
    }, 'Ip'),
    (f'/{API_VERSION2_URL}/iocs/feeds/domains', {
        'domain': 'domain',
        'command_name': 'threat-grid-feeds-domain',
    }, 'Domain'),
    (f'/{API_VERSION2_URL}/iocs/feeds/artifacts', {
        'artifact': 'artifact',
        'command_name': 'threat-grid-feeds-artifact',
    }, 'Artifact'),
])
def test_feeds_command(requests_mock, mock_client, url, args, outputs_prefix):
    """
    Scenario: Retrieves a list of domain / IP / URL / path / artifact /
        registry key that specified, associated with an Indicator of Compromise (IOC).

    Given:
     - User has provided valid credentials.
    When:
     - threat-grid-feeds-url called.
     - threat-grid-feeds-path called.
     - threat-grid-feeds-ip called.
     - threat-grid-feeds-domain called.
     - threat-grid-feeds-network-stream called.
     - threat-grid-feeds-artifact called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from ThreatGrid import feeds_command

    mock_response = load_mock_response('feeds.json')

    requests_mock.get(url=url, json=mock_response)

    result = feeds_command(mock_client, args)

    assert result.outputs_prefix == f'ThreatGrid.{outputs_prefix}'
    assert result.outputs[0]['ioc'] == 'data_items[0]_ioc'  # type: ignore[assignment]


def test_sample_upload_command(requests_mock, mock_client):
    """
    Scenario: Submits a sample to threat grid for analysis. URL or file, not both.
    Given:
     - User has provided valid credentials.
    When:
     - threat-grid-upload-sample called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from ThreatGrid import sample_upload_command

    mock_response = load_mock_response('sample_upload.json')

    url = f'/{API_VERSION2_URL}/samples'

    requests_mock.post(url=url, json=mock_response)

    result = sample_upload_command(mock_client, {'url': 'url'})

    assert result.outputs_prefix == 'ThreatGrid.Sample'
    assert result.outputs['id'] == 'data_id'  # type: ignore[assignment]


@pytest.mark.parametrize('url_prefix ,args, outputs_prefix', [
    (f"urls/{URL_SHA256}", {
        'command_name': 'threat-grid-url-search',
        'url': 'url',
    }, 'url'),
    ('ips/ip', {
        'command_name': 'threat-grid-ip-search',
        'ip': 'ip',
    }, 'ip'),
])
def test_search_command(requests_mock, mock_client, url_prefix, args, outputs_prefix):
    """
    Scenario: Search IPs / URLs.
    Given:
     - User has provided valid credentials.
    When:
     - threat-grid-url-search called.
     - threat-grid-ip-search called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from ThreatGrid import search_command

    mock_response = load_mock_response('search.json')
    requests_mock.get(url=f'/{API_VERSION2_URL}/{url_prefix}', json=mock_response)

    result = search_command(mock_client, args)

    assert result.outputs_prefix == 'ThreatGrid.search'
    assert result.outputs_key_field == outputs_prefix


def test_submission_search_command(requests_mock, mock_client):
    """
    Scenario: Search threat grid submissions.
    Given:
     - User has provided valid credentials.
    When:
     - threat-grid-search-submissions called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from ThreatGrid import submission_search_command

    mock_response = load_mock_response('submission_search.json')

    url = f'/{API_VERSION2_URL}/search/submissions'

    requests_mock.get(url=url, json=mock_response)

    result = submission_search_command(mock_client, {})

    assert result.outputs_prefix == 'ThreatGrid.Sample'
    assert result.outputs[0]['sample'] == 'sample_id'  # type: ignore[assignment]


@pytest.mark.parametrize('args,outputs_prefix,outputs_key_field', [({
    'command_name': 'ip',
    'ip': 'ip'
}, 'IP', 'indicator'), ({
    'command_name': 'url',
    'url': 'url'
}, 'URL', 'url'), ({
    'command_name': 'domain',
    'domain': 'domain'
}, 'Domain', 'domain'), ({
    'command_name': 'file',
    'file': 'file'
}, 'File', 'md5')])
def test_reputation_command(
    requests_mock,
    mock_client,
    args,
    outputs_prefix,
    outputs_key_field,
):
    """
    Scenario: Search threat grid submissions.
    Given:
     - User has provided valid credentials.
    When:
     - threat-grid-search-submissions called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from ThreatGrid import reputation_command

    if args['command_name'] == 'ip':
        mock_response = load_mock_response('sample_analysis.json')
        requests_mock.get(url=f'/{API_VERSION2_URL}/samples/sample_id/analysis/annotations',
                          json=mock_response)

    mock_response = load_mock_response('submission_search.json')

    url = f'/{API_VERSION2_URL}/search/submissions'

    requests_mock.get(url=url, json=mock_response)
    args.update({'reliability': DBotScoreReliability.B})
    result = reputation_command(mock_client, args)

    assert result[0].outputs_prefix == f'ThreatGrid.{outputs_prefix}'
    assert result[0].outputs_key_field == outputs_key_field


@pytest.mark.parametrize('date, output', [
    ('2022-01-21T12:09:33Z', False),
    (str(datetime.now()).split(" ")[0], True),
])
def test_validate_days_diff(date, output):
    """ Validate days diff.
    """
    from ThreatGrid import validate_days_diff
    result = validate_days_diff(date)
    assert result is output


@pytest.mark.parametrize('args, outputs', [
    ({
        'page': 1,
        'page_size': 2,
        'limit': 50,
    }, {
        'limit': 2,
        'offset': 0,
    }),
    ({
        'page': None,
        'page_size': None,
        'limit': 20,
    }, {
        'limit': 20,
        'offset': 0,
    }),
    ({
        'page': None,
        'page_size': None,
        'limit': 50,
    }, {
        'limit': 50,
        'offset': 0,
    }),
])
def test_pagination(args, outputs):
    """ Validate pagination args.

    Args:
        args (_type_): pagination args.
        outputs (_type_): pagination args required output.
    """

    from ThreatGrid import pagination
    limit, offset, _ = pagination(args)
    assert limit == outputs['limit']
    assert offset == outputs['offset']
