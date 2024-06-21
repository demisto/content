import hashlib
import json
import os
from unittest import mock
import pytest
from pytest_mock import MockerFixture
from ThreatGridv2 import Client
from datetime import datetime
from CommonServerPython import *  # noqa: F401
'''MOCK PARAMETERS '''
API_TOKEN = "api_token"
'''CONSTANTS'''
BASE_URL = 'https://panacea.threatgrid.com'
API_VERSION2_URL = 'api/v2'
API_VERSION3_URL = 'api/v3'
URL_SHA256 = hashlib.sha256(b'http://test.com:80/').hexdigest()

DBOT_SCORE = Common.DBotScore(indicator='url_value',
                              indicator_type='url',
                              integration_name="ThreatGrid",
                              reliability=DBotScoreReliability.B,
                              score=Common.DBotScore.SUSPICIOUS)


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """

    with open(os.path.join('test_data', file_name),
              encoding='utf-8') as mock_file:
        return json.loads(mock_file.read())


FILE_ENTRY = {
    'filename': 'sample_id-report.html',
    'data': load_mock_response('sample_get.json')
}


@pytest.fixture(autouse=True)
def mock_client():

    return Client(base_url=BASE_URL,
                  api_token=API_TOKEN,
                  proxy=False,
                  verify=True)


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
@mock.patch('ThreatGridv2.fileResult', lambda filename, data: FILE_ENTRY)
def test_get_sample_command(requests_mock, mock_client, url, args, outputs):
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

    from ThreatGridv2 import get_sample_command

    mock_response = load_mock_response('sample_get.json')

    requests_mock.get(url=url, json=mock_response)

    result = get_sample_command(mock_client, args)

    if isinstance(result, dict):
        assert result.get('filename') == f'sample_id-{args["artifact"]}'
        assert result.get('data').get('id') == 'id'
        assert result.get('data').get('data').get('md5') == 'data_md5'
    else:
        assert result.outputs_prefix == outputs
        assert result.outputs.get("id") == 'data_id'
        assert result.outputs.get("md5") == 'data_md5'
        assert result.outputs.get("sha1") == 'data_sha1'
        assert result.outputs.get("status") == 'data_status'
        assert result.outputs.get("sha256") == 'data_sha256'


@pytest.mark.parametrize('url, args, outputs_prefix', [
    (f'/{API_VERSION2_URL}/ips/ip/samples', {
        'ip': 'ip',
        'command_name': 'threat-grid-ip-samples-list',
    }, 'ThreatGrid.IpAssociatedSample'),
    (f"/{API_VERSION2_URL}/urls/{URL_SHA256}/samples", {
        'url': 'http://test.com:80',
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
def test_list_associated_samples_command(requests_mock, mock_client, url, args,
                                         outputs_prefix):
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

    from ThreatGridv2 import list_associated_samples_command

    mock_response = load_mock_response('associated_samples_list.json')

    requests_mock.get(url=url, json=mock_response)

    result = list_associated_samples_command(mock_client, args)

    assert result.outputs_prefix == outputs_prefix
    assert result.outputs.get('samples')[0].get('sha256') == 'sha256'
    assert result.outputs.get('samples')[0].get(
        'filename') == 'data_samples[0]_filename'
    assert result.outputs.get('samples')[0].get(
        'details') == 'data_samples[0]_details'
    assert result.outputs.get('samples')[0].get(
        'login') == 'data_samples[0]_login'


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
    (f'/{API_VERSION2_URL}/samples/sample_id/analysis/network_streams/network_stream',
     {
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
def test_analysis_sample_command(requests_mock, mock_client, url, args,
                                 outputs_prefix):
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

    from ThreatGridv2 import analysis_sample_command

    mock_response = load_mock_response('sample_analysis.json')

    requests_mock.get(url=url, json=mock_response)

    result = analysis_sample_command(mock_client, args)

    assert result.outputs_prefix == f'ThreatGrid.{outputs_prefix}'
    assert result.outputs['items']['network']['ip1'][
        'ts'] == 'data_items_network_ip1_ts'
    assert result.outputs['items']['network']['ip2'][
        'ts'] == 'data_items_network_ip2_ts'
    assert result.outputs['items']['network']['ip3'][
        'ts'] == 'data_items_network_ip3_ts'


def test_analysis_sample_command_no_response(requests_mock, mock_client):
    """
    Given:
     - threat-grid-analysis-iocs-get called with sample_id
    When:
     - API call is made to get sample analysis data, but no response is returned.
    Then:
     - Ensure CommandResults contains a readable output indicating no results were found.
    """
    from ThreatGridv2 import analysis_sample_command

    url = f'/{API_VERSION2_URL}/samples/sample_id/analysis/annotations'
    args = {
        'sample_id': 'sample_id',
        'command_name': 'threat-grid-analysis-annotations-get'
    }

    requests_mock.get(url=url, json={})

    result = analysis_sample_command(mock_client, args)

    assert result.readable_output == '### No results were found for sample_id sample_id'


def test_get_rate_limit_command(requests_mock, mock_client):
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

    from ThreatGridv2 import get_rate_limit_command

    mock_response = load_mock_response('rate_limit.json')
    login = 'login'
    entity_type = 'user'
    url = f'/{API_VERSION3_URL}/users/{login}/rate-limit'

    requests_mock.get(url=url, json=mock_response)

    result = get_rate_limit_command(mock_client, {
        'login': login,
        'entity_type': entity_type,
    })

    assert result.outputs_prefix == 'ThreatGrid.RateLimit'
    assert result.outputs.get(
        'submissions-available') == 'user_submissions-available'
    assert result.outputs.get(
        'submission-wait-seconds') == 'data_user_submission-wait-seconds'
    assert result.outputs.get('submission-rate-limit') == []


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

    from ThreatGridv2 import who_am_i_command

    mock_response = load_mock_response('whoami.json')
    url = f'/{API_VERSION3_URL}/session/whoami'
    requests_mock.get(url=url, json=mock_response)
    result = who_am_i_command(mock_client, {})

    assert result.outputs_prefix == 'ThreatGrid.User'
    assert result.outputs.get('email') == 'data_email'
    assert result.outputs.get('api_key') == 'data_api_key'
    assert result.outputs.get('login') == 'data_login'
    assert result.outputs.get('role') == 'data_role'


def test_get_specific_feed_command(requests_mock, mock_client):
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

    from ThreatGridv2 import get_specific_feed_command

    mock_response = load_mock_response('specific_feed.json')
    feed_name = 'feed_name'
    output_type = 'output_type'
    url = f'/{API_VERSION3_URL}/feeds/{feed_name}.{output_type}'

    requests_mock.get(url=url, json=mock_response)

    result = get_specific_feed_command(
        mock_client, {
            'feed_name': feed_name,
            'output_type': output_type,
            'before': 'before',
            'after': 'after',
        })

    assert result.outputs_prefix == 'ThreatGrid.Feed'
    assert result.outputs[0].get('sample') == 'sample'
    assert result.outputs[1].get('sample_sha256') == 'sample_sha256'
    assert result.outputs[0].get('sample_sha1') == 'sample_sha1'
    assert result.outputs[0].get('sample_md5') == 'sample_md5'


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
def test_associated_command(requests_mock, mock_client, url, args,
                            outputs_prefix):
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

    from ThreatGridv2 import associated_command

    json_data = args['command_name'][12:].replace("-", "_")
    arg_name = args['command_name'].split('-')[2]
    arg_name_2 = args['command_name'].split('-')[4]

    mock_response = load_mock_response(f'{json_data}.json')

    requests_mock.get(url=url, json=mock_response)

    result = associated_command(mock_client, args)

    assert result.outputs_prefix == f'ThreatGrid.{outputs_prefix}'
    assert result.outputs.get(arg_name) == f'data_{arg_name}'
    assert result.outputs.get(arg_name_2)[0].get(
        'details') == 'data[0]_details'
    assert result.outputs.get(arg_name_2)[1].get(
        'details') == 'data[1]_details'


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

    from ThreatGridv2 import feeds_command

    mock_response = load_mock_response('feeds.json')

    requests_mock.get(url=url, json=mock_response)

    result = feeds_command(mock_client, args)

    assert result.outputs_prefix == f'ThreatGrid.{outputs_prefix}'
    assert result.outputs[0].get('ioc') == 'ioc'
    assert result.outputs[0].get('confidence') == 'confidence'
    assert result.outputs[0].get('severity') == 'severity'
    assert result.outputs[0].get('path') == 'path'
    assert result.outputs[0].get('sample_id') == 'sample_id'


def test_upload_sample_command(requests_mock, mock_client):
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

    from ThreatGridv2 import upload_sample_command

    mock_response = load_mock_response('sample_upload.json')

    url = f'/{API_VERSION2_URL}/samples'

    requests_mock.post(url=url, json=mock_response)

    result = upload_sample_command(mock_client, {
        'url': 'url',
        'private': True
    })

    assert result.outputs_prefix == 'ThreatGrid.Sample'
    assert result.outputs.get('id') == 'data_id'
    assert result.outputs.get('sha256') == 'data_sha256'
    assert result.outputs.get('status') == 'data_status'
    assert result.outputs.get('state') == 'data_state'
    assert result.outputs.get('private') is True


@pytest.mark.parametrize('url_prefix ,args, outputs_prefix', [
    (f"urls/{URL_SHA256}", {
        'command_name': 'threat-grid-url-search',
        'url': 'http://test.com:80',
    }, 'url'),
    ('ips/ip', {
        'command_name': 'threat-grid-ip-search',
        'ip': 'ip',
    }, 'ip'),
])
def test_search_command(requests_mock, mock_client, url_prefix, args,
                        outputs_prefix):
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

    from ThreatGridv2 import search_command

    mock_response = load_mock_response('search.json')
    requests_mock.get(url=f'/{API_VERSION2_URL}/{url_prefix}',
                      json=mock_response)

    result = search_command(mock_client, args)

    assert result.outputs_prefix == 'ThreatGrid.search'
    assert result.outputs_key_field == outputs_prefix
    assert result.outputs.get('items')[0].get(
        'result') == 'data_items[0]_result'
    assert result.outputs.get('items')[1].get(
        'result') == 'data_items[1]_result'
    assert result.outputs.get('items')[2].get(
        'result') == 'data_items[2]_result'


def test_search_submission_command(requests_mock, mock_client):
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

    from ThreatGridv2 import search_submission_command

    mock_response = load_mock_response('submission_search.json')

    url = f'/{API_VERSION2_URL}/search/submissions'

    requests_mock.get(url=url, json=mock_response)

    result = search_submission_command(mock_client, {})

    assert result.outputs_prefix == 'ThreatGrid.Sample'
    assert result.outputs[0].get('sample') == 'sample_id'
    assert result.outputs[0].get('md5') == 'data_md5'
    assert result.outputs[0].get('sha1') == 'data_sha1'
    assert result.outputs[0].get('filename') == 'data_filename'


@pytest.mark.parametrize('args,outputs_key_field', [({
    'command_name': 'ip',
    'ip': 'ip'
}, 'ip'), ({
    'command_name': 'url',
    'url': 'url'
}, 'url'), ({
    'command_name': 'domain',
    'domain': 'domain'
}, 'domain'), ({
    'command_name': 'file',
    'file': 'file'
}, 'md5')])
def test_reputation_command(
    requests_mock,
    mock_client,
    args,
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

    from ThreatGridv2 import reputation_command

    if args['command_name'] == 'ip':
        mock_response = load_mock_response('sample_analysis.json')
        requests_mock.get(
            url=f'/{API_VERSION2_URL}/samples/sample_id/analysis/annotations',
            json=mock_response)

    mock_response = load_mock_response('submission_search.json')

    url = f'/{API_VERSION2_URL}/search/submissions'

    requests_mock.get(url=url, json=mock_response)
    args.update({'reliability': DBotScoreReliability.B})
    result = reputation_command(mock_client, args)

    assert result[0].outputs_key_field == outputs_key_field


@pytest.mark.parametrize('date, output', [
    ('2022-01-21T12:09:33Z', False),
    (str(datetime.now()).split(" ")[0], True),
])
def test_is_day_diff_valid(date, output):
    """ Validate days diff.
    """
    from ThreatGridv2 import is_day_diff_valid
    result = is_day_diff_valid(date)
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

    from ThreatGridv2 import pagination
    limit, offset, _ = pagination(args)
    assert limit == outputs['limit']
    assert offset == outputs['offset']


def test_parse_url_indicator():
    """ Parse URL indicator.
    """
    from ThreatGridv2 import parse_url_indicator
    result = parse_url_indicator('url', DBOT_SCORE)

    assert result.outputs_key_field == 'url'
    assert result.outputs_prefix == 'ThreatGrid.URL'


def test_parse_domain_indicator():
    """ Parse domain indicator.
    """
    from ThreatGridv2 import parse_domain_indicator
    result = parse_domain_indicator('domain', DBOT_SCORE)

    assert result.outputs_key_field == 'domain'
    assert result.outputs_prefix == 'ThreatGrid.Domain'


@pytest.mark.parametrize('url', [
    'http://test.com:80',
    'https://test.com:80',
    'http://test.com',
    'test.com',
])
def test_validate_url_template(url):
    """ Parse domain indicator.
    """
    from ThreatGridv2 import validate_url_template
    result = validate_url_template(url)

    assert result == 'http://test.com:80/'


@pytest.mark.parametrize(
    "mock_raw_response, expected_exception",
    [
        ({"state": "fail"}, "Uploading test to ThreatGrid failed"),
    ],
)
def test_schedule_command_sample_upload_when_state_is_fail(
    mocker,
    mock_client,
    mock_raw_response: dict[str, str],
    expected_exception: str,
):
    """
    Given:
        - sample_id
    When:
        - run schedule_command function
    Then:
        - Ensure that when returned from the api the state is fail, an error is raised.
    """
    from ThreatGridv2 import schedule_command
    mocker.patch(
        "ThreatGridv2.sample_state_get_command",
        return_value=CommandResults(
            raw_response=mock_raw_response
        )
    )
    with pytest.raises(DemistoException, match=expected_exception):
        schedule_command({"sample_id": "test"}, mock_client)


@pytest.mark.parametrize(
    "files, payload, expected_call",
    [
        (None, {"url": "test"}, {"files": None, "data": {"url": "test"}, "params": {}}),
        (
            "test",
            None,
            {"files": "test", "data": {"api_key": "api_key_test", 'classify': True}, "params": {}},
        ),
    ],
)
def test_upload_sample_method(
    mocker: MockerFixture,
    mock_client,
    files,
    payload: dict[str, str],
    expected_call: dict[str, str],
):
    """
    Given:
        - files or urls
    When:
        - run `upload_sample` method
    Then:
        - Ensure that when the sample is a file, the data request contains the `api_key`
        - Ensure that when the sample is a file the `Authorization` header not in `client._headers`
    """
    mock_func = mocker.patch.object(mock_client, "_http_request")
    mock_client.api_key = "api_key_test"
    mock_client.upload_sample(files=files, payload=payload)
    assert mock_func.call_args[1] == expected_call
    assert "Authorization" not in mock_client._headers if files else True
