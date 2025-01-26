import demistomock as demisto
import pytest
from freezegun import freeze_time
from CommonServerPython import *
import json


MOCK_PARAMS = {
    'access-key': 'fake_access_key',
    'secret-key': 'fake_access_key',
    'url': 'http://123-fake-api.com/',
    'unsecure': True,
    'proxy': True,
    'assetsFetchInterval': '1440'
}

MOCK_RAW_VULN_BY_ASSET = {
    'vulnerabilities': [
        {
            'count': 117,
            'plugin_family': 'General',
            'plugin_id': 51292,
            'plugin_name': 'Fake Plugin Name',
            'vulnerability_state': 'Resurfaced',
            'accepted_count': 0,
            'recasted_count': 0,
            'counts_by_severity': [
                {
                    'count': 117,
                    'value': 2
                }
            ],
            'severity': 2
        },
    ]
}

EXPECTED_VULN_BY_ASSET_RESULTS = [
    {
        'Id': 51292,
        'Name': 'Fake Plugin Name',
        'Severity': 'Medium',
        'Family': 'General',
        'VulnerabilityOccurences': 117,
        'VulnerabilityState': 'Resurfaced'
    }
]
MOCK_CLIENT_ARGS = {
    'base_url': MOCK_PARAMS['url'],
    'verify': True,
    'proxy': True,
    'ok_codes': (200,),
}


def util_load_json(file_path):
    with open(file_path, encoding='utf-8') as f:
        return json.loads(f.read())


MOCK_AUDIT_LOGS = util_load_json('test_data/mock_events.json')
MOCK_CHUNKS_STATUS = util_load_json('test_data/mock_chunks_status.json')
MOCK_CHUNKS_STATUS_PROCESSING = util_load_json('test_data/mock_chunks_status_processing.json')
MOCK_CHUNKS_STATUS_ERROR = util_load_json('test_data/mock_chunks_status_error.json')
MOCK_UUID = util_load_json('test_data/mock_export_uuid.json')
MOCK_CHUNK_CONTENT = util_load_json('test_data/mock_chunk_content.json')
BASE_URL = 'https://cloud.tenable.com'


def mock_demisto(mocker, mock_args=None):
    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, 'args', return_value=mock_args)
    mocker.patch.object(demisto, 'uniqueFile', return_value='file')
    mocker.patch.object(demisto, 'investigation', return_value={'id': 'id'})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'debug')


def test_get_scan_status(mocker, requests_mock):
    mock_demisto(mocker, {'scanId': '25'})
    requests_mock.get(MOCK_PARAMS['url'] + 'scans/25', json={'info': {'status': 'canceled'}})

    from Tenable_io import get_scan_status_command
    results = get_scan_status_command()

    entry_context = results['EntryContext']['TenableIO.Scan(val.Id && val.Id === obj.Id)']

    assert 'Scan status for 25' in results['HumanReadable']
    assert entry_context['Id'] == '25'
    assert entry_context['Status'] == 'canceled'


def test_get_vuln_by_asset(mocker, requests_mock):
    mock_demisto(mocker, {'hostname': 'fake.hostname'})
    requests_mock.get(MOCK_PARAMS['url'] + 'workbenches/assets', json={'assets': [{'id': 'fake_asset_id'}]})
    requests_mock.get(MOCK_PARAMS['url'] + 'workbenches/assets/fake_asset_id/vulnerabilities/',
                      json=MOCK_RAW_VULN_BY_ASSET)

    from Tenable_io import get_vulnerabilities_by_asset_command
    results = get_vulnerabilities_by_asset_command()

    actual_result = results['EntryContext']['TenableIO.Vulnerabilities']

    for k in actual_result[0]:
        assert EXPECTED_VULN_BY_ASSET_RESULTS[0][k] == actual_result[0][k]


def test_pause_scan_command(mocker, requests_mock):
    mock_demisto(mocker, {'scanId': '25'})
    requests_mock.get(MOCK_PARAMS['url'] + 'scans/25', json={'info': {'status': 'running'}})
    requests_mock.post(MOCK_PARAMS['url'] + 'scans/25/pause', json={'info': {'status': 'running'}})

    from Tenable_io import pause_scan_command

    results = pause_scan_command()
    entry_context = results[0]['EntryContext']['TenableIO.Scan(val.Id && val.Id === obj.Id)']

    assert 'scan was paused successfully' in results[0]['HumanReadable']
    assert entry_context['Id'] == '25'
    assert entry_context['Status'] == 'Pausing'


def test_resume_scan_command(mocker, requests_mock):
    mock_demisto(mocker, {'scanId': '25'})
    requests_mock.get(MOCK_PARAMS['url'] + 'scans/25', json={'info': {'status': 'paused'}})
    requests_mock.post(MOCK_PARAMS['url'] + 'scans/25/resume', json={'info': {'status': 'paused'}})
    from Tenable_io import resume_scan_command

    results = resume_scan_command()
    entry_context = results[0]['EntryContext']['TenableIO.Scan(val.Id && val.Id === obj.Id)']

    assert 'scan was resumed successfully' in results[0]['HumanReadable']
    assert entry_context['Id'] == '25'
    assert entry_context['Status'] == 'Resuming'


def test_get_vulnerability_details_command(mocker, requests_mock):
    mock_demisto(mocker, {'vulnerabilityId': '1', 'dateRange': '3'})
    requests_mock.get(MOCK_PARAMS['url'] + 'workbenches/vulnerabilities/1/info',
                      json={'info': {'Id': '1'}})
    from Tenable_io import get_vulnerability_details_command

    results = get_vulnerability_details_command()
    entry_context = results['EntryContext']['TenableIO.Vulnerabilities']

    assert 'Vulnerability details' in results['HumanReadable']
    assert entry_context['Id'] == '1'


def test_get_scans_command(mocker, requests_mock):
    mock_demisto(mocker, {'folderId': '1'})
    requests_mock.get(MOCK_PARAMS['url'] + 'scans/?folder_id=1',
                      json={'scans': [{'status': 'running', 'id': '1'}],
                            'info': {'id': '1'}})
    requests_mock.get(MOCK_PARAMS['url'] + 'scans/1', json={'info': {'status': 'paused'}})

    from Tenable_io import get_scans_command

    results = get_scans_command()
    entry_context = results[0]['EntryContext']['TenableIO.Scan(val.Id && val.Id === obj.Id)']

    assert 'Tenable.io - List of Scans' in results[0]['HumanReadable']
    assert entry_context[0]['Id'] == '1'


def test_launch_scan_command(mocker, requests_mock):
    mock_demisto(mocker, {'scanId': '1', 'scanTargets': 'target1,target2'})
    requests_mock.get(MOCK_PARAMS['url'] + 'scans/1', json={'info': {'status': 'paused'}})
    requests_mock.post(MOCK_PARAMS['url'] + 'scans/1/launch',
                       json={})

    from Tenable_io import launch_scan_command

    results = launch_scan_command()
    entry_context = results['EntryContext']['TenableIO.Scan(val.Id && val.Id === obj.Id)']

    assert 'The requested scan was launched successfully' in results['HumanReadable']
    assert entry_context['Id'] == '1'


def test_get_asset_details_command(mocker, requests_mock):

    from test_data.response_and_results import MOCK_RAW_ASSET_BY_IP
    from test_data.response_and_results import MOCK_RAW_ASSET_ATTRIBUTES
    from test_data.response_and_results import EXPECTED_ASSET_INFO_RESULTS

    mock_demisto(mocker, {'ip': '1.3.2.1'})
    requests_mock.get(f"{MOCK_PARAMS['url']}workbenches/assets", json={'assets': [{'id': 'fake_asset_id'}]})
    requests_mock.get(f"{MOCK_PARAMS['url']}workbenches/assets/fake_asset_id/info",
                      json=MOCK_RAW_ASSET_BY_IP)
    requests_mock.get(f"{MOCK_PARAMS['url']}api/v3/assets/fake_asset_id/attributes",
                      json=MOCK_RAW_ASSET_ATTRIBUTES)

    from Tenable_io import get_asset_details_command

    response = get_asset_details_command()

    assert response.outputs == EXPECTED_ASSET_INFO_RESULTS
    assert response.outputs_prefix == 'TenableIO.AssetDetails'
    assert response.outputs_key_field == 'id'


@pytest.mark.parametrize('range_str, expected_lower_range_bound,expected_upper_range_bound', [
    ('2.5-3', 2.5, 3),
    ('2.5-3.5', 2.5, 3.5),
    ('0.1-3', 0.1, 3),
    ('0.1 - 3', 0.1, 3),
    ('0-1', 'exception', 'exception'),
    ('3-100', 'exception', 'exception'),
    ('0', 'exception', 'exception'),
    ('3-0', 'exception', 'exception')
])
def test_validate_range(range_str, expected_lower_range_bound, expected_upper_range_bound):
    """
    Given:
        - range_str (str): A string that represents a range of values in format 2.5-3.0.
    When:
        - Running the validate_range function with vprScoreRange argument.
    Then:
        - Verify that validation range function works as expected.
    """
    from Tenable_io import validate_range

    if expected_lower_range_bound == expected_upper_range_bound == 'exception':
        err_msg = 'Please specify a valid vprScoreRange. The VPR values range is 0.1-10.0.'
        with pytest.raises(DemistoException, match=err_msg):
            lower_range_bound, upper_range_bound = validate_range(range_str)
    else:
        lower_range_bound, upper_range_bound = validate_range(range_str)
        assert lower_range_bound == expected_lower_range_bound
        assert upper_range_bound == expected_upper_range_bound


@freeze_time("2012-01-14", tz_offset=-4)
@pytest.mark.parametrize('date_str, expected_date', [
    ('1 day ago', 1326326400),
    ('2 days ago', 1326240000),
    ('1326232800', 1326232800)
])
def test_relational_date_to_epoch_date_format(date_str, expected_date):
    """
    Given:
        - date_str (str): A string that represents a date in epoch time or relational expression date.
    When:
        - Running the relational_date_to_epoch_date_format function.
    Then:
        - Verify date returned as epoch time as expected.
    """
    from Tenable_io import relational_date_to_epoch_date_format

    date = relational_date_to_epoch_date_format(date_str)

    assert date == expected_date


@pytest.mark.parametrize('args, expected_exception', [
    ({'vprScoreOperator': 'eq', 'vprScoreValue': '3.5', 'vprScoreRange': '3.5-3'},
     'Please specify only one of vprScoreRange or vprScoreOperator'),
    ({'vprScoreOperator': 'eq', 'vprScoreValue': '', 'vprScoreRange': ''}, 'Please specify vprScoreValue and vprScoreOperator'),
    ({'vprScoreOperator': '', 'vprScoreValue': '3.5', 'vprScoreRange': ''}, 'Please specify vprScoreValue and vprScoreOperator'),
])
def test_build_vpr_score_validation(args, expected_exception):
    """
    Given:
        - args (dict): args with vprScoreOperator,vprScoreValue and vprScoreRange.
    When:
        - Running the build_vpr_score_validation with vprScoreOperator,vprScoreValue and vprScoreRange arguments.
    Then:
        - Verify that validation function works as expected.
    """
    from Tenable_io import build_vpr_score
    with pytest.raises(DemistoException) as de:
        build_vpr_score(args)

    assert de.value.message == expected_exception


@pytest.mark.parametrize('args, expected_vpr_score', [
    ({'vprScoreOperator': 'equal', 'vprScoreValue': '3.5'}, {'eq': [3.5], 'neq': None, 'gt': None,
                                                             'lt': None, 'gte': None, 'lte': None}),
    ({'vprScoreOperator': 'not equal', 'vprScoreValue': '3.5'}, {'eq': None, 'neq': [3.5], 'gt': None,
                                                                 'lt': None, 'gte': None, 'lte': None}),
    ({'vprScoreOperator': 'lt', 'vprScoreValue': '3.5'}, {'eq': None, 'neq': None, 'gt': None,
                                                          'lt': 3.5, 'gte': None, 'lte': None}),
    ({'vprScoreOperator': 'lte', 'vprScoreValue': '3.5'}, {'eq': None, 'neq': None, 'gt': None,
                                                           'lt': None, 'gte': None, 'lte': 3.5}),
    ({'vprScoreOperator': 'gt', 'vprScoreValue': '3.5'}, {'eq': None, 'neq': None, 'gt': 3.5,
                                                          'lt': None, 'gte': None, 'lte': None}),
    ({'vprScoreOperator': 'gte', 'vprScoreValue': '3.5'}, {'eq': None, 'neq': None, 'gt': None,
                                                           'lt': None, 'gte': 3.5, 'lte': None}),
    ({'vprScoreRange': '2 - 3.3'}, {'gte': 2.0, 'lte': 3.3}),
])
def test_build_vpr_score(args, expected_vpr_score):
    """
    Given:
        - args (dict): args with vprScoreOperator,vprScoreValue and vprScoreRange.
    When:
        - Running the build_vpr_score function with vprScoreOperator,vprScoreValue and vprScoreRange arguments.
    Then:
        - Verify that build_vpr_score function works as expected.
    """
    from Tenable_io import build_vpr_score
    vpr_score = build_vpr_score(args)

    assert vpr_score == expected_vpr_score


def test_export_assets_build_command_result():
    """
    Given:
        - export_assets_response (list[dict]): An API response from Tenable.io.
    When:
        - Running the export_assets_build_command_result function.
    Then:
        - Verify command result values as expected.
    """
    from test_data.response_and_results import export_assets_response
    from Tenable_io import export_assets_build_command_result
    command_result = export_assets_build_command_result(export_assets_response)

    assert command_result.outputs == export_assets_response
    assert command_result.readable_output == '### Assets\n|ASSET ID|DNS NAME (FQDN)|SYSTEM TYPE|OPERATING SYSTEM|IPV4 ADDRESS|' \
                                             'NETWORK|FIRST SEEN|LAST SEEN|LAST LICENSED SCAN|SOURCE|TAGS|\n|' \
                                             '---|---|---|---|---|---|---|---|---|---|---|\n|' \
                                             ' XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX |' \
                                             ' some_fqdns | general-purpose | Linux Kernel 2.6 |' \
                                             ' 00.000.00.00 | Default | 2024-08-13T15:11:08.145Z ' \
                                             '| 2024-08-13T15:11:08.145Z | 2022-12-28T17:10:47.756Z |' \
                                             ' SOME_SCAN | some_key:test |\n'
    assert command_result.raw_response == export_assets_response


def test_export_vulnerabilities_build_command_result():
    """
    Given:
        - export_vulnerabilities_response (list[dict]): An API response from Tenable.io.
    When:
        - Running the export_vulnerabilities_build_command_result function.
    Then:
        - Verify command result values as expected.
    """
    from test_data.response_and_results import export_vulnerabilities_response
    from Tenable_io import export_vulnerabilities_build_command_result
    command_result = export_vulnerabilities_build_command_result(export_vulnerabilities_response)

    assert command_result.outputs == export_vulnerabilities_response
    assert command_result.readable_output == '### Vulnerabilities' \
                                             '\n|ASSET ID|ASSET NAME|IPV4 ADDRESS|OPERATING SYSTEM|SYSTEM TYPE|DNS NAME (FQDN)|' \
                                             'SEVERITY|PLUGIN ID|PLUGIN NAME|VULNERABILITY PRIORITY RATING|PROTOCOL|' \
                                             'PORT|FIRST SEEN|' \
                                             'LAST SEEN|DESCRIPTION|SOLUTION|\n|' \
                                             '---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n|' \
                                             ' XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX | some_hostname | 00.000.00.00 |' \
                                             ' Linux Kernel 2.6 | general-purpose | some_fqdn | info | 11111 | some_name |' \
                                             ' 5.2 | TCP | 21 | 2023-08-15T15:56:18.852Z | 2023-08-15T15:56:18.852Z |' \
                                             ' some_description | solution. |\n'
    assert command_result.raw_response == export_vulnerabilities_response


@pytest.mark.parametrize('args, return_value_export_request_with_export_uuid', [
    ({'chunkSize': '500'}, {"uuid": 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX', "status": 'PROCESSING'}),
    ({'chunkSize': '500', 'exportUuid': 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX'},
     {"uuid": 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX', "status": 'FINISHED', 'chunks_available': [1]})
])
def test_export_assets_command(mocker, args, return_value_export_request_with_export_uuid):
    """
    Given:
        - args (dict): Arguments passed down by the CLI (except from exportUuid) to provide in the HTTP request.
          return_value_export_request_with_export_uuid(dict): mock response from API.
    When:
        - Running the tenable-io-export-assets command.
    Then:
        - Verify that tenable-io-export-assets command works as expected.
    """
    from Tenable_io import export_assets_command
    import Tenable_io
    from test_data.response_and_results import export_assets_response
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported')
    mocker.patch.object(Tenable_io, 'export_request', return_value={"export_uuid": 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX'})
    mocker.patch.object(Tenable_io, 'export_request_with_export_uuid',
                        return_value={"export_uuid": 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX'})
    mocker.patch.object(Tenable_io, 'export_request_with_export_uuid',
                        return_value=return_value_export_request_with_export_uuid)
    mocker.patch.object(Tenable_io, 'get_chunks_request',
                        return_value=export_assets_response)
    mocker.patch.object(demisto, 'args',
                        return_value=args)
    response = export_assets_command(args)
    if not args.get('exportUuid'):
        assert response.readable_output == 'Waiting for export assets to finish...'
    else:
        assert response.outputs == export_assets_response
        assert response.readable_output == '### Assets\n|ASSET ID|DNS NAME (FQDN)|SYSTEM TYPE|OPERATING SYSTEM|IPV4 ADDRESS' \
                                           '|NETWORK|FIRST SEEN|LAST SEEN|LAST LICENSED SCAN|SOURCE|TAGS|\n|' \
                                           '---|---|---|---|---|---|---|---|---|---|---|\n|' \
                                           ' XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX | some_fqdns | general-purpose |' \
                                           ' Linux Kernel 2.6 | 00.000.00.00 | Default | 2024-08-13T15:11:08.145Z |' \
                                           ' 2024-08-13T15:11:08.145Z | 2022-12-28T17:10:47.756Z | SOME_SCAN | some_key:test |\n'
        assert response.raw_response == export_assets_response


@pytest.mark.parametrize('args, return_value_export_request_with_export_uuid', [
    ({'numAssets': '500'}, {"uuid": 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX', "status": 'PROCESSING'}),
    ({'numAssets': '500', 'exportUuid': 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX'},
     {"uuid": 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX', "status": 'FINISHED', 'chunks_available': [1]})
])
def test_export_vulnerabilities_command(mocker, args, return_value_export_request_with_export_uuid):
    """
    Given:
        - args (dict): Arguments passed down by the CLI (except from exportUuid) to provide in the HTTP request.
          return_value_export_request_with_export_uuid(dict): mock response from API.
    When:
        - Running the tenable-io-export-vulnerabilities command.
    Then:
        - Verify that tenable-io-export-vulnerabilities command works as expected.
    """
    from Tenable_io import export_vulnerabilities_command
    import Tenable_io
    from test_data.response_and_results import export_vulnerabilities_response
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)
    mocker.patch.object(Tenable_io, 'export_request', return_value={"export_uuid": 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX'})
    mocker.patch.object(Tenable_io, 'export_request_with_export_uuid',
                        return_value={"export_uuid": 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX'})
    mocker.patch.object(Tenable_io, 'export_request_with_export_uuid',
                        return_value=return_value_export_request_with_export_uuid)
    mocker.patch.object(Tenable_io, 'get_chunks_request',
                        return_value=export_vulnerabilities_response)
    mocker.patch.object(demisto, 'args',
                        return_value=args)
    response = export_vulnerabilities_command(args)
    if not args.get('exportUuid'):
        assert response.readable_output == 'Waiting for export vulnerabilities to finish...'
    else:
        assert response.outputs == export_vulnerabilities_response
        assert response.readable_output == '### Vulnerabilities' \
                                           '\n|ASSET ID|ASSET NAME|IPV4 ADDRESS|OPERATING SYSTEM|' \
                                           'SYSTEM TYPE|DNS NAME (FQDN)|SEVERITY|PLUGIN ID|PLUGIN NAME|' \
                                           'VULNERABILITY PRIORITY RATING|PROTOCOL|PORT|FIRST SEEN|LAST SEEN|' \
                                           'DESCRIPTION|SOLUTION|\n|' \
                                           '---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n|' \
                                           ' XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX | some_hostname |' \
                                           ' 00.000.00.00 | Linux Kernel 2.6 | general-purpose | some_fqdn |' \
                                           ' info | 11111 | some_name | 5.2 | TCP | 21 |' \
                                           ' 2023-08-15T15:56:18.852Z | 2023-08-15T15:56:18.852Z |' \
                                           ' some_description | solution. |\n'
        assert response.raw_response == export_vulnerabilities_response


@pytest.mark.parametrize(
    'args, expected_result',
    [
        # Test case 1: Basic input with limit and offset
        (
            {
                'sortFields': '',
                'sortOrder': 'asc',
                'excludeRollover': False,
                'limit': 10,
                'offset': 0
            },
            {
                'sort': '',
                'exclude_rollover': False,
                'limit': 10,
                'offset': 0,
            }
        ),
        # Test case 2: Sorting by a multiple fields in ascending order
        (
            {
                'sortFields': 'name,date,status',
                'sortOrder': 'asc',
                'excludeRollover': False,
            },
            {
                'sort': 'name:asc,date:asc,status:asc',
                'exclude_rollover': False,
                'limit': 50,
                'offset': 0
            }
        ),
        # Test case 3: Sorting by multiple fields in different orders
        (
            {
                'sortFields': 'name,date,status',
                'sortOrder': 'asc,desc,asc',
                'excludeRollover': False,
            },
            {
                'sort': 'name:asc,date:desc,status:asc',
                'exclude_rollover': False,
                'limit': 50,
                'offset': 0
            }
        )
    ]
)
def test_scan_history_params(args, expected_result):
    """
    Given:
        Case 1: Only sortOrder is defined (Default).
        Case 2: The sortFields has multiple values and sortOrder only one.
        Case 3: Both sort lists have multiple values.

    When:
        - Running the tenable-io-get-scan-history command.

    Then:
        Case 1: Return empty sort.
        Case 2: Sort all sortFields by sortOrder.
        Case 3: Match sortFields and sortOrder's values by index.
    """
    from Tenable_io import scan_history_params

    result = scan_history_params(args)

    assert result == expected_result


def test_list_scan_filters_command(mocker):
    '''
    Given:
        -  A request to list Tenable IO scan filters.

    When:
        - Running the "list-scan-filters" command.

    Then:
        - Verify that tenable-io-list-scan-filters command works as expected.
    '''
    from Tenable_io import list_scan_filters_command, Client

    test_data = util_load_json('test_data/list_scan_filters.json')

    request = mocker.patch.object(BaseClient, '_http_request', return_value=test_data['response_json'])
    mock_demisto(mocker)

    results = list_scan_filters_command(Client(**MOCK_CLIENT_ARGS))

    assert results.outputs == test_data['outputs']
    assert results.readable_output == test_data['readable_output']
    assert results.outputs_prefix == 'TenableIO.ScanFilter'
    assert results.outputs_key_field == 'name'

    request.assert_called_with(*test_data['called_with']['args'])


def test_get_scan_history_command(mocker):
    '''
    Given:
        -  A request to get Tenable IO scan history.

    When:
        - Running the "get-scan-history" command.

    Then:
        - Verify that tenable-io-get-scan-history command works as expected.
    '''
    from Tenable_io import get_scan_history_command, Client

    test_data = util_load_json('test_data/get_scan_history.json')

    request = mocker.patch.object(
        BaseClient, '_http_request', return_value=test_data['response_json'])
    mock_demisto(mocker)

    results = get_scan_history_command(test_data['args'], Client(**MOCK_CLIENT_ARGS))

    assert results.outputs_prefix == 'TenableIO.ScanHistory'
    assert results.outputs_key_field == 'id'
    assert results.outputs == test_data['outputs']
    assert results.readable_output == test_data['readable_output']

    request.assert_called_with(
        *test_data['called_with']['args'],
        **test_data['called_with']['kwargs'])


def test_initiate_export_scan(mocker):
    '''
    Given:
        - A request to export a scan report.

    When:
        - Running the "export-scan" command.

    Then:
        - Initiate an export scan request.
    '''

    from Tenable_io import initiate_export_scan, Client

    test_data = util_load_json('test_data/initiate_export_scan.json')
    mock_demisto(mocker)
    request = mocker.patch.object(
        BaseClient, '_http_request', return_value=test_data['response_json'])
    file = initiate_export_scan(test_data['args'], Client(**MOCK_CLIENT_ARGS))

    assert file == test_data['expected_file']
    request.assert_called_with(
        *test_data['called_with']['args'],
        **test_data['called_with']['kwargs'])


def test_download_export_scan(mocker):
    '''
    Given:
        - A request to export a scan report.

    When:
        - Running the "export-scan" command.

    Then:
        - Initiate an export scan request.
    '''
    from Tenable_io import Client

    mock_demisto(mocker)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported')
    request = mocker.patch.object(
        BaseClient, '_http_request', return_value=b'')

    result = Client(**MOCK_CLIENT_ARGS).download_export_scan('scan_id', 'file_id', 'HTML')

    assert result == {
        'Contents': '',
        'ContentsFormat': 'text',
        'Type': 9,
        'File': 'scan_scan_id_file_id.html',
        'FileID': 'file',
    }
    request.assert_called_with(
        'GET', 'scans/scan_id/export/file_id/download', resp_type='content')


@pytest.mark.parametrize(
    'args, response_json, message',
    [
        ({'scanId': '', 'format': 'HTML', 'filterSearchType': ''}, {},
         'The "chapters" field must be provided for PDF or HTML formats.'),
        ({'scanId': '', 'format': '', 'filterSearchType': ''}, {'status': 'error'},
         'Tenable IO encountered an error while exporting the scan report file.')
    ]
)
def test_export_scan_command_errors(mocker, args, response_json, message):
    '''
    Given:
        - A request to export a scan report.

    When:
        - Running the "export-scan" command in any of the following cases:
            - Case A: The "format" arg is HTML or PDF but "chapters" is not defined.
            - Case B: An export scan request has been made and the report status is "error" or unrecognized.

    Then:
        - Return an error.
    '''

    from Tenable_io import export_scan_command, Client

    mock_demisto(mocker)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported')
    mocker.patch.object(BaseClient, '_http_request', return_value=response_json)
    mocker.patch.object(Client, 'initiate_export_scan', return_value={'file': 'file_id'})

    with pytest.raises(DemistoException, match=message):
        export_scan_command(args, Client(**MOCK_CLIENT_ARGS))


@pytest.mark.parametrize(
    'args, expected_result',
    (
        (
            {
                'page': '10',
                'pageSize': '5',
                'limit': '50'
            },
            {
                'limit': 5,
                'offset': 45
            }
        ),
        (
            {
                'limit': '50',
                'page': '23'
            },
            {
                'limit': '50',
                'offset': 0
            }
        )
    )
)
def test_scan_history_pagination_params(args, expected_result):

    from Tenable_io import scan_history_pagination_params

    result = scan_history_pagination_params(args)

    assert result == expected_result


def test_get_audit_logs_command(mocker, requests_mock):
    """
    Given:
        - get-audit-logs command arguments.
    When:
        - Running the command tenable-get-audit-logs
    Then:
        - Verify that when a list of events exists, it will take the last timestamp
        - Verify that when there are no events yet (first fetch) the timestamp for all will be as the first fetch
    """
    from Tenable_io import get_audit_logs_command, Client
    mock_demisto(mocker)
    client = Client(base_url=BASE_URL, verify=False, headers={}, proxy=False)
    requests_mock.get(f'{BASE_URL}/audit-log/v1/events?limit=2', json=MOCK_AUDIT_LOGS)

    results, audit_logs = get_audit_logs_command(client, limit=2)

    assert len(audit_logs) == 3


def test_vulnerabilities_process(mocker, requests_mock):
    """
    Given:
        - vulnerabilities fetch interval.
    When:
        - Running the fetch vulnerabilities process running.
    Then:
        - Verify that fetch should run
        - Verify export uuid being updated in the integration context
        - Verify vulnerabilities returned and finished flag is up.
    """

    from Tenable_io import generate_export_uuid, handle_vulns_chunks, get_vulnerabilities_export_status, Client
    mock_demisto(mocker)
    client = Client(base_url=BASE_URL, verify=False, headers={}, proxy=False)
    requests_mock.post(f'{BASE_URL}/vulns/export', json=MOCK_UUID)
    requests_mock.get(f'{BASE_URL}/vulns/export/123/status', json=MOCK_CHUNKS_STATUS)
    requests_mock.get(f'{BASE_URL}/vulns/export/123/chunks/1', json=MOCK_CHUNK_CONTENT)
    last_run = {}

    generate_export_uuid(client, last_run=last_run)
    assert last_run.get('vuln_export_uuid') == '123'

    status = get_vulnerabilities_export_status(client, last_run)
    assert status == "FINISHED"
    assert last_run.get("vulns_available_chunks")

    vulnerabilities, last_run = handle_vulns_chunks(client, last_run)

    assert len(vulnerabilities) == 1


def test_fetch_audit_logs_no_duplications(mocker, requests_mock):
    """

    Given:
        - last run object and audit log response from API.
    When:
        - Running the fetch events process.
    Then:
        - Verify no duplicated audit logs are returned from the API.

    """
    from Tenable_io import fetch_events_command, Client
    mock_demisto(mocker)
    client = Client(base_url=BASE_URL, verify=False, headers={}, proxy=False)
    requests_mock.get(f'{BASE_URL}/audit-log/v1/events?f=date.gt:2022-09-20&limit=5000', json=MOCK_AUDIT_LOGS)
    last_run = {'last_fetch_time': '2022-09-20'}
    first_fetch = arg_to_datetime('3 days')
    audit_logs, new_last_run = fetch_events_command(client, first_fetch, last_run, 1)

    assert len(audit_logs) == 1
    assert audit_logs[0].get('id') == '1234'

    last_run.update({'index_audit_logs': 1, 'last_fetch_time': '2022-09-20'})
    audit_logs, new_last_run = fetch_events_command(client, first_fetch, last_run, 1)

    assert len(audit_logs) == 1
    assert audit_logs[0].get('id') == '12345'


@pytest.mark.parametrize(
    'dt_now, dt_start_date, audit_logs, last_index_fetched, new_last_index_fetched',
    [
        (datetime(2024, 1, 26), datetime(2024, 1, 25), [{}], 1, 0),
        (datetime(2024, 1, 26), datetime(2024, 1, 26), [{}], 1, 2),
        (datetime(2024, 1, 26), datetime(2024, 1, 26), [], 1, 1),
    ]
)
def test_set_index_audit_logs(dt_now: datetime, dt_start_date: datetime, audit_logs: List[dict], last_index_fetched: int,
                              new_last_index_fetched: int):
    """
    Given:
        - all the arguments are needed for the function
    When:
        - Running the set_index_audit_logs function.
    Then:
        - Verify the result is correct as expected by the logic which is written there.
    """
    from Tenable_io import set_index_audit_logs
    result = set_index_audit_logs(dt_now, dt_start_date, audit_logs, last_index_fetched)
    assert new_last_index_fetched == result


def test_test_module(requests_mock, mocker):
    """
    Given:
        - The client object.
    When:
        - Running the test_module function.
    Then:
        - Verify the result is ok as expected.
    """
    from Tenable_io import test_module, Client
    mock_demisto(mocker)
    client = Client(base_url=BASE_URL, verify=False, headers={}, proxy=False)
    requests_mock.get(f'{BASE_URL}/filters/scans/reports', json={})
    result = test_module(client, demisto.params())

    assert result == 'ok'


def test_fetch_assets(requests_mock):
    """
    Given:
        - assets fetch interval.
    When:
        - Running the fetch assets process running.
    Then:
        - Verify that fetch should run
        - Verify export uuid being updated in the integration context
        - Verify assets returned and finished flag is up.
    """
    from Tenable_io import generate_assets_export_uuid, handle_assets_chunks, get_asset_export_job_status, Client
    client = Client(base_url=BASE_URL, verify=False, headers={}, proxy=False)
    requests_mock.post(f'{BASE_URL}/assets/export', json={"export_uuid": "123"})
    requests_mock.get(f'{BASE_URL}/assets/export/123/status', json={"status": "FINISHED", "chunks_available": [1]})
    requests_mock.get(f'{BASE_URL}/assets/export/123/chunks/1', json=util_load_json('test_data/mock_assets_chunk.json'))
    last_run = {}

    generate_assets_export_uuid(client, last_run)
    assert last_run.get('assets_export_uuid') == '123'
    status = get_asset_export_job_status(client, last_run)
    assert status == "FINISHED"
    assert last_run.get("assets_available_chunks")
    assets, last_run = handle_assets_chunks(client, last_run)

    assert len(assets) == 2


FETCH_ASSETS_EXAMPLES = [
    # export uuid 111 is valid, assets are returned.
    (
        [{"id": "asset_id_one", "name": "asset_name_one"}],
        [{"id": "asset_id_one", "name": "asset_name_one"}],
        {}
    ),
    # export uuid 111 is not valid, so new export uuid 222 is generated
    (
        {'status': 404, 'message': 'Export expired or not found'},
        [],
        {'assets_export_uuid': '222', 'nextTrigger': '30', 'type': 1}
    ),
    # # export uuid is valid, but chunk is not valid.
    (
        {'status': 404, 'message': 'invalid chunk'},
        [],
        {'assets_export_uuid': '222', 'nextTrigger': '30', 'type': 1}
    )
]


@pytest.mark.parametrize('api_response, expected_assets, expected_last_run', FETCH_ASSETS_EXAMPLES)
def test_handle_assets_chunks(requests_mock, api_response, expected_assets, expected_last_run):
    """
    Given:
        - assets last run object, containing an expired export uuid.
    When:
        - Calling handle_assets_chunks method.
    Then:
        - Verify that new export uuid was generated.
        - lastrun object was updated.
    """
    from Tenable_io import handle_assets_chunks, Client
    client = Client(base_url=BASE_URL, verify=False, headers={}, proxy=False)
    requests_mock.get(f'{BASE_URL}/assets/export/111/chunks/1', json=api_response)
    requests_mock.post(f'{BASE_URL}/assets/export', json={"export_uuid": "222"})

    assets_last_run = {
        'assets_export_uuid': '111',
        'assets_available_chunks': [1],

    }

    assets, new_last_run = handle_assets_chunks(client, assets_last_run)

    assert assets == expected_assets
    assert new_last_run.get('assets_export_uuid') == expected_last_run.get('assets_export_uuid')
    assert new_last_run.get('assets_available_chunks') == expected_last_run.get('assets_available_chunks')
    assert new_last_run.get('nextTrigger') == expected_last_run.get('nextTrigger')
    assert new_last_run.get('type') == expected_last_run.get('type')
