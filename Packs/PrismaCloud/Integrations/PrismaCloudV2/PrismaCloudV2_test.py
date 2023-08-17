import pytest
from unittest.mock import patch
from freezegun import freeze_time

from CommonServerPython import *  # noqa: F401

from PrismaCloudV2 import Client
from test_data import input_data

AUTH_HEADER = 'auth_header'


@pytest.fixture
@patch('PrismaCloudV2.Client.generate_auth_token')
def prisma_cloud_v2_client(mocker):
    from PrismaCloudV2 import HEADERS, REQUEST_CSPM_AUTH_HEADER
    headers = HEADERS
    headers[REQUEST_CSPM_AUTH_HEADER] = AUTH_HEADER

    return Client(server_url='https://api.prismacloud.io/', verify=True, proxy=False, headers=headers,
                  username='username', password='password', mirror_direction=None, close_incident=False, close_alert=False)


''' COMMAND FUNCTIONS TESTS '''


def test_alert_filter_list_command(mocker, prisma_cloud_v2_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - prisma-cloud-alert-filter-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from PrismaCloudV2 import alert_filter_list_command
    http_request = mocker.patch.object(prisma_cloud_v2_client, '_http_request')
    alert_filter_list_command(prisma_cloud_v2_client)
    http_request.assert_called_with('GET', 'filter/alert/suggest')


def test_alert_search_command_no_next_token(mocker, prisma_cloud_v2_client):
    """
    Given:
        - All relevant arguments for the command that is executed without "next_token"
    When:
        - prisma-cloud-alert-search command is executed
    Then:
        - The http request is called with the right arguments
    """
    from PrismaCloudV2 import alert_search_command
    http_request = mocker.patch.object(prisma_cloud_v2_client, '_http_request')
    args = {'filters': 'alert.status=open,policy.remediable=true,cloud.type=gcp,policy.type=config',
            'limit': '10',
            'time_range_unit': 'week',
            'time_range_value': '3'}
    alert_search_command(prisma_cloud_v2_client, args)
    http_request.assert_called_with('POST', 'v2/alert', params={'detailed': 'true'},
                                    json_data={'limit': 10,
                                               'filters': [{'name': 'alert.status', 'operator': '=', 'value': 'open'},
                                                           {'name': 'policy.remediable', 'operator': '=', 'value': 'true'},
                                                           {'name': 'cloud.type', 'operator': '=', 'value': 'gcp'},
                                                           {'name': 'policy.type', 'operator': '=', 'value': 'config'}],
                                               'timeRange': {'type': 'relative', 'value': {'amount': 3, 'unit': 'week'}}})


def test_alert_search_command_with_next_token(mocker, prisma_cloud_v2_client):
    """
    Given:
        - All relevant arguments for the command that is executed with "next_token"
    When:
        - prisma-cloud-alert-search command is executed
    Then:
        - The http request is called with the right arguments
    """
    from PrismaCloudV2 import alert_search_command
    http_request = mocker.patch.object(prisma_cloud_v2_client, '_http_request')
    args = {'limit': '10',
            'time_range_unit': 'week',
            'time_range_value': '3',
            'next_token': 'TOKEN'}
    alert_search_command(prisma_cloud_v2_client, args)
    http_request.assert_called_with('POST', 'v2/alert', params={'detailed': 'true'},
                                    json_data={'limit': 10,
                                               'timeRange': {'type': 'relative', 'value': {'amount': 3, 'unit': 'week'}},
                                               'pageToken': 'TOKEN'})


def test_alert_get_details_command(mocker, prisma_cloud_v2_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - prisma-cloud-alert-get-details command is executed
    Then:
        - The http request is called with the right arguments
    """
    from PrismaCloudV2 import alert_get_details_command
    http_request = mocker.patch.object(prisma_cloud_v2_client, '_http_request')
    args = {'alert_id': 'P-123456'}
    alert_get_details_command(prisma_cloud_v2_client, args)
    http_request.assert_called_with('GET', 'alert/P-123456', params={'detailed': 'true'})


def test_alert_dismiss_command(mocker, prisma_cloud_v2_client):
    """
    Given:
        - All relevant arguments for the command that is executed when dismissing alert
    When:
        - prisma-cloud-alert-dismiss command is executed
    Then:
        - The http request is called with the right arguments
    """
    from PrismaCloudV2 import alert_dismiss_command
    http_request = mocker.patch.object(prisma_cloud_v2_client, '_http_request')
    args = {'alert_ids': 'P-123456', 'policy_ids': 'a11b2cc3-1111-2222-33aa-a1b23ccc4dd5', 'dismissal_note': 'from XSOAR',
            'time_range_unit': 'month'}
    alert_dismiss_command(prisma_cloud_v2_client, args)
    http_request.assert_called_with('POST', 'alert/dismiss',
                                    json_data={'alerts': ['P-123456'], 'policies': ['a11b2cc3-1111-2222-33aa-a1b23ccc4dd5'],
                                               'dismissalNote': 'from XSOAR',
                                               'filter': {'timeRange': {'type': 'to_now', 'value': 'month'}}},
                                    resp_type='response')


def test_alert_snooze_command(mocker, prisma_cloud_v2_client):
    """
    Given:
        - All relevant arguments for the command that is executed when snoozing alert
    When:
        - prisma-cloud-alert-dismiss command is executed
    Then:
        - The http request is called with the right arguments
    """
    from PrismaCloudV2 import alert_dismiss_command
    http_request = mocker.patch.object(prisma_cloud_v2_client, '_http_request')
    args = {'alert_ids': 'P-123456,P-111111', 'dismissal_note': 'from XSOAR', 'snooze_unit': 'hour', 'snooze_value': '1'}
    alert_dismiss_command(prisma_cloud_v2_client, args)
    http_request.assert_called_with('POST', 'alert/dismiss',
                                    json_data={'alerts': ['P-123456', 'P-111111'], 'dismissalNote': 'from XSOAR',
                                               'dismissalTimeRange': {'type': 'relative', 'value': {'amount': 1, 'unit': 'hour'}},
                                               'filter':
                                                   {'timeRange': {'type': 'relative', 'value': {'amount': 1, 'unit': 'hour'}}}},
                                    resp_type='response')


def test_alert_reopen_command(mocker, prisma_cloud_v2_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - prisma-cloud-alert-reopen command is executed
    Then:
        - The http request is called with the right arguments
    """
    from PrismaCloudV2 import alert_reopen_command
    http_request = mocker.patch.object(prisma_cloud_v2_client, '_http_request')
    args = {'policy_ids': 'a11b2cc3-1111-2222-33aa-a1b23ccc4dd5', 'filters': 'alert.status=dismissed',
            'time_range_date_from': '01/31/2023', 'time_range_date_to': '02/01/2023'}
    alert_reopen_command(prisma_cloud_v2_client, args)
    http_request.assert_called_with('POST', 'alert/reopen',
                                    json_data={'policies': ['a11b2cc3-1111-2222-33aa-a1b23ccc4dd5'],
                                               'dismissalTimeRange': {'type': 'absolute',
                                                                      'value': {'startTime': 1675123200000,
                                                                                'endTime': 1675209600000}},
                                               'filter': {'timeRange': {'type': 'absolute',
                                                                        'value': {'startTime': 1675123200000,
                                                                                  'endTime': 1675209600000}},
                                                          'filters': [
                                                              {'name': 'alert.status', 'operator': '=', 'value': 'dismissed'}]}},
                                    resp_type='response')


def test_remediation_command_list_command(mocker, prisma_cloud_v2_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - prisma-cloud-remediation-command-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from PrismaCloudV2 import remediation_command_list_command
    http_request = mocker.patch.object(prisma_cloud_v2_client, '_http_request')
    args = {'policy_id': 'a11b2cc3-1111-2222-33aa-a1b23ccc4dd5'}
    remediation_command_list_command(prisma_cloud_v2_client, args)
    http_request.assert_called_with('POST', 'alert/remediation',
                                    json_data={'filter': {'timeRange': {'type': 'to_now', 'value': 'epoch'}},
                                               'policies': ['a11b2cc3-1111-2222-33aa-a1b23ccc4dd5']})


def test_alert_remediate_command(mocker, prisma_cloud_v2_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - prisma-cloud-alert-remediate command is executed
    Then:
        - The http request is called with the right arguments
    """
    from PrismaCloudV2 import alert_remediate_command
    http_request = mocker.patch.object(prisma_cloud_v2_client, '_http_request')
    args = {'alert_id': 'P-123456'}
    alert_remediate_command(prisma_cloud_v2_client, args)
    http_request.assert_called_with('PATCH', 'alert/remediation/P-123456', resp_type='response')


def test_config_search_command(mocker, prisma_cloud_v2_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - prisma-cloud-config-search command is executed
    Then:
        - The http request is called with the right arguments
    """
    from PrismaCloudV2 import config_search_command
    http_request = mocker.patch.object(prisma_cloud_v2_client, '_http_request')
    args = {'query': "config from cloud.resource where cloud.region = 'AWS Ohio' ", 'limit': '1'}
    config_search_command(prisma_cloud_v2_client, args)
    http_request.assert_called_with('POST', 'search/config',
                                    json_data={'limit': 1, 'query': "config from cloud.resource where cloud.region = 'AWS Ohio' ",
                                               'sort': [{'direction': 'desc', 'field': 'insertTs'}],
                                               'timeRange': {'type': 'to_now', 'value': 'epoch'}})


def test_event_search_command(mocker, prisma_cloud_v2_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - prisma-cloud-event-search command is executed
    Then:
        - The http request is called with the right arguments
    """
    from PrismaCloudV2 import event_search_command
    http_request = mocker.patch.object(prisma_cloud_v2_client, '_http_request')
    args = {'query': "event from cloud.audit_logs where cloud.type = 'aws'", 'limit': '5'}
    event_search_command(prisma_cloud_v2_client, args)
    http_request.assert_called_with('POST', 'search/event',
                                    json_data={'limit': 5, 'query': "event from cloud.audit_logs where cloud.type = 'aws'",
                                               'timeRange': {'type': 'to_now', 'value': 'epoch'}})


def test_network_search_command(mocker, prisma_cloud_v2_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - prisma-cloud-network-search command is executed
    Then:
        - The http request is called with the right arguments
    """
    from PrismaCloudV2 import network_search_command
    http_request = mocker.patch.object(prisma_cloud_v2_client, '_http_request')
    args = {'query': "network from vpc.flow_record where cloud.account = 'AWS Prod' AND "
                     "source.publicnetwork IN ( 'Suspicious IPs' ) AND bytes > 0 "}
    network_search_command(prisma_cloud_v2_client, args)
    http_request.assert_called_with('POST', 'search',
                                    json_data={'query': "network from vpc.flow_record where cloud.account = 'AWS Prod' AND "
                                                        "source.publicnetwork IN ( 'Suspicious IPs' ) AND bytes > 0 ",
                                               'timeRange': {'type': 'to_now', 'value': 'epoch'}})


def test_trigger_scan_command(mocker, prisma_cloud_v2_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - prisma-cloud-trigger-scan command is executed
    Then:
        - The http request is called with the right arguments
    """
    from PrismaCloudV2 import trigger_scan_command, HEADERS, REQUEST_CCS_AUTH_HEADER
    http_request = mocker.patch.object(prisma_cloud_v2_client, '_http_request')
    headers = HEADERS
    headers[REQUEST_CCS_AUTH_HEADER] = AUTH_HEADER
    trigger_scan_command(prisma_cloud_v2_client)
    http_request.assert_called_with('POST', 'code/api/v1/scans/integrations', headers=headers)


def test_error_file_list_command(mocker, prisma_cloud_v2_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - prisma-cloud-error-file-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from PrismaCloudV2 import error_file_list_command, HEADERS, REQUEST_CCS_AUTH_HEADER
    http_request = mocker.patch.object(prisma_cloud_v2_client, '_http_request')
    args = {'repository': 'name/Name', 'source_types': 'Github', 'limit': '10'}
    headers = HEADERS
    headers[REQUEST_CCS_AUTH_HEADER] = AUTH_HEADER
    error_file_list_command(prisma_cloud_v2_client, args)
    http_request.assert_called_with('POST', 'code/api/v1/errors/files',
                                    json_data={'repository': 'name/Name', 'sourceTypes': ['Github']},
                                    headers=headers)


def test_resource_get_command(mocker, prisma_cloud_v2_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - prisma-cloud-resource-get command is executed
    Then:
        - The http request is called with the right arguments
    """
    from PrismaCloudV2 import resource_get_command
    http_request = mocker.patch.object(prisma_cloud_v2_client, '_http_request')
    args = {'rrn': 'rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25'}
    resource_get_command(prisma_cloud_v2_client, args)
    http_request.assert_called_with('POST', 'resource', json_data={'rrn': 'rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25'})


def test_account_list_command(mocker, prisma_cloud_v2_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - prisma-cloud-account-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from PrismaCloudV2 import account_list_command
    http_request = mocker.patch.object(prisma_cloud_v2_client, '_http_request')
    args = {}
    account_list_command(prisma_cloud_v2_client, args)
    http_request.assert_called_with('GET', 'cloud', json_data={'excludeAccountGroupDetails': 'false'})


def test_account_status_get_command(mocker, prisma_cloud_v2_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - prisma-cloud-account-status-get command is executed
    Then:
        - The http request is called with the right arguments
    """
    from PrismaCloudV2 import account_status_get_command
    http_request = mocker.patch.object(prisma_cloud_v2_client, '_http_request', return_value=[{'name': 'Config', 'status': 'ok'}])
    args = {'account_ids': '222222333333'}
    account_status_get_command(prisma_cloud_v2_client, args)
    http_request.assert_called_with('GET', 'account/222222333333/config/status')


def test_account_owner_list_command(mocker, prisma_cloud_v2_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - prisma-cloud-account-owner-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from PrismaCloudV2 import account_owner_list_command
    http_request = mocker.patch.object(prisma_cloud_v2_client, '_http_request', return_value=['foo@test.com'])
    args = {'account_ids': '222222333333'}
    account_owner_list_command(prisma_cloud_v2_client, args)
    http_request.assert_called_with('GET', 'cloud/222222333333/owners')


def test_host_finding_list_command(mocker, prisma_cloud_v2_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - prisma-cloud-host-finding-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from PrismaCloudV2 import host_finding_list_command
    http_request = mocker.patch.object(prisma_cloud_v2_client, '_http_request')
    args = {'rrn': 'rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25',
            'finding_types': 'guard_duty_host,guard_duty_iam'}
    host_finding_list_command(prisma_cloud_v2_client, args)
    http_request.assert_called_with('POST', 'resource/external_finding',
                                    json_data={'rrn': 'rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25',
                                               'findingType': ['guard_duty_host', 'guard_duty_iam']})


def test_permission_list_command_no_next_token(mocker, prisma_cloud_v2_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - prisma-cloud-permission-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from PrismaCloudV2 import permission_list_command
    http_request = mocker.patch.object(prisma_cloud_v2_client, '_http_request')
    args = {'query': "config from iam where source.cloud.service.name = 'EC2'", 'limit': '2'}
    permission_list_command(prisma_cloud_v2_client, args)
    http_request.assert_called_with('POST', 'api/v1/permission',
                                    json_data={'limit': 2, 'query': "config from iam where source.cloud.service.name = 'EC2'"})


def test_permission_list_command_with_next_token(mocker, prisma_cloud_v2_client):
    """
    Given:
        - All relevant arguments for the command that is executed, with "next_token"
    When:
        - prisma-cloud-permission-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from PrismaCloudV2 import permission_list_command
    http_request = mocker.patch.object(prisma_cloud_v2_client, '_http_request')
    args = {'next_token': 'TOKEN', 'limit': '2'}
    permission_list_command(prisma_cloud_v2_client, args)
    http_request.assert_called_with('POST', 'api/v1/permission/page', json_data={'limit': 2, 'pageToken': 'TOKEN'})


''' HELPER FUNCTIONS TESTS '''


@pytest.mark.parametrize('dict_input, url_field, expected_result', (input_data.nested_url_field,
                                                                    input_data.outer_url_field,
                                                                    input_data.suffix_with_beginning_char,
                                                                    input_data.url_field_nonexistent))
def test_concatenate_url(prisma_cloud_v2_client, dict_input, url_field, expected_result):
    """
    Given:
        - A url entry in a dictionary, with the value of the suffix only
    When:
        - The url is about to be shown to the user
    Then:
        - Update the dictionary given with the url value as base and suffix
    """
    prisma_cloud_v2_client._concatenate_url(dict_input, url_field)
    assert dict_input == expected_result


@pytest.mark.parametrize('url_to_format, formatted_url', (('https://api.prismacloud.io', 'https://api.prismacloud.io/'),
                                                          ('https://app.prismacloud.io/', 'https://api.prismacloud.io/'),
                                                          ('https://other.prismacloud.io/', 'https://other.prismacloud.io/'),
                                                          ('https://app.prismacloud.io/app', 'https://api.prismacloud.io/app/'),
                                                          ))
def test_format_url(url_to_format, formatted_url):
    """
    Given:
        - URL is given in integration parameters
    When:
        - A command is executed
    Then:
        - The URL is changed to support API
    """
    from PrismaCloudV2 import format_url

    assert format_url(url_to_format) == formatted_url


def test_extract_nested_values():
    """
    Given:
        - A response with nested fields
    When:
        - Creating a human readable response
    Then:
        - The wanted nested fields are extracted
    """
    from PrismaCloudV2 import extract_nested_values

    readable_response = {'id': 'P-1234567', 'status': 'open', 'reason': 'NEW_ALERT', 'firstSeen': 1660654610830,
                         'lastSeen': 1660654610830, 'alertTime': 1660654610830, 'eventOccurred': 1660654610256,
                         'resource': {'id': '-123456712345679737', 'name': 'AssumeRole', 'account': 'MyAccount',
                                      'accountId': '123456797356',
                                      'regionId': 'us-east-1', 'resourceType': 'EVENT', 'data': {'country': 'USA'},
                                      'resourceDetailsAvailable': False}, 'triggeredBy': '188612342792',
                         'policy': {'remediable': False}}
    nested_headers = {'resource.name': 'Resource Name', 'resource.id': 'Resource ID', 'resource.account': 'Account',
                      'resource.accountId': 'Account ID', 'resource.resourceType': 'Resource Type',
                      'resource.data.country': 'Country', 'policy.remediable': 'Is Remediable', 'id': 'Alert ID'}

    extract_nested_values(readable_response, nested_headers)
    assert set(nested_headers.values()).issubset(set(readable_response.keys()))

    assert readable_response['Resource Name'] == 'AssumeRole'
    assert readable_response['Resource ID'] == '-123456712345679737'
    assert readable_response['Account'] == 'MyAccount'
    assert readable_response['Account ID'] == '123456797356'
    assert readable_response['Resource Type'] == 'EVENT'
    assert readable_response['Country'] == 'USA'
    assert readable_response['Is Remediable'] is False
    assert readable_response['Alert ID'] == 'P-1234567'


def test_extract_nested_values_nonexistent_key():
    """
    Given:
        - A response with nested fields, and nested headers that do not exist in it partly or fully
    When:
        - Creating a human readable response
    Then:
        - The wanted nested fields that exist partly are extracted with None, and that don't exist are not extracted
    """
    from PrismaCloudV2 import extract_nested_values

    readable_response = {'id': 'P-1234567', 'status': 'open', 'reason': 'NEW_ALERT', 'firstSeen': 1660654610830,
                         'lastSeen': 1660654610830, 'alertTime': 1660654610830, 'eventOccurred': 1660654610256,
                         'resource': {'id': '-123456712345679737', 'name': 'AssumeRole', 'account': 'MyAccount',
                                      'accountId': '123456797356',
                                      'regionId': 'us-east-1', 'resourceType': 'EVENT', 'data': {'country': 'USA'},
                                      'resourceDetailsAvailable': False}, 'triggeredBy': '188612342792'}
    nested_headers = {'resource.othername': 'Resource Other Name', 'nonexistent.b': 'b'}

    extract_nested_values(readable_response, nested_headers)
    assert readable_response.get('Resource Other Name') is None


def test_change_timestamp_to_datestring_in_dict():
    """
    Given:
        - A dictionary with timestamps values in time fields
    When:
        - Creating a human readable response
    Then:
        - The time fields are changed to datestrings
    """
    from PrismaCloudV2 import change_timestamp_to_datestring_in_dict

    response_with_timestamp = {'id': 'P-11111',
                               'status': 'open',
                               'reason': 'RESOURCE_UPDATED',
                               'policyId': 'a11b2cc3-1111-2222-33aa-a1b23ccc4dd5',
                               'firstSeen': 1557254018605,
                               'lastSeen': 1668017403014,
                               'alertTime': 1668017403014,
                               'lastUpdated': 1669196436771}
    response_with_datestring = {'id': 'P-11111',
                                'status': 'open',
                                'reason': 'RESOURCE_UPDATED',
                                'policyId': 'a11b2cc3-1111-2222-33aa-a1b23ccc4dd5',
                                'firstSeen': '2019-05-07T18:33:38Z',
                                'lastSeen': '2022-11-09T18:10:03Z',
                                'alertTime': '2022-11-09T18:10:03Z',
                                'lastUpdated': '2022-11-23T09:40:36Z'}
    change_timestamp_to_datestring_in_dict(response_with_timestamp)
    assert response_with_timestamp == response_with_datestring


@pytest.mark.parametrize('date_str, epoch_date', (('07/11/1998', 900115200000), ('now', 1000000130000)))
@freeze_time('2001-09-09 01:48:50 UTC')
def test_convert_date_to_unix(date_str, epoch_date):
    """
    Given:
        - A date in a human readable format
    When:
        - Creating a time filter for a request
    Then:
        - The date in milliseconds since epoch format is returned
    """
    from PrismaCloudV2 import convert_date_to_unix
    assert convert_date_to_unix(date_str) == epoch_date


@pytest.mark.parametrize('base_case, unit_value, amount_value, time_from, time_to, expected_output',
                         (input_data.only_unit_value,
                          input_data.unit_amount_and_unit_value,
                          input_data.only_time_to,
                          input_data.time_from_and_time_to,
                          input_data.use_given_base_case,
                          input_data.use_default_base_case,
                          ))
def test_handle_time_filter(base_case, unit_value, amount_value, time_from, time_to, expected_output):
    """
    Given:
        - Relevant time filter arguments given from the user
    When:
        - Creating the time filter for the request
    Then:
        - The right time filter is returned
    """
    from PrismaCloudV2 import handle_time_filter

    assert handle_time_filter(base_case, unit_value, amount_value, time_from, time_to) == expected_output


@pytest.mark.parametrize('base_case, unit_value, amount_value, time_from, time_to, expected_error',
                         (input_data.only_amount_value,
                          input_data.wrong_unit_value_relative,
                          input_data.wrong_unit_value_to_now,
                          input_data.only_time_from,
                          input_data.unit_amount_and_time_to,
                          input_data.unit_value_and_time_to,
                          ))
def test_handle_time_filter_error(base_case, unit_value, amount_value, time_from, time_to, expected_error):
    """
    Given:
        - Some time filter arguments given from the user, not the way they should
    When:
        - Creating the time filter for the request
    Then:
        - A relevant error is raised
    """
    from PrismaCloudV2 import handle_time_filter

    with pytest.raises(DemistoException) as de:
        handle_time_filter(base_case, unit_value, amount_value, time_from, time_to)
    assert de.value.message == expected_error


@pytest.mark.parametrize('input_filters,expected_parsed_filters', (input_data.with_filters,
                                                                   input_data.empty_filters))
def test_handle_filters(input_filters, expected_parsed_filters):
    """
    Given:
        - A list of filters given from the user, in the format of filtername=filtervalue
    When:
        - Creating the list of filters in the format that the request expects
    Then:
        - The returned list is in the right format
    """
    from PrismaCloudV2 import handle_filters

    filters = argToList(input_filters)
    parsed_filters = handle_filters(filters)
    assert parsed_filters == expected_parsed_filters


@pytest.mark.parametrize('filter_name', ('no_equal_sign', 'too=many=equal_signs', ' ', 'no_value= ', '=no_name'))
def test_handle_filters_error(filter_name):
    """
    Given:
        - A list of filters given from the user, in a wrong format
    When:
        - Creating the list of filters in the format that the request expects
    Then:
        - An error is raised with the name of the wrong filter
    """
    from PrismaCloudV2 import handle_filters

    filters = argToList(filter_name)
    with pytest.raises(DemistoException) as de:
        handle_filters(filters)
    assert de.value.message == f'Filters should be in the format of "filtername1=filtervalue1,filtername2=filtervalue2". ' \
                               f'The filter "{filters[0]}" doesn\'t meet this requirement.'


def test_handle_tags():
    """
    Given:
        - A list of tags given from the user, in the format of tagkey=tagvalue
    When:
        - Creating the list of tags in the format that the request expects
    Then:
        - The returned list is in the right format
    """
    from PrismaCloudV2 import handle_tags

    filters = argToList('Environment=local.resource_prefix.value')
    parsed_filters = handle_tags(filters)
    assert parsed_filters == [{'key': 'Environment', 'value': 'local.resource_prefix.value'}]


@pytest.mark.parametrize('tag_name', ('no_equal_sign', 'too=many=equal_signs', ' ', 'no_value= ', '=no_key'))
def test_handle_tags_error(tag_name):
    """
    Given:
        - A list of tags given from the user, in a wrong format
    When:
        - Creating the list of tags in the format that the request expects
    Then:
        - An error is raised with the name of the wrong tag
    """
    from PrismaCloudV2 import handle_tags

    filters = argToList(tag_name)
    with pytest.raises(DemistoException) as de:
        handle_tags(filters)
    assert de.value.message == f'Tags should be in the format of "tagkey1=tagvalue1,tagkey2=tagvalue2". ' \
                               f'The tag "{filters[0]}" doesn\'t meet this requirement.'


def test_validate_array_arg():
    """
    Given:
        - An array argument given from the user, one having right values and second having wrong values
    When:
        - Preparing for a request and checking that the provided arguments have the right values
    Then:
        - An error is raised only when an argument value that is not in the list of available options is found
    """
    from PrismaCloudV2 import validate_array_arg

    options = ['good', 'another_good', 'more_good']
    validate_array_arg(argToList('good,another_good'), 'Good Name', options)  # should just pass
    with pytest.raises(DemistoException) as de:
        validate_array_arg(argToList('more_good,bad,good'), 'Bad Name', options)
    assert de.value.message == 'Bad Name values are unexpected, must be of the following: good, another_good, more_good.'


def test_remove_empty_values():
    """
    Given:
        - A dictionary to remove empty values from
    When:
        - Removing empty values from the given dict and from the nested dicts and lists in it
    Then:
        - The returned dictionary is the original dictionary without the empty values and nested values
    """
    from PrismaCloudV2 import remove_empty_values

    dict_input = {'empty1': [],
                  'empty2': None,
                  'empty3': False,
                  'empty4': {},
                  'empty5': '',
                  'empty6': {'v1': None, 'v2': [], 'v3': {}},
                  'empty7': {'v1': {'empty': {'nested_empty': None}}},
                  'empty8': [{'v1': None}, {'v2': ''}],
                  'with_value1': 'text',
                  'with_value2': ['v1', 'v2'],
                  'with_value3': {'v1', 'v2'},
                  'with_value4': {'v1': None, 'v2': 'v3'},
                  'with_value5': {'timeRange': {'type': 'to_now', 'value': 'epoch'},
                                  'filters': [{"name": "string1", "operator": "=", "value": "string1"},
                                              {"name": "string2", "operator": "=", "value": "string2"}],
                                  },
                  'with_value6': 'false',
                  }
    dict_expected_output = {'with_value1': 'text',
                            'with_value2': ['v1', 'v2'],
                            'with_value3': {'v1', 'v2'},
                            'with_value4': {'v2': 'v3'},
                            'with_value5': {
                                'timeRange': {'type': 'to_now', 'value': 'epoch'},
                                'filters': [{"name": "string1", "operator": "=", "value": "string1"},
                                            {"name": "string2", "operator": "=", "value": "string2"}]},
                            'with_value6': 'false',
                            }

    assert remove_empty_values(dict_input) == dict_expected_output


@pytest.mark.parametrize('page_size, page_number, offset', ((100, 1, 0),
                                                            (2, 2, 2),
                                                            (5, 3, 10),
                                                            ))
def test_calculate_offset(page_size, page_number, offset):
    """
    Given:
        - 'page_size' and 'page_number' arguments
    When:
        - A command that has paging is executed
    Then:
        - Returns the right offset that will be sent to the request
    """
    from PrismaCloudV2 import calculate_offset
    assert calculate_offset(page_size, page_number) == (page_size, offset)


''' FETCH HELPER FUNCTIONS TESTS '''


@pytest.mark.parametrize('given_alert, expected_severity', (({'policy': {'severity': 'high'}}, IncidentSeverity.HIGH),
                                                            ({'policy': {'severity': 'medium'}}, IncidentSeverity.MEDIUM),
                                                            ({'policy': {'severity': 'low'}}, IncidentSeverity.LOW),
                                                            ({'policy': {'severity': 'critical'}}, IncidentSeverity.CRITICAL),
                                                            ({'policy': {'severity': 'informational'}}, IncidentSeverity.INFO),
                                                            ({'policy': {'severity': 'other'}}, IncidentSeverity.UNKNOWN),
                                                            ({'policy': {}}, IncidentSeverity.UNKNOWN),
                                                            ({}, IncidentSeverity.UNKNOWN),
                                                            ))
def test_translate_severity(given_alert, expected_severity):
    """
    Given:
        - An alert with or without the severity of their policy
    When:
        - Fetching incident and creating the incident context from a given alert
    Then:
        - Returns the right severity for this alert
    """
    from PrismaCloudV2 import translate_severity
    assert translate_severity(given_alert) == expected_severity


def test_expire_stored_ids():
    """
    Given:
        - Fetched alerts IDs with their alert time
        - The next fetch run time according to the last alert time
        - The fetch look back time given from the user
    When:
        - Fetching incident and preparing the values to save for the next run
    Then:
        - Returns the fetched alerts IDs with their alert time, that their alert time will be fetched in the next fetch
    """
    from PrismaCloudV2 import expire_stored_ids, FETCH_LOOK_BACK_TIME
    updated_last_run_time = 1000000000000
    fetched_ids = {'N-111111': 1000000000000,  # same time
                   'P-222222': 999996400000,  # 1 hour before (FETCH_LOOK_BACK_TIME*3)
                   'P-333333': 999998800000,  # 20 minutes before
                   'P-444444': 999996340000,  # 61 minutes before
                   'N-555555': 999992800000,  # 2 hours before
                   'N-666666': 999996460000,  # 59 minutes before
                   }

    expected_fetched_ids = {'N-111111': 1000000000000,  # same time
                            'P-222222': 999996400000,  # 1 hour before
                            'P-333333': 999998800000,  # 20 minutes before
                            'N-666666': 999996460000,  # 59 minutes before
                            }
    assert expire_stored_ids(fetched_ids, updated_last_run_time, FETCH_LOOK_BACK_TIME) == expected_fetched_ids


@pytest.mark.parametrize('now, first_fetch, look_back, last_run_time, expected_fetch_time_range',
                         (input_data.start_at_first_fetch_default,
                          input_data.start_at_first_fetch,
                          input_data.start_at_first_fetch2,
                          input_data.start_at_last_run_time_with_look_back,
                          input_data.start_at_last_run_time,
                          ))
@freeze_time('2023-02-10 11:00:00 UTC')
def test_calculate_fetch_time_range(now, first_fetch, look_back, last_run_time, expected_fetch_time_range):
    """
    Given:
        - All relevant times to calculate the fetch time range
    When:
        - Creating the arguments for the fetch incidents request
    Then:
        - Returns the right fetch time range for the request
    """
    from PrismaCloudV2 import calculate_fetch_time_range
    assert calculate_fetch_time_range(now, first_fetch, look_back, last_run_time) == expected_fetch_time_range


@pytest.mark.parametrize('last_run_epoch_time, look_back_minutes, expected_epoch_time',
                         ((1676023200000, 20, 1676022000000),
                          (1676023200000, 60, 1676019600000),
                          (1676023200000, 0, 1676023200000),
                          ))
def test_add_look_back(last_run_epoch_time, look_back_minutes, expected_epoch_time):
    """
    Given:
        - Last run time and time in minutes to look back.
    When:
        - Creating the arguments for the fetch incidents request and calculating the time to start fetching from
    Then:
        - Returns the right fetch time with look back added to it
    """
    from PrismaCloudV2 import add_look_back
    assert add_look_back(last_run_epoch_time, look_back_minutes) == expected_epoch_time


@pytest.mark.parametrize('limit, request_results, expected_incidents, expected_fetched_ids, expected_updated_last_run_time',
                         (input_data.low_limit_for_request,
                          input_data.exactly_limit_for_request,
                          input_data.more_than_limit_for_request,
                          input_data.high_limit_for_request,
                          ))
@freeze_time('2001-09-09 01:49:00 UTC')
def test_fetch_request(mocker, prisma_cloud_v2_client, limit, request_results, expected_incidents, expected_fetched_ids,
                       expected_updated_last_run_time):
    """
    Given:
        - All needed arguments for the fetch request
    When:
        - Fetching incidents, doing the request and filtering the alerts got from Prisma Cloud
    Then:
        - Returns the incidents up to the limit given, the fetched IDs and the updated last run time according to the limit given
    """
    from PrismaCloudV2 import fetch_request

    mocker.patch.object(prisma_cloud_v2_client, '_http_request', side_effect=request_results)
    fetched_ids = {'P-111111': 1000000110000,
                   'P-222222': 999996400000}
    now = 1000000140000
    assert fetch_request(client=prisma_cloud_v2_client,
                         fetched_ids=fetched_ids,
                         filters=[],
                         limit=limit,
                         now=now,
                         time_range={'type': 'absolute', 'value': {'endTime': now, 'startTime': 1000000110000}}) == \
        (expected_incidents, expected_fetched_ids, expected_updated_last_run_time)


@pytest.mark.parametrize('limit, expected_incidents, expected_updated_fetched_ids',
                         (input_data.low_limit_for_filter,
                          input_data.exactly_limit_for_filter,
                          input_data.high_limit_for_filter,
                          ))
def test_filter_alerts(prisma_cloud_v2_client, limit, expected_incidents, expected_updated_fetched_ids):
    """
    Given:
        - The IDs that were already fetched, the items in the response from the request and the limit of incidents to return
    When:
        - Fetching incidents and filtering the alerts got from Prisma Cloud
    Then:
        - Returns the incidents up to the limit given, without those that were already fetched
    """
    from PrismaCloudV2 import filter_alerts

    fetched_ids = {'N-111111': 1000000000000,
                   'P-222222': 999996400000}
    response_items = [{'id': 'N-111111', 'alertTime': 1000000000000, 'policy': {'name': 'Policy One', 'severity': 'high'}},
                      input_data.truncated_alert6,
                      input_data.truncated_alert7]

    assert filter_alerts(prisma_cloud_v2_client, fetched_ids, response_items, limit) == expected_incidents
    assert fetched_ids == expected_updated_fetched_ids


@pytest.mark.parametrize('alert, expected_incident_context',
                         ((input_data.truncated_alert6, input_data.incident6),
                          (input_data.truncated_alert7, input_data.incident7),
                          (input_data.truncated_alert_no_policy, input_data.incident_no_policy),
                          (input_data.full_alert, input_data.full_incident),
                          ))
def test_alert_to_incident_context(prisma_cloud_v2_client, alert, expected_incident_context):
    """
    Given:
        - An alert as it was got in the response of the request to Prisma Cloud
    When:
        - Fetching incidents and creating XSOAR incidents out of them
    Then:
        - Returns the incident that was created from the alert given
    """
    from PrismaCloudV2 import alert_to_incident_context, add_mirroring_fields
    add_mirroring_fields(prisma_cloud_v2_client, alert)
    assert alert_to_incident_context(alert) == expected_incident_context


@pytest.mark.parametrize('last_run, params, incidents, fetched_ids, updated_last_run_time, '
                         'expected_fetched_ids, expected_updated_last_run_time',
                         (input_data.fetch_first_run,
                          input_data.fetch_no_incidents,
                          input_data.fetch_with_last_run,
                          input_data.fetch_with_expiring_ids))
@freeze_time('2001-09-09 01:48:50 UTC')
def test_fetch_incidents(mocker, prisma_cloud_v2_client, last_run, params, incidents, fetched_ids, updated_last_run_time,
                         expected_fetched_ids, expected_updated_last_run_time):
    """
    Given:
        - Last run data and parameters for the fetch request
    When:
        - Fetching incidents
    Then:
        - Returns the incidents up to the limit given, the fetched IDs and the updated last run time
        - The updated last run time is the later between the first fetch time and the alert time of the last fetched incident
    """
    from PrismaCloudV2 import fetch_incidents

    mocker.patch('PrismaCloudV2.fetch_request', return_value=(incidents, fetched_ids, updated_last_run_time))
    assert fetch_incidents(prisma_cloud_v2_client, last_run, params) == \
        (incidents, expected_fetched_ids, expected_updated_last_run_time)


''' MIRRORING FUNCTIONS TESTS '''


@pytest.fixture
@patch('PrismaCloudV2.Client.generate_auth_token')
def prisma_cloud_v2_mirroring_client(mocker):
    from PrismaCloudV2 import HEADERS, REQUEST_CSPM_AUTH_HEADER
    headers = HEADERS
    headers[REQUEST_CSPM_AUTH_HEADER] = AUTH_HEADER

    return Client(server_url='https://api.prismacloud.io/', verify=True, proxy=False, headers=headers,
                  username='username', password='password', mirror_direction="Incoming And Outgoing",
                  close_incident=True, close_alert=True)


def test_get_modified_remote_data_command(mocker, prisma_cloud_v2_mirroring_client):
    """
    Given
        - arguments - lastUpdate time.
        - raw prisma cloud alerts (alert_search_request raw response).
    When
        - Running the get_modified_remote_data_command.
    Then
        - Verify that the returned value is a list of incidents IDs that were modified since the lastUpdate time.
    """
    from PrismaCloudV2 import get_modified_remote_data_command
    mocker.patch('PrismaCloudV2.Client.alert_search_request', return_value={'items': input_data.alert_search_request_response})
    last_update = '2023-08-16T08:17:09Z'
    args = {'lastUpdate': last_update}
    params = {'filters': 'alert.status=open,alert.status=dismissed,alert.status=snoozed,alert.status=resolved'}

    result = get_modified_remote_data_command(client=prisma_cloud_v2_mirroring_client,
                                              args=args,
                                              params=params)

    assert result.modified_incident_ids == ['P-1111111', 'P-1111112', 'P-1111113']


@pytest.mark.parametrize('raw_response, expected_updated_object', [
    (input_data.alert_get_details_request_dismissed_alert_raw_response,
     input_data.get_remote_alert_data_dismissed_alert_updated_object),
    (input_data.alert_get_details_request_snoozed_alert_raw_response,
     input_data.get_remote_alert_data_snoozed_alert_updated_object),
    (input_data.alert_get_details_request_resolved_alert_raw_response,
     input_data.get_remote_alert_data_resolved_alert_updated_object),
    (input_data.alert_get_details_request_reopened_alert_raw_response,
     input_data.get_remote_alert_data_reopened_alert_updated_object),
])
def test_get_remote_alert_data(mocker, prisma_cloud_v2_mirroring_client, raw_response, expected_updated_object):
    """
    Given
        1. Raw response of the alert_get_details_request with data of a dismissed alert.
        2. Raw response of the alert_get_details_request with data of a snoozed alert.
        3. Raw response of the alert_get_details_request with data of a resolved alert.
        4. Raw response of the alert_get_details_request with data of a reopened alert.

    When
        - Running the get_remote_alert_data function.
    Then
        - Verify that the updated_object is as expected.
    """
    from PrismaCloudV2 import get_remote_alert_data
    remote_alert_id = 'test id'
    mocker.patch('PrismaCloudV2.Client.alert_get_details_request',
                 return_value=raw_response)
    alert_details, updated_object = get_remote_alert_data(prisma_cloud_v2_mirroring_client, remote_alert_id)

    assert alert_details == raw_response
    assert updated_object == expected_updated_object


@pytest.mark.parametrize('updated_mirrored_object, function_calls', [
    (input_data.get_remote_alert_data_dismissed_alert_updated_object, [1, 0]),
    (input_data.get_remote_alert_data_snoozed_alert_updated_object, [1, 0]),
    (input_data.get_remote_alert_data_resolved_alert_updated_object, [1, 0]),
    (input_data.get_remote_alert_data_reopened_alert_updated_object, [0, 1]),
])
def test_set_xsoar_incident_entries(mocker, prisma_cloud_v2_mirroring_client, updated_mirrored_object, function_calls):
    """
        Given
            1. A mirrored updated_object of a dismissed alert.
            2. A mirrored updated_object of a snoozed alert.
            3. A mirrored updated_object of a resolved alert.
            4. A mirrored updated_object of a re-opened alert.

        When
            - Running the set_xsoar_incident_entries function.
        Then
            1-3. Verify that the close_incident_in_xsoar function was called once,
                 and that the reopen_incident_in_xsoar function wasn't called.
            4. Verify that the reopen_incident_in_xsoar function was called once,
               and that the close_incident_in_xsoar function wasn't called.
    """
    from PrismaCloudV2 import set_xsoar_incident_entries

    mock_close_xsoar_incident = mocker.patch('PrismaCloudV2.close_incident_in_xsoar', return_value=None)
    mock_reopen_xsoar_incident = mocker.patch('PrismaCloudV2.reopen_incident_in_xsoar', return_value=None)
    set_xsoar_incident_entries(updated_mirrored_object, 'P-1111111')

    assert mock_close_xsoar_incident.call_count == function_calls[0]
    assert mock_reopen_xsoar_incident.call_count == function_calls[1]


@pytest.mark.parametrize('mirrored_status, mirrored_dismissal_note', [
    ('dismissed', 'test_dismissed'),
    ('snoozed', 'test_snoozed'),
    ('resolved', 'test_resolved'),
    ('resolved', ''),
])
def test_close_incident_in_xsoar(mirrored_status, mirrored_dismissal_note):
    """
        Given
            - A mirrored remoter alert id, a status and a dismissal note.
        When
            - Running the close_incident_in_xsoar function.
        Then
            - Verify that the close xsoar entry created as expected.
    """
    from PrismaCloudV2 import close_incident_in_xsoar
    remote_alert_id = 'test id'
    close_entry = close_incident_in_xsoar(remote_alert_id, mirrored_status, mirrored_dismissal_note)

    close_entry_contents = close_entry.get('Contents')
    assert close_entry_contents.get('dbotIncidentClose') is True
    assert close_entry_contents.get('rawCloseReason') == mirrored_status
    assert close_entry_contents.get('closeReason') == f'Alert was {mirrored_status} on Prisma Cloud.'
    if not mirrored_dismissal_note:  # resolved (case 4)
        assert close_entry_contents.get('closeNotes') == 'resolved'
    else:
        assert close_entry_contents.get('closeNotes') == mirrored_dismissal_note


def test_reopen_incident_in_xsoar():
    """
        Given
            - A mirrored remote alert id.
        When
            - Running the reopen_incident_in_xsoar function.
        Then
            - Verify that the reopen xsoar entry created as expected.
    """
    from PrismaCloudV2 import reopen_incident_in_xsoar
    remote_alert_id = 'test id'
    reopen_entry = reopen_incident_in_xsoar(remote_alert_id)

    close_entry_contents = reopen_entry.get('Contents')
    assert close_entry_contents.get('dbotIncidentReopen') is True


@pytest.mark.parametrize('mirrored_data, updated_object, expected_entry', [
    (input_data.alert_get_details_request_dismissed_alert_raw_response,
     input_data.get_remote_alert_data_dismissed_alert_updated_object,
     input_data.dismissed_closed_xsoar_entry),
    (input_data.alert_get_details_request_snoozed_alert_raw_response,
     input_data.get_remote_alert_data_snoozed_alert_updated_object,
     input_data.snoozed_closed_xsoar_entry),
    (input_data.alert_get_details_request_resolved_alert_raw_response,
     input_data.get_remote_alert_data_resolved_alert_updated_object,
     input_data.resolved_closed_xsoar_entry),
    (input_data.alert_get_details_request_reopened_alert_raw_response,
     input_data.get_remote_alert_data_reopened_alert_updated_object,
     input_data.reopened_closed_xsoar_entry),
])
def test_get_remote_data_command(mocker, prisma_cloud_v2_mirroring_client, mirrored_data, updated_object, expected_entry):
    """
        Given
            - A mirrored data, updated object (the object containing only the fields that should be mirrored) of a:
                1. Dismissed alert
                2. Snoozed alert
                3. Resolved alert
                4. Re-opened alert
        When
            - Running the get_remote_data_command.
        Then
            - Verify that the GetRemoteDataResponse object contains the updated object as the mirrored_object,
              and the expected xsoar entry.

    """
    from PrismaCloudV2 import get_remote_data_command

    args = {'id': 'test id', 'lastUpdate': '2023-08-16T08:17:09Z'}

    mocker.patch('PrismaCloudV2.get_remote_alert_data', return_value=(mirrored_data, updated_object))

    result = get_remote_data_command(prisma_cloud_v2_mirroring_client, args)
    entry = result.entries[0].get('Contents')
    if 'closed' in entry:  # removing the closed field cause time fields could be problematic for testing
        entry.pop('closed')
    assert entry == expected_entry
    assert result.mirrored_object == updated_object


@pytest.mark.parametrize('mirrored_data, updated_object', [
    (input_data.alert_get_details_request_dismissed_alert_raw_response,
     input_data.get_remote_alert_data_dismissed_alert_updated_object,),
    (input_data.alert_get_details_request_reopened_alert_raw_response,
     input_data.get_remote_alert_data_reopened_alert_updated_object),
])
def test_get_remote_data_command_close_incident_false(mocker, prisma_cloud_v2_mirroring_client, mirrored_data, updated_object):
    """
        Given
            - A mirrored data, updated object (the object containing only the fields that should be mirrored) of an alert:
                1. Closed alert.
                2. Reopened alert.
            - A client with the field close_incident = False (which indicates that the user doest want to close or to re-open
              xsaor incidents as part of the mirror in process).
        When
            - Running the get_remote_data_command.
        Then
            - Verify that the GetRemoteDataResponse object contains the updated object as the mirrored_object,
              and no XSOAR entries (because we don't want to close\re-open the mirrored incident).

    """
    from PrismaCloudV2 import get_remote_data_command

    args = {'id': 'test id', 'lastUpdate': '2023-08-16T08:17:09Z'}

    mocker.patch('PrismaCloudV2.get_remote_alert_data', return_value=(mirrored_data, updated_object))

    # Set the incident_close integration parameter to False:
    prisma_cloud_v2_mirroring_client.close_incident = False

    result = get_remote_data_command(prisma_cloud_v2_mirroring_client, args)

    assert result.entries == []
    assert result.mirrored_object == updated_object


@pytest.mark.parametrize('incident_status, whether_to_close, whether_to_reopen, expected_result', [
    (IncidentStatus.DONE, True, False, [1, 0]),
    (IncidentStatus.DONE, False, False, [0, 0]),
    (IncidentStatus.ACTIVE, False, True, [0, 1]),
    (IncidentStatus.ACTIVE, False, False, [0, 0]),
    (IncidentStatus.ARCHIVE, False, True, [0, 0]),
    (IncidentStatus.ARCHIVE, True, False, [0, 0]),
    (IncidentStatus.PENDING, False, True, [0, 0]),
    (IncidentStatus.PENDING, True, False, [0, 0]),
])
def test_update_remote_alert(mocker, prisma_cloud_v2_mirroring_client,
                             incident_status, whether_to_close, whether_to_reopen, expected_result):
    """
        Given
            Incident Status, mock response of the whether_to_close_in_prisma_cloud function and a
            mock response of the whether_to_reopen_in_prisma_cloud function:
            1. Closed, Yes, No.
            2. Closed, No, No.
            3. Open, No, Yes.
            4. Open, No, No.
            5. Archive, No, Yes.
            6. Archive, Yes, No.
            7. Pending, No, Yes.
            8. Pending, Yes, No.

        When
            - Running the update_remote_alert function.
        Then
            1. Verify that the close_alert_in_prisma_cloud function was called once,
               and that the reopen_alert_in_prisma_cloud function wasn't called.
            2. Verify that none of the functions were called.
            3. Verify that the reopen_alert_in_prisma_cloud function was called once,
               and that the close_alert_in_prisma_cloud function wasn't called.
            4. Verify that none of the functions were called.
            5 -8. Verify that none of the functions were called.
    """
    from PrismaCloudV2 import update_remote_alert

    mocker.patch('PrismaCloudV2.whether_to_close_in_prisma_cloud', return_value=whether_to_close)
    mocker.patch('PrismaCloudV2.whether_to_reopen_in_prisma_cloud', return_value=whether_to_reopen)

    mock_close_prisma_alert = mocker.patch('PrismaCloudV2.close_alert_in_prisma_cloud', return_value=None)
    mock_reopen_prisma_alert = mocker.patch('PrismaCloudV2.reopen_alert_in_prisma_cloud', return_value=None)

    update_remote_alert(prisma_cloud_v2_mirroring_client, {}, incident_status, 'test_id')

    assert mock_close_prisma_alert.call_count == expected_result[0]
    assert mock_reopen_prisma_alert.call_count == expected_result[1]


@pytest.mark.parametrize('user_selection, delta, expected_result', [
    (True, {'closeReason': 'USER_DISMISSED', 'closingUserId': '', 'closeNotes': 'test'}, True),
    (True, {'closeReason': 'USER_DISMISSED'}, True),
    (True, {'closingUserId': ''}, True),
    (True, {'closeNotes': 'test'}, True),
    (True, {}, False),
    (False, {'closeReason': 'USER_DISMISSED', 'closingUserId': '', 'closeNotes': 'test'}, False),
])
def test_whether_to_close_in_prisma_cloud(user_selection, delta, expected_result):
    """
        Given
            - The user selection regarding mirroring out closing of an XSOAR incident (determined in the 'close_alert'
             integration parameter), the mirrored incident delta.
                1. True, delta includes all closing fields.
                2-4. True, delta includes some of the closing fields.
                5. True, delta doesn't include closing fields.
                6. False, delta includes all closing fields.
        When
            - Running the whether_to_close_in_prisma_cloud function.
        Then
            - Verify that the result is as expected:
                1-4: True.
                5-6. False.
    """
    from PrismaCloudV2 import whether_to_close_in_prisma_cloud

    assert whether_to_close_in_prisma_cloud(user_selection, delta) == expected_result


@pytest.mark.parametrize('user_selection, delta, expected_result', [
    (True, {'closingUserId': ''}, True),
    (True, {}, False),
    (False, {'closingUserId': ''}, False),
])
def test_whether_to_reopen_in_prisma_cloud(user_selection, delta, expected_result):
    """
        Given
            - The user selection regarding mirroring out re-opening of an XSOAR incident (determined in the 'close_alert'
             integration parameter), the mirrored incident delta.
                1. True, delta includes the closingUserId field.
                2. True, delta doesn't include the closingUserId field.
                3. False, delta includes the closingUserId field.
        When
            - Running the whether_to_reopen_in_prisma_cloud function.
        Then
            - Verify that the result is as expected:
                1. True.
                2. False.
                3. False.
    """
    from PrismaCloudV2 import whether_to_reopen_in_prisma_cloud

    assert whether_to_reopen_in_prisma_cloud(user_selection, delta) == expected_result


def test_close_alert_in_prisma_cloud(mocker, prisma_cloud_v2_mirroring_client):
    """
        Given
            - A list of incident IDs to close in Prisma, a delta of the incident, and a time filter.

        When
            - Running the close_alert_in_prisma_cloud function.
        Then
            - Verify that the Client.alert_dismiss_request has called with expected args.

    """
    from PrismaCloudV2 import close_alert_in_prisma_cloud

    incident_ids_to_close = ['P-1111111']
    delta = {'closeReason': 'USER_DISMISSED', 'closingUserId': '', 'closeNotes': 'test'}

    time_filter = {'type': 'to_now', 'value': 'epoch'}  # base case
    mocker.patch('PrismaCloudV2.handle_time_filter', return_value=time_filter)

    mock_alert_dismiss_request = mocker.patch('PrismaCloudV2.Client.alert_dismiss_request', return_value=None)

    close_alert_in_prisma_cloud(prisma_cloud_v2_mirroring_client, incident_ids_to_close, delta)

    assert mock_alert_dismiss_request.call_args.kwargs == \
        {'dismissal_note': 'Closed by XSOAR - Closing Reason: USER_DISMISSED, Closing Notes: test.',
         'time_range': time_filter,
            'alert_ids': incident_ids_to_close}


def test_reopen_alert_in_prisma_cloud(mocker, prisma_cloud_v2_mirroring_client):
    """
        Given
            - A list of incident IDs to reopen in Prisma, and a time filter.

        When
            - Running the reopen_alert_in_prisma_cloud function.
        Then
            - Verify that the Client.alert_reopen_request has called with expected args.

    """
    from PrismaCloudV2 import reopen_alert_in_prisma_cloud

    incident_ids_to_reopen = ['P-1111111']

    time_filter = {'type': 'to_now', 'value': 'epoch'}  # base case
    mocker.patch('PrismaCloudV2.handle_time_filter', return_value=time_filter)

    mock_alert_reopen_request = mocker.patch('PrismaCloudV2.Client.alert_reopen_request', return_value=None)

    reopen_alert_in_prisma_cloud(prisma_cloud_v2_mirroring_client, incident_ids_to_reopen)

    assert mock_alert_reopen_request.call_args.kwargs == {'time_range': time_filter, 'alert_ids': incident_ids_to_reopen}


@pytest.mark.parametrize('args, expected_call_count', [
    ({'incidentChanged': True, 'remoteId': 'P-1111111', 'status': IncidentStatus.ACTIVE, 'delta': {'closingUserId': ''}}, 1),
    ({'incidentChanged': True, 'remoteId': 'P-1111111', 'status': IncidentStatus.DONE,
      'delta': {'closeReason': 'USER_DISMISSED', 'closingUserId': '', 'closeNotes': 'test'}}, 1),
    ({'incidentChanged': False, 'remoteId': 'P-1111111', 'status': IncidentStatus.ACTIVE, 'delta': {}}, 0)
])
def test_update_remote_system_command(mocker, prisma_cloud_v2_mirroring_client, args, expected_call_count):
    """
        Given
            - Demisto args object contains:
                1. incidentChanged field with True value, the remote alert ID, the xsoar incident status - open, and the delta.
                2. incidentChanged field with True value, the remote alert ID, the xsoar incident status - closed, and the delta.
                3. incidentChanged field with False value, the remote alert ID, the xsoar incident status, and an empty delta.
        When
            - Running the update_remote_system_command.
        Then
            - Verify that:
            1-2. The update_remote_alert function was called (cause mirror out process should be performed (incidentChanged=True).
            3.  The update_remote_alert function wasn't called (cause mirror out process should not be performed
             (incidentChanged=False).
    """
    from PrismaCloudV2 import update_remote_system_command

    mock_update_remote_alert = mocker.patch('PrismaCloudV2.update_remote_alert', return_value=None)

    result = update_remote_system_command(prisma_cloud_v2_mirroring_client, args)

    assert mock_update_remote_alert.call_count == expected_call_count
    assert result == 'P-1111111'
