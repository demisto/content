from typing import Union

import dateparser
import demistomock as demisto
import requests
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

# IMPORTS


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """
    def __init__(self, base_url: str, use_ssl: bool, use_proxy: bool, token=None):
        self.token = token
        super().__init__(base_url, verify=use_ssl, proxy=use_proxy, headers={'Accept': 'application/json',
                                                                             'Content-Type': 'application/json'})
        if self.token:
            self._headers.update({'X-Auth-Token': self.token})

    def test_module_request(self):
        url_suffix = '/alerts/_search'
        body = {
            "criteria": {
                "group_results": True,
                "minimum_severity": 3,
                "create_time": {
                    "start": "2020-01-27T23:10:20.814Z",
                    "end": "2020-01-27T23:10:25.814Z"
                }
            },
            "sort": [{"field": "first_event_time", "order": "DESC"}],
            "rows": 1,
            "start": 0
        }

        return self._http_request('POST', url_suffix=url_suffix, json_data=body)

    def search_alerts_request(self, limit: int):

        suffix_url = '/alerts/_search'
        body = {
            "criteria": {
                'group_results': True,
                'minimum_severity': 3,
                'create_time': {
                    'start': '2020-01-27T23:10:20.814Z',
                    'end': '2020-01-27T23:10:25.814Z'
                }
            },
            'sort': [{'field': 'first_event_time', 'order': 'DESC'}],
            'rows': limit,
            'start': 0
        }

        return self._http_request('POST', suffix_url, json_data=body)

    def alert_workflow_update_request(self, alert_id, state, comment, remediation_state):

        suffix_url = f'/alerts/{alert_id}/workflow'
        body = assign_params(
            state=state,
            comment=comment,
            remediation_state=remediation_state
        )

        return self._http_request('POST', suffix_url, json_data=body)

    def devices_list_request(self, device_id: Union[list, str], status: str, device_os: str, last_contact_time: str,
                             ad_group_id: int, policy_id: int, target_priority: str, limit: int, sort_field: str,
                             sort_order: str):

        suffix_url = '/devices/_search'

        body = {
            'criteria': {
                'id': device_id,
                'status': status,
                'os': device_os,
                'last_contact_time': last_contact_time,
                'ad_group_id': ad_group_id,
                'policy_id': policy_id,
                'target_priority': target_priority
            },
            'rows': limit,
            'start': 0,
            'sort': [
                {
                    'field': sort_field,
                    'order': sort_order
                }
            ]
        }

        return self._http_request('POST', suffix_url, json_data=body)

    def device_quarantine_request(self, device_id: Union[list, str]):

        suffix_url = '/device_actions'

        body = {
            'action_type': 'QUARANTINE',
            'device_id': device_id,
            'options': {
                'toggle': 'ON'
            }
        }

        return self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_unquarantine_request(self, device_id: Union[list, str]):
        suffix_url = '/device_actions'

        body = {
            'action_type': 'QUARANTINE',
            'device_id': device_id,
            'options': {
                'toggle': 'OFF'
            }
        }

        return self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_bypass_request(self, device_id: Union[list, str]):
        suffix_url = '/device_actions'

        body = {
            'action_type': 'BYPASS',
            'device_id': device_id,
            'options': {
                'toggle': 'ON'
            }
        }

        return self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_unbypass_request(self, device_id: Union[list, str]):
        suffix_url = '/device_actions'

        body = {
            'action_type': 'BYPASS',
            'device_id': device_id,
            'options': {
                'toggle': 'OFF'
            }
        }

        return self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_background_scan_request(self, device_id: Union[list, str]):
        suffix_url = '/device_actions'

        body = {
            'action_type': 'BACKGROUND_SCAN',
            'device_id': device_id,
            'options': {
                'toggle': 'ON'
            }
        }

        return self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_background_scan_request_stop(self, device_id: Union[list, str]):
        suffix_url = '/device_actions'

        body = {
            'action_type': 'BACKGROUND_SCAN',
            'device_id': device_id,
            'options': {
                'toggle': 'OFF'
            }
        }

        return self._http_request('POST', suffix_url, json_data=body, resp_type='content')

    def device_policy_update(self, device_id: Union[list, str], policy_id: str):
        suffix_url = '/device_actions'

        body = {
            'action_type': 'UPDATE_POLIC',
            'device_id': device_id,
            'options': {
                'policy_id': policy_id
            }
        }

        return self._http_request('POST', suffix_url, json_data=body, resp_type='content')


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    client.test_module_request()
    return 'ok'


def alert_workflow_update_command(client: Client, args: dict):

    alert_id = args.get('alert_id')
    state = args.get('state')
    comment = args.get('comment')
    remediation_state = args.get('remediation_state')

    result = client.alert_workflow_update_request(alert_id, state, comment, remediation_state)

    readable_output = tableToMarkdown(f'Successfully updated the alert: "{alert_id}"', result)
    outputs = {
        'AlertID': alert_id,
        'State': result.get('state'),
        'Remediation': result.get('remediation'),
        'LastUpdateTime': result.get('last_update_time'),
        'Comment': result.get('comment'),
        'ChangedBy': result.get('changed_by')
    }

    results = CommandResults(
        outputs_prefix='CarbonBlackEEDR.Alert',
        outputs_key_field='AlertID',
        outputs=outputs,

        readable_output=readable_output,
        raw_response=result
    )
    return results


def list_devices_command(client: Client, args: dict):
    device_id = argToList(args.get('device_id'))
    status = args.get('status')
    device_os = args.get('device_os')
    last_contact_time = args.get('last_contact_time')
    ad_group_id = args.get('ad_group_id')
    policy_id = args.get('policy_id')
    target_priority = args.get('target_priority')
    limit = args.get('limit')
    sort_field = args.get('sort_field')
    sort_order = args.get('sort_order')

    result = client.devices_list_request(device_id, status, device_os, last_contact_time, ad_group_id, policy_id,
                                         target_priority, limit, sort_field, sort_order)


def device_quarantine_command(client: Client, args: dict):

    device_id = argToList(args.get('device_id'))
    client.device_quarantine_request(device_id)

    return 'The device has been quarantine', {}, {}


def device_unquarantine_command(client: Client, args: dict):
    device_id = argToList(args.get('device_id'))
    result = client.device_quarantine_request(device_id)

    return 'The device has been unquarantine', {}, result

# def fetch_incidents(client, last_run, first_fetch_time):
#     """
#     This function will execute each interval (default is 1 minute).
#
#     Args:
#         client (Client): HelloWorld client
#         last_run (dateparser.time): The greatest incident created_time we fetched from last fetch
#         first_fetch_time (dateparser.time): If last_run is None then fetch all incidents since first_fetch_time
#
#     Returns:
#         next_run: This will be last_run in the next fetch-incidents
#         incidents: Incidents that will be created in Demisto
#     """
#     # Get the last fetch time, if exists
#     last_fetch = last_run.get('last_fetch')
#
#     # Handle first time fetch
#     if last_fetch is None:
#         last_fetch, _ = dateparser.parse(first_fetch_time)
#     else:
#         last_fetch = dateparser.parse(last_fetch)
#
#     latest_created_time = last_fetch
#     incidents = []
#     items = client.list_incidents()
#     for item in items:
#         incident_created_time = dateparser.parse(item['created_time'])
#         incident = {
#             'name': item['description'],
#             'occurred': incident_created_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
#             'rawJSON': json.dumps(item)
#         }
#
#         incidents.append(incident)
#
#         # Update last run and add incident if the incident is newer than last fetch
#         if incident_created_time > latest_created_time:
#             latest_created_time = incident_created_time
#
#     next_run = {'last_fetch': latest_created_time.strftime(DATE_FORMAT)}
#     return next_run, incidents


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    cb_custom_key = demisto.params().get('custom_key')
    cb_custom_id = demisto.params().get('custom_id')
    token = f'{cb_custom_key}/{cb_custom_id}'
    cb_org_key = demisto.params().get('organization_key')
    # get the service API url
    base_url = urljoin(demisto.params().get('url'), f'/appservices/v6/orgs/{cb_org_key}')

    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('fetch_time', '3 days').strip()

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            use_ssl=verify_certificate,
            token=token,
            use_proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        # elif demisto.command() == 'fetch-incidents':
        #     # Set and define the fetch incidents command to run after activated via integration settings.
        #     next_run, incidents = fetch_incidents(
        #         client=client,
        #         last_run=demisto.getLastRun(),
        #         first_fetch_time=first_fetch_time)
        #
        #     demisto.setLastRun(next_run)
        #     demisto.incidents(incidents)

        elif demisto.command() == 'cb-eedr-alert-workflow-update':
            return_results(alert_workflow_update_command(client, demisto.args()))
        # elif demisto.command() == 'cb-eedr-devices-list':
        #     return_outputs(*list_devices_command(client, demisto.args()))
        elif demisto.command() == 'cb-eedr-device-quarantine':
            return_outputs(*device_quarantine_command(client, demisto.args()))
        elif demisto.command() == 'cb-eedr-device-unquarantine':
            return_outputs(*device_unquarantine_command(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
