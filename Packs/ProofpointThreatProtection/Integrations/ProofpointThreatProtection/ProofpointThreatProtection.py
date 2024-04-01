import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json
from typing import Any
import dateparser


''' CONSTANTS '''


URL_SUFFIX_BLOCKLIST = '/emailProtection/modules/spam/orgBlockList'
URL_SUFFIX_SAFELIST = '/emailProtection/modules/spam/orgSafeList'


class Client(BaseClient):
    """Client class to interact with the service API"""

    def get_access_token(self, client_id, client_secret):
        """
        Get an access token that was previously created if it is still valid, else, generate a new access token from
        the API key and secret.
        """
        # Check if there is an existing valid access token
        integration_context = get_integration_context()
        if integration_context.get('access_token') and integration_context.get('expiry_time') > date_to_timestamp(datetime.now()):
            return integration_context.get('access_token')
        else:
            try:
                res = self._http_request(
                    method='POST',
                    full_url='https://auth.proofpoint.com/v1/token',
                    headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    data={
                        'grant_type': 'client_credentials',
                        'client_id': client_id,
                        'client_secret': client_secret
                    }
                )
                if res.get('access_token'):
                    expiry_time = date_to_timestamp(datetime.now(), date_format='%Y-%m-%dT%H:%M:%S')
                    expiry_time += res.get('expires_in', 0) * 1000 - 10
                    context = {
                        'access_token': res.get('access_token'),
                        'expiry_time': expiry_time
                    }
                    set_integration_context(context)
                    self._headers['Authorization'] = f'Bearer {res.get("access_token")}'
                    return res.get('access_token')
            except Exception as e:
                return_error(f'Error occurred while creating an access token. Please check the instance configuration.'
                             f'\n\n{e.args[0]}')

    def get_safelist(self, cluster_id):
        return self._http_request(
            'GET',
            url_suffix=URL_SUFFIX_SAFELIST,
            params={'clusterId': cluster_id}
        )

    def safelist_add_delete(self, cluster_id, args):
        return self._http_request(
            'POST',
            url_suffix=URL_SUFFIX_SAFELIST,
            params={'clusterId': cluster_id},
            data={
                'action': args.get('action'),
                'attribute': args.get('attribute'),
                'operator': args.get('operator'),
                'value': args.get('value'),
                'comment': args.get('comment')
            }
        )

    def get_blocklist(self, cluster_id):
        return self._http_request(
            'GET',
            url_suffix=URL_SUFFIX_BLOCKLIST,
            params={'clusterId': cluster_id}
        )

    def blocklist_add_delete(self, cluster_id, args):
        return self._http_request(
            'POST',
            url_suffix=URL_SUFFIX_BLOCKLIST,
            params={'clusterId': cluster_id},
            data={
                'action': args.get('action'),
                'attribute': args.get('attribute'),
                'operator': args.get('operator'),
                'value': args.get('value'),
                'comment': args.get('comment')
            }
        )


''' HELPER FUNCTIONS '''


''' COMMAND FUNCTIONS '''


def test_module(client: Client, cluster_id) -> str:
    client.get_blocklist(cluster_id)
    return 'ok'


def safelist_get_command(client: Client, cluster_id) -> CommandResults:
    res = client.get_safelist(cluster_id)

    outputs = {
        'Safelist': res.get('entries')
    }

    return CommandResults(
        readable_output="Organizational Safe List",
        outputs_prefix='ProofpointThreatProtection',
        outputs_key_field='',
        outputs=outputs
    )


def safelist_add_delete_command(client: Client, cluster_id, args) -> CommandResults:
    res = client.safelist_add_delete(cluster_id, args)

    outputs = {
        'Safelist': res
    }

    return CommandResults(
        readable_output="Organizational Safe List",
        outputs_prefix='ProofpointThreatProtection',
        outputs_key_field='',
        outputs=outputs
    )


def blocklist_get_command(client: Client, cluster_id) -> CommandResults:
    res = client.get_blocklist(cluster_id)

    outputs = {
        'Blocklist': res.get('entries')
    }

    return CommandResults(
        readable_output="Organizational Block List",
        outputs_prefix='ProofpointThreatProtection',
        outputs_key_field='',
        outputs=outputs
    )


def blocklist_add_delete_command(client: Client, cluster_id, args) -> CommandResults:
    res = client.blocklist_add_delete(cluster_id, args)

    outputs = {
        'Blocklist': res
    }

    return CommandResults(
        readable_output="Organizational Block List",
        outputs_prefix='ProofpointThreatProtection',
        outputs_key_field='',
        outputs=outputs
    )


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    client_id = params.get('credentials', {}).get('username')
    client_secret = params.get('credentials', {}).get('password')
    base_url = params.get('url')
    cluster_id = params.get('cluster_id')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')
    commands = {
        'test-module': test_module,
        'proofpoint-tp-safelist-get': safelist_get_command,
        'proofpoint-tp-blocklist-get': blocklist_get_command
    }
    commands_with_args = {
        'proofpoint-tp-safelist-add-or-delete-entry': safelist_add_delete_command,
        'proofpoint-tp-blocklist-add-or-delete-entry': blocklist_add_delete_command
    }
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)
        client.get_access_token(client_id, client_secret)
        if command in commands:
            return_results(commands[command](client, cluster_id))
        elif command in commands_with_args:
            return_results(commands_with_args[command](client, cluster_id, args))
        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
