"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    """
    def export_assets_request(self, chuck_size: int, last_fetch):
        """

        Args:
            chuck_size: maximum number of assets to fetch.
            last_fetch: the last asset that was fetched previously.

        Returns: The UUID of the assets export job.

        """
        payload = {
            "filters":
                {}
        }
        if last_fetch:
            payload['filters'].update({'last_fetch': last_fetch})

        res = self._http_request(method='POST', url_suffix='assets/export', params={'chunk_size': chuck_size}, json_data=payload,
                                 headers=self._headers)
        return res.get('export_uuid')

    def get_export_assets_status(self, export_uuid):
        """
        Args:
                export_uuid: The UUID of the vulnerabilities export job.

        Returns: The assets' chunk id.

        """
        res = self._http_request(method='GET', url_suffix=f'assets/export/{export_uuid}/status', headers=self._headers)
        return res.get('chunk_id')

    def download_assets_chunk(self, export_uuid: str, chunk_id: int):
        """

        Args:
            export_uuid: The UUID of the assets export job.
            chunk_id: The ID of the chunk you want to export.

        Returns: Chunk of assets from API.

        """
        return self._http_request(method='GET', url_suffix=f'/assets/export/{export_uuid}/chunks/{chunk_id}',
                                  headers=self._headers)


    def get_networks_requests(self, name, filter_type):
        query = ''
        return self._http_request(method='GET', url_suffix=f'/networks{query}',
                                  headers=self._headers)

''' HELPER FUNCTIONS '''


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def list_networks_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    network_name = args.get('name')
    filter_type =args.get('filter_type')
    # Call the Client function and get the raw response
    result = client.get_networks_request(network_name, filter_type)

    return CommandResults(
        outputs_prefix='TenableIO.Network',
        outputs_key_field='',
        outputs=result,
    )

@polling_function('fetch-assets', requires_polling_arg=False)
def fetch_assets_command(client: Client, params: Dict):
    assets = []
    last_found = arg_to_number(args.get('last_found'))
    num_assets = arg_to_number(args.get('num_assets')) or 5000
    severity = argToList(args.get('severity'))
    export_uuid = args.get('export_uuid')
    if not export_uuid:
        export_uuid = client.get_export_uuid(num_assets=num_assets, last_found=last_found,
                                             severity=severity)  # type: ignore

    status, chunks_available = client.get_export_status(export_uuid=export_uuid)
    if status == 'FINISHED':
        for chunk_id in chunks_available:
            vulnerabilities.extend(client.download_vulnerabilities_chunk(export_uuid=export_uuid, chunk_id=chunk_id))
        readable_output = tableToMarkdown('Vulnerabilities List:', vulnerabilities,
                                          removeNull=True,
                                          headerTransform=string_to_table_header)

        results = CommandResults(readable_output=readable_output,
                                 raw_response=vulnerabilities)
        return PollResult(response=results)
    elif status in ['CANCELLED', 'ERROR']:
        results = CommandResults(readable_output='Export job failed',
                                 entry_type=entryTypes['error'])
        return PollResult(response=results)
    else:
        results = CommandResults(readable_output='Export job failed',
                                 entry_type=entryTypes['error'])
        return PollResult(continue_to_poll=True, args_for_next_run={"export_uuid": export_uuid, **args},
                          response=results)


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions
    """

    params = demisto.params()
    command = demisto.command()

    # get the service API url
    base_url = urljoin(params.get('url'))
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    access_key = params.get('credentials', {}).get('identifier', '')
    secret_key = params.get('credentials', {}).get('password', '')

    # Fetch Params
    """
    what is going to be our fetch params?
    
    """
    first_fetch = arg_to_datetime(params.get('first_fetch', '3 days'))
    assets_first_fetch = arg_to_datetime(params.get("first_fetch_time_assets"), "3 days")

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        headers = {'X-ApiKeys': f'accessKey={access_key}; secretKey={secret_key}',
                   "Accept": "application/json"}
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command == 'fetch-assets':
            last_run = demisto.getassetsLastRun()
            """
            when running fetch-assets we going to get all vulnerablilies and events as well, and then return all to xsiam together
            but why return everything all together when the only job running is fetch assets
            assume we have one checkbox `isfetchassetsandevents' then on serverside, its translated to having `fetch-assets` 
            and `fetch events` commands, we can get vulns with command of get vulns isn't it?
            """
            fetch_assets_from = last_run.get("fetch_from") or assets_first_fetch

        elif command == 'fetch-events':
            """implement same as collector??"""

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
