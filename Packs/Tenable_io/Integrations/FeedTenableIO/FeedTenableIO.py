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

    def export_vulnerabilities_request(self, num_assets: int, last_found: Optional[float], severity: List[str]):
        """

        Args:
            num_assets: number of assets used to chunk the vulnerabilities.
            last_found: vulnerabilities that were last found between the specified date (in Unix time) and now.
            severity: severity of the vulnerabilities to include in the export.

        Returns: The UUID of the vulnerabilities export job.

        """
        payload: Dict[str, Union[Any]] = {
            "filters":
                {
                    "severity": severity
                },
            "num_assets": num_assets
        }
        if last_found:
            payload['filters'].update({"last_found": last_found})

        res = self._http_request(method='POST', url_suffix='/vulns/export', headers=self._headers, json_data=payload)
        return res.get('export_uuid', '')

    def get_vulnerabilities_export_status(self, export_uuid: str):
        """

        Args:
            export_uuid: The UUID of the vulnerabilities export job.

        Returns: The status of the job, and number of chunks available if succeeded.

        """
        res = self._http_request(method='GET', url_suffix=f'/vulns/export/{export_uuid}/status',
                                 headers=self._headers)
        status = res.get('status')
        chunks_available = res.get('chunks_available', [])
        return status, chunks_available

    def download_vulnerabilities_chunk(self, export_uuid: str, chunk_id: int):
        """

        Args:
            export_uuid: The UUID of the vulnerabilities export job.
            chunk_id: The ID of the chunk you want to export.

        Returns: Chunk of vulnerabilities from API.

        """
        return self._http_request(method='GET', url_suffix=f'/vulns/export/{export_uuid}/chunks/{chunk_id}',
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
    """what is going to be our fetch params?
    two intervals to events and assets? for assets created?
    """
    first_fetch = arg_to_datetime(params.get('first_fetch', '3 days'))

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
            last_run = demisto.getLastRun()
            """
            when running fetch-assets we going to get all vulnerablilies and events as well, and then return all to xsiam together
            but why return everything all together when the only job running is fetch assets
            assume we have one checkbox `isfetchassetsandevents' then on serverside, its translated to having `fetch-assets` 
            and `fetch events` commands, we can get vulns with command of get vulns isn't it?
            """
        elif command == 'fetch-events':
            """implement same as collector??"""

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
