import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Dict, Any, Optional

import requests

requests.packages.urllib3.disable_warnings()


class Client(BaseClient):

    def test_connectivity(self):
        return self._http_request(
            method='GET',
            url_suffix='/api/app/info'
        )

    def air_acquire(self, hostname: str, profile: str, case_id: str, organization_id: int) -> Dict[str, str]:
        ''' Makes a POST request /api/public/acquisitions/acquire endpoint to verify acquire evidence

        :param hostname str: endpoint hostname to start acquisition.
        :param profile str: predefined 5 acquisiton profile name.
        :param case_id str: The Case ID to associate with in AIR Server.
        :param organization_id int: Organizsation ID of the endpoint.

        Create a payload with the parameters
        :return JSON response from /api/app/info endpoint
        :rtype Dict[str, Any]
        '''

        payload: Dict[str, Any] = {
            "caseId": case_id,
            "droneConfig": {
                "autoPilot": False,
                "enabled": False
            },
            "taskConfig": {
                "choice": "use-policy"
            },
            "acquisitionProfileId": profile,
            "filter": {
                "name": hostname,
                "organizationIds": [organization_id]
            }
        }
        return self._http_request(
            method='POST',
            url_suffix='/api/public/acquisitions/acquire',
            json_data=payload
        )

    def air_isolate(self, hostname: str, organization_id: int, isolation: str) -> Dict[str, str]:
        ''' Makes a POST request /api/public/acquisitions/acquire endpoint to verify acquire evidence
        :param hostname str: endpoint hostname to start acquisition.
        :param isolation str: To isolate enable, to disable isolate use disable
        :param organization_id int: Organization ID of the endpoint.

        Create a payload with the parameters
        :return JSON response from /api/public/endpoints/tasks/isolation endpoint
        :rtype Dict[str, Any]
        '''

        payload: Dict[str, Any] = {
            "enabled": True,
            "filter": {
                "name": hostname,
                "organizationIds": [organization_id]
            }
        }

        if isolation == 'disable':
            disable = {"enabled": False}
            payload.update(disable)

        return self._http_request(
            method='POST',
            url_suffix='/api/public/endpoints/tasks/isolation',
            json_data=payload
        )


def test_connection(client: Client) -> str:
    '''Command for test-connection'''

    result: Dict[str, Any] = client.test_connectivity()
    initialized: Optional[bool] = result['initialized']

    if initialized is True:
        return demisto.results('ok')
    else:
        return demisto.results('test connection failed')


def air_acquire_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    '''Command handler for acquire command'''
    hostname = args.get('hostname', '')
    profile = args.get('profile', '')
    case_id = args.get('case_id', '')
    organization_id = args.get('organization_id', '')

    result: Dict[str, Any] = client.air_acquire(hostname, profile, case_id, organization_id)

    return CommandResults(
        outputs_prefix='BinalyzeAIR.Acquisition',
        outputs_key_field='hostname',
        outputs=result,
    )


def air_isolate_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ''' Command handler isolate '''

    hostname = args.get('hostname', '')
    organization_id = args.get('organization_id', '')
    isolation = args.get('isolation', '')

    result: Dict[str, Any] = client.air_isolate(hostname, organization_id, isolation)

    return CommandResults(
        outputs_prefix='BinalyzeAIR.Isolate',
        outputs_key_field='hostname',
        outputs=result,
    )


''' Entrypoint '''


def main() -> None:
    api_key: str = demisto.params().get('api_key')
    base_url: str = demisto.params()['server']
    verify_certificate: bool = not demisto.params().get('insecure', False)
    proxy: bool = demisto.params().get('proxy', False)
    command: str = demisto.command()
    args: Dict[str, Any] = demisto.args()
    headers: Dict[str, Any] = {
        'Authorization': f'Bearer {api_key}',
        'User-Agent': 'Binalyze AIR',
        'Content-type': 'application/json',
        'Accept-Charset': 'UTF-8'
    }
    try:
        demisto.debug(f'Command being called is {demisto.command()}')
        client: Client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            ok_codes=(404, 200)
        )
        if command == 'test-module':
            return_results(test_connection(client))
        elif command == 'binalyze-air-acquire':
            return_results(air_acquire_command(client, args))
        elif command == 'binalyze-air-isolate':
            return_results(air_isolate_command(client, args))

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute "{command}". Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()