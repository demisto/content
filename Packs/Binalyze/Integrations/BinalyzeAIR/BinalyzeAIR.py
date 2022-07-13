import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401

requests.packages.urllib3.disable_warnings()


class Client(BaseClient):

    def air_acquire(self, endpoint: str, profile: str, caseid: str, organization_id: int) -> Dict[str, str]:
        ''' Makes a POST request /api/public/acquisitions/acquire endpoint to verify acquire evidence

        :param endpoint str: endpoint hostname to start acquisition.
        :param profile str: predefined 5 acquisiton profile name.
        :param caseid str: The Case ID to associate with in AIR Server.
        :param organization_id int: Organizsation ID of the endpoint.

        Create a payload with the parameters
        :return JSON response from /api/app/info endpoint
        :rtype Dict[str, Any]
        '''

        payload: Dict[str, Any] = {
            "caseId": caseid,
            "droneConfig": {
                "autoPilot": False,
                "enabled": False
            },
            "taskConfig": {
                "choice": "use-policy"
            },
            "acquisitionProfileId": profile,
            "filter": {
                "name": endpoint,
                "organizationIds": [organization_id]
            }
        }
        return self._http_request(
            method='POST',
            url_suffix='/api/public/acquisitions/acquire',
            json_data=payload
        )

    def air_isolate(self, endpoint: str, organization_id: int, isolation: str) -> Dict[str, str]:
        ''' Makes a POST request /api/public/acquisitions/acquire endpoint to verify acquire evidence
        :param endpoint str: endpoint hostname to start acquisition.
        :param isolation str: To isolate enable, to disable isolate use disable
        :param organization_id int: Organization ID of the endpoint.

        Create a payload with the parameters
        :return JSON response from /api/public/endpoints/tasks/isolation endpoint
        :rtype Dict[str, Any]
        '''

        payload: Dict[str, Any] = {
            "enabled": True,
            "filter": {
                "name": endpoint,
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


def test_connection(base_url) -> str:
    '''Command for test-connection'''

    response = requests.get(f'{base_url}/api/app/info')
    if response.status_code == 200:
        return demisto.results('ok')
    else:
        return demisto.results('test connection failed')


def air_acquire_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    '''Command handler for acquire command'''
    endpoint = args.get('endpoint', None)
    profile = args.get('profile', None)
    caseid = args.get('caseid', None)
    organization_id = args.get('organization_id', None)

    result: Dict[str, Any] = client.air_acquire(endpoint, profile, caseid, organization_id)

    return CommandResults(
        outputs_prefix='Binalyze.Air.Acquisition',
        outputs_key_field='endpoint',
        outputs=result,
    )


def air_isolate_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ''' Command handler isolate '''

    endpoint = args.get('endpoint', None)
    organization_id = args.get('organization_id', None)
    isolation = args.get('isolation', None)

    result: Dict[str, Any] = client.air_isolate(endpoint, organization_id, isolation)

    return CommandResults(
        outputs_prefix='Binalyze.Air.Isolate',
        outputs_key_field='endpoint',
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
            proxy=proxy
        )
        if command == 'test-module':
            return_results(test_connection(base_url))
        elif command == 'binalyze-air-acquire':
            return_results(air_acquire_command(client, args))
        elif command == 'binalyze-air-isolate':
            return_results(air_isolate_command(client, args))

    except Exception as ex:
        message: str = str(ex)
        if '404' in message:
            return_results(f'Nothing found for {command}')
        else:
            demisto.error(traceback.format_exc())  # print the traceback
            return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
