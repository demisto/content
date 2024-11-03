import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any

import urllib3

urllib3.disable_warnings()


class Client(BaseClient):

    def test_api(self):
        return self._http_request(
            method='GET',
            url_suffix='/api/public/endpoints?filter[organizationIds]=0'
        )

    def get_profile_id(self, profile: str, organization_id: int | None) -> str:
        '''Gets the profile ID based on the profile name and organization ID by making a GET request to the
        '/api/public/acquisitions/profiles' endpoint.
        Args:
        profile (str): The name of the profile to query.
        organization_id (int): The organization ID associated with the profile.
        Returns:
        str: The profile ID obtained from the API response.
        Raises:
        DemistoException: If there is an error making the HTTP request or processing the API response.
        '''
        preset_profiles = ["browsing-history", "compromise-assessment", "event-logs", "full", "memory-ram-pagefile", "quick"]
        if profile in preset_profiles:
            return profile
        else:
            result = self._http_request(
                method='GET',
                url_suffix=f'/api/public/acquisitions/profiles?filter[name]={profile}&filter[organizationIds]='
                           f'{organization_id}').get("result", {}).get("entities", [])
            profile_id = ""
            for entity in result:
                if entity.get("name") == profile:
                    profile_id = entity.get("_id")
                    if profile_id:
                        return profile_id
            # There is no match with profile_id.
            if not profile_id:
                return_error(f'The acquisition profile "{profile}" cannot be found. Please ensure that you enter a valid '
                             f'profile name.')
            return ""

    def air_acquire(self, hostname: str, profile: str, case_id: str, organization_id: int | None) -> dict[str, Any]:
        ''' Makes a POST request /api/public/acquisitions/acquire endpoint to verify acquire evidence

        :param hostname str: endpoint hostname to start acquisition.
        :param profile str: get the profile string makes a query, and uses profile_id for mapping correct profile.

        :param case_id str: The Case ID to associate with in AIR Server.
        :param organization_id int: Organizsation ID of the endpoint.

        Create a payload with the parameters
        :return JSON response from /api/app/info endpoint
        :rtype Dict[str, Any]
        '''

        payload: dict[str, Any] = {
            "caseId": case_id,
            "droneConfig": {
                "autoPilot": False,
                "enabled": False
            },
            "taskConfig": {
                "choice": "use-policy"
            },
            "acquisitionProfileId": self.get_profile_id(profile, organization_id),
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

    def air_isolate(self, hostname: str, organization_id: int | None, isolation: str) -> dict[str, Any]:
        ''' Makes a POST request /api/public/acquisitions/acquire endpoint to verify acquire evidence
        :param hostname str: endpoint hostname to start acquisition.
        :param isolation str: To isolate enable, to disable isolate use disable
        :param organization_id int: Organization ID of the endpoint.

        Create a payload with the parameters
        :return JSON response from /api/public/endpoints/tasks/isolation endpoint
        :rtype Dict[str, Any]
        '''

        payload: dict[Any, Any] = {
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
    try:
        client.test_api()
    except DemistoException as ex:
        if 'Unauthorized' in str(ex):
            return demisto.results(f'Authorization Error: Make sure API Key is correctly set.{str(ex)}')
        if 'ConnectionError' in str(ex):
            return demisto.results(f'Connection Error: Test connection failed. {str(ex)}')
        else:
            raise ex
    return demisto.results('ok')


def air_acquire_command(client: Client, args: dict[str, Any]) -> CommandResults:
    '''Command handler for acquire command'''
    hostname = args.get('hostname', '')
    profile = args.get('profile', '')
    case_id = args.get('case_id', '')
    organization_id = args.get('organization_id', '')

    result: dict[str, Any] = client.air_acquire(hostname, profile, case_id, arg_to_number(organization_id))
    readable_output = tableToMarkdown('Binalyze AIR Acquisition Results', result,
                                      headers=('success', 'result', 'statusCode', 'errors'),
                                      headerTransform=string_to_table_header)

    if result.get('statusCode') == 404:
        return CommandResults(readable_output='No contex for queried hostname.')

    return CommandResults(
        outputs_prefix='BinalyzeAIR.Acquisition',
        outputs_key_field='hostname',
        outputs={
            'Result': result['result'],
            'Success': result['success']
        },
        readable_output=readable_output,
    )


def air_isolate_command(client: Client, args: dict[str, Any]) -> CommandResults:
    ''' Command handler isolate '''

    hostname = args.get('hostname', '')
    organization_id = args.get('organization_id', '')
    isolation = args.get('isolation', '')

    result: dict[Any, Any] = client.air_isolate(hostname, arg_to_number(organization_id), isolation)
    readable_output = tableToMarkdown('Binalyze AIR Isolate Results', result,
                                      headers=('success', 'result', 'statusCode', 'errors'),
                                      headerTransform=string_to_table_header)
    if result.get('statusCode') == 404:
        return CommandResults(readable_output='No contex for queried hostname.')

    return CommandResults(
        outputs_prefix='BinalyzeAIR.Isolate',
        outputs_key_field='hostname',
        outputs={
            'Result': result['result'],
            'Success': result['success']
        },
        readable_output=readable_output,
    )


''' Entrypoint '''


def main() -> None:  # pragma: no cover
    api_key: str = demisto.params().get('api_key')
    base_url: str = demisto.params()['server']
    verify_certificate: bool = not demisto.params().get('insecure', False)
    proxy: bool = demisto.params().get('proxy', False)
    command: str = demisto.command()
    args: dict[str, Any] = demisto.args()
    headers: dict[str, Any] = {
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


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
