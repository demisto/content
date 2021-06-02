from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
OUTPUTS_PREFIX = 'GoogleMaps'

requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


class Client(BaseClient):
    def __init__(self, api_key: str, proxy: bool, insecure: bool):
        """
        Client to use in the IPinfo integration. Uses BaseClient
        """
        super().__init__(base_url='https://maps.googleapis.com/maps/api/',
                         verify=not insecure,
                         proxy=proxy)
        self.api_key = api_key

    def google_maps_geocode(self, search_address: str) -> List[CommandResults]:
        # noinspection PyTypeChecker
        response: Dict[str, Any] = self._http_request(method='GET', url_suffix='geocode/json?',
                                                      params=assign_params(address=search_address, key=self.api_key))

        status = demisto.get(response, 'status')

        if status == 'ZERO_RESULTS':
            return [CommandResults(readable_output='No matching places were found.')]

        elif status != 'OK':  # happens when there are zero results (handled above) or an error
            error_message = demisto.get(response, 'error_message') or 'See response for details.'
            raise DemistoException(message=error_message, res=response)

        else:
            coordinate_dict = response['results'][0]['geometry']['location']
            response_address = response['results'][0]['formatted_address']

            note_outputs = {**coordinate_dict, **{'SearchAddress': search_address, 'Address': response_address}}

            # noinspection PyTypeChecker
            readable_output = tableToMarkdown(name='Results',
                                              t=note_outputs,
                                              headers=list(note_outputs.keys()),
                                              headerTransform=pascalToSpace)

            result_note = CommandResults(outputs_prefix=OUTPUTS_PREFIX,
                                         outputs_key_field=['lat', 'lng'],
                                         outputs=note_outputs,
                                         readable_output=readable_output,
                                         entry_type=EntryType.NOTE,
                                         raw_response=response)

            result_map = CommandResults(entry_type=EntryType.MAP_ENTRY_TYPE,
                                        raw_response=coordinate_dict)

            return [result_note, result_map]


def google_maps_geocode_command(client: Client, address: str) -> List[CommandResults]:
    return client.google_maps_geocode(address)


def test_module(client: Client) -> str:
    """Tests GoogleMaps by geocoding the address of Demisto's (original) HQ"""
    client.google_maps_geocode('45 Rothschild, Tel Aviv')
    return 'ok'  # on any failure, an exception is raised


def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    proxy = demisto.get(params, 'proxy') or False
    api_key = demisto.get(params, 'api_key.password') or ''
    insecure = demisto.get(params, 'insecure') or False

    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(api_key=api_key, proxy=proxy, insecure=insecure)

        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'google-maps-geocode':
            return_results(google_maps_geocode_command(client, **args))

        else:
            raise NotImplementedError(f"command '{command}' is not supported")

    except Exception as e:
        demisto.error(traceback.format_exc())  # prints the traceback

        error_parts = (f'Failed to execute the {command} command.', 'Error:', {str(e)})
        if isinstance(e, DemistoException):
            error_parts += f'Raw response:,{e.res}'

        return_error('\n'.join(error_parts))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
