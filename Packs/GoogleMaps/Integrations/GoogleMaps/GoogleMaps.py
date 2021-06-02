from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings

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

    def google_maps_geocode(self, address: str) -> List[CommandResults]:
        # noinspection PyTypeChecker
        response: Dict[str, Any] = self._http_request(method='GET',
                                                      url_suffix='geocode/json?',
                                                      params=assign_params(address=address,
                                                                           key=self.api_key))
        if 'error_message' in response:
            return_error(response['error_message'], str(response))
            return []  # todo check

        if response['status'] == 'ZERO_RESULTS':  # todo perhaps if not response['results']?
            return_results('No matching places were found.')
            return []  # todo check

        coordinate_dict = response['results'][0]['geometry']['location']
        response_address = response['results'][0]['formatted_address']

        note_outputs = {**coordinate_dict,
                        **{'Input_Address': address, 'Address': response_address}}

        result_note = CommandResults(outputs_prefix='GoogleMaps',
                                     outputs_key_field=['lat', 'lng'],
                                     outputs=note_outputs,
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
    api_key = demisto.get(params, 'api_key.password') or '' # todo
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
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.'
                     f'\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
