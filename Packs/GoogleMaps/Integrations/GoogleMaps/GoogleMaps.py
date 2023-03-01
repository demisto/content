from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3

OUTPUTS_PREFIX = 'GoogleMaps'

STATUS_OK = 'OK'
STATUS_ZERO_RESULTS = 'ZERO_RESULTS'

MESSAGE_ZERO_RESULTS = 'No matching places were found.'

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member


class Client(BaseClient):
    def __init__(self, api_key: str, base_url: str, proxy: bool, insecure: bool):
        """
        Client to use in the GoogleMaps integration. Uses BaseClient
        """
        super().__init__(base_url=base_url,
                         verify=not insecure,
                         proxy=proxy)
        self.api_key = api_key

    def http_request(self, params: Dict):
        return self._http_request(method='GET',
                                  url_suffix='geocode/json?',
                                  params={**params,
                                          'key': self.api_key})

    def google_maps_geocode(self, search_address: str) -> dict:
        return self.http_request(params={'address': search_address})


def google_maps_geocode_command(client: Client, search_address: str, error_on_no_results: bool) -> List[CommandResults]:
    response = client.google_maps_geocode(search_address)

    status = demisto.get(response, 'status')
    if status == STATUS_OK:
        return parse_response(response, search_address)

    elif status == STATUS_ZERO_RESULTS:
        if error_on_no_results:
            raise DemistoException(message=MESSAGE_ZERO_RESULTS, res=response)
        return [CommandResults(readable_output=MESSAGE_ZERO_RESULTS)]

    else:
        error_message = demisto.get(response, 'error_message') or ''
        raise DemistoException(message=error_message, res=response)


def test_module(client: Client) -> str:
    """Tests GoogleMaps by geocoding a specific address"""
    google_maps_geocode_command(client, '45 Rothschild, Tel Aviv', True)
    return 'ok'  # on any failure, an exception is raised


def parse_response(response: Dict, search_address: str) -> List[CommandResults]:
    """ Parses Google Maps API to a list of CommandResult objects """
    first_result = (response.get('results') or [])[0]

    coordinate_dict = demisto.get(first_result, 'geometry.location')
    response_address = demisto.get(first_result, 'formatted_address')

    country = None
    for component in first_result['address_components']:
        if 'country' in (demisto.get(component, 'types') or []):
            country = demisto.get(component, 'long_name')
            break

    note_outputs = {'SearchAddress': search_address,
                    'Address': response_address,
                    'Country': country,
                    **coordinate_dict}

    # noinspection PyTypeChecker
    readable_output = tableToMarkdown(name='Geocoding Results',
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


def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    proxy = demisto.get(params, 'proxy') or False
    base_url = demisto.get(params, 'base_url') or 'https://maps.googleapis.com/maps/api/'
    api_key = demisto.get(params, 'api_key.password') or ''
    insecure = demisto.get(params, 'insecure') or False
    error_on_no_results = demisto.get(params, 'error_on_no_results') or False

    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(base_url=base_url, api_key=api_key, proxy=proxy, insecure=insecure)

        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'google-maps-geocode':
            return_results(google_maps_geocode_command(client=client,
                                                       error_on_no_results=error_on_no_results,
                                                       **args))

        else:
            raise NotImplementedError(f"command '{command}' is not supported")

    except Exception as e:

        error_parts = [f'Failed to execute the {command} command.',
                       'Error:',
                       str(e)]

        if isinstance(e, DemistoException):
            error_parts.extend(('Raw response:', str(e.res)))  # pylint: disable=E1101

        return_error('\n'.join(error_parts))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
