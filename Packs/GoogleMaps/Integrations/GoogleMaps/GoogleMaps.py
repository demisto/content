from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any, Tuple, List

# Disable insecure warnings
from Packs.Base.Scripts.CommonServerPython.CommonServerPython import BaseClient

requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


class Client(BaseClient):
    def __init__(self, api_key: str, proxy: bool):
        """
        Client to use in the IPinfo integration. Uses BaseClient
        """
        super().__init__(base_url='https://maps.googleapis.com/maps/api/',
                         proxy=proxy)
        self.api_key = api_key

    def geocode(self, address: str):
        address = re.sub(r'\s+', '+', address).strip('+')  # Google Maps API format

        # noinspection PyTypeChecker
        response: List[Dict[str, Any]] = self._http_request(method='GET',
                                                            url_suffix='geocode/json?',
                                                            params=assign_params(address=address,
                                                                                 api_key=self.api_key))

        coordinate_dict = response[0]['geometry']['location']
        return_results(CommandResults(outputs_prefix='GoogleMaps',
                                      outputs_key_field=['lat', 'lon'],
                                      entry_type=EntryType.MAP_ENTRY_TYPE,
                                      outputs=coordinate_dict,
                                      raw_response=response))


def google_maps_geocode_command(client: Client, address: str):
    return client.geocode(address)


def test_module(client: Client) -> str:
    """Tests GoogleMaps by geocoding the address of our TLV site"""
    client.geocode('94 Yigal Alon, Tel Aviv')
    return 'ok'  # on any failure, an exception is raised


def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    proxy = demisto.get(params, 'proxy') or False
    api_key = demisto.get(params, 'credentials.password') or ''

    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(api_key=api_key, proxy=proxy)

        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'geocode':
            google_maps_geocode_command(client, **args)
        else:
            raise NotImplementedError(f"command {command} is not supported")

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.'
                     f'\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
