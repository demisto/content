from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any, Tuple, List

# Disable insecure warnings
from Packs.Base.Scripts.CommonServerPython.CommonServerPython import BaseClient

requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


def parse_geocoding_response(response: List[Dict[str, Any]]) -> Tuple[float, float]:
    coordinates = response[0]['geometry']['location']
    return coordinates['lat'], coordinates['lon']


class Client(BaseClient):
    def __init__(self, api_key: str, proxy: bool):
        """
        Client to use in the IPinfo integration. Uses BaseClient
        """
        super().__init__(base_url='https://maps.googleapis.com/maps/api/', proxy=proxy)
        self.api_key = api_key

    def geocode(self, address: str) -> Tuple[float, float]:
        address = address.replace(' ', '+')

        response = self._http_request(method='GET',
                                      url_suffix='geocode/json?',
                                      params=assign_params(address=address, api_key=self.api_key))

        # noinspection PyTypeChecker
        return parse_geocoding_response(response)


def main():
    pass

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
