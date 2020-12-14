from CommonServerPython import *

import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    def __init__(self, input_url: str, username: str, password: str, verify_certificate: bool, proxy: bool):
        base_url = urljoin(input_url, '/api/v2/')
        headers = {
            "Content-Type": "application/json",
        }
        authentication = (username, password)
        super(Client, self).__init__(base_url=base_url,
                                     verify=verify_certificate,
                                     headers=headers,
                                     auth=authentication,
                                     proxy=proxy)

    def api_request(self, url_suffix: str, data: dict = {}) -> dict:
        return self._http_request(method='GET', url_suffix=url_suffix, params=data)


def inventories_list(client: Client):


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    base_url = demisto.params()['url']

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')

    username = demisto.params().get("credentials")["identifier"],
    password = demisto.params().get("credentials")["password"],

    try:

        client = Client(
            base_url=base_url,
            username=username,
            password=password,
            verify=verify_certificate,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            # return_results(test_module(client))
            x=1

        elif demisto.command() == 'ansible-awx-inventories-list ':
            return_results(inventories_list(client,))


    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
