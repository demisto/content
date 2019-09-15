import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
from distutils.util import strtobool
from datetime import datetime

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' HELPERS '''


def convert_unix_to_date(d):
    """ Convert millise since epoch to date formatted MM/DD/YYYY HH:MI:SS """
    if d:
        dt = datetime.utcfromtimestamp(d / 1000)
        return dt.strftime('%m/%d/%Y %H:%M:%S')
    return 'N/A'


def convert_date_to_unix(d):
    """ Convert a given date to millis since epoch """
    return int((d - datetime.utcfromtimestamp(0)).total_seconds() * 1000)


class Client:
    def __init__(self, exabeam_url, credentials, password, verify, proxies):
        self.base_url = f'{exabeam_url}/uba/api/'
        self.credentials = credentials
        self.password = password
        self.verify = verify
        self.proxies = proxies

    def http_request(self, method, url_suffix, params=None, data=None):
        full_url = self.base_url + url_suffix

        res = requests.request(
            method,
            full_url,
            verify=self.verify,
            params=params,
            json=data,
            auth=(self.credentials, self.password),
            proxies=self.proxies
        )

        if res.status_code not in [200, 204]:
            raise ValueError(f'Error in API call to Exabeam {res.status_code}. Reason: {res.text}')

        try:
            return res.json()
        except Exception:
            raise ValueError(
                f'Failed to parse http response to JSON format. Original response body: \n{res.text}')

    def test_module(self):
        """
        Performs basic get request to check if the server is reachable.
        """
        suffix_url = 'ping'
        self.http_request('GET', suffix_url)
        return True

    def get_notable_users_request(self, unit=None, num=None, limit=None):

        suffix_url = 'users/notable'

        params = {
            'unit': unit,
            'num': num,
            'numberOfResults': limit
        }

        response = self.http_request('GET', suffix_url, params)
        return response


''' COMMANDS + REQUESTS FUNCTIONS '''


def get_notable_users(client, args):

    """
    Get notable users in a period of time
    """
    unit = args.get('time_duration_unit')
    num = args.get('time_duration_number')
    limit = args.get('limit')

    users = client.get_notable_users_request(unit, num, limit)

    return users


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    credentials = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')

    # Remove trailing slash to prevent wrong URL path to service
    server_url = demisto.params()['url'][:-1] \
        if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
    verify_certificate = not demisto.params().get('insecure', False)

    # Remove proxy if not set to true in params
    proxies = handle_proxy()

    LOG('Command being called is %s' % (demisto.command()))

    try:
        client = Client(server_url, verify_certificate, credentials, password, proxies)
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            client.test_module()
            demisto.results('ok')
        elif demisto.command() == 'get-notable-users':
            get_notable_users(client, demisto.args())

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

