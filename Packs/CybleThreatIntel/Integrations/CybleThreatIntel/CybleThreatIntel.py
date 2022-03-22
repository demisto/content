import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import requests
from datetime import date, timedelta

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''

class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def get_taxii(self, method, taxiiurl, args):
        """
        Fetch Taxii events for the given parameters
        :param method: Requests method to be used
        :param taxiiurl: API URL Suffix to be used
        :param params:
        :return:
        """

        taxii_data = None
        params = {
            'token': args['token'],
            'page': int(args['page'] if 'page' in args.keys() else 1),
            'limit': int(args['limit'] if 'limit' in args.keys() else 1),
            'start_date': args['start_date'] if 'start_date' in args.keys() else "",
            'end_date': args['end_date'] if 'end_date' in args.keys() else ""
        }

        url = urljoin(self._base_url, taxiiurl)
        response = requests.request(method, url, data=params)
        resp = response.json()

        try:
            if 'count' in resp.keys():
                taxii_data = resp
            else:
                demisto.error("Error trying to Fetch Taxii's {}".format(resp))
        except Exception as e:
            demisto.error("[{}] exception seen for response [{}]".format(e, resp))
        return taxii_data


def get_test_response(client, method, params):
    """
    Test the integration connection state
    :param client: instance of client to communicate with server
    :param method: Requests method to be used
    :param params: Parameters for requests
    :return: Test Response Success or Failure
    """

    payload = params
    taxii_url = r'/taxii/stix-data/v21/get'
    result = client.get_taxii(method, taxii_url, payload)

    if result is not None:
        return 'ok'
    else:
        demisto.error("Failed to connect")
        return 'fail'


def cyble_fetch_taxii(client, method, args):
    '''
    TAXII feed details will be pulled from server
    :param client: instance of client to communicate with server
    :param method: Requests method to be used
    :param args: Parameters for fetching the feed
    :return: TAXII feed details
    '''

    params = {
        'token': args['token'],
        'page': int(args['page'] if 'page' in args.keys() else 1),
        'limit': int(args['limit'] if 'limit' in args.keys() else 1),
        'start_date': args['start_date'] if 'start_date' in args.keys() else "",
        'end_date': args['end_date'] if 'end_date' in args.keys() else "",
        'start_time': args['start_time'] if 'start_time' in args.keys() else "",
        'end_time': args['end_time'] if 'end_time' in args.keys() else ""
    }

    taxii_url = r'/taxii/stix-data/v21/get'
    result = client.get_taxii(method, taxii_url, params)

    if result is not None:
        return result
    return "Failed to Fetch Taxiis !!"


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # get the service API url
    base_url = demisto.params().get('url')
    token = demisto.params().get('token')

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)

        args = demisto.args()
        args['token'] = token

        if demisto.command() == 'test-module':
            if 'start_date' not in args.keys():
                args['start_date'] = datetime.today().strftime('%Y-%m-%d')
            if 'end_date' not in args.keys():
                args['end_date'] = datetime.today().strftime('%Y-%m-%d')
            if args['token'] is not None:
                resp = get_test_response(client, 'POST', args)
                # request was succesful
                return_results(resp)

        elif demisto.command() == 'cyble-vision-fetch-taxii':
            # fetch events using taxii service

            if 'start_date' not in args.keys():
                args['start_date'] = datetime.today().strftime('%Y-%m-%d')
            if 'end_date' not in args.keys():
                args['end_date'] = datetime.today().strftime('%Y-%m-%d')

            if args['token'] is not None:
                command_results = CommandResults(
                    outputs_prefix='CybleIntel.Threat',
                    outputs_key_field='details',
                    outputs=cyble_fetch_taxii(client, "POST", args)
                )
                return_results(command_results)
            else:
                demisto.error("Error fetching Threat Indicators.")

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()