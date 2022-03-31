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

        taxii_data = {}
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
                taxii_data = {"error": "Failed to fetch feed!!"}
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
    ret_val = 'fail'
    payload = params
    taxii_url = r'/taxii/stix-data/v21/get'
    if params.get('token'):
        result = client.get_taxii(method, taxii_url, payload)
        if result:
            ret_val = 'ok'
    else:
        demisto.error("Failed to connect")

    return ret_val


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
    if args.get('token'):
        result = client.get_taxii(method, taxii_url, params)
    else:
        result = {"error": "Invalid Token!!"}

    command_results = CommandResults(
        outputs_prefix='CybleIntel.Threat',
        outputs_key_field='details',
        outputs=result
    )

    return command_results


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
        if 'start_date' not in args.keys():
            args['start_date'] = datetime.today().strftime('%Y-%m-%d')
        if 'end_date' not in args.keys():
            args['end_date'] = datetime.today().strftime('%Y-%m-%d')

        if demisto.command() == 'test-module':
            return_results(get_test_response(client, 'POST', args))

        elif demisto.command() == 'cyble-vision-fetch-taxii':
            # fetch events using taxii service
            return_results(cyble_fetch_taxii(client, "POST", args))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()