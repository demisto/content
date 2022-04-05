import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import requests

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
            'token': args.get('token', ''),
            'page': arg_to_number(args.get('page', 1)),
            'limit': arg_to_number(args.get('limit', 1)),
            'start_date': args.get('start_date', ''),
            'end_date': args.get('end_date', '')
        }

        url = urljoin(self._base_url, taxiiurl)
        response = requests.request(method, url, data=params)
        resp = response.json()

        try:
            if 'count' in resp.keys():
                taxii_data = resp
            else:
                taxii_data = {"error": "Failed to fetch feed!!"}
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
        if not result.get('error'):
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
        'token': args.get('token', ''),
        'page': arg_to_number(args.get('page', 1)),
        'limit': arg_to_number(args.get('limit', 1)),
        'start_date': args.get('start_date', ''),
        'end_date': args.get('end_date', ''),
        'start_time': args.get('start_time', ''),
        'end_time': args.get('end_time', ''),
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
