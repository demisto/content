import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
date_format = "%Y-%m-%d"
time_format = "%H:%M:%S"


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
            'start_date': datetime.strptime(args.get('start_date'), date_format).date(),
            'end_date': datetime.strptime(args.get('end_date'), date_format).date(),
            'start_time': datetime.strptime(args.get('start_time', '00:00:00'), time_format).time(),
            'end_time': datetime.strptime(args.get('end_time', '00:00:00'), time_format).time(),
        }

        url = urljoin(self._base_url, taxiiurl)
        response = requests.request(method, url, data=params)
        resp = response.json()

        try:
            if 'count' in resp.keys():
                taxii_data = resp
            else:
                taxii_data = resp
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
    ret_val = 'ok'
    payload = params
    taxii_url = r'/taxii/stix-data/v21/get'
    if params.get('token'):
        result = client.get_taxii(method, taxii_url, payload)
        if result.get('message') or False:
            ret_val = result
        elif not len(result):
            ret_val = "Failed to fetch feed!!"
    else:
        ret_val = 'Access token missing.'

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
        'start_date': args.get('start_date'),
        'end_date': args.get('end_date'),
        'start_time': args.get('start_time', '00:00:00'),
        'end_time': args.get('end_time', '00:00:00')
    }

    taxii_url = r'/taxii/stix-data/v21/get'
    if args.get('token'):
        result = client.get_taxii(method, taxii_url, params)
    else:
        result = {"error": "Invalid Token!!"}

    temp_list = []
    for eachone in result.get('result', []):
        temp_list.append(eachone.get('indicator'))

    md = tableToMarkdown('Indicator Details:', temp_list, headers=['name', 'indicator_types', 'pattern', 'modified'])
    command_results = CommandResults(
        readable_output=md,
        outputs_prefix='CybleIntel.Threat',
        outputs_key_field='details',
        outputs=result
    )

    return command_results


def validate_input(args):
    """
    Check if the input params for the command are valid. Return an error if any
    :param args: dictionary of input params
    """
    try:
        # we assume all the params to be non-empty, as cortex ensures it
        if int(args.get('page', '1')) <= 0:
            raise ValueError(f"Parameter should be positive number, page: {arg_to_number(args.get('page'))}'")

        if int(args.get('limit', '1')) <= 0 or int(args.get('limit', '1')) > 20:
            raise ValueError(f"Limit should be positive number upto 20, limit: {arg_to_number(args.get('limit', 0))}")

        date_format = "%Y-%m-%d"
        try:
            _start_date = datetime.strptime(args.get('start_date'), date_format)
            _end_date = datetime.strptime(args.get('end_date'), date_format)
        except Exception:
            raise ValueError("Invalid date format received")

        if _start_date > datetime.today():
            raise ValueError(f"Start date must be a date before or equal to {datetime.today().strftime(date_format)}")
        if _end_date > datetime.today():
            raise ValueError(f"End date must be a date before or equal to {datetime.today().strftime(date_format)}")
        if _start_date > _end_date:
            raise ValueError(f"Start date {args.get('start_date')} cannot be after end date {args.get('end_date')}")

        time_format = "%H:%M:%S"
        try:
            datetime.strptime(args.get('start_time', '00:00:00'), time_format).time()
            datetime.strptime(args.get('end_time', '00:00:00'), time_format).time()
        except Exception:
            raise ValueError("Invalid time format received")

        return None
    except Exception as e:
        demisto.error("Exception with validating inputs [{}]".format(e))
        raise e


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
            args['start_date'] = datetime.today().strftime(date_format)
        if 'end_date' not in args.keys():
            args['end_date'] = datetime.today().strftime(date_format)

        if demisto.command() == 'test-module':
            return_results(get_test_response(client, 'POST', args))

        elif demisto.command() == 'cyble-vision-fetch-taxii':
            # fetch events using taxii service
            validate_input(args)
            return_results(cyble_fetch_taxii(client, "POST", args))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
