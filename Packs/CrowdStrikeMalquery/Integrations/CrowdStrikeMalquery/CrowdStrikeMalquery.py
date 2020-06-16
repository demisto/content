import json
from typing import Tuple

import dateparser
import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# TODO - make sure to handle HTTP 429:
#  The MalQuery API is rate-limited based on your subscription. Each customer can make a number of searches and
#  downloads per month. If you reach your monthly quota, MalQuery API requests return an HTTP 429 status.


# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

# Note: True life time of token is actually 30 mins
TOKEN_LIFE_TIME = 28


def get_passed_mins(start_time, end_time_str):
    """
        Returns the time passed in mins
        :param start_time: Start time in datetime
        :param end_time_str: End time in str
        :return: The passed mins in int
    """
    time_delta = start_time - datetime.fromtimestamp(end_time_str)
    return time_delta.seconds / 60


def remove_None_values_keys(d):
    return {
        key: value
        for key, value in d.items()
        if value is not None
    }


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """
    def __init__(self, base_url, verify, proxy, client_id, client_secret):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.client_id = client_id,
        self.client_secret = client_secret

    def http_request(self, *args, headers=None, **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.

        Returns:
            requests.Response: The http response
        """
        token = self.get_access_token()
        default_headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }
        if headers:
            default_headers.update(headers)

        return super()._http_request(*args, headers=default_headers, **kwargs)  # type: ignore[misc]

    def get_access_token(self, new_token=False):
        """
            Retrieves the token from the server if it's expired and updates the global HEADERS to include it

            :param new_token: If set to True will generate a new token regardless of time passed

            :rtype: ``str``
            :return: Token
        """
        now = datetime.now()
        integration_context = demisto.getIntegrationContext()
        access_token = integration_context.get('access_token')
        valid_until = integration_context.get('valid_until')
        if access_token and not new_token:
            if get_passed_mins(now, valid_until) >= TOKEN_LIFE_TIME:
                # token expired
                access_token = self.get_token_request()
                integration_context = {
                    'access_token': access_token,
                    'valid_until': date_to_timestamp(now) / 1000},
                demisto.setIntegrationContext(integration_context)
                return access_token
            else:
                # token hasn't expired
                return access_token
        else:
            # there's no token
            access_token = self.get_token_request()
            integration_context = {'access_token': access_token,
                                   'valid_until': date_to_timestamp(now) / 1000},
            demisto.setIntegrationContext(integration_context)
            return access_token

    def get_token_request(self):
        """
            Sends token request

            :rtype ``str``
            :return: Access token
        """
        # body = f"client_id={self.client_id}&client_secret={self.client_secret}"
        body = {
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        token_response = self._http_request(method='POST', full_url='https://api.crowdstrike.com/oauth2/token',
                                            url_suffix='', data=body, headers=headers)
        if not token_response:
            err_msg = 'Authorization Error: User has no authorization to create a token.' \
                      ' Please make sure you entered the credentials correctly.'
            raise Exception(err_msg)
        return token_response.get('access_token')

    def exact_search(self, body):
        return self.http_request(method="POST", url_suffix='/queries/exact-search/v1', json_data=body)

    def fuzzy_search(self, body):
        return self.http_request(method="POST", url_suffix='/combined/fuzzy-search/v1', json_data=body)

    def hunt(self, body):
        return self.http_request(method="POST", url_suffix='/queries/hunt/v1', json_data=body)

    def get_request(self, request_id):
        params = {'ids': request_id}
        return self.http_request(method="GET", url_suffix='/entities/requests/v1', params=params)


def test_module(client: Client, args: dict):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        client.get_access_token()
    except Exception as e:
        raise DemistoException(
            f"Test failed. Please check your parameters. \n {e}")
    return 'ok'


# all the commands return request_id in order to question the server onc again. do we wnat to genric polling it or
# poll the results ourselves?
def exact_search_command(client: Client, args: dict) -> CommandResults:
    pattern_names = ['hex', 'ascii', 'wide_string']
    patterns = [
        {
            "type": key,
            "value": args[key]
        } for key in pattern_names if args.get(key)
    ]

    # must provide a pattern (hex, ascii ot wide string)
    if not patterns:
        raise DemistoException("You must provide a query to search in the following patterns: Hex, ASCII, Wide string")

    # TODO: Check how a comma separated args returns and validate values types are the same as the api
    # dates format: YYYY/MM/DD
    query_filters = {
        "limit": int(args.get('limit')) if args.get('limit') else None,
        "filter_meta": args.get('filter_meta'),
        "filter_filetypes": args.get('file_types'),
        "max_size": args.get('max_size'),
        "min_size": args.get('min_size'),
        "max_date": args.get('max_date'),
        "min_date": args.get('min_date'), }
    options = remove_None_values_keys(query_filters)
    body = {"options": options, "patterns": patterns}
    raw_response = client.exact_search(body)
    entry_context = {
        "Request_ID": raw_response.get('meta', {}).get('reqid'),
        "Status": raw_response.get('meta', {}).get('status')
    }

    human_readable = tableToMarkdown('Search Result', entry_context, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='Malquery',
        outputs_key_field='Request_ID',
        outputs=entry_context,
        raw_response=raw_response)


def fuzzy_search_command(client: Client, args: dict) -> CommandResults:
    pattern_names = ['hex', 'ascii', 'wide_string']
    patterns = [
        {
            "type": key,
            "value": args[key]
        } for key in pattern_names if args.get(key)
    ]
    # must provide a pattern (hex, ascii ot wide string)
    if not patterns:
        raise DemistoException("You must provide a query to search in the following patterns: Hex, ASCII, Wide string")

    query_filters = {
        "limit": int(args.get('limit')) if args.get('limit') else None,
        "filter_meta": args.get('filter_meta'),
     }
    options = remove_None_values_keys(query_filters)
    body = {"options": options, "patterns": patterns}
    raw_response = client.fuzzy_search(body)
    entry_context = {
        "Request_ID": raw_response.get('meta', {}).get('reqid'),
        "Status": raw_response.get('meta', {}).get('status')
    }
    human_readable = tableToMarkdown('Search Result', entry_context, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='Malquery',
        outputs_key_field='Request_ID',
        outputs=entry_context,
        raw_response=raw_response)


# TODO: Need to check with the yara_rule
def hunt_command(client: Client, args: dict) -> CommandResults:
    yara_rule = args.get('yara_rule')

    # TODO: Check how a comma separated args returns and validate values types are the same as the api
    # dates format: YYYY/MM/DD
    query_filters = {
        "limit": int(args.get('limit')) if args.get('limit') else None,
        "filter_meta": args.get('filter_meta'),
        "filter_filetypes": args.get('file_types'),
        "max_size": args.get('max_size'),
        "min_size": args.get('min_size'),
        "max_date": args.get('max_date'),
        "min_date": args.get('min_date'), }
    options = remove_None_values_keys(query_filters)
    body = {"options": options, "yara_rule": yara_rule}
    raw_response = client.hunt(body)
    entry_context = {
        "Request_ID": raw_response.get('meta', {}).get('reqid'),
        "Status": raw_response.get('meta', {}).get('status')
    }

    human_readable = tableToMarkdown('Search Result', entry_context, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='Malquery',
        outputs_key_field='Request_ID',
        outputs=entry_context,
        raw_response=raw_response)


# TODO: ask arseny how the context should look like
def get_request_command(client: Client, args: dict):
    request_id = args.get('request_id')
    raw_response = client.get_request(request_id)
    resources = raw_response.get('resources')
    entry_context = {
        "Request_ID": raw_response.get('meta', {}).get('reqid'),
        "Status": raw_response.get('meta', {}).get('status'),
        "Resources_Found": resources
    }

    human_readable = tableToMarkdown('Search Result', entry_context, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='Malquery',
        outputs_key_field='Request_ID',
        outputs=entry_context,
        raw_response=raw_response)


def get_file_metadata_command():
    pass


def file_download_command():
    pass


def sample_multidownload_command():
    pass


def sample_fetch_command():
    pass


def get_ratelimit_command():
    pass


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # TODO: add typing
    params = demisto.params()
    client_id = params.get('client_id')
    client_secret = params.get('client_secret')
    base_url = urljoin(params.get('base_url', '').rstrip('/'), '/malquery')

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    commands = {
        'test-module': test_module,
        'cs-malquery-exact-search': exact_search_command,
        'cs-malquery-fuzzy-search': fuzzy_search_command,
        'cs-malquery-hunt': hunt_command,
        'cs-malquery-request-get-status': get_request_command,
        'file': get_file_metadata_command,
        'cs-malquery-file-download': file_download_command,
        'cs-malquery-sample-multidownload': sample_multidownload_command,
        'cs-malquery-sample-fetch': sample_fetch_command,
        'cs-malquery-ratelimit-get': get_ratelimit_command,

    }
    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            client_id=client_id,
            client_secret=client_secret,
            proxy=proxy)

        if command in commands:
            return_results(commands[command](client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
