import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR_NAME = 'CrowdStrikeMalquery'
DBOT_SCORE = {
    'unknown': 0,
    'clean': 1,
    'unwanted': 2,
    'malware': 3,
    'malicious': 3,
}

# Note: True life time of token is actually 30 mins
TOKEN_LIFE_TIME = 28


def get_passed_mins(start_time, end_time_str, tz=None):
    """
        Returns the time passed in mins
        :param start_time: Start time in datetime
        :param end_time_str: End time in str
        :return: The passed mins in int
    """
    time_delta = start_time - datetime.fromtimestamp(end_time_str, tz)
    return time_delta.seconds / 60


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

    def get_access_token(self):
        """
           Obtains access and refresh token from server.
           Access token is used and stored in the integration context until expiration time.
           After expiration, new refresh token and access token are obtained and stored in the
           integration context.

           Returns:
               str: Access token that will be added to authorization header.
       """
        now = datetime.now()
        integration_context = demisto.getIntegrationContext()[0] \
            if isinstance(demisto.getIntegrationContext(), list) else demisto.getIntegrationContext()
        access_token = integration_context.get('access_token')
        valid_until = integration_context.get('valid_until')
        if access_token:
            if get_passed_mins(now, valid_until) >= TOKEN_LIFE_TIME:
                # token expired
                access_token = self.get_token_request()
                integration_context = {'access_token': access_token, 'valid_until': date_to_timestamp(now) / 1000}
                demisto.setIntegrationContext(integration_context)
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
        return self.http_request(method="POST", url_suffix='/combined/fuzzy-search/v1', json_data=body, timeout=40)

    def hunt(self, body):
        return self.http_request(method="POST", url_suffix='/queries/hunt/v1', json_data=body)

    def get_request(self, request_id):
        params = {'ids': request_id}
        return self.http_request(method="GET", url_suffix='/entities/requests/v1', params=params)

    def get_quotas(self):
        return self.http_request(method="GET", url_suffix='/aggregates/quotas/v1')

    def file_download(self, file_id):
        headers = {"accept": "application/octet-stream"}
        params = {'ids': file_id}
        return self.http_request(method="GET", url_suffix='/entities/download-files/v1', headers=headers, params=params,
                                 resp_type="response")

    def samples_multidownload(self, body):
        return self.http_request(method="POST", url_suffix='/entities/samples-multidownload/v1', json_data=body)

    def fetch_samples(self, request_id):
        headers = {"accept": "application/zip"}
        params = {'ids': request_id}
        return self.http_request(method="GET", url_suffix='/entities/samples-fetch/v1', headers=headers, params=params,
                                 resp_type="response")

    def get_files_metadata(self, files_ids):
        params = {'ids': files_ids}
        return self.http_request(method="GET", url_suffix='/entities/metadata/v1', params=params)


def test_module(client: Client, args: dict):
    """
    Returning 'ok' indicates that an access token was obtained successfully. Connection to the service is successful.

    Args:
        client:  Client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        client.get_access_token()
    except Exception as e:
        raise DemistoException(
            f"Test failed. Please check your parameters. \n {e}")
    return 'ok'


def exact_search_command(client: Client, args: dict) -> CommandResults:
    pattern_names = ['hex', 'ascii', 'wide']
    patterns = [
        {
            "type": key,
            "value": args[key]
        } for key in pattern_names if args.get(key)
    ]

    # must provide a pattern (hex, ascii ot wide string)
    if not patterns:
        raise DemistoException("You must provide a query to search in one of the following patterns: Hex, ASCII, "
                               "Wide string")

    # dates format: YYYY/MM/DD
    query_filters = assign_params(limit=int(args.get('limit', '100')),
                                  filter_meta=argToList(args.get('filter_meta')),
                                  filter_filetypes=argToList(args.get('file_types')),
                                  max_size=args.get('max_size'),
                                  min_size=args.get('min_size'),
                                  max_date=args.get('max_date'),
                                  min_date=args.get('min_date'))
    body = {"options": query_filters, "patterns": patterns}
    raw_response = client.exact_search(body)
    entry_context = {"Request_ID": raw_response.get('meta', {}).get('reqid')}

    human_readable = tableToMarkdown('Search Result', entry_context, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='Malquery',
        outputs_key_field='Request_ID',
        outputs=entry_context,
        raw_response=raw_response)


def fuzzy_search_command(client: Client, args: dict) -> CommandResults:
    pattern_names = ['hex', 'ascii', 'wide']
    patterns = [
        {
            "type": key,
            "value": args[key]
        } for key in pattern_names if args.get(key)
    ]
    # must provide a pattern (hex, ascii ot wide string)
    if not patterns:
        raise DemistoException("You must provide a query to search in the following patterns: Hex, ASCII, Wide string")
    query_filters = assign_params(limit=int(args.get('limit', '100')),
                                  filter_meta=argToList(args.get('filter_meta')))
    body = {"options": query_filters, "patterns": patterns}
    raw_response = client.fuzzy_search(body)
    resources_found = raw_response.get('resources', {})
    human_readable = tableToMarkdown('Fuzzy Search Result', resources_found, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='Malquery.File(val.md5 && val.md5 == obj.md5 || val.sha256 && val.sha256 == obj.sha256)',
        outputs_key_field='',
        outputs=resources_found,
        raw_response=raw_response)


def hunt_command(client: Client, args: dict) -> CommandResults:
    yara_rule = args.get('yara_rule')
    yar_file_entry_id = args.get('yar_file_entry_id')
    if not (yara_rule or yar_file_entry_id):
        raise DemistoException("You must provide either a YARA rule or a YAR file in order to execute the HUNT command")

    if yar_file_entry_id:
        file_path = demisto.getFilePath(yar_file_entry_id).get("path")
        with open(file_path, "rb") as file:
            yara_rule = file.read().decode("utf-8")

    # dates format: YYYY/MM/DD
    query_filters = assign_params(limit=int(args.get('limit', '100')),
                                  filter_meta=argToList(args.get('filter_meta')),
                                  filter_filetypes=argToList(args.get('file_types')),
                                  max_size=args.get('max_size'),
                                  min_size=args.get('min_size'),
                                  max_date=args.get('max_date'),
                                  min_date=args.get('min_date'))
    body = {"options": query_filters, "yara_rule": yara_rule}
    raw_response = client.hunt(body)
    entry_context = {"Request_ID": raw_response.get('meta', {}).get('reqid')}
    human_readable = tableToMarkdown('Search Result', entry_context, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='Malquery',
        outputs_key_field='Request_ID',
        outputs=entry_context,
        raw_response=raw_response)


def get_request_command(client: Client, args: dict) -> CommandResults:
    request_id = args.get('request_id')
    raw_response = client.get_request(request_id)
    resources = raw_response.get('resources')
    status = raw_response.get('meta', {}).get('status')

    # Possible values: inprogress, failed, done
    if status != 'done':
        entry_context = {
            "Request_ID": request_id,
            "Status": status
        }
        human_readable = tableToMarkdown('Request Status:', entry_context, removeNull=True)
    else:
        entry_context = {
            "Request_ID": request_id,
            "Status": status,
            "File": resources if resources else None
        }
        human_readable = tableToMarkdown(f'Search Result for request: {request_id}', resources, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='Malquery',
        outputs_key_field='Request_ID',
        outputs=entry_context,
        raw_response=raw_response)


def get_file_metadata_command(client: Client, args: dict):
    files_ids = argToList(args.get('file'))
    raw_response = client.get_files_metadata(files_ids)
    files = raw_response.get('resources', [])
    command_results: List[CommandResults] = []

    for file in files:
        file_label = file.get('label')
        sha256 = file.get('sha256')
        dbot_score = Common.DBotScore(
            indicator=sha256,
            indicator_type=DBotScoreType.FILE,
            integration_name=VENDOR_NAME,
            score=DBOT_SCORE[file_label]
        )
        file_entry = Common.File(sha256=sha256, dbot_score=dbot_score)
        table_name = f'{VENDOR_NAME} File reputation for: {sha256}'
        md = tableToMarkdown(table_name, file, removeNull=True)

        command_results.append(CommandResults(
            outputs_prefix='Malquery.File',
            outputs_key_field='sha256',
            outputs=file,
            readable_output=md,
            raw_response=raw_response,
            indicator=file_entry)
        )

    return command_results


def file_download_command(client: Client, args: dict):
    file_id = args.get('file_id')
    raw_response = client.file_download(file_id)
    try:
        content = raw_response.content
    except Exception as e:
        raise DemistoException(
            f"Failed to load file data. \n {e}")

    return fileResult(file_id, content)


# Malquery counts the download as the number of sha256 passed to the endpoint and not as a single download.
def samples_multidownload_command(client: Client, args: dict) -> CommandResults:
    samples = argToList(args.get('samples'))
    body = {"samples": samples}
    raw_response = client.samples_multidownload(body)
    entry_context = {"Request_ID": raw_response.get('meta', {}).get('reqid')}
    human_readable = tableToMarkdown('Samples Multidownload Request', entry_context, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='Malquery',
        outputs_key_field='Request_ID',
        outputs=entry_context,
        raw_response=raw_response)


def samples_fetch_command(client: Client, args: dict):
    request_id = args.get('request_id')
    raw_response = client.fetch_samples(request_id)
    try:
        content = raw_response.content
        return fileResult(request_id, content)
    except DemistoException as e:
        if str(e).find('Could not find sample archive'):
            return 'Could not find sample archive, The file is not indexed by MalQuery.'
        else:
            raise


def get_ratelimit_command(client: Client, args: dict) -> CommandResults:
    raw_response = client.get_quotas()
    meta = raw_response.get('meta', {})
    headers = ['hunt_count', 'download_count', 'monitor_count', 'hunt_limit', 'download_limit', 'monitor_limit',
               'refresh_time', 'days_left']
    human_readable = tableToMarkdown('Quota Data', meta, headers=headers, removeNull=True)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='Malquery.Quota',
        outputs_key_field='refresh_time',
        outputs=meta,
        raw_response=raw_response)


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    client_id: str = params.get('client_id')
    client_secret: str = params.get('client_secret')
    base_url: str = urljoin(params.get('base_url', '').rstrip('/'), '/malquery')
    verify_certificate: bool = not params.get('insecure', False)
    proxy: bool = params.get('proxy', False)

    commands = {
        'test-module': test_module,
        'cs-malquery-exact-search': exact_search_command,
        'cs-malquery-fuzzy-search': fuzzy_search_command,
        'cs-malquery-hunt': hunt_command,
        'cs-malquery-get-request': get_request_command,
        'file': get_file_metadata_command,
        'cs-malquery-file-download': file_download_command,
        'cs-malquery-samples-multidownload': samples_multidownload_command,
        'cs-malquery-sample-fetch': samples_fetch_command,
        'cs-malquery-get-ratelimit': get_ratelimit_command,

    }
    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        handle_proxy()
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
