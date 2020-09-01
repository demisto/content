import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''
import traceback
import tempfile

''' CONSTANTS '''
BASE_URL = 'https://api.adp.com/'
TOKEN_REQUEST_URL = 'https://accounts.adp.com/auth/oauth/v2/token'  # guardrails-disable-line
GRANT_TYPE_CLIENT_CREDENTIALS = 'client_credentials'

'''CLIENT CLASS'''


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """
    cert_file = tempfile.NamedTemporaryFile().name

    def __init__(self, base_url, cert=None, verify=True, proxy=False,
                 ok_codes=tuple(), headers=None, auth=None, client_id=None, client_secret=None):

        # Load the cert for Mutual TLS
        with open(self.cert_file, "w") as text_file:
            text_file.write(cert)
        self._base_url = base_url
        self._verify = verify
        self._ok_codes = ok_codes
        self._headers = headers
        self._auth = auth
        self._session = requests.Session()
        if not proxy:
            self._session.trust_env = False

        access_token = self.get_access_token(client_id, client_secret)
        self._headers['Authorization'] = f'Bearer {access_token}'

    def get_access_token(self, client_id, client_secret):

        query_params = {
            'grant_type': GRANT_TYPE_CLIENT_CREDENTIALS
        }
        res = self._http_request(method="POST", full_url=TOKEN_REQUEST_URL, url_suffix=None, params=query_params,
                                 cert=self.cert_file, auth=requests.auth.HTTPBasicAuth(client_id, client_secret))
        access_token = res.get('access_token')

        return access_token

    # This makes a call to ADP that triggers async process on ADP. ADP will send a retry-after header to try after that
    def get_workers_async(self):
        uri_suffix = '/hr/v2/workers'
        query_params = {
            'count': 'true'
        }
        headers = self._headers
        headers['prefer'] = 'respond-async'

        return self._http_request(method="GET", url_suffix=uri_suffix, headers=headers, resp_type='response',
                                  params=query_params, cert=self.cert_file)

    def get_workers_by_uri(self, uri):
        return self.get_paged_workers(uri)

    def get_paged_workers(self, uri):
        workers_list = []
        res = self._http_request(method="GET", url_suffix=uri, cert=self.cert_file, resp_type='response')
        if res.status_code == 200:
            workers = res.json().get('workers', [])
            workers_list.extend(workers)

        while "location" in res.headers and res.status_code == 200:
            next_page_uri = res.headers.get('location')
            res = self._http_request(method="GET", url_suffix=next_page_uri, cert=self.cert_file, resp_type='response')
            workers = res.json().get('workers', [])
            workers_list.extend(workers)
        return workers_list

    def get_workers_by_associate_oid(self, associate_oid):
        uri_suffix = f'/hr/v2/workers/{associate_oid}'
        return self._http_request(method="GET", url_suffix=uri_suffix, cert=self.cert_file)


''' COMMAND FUNCTIONS '''


def test_module(client, args):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    uri_suffix = '/hr/v2/workers'
    query_params = {
        '$top': '1'
    }

    client._http_request(method="GET", url_suffix=uri_suffix, params=query_params, cert=client.cert_file)
    return 'ok', None, None


def get_worker_command(client, args):
    res = client.get_workers_by_associate_oid(args.get('associateOID'))
    readable_output = tableToMarkdown('ADP Worker:', res)

    return (
        readable_output,
        {},
        res
    )


def get_all_workers_trigger_async_command(client, args):
    res = client.get_workers_async()
    retry_after = res.headers["Retry-After"]
    # Get next URI from the response headers
    async_uri = res.links.get('/adp/processing-status', {}).get('url')

    outputs = {
        'ADP': {
            'WorkersURI': async_uri,
            "RetryAfter": retry_after
        }
    }

    readable_output = tableToMarkdown('ADP Async Response:', outputs.get('ADP'))

    return (
        readable_output,
        outputs,
        None
    )


def get_all_workers_command(client, args):

    workers_uri = args.get('workersURI')
    workers = client.get_workers_by_uri(workers_uri)

    return (
        None,
        {},
        workers
    )


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()

    LOG(f'Command being called is {command}')
    commands = {
        'test-module': test_module,
        'adp-get-worker': get_worker_command,
        'adp-get-all-workers-trigger-async': get_all_workers_trigger_async_command,
        'adp-get-all-workers': get_all_workers_command
    }

    adp_credentials = params.get('adp_credentials', {})

    client_id = adp_credentials.get('identifier')
    client_secret = adp_credentials.get('password')
    credentials = adp_credentials.get('credentials')
    cert = credentials.get('sshkey') if credentials.get('sshkey') else params.get('cert_file')

    if not cert:
        raise Exception('ADP Certificate and Key is required to call the APIs')

    client = Client(
        base_url=BASE_URL,
        verify=verify_certificate,
        headers={
            'Accept': 'application/json'
        },
        proxy=proxy,
        cert=cert,
        client_id=client_id,
        client_secret=client_secret
    )
    try:
        if command in commands:
            human_readable, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)
    # Log exceptions
    except Exception:
        return_error(f'Failed to execute {demisto.command()} command. Traceback: {traceback.format_exc()}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
