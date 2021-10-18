from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool = True, proxy: bool = False, ok_codes=tuple(), headers: dict = None,
                 token: str = None):
        super().__init__(base_url, verify, proxy, ok_codes, headers)
        self.token = token

    def get_file_report(self, file_hash: str):
        return self._http_request(
            'POST',
            url_suffix='/get/report',
            params={'apikey': self.token, 'format': 'pdf', 'hash': file_hash},
            resp_type='response',
            ok_codes=(200, 404),
        )


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    try:
        wildfire_hash_example = 'dca86121cc7427e375fd24fe5871d727'  # guardrails-disable-line
        client.get_file_report(wildfire_hash_example)
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def wildfire_get_report_command(client: Client, args: Dict[str, str]):
    """
    Args:
        client: the Client object
        args: the command arguments from demisto.args(), file hash (sha256) to query on
    """
    sha256 = str(args.get('sha256'))
    if not sha256Regex.match(sha256):
        raise Exception('Invalid hash. Only SHA256 are supported.')

    res = client.get_file_report(sha256)

    if res.status_code == 200:
        return_results({
            'status': 'success',
            'data': base64.b64encode(res.content).decode()
        })

    elif res.status_code == 404:
        return_results({
            'status': 'not found'
        })


''' MAIN FUNCTION '''


def main():
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    base_url = params.get('server')
    if base_url and base_url[-1] == '/':
        base_url = base_url[:-1]
    if base_url and not base_url.endswith('/publicapi'):
        base_url += '/publicapi'
    token = params.get('token')
    if not token:
        token = demisto.getLicenseCustomField("WildFire-Reports.token")
    if not token:
        return_results({
            'status': 'error',
            'error': {
                'title': "Couldn't fetch the Wildfire report.",
                'description': "The token can't be empty.",
                'techInfo': "The token can't be empty, Please fill the token in the instance configuration or in the license."
            }
        })
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            token=token,
            headers=headers,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == 'test-module':
            result = test_module(client)
            return_results(result)

        elif command == 'wildfire-get-report':
            wildfire_get_report_command(client, args)

    # Log exceptions and return errors
    except Exception as e:
        # demisto.error(traceback.format_exc())  # print the traceback
        # Its not an error because it's not return to the warroom
        return_results({
            'status': 'error',
            'error': {
                'title': "Couldn't fetch the Wildfire report.",
                'description': f'Failed to download report.\nError:\n{str(e)}',
                'techInfo': f'Failed to execute command {demisto.command()}.\nError:\n{str(e)}\n'
                            f'Trace back:\n{traceback.format_exc()}'
            }
        })


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
