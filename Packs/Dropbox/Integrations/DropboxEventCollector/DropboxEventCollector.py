# pylint: disable=no-name-in-module
# pylint: disable=no-self-argument
import json

import urllib3
from pydantic import parse_obj_as

from SiemApiModule import *  # noqa: E402

urllib3.disable_warnings()
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VENDOR = "dropbox"
PRODUCT = "dropbox"


class DropboxEventsRequestConfig(IntegrationHTTPRequest):
    # Endpoint: https://api.dropbox.com/2/team_log/get_events
    url: AnyUrl = parse_obj_as(AnyUrl, 'https://api.dropbox.com')
    method: Method = Method.POST
    headers: dict = {'Content-Type': 'application/json'}
    data: str
    verify: bool = not demisto.params().get('insecure')


class DropboxEventsClient(IntegrationEventsClient):
    request: DropboxEventsRequestConfig
    options: IntegrationOptions
    credentials: Credentials

    def __init__(
        self,
        request: DropboxEventsRequestConfig,
        options: IntegrationOptions,
        credentials: Credentials,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.credentials = credentials
        self.refresh_token = demisto.getIntegrationContext().get('refresh_token')
        if session is None:
            session = requests.Session()
        super().__init__(request, options, session)

    def set_request_filter(self, cursor: str):
        if 'continue' not in str(self.request.url):
            demisto.info('continue not in request url')
            self.request.url = parse_obj_as(AnyUrl, f'{str(self.request.url).removesuffix("/")}/continue')

        self.request.data = json.dumps({'cursor': cursor})

    def get_access_token(self):
        request = IntegrationHTTPRequest(
            method=Method.POST,
            url=f'{str(self.request.url).removesuffix("/")}/oauth2/token',  # type: ignore[arg-type]
            data={'grant_type': 'refresh_token', 'refresh_token': f'{self.refresh_token}'},
            auth=HTTPBasicAuth(self.credentials.identifier, self.credentials.password),  # type: ignore[arg-type]
            verify=self.request.verify,
        )
        response = self.call(request)
        demisto.debug(f'Send request to obtain access_token get status code: {response.status_code}')       # pragma: no cover
        self.request.headers['Authorization'] = f'Bearer {response.json()["access_token"]}'
        self.request.url = parse_obj_as(AnyUrl, f'{str(self.request.url).removesuffix("/")}/2/team_log/get_events')


class DropboxEventsGetter(IntegrationGetEvents):
    client: DropboxEventsClient

    def get_last_run(self: Any, event: dict) -> dict:  # type: ignore
        last_datetime = datetime.strptime(event.get('timestamp', ''), DATETIME_FORMAT) + timedelta(seconds=1)
        return {'start_time': datetime.strftime(last_datetime, DATETIME_FORMAT)}

    def _iter_events(self):
        self.client.get_access_token()
        # region First Call
        results = self.client.call(self.client.request).json()
        # endregion

        # region Yield Response
        while results.get('events'):  # Run as long there are logs
            yield sorted(results.get('events', []), key=lambda d: d.get('timestamp'))

            if results.get('has_more'):
                self.client.set_request_filter(results.get('cursor'))
                demisto.debug(
                    f'Setting the next request filter {results.get("cursor")}'      # pragma: no cover
                )
                results = self.client.call(self.client.request).json()
            else:
                break


# ----------------------------------------- Authentication Functions -----------------------------------------

def start_auth_command(base_url: str, app_key: str) -> CommandResults:      # pragma: no cover
    url = f'https://www.dropbox.com/oauth2/authorize?client_id={app_key}&token_access_type=offline&response_type=code'
    message = f"""### Authorization instructions
1. To sign in, use a web browser to open the page [{url}]({url})
2. Run the **!dropbox-auth-complete** command with the code returned from Dropbox in the War Room."""
    demisto.debug('start auth command')
    return CommandResults(readable_output=message)


def complete_auth_command(code: str, credentials: Credentials, base_url: str, insecure: bool) -> CommandResults:
    data = {
        'grant_type': 'authorization_code',
        'code': code,
    }
    auth = (credentials.identifier or '', credentials.password)
    redable_output = ''
    response = requests.post(f'{base_url}/oauth2/token', data=data, auth=auth, verify=insecure)
    if response.ok:
        demisto.setIntegrationContext({'refresh_token': response.json()['refresh_token']})
        readable_output = '✅ Authorization completed successfully.'
    else:
        readable_output = f'❌ Authorization completed failed. {response.text}'

    demisto.debug(f'Complete auth command {readable_output=}')  # pragma: no cover
    return CommandResults(readable_output=redable_output)


def reset_auth_command() -> CommandResults:
    demisto.debug('resetting integration context to empty dict.')  # pragma: no cover
    set_integration_context({})
    message = 'Authorization was reset successfully. Run **!dropbox-auth-start** to start the authentication process.'
    return CommandResults(readable_output=message)


def test_connection(events_client: DropboxEventsGetter) -> str:
    events_client.run()
    return '✅ Success.'


# ----------------------------------------- Main Functions -----------------------------------------

def main(command: str, demisto_params: dict):
    first_fetch = datetime.strftime(
        dateparser.parse(demisto_params.get('fetch_from', '')) or datetime.now() - timedelta(days=7), DATETIME_FORMAT
    )
    start_time = demisto_params.get('start_time', first_fetch)
    request = DropboxEventsRequestConfig(data=json.dumps({'time': {'start_time': start_time}}), **demisto_params)
    credentials = Credentials(**demisto_params.get('credentials', {}))
    options = IntegrationOptions(**demisto_params)
    client = DropboxEventsClient(request, options, credentials)
    get_events = DropboxEventsGetter(client, options)

    try:
        base_url = str(demisto_params.get('url')).removesuffix('/')
        insecure = not demisto_params.get('insecure')

        if command == 'test-module':
            raise DemistoException("Please run the !dropbox-auth-test command in order to test the connection")

        # ----- Authentication Commands ----- #
        elif command == 'dropbox-auth-start':
            return_results(start_auth_command(base_url, str(credentials.identifier)))

        elif command == 'dropbox-auth-complete':
            return_results(complete_auth_command(str(demisto_params.get('code')), credentials, base_url, insecure))

        elif not demisto.getIntegrationContext().get('refresh_token'):
            demisto.debug('Integration getIntegrationContext.get(refresh_token) is empty run auth start.')  # pragma: no cover
            return_results(CommandResults(readable_output='Please run the **!dropbox-auth-start** command first'))

        elif command == 'dropbox-auth-reset':
            return_results(reset_auth_command())

        elif command == 'dropbox-auth-test':
            results = test_connection(get_events)
            return_results(CommandResults(readable_output=results))

        # ----- Fetch/Get events command ----- #
        elif command in ('fetch-events', 'dropbox-get-events'):
            events = get_events.run()

            if command == 'fetch-events' or argToBoolean(demisto_params.get('should_push_events')):
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

                if events:
                    last_run = get_events.get_last_run(events[-1])
                    demisto.debug(f'Set last run to {last_run}')    # pragma: no cover.
                    demisto.setLastRun(last_run)

            if command == 'dropbox-get-events':
                command_results = CommandResults(
                    readable_output=tableToMarkdown(
                        'Dropbox logs', events, removeNull=True, headerTransform=pascalToSpace
                    ),
                    raw_response=events,
                )
                return_results(command_results)

    except Exception as e:
        return_error(
            f'An error was returned from dropbox event collector while executing {command} command. error: {str(e)}'
        )


if __name__ in ('__main__', '__builtin__', 'builtins'):
    # Args is always stronger. Get getLastRun even stronger
    demisto_params_ = demisto.params() | demisto.args() | demisto.getLastRun()
    main(demisto.command(), demisto_params_)
