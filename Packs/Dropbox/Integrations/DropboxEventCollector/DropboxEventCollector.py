# pylint: disable=no-name-in-module
# pylint: disable=no-self-argument
import json

import urllib3
from pydantic import parse_obj_as

from SiemApiModule import *  # noqa: E402

urllib3.disable_warnings()
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class DropboxEventsRequestConfig(IntegrationHTTPRequest):
    # Endpoint: https://api.dropbox.com/2/team_log/get_events
    url = parse_obj_as(AnyUrl, 'https://api.dropbox.com/2/team_log/get_events')
    method = Method.POST
    headers = {'Content-Type': 'application/json'}
    data: str
    verify = not demisto.params().get('insecure')


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
        if 'continue' not in self.request.url:
            self.request.url += '/continue'
        self.request.data = json.dumps({'cursor': cursor})

    def get_access_token(self):
        request = IntegrationHTTPRequest(
            method=Method.POST,
            url=parse_obj_as(AnyUrl, 'https://api.dropbox.com/oauth2/token'),
            data={'grant_type': 'refresh_token', 'refresh_token': f'{self.refresh_token}'},
            auth=HTTPBasicAuth(self.credentials.identifier, self.credentials.password),
            verify=self.request.verify,
        )
        response = self.call(request)
        self.request.headers['Authorization'] = f'Bearer {response.json()["access_token"]}'


class DropboxEventsGetter(IntegrationGetEvents):
    client: DropboxEventsClient

    def get_last_run(self: Any, events: list[dict]) -> dict:  # type: ignore
        last_datetime = max([datetime.strptime(event.get('timestamp'), DATETIME_FORMAT) for event in events])
        last_datetime_with_delta = last_datetime + timedelta(milliseconds=1)
        return {'start_time': datetime.strftime(last_datetime_with_delta, DATETIME_FORMAT)}

    def _iter_events(self):
        self.client.get_access_token()
        # region First Call
        results = self.client.call(self.client.request).json()
        # endregion

        # region Yield Response
        while events := results.get('events'):  # Run as long there are logs
            yield events

            if results.get('has_more'):
                self.client.set_request_filter(results.get('cursor'))
                demisto.debug(
                    f'Setting the next request filter {results.get("cursor")}'
                )
                results = self.client.call(self.client.request).json()
            else:
                break


# ----------------------------------------- Authentication Functions -----------------------------------------

def start_auth_command(app_key: str) -> CommandResults:
    url = f'https://www.dropbox.com/oauth2/authorize?client_id={app_key}&token_access_type=offline&response_type=code'
    message = f"""### Authorization instructions
1. To sign in, use a web browser to open the page [{url}]({url})
2. Run the **auth-complete** command with the code returned from Dropbox in the War Room."""
    return CommandResults(readable_output=message)


def complete_auth_command(code: str, credentials: Credentials, insecure: bool) -> CommandResults:
    data = {
        'grant_type': 'authorization_code',
        'code': code,
    }
    auth = (credentials.identifier, credentials.password)

    response = requests.post('https://api.dropbox.com/oauth2/token', data=data, auth=auth, verify=insecure)
    if response.ok:
        demisto.setIntegrationContext({'refresh_token': response.json()['refresh_token']})
    else:
        return CommandResults(readable_output=f'❌ Authorization completed failed. {response.text}')

    return CommandResults(readable_output='✅ Authorization completed successfully.')


def reset_auth_command() -> CommandResults:
    set_integration_context({})
    message = 'Authorization was reset successfully. Run **!dropbox-auth-start** to start the authentication process.'
    return CommandResults(readable_output=message)


def test_connection(refresh_token: str, credentials: Credentials, insecure: bool) -> CommandResults:
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': f'{refresh_token}',
    }
    auth = (credentials.identifier, credentials.password)

    response = requests.post('https://api.dropbox.com/oauth2/token', data=data, auth=auth, verify=insecure)

    if response.ok and response.json().get('access_token'):
        return CommandResults(readable_output='✅ Success.')


# ----------------------------------------- Main Functions -----------------------------------------

def main(command: str, demisto_params: dict):
    first_fetch = datetime.strftime(dateparser.parse(demisto_params.get('fetch_from', '7 days')), DATETIME_FORMAT)
    start_time = demisto_params.get('start_time', first_fetch)
    request = DropboxEventsRequestConfig(data=json.dumps({'time': {'start_time': start_time}}), **demisto_params)
    credentials = Credentials(**demisto_params.get('credentials', {}))
    options = IntegrationOptions(**demisto_params)
    client = DropboxEventsClient(request, options, credentials)
    get_events = DropboxEventsGetter(client, options)

    try:
        insecure = demisto_params.get('insecure')

        if command == 'test-module':
            raise DemistoException("Please run the !dropbox-auth-test command in order to test the connection")

        # ----- Authentication Commands ----- #
        elif command == 'dropbox-auth-start':
            return_results(start_auth_command(credentials.identifier))

        elif command == 'dropbox-auth-complete':
            return_results(complete_auth_command(demisto_params.get('code'), credentials, insecure))

        elif not demisto.getIntegrationContext().get('refresh_token'):
            return_results(CommandResults(readable_output='Please run the **dropbox-auth-start** command first'))

        elif command == 'dropbox-auth-reset':
            return_results(reset_auth_command())

        elif command == 'dropbox-auth-test':
            return_results(test_connection(demisto.getIntegrationContext().get('refresh_token'), credentials, insecure))

        # ----- Fetch/Get events command ----- #
        elif command in ('fetch-events', 'dropbox-get-events'):
            events = get_events.run()

            if command == 'fetch-events' or demisto_params.get('should_push_events'):
                send_events_to_xsiam(events, vendor=demisto_params.get('vendor', 'dropbox'),
                                     product=demisto_params.get('product', 'dropbox'))

                if events:
                    last_run = get_events.get_last_run(events)
                    demisto.debug(f'Set last run to {last_run}')
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
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    # Args is always stronger. Get getLastRun even stronger
    demisto_params_ = demisto.params() | demisto.args() | demisto.getLastRun()
    main(demisto.command(), demisto_params_)
