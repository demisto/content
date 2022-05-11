# pylint: disable=no-name-in-module
# pylint: disable=no-self-argument
import urllib3
from SiemApiModule import *  # noqa: E402

urllib3.disable_warnings()

# -----------------------------------------  GLOBAL VARIABLES  -----------------------------------------
DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'


class CyberArkEventsRequest(IntegrationHTTPRequest):
    method = Method.GET
    headers = {'Accept': '*/*', 'Content-Type': 'application/json'}


class CyberArkEventsClient(IntegrationEventsClient):
    request: IntegrationHTTPRequest
    options: IntegrationOptions

    def __init__(
        self,
        request: CyberArkEventsRequest,
        options: IntegrationOptions,
        credentials: Credentials,
        session=requests.Session(),
    ) -> None:
        self.access_token = None
        self.credentials = credentials
        super().__init__(request, options, session)

    def set_request_filter(self, after: Any):
        self.request.data = json.dumps({"Script": f"Select ID from Event where WhenOccurred >= '{dateparser.parse('1 week', settings={'TIMEZONE': 'UTC'}).strftime(DATE_FORMAT)}' and WhenOccurred <= '{datetime.now().strftime(DATE_FORMAT)}'"})

    def authenticate(self):
        request = IntegrationHTTPRequest(
            method=self.request.method,
            url=f"{demisto.params().get('url')}/oauth2/token/{demisto.params().get('app_id')}",
            headers={'Authorization': f"Basic {base64.b64encode(f'{self.credentials.identifier}:{self.credentials.password}'.encode()).decode()}"},
            data={'grant_type': 'client_credentials', 'scope': 'siem'},
            verify=not self.request.verify,
        )

        response = self.call(request)
        self.access_token = response.json()['access_token']
        self.request.headers['Authorization'] = f'Bearer {self.access_token}'


class CyberArkGetEvents(IntegrationGetEvents):
    client: CyberArkEventsClient

    def get_last_run(self: Any, event) -> dict:  # type: ignore
        # The date is in timestamp format and looks like {'WhenOccurred': '/Date(1651483379362)/'}
        last_date = int(dict(event).get('WhenOccurred', '').removesuffix(')/').removeprefix('/Date('))
        last_run = datetime.utcfromtimestamp(last_date / 1000).strftime(DATETIME_FORMAT)

        demisto.debug(f"Getting the last run {last_run}")
        return {'from': last_run}

    def _iter_events(self):
        self.client.authenticate()
        demisto.debug('authenticated successfully')

        result = self.client.call(self.client.request).json()['Result']

        if events := result.get('Results'):
            yield [event.get('Row') for event in events]


def get_request_params(**kwargs: dict) -> dict:
    fetch_from = kwargs.get('from', '3 days')
    from_day = datetime.strftime(dateparser.parse(fetch_from, settings={'TIMEZONE': 'UTC'}), DATETIME_FORMAT)
    to_day = datetime.strftime(datetime.now(), DATETIME_FORMAT)

    params = {
        'url': f'{kwargs.get("url", "").removesuffix("/")}/RedRock/Query',
        'data': json.dumps({
            "Script": f"Select * from Event where WhenOccurred > '{from_day}' and WhenOccurred <= '{to_day}'"
        }),
        'verify': not kwargs.get('insecure')
    }
    return params


def main(command: str, demisto_params: dict):
    credentials = Credentials(**demisto_params.get('credentials', {}))
    options = IntegrationOptions(**demisto_params)
    request_params = get_request_params(**demisto_params)
    request = CyberArkEventsRequest(**request_params)
    client = CyberArkEventsClient(request, options, credentials)
    get_events = CyberArkGetEvents(client, options)

    try:
        if command == 'test-module':
            get_events.run()
            demisto.results('ok')

        if command in ('fetch-events', 'CyberArk-get-events'):
            events = get_events.run()
            send_events_to_xsiam(events, vendor='CyberArk', product='Idaptive')

            if events:
                last_run = get_events.get_last_run(events[-1])
                demisto.setLastRun(last_run)
                demisto.debug(f'Set last run to {last_run}')

                if command == 'CyberArk-fetch-events':
                    CommandResults(
                        readable_output=tableToMarkdown(
                            'CyberArkIdentity RedRock records', events, removeNull=True, headerTransform=pascalToSpace
                        ),
                        raw_response=events,
                    )
                    demisto.results(CommandResults)

    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    # Args is always stronger. Get getIntegrationContext even stronger
    demisto_params_ = demisto.params() | demisto.args() | demisto.getLastRun()
    main(demisto.command(), demisto_params_)
