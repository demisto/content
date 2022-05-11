# pylint: disable=no-name-in-module
# pylint: disable=no-self-argument
import json
import secrets

import jwt
import urllib3
from cryptography import exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from pydantic import Field, parse_obj_as

from SiemApiModule import *  # noqa: E402

urllib3.disable_warnings()

# -----------------------------------------  GLOBAL VARIABLES  -----------------------------------------
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
EVENT_FIELDS = [
    'AuthMethod',
    'DirectoryServiceUuid',
    'DirectoryServicePartnerName',
    'EntityName',
    'EntityType',
    'EntityUuid'
    'FromIPAddress',
    'Level',
    'ImpersonatorUuiid',
    'NewEntity',
    'NormalizedUser',
    'OldEntity',
    'RequestDeviceOS',
    'RequestHostName',
    'RequestIsMobileDevice',
    'Tenant',
    'UserGuid',
    'WhenLogged',
    'WhenOccurred',
]


class CyberArkEventsRequest(IntegrationHTTPRequest):
    method = Method.GET


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
        self.request.url += 'RedRock/Query'
        self.request.headers = {'Accept': '*/*', 'Content-Type': 'application/json'}
        self.request.data = json.dumps({"Script": f"Select ID from Event where WhenOccurred >= '{dateparser.parse('1 week', settings={'TIMEZONE': 'UTC'}).strftime(DATE_FORMAT)}' and WhenOccurred <= '{datetime.now().strftime(DATE_FORMAT)}'"})
        self.request.verify = not self.request.verify

    def set_request_filter(self, after: Any):
        self.request.data = json.dumps({"Script": f"Select ID from Event where WhenOccurred >= '{dateparser.parse('1 week', settings={'TIMEZONE': 'UTC'}).strftime(DATE_FORMAT)}' and WhenOccurred <= '{datetime.now().strftime(DATE_FORMAT)}'"})

    def authenticate(self):
        request = IntegrationHTTPRequest(
            method=self.request.method,
            url=f"{self.request.url}/oauth2/token/{demisto.params().get('app_id')}",
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
        last_run = event['Row']['WhenOccurred']
        demisto.debug(f"Getting the last run {last_run}")
        return {'WhenOccurred': last_run}

    def _iter_events(self):
        self.client.authenticate()
        demisto.debug('authenticated successfully')

        events = self.client.call(self.client.request).json()['Result']

        while True:
            if not events['Results']:
                break
            yield events['Results']

            # self.client.set_request_filter(events['Results'][-1]['Row']['WhenOccurred'])
            # demisto.debug(
            #     f'Setting then next request filter {events["next_stream_position"]=}'
            # )
            # events = self.client.call(self.client.request).json()


def main(command: str, demisto_params: dict):
    credentials = Credentials(**demisto_params.get('credentials'))
    options = IntegrationOptions(**demisto_params)
    request = CyberArkEventsRequest(**demisto_params)
    client = CyberArkEventsClient(request, options, credentials)
    get_events = CyberArkGetEvents(client, options)

    try:
        if command == '':
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
                        readable_output=tableToMarkdown('CyberArkIdentity RedRock records', events, removeNull=True, headerTransform=pascalToSpace),
                        raw_response=events,
                    )
                    demisto.results(CommandResults)

    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    # Args is always stronger. Get getIntegrationContext even stronger
    demisto_params_ = demisto.params() | demisto.args() | demisto.getLastRun()
    main(demisto.command(), demisto_params_)
