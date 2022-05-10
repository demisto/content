# pylint: disable=no-name-in-module
# pylint: disable=no-self-argument

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


# -----------------------------------------  HELPER CLASSES  -----------------------------------------
class CyberArkEventsParams(BaseModel):
    limit: int = Field(500, gt=0, le=500)
    stream_position: Optional[str]
    stream_type = 'admin_logs'
    created_after: Optional[str]
    # validators
    _normalize_after = validator('created_after', pre=True, allow_reuse=True)(
        get_box_events_timestamp_format
    )

    class Config:
        validate_assignment = True


class CyberArkEventsRequest(IntegrationHTTPRequest):
    url = parse_obj_as(AnyUrl, 'https://api.box.com/2.0/events')
    method = Method.GET
    params: BoxEventsParams


class CyberArkEventsClient(IntegrationEventsClient):
    request: BoxEventsRequest
    options: IntegrationOptions

    def __init__(
        self,
        request: BoxEventsRequest,
        options: IntegrationOptions,
        box_credentials: BoxCredentials,
        session=requests.Session(),
    ) -> None:
        self.box_credentials = box_credentials
        super().__init__(request, options, session)

    def set_request_filter(self, after: Any):
        self.request.params.stream_position = after

    def authenticate(self):
        request = IntegrationHTTPRequest(
            method=Method.POST,
            url='https://api.box.com/oauth2/token',
            data=self._create_authorization_body(),
            verify=self.request.verify,
        )

        response = self.call(request)
        self.access_token = response.json()['access_token']
        self.request.headers = {'Authorization': f'Bearer {self.access_token}'}

    def _create_authorization_body(self):
        claims = Claims(
            client_id=self.box_credentials.boxAppSettings.clientID,
            id=self.box_credentials.enterpriseID,
        )

        decrypted_private_key = _decrypt_private_key(
            self.box_credentials.boxAppSettings.appAuth
        )
        assertion = jwt.encode(
            payload=claims.dict(),
            key=decrypted_private_key,
            algorithm='RS512',
            headers={
                'kid': self.box_credentials.boxAppSettings.appAuth.publicKeyID
            },
        )
        body = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion': assertion,
            'client_id': self.box_credentials.boxAppSettings.clientID,
            'client_secret': self.box_credentials.boxAppSettings.clientSecret,
        }
        return body


class CyberArkGetEvents(IntegrationGetEvents):
    client: BoxEventsClient

    def get_last_run(self: Any) -> dict:  # type: ignore
        demisto.debug(f'setting {self.client.request.params.stream_position=}')
        return {'stream_position': self.client.request.params.stream_position}

    def _iter_events(self):
        self.client.authenticate()
        demisto.debug('authenticated successfully')
        # region First Call
        events = self.client.call(self.client.request).json()
        # endregion
        # region Yield Response
        while True:  # Run as long there are logs
            self.client.set_request_filter(events['next_stream_position'])
            demisto.debug(
                f'setting then next request filter {events["next_stream_position"]=}'
            )
            if not events['entries']:
                break
            yield events['entries']
            # endregion
            # region Do next call
            events = self.client.call(self.client.request).json()
            # endregion


# -----------------------------------------  HELPER FUNCTIONS  -----------------------------------------
def get_access_token(**kwargs: dict) -> str:
    credentials = Credentials(**kwargs.get('credentials'))
    user_name = credentials.identifier
    password = credentials.password
    url = f'{kwargs.get("url")}/oauth2/token/{kwargs.get("app_id")}'
    headers = {'Authorization': f"Basic {base64.b64encode(f'{user_name}:{password}'.encode()).decode()}"}
    data = {'grant_type': 'client_credentials', 'scope': 'siem'}

    response = requests.post(url, headers=headers, data=data, verify=not kwargs.get('insecure'))
    json_response = response.json()
    access_token = json_response.get('access_token')

    return access_token


def get_headers(access_token: str) -> dict:
    return {
        'Authorization': f'Bearer {access_token}',
        'Accept': '*/*',
        'Content-Type': 'application/json'
    }


def get_data(fetch_from: str) -> dict:
    _from = dateparser.parse(fetch_from, settings={'TIMEZONE': 'UTC'}).strftime(DATE_FORMAT)
    to = datetime.now().strftime(DATE_FORMAT)

    return {"Script": f"Select {EVENT_FIELDS} from Event where WhenOccurred >= '{_from}' and WhenOccurred <= '{to}'"}


def prepare_demisto_params(**kwargs: dict) -> dict:
    params = {
        'url': kwargs.get('url', '') + 'RedRock/Query',
        'method': Method.GET,
        'headers': get_headers(get_access_token(**kwargs)),
        'data': json.dumps(get_data(kwargs.get('from', '3 days'))),
        'verify': not kwargs.get('verify'),

    }
    return params


def main(command: str, demisto_params: dict):
    demisto_params.update(prepare_demisto_params(**demisto_params))

    request = IntegrationHTTPRequest(**demisto_params)
    options = IntegrationOptions(**demisto_params)
    client = IntegrationEventsClient(request, options)
    get_events = IntegrationGetEvents(client, options)

    try:
        if command == 'test-module':
            get_events.run()
            demisto.results('ok')
        elif command in ('fetch-events', 'CyberArk-get-events'):
            events = get_events.run(demisto_params.get('max_fetch'))
            if events:
                if command == 'fetch-events':
                    send_events_to_xsiam(events, 'CyberArkIdentity', 'RedRock records')
                if command == 'CyberArkIdentity-fetch-events':
                    get_events.events_to_incidents(events)
                    CommandResults(
                        readable_output=tableToMarkdown('CyberArkIdentity RedRock records', events, removeNull=True, headerTransform=pascalToSpace),
                        outputs_prefix='JiraAudit.Records',
                        outputs_key_field='id',
                        outputs=events,
                        raw_response=events,
                    )
                    demisto.results(CommandResults)
                demisto.setLastRun({'from': events[-1].get('')})
    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    # Args is always stronger. Get getIntegrationContext even stronger
    demisto_params_ = demisto.params() | demisto.args() | demisto.getLastRun()
    main(demisto.command(), demisto_params_)
