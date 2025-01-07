# pylint: disable=no-name-in-module
# pylint: disable=no-self-argument

import dateparser
import secrets
import jwt
from cryptography import exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from pydantic import ConfigDict, Field, parse_obj_as

from SiemApiModule import *  # noqa: E402


class Claims(BaseModel):
    iss: str = Field(alias='client_id')
    sub: str = Field(alias='id', description='user id or enterprise id')
    box_sub_type: str = 'enterprise'
    aud: AnyUrl
    jti: str = secrets.token_hex(64)
    exp: int = round(time.time()) + 45


class AppAuth(BaseModel):
    publicKeyID: str
    privateKey: str
    passphrase: str


class BoxAppSettings(BaseModel):
    clientID: str
    clientSecret: str
    appAuth: AppAuth
    model_config = ConfigDict(arbitrary_types_allowed=True)


class BoxCredentials(BaseModel):
    enterpriseID: str
    boxAppSettings: BoxAppSettings

    class MyConfig:
        validate_assignment = True


def get_box_events_timestamp_format(value):
    """Converting int(epoch), str(3 days) or datetime to Box's api time"""
    timestamp: Optional[datetime]
    if isinstance(value, int):
        value = str(value)
    if not isinstance(value, datetime):
        timestamp = dateparser.parse(value)
    if timestamp is None:
        raise TypeError(f'after is not a valid time {value}')
    return timestamp.isoformat('T', 'seconds')


class BoxEventsParams(BaseModel):
    event_type: Optional[str] = None
    limit: int = Field(500, alias='page_size', gt=0, le=500)
    stream_position: Optional[str] = None
    stream_type: str = 'admin_logs'
    created_after: Optional[str]
    # validators
    _normalize_after = validator('created_after', pre=True, allow_reuse=True)(
        get_box_events_timestamp_format
    )  # type: ignore[type-var]
    model_config = ConfigDict(validate_assignment=True)


def not_gate(v):
    """Due to a bug in the validator object (collision with CommonServerPython)
    we can pass this a a simple lambda. So here we are.

    Just doing not if v is bool, else it is true.

    Used when getting insecure and should change the insecure to verify.
    insecure == True, verify is False.
    """
    v_ = parse_obj_as(bool, False if v is None else v)
    return not v_


class BoxEventsRequestConfig(IntegrationHTTPRequest):
    # Endpoint: https://developer.box.com/reference/get-events/
    method: Method = Method.GET
    params: BoxEventsParams   # type: ignore[assignment]
    verify: Optional[bool] = Field(True, alias='insecure')  # type: ignore[assignment]

    # validators
    _oppsite_verify = validator('verify', allow_reuse=True)(not_gate)  # type: ignore[type-var]


class BoxIntegrationOptions(IntegrationOptions):
    product_name: str = 'box'
    vendor_name: str = 'box'
    should_push_events: bool = False


class BoxEventsClient(IntegrationEventsClient):
    request: BoxEventsRequestConfig
    options: IntegrationOptions

    def __init__(
        self,
        request: BoxEventsRequestConfig,
        options: IntegrationOptions,
        box_credentials: BoxCredentials,
        api_url: str,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.api_url: str = api_url
        self.authorization_url = parse_obj_as(AnyUrl, urljoin(str(self.api_url), '/oauth2/token'))

        if session is None:
            session = requests.Session()
        self.box_credentials = box_credentials
        super().__init__(request, options, session)

    def set_request_filter(self, after: str):
        self.request.params.stream_position = after

    def authenticate(self):
        request = IntegrationHTTPRequest(
            method=Method.POST,
            url=self.authorization_url,
            data=self._create_authorization_body(),
            verify=self.request.verify,  # type: ignore[arg-type]
        )

        response = self.call(request)
        self.access_token = response.json()['access_token']
        self.request.headers = {'Authorization': f'Bearer {self.access_token}'}

    def _create_authorization_body(self):
        claims = Claims(
            client_id=self.box_credentials.boxAppSettings.clientID,
            id=self.box_credentials.enterpriseID,
            aud=self.authorization_url,
        )

        decrypted_private_key = _decrypt_private_key(
            self.box_credentials.boxAppSettings.appAuth
        )
        assertion = jwt.encode(
            payload=claims.model_dump(mode='json'),  # type: ignore[attr-defined]
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


class BoxEventsGetter(IntegrationGetEvents):
    client: BoxEventsClient

    def get_last_run(self: Any) -> dict:  # type: ignore
        demisto.debug(f'getting {self.client.request.params.stream_position=}')
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
            # The next stream position points to where new messages will arrive.
            demisto.debug(
                f'setting the next request filter {events["next_stream_position"]=}'
            )
            if not events['entries']:
                break
            yield events['entries']
            # endregion
            # region Do next call
            events = self.client.call(self.client.request).json()
            # endregion


def _decrypt_private_key(app_auth: AppAuth):
    """
    Attempts to load the private key as given in the integration configuration.

    :return: an initialized Private key object.
    """
    try:
        key = load_pem_private_key(
            data=app_auth.privateKey.encode('utf8'),
            password=app_auth.passphrase.encode('utf8'),
            backend=default_backend(),
        )
    except (
        TypeError,
        ValueError,
        exceptions.UnsupportedAlgorithm,
    ) as exception:
        raise DemistoException(
            'An error occurred while loading the private key.', exception
        )
    return key


def main(command: str, demisto_params: dict):
    try:
        box_credentials = BoxCredentials.parse_raw(
            demisto_params['credentials_json']['password']
        )
        events_request_params = demisto_params.copy()
        events_request_params['url'] = urljoin(demisto_params.get('url', 'https://api.box.com'), '/2.0/events')
        request = BoxEventsRequestConfig(
            params=BoxEventsParams.parse_obj(events_request_params),
            **events_request_params,
        )
        options = BoxIntegrationOptions.parse_obj(demisto_params)
        client = BoxEventsClient(request, options, box_credentials,
                                 api_url=demisto_params.get('url', 'https://api.box.com'))
        get_events = BoxEventsGetter(client, options)
        if command == 'test-module':
            get_events.client.options.limit = 1
            get_events.run()
            demisto.results('ok')
            return
        demisto.debug('not in test module, running box-get-events')
        events = get_events.run()
        demisto.debug(f'got {len(events)=} from api')
        if command == 'box-get-events':
            demisto.debug('box-get-events, publishing events to incident')
            return_results(CommandResults('BoxEvents', 'event_id', events))
            if options.should_push_events:
                send_events_to_xsiam(events, options.vendor_name, options.product_name)
        if command == 'fetch-events':
            last_run = get_events.get_last_run()
            demisto.debug(
                f'in fetch-events. settings should push events to true, setting {last_run=}'
            )
            send_events_to_xsiam(events, options.vendor_name, options.product_name)
            demisto.setLastRun(last_run)
        demisto.debug(f'finished fetching events. {options.should_push_events=}')
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{e}\nTraceback:{traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    # Args is always stronger. Get getLastRun even stronger
    demisto_params_ = demisto.params() | demisto.args() | demisto.getLastRun()
    main(demisto.command(), demisto_params_)
