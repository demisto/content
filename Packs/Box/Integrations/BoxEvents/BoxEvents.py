from datetime import datetime
import secrets
import urllib3
from CommonServerPython import *
import demistomock as demisto
from pydantic import BaseModel, validator, Field, parse_obj_as
import dateparser
import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography import exceptions

from SiemApiModule import *  # noqa: E402


urllib3.disable_warnings()


class Claims(BaseModel):
    iss: str = Field(alias='client_id')
    sub: str = Field(alias='id', decription='user id or enterprise id')
    box_sub_type = 'enterprise'
    aud: AnyUrl = parse_obj_as(AnyUrl, 'https://api.box.com/oauth2/token')
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

    class Config:
        arbitrary_types_allowed = True


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


class BoxEventsRequest(IntegrationHTTPRequest):
    url = parse_obj_as(AnyUrl, 'https://api.box.com/2.0/events/')
    method = Method.GET
    params: BoxEventsParams


class BoxEventsClient(IntegrationEventsClient):
    request: BoxEventsRequest
    options: IntegrationOptions

    def __init__(
        self,
        request: BoxEventsRequest,
        options: IntegrationOptions,
        box_credentials: BoxCredentials,
    ) -> None:
        self.box_credentials = box_credentials
        super().__init__(request, options)

    def set_request_filter(self, after: Any):
        self.request.params.stream_position = after  # type: ignore[attr-defined]

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


class BoxEventsGetEvents(IntegrationGetEvents):
    def get_last_run(self: Any) -> dict:  # type: ignore
        demisto.debug(f'setting {self.client.request.params.stream_position=}')
        return {'stream_position': self.client.request.params.stream_position}

    def _iter_events(self):
        self.client.authenticate()
        demisto.debug('authenticated succesfully')
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


def main(demisto_params: dict):
    box_credentials = BoxCredentials.parse_raw(
        demisto_params['credentials_json']
    )
    request = BoxEventsRequest(
        params=BoxEventsParams.parse_obj(demisto_params),
        **demisto_params,
    )

    # If you're not using basic auth or Bearer __token_, you should implement your own
    # set_authorization(request, demisto_params['auth_credendtials'])
    options = IntegrationOptions.parse_obj(demisto_params)
    client = BoxEventsClient(request, options, box_credentials)
    get_events = BoxEventsGetEvents(client, options)
    command = demisto.command()
    if command == 'test-module':
        get_events.client.request.params.limit = 1  # type: ignore[attr-defined]
        get_events.run()
        demisto.results('ok')
    else:
        events = get_events.run()
        demisto.debug(f'got {len(events)=} from api')
        if events:
            demisto.setLastRun(get_events.get_last_run())
            send_events_to_xsiam(events, 'box', 'box')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    # Args is always stronger. Get getIntegrationContext even stronger
    demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()
    main(demisto_params)
