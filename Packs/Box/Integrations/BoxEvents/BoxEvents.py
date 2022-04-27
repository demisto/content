from datetime import datetime
import enum
import secrets
import urllib3
from CommonServerPython import *
import demistomock as demisto
from pydantic import (
    BaseModel,
    validator,
    Field
)
import dateparser
import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography import exceptions

urllib3.disable_warnings()

class BoxSubTypes(str, enum.Enum):
    user = 'user'
    enterprise = 'enterprise' 

class Claims(BaseModel):
    iss: str = Field(alias='client_id')
    sub: str = Field(alias='id', decription='user id or enterprise id')
    box_sub_type: BoxSubTypes
    aud: AnyUrl = 'https://api.box.com/oauth2/token'
    jti: bytes = secrets.token_hex(64)
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
    sub_type: BoxSubTypes
    boxAppSettings: BoxAppSettings

class BoxEventsOptions(IntegrationOptions):
    limit: int = 10

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
    limit: int = 500
    stream_position: Optional[str]
    stream_type: Optional[str] = 'admin_logs'
    created_after: str
    # validators
    _normalize_after = validator('created_after', pre=True, allow_reuse=True)(
        get_box_events_timestamp_format
    )

    class Config:
        validate_assignment = True


class BoxEventsRequest(IntegrationHTTPRequest):
    params: BoxEventsParams


class BoxEventsClient(IntegrationEventsClient):
    request: BoxEventsRequest
    options: BoxEventsOptions

    def __init__(self, request: BoxEventsRequest, options: BoxEventsOptions, auth_body: dict) -> None:
        self.auth_body = auth_body
        super().__init__(request, options)

    def set_request_filter(self, after: Any):
        self.request.params.stream_position = after  # type: ignore[attr-defined]

    def authenticate(self):
        request = IntegrationHTTPRequest(
            method = Method.POST,
            url = 'https://api.box.com/oauth2/token',
            data = self.auth_body,
            verify=False
        )
        
        response = self.call(request)
        self.access_token = response.json()['access_token']
        self.request.headers = {'Authorization': f'Bearer {self.access_token}'}



class BoxEventsGetEvents(IntegrationGetEvents):
    @staticmethod
    def get_last_run(events: Any) -> dict:  # type: ignore
        created = events[-1].get('next_stream_position')
        return {'stream_position': created}

    def _iter_events(self):
        self.client.authenticate()
        # region First Call
        events = self.client.call(self.client.request).json()
        # endregion
        # region Yield Response
        while True and events:  # Run as long there are logs
            yield events['entries']
            # endregion
            # region Prepare Next Iteration (Paging)
            if not events['entries']:
                demisto.debug(f'No more entries, finished reading events, {events["next_stream_position"]=}')
                break

            self.client.set_request_filter(events['next_stream_position'])
            # endregion
            # region Do next call
            events = self.client.call(self.client.request).json()
            try:
                events.pop(0)
            except (KeyError):
                demisto.info('empty list, breaking')
                break
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
        except (TypeError, ValueError, exceptions.UnsupportedAlgorithm) as exception:
            raise DemistoException("An error occurred while loading the private key.", exception)
        return key

def create_authorization_body(box_creds: BoxCredentials):
    claims = Claims(
        client_id=box_creds.boxAppSettings.clientID,
        id=box_creds.enterpriseID,
        box_sub_type=box_creds.sub_type,
    )

    decrypted_private_key = _decrypt_private_key(box_creds.boxAppSettings.appAuth)
    assertion = jwt.encode(
            payload=claims.dict(),
            key=decrypted_private_key,
            algorithm='RS512',
            headers={
                'kid': box_creds.boxAppSettings.appAuth.publicKeyID
            }
        )
    body = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion': assertion,
            'client_id': box_creds.boxAppSettings.clientID,
            'client_secret': box_creds.boxAppSettings.clientSecret
        }
    return body

    
     

def main(demisto_params: dict):
    box_credentials = BoxCredentials.parse_raw(demisto_params['credentials_json'])
    auth_body = create_authorization_body(box_credentials)
    request = BoxEventsRequest(
        url='https://api.box.com/2.0/events/',
        method=Method.GET,
        params=BoxEventsParams.parse_obj(demisto_params),
        verify=demisto_params['verify']
    )

    # If you're not using basic auth or Bearer __token_, you should implement your own
    # set_authorization(request, demisto_params['auth_credendtials'])
    options = BoxEventsOptions.parse_obj(demisto_params)
    client = BoxEventsClient(request, options, auth_body)
    get_events = BoxEventsGetEvents(client, options)
    command = demisto.command()
    if command == 'test-module':
        get_events.run()
        demisto.results('ok')
    else:
        events = get_events.run()

        if events:
            demisto.setIntegrationContext(
                IntegrationGetEvents.get_last_run(events)
            )
        command_results = CommandResults(
            readable_output=tableToMarkdown(
                'BoxEvents events', events, headerTransform=pascalToSpace, headers=['events']
            ),
            outputs_prefix='BoxEvents.Events',
            outputs_key_field='@timestamp',
            outputs=events,
            raw_response=events,
        )
        print(events)
        return_results(command_results)

if __name__ in ('__main__', '__builtin__', 'builtins'):
    # Args is always stronger. Get getIntegrationContext even stronger
    demisto_params = (
        demisto.params() | demisto.args() | demisto.getIntegrationContext()
    )
    main(demisto_params)