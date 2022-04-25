from datetime import datetime
import urllib3
from CommonServerPython import *
import demistomock as demisto
from pydantic import (
    BaseModel,
    validator,
)
import dateparser
import jwt

urllib3.disable_warnings()


class JWT(BaseModel):
    iss: str
    sub: str # userid
    box_sub_type: str = 'user'
    aud: str # self.authentication_url
    jti: bytes # secrets.token_hex(64),
    exp: int = round(time.time()) + 45

class BoxAppSettings(BaseModel):
    clientID: str
    appAuth: str
    clientSecret: str
    publicKeyID: str
    privateKey: str
    passphrase: str
    enterpriseID: str

class BoxCredentials:
    enterpriseID: str
    boxAppSettings: Json[BoxAppSettings]

class BoxEventsOptions(IntegrationOptions):
    limit: int = 10
    credentials_json: Json[BoxCredentials]

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
    def __init__(self, request: BoxEventsRequest, options: BoxEventsOptions) -> None:
        self.box_auth = options.box_auth
        super().__init__(request, options)

    def create_jwt(self):
        jwt = JWT(
            iss=self.options
        )
    def set_request_filter(self, after: Any):
        self.request.params.stream_position = after  # type: ignore[attr-defined]

    def get_authorization(self):
        assertion = jwt.encode(
            payload=self.box_auth.dict(),
            key=self._decrypt_private_key(),
            algorithm='RS512',
            headers={
                'kid': self.public_key_id
            }
        )

        params = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion': assertion,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }

        request = IntegrationHTTPRequest(
            method=Method.POST,
            url=self.authentication_url,
            data=params
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
        # region First Call
        events = self.client.call(self.client.request).json()
        # endregion
        # region Yield Response
        while True and events:  # Run as long there are logs
            yield events
            # endregion
            # region Prepare Next Iteration (Paging)
            if not events['entries']:
                demisto.debug(f'No more entries, finished reading events, {events["next_stream_position"]=}')
                break

            self.client.set_request_filter(events['next_stream_position'])
            # endregion
            # region Do next call
            events = self.client.call().json()
            try:
                events.pop(0)
            except (IndexError):
                demisto.info('empty list, breaking')
                break
            # endregion


if __name__ in ('__main__', '__builtin__', 'builtins'):
    # Args is always stronger. Get getIntegrationContext even stronger
    demisto_params = (
        demisto.params() | demisto.args() | demisto.getIntegrationContext()
    )

    demisto_params['params'] = BoxEventsParams.parse_obj(demisto_params)
    request = BoxEventsRequest.parse_obj(demisto_params)

    # If you're not using basic auth or Bearer __token_, you should implement your own
    # set_authorization(request, demisto_params['auth_credendtials'])
    options = BoxEventsOptions.parse_obj(demisto_params)

    client = BoxEventsClient(request, options)
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
                'BoxEvents events', events, headerTransform=pascalToSpace
            ),
            outputs_prefix='BoxEvents.Events',
            outputs_key_field='@timestamp',
            outputs=events,
            raw_response=events,
        )
        return_results(command_results)
