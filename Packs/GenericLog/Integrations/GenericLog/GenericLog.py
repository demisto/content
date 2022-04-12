from datetime import datetime
from enum import Enum
import urllib3
from CommonServerPython import *
import demistomock as demisto
from pydantic import (
    BaseConfig,
    BaseModel,
    AnyUrl,
    Field,
    Json,
    validator,
)
import requests
import dateparser
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings()


class Method(str, Enum):
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    HEAD = 'HEAD'
    PATCH = 'PATCH'
    DELETE = 'DELETE'


class Options(BaseModel):
    """Add here any option you need to add to the logic"""

    proxy: bool = False
    limit: int = 100


def get_github_timestamp_format(value):
    """Converting int(epoch), str(3 days) or datetime to github's api time"""
    timestamp: Optional[datetime]
    if isinstance(value, int):
        value = str(value)
    if not isinstance(value, datetime):
        timestamp = dateparser.parse(value)
    if timestamp is None:
        raise TypeError(f'after is not a valid time {value}')
    timestamp_epoch = timestamp.timestamp() * 1000
    str_bytes = f'{timestamp_epoch}|'.encode('ascii')
    base64_bytes = base64.b64encode(str_bytes)
    return base64_bytes.decode('ascii')


class ReqParams(
    BaseModel
):  # TODO: implement request params or any API-specific model (if any)
    include: str
    order: str = 'asc'
    after: str
    per_page: int = 100  # Maximum is 100
    # validators
    _normalize_after = validator('after', pre=True, allow_reuse=True)(
        get_github_timestamp_format
    )

    class Config:
        validate_assignment = True


class Request(BaseModel):
    method: Method
    url: AnyUrl
    headers: Json[dict] = dict()  # type: ignore [type-arg, assignment]
    params: ReqParams
    verify: bool = True
    data: Optional[str] = None
    auth: Optional[HTTPBasicAuth]

    class Config(BaseConfig):
        arbitrary_types_allowed = True


class Credentials(BaseModel):
    password: str
    identifier: Optional[str]


def set_authorization(request: Request, auth_credendtials):
    """Automatic authorization.
    Supports {Authorization: Bearer __token__}
    or Basic Auth.
    """
    creds = Credentials.parse_obj(auth_credendtials)
    if creds.password and creds.identifier:
        request.auth = HTTPBasicAuth(creds.identifier, creds.password)
    auth = {'Authorization': f'Bearer {creds.password}'}
    if request.headers:
        request.headers |= auth  # type: ignore[assignment, operator]
    else:
        request.headers = auth  # type: ignore[assignment]


class Client:
    def __init__(
        self, request: Request, options: Options, session=requests.Session()
    ):
        self.request = request
        self.options = options
        self.session = session
        self._set_proxy()
        self._skip_cert_verification()

    def __del__(self):
        try:
            self.session.close()
        except AttributeError as err:
            demisto.debug(
                f'ignore exceptions raised due to session not used by the client. {err=}'
            )

    def call(self) -> requests.Response:
        try:
            response = self.session.request(**self.request.dict())
            response.raise_for_status()
            return response
        except Exception as exc:
            msg = f'something went wrong with the http call {exc}'
            LOG(msg)
            raise DemistoException(msg) from exc

    def set_from_time_filter(self, after: Any):
        """TODO: set the next time to fetch"""
        self.request.params.after = after

    def _skip_cert_verification(
        self, skip_cert_verification=skip_cert_verification
    ):
        if not self.request.validate:
            skip_cert_verification()

    def _set_proxy(self):
        if self.options.proxy:
            ensure_proxy_has_http_prefix()
        else:
            skip_proxy()


class GetEvents:
    def __init__(self, client: Client, options: Options) -> None:
        self.client = client
        self.options = options

    def call(self):
        resp = self.client.call()
        return resp.json()

    def _iter_events(self):
        # region First Call
        events = self.call()
        # endregion
        # region Yield Response
        while True and events:  # Run as long there are logs
            yield events
            # endregion
            # region Prepare Next Iteration (Paging)
            last = events.pop()
            self.client.set_from_time_filter(last['@timestamp'])
            # endregion
            # region Do next call
            events = self.call()
            try:
                events.pop(0)
            except (IndexError):
                demisto.info('empty list, breaking')
                break
            # endregion

    def run(self):
        stored = []
        for logs in self._iter_events():
            stored.extend(logs)
            if len(stored) >= self.options.limit:
                return stored[: self.options.limit]
        return stored

    @staticmethod
    def get_last_run(events) -> dict:
        """TODO: Implement the last run (from previous logs)"""
        last_time = events[-1].get('@timestamp') / 1000
        next_fetch_time = datetime.fromtimestamp(last_time) + timedelta(
            seconds=1
        )
        return {'after': next_fetch_time.isoformat()}


if __name__ in ('__main__', '__builtin__', 'builtins'):
    # Args is always stronger. Get getIntegrationContext even stronger
    demisto_params = (
        demisto.params() | demisto.args() | demisto.getIntegrationContext()
    )

    demisto_params['params'] = ReqParams.parse_obj(demisto_params)
    request = Request.parse_obj(demisto_params)

    # TODO: If you're not using basic auth or Bearer __token_, you should implement your own
    set_authorization(request, demisto_params['auth_credendtials'])

    options = Options.parse_obj(demisto_params)

    client = Client(request, options)

    get_events = GetEvents(client, options)

    command = demisto.command()
    if command == 'test-module':
        get_events.run()
        demisto.results('ok')
    else:
        events = get_events.run()

        if events:
            demisto.setIntegrationContext(GetEvents.get_last_run(events))
        command_results = CommandResults(
            readable_output=tableToMarkdown(
                'Github events', events, headerTransform=pascalToSpace
            ),
            outputs_prefix='Github.Events',
            outputs_key_field='@timestamp',
            outputs=events,
            raw_response=events,
        )
        return_results(command_results)
