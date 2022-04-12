from datetime import datetime
from enum import Enum
import urllib3
from CommonServerPython import *
import demistomock as demisto
from pydantic import BaseConfig, BaseModel, AnyUrl, Json, validator
import requests
import dateparser
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings()

def convert_to_github_date(value: Union[str, datetime, int]) -> str:
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


class Method(str, Enum):
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    HEAD = 'HEAD'
    PATCH = 'PATCH'
    DELETE = 'DELETE'


class Options(BaseModel):
    proxy: bool = False

class Request(BaseModel):
    method: Method
    url: AnyUrl
    headers: Union[Json, dict] = {}
    params: Optional[BaseModel]
    verify: bool = True
    data: Optional[str] = None
    auth: Optional[HTTPBasicAuth]

    class Config(BaseConfig):
        arbitrary_types_allowed = True


class ReqParams(BaseModel):  # TODO: implement request params (if any)
    include: str
    order: str = 'asc'
    after: str
    per_page: int = 100  # Maximum is 100
    _normalize_after = validator('after', pre=True, allow_reuse=True)(
        convert_to_github_date
    )


class Args(BaseModel):
    limit: int = 10


class Client:
    def __init__(self, request: Request, options: Options, session = requests.Session()):
        self.request = request
        self.options = options
        self.session = session
        self._set_proxy()
        self._skip_cert_verification()

    def __del__(self):
        try:
            self._session.close()
        except AttributeError as err:
            demisto.debug(f'ignore exceptions raised due to session not used by the client. {err=}')
            

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
        self.request.params.after = convert_to_github_date(after)  # type: ignore[union-attr]
    
    def _skip_cert_verification(self, skip_cert_verification=skip_cert_verification):
        if not self.request.validate:
            skip_cert_verification()

    def _set_proxy(self):
        if self.options.proxy:
            ensure_proxy_has_http_prefix()
        else:
            skip_proxy()

class GetEvents:
    def __init__(self, client: Client) -> None:
        self.client = client

    def call(self):
        resp = self.client.call()
        return resp.json()

    def _iter_events(self):
        # region First Call
        logs = self.call()
        # endregion
        # region Yield Response
        while True and logs:  # Run as long there are logs
            yield logs
            # endregion
            # region Prepare Next Iteration (Paging)
            last = logs.pop()
            self.client.set_from_time_filter(last['@timestamp'])
            # endregion
            # region Do next call
            logs = self.call()
            try:
                logs.pop(0)
            except (IndexError):
                demisto.info('empty list, breaking')
                break
            # endregion

    def get_events(self, limit=10):
        stored = []
        for logs in self._iter_events():
            stored.extend(logs)
            if len(stored) >= limit:
                return stored[:limit]
        return stored

    @staticmethod
    def get_last_run(logs) -> dict:
        """TODO: Implement the last run (from previous logs)"""
        last_time = logs[-1].get('@timestamp') / 1000
        next_fetch_time = datetime.fromtimestamp(last_time) + timedelta(
            seconds=1
        )
        return {'after': next_fetch_time.isoformat()}


if __name__ in ('__main__', '__builtin__', 'builtins'):
    # Args is always stronger. Get last run even stronger
    demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()
    demisto_params['params'] = ReqParams.parse_obj(demisto_params)
    request = Request.parse_obj(demisto_params)
    # TODO: Implement authorization
    request.headers[  # type: ignore[index] 
        'Authorization'
    ] = f"Bearer {demisto_params['api_key']['password']}"

    options = Options.parse_obj(demisto_params)

    client = Client(request, options)

    get_logs = GetEvents(client)

    command = demisto.command()
    if command == 'test-module':
        get_logs.get_events(limit=1)
        demisto.results('ok')
    else:
        args = Args(**demisto_params)
        logs = get_logs.get_events(args.limit)
        if logs:
            demisto.setLastRun(GetEvents.get_last_run(logs))
        demisto.results({'github': logs})
