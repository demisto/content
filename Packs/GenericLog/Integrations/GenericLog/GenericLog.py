from __future__ import annotations
from datetime import datetime
from enum import Enum
from urllib.error import HTTPError
from CommonServerPython import *
import demistomock as demisto
from pydantic import BaseModel, AnyUrl, Json, validator
import requests
import dateparser


def convert_to_github_date(value: Union[str, datetime, int]) -> str:
    """Converting int(epoch), str(3 days) or datetime to github's api time"""
    if isinstance(value, int):
        value = str(value)
    if isinstance(value, str):
        value = dateparser.parse(value)
    if value is None:
        raise TypeError(f'after is not a valid time {value}')
    timestamp = value.timestamp() * 1000
    str_bytes = f'{timestamp}|'.encode('ascii')
    base64_bytes = base64.b64encode(str_bytes)
    return base64_bytes.decode('ascii')


class Method(str, Enum):
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    HEAD = 'HEAD'
    PATCH = 'PATCH'
    DELETE = 'DELETE'


class ReqParams(BaseModel):
    include: str
    order: str = 'asc'
    after: str
    _normalize_after = validator('after', pre=True, allow_reuse=True)(
        convert_to_github_date
    )

    def set_after(self, after):
        self.after = convert_to_github_date(after)


class Request(BaseModel):
    method: Method
    url: AnyUrl
    headers: Optional[Union[Json[dict], dict]]
    params: Optional[ReqParams]
    verify = True
    data: Optional[str] = None


class Args(BaseModel):
    limit: int = 10


class Client:
    def __init__(self, request: Request):
        self.request = request

    def call(self, requests=requests) -> requests.Response:
        try:
            response = requests.request(**self.request.dict())
            response.raise_for_status()
            return response
        except Exception as exc:
            msg = f'something went wrong with the http call {exc}'
            LOG(msg)
            raise DemistoException(msg) from exc

    def set_after(self, after: str):
        self.request.params.set_after(after)


class GetLogs:
    def __init__(self, client: Client) -> None:
        self.client = client

    def _iter_logs(self):
        # region First Call
        response = self.client.call()
        logs: list = response.json()
        if not logs:
            return []
        # endregion
        # region Yield Response
        while True:
            yield logs
            # endregion
            # region Prepare Next Iteration (Paging)
            last = logs.pop()
            self.client.set_after(last['@timestamp'])
            # endregion
            # region Do next call
            response = self.client.call()
            logs: list = response.json()
            try:
                logs.pop(0)
                assert logs
            except (IndexError, AssertionError):
                LOG('empty list, breaking')
                break
            # endregion

    def get_logs(self, limit=10):
        stored = []
        for logs in self._iter_logs():
            stored.extend(logs)
            if len(stored) >= limit:
                return stored[:limit]
        return stored

    @staticmethod
    def get_last_run(logs) -> dict:
        last_time = logs[-1].get('@timestamp') / 1000
        next_fetch_time = datetime.fromtimestamp(last_time) + timedelta(seconds=1)
        return {'after': next_fetch_time.isoformat()}


if __name__ in ('__main__', '__builtin__', 'builtins'):
    # Args is always stronger. Get last run even stronger
    demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()

    demisto_params['params'] = ReqParams(**demisto_params)

    request = Request(**demisto_params)

    client = Client(request)

    get_logs = GetLogs(client)

    command = demisto.command()
    if command == 'test-module':
        limit = 1
        get_logs.get_logs(limit)
        demisto.results('ok')
    else:
        args = Args(**demisto_params)
        logs = get_logs.get_logs(args.limit)
        if logs:
            demisto.setLastRun(GetLogs.get_last_run(logs))
        demisto.results({'github': logs})
