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
    per_page: str = '100'
    _normalize_after = validator('after', pre=True, allow_reuse=True)(
        convert_to_github_date
    )

    def set_after_value(self, after):
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

    def set_next_run_filter(self, after: str):
        self.request.params.set_after_value(after)


class GetEvents:
    def __init__(self, client: Client) -> None:
        self.client = client

    def _iter_events(self):
        # region First Call
        response = self.client.call()
        events: list = response.json()
        if not events:
            return []
        # endregion
        # region Yield Response
        while True:
            yield events
        # endregion
            # region Prepare Next Iteration (Paging)
            last = events.pop()
            self.client.set_next_run_filter(last['@timestamp'])
            # endregion
            # region Do next call
            response = self.client.call()
            events: list = response.json()
            try:
                events.pop(0)
                assert events
            except (IndexError, AssertionError):
                LOG('empty list, breaking')
                break
            # endregion

    def aggregated_results(self, limit=10):
        stored_events = []
        for events in self._iter_events():
            stored_events.extend(events)
            if len(stored_events) >= limit:
                return stored_events[:limit]
        return stored_events

    @staticmethod
    def get_last_run(events) -> dict:
        last_time = events[-1].get('@timestamp') / 1000
        next_fetch_time = datetime.fromtimestamp(last_time) + timedelta(seconds=1)
        return {'after': next_fetch_time.isoformat()}


if __name__ in ('__main__', '__builtin__', 'builtins'):
    # Args is always stronger. Get last run even stronger
    demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()

    # merge the headers together
    headers = json.loads(demisto_params['headers'])
    encrypted_headers = json.loads(demisto_params['encrypted_headers'])
    demisto_params['headers'] = dict(encrypted_headers.items() | headers.items())
    del demisto_params['encrypted_headers']

    demisto_params['params'] = ReqParams(**demisto_params)

    last_run = '2022-04-11T13:20:00Z'
    demisto_params['params'].set_after_value(last_run)

    request = Request(**demisto_params)

    client = Client(request)

    get_events = GetEvents(client)

    command = demisto.command()
    if command == 'test-module':
        get_events.aggregated_results(limit=1)
        demisto.results('ok')
    else:
        args = Args(**demisto_params)
        events = get_events.aggregated_results(args.limit)
        if events:
            demisto.setLastRun(GetEvents.get_last_run(events))

        command_results = CommandResults(
            readable_output=tableToMarkdown('Github events', events, headerTransform=pascalToSpace),
            outputs_prefix='Github.Events',
            outputs_key_field='@timestamp',
            outputs=events,
            raw_response=events,
        )
        return_results(command_results)

