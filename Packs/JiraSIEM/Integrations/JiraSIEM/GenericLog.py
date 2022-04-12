import __future__
from datetime import datetime
from enum import Enum
from CommonServerPython import *
import demistomock as demisto
from pydantic import BaseModel, AnyUrl, Json
import requests
from requests.auth import HTTPBasicAuth
import dateparser


class Method(str, Enum):
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    HEAD = 'HEAD'
    PATCH = 'PATCH'
    DELETE = 'DELETE'


class Request(BaseModel):
    method: Method
    url: AnyUrl
    headers: Optional[Union[Json[dict], dict]]
    params: Optional[Union[Json[dict], dict]]
    verify: bool = True
    data: str = None
    auth: Optional[HTTPBasicAuth]

    class Config:
        arbitrary_types_allowed = True


class Params(BaseModel):  # The params class should be in the DOTO section since each vendor has separate params
    per_page: str = '100'
    _from: str = ''


class Client:
    def __init__(self, request: Request, params: Params):
        self.request = request
        self.params = params

    def call(self, requests=requests) -> requests.Response:
        self.request.params = self.params
        return requests.request(**self.request.dict())

    def set_last_fetch(self, last_fetch: str):
        self.params._from = last_fetch


class GetLogs:
    def __init__(self, client: Client, after: int) -> None:
        self.client = client
        self.after = after

    def _iter_logs(self):
        # TODO how to generify this?

        # do call
        # yield response
        # check if should stop, break
        # prepare next iteration

        response = self.client.call()
        response.raise_for_status()
        logs: list = response.json()

        if not logs:
            return []

        while True:
            yield logs
            last = logs.pop()
            self.client.set_last_fetch(
                last['created']
            )

            response = self.client.call()
            logs: list = response.json()

            try:
                logs.pop(0)
                assert logs
            except (IndexError, AssertionError):
                LOG('empty list, breaking')
                break

    def get_logs(self, limit=10):
        stored = []
        for logs in self._iter_logs():
            stored.extend(logs)
            if len(stored) >= limit:
                return stored[:limit]
        return stored

    # @classmethod
    # def datetime_to_github_timestamp(cls, datet: datetime) -> str:
    #     da = datet.timestamp() * 1000
    #     return cls.encode_b64(da)

    # @staticmethod
    # def encode_b64(timestamp) -> str:
    #     str_bytes = f'{timestamp}|'.encode('ascii')
    #     base64_bytes = base64.b64encode(str_bytes)
    #     return base64_bytes.decode('ascii')


def main():
    params = demisto.params()
    params['auth'] = HTTPBasicAuth(params.get('username'), params.get('password'))
    request = Request(**params)

    if not (last_run := demisto.getLastRun()):
        last_run = dateparser.parse(params['first_fetch'])
    else:
        last_run = dateparser.parse(last_run.get('last_run'))

    params['_from'] = last_run  # Should change the function name to generic

    req_params = Params(**params)
    client = Client(request, req_params)
    get_logs = GetLogs(client, last_run)

    limit = int(params.get('limit', '1000'))
    command = demisto.command()

    if command == 'test-module':
        limit = 1
        get_logs.get_logs(limit)
        demisto.results('ok')
    else:
        logs = get_logs.get_logs(limit=limit)

        if logs:
            last_time = logs[-1].get('@timestamp') / 1000
            next_fetch_time = datetime.fromtimestamp(last_time) + timedelta(seconds=1)
            last_time_str = next_fetch_time.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
            demisto.setLastRun({'last_run': last_time_str})

        command_results = CommandResults(
            readable_output=tableToMarkdown('Github logs', logs, headerTransform=pascalToSpace),
            outputs_prefix='Github.Logs',
            outputs_key_field='@timestamp',
            outputs=logs,
            raw_response=logs,
        )
        return_results(command_results)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
