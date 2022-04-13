from enum import Enum
import urllib3
from CommonServerPython import *
import demistomock as demisto
from pydantic import BaseConfig, BaseModel, AnyUrl, Json, validator, Field
import requests
from requests.auth import HTTPBasicAuth
import dateparser
from datetime import datetime

urllib3.disable_warnings()


DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"


class Method(str, Enum):
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    HEAD = 'HEAD'
    PATCH = 'PATCH'
    DELETE = 'DELETE'


class Args(BaseModel):
    from_: str = Field(
        datetime.strftime(dateparser.parse(demisto.params().get('first_fetch', '3 days')), DATETIME_FORMAT),
        alias='from'
    )
    limit: int = 1000
    offset: int = 0


class ReqParams(BaseModel):
    from_: str = Field(
        datetime.strftime(dateparser.parse(demisto.params().get('first_fetch', '3 days')), DATETIME_FORMAT),
        alias='from'
    )
    limit: int = 1000
    offset: int = 0


class Request(BaseModel):
    method: Method
    url: AnyUrl
    headers: Union[Json, dict] = {}
    params: Optional[ReqParams]
    insecure: bool = Field(not demisto.params().get('insecure', False), alias='verify')
    proxy: bool = Field(demisto.params().get('proxy', False), alias='proxies')
    data: Optional[str]
    auth: Optional[HTTPBasicAuth]

    class Config(BaseConfig):
        arbitrary_types_allowed = True


class Client:
    def __init__(self, request: Request, session=requests.Session()):
        self.request = request
        self.session = session
        self._set_proxy()
        self._set_cert_verification()

    def __del__(self):
        try:
            self.session.close()
        except AttributeError as err:
            demisto.debug(f'Ignore exceptions raised due to session not used by the client. {err}')

    def call(self) -> requests.Response:
        try:
            response = self.session.request(**self.request.dict(by_alias=True))
            response.raise_for_status()
            return response
        except Exception as exc:
            msg = f'Something went wrong with the http call {exc}'
            LOG(msg)
            raise DemistoException(msg) from exc

    def prepare_next_run(self, offset: int):
        self.request.params.offset = offset

    def _set_cert_verification(self):
        if not self.request.insecure:
            skip_cert_verification()

    def _set_proxy(self):
        if self.request.proxy:
            ensure_proxy_has_http_prefix()
        else:
            skip_proxy()


class GetEvents:
    def __init__(self, client: Client) -> None:
        self.client = client

    def call(self):
        resp = self.client.call()
        return resp.json().get('records', [])

    def _iter_events(self):
        events = self.call()
        offset = 0

        while events:  # Run as long there are logs
            yield events

            offset += self.client.request.params.limit
            self.client.prepare_next_run(offset)
            events = self.call()

    def run(self, mas_fetch=100):
        stored = []
        for logs in self._iter_events():
            stored.extend(logs)
            if len(stored) >= mas_fetch:
                return stored[:mas_fetch]
        return stored

    @staticmethod
    def get_last_run(logs) -> dict:
        last_time = logs[0].get('created').removesuffix('+0000')
        return {'from': last_time}


def main():
    # Args is always stronger. Get last run even stronger
    demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()
    credentials = demisto_params.get('credentials', {})
    demisto_params['auth'] = HTTPBasicAuth(credentials.get('identifier'), credentials.get('password'))
    demisto_params['params'] = ReqParams.parse_obj(demisto_params)
    request = Request.parse_obj(demisto_params)
    client = Client(request)
    get_events = GetEvents(client)
    command = demisto.command()

    if command == 'test-module':
        get_events.run(mas_fetch=1)
        demisto.results('ok')
    else:
        events = get_events.run(mas_fetch=int(demisto_params.get('max_fetch', 100)))
        if events:
            demisto.setLastRun(GetEvents.get_last_run(events))
        command_results = CommandResults(
            readable_output=tableToMarkdown('Jira records', events, removeNull=True, headerTransform=pascalToSpace),
            outputs_prefix='Jira.Records',
            outputs_key_field='id',
            outputs=events,
            raw_response=events,
        )
        return_results(command_results)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
