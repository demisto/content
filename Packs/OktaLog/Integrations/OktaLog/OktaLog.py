from enum import Enum

from pydantic import BaseModel, AnyUrl, Json

from CommonServerPython import *


class Method(str, Enum):
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    HEAD = 'HEAD'
    PATCH = 'PATCH'
    DELETE = 'DELETE'


class ReqParams(BaseModel):
    since: str
    sortOrder: Optional[str] = 'ASCENDING'
    limit: str = '100'

    def set_since_value(self, since):
        self.since = since



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
        self.request.params.set_since_value(after)


class GetEvents:
    def __init__(self, client: Client) -> None:
        self.client = client

    def _iter_events(self, last_object_ids):
        response = self.client.call()
        events: list = response.json()
        if last_object_ids:
            events = GetEvents.remove_duplicates(events, last_object_ids)
        if not events:
            return []
        while True:
            yield events
            last = events.pop()
            self.client.set_next_run_filter(last['published'])
            response = self.client.call()
            events: list = response.json()
            try:
                events.pop(0)
                assert events
            except (IndexError, AssertionError):
                LOG('empty list, breaking')
                break

    def aggregated_results(self, request_size=10, last_object_ids=None):
        stored_events = []
        for events in self._iter_events(last_object_ids):
            stored_events.extend(events)
            if len(stored_events) >= request_size:
                return stored_events[:request_size]
        return stored_events

    @staticmethod
    def get_last_run(events) -> dict:
        ids = []
        last_time = events[-1].get('published')
        for event in events:
            if event.get('published') == last_time:
                ids.append(event.get('uuid'))
        last_time = datetime.fromisoformat(str(last_time).replace('Z', ''))
        last_time = last_time - timedelta(milliseconds=1)
        return {'after': last_time.isoformat(), 'ids': ids}

    @staticmethod
    def remove_duplicates(events, ids):
        duplicates_indexes = []
        for i in range(len(events)):
            event_id = events[i]['uuid']
            if event_id in ids:
                duplicates_indexes.append(i)
        if len(duplicates_indexes) > 0:
            for i in duplicates_indexes:
                del events[i]
        return events


if __name__ in ('__main__', '__builtin__', 'builtins'):
    # Args is always stronger. Get last run even stronger
    demisto_params = demisto.params() #| demisto.args() | demisto.getLastRun()
    request_size = demisto_params.get('request_size')
    if not request_size:
        request_size = 1000
    else:
        request_size = int(request_size)
    print('request_size', request_size)
    print('*********************\n******************************\n*******************')
    print(demisto_params)
    print('*********************\n******************************\n*******************')
    if 'after' in demisto_params:
        after = int(demisto_params['after'])

    headers = json.loads(demisto_params['headers'])
    encrypted_headers = json.loads(demisto_params['encrypted_headers'])
    demisto_params['headers'] = dict(encrypted_headers.items() | headers.items())
    del demisto_params['encrypted_headers']
    # TODO: replace them when doing a pr
    # last_run = demisto.getLastRun()
    last_run = demisto.getIntegrationContext()
    print('ctx', last_run)
    last_object_ids = last_run.get('ids')
    # last_object_ids = ['180553f5-2e26-11ec-9335-f73245edc71f']
    if 'after' not in last_run:
        delta = datetime.today() - timedelta(days=after)
        last_run = delta.isoformat()
    else:
        last_run = last_run['after']
        print('after', last_run)
    demisto_params['params'] = ReqParams(**demisto_params, since=last_run)
    # demisto_params['params'].set_since_value('last_run')
    print('last_run', last_run)

    request = Request(**demisto_params)

    client = Client(request)

    get_events = GetEvents(client)

    command = demisto.command()
    if command == 'test-module':
        get_events.aggregated_results(limit=1)
        demisto.results('ok')
    else:
        args = Args(**demisto_params)
        events = get_events.aggregated_results(request_size, last_object_ids=last_object_ids)
        if events:
            # TODO: replace them when doing a pr
            # demisto.setLastRun(GetEvents.get_last_run(events))
            demisto.setIntegrationContext(GetEvents.get_last_run(events))

        command_results = CommandResults(
            readable_output=tableToMarkdown('Okta Logs', events, headerTransform=pascalToSpace),
            outputs_prefix='Okta.Logs',
            outputs_key_field='published',
            outputs=events,
            raw_response=events,
        )
        return_results(command_results)
