from enum import Enum
from pydantic import BaseModel, AnyUrl, Json # noqa
from CommonServerPython import *


class Method(str, Enum):
    """
    A list that represent the types of http request available
    """
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    HEAD = 'HEAD'
    PATCH = 'PATCH'
    DELETE = 'DELETE'


class ReqParams(BaseModel):
    """
    A class that stores the request query params
    """
    since: str
    sortOrder: Optional[str] = 'ASCENDING'
    limit: str = '1000'

    def set_since_value(self, since: str) -> None:
        self.since = since


class Request(BaseModel):
    """
    A class that stores a request configuration
    """
    method: Method
    url: AnyUrl
    headers: Optional[Union[Json[dict], dict]]
    params: Optional[ReqParams]
    verify = True
    data: Optional[str] = None


class Client:
    """
    A class for the client request handling
    """

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
    """
    A class to handle the flow of the integration
    """

    def __init__(self, client: Client) -> None:
        self.client = client

    def make_api_call(self):
        limit_tmp = int(self.client.request.params.limit)
        if limit_tmp > 1000:
            self.client.request.params.limit = '1000'
        response = self.client.call()
        events: list = response.json()
        self.client.request.params.limit = str(limit_tmp - len(events))
        return events


    def _iter_events(self, last_object_ids: list) -> None:
        """
        Function that responsible for the iteration over the events returned from the Okta api
        """

        events: list = self.make_api_call()
        if last_object_ids:
            events = GetEvents.remove_duplicates(events, last_object_ids)
        while True:
            yield events
            last = events[-1]
            self.client.set_next_run_filter(last['published'])
            events: list = self.make_api_call()
            try:
                assert events
            except (IndexError, AssertionError):
                LOG('empty list, breaking')
                break

    def aggregated_results(self, last_object_ids: List[str] = None) -> List[dict]:
        """
        Function to group the events returned from the api
        """
        stored_events = []
        for events in self._iter_events(last_object_ids):
            stored_events.extend(events)
            if int(self.client.request.params.limit) == 0 or len(events) == 0:
                break
        return stored_events

    @staticmethod
    def get_last_run(events: List[dict]) -> dict:
        """
        Get the info from the last run, it returns the time to query from and a list of ids to prevent duplications
        """

        ids = []
        # gets the last event time
        last_time = events[-1].get('published')
        for event in events:
            if event.get('published') == last_time:
                ids.append(event.get('uuid'))
        last_time = datetime.strptime(str(last_time).lower().replace('z', ''), '%Y-%m-%dt%H:%M:%S.%f')
        return {'after': last_time.isoformat(), 'ids': ids}

    @staticmethod
    def remove_duplicates(events: list, ids: list) -> list:
        """
        Remove object duplicates by the uuid of the object
        """

        duplicates_indexes = []
        for i in range(len(events)):
            event_id = events[i]['uuid']
            if event_id in ids:
                duplicates_indexes.append(i)
        if len(duplicates_indexes) > 0:
            for i in duplicates_indexes:
                del events[i]
        return events


def main():
    # Args is always stronger. Get last run even stronger
    demisto_params = demisto.params() #| demisto.args()
    events_to_add_per_request = demisto_params.get('events_to_add_per_request', 2000)
    try:
        events_to_add_per_request = int(events_to_add_per_request)
    except ValueError:
        events_to_add_per_request = 2000
    after = demisto_params['after']
    api_key = demisto_params['api_key']
    demisto_params['headers'] = {"Accept": "application/json", "Content-Type": "application/json",
                                 "Authorization": f"SSWS {api_key}"}
    last_run = demisto.getLastRun()
    last_object_ids = last_run.get('ids')
    # If we do not have an after in the last run than we calculate after according to now - after param .
    if 'after' not in last_run:
        delta = datetime.today() - timedelta(days=after)
        last_run = delta.isoformat()
    else:
        last_run = last_run['after']
    demisto_params['params'] = ReqParams(**demisto_params, since=last_run)

    request = Request(**demisto_params)

    client = Client(request)

    get_events = GetEvents(client)

    command = demisto.command()
    if command == 'test-module':
        get_events.aggregated_results()
        demisto.results('ok')
    elif command == 'okta-get-events' or command == 'fetch-events':
        try:
            events = get_events.aggregated_results(last_object_ids=last_object_ids)
        except Exception as e:
            raise Exception(str(e))
        events_number = len(events)
        if events:
            demisto.setLastRun(GetEvents.get_last_run(events))
            if command == 'fetch-events':
                demisto.updateModuleHealth({'eventsPulled': len(events)})
                while len(events) > 0:
                    send_events_to_xsiam(events[:events_to_add_per_request], 'okta', 'okta')
                    events = events[events_to_add_per_request:]

            elif command == 'okta-get-events':
                command_results = CommandResults(
                    readable_output=tableToMarkdown('Okta Logs', events, headerTransform=pascalToSpace),
                    outputs_prefix='Okta.Logs',
                    outputs_key_field='published',
                    outputs=events,
                    raw_response=events,
                )
                return_results(command_results)
        demisto.updateModuleHealth({'eventsPulled': events_number})


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
