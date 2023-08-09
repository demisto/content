from enum import Enum
from pydantic import BaseModel, AnyUrl, Json  # pylint: disable=no-name-in-module
from CommonServerPython import *

VENDOR = "okta"
PRODUCT = "okta"


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


class ReqParams(BaseModel):  # pragma: no cover
    """
    A class that stores the request query params
    """
    since: str
    sortOrder: Optional[str] = 'ASCENDING'
    limit: str = '1000'

    def set_since_value(self, since: str) -> None:  # pragma: no cover
        self.since = since


class Request(BaseModel):  # pragma: no cover
    """
    A class that stores a request configuration
    """
    method: Method = Method.GET
    url: AnyUrl
    headers: Optional[Union[Json[dict], dict]]
    params: Optional[ReqParams]
    verify: bool = True
    data: Optional[str] = None


class Client:
    """
    A class for the client request handling
    """

    def __init__(self, request: Request):  # pragma: no cover
        self.request = request

    def call(self, requests=requests) -> requests.Response:  # pragma: no cover
        try:
            response = requests.request(**self.request.dict())
            response.raise_for_status()
            return response
        except Exception as exc:
            msg = f'something went wrong with the http call {exc}'
            LOG(msg)
            raise DemistoException(msg) from exc

    def set_next_run_filter(self, after: str):
        self.request.params.set_since_value(after)  # type: ignore


class GetEvents:
    """
    A class to handle the flow of the integration
    """

    def __init__(self, client: Client) -> None:
        self.client = client

    def make_api_call(self):
        limit_tmp = int(self.client.request.params.limit)  # type: ignore
        if limit_tmp > 1000:
            self.client.request.params.limit = '1000'  # type: ignore
        response = self.client.call()
        events: list = response.json()
        self.client.request.params.limit = str(limit_tmp - len(events))  # type: ignore
        return events

    def _iter_events(self, last_object_ids: list) -> None:  # type: ignore  # pragma: no cover
        """
        Function that responsible for the iteration over the events returned from the Okta api
        """

        events: list = self.make_api_call()  # type: ignore
        if last_object_ids:
            events = GetEvents.remove_duplicates(events, last_object_ids)
        while True:
            yield events
            last = events[-1]
            self.client.set_next_run_filter(last['published'])
            events: list = self.make_api_call()  # type: ignore
            try:
                assert events
            except (IndexError, AssertionError):
                LOG('empty list, breaking')
                break

    def aggregated_results(self, last_object_ids: List[str] = None) -> List[dict]:  # pragma: no cover
        """
        Function to group the events returned from the api
        """
        stored_events = []
        for events in self._iter_events(last_object_ids):  # type: ignore
            stored_events.extend(events)
            if int(self.client.request.params.limit) == 0 or len(events) == 0:  # type: ignore
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
        for event in reversed(events):
            if event.get('published') != last_time:
                break
            ids.append(event.get('uuid'))
        last_time = datetime.strptime(str(last_time).lower().replace('z', ''), '%Y-%m-%dt%H:%M:%S.%f')
        return {'after': last_time.isoformat(), 'ids': ids}

    @staticmethod
    def remove_duplicates(events: list, ids: list) -> list:
        """
        Remove object duplicates by the uuid of the object
        """
        return [event for event in events if event['uuid'] not in ids]


def main():  # pragma: no cover
    try:
        demisto_params = demisto.params() | demisto.args()
        events_limit = int(demisto_params.get('limit', 2000))
        should_push_events = argToBoolean(demisto_params.get('should_push_events', 'false'))
        after = dateparser.parse(demisto_params['after'].strip())
        api_key = demisto_params['api_key']['password']
        demisto_params['headers'] = {"Accept": "application/json", "Content-Type": "application/json",
                                     "Authorization": f"SSWS {api_key}"}
        demisto_params['url'] = urljoin(demisto_params['url'], '/api/v1/logs')
        last_run = demisto.getLastRun()
        last_object_ids = last_run.get('ids')
        if 'after' not in last_run:
            last_run = after.isoformat()  # type: ignore
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

        if command == 'okta-get-events':
            events = get_events.aggregated_results(last_object_ids=last_object_ids)
            command_results = CommandResults(
                readable_output=tableToMarkdown('Okta Logs', events, headerTransform=pascalToSpace),
                raw_response=events,
            )
            return_results(command_results)

            if should_push_events:
                send_events_to_xsiam(events[:events_limit], vendor=VENDOR, product=PRODUCT)

        elif command == 'fetch-events':
            events = get_events.aggregated_results(last_object_ids=last_object_ids)
            send_events_to_xsiam(events[:events_limit], vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(GetEvents.get_last_run(events))

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
