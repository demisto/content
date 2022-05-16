from datetime import datetime
from enum import Enum
import urllib3
from CommonServerPython import *
import demistomock as demisto
from pydantic import BaseModel, AnyUrl, Json, validator  # pylint: disable=no-name-in-module
import dateparser
from collections.abc import Generator


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
    include: str
    order: str = 'asc'
    after: str
    per_page: int = 100  # Maximum is 100
    _normalize_after = validator('after', pre=True, allow_reuse=True)(
        get_github_timestamp_format
    )


class Request(BaseModel):
    """
    A class that stores a request configuration
    """
    method: Method = Method.GET
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
        if self.request.params:
            self.request.params.after = get_github_timestamp_format(after)


class GetEvents:
    """
    A class to handle the flow of the integration
    """
    def __init__(self, client: Client) -> None:
        self.client = client

    def _iter_events(self) -> Generator:
        """
        Function that responsible for the iteration over the events returned from github api
        """
        response = self.client.call()
        events: list = response.json()

        if not events:
            return []

        while True:
            yield events
            last = events.pop()
            self.client.set_next_run_filter(last['@timestamp'])
            response = self.client.call()
            events = response.json()
            try:
                events.pop(0)
                assert events
            except (IndexError, AssertionError):
                LOG('empty list, breaking')
                break

    def aggregated_results(self, limit=2000) -> List[dict]:
        """
        Function to group the events returned from the api
        """
        stored_events = []
        for events in self._iter_events():
            stored_events.extend(events)
            if len(stored_events) >= limit:
                return stored_events[:limit]
        return stored_events

    @staticmethod
    def get_last_run(events: List[dict]) -> dict:
        """
        Get the info from the last run, it returns the time to query from and a list of ids to prevent duplications
        """

        last_timestamp = events[-1]['@timestamp']
        last_time = last_timestamp / 1000
        next_fetch_time = datetime.fromtimestamp(last_time) + timedelta(
            seconds=1
        )
        return {'after': next_fetch_time.isoformat()}


def main():
    # Args is always stronger. Get last run even stronger
    demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()
    events_to_add_per_request = demisto_params.get('events_to_add_per_request', 1000)
    try:
        events_to_add_per_request = int(events_to_add_per_request)
    except ValueError:
        events_to_add_per_request = 1000

    headers = {'Authorization': f"Bearer {demisto_params['auth_credendtials']['password']}",
               'Accept': 'application/vnd.github.v3+json'}

    demisto_params['headers'] = headers
    demisto_params['params'] = ReqParams(**demisto_params)

    request = Request(**demisto_params)

    client = Client(request)

    get_events = GetEvents(client)

    command = demisto.command()
    try:
        urllib3.disable_warnings()

        if command == 'test-module':
            get_events.aggregated_results(limit=1)
            return_results('ok')
        elif command in ('github-get-events', 'fetch-events'):
            events = get_events.aggregated_results(limit=int(demisto_params.get('limit')))

            if command == 'fetch-events':
                if events:
                    demisto.setLastRun(GetEvents.get_last_run(events))
                else:
                    send_events_to_xsiam([], 'github', demisto_params.get('product'))

            elif command == 'github-get-events':
                command_results = CommandResults(
                    readable_output=tableToMarkdown('Github Logs', events, headerTransform=pascalToSpace),
                    outputs_prefix='Github.Logs',
                    outputs_key_field='@timestamp',
                    outputs=events,
                    raw_response=events,
                )
                return_results(command_results)

            while len(events) > 0:
                send_events_to_xsiam(events[:events_to_add_per_request], 'github',
                                     demisto_params.get('product'))
                events = events[events_to_add_per_request:]

    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
