from datetime import datetime
from enum import Enum
import urllib3
from CommonServerPython import *
import demistomock as demisto
import dateparser
from collections.abc import Generator
from SiemApiModule import *  # noqa: E402

urllib3.disable_warnings()


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


class GithubParams(BaseModel):
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


class GithubEventsRequestConfig(IntegrationHTTPRequest):
    url = AnyUrl
    method = Method.GET
    params: GithubParams


class GithubClient(IntegrationEventsClient):
    def set_request_filter(self, after: str):
        if self.request.params:
            self.request.params.after = get_github_timestamp_format(after)


class GithubGetEvents(IntegrationGetEvents):

    def _iter_events(self) -> Generator:
        """
        Function that responsible for the iteration over the events returned from github api
        """
        events = self.client.call(self.client.request).json()

        if not events:
            return []

        while True:
            yield events
            last = events.pop()
            self.client.set_request_filter(last['@timestamp'])
            events = self.client.call(self.client.request).json()
            try:
                events.pop(0)
                assert events
            except (IndexError, AssertionError):
                LOG('empty list, breaking')
                break

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
    demisto_params['params'] = GithubParams(**demisto_params)

    request = GithubEventsRequestConfig(**demisto_params)

    options = IntegrationOptions.parse_obj(demisto_params)
    client = GithubClient(request, options)

    get_events = GithubGetEvents(client, options)

    command = demisto.command()
    try:
        if command == 'test-module':
            get_events.run()
            return_results('ok')
        elif command in ('github-get-events', 'fetch-events'):
            events = get_events.run()

            if command == 'fetch-events':
                if events:
                    demisto.setLastRun(GithubGetEvents.get_last_run(events))
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
