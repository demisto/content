import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import datetime
import urllib3
import dateparser
from collections.abc import Generator
from SiemApiModule import *  # noqa: E402

urllib3.disable_warnings()
VENDOR = 'github'
PRODUCT = 'github-audit'
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def get_github_timestamp_format(value):
    """Converts int(epoch), str(3 days), or datetime to GitHub's API time format.

    Args:
        value (Any): The value to convert to GitHub's API time format.

    Returns:
        str: The value in GitHub's API time format.

    Raises:
        TypeError: If the input value is not a valid time.
    """
    if isinstance(value, int):
        value = datetime.utcfromtimestamp(value / 1000)
    elif isinstance(value, str):
        value = dateparser.parse(value)
    if not isinstance(value, datetime):
        raise TypeError(f'after is not a valid time {value}')

    return f'created:>{value.strftime(DATETIME_FORMAT)}'


def prepare_demisto_params(params: dict):
    params['phrase'] = params.get('after')
    del params['after']


class GithubParams(BaseModel):
    """
    A class that stores the request query params
    """
    include: str
    order: str = 'asc'
    phrase: str
    per_page: int = 100  # Maximum is 100
    _normalize_after = validator('phrase', pre=True, allow_reuse=True)(  # type: ignore[type-var]
        get_github_timestamp_format
    )


class GithubEventsRequestConfig(IntegrationHTTPRequest):
    url: AnyUrl
    method: Method = Method.GET
    params: GithubParams  # type: ignore


class GithubClient(IntegrationEventsClient):
    def set_request_filter(self, after: str):
        if self.request.params:
            self.request.params.phrase = get_github_timestamp_format(after)  # type: ignore


class GithubGetEvents(IntegrationGetEvents):

    def _iter_events(self) -> Generator | list:  # type: ignore[return]
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
                assert events
            except (IndexError, AssertionError):
                LOG('empty list, breaking')
                break

    @staticmethod
    def get_last_run(events: List[dict]) -> dict:
        """
        Get the info from the last run, it returns the time to query from and a list of ids to prevent duplications
        """
        if not events:
            return demisto.getLastRun()
        last_timestamp = events[-1]['@timestamp']
        return {'after': last_timestamp}


def main():  # pragma: no cover
    # Once the parameter "after" is hidden, the previous value of the parameter is saved, not the new default value which
    # is 1 minute. For example if the previous value of "after" (First fetch time interval) was "3 days", after the parameter
    # "after" is hidden it will remain "3 days" and each time Reset the "last run" timestamp is used, it will use "3 days"
    # instead of "1 minute".
    demisto.params()['after'] = '1 minute'
    # Args is always stronger. Get last run even stronger
    demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()
    demisto.debug(f'{demisto_params.get("after")=}')

    should_push_events = argToBoolean(demisto_params.get('should_push_events', 'false'))

    headers = {'Authorization': f"Bearer {demisto_params['auth_credendtials']['password']}",
               'Accept': 'application/vnd.github.v3+json'}

    demisto_params['headers'] = headers

    prepare_demisto_params(demisto_params)
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
            demisto.debug(f'{len(events)=}')

            if command == 'fetch-events':
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                demisto.setLastRun(GithubGetEvents.get_last_run(events))

            elif command == 'github-get-events':
                command_results = CommandResults(
                    readable_output=tableToMarkdown('Github Logs', events, headerTransform=pascalToSpace),
                    outputs_prefix='Github.Logs',
                    outputs_key_field='@timestamp',
                    outputs=events,
                    raw_response=events,
                )
                return_results(command_results)
                if should_push_events:
                    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
