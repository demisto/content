from datetime import datetime
import urllib3
from CommonServerPython import *
import demistomock as demisto
from pydantic import (
    BaseModel,
    validator,
)
import dateparser

urllib3.disable_warnings()


class GithubOptions(IntegrationOptions):
    limit: int = 10


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


class GithubParams(
    BaseModel
):  # TODO: implement request params or any API-specific model (if any)
    include: str
    order: str = 'asc'
    after: str
    per_page: int = 100  # Maximum is 100
    # validators
    _normalize_after = validator('after', pre=True, allow_reuse=True)(
        get_github_timestamp_format
    )

    class Config:
        validate_assignment = True


class GithubRequest(IntegrationHTTPRequest):
    params: GithubParams


class GithubClient(IntegrationEventsClient):
    def set_request_filter(self, after: Any):
        self.request.params.after = after  # type: ignore[attr-defined]


class GithubGetEvents(IntegrationGetEvents):
    @staticmethod
    def get_last_run(events: Any) -> dict:  # type: ignore
        """TODO: Implement the last run (from previous logs)"""
        last_time = events[-1].get('@timestamp') / 1000
        next_fetch_time = datetime.fromtimestamp(last_time) + timedelta(
            seconds=1
        )
        return {'after': next_fetch_time.isoformat()}

    def _iter_events(self):
        # region First Call
        events = self.call().json()
        # endregion
        # region Yield Response
        while True and events:  # Run as long there are logs
            yield events
            # endregion
            # region Prepare Next Iteration (Paging)
            last = events.pop()
            self.client.set_request_filter(last['@timestamp'])
            # endregion
            # region Do next call
            events = self.call().json()
            try:
                events.pop(0)
            except (IndexError):
                demisto.info('empty list, breaking')
                break
            # endregion


if __name__ in ('__main__', '__builtin__', 'builtins'):
    # Args is always stronger. Get getIntegrationContext even stronger
    demisto_params = (
        demisto.params() | demisto.args() | demisto.getIntegrationContext()
    )

    demisto_params['params'] = GithubParams.parse_obj(demisto_params)
    request = GithubRequest.parse_obj(demisto_params)

    # TODO: If you're not using basic auth or Bearer __token_, you should implement your own
    set_authorization(request, demisto_params['auth_credendtials'])

    options = GithubOptions.parse_obj(demisto_params)

    client = GithubClient(request, options)
    get_events = GithubGetEvents(client, options)
    command = demisto.command()
    if command == 'test-module':
        get_events.run()
        demisto.results('ok')
    else:
        events = get_events.run()

        if events:
            demisto.setIntegrationContext(
                IntegrationGetEvents.get_last_run(events)
            )
        command_results = CommandResults(
            readable_output=tableToMarkdown(
                'Github events', events, headerTransform=pascalToSpace
            ),
            outputs_prefix='Github.Events',
            outputs_key_field='@timestamp',
            outputs=events,
            raw_response=events,
        )
        return_results(command_results)
