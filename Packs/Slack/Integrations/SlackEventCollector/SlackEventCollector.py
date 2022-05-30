# pylint: disable=no-name-in-module
# pylint: disable=no-self-argument

import urllib3
from pydantic import Field, parse_obj_as

from SiemApiModule import *  # noqa: E402

urllib3.disable_warnings()


def get_slack_events_to_timestamp_format(value: Any) -> int:
    """Converting datetime input to Unix timestamp format"""
    datetime_obj: Optional[datetime]
    if isinstance(value, int):
        value = str(value)
    if not isinstance(value, datetime):
        datetime_obj = dateparser.parse(value)
    if datetime_obj is None:
        raise TypeError(f'Argument is not a valid time: {value}')
    return int(datetime_obj.timestamp())


class SlackEventsParams(BaseModel):
    oldest: Optional[int]
    latest: Optional[int]
    limit: int = Field(1000, alias='limit', gt=0, le=9999)
    action: Optional[str]
    actor: Optional[str]
    entity: Optional[str]
    last_id: Optional[str]  # used in lastRun object only, for dedup

    # validators
    _normalize_oldest = validator('oldest', pre=True, allow_reuse=True)(
        get_slack_events_to_timestamp_format
    )
    _normalize_latest = validator('latest', pre=True, allow_reuse=True)(
        get_slack_events_to_timestamp_format
    )

    class Config:
        validate_assignment = True


class SlackEventsRequestConfig(IntegrationHTTPRequest):
    # https://api.slack.com/admins/audit-logs#how_to_call
    params: SlackEventsParams
    url = parse_obj_as(AnyUrl, 'https://api.slack.com/audit/v1/logs')
    headers = {'Accept': 'application/json'}
    method = Method.GET


class SlackEventClient(IntegrationEventsClient):
    def __init__(self, params: dict) -> None:
        request = SlackEventsRequestConfig(params=SlackEventsParams.parse_obj(params))
        set_authorization(request, params.get('user_token'))
        options = IntegrationOptions.parse_obj(params)
        super().__init__(request, options)

    def set_request_filter(self, _: Any) -> None:
        pass


class SlackGetEvents(IntegrationGetEvents):
    def __init__(self, client: IntegrationEventsClient) -> None:
        super().__init__(client, client.options)

    @staticmethod
    def get_last_run(events: list) -> dict:
        return {
            'oldest': events[-1]['date_create'],
            'last_id': events[-1]['id']
        }

    def remove_duplicates(self, events: list) -> list:
        if events and events[0].get('date_create') == self.client.request.params.oldest:
            for idx, event in enumerate(events):
                if event.get('id') == self.client.request.params.last_id:
                    return events[idx + 1:]
        return events

    def _iter_events(self) -> list:
        # No need to implement a generator, since the API supports limit of 9999 records.
        events = (self.call().json() or {}).get('entries', [])
        events.reverse()  # results from API are descending (most to least recent)
        return [self.remove_duplicates(events)]


''' MAIN FUNCTION '''


def main(command: str, params: dict) -> None:  # pragma: no cover
    client = SlackEventClient(params)
    get_events = SlackGetEvents(client)
    demisto.debug(f'Command being called is {command}')

    try:
        if command == 'test-module':
            client.request.params.limit = 1
            get_events.run()
            demisto.results('ok')

        elif command in ['slack-get-events', 'fetch-events']:
            events = get_events.run()

            if argToBoolean(params.get('should_push_events', 'true')):
                send_events_to_xsiam(
                    events,
                    params.get('vendor', 'slack'),
                    params.get('product', 'slack')
                )

            if command == 'slack-get-events':
                return_results(
                    CommandResults(
                        outputs_prefix='SlackEvents',
                        outputs_key_field='id',
                        outputs=events,
                        readable_output=tableToMarkdown('Slack Audit Logs', events, date_fields=['date_create']),
                    )
                )
            elif events:
                demisto.setLastRun(get_events.get_last_run(events))

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{e}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()
    main(demisto.command(), demisto_params)
