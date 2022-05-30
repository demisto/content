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


class Params(BaseModel):
    oldest: Optional[int]
    latest: Optional[int]
    limit: int = Field(1000, alias='limit', gt=0, le=9999)
    action: Optional[str]
    actor: Optional[str]
    entity: Optional[str]
    last_id: Optional[str]  # used for dedup only

    # validators
    _normalize_oldest = validator('oldest', pre=True, allow_reuse=True)(
        get_slack_events_to_timestamp_format
    )
    _normalize_latest = validator('latest', pre=True, allow_reuse=True)(
        get_slack_events_to_timestamp_format
    )

    class Config:
        validate_assignment = True


class RequestConfig(IntegrationHTTPRequest):
    # https://api.slack.com/admins/audit-logs#how_to_call
    params: Optional[Params] = None
    url = parse_obj_as(AnyUrl, 'https://api.slack.com/audit/v1/logs')
    headers = {'Accept': 'application/json'}
    method = Method.GET


class Client(IntegrationEventsClient):
    def __init__(self, creds: dict) -> None:
        request = RequestConfig()
        set_authorization(request, creds)
        super().__init__(request)

    @staticmethod
    def get_last_run(events: list) -> dict:
        return {
            'oldest': events[-1]['date_create'],
            'last_id': events[-1]['id']
        }

    def remove_duplicates(self, events: list) -> list:
        if events and events[0].get('date_create') == self.request.params.oldest:
            for idx, event in enumerate(events):
                if event.get('id') == self.request.params.last_id:
                    return events[idx + 1:]
        return events

    def run(self) -> list:
        events = (self.call().json() or {}).get('entries', [])
        events = events.get('entries', [])
        events.reverse()  # results from API are descending (most to least recent)
        return self.remove_duplicates(events)


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    command = demisto.command()
    params = demisto.getXSIAMParams()
    client = Client(params.get('user_token'))

    demisto.debug(f'Command being called is {command}')
    try:
        if command == 'test-module':
            client.request.params = Params(limit=1)
            client.run()
            demisto.results('ok')

        elif command in ['slack-get-events', 'fetch-events']:
            client.request.params = Params.parse_obj(params)
            events = client.run()

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
                demisto.setLastRun(client.get_last_run(events))

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{e}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
