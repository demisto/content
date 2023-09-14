import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *


VENDOR = 'Infoblox BloxOne'
PRODUCT = 'Threat Defense'


class BloxOneTDEventCollectorClient(BaseClient):
    def __init__(self, api_key: str, verify=True, proxy=False):
        super(BloxOneTDEventCollectorClient, self).__init__(
            headers={'Authorization': f'Token {api_key}'},
            base_url='https://csp.infoblox.com',
            verify=verify,
            proxy=proxy
        )

    def fetch_events(self, from_ts: int, to_ts: int, limit: int = 1000, offset: int = 0) -> list[dict]:
        def map_time(event: dict) -> dict:
            event['_time'] = event.get('event_time')
            return event

        events = self._http_request('GET', '/api/dnsdata/v2/dns_event',
                                    params={'t0': from_ts, 't1': to_ts, '_limit': limit, '_offset': offset}
                                    ).get('result', [])
        return list(map(map_time, events))


def fetch_events_command(client: BloxOneTDEventCollectorClient, params: dict, last_run: dict):
    from_ts = last_run.get('from_ts') or parse_from_ts_from_params(params.get('first_fetch'))
    current_ts = int(datetime.utcnow().timestamp())
    offset = arg_to_number(last_run.get('offset')) or 0
    limit = arg_to_number(params.get('max_fetch')) or 1000
    limit = min(limit, 10000)
    events = client.fetch_events(from_ts, current_ts, limit, offset)

    send_events_to_xsiam(events, VENDOR, PRODUCT)
    demisto.setLastRun(
        {'from_ts': current_ts} if len(events) < limit else {'from_ts': from_ts, 'offset': offset + limit}
    )


def get_events_command(client: BloxOneTDEventCollectorClient, args: dict):
    events = client.fetch_events(
        args['from'], args['to'],
        min(arg_to_number(args.get('limit')) or 1000, 10000),
        arg_to_number(args.get('offset')) or 0
    )
    if argToBoolean(args.get('should_push_events', False)):
        send_events_to_xsiam(events, VENDOR, PRODUCT)

    return CommandResults(outputs=events, outputs_prefix="TestGetEvents")


def parse_from_ts_from_params(first_fetch_str: str = None) -> int:
    """
    Parses the `first_fetch_str` parameter as a date/time string and returns its Unix timestamp value in seconds.
    Args:
        first_fetch_str (str, optional): The (relative) date/time string to parse. Defaults to None,
        in which case the value "1 day" will be used.
    Returns:
        int: The Unix timestamp value of the parsed date/time string, in seconds.
    Raises:
        DemistoException: If the `first_fetch_str` parameter is not a valid date/time string.
    """

    from_date_time = dateparser.parse(first_fetch_str or '1 day', settings={'TIMEZONE': 'UTC'})
    if not from_date_time:
        raise DemistoException('Invalid date format in "First fetch time interval" parameter')
    return int(from_date_time.timestamp())


def command_test_module(client: BloxOneTDEventCollectorClient, params: dict) -> str:
    current_ts = int(datetime.utcnow().timestamp())
    previous_ts = current_ts - 60
    client.fetch_events(previous_ts, current_ts, 1)
    parse_from_ts_from_params(params.get('first_fetch'))
    return 'ok'


def main():
    params = demisto.params()
    client = BloxOneTDEventCollectorClient(
        api_key=dict_safe_get(params, ['credentials', 'password']),
        verify=not argToBoolean(params.get('insecure', False)),
        proxy=argToBoolean(params.get('proxy', False))
    )

    command = demisto.command()
    results: CommandResults | str | None = None
    try:
        if command == 'test-module':
            results = command_test_module(client, params)
        elif command == 'bloxone-td-event-collector-get-events':
            results = get_events_command(client, demisto.args())
        elif command == 'fetch-events':
            fetch_events_command(client, params, demisto.getLastRun() or {})
        else:
            raise NotImplementedError(f'command {command} is not implemented.')

        if results:
            return_results(results)
    except Exception as e:
        auth_error = isinstance(e, DemistoException) and getattr(e, 'res') is not None\
            and e.res.status_code == 401  # pylint: disable=E1101
        if auth_error:
            error_msg = 'authentication error please check your API key and try again.'
        else:
            error_msg = f'an error occurred while executing command {command}\nerror: {e}'

        return_error(error_msg, e)


if __name__ in ('__main__', 'builtins'):
    main()
