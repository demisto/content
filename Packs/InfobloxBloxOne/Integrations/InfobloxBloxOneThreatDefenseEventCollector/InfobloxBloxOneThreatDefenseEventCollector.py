from CommonServerPython import *
from CommonServerUserPython import *
import demistomock as demisto


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

    def fetch_events(self, from_ts: int, to_ts: int, limit: int = 1000, offset: int = 0) -> List[Dict]:
        def map_time(event: Dict) -> Dict:
            event['_time'] = event['event_time']
            return event

        events = self._http_request('GET', '/api/dnsdata/v2/dns_event',
                                    params={'t0': from_ts, 't1': to_ts, '_limit': limit, '_offset': offset}
                                    )['result']
        return list(map(map_time, events))


def fetch_events_command(client: BloxOneTDEventCollectorClient, params: Dict, last_run: Dict):
    from_ts = last_run.get('from_ts')
    if from_ts is None:
        from_date_time = dateparser.parse(params.get('first_fetch', '1 day'), settings={'TIMEZONE': 'UTC'})
        if from_date_time is None:
            raise DemistoException('Invalid date format in "First fetch time interval" parameter')

        from_ts = int(from_date_time.timestamp())

    current_ts = int(datetime.utcnow().timestamp())
    offset = arg_to_number(last_run.get('offset')) or 0
    limit = arg_to_number(params.get('max_fetch')) or 1000
    limit = min(limit, 10000)
    events = client.fetch_events(from_ts, current_ts, limit, offset)

    send_events_to_xsiam(events, VENDOR, PRODUCT)
    demisto.setLastRun(
        {'from_ts': current_ts} if len(events) < limit else {'from_ts': from_ts, 'offset': offset + limit}
    )


def get_events_command(client: BloxOneTDEventCollectorClient, args: Dict):
    events = client.fetch_events(
        args['from'], args['to'],
        min(arg_to_number(args.get('limit')) or 1000, 10000),
        arg_to_number(args.get('offset')) or 0
    )
    if argToBoolean(args.get('should_push_events')):
        send_events_to_xsiam(events, VENDOR, PRODUCT)

    return CommandResults(outputs=events)


def command_test_module(client: BloxOneTDEventCollectorClient) -> str:
    current_ts = int(datetime.utcnow().timestamp())
    previous_ts = current_ts - 60
    client.fetch_events(previous_ts, current_ts, 1)
    return 'ok'


def main():
    params = demisto.params()
    client = BloxOneTDEventCollectorClient(
        api_key=params['credentials']['password'],
        verify=not argToBoolean(params.get('insecure', False)),
        proxy=argToBoolean(params.get('proxy', False))
    )

    command = demisto.command()
    results: Optional[CommandResults | str] = None
    try:
        if command == 'test-module':
            results = command_test_module(client)
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
            error_msg = 'authentication error'
        else:
            error_msg = f'an error occurred while executing command {command}\nerror: {e}'

        return_error(error_msg, e)


if __name__ in ('__main__', 'builtins'):
    main()
