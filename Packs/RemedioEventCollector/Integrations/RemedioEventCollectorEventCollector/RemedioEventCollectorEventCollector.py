import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403
from datetime import datetime, timezone


PAGE_SIZE = 1000


class Client(BaseClient):
    def __init__(self, base_url, api_key, verify=True, proxy=False):
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            headers={
                'x-api-key': api_key,
                'Content-Type': 'application/json',
            },
        )

    def get_misconfigurations(self, max_fetch=None):
        all_misconfigs = []
        cursor = None

        while True:
            params = {'limit': PAGE_SIZE}
            if cursor:
                params['cursor'] = cursor

            response = self._http_request(
                method='POST',
                url_suffix='/misconfigurations',
                params=params,
                json_data={},
            )

            data = response.get('data', [])
            all_misconfigs.extend(data)

            if max_fetch and len(all_misconfigs) >= max_fetch:
                all_misconfigs = all_misconfigs[:max_fetch]
                break

            cursor = response.get('nextCursor')
            if not cursor:
                break

        return all_misconfigs

    def test_connection(self):
        self._http_request(
            method='POST',
            url_suffix='/misconfigurations',
            params={'limit': 1},
            json_data={},
        )


def build_event(misconfig, fetch_time):
    return {
        '_time': fetch_time,
        'event_type': 'misconfiguration',
        'misconfigurationId': misconfig['misconfigurationId'],
        'title': misconfig.get('title', ''),
        'description': misconfig.get('description', ''),
        'severity': misconfig.get('severity', ''),
        'alertsCount': misconfig.get('alertsCount', 0),
        'devicesCount': misconfig.get('devicesCount', 0),
        'instancesCount': misconfig.get('instancesCount', 0),
        'instanceValueCategory': misconfig.get('instanceValueCategory', ''),
        'cvss': misconfig.get('scores', {}).get('cvss', 0),
    }


def fetch_events(client, params):
    max_fetch = arg_to_number(params.get('max_fetch'), arg_name='max_fetch')
    fetch_time = datetime.now(tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    misconfigs = client.get_misconfigurations(max_fetch=max_fetch)
    events = [build_event(m, fetch_time) for m in misconfigs]

    if events:
        try:
            send_events_to_xsiam(
                events=events,
                vendor='remedio',
                product='misconfigurations',
            )
        except Exception as e:
            demisto.debug(f'Failed to send {len(events)} events to XSIAM: {e}')
            raise

    demisto.setLastRun({'last_fetch': fetch_time})
    demisto.debug(f'Fetched and sent {len(events)} misconfiguration events to XSIAM')


def get_events_command(client, args):
    limit = arg_to_number(args.get('limit')) or 100
    should_push = argToBoolean(args.get('should_push_events', 'false'))
    misconfigs = client.get_misconfigurations(max_fetch=limit)
    fetch_time = datetime.now(tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    events = [build_event(m, fetch_time) for m in misconfigs]

    if should_push and events:
        send_events_to_xsiam(
            events=events,
            vendor='remedio',
            product='misconfigurations',
        )

    return CommandResults(
        readable_output=tableToMarkdown(
            'Remedio Misconfigurations',
            events,
            headers=['_time', 'misconfigurationId', 'title', 'severity',
                     'alertsCount', 'devicesCount', 'cvss'],
        ),
        outputs_prefix='Remedio.Misconfigurations',
        outputs_key_field='misconfigurationId',
        outputs=events,
    )


def test_module(client):
    try:
        client.test_connection()
        return 'ok'
    except DemistoException as e:
        if e.res is not None:
            if e.res.status_code == 401:
                return 'Authorization failed - check API key'
            if e.res.status_code == 403:
                return 'Forbidden - check API key permissions'
        if 'Connection' in str(e):
            return f'Connection failed - verify server URL: {e}'
        raise


def main():
    try:
        params = demisto.params()
        command = demisto.command()
        demisto.debug(f'Command being called is {command}')

        api_key = params.get('api_key', {})
        if isinstance(api_key, dict):
            api_key = api_key.get('password', '')

        client = Client(
            base_url=params.get('url', '').rstrip('/') + '/customer_api/v1',
            api_key=api_key,
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
        )

        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'fetch-events':
            fetch_events(client, params)
        elif command == 'remedio-get-events':
            return_results(get_events_command(client, demisto.args()))
        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
