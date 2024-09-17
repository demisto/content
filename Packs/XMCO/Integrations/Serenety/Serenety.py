import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

''' CONSTANTS '''

ISO_8601_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def _get(self, url_suffix: str, params: dict[str, Any] | None = None):
        return self._http_request(method="GET", url_suffix=url_suffix, params=params)

    def _post(self, url_suffix: str, params: dict[str, Any] | None = None):
        return self._http_request(
            method="POST", url_suffix=url_suffix, data=json.dumps(params)
        )

    def fetch_current_user(self) -> dict[str, Any]:
        return self._get('/user/current')

    def fetch_alert(self, scope_id: str = None, dry_run: bool = None) -> list[dict[str, Any]]:
        has_next = True
        params: dict[str, Any] = {
            "page": 1
        }
        if scope_id:
            params['scope'] = scope_id

        if dry_run is not None:
            params['to_sync'] = dry_run

        res = self._get(
            url_suffix='/ticketor/serenety',
            params=params
        )
        data = res.get('items')

        while has_next:
            if res and res['page'] < res['pages']:
                params['page'] += 1
                res = self._get(
                    url_suffix='/ticketor/serenety',
                    params=params
                )

                data += res.get('items', [])
            else:
                has_next = False

        return data


''' HELPER FUNCTIONS'''


def convert_to_demisto_severity(severity: str) -> float:
    """
    Maps XMCO severity to Cortex XSOAR severity.
    Converts the XMCO alert severity level ('none', 'low', 'medium', 'high', 'critical') to Cortex XSOAR alert
    severity (1 to 4).

    Args:
        severity (str): severity as returned from the LePortail API.

    Returns:
        int: Cortex XSOAR Severity (0,5 to 4)
    """
    return {
        'none': IncidentSeverity.INFO,
        'low': IncidentSeverity.LOW,
        'medium': IncidentSeverity.MEDIUM,
        'high': IncidentSeverity.HIGH,
        'critical': IncidentSeverity.CRITICAL
    }.get(severity, IncidentSeverity.INFO)


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'User <username> is authenticated' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'User <first_name> <surname> is authenticated' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        result = client.fetch_current_user()
        if result.get('_error', None):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return message


def fetch_incidents(client: Client,
                    last_run: dict,
                    first_fetch_time: str,
                    scope: str = None, ) -> tuple[dict[str, str], list[dict]]:
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client: XMCO LePortail client
        last_run: A dict with a key containing the latest incident created time we got
        from last fetch
        first_fetch_time: If last_run is None then fetch all incidents since first_fetch_time
        scope: filter incident by scope from LePortail

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Cortex XSOAR
    """
    # Get the last fetch time, if exists
    last_fetch = last_run.get("last_fetch", None)
    if last_fetch is None:
        last_fetch = first_fetch_time
    else:
        last_fetch = datetime.now().strftime(ISO_8601_FORMAT)

    incidents: list[dict[str, Any]] = []
    items = client.fetch_alert(scope)
    for item in items:
        try:
            data = item.get('data', {})
            if data:
                created = dateparser.parse(data['_created'])
                incident = {
                    'severity': convert_to_demisto_severity(data.get('severity', 'low')),
                    'occurred': created.strftime(ISO_8601_FORMAT),  # type: ignore[union-attr]
                    'Category': data['custom_fields']['category'],
                    'rawJSON': json.dumps(data),
                }

                incidents.append(incident)
        except Exception as e:
            demisto.debug(f'{e}')
            continue

    next_run = {'last_fetch': last_fetch}

    return next_run, incidents


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    params = demisto.params()
    args = demisto.params()
    command = demisto.command()

    api_key = params.get('api_key', {}).get('password', '')

    # get the service API url
    base_url = urljoin(params['url'], '/api')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not params.get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')
    demisto.debug(f'APIKEY {api_key}')
    try:
        headers: dict = {
            "Authorization": f'Bearer {api_key}',
            "Content-Type": "application/json; charset=utf-8"
        }

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif demisto.command() == 'fetch-incidents':

            first_fetch_datetime = arg_to_datetime(arg=params.get("first_fetch"), arg_name="First fetch time", required=True)
            if first_fetch_datetime:
                first_fetch_time = first_fetch_datetime.strftime(ISO_8601_FORMAT)
            else:
                first_fetch_time = datetime.now().strftime(ISO_8601_FORMAT)

            next_run, incidents = fetch_incidents(client=client,
                                                  last_run=demisto.getLastRun(),
                                                  first_fetch_time=first_fetch_time,
                                                  scope=args.get('scope', None))
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        else:
            raise NotImplementedError(f"command {command} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
