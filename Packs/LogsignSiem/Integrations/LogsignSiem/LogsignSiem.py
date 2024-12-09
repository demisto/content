import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *
from datetime import datetime, timedelta
import urllib3
# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT: str = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
DATE_FORMAT_WITH_MICROSECOND = '%Y-%m-%dT%H:%M:%S.%fZ'
LOGSIGN_INC_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
DEFAULT_FETCH_LIMIT = 50
DEFAULT_FIRST_FETCH = '1 hour'
CONTENT_TYPE_JSON = 'application/json'
API_VERSION = 'v1.0'
INTEGRATION_VERSION = 'v1.0'

URL_SUFFIX: dict[str, str] = {
    'FETCH_INCIDENTS': 'get_incidents',
    'GET_COLUMN': 'get_columns',
    'GET_COUNT': 'get_count',
    'TEST_API': 'test_api'
}


class Client(BaseClient):
    def __init__(self, url: str, api_key: str, verify: bool, proxy: bool):
        """
            :type url: ``str``
            :param url: Base url of API Endpoint

            :type api_key: ``str``
            :param api_key: API Key

            :type verify: ``bool``
            :param verify: Whether the request should verify the SSL certificate.

            :type proxy: ``bool``
            :param proxy: Whether to run the integration using the system proxy.
        """
        self._api_key = api_key
        self._proxies = proxy
        super().__init__(base_url=url, verify=verify, proxy=self._proxies)

    def get_incidents(self, method: str, last_run: Any, query: str) -> Any:
        """
            Get-Incidents Service

            :type method: ``str``
            :param method: The HTTP method, for example: GET, POST, and so on.

            :type last_run: ``str``
            :param last_run: The greatest incident created_time we fetched from last fetch

            :type query: ``str``
            :param query: Query

            :return: Depends on the resp_type parameter
            :rtype: ``dict`` or ``str`` or ``requests.Response``
        """
        try:
            last_run = datetime.strftime(last_run, DATE_FORMAT)
        except Exception:
            raise ValueError('last_run type is not datetime format')
        return self._http_request(
            method=method,
            url_suffix=URL_SUFFIX['FETCH_INCIDENTS'],
            params={
                'api_key': self._api_key,
                'last_run': last_run,
                'query': query if query is not None else ''
            }
        )

    def get_query(self, method: str, query: str, url_suffix: str, grouped_column: str,
                  criteria: str, time_frame: str):
        """
            Get-Query Service

            :type method: ``str``
            :param method: The HTTP method, for example: GET, POST, and so on.

            :type query: ``str``
            :param query: Elastic search query for LogsignSiem Search Engine.

            :type url_suffix: ``str``
            :param url_suffix: The API endpoint.

            :type grouped_column: ``str``
            :param grouped_column: GroupedColumn (e.g. Source.IP)

            :type criteria: ``str``
            :param criteria: Criteria [value or unique]

            :type time_frame: ``str``
            :param time_frame: TimeFrame [min, hour, day] (e.g 1 day)

            :return: Depends on the resp_type parameter
            :rtype: ``dict`` or ``str`` or ``requests.Response``
        """
        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            params={
                'api_key': self._api_key,
                'query': query,
                'grouped_column': grouped_column,
                'criteria': criteria,
                'time_frame': time_frame
            }
        )

    def test_api(self, method: str, url_suffix: str) -> Any:
        """
            Test API Service

            :type method: ``str``
            :param method: The HTTP method, for example: GET, POST, and so on.

            :type url_suffix: ``str``
            :param url_suffix: The API endpoint.

            :return: Depends on the resp_type parameter
            :rtype: ``dict`` or ``str`` or ``requests.Response``
        """
        return self._http_request(method=method, url_suffix=url_suffix, params={'api_key': self._api_key})


def get_datetime_now(first_fetch_time):
    """
        Get Datetime Now ISO8601 format with UTC

    """
    now = datetime.now() - timedelta(hours=int(first_fetch_time.split()[0]))
    return now.strftime(DATE_FORMAT)


def api_check_command(client: Client) -> str:
    """Tests API connectivity and authentication'

        Returning 'ok' indicates that the integration works like it is supposed to.
        Connection to the service is successful.
        Raises exceptions if something goes wrong.

        :type client: ``Client``
        :param Client: client to use

        :return: 'ok' if test passed, anything else will fail the test.
        :rtype: ``str``
    """
    try:
        client.test_api('GET', URL_SUFFIX['TEST_API'])
    except Exception:
        raise ValueError('Authorization Error: Make sure Logsign Discovery API Key is correctly set')
    return 'ok'


def check_arg(key: str, args: dict[str, Any]) -> Any:
    """
        Check Arg Service

        :type key: ``str``
        :param key: Check arg in dict

        :type args: ``dict``
        :param args: Args dict (e.g {key: value})

        :return: Depends on the key parameter
        :rtype: ``dict`` or ``str`` or ``list``
    """
    tmp = args.get(key, None)
    if not tmp:
        raise ValueError(f"{key} not specified!")
    return tmp


def get_generic_data(data: dict[str, Any], key: str, output_prefix: str) -> CommandResults:
    """
        Get Generic Data Service

        :type data: ``dict``
        :param data: incidents json data

        :type key: ``str``
        :param key: query service type (e.g column, count)

        :type output_prefix: ``str``
        :param output_prefix: output_prefix for HumanCommandResult (e.g Logsign.Incident, Logsign.Count)

        :rtype: ``CommandResults`
        :return CommandResults: use to return results to warroom
    """
    result = {key: check_arg(key, data)}
    return CommandResults(
        outputs_prefix=output_prefix,
        outputs=result,
        raw_response=json.dumps(data)
    )


def fetch_incidents(client: Client, first_fetch: str, max_fetch: int, query: str) -> tuple[dict[str, str], list[dict]]:
    """
        This function is called for fetching incidents.

        :type client: ``Client``
        :param Client: Client object

        :type first_fetch: ``str``
        :param first_fetch: Example: "1 hour"

        :type max_fetch: ``int``
        :param max_fetch: Maximum number of incidents per fetch (Recommended less than 200)

        :type query: ``str``
        :param query: Example: Alert.AlertUID:1 Action.Object:1 ...

        :rtype: ``Tuple[Dict[str, int], List[dict]]``
        :return next_run: This will be last_run in the next fetch-incidents
        :return incidents: Incidents that will be created in Cortex XSOAR
    """
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('last_fetch', None)

    if last_fetch is None:
        last_fetch = datetime.utcnow() - timedelta(hours=int(first_fetch.split()[0]))
    else:
        last_fetch = datetime.strptime(last_fetch, DATE_FORMAT)

    latest_created_time = last_fetch

    data = client.get_incidents(method='GET', last_run=last_fetch, query=query)

    incidents: list[dict[str, Any]] = []
    for incident in data['incidents']:
        # convert the date to ISO8601
        created_at_str = f"{datetime.strptime(incident['Time']['Generated'], LOGSIGN_INC_DATE_FORMAT).isoformat()}Z"
        created_at_dt = datetime.strptime(created_at_str, DATE_FORMAT)

        inc = {
            'name': f"Logsign-{created_at_str}",
            'occured': created_at_str,
            'rawJSON': json.dumps(incident)
        }

        incidents.append(inc)
        latest_created_time = created_at_dt

        if len(incidents) >= max_fetch:
            break

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': datetime.strftime(latest_created_time, DATE_FORMAT)}
    return next_run, incidents


def get_query_command(client: Client, url_suffix: str, args: dict[str, Any]) -> CommandResults:
    """
        This function is called for query commands.

        :type client: ``Client``
        :param Client: Client object

        :type url_suffix: ``str``
        :param url_suffix: The API endpoint.

        :type args: ``dict``
        :param args: Command args

        :rtype: ``CommandResults`
        :return CommandResults: use to return results to warroom
    """
    query = check_arg('query', args)
    grouped_column = check_arg('grouped_column', args)
    criteria = check_arg('criteria', args)
    time_frame = check_arg('time_frame', args)

    response = client.get_query('GET', query, url_suffix, grouped_column, criteria, time_frame)

    result = CommandResults()
    if url_suffix == URL_SUFFIX['GET_COUNT']:
        result = get_generic_data(response, 'count', 'LogsignSiem.Count')
    elif url_suffix == URL_SUFFIX['GET_COLUMN']:
        result = get_generic_data(response, 'columns', 'LogsignSiem.Columns')
    return result


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    command = demisto.command()
    demisto.info(f'[Logsign] Command being called is {command}')

    try:
        params = demisto.params()
        base_url = params.get('url')

        verify_certificate = params.get('insecure', False)
        proxy = params.get('proxy', False)

        first_fetch = params.get('first_fetch')
        first_fetch_time = DEFAULT_FIRST_FETCH if not first_fetch else first_fetch

        api_key = params.get('apikey')
        query = params.get('query', '')

        max_fetch = params.get('max_fetch')
        max_fetch = DEFAULT_FETCH_LIMIT if not params.get('max_fetch') else int(max_fetch)

        client = Client(url=base_url, api_key=api_key, verify=verify_certificate, proxy=proxy)

        args = demisto.args()

        if command == 'fetch-incidents':
            last_run, incidents = fetch_incidents(client, first_fetch_time, max_fetch, query)
            demisto.setLastRun(last_run)
            demisto.incidents(incidents)
        elif command == 'logsign-get-columns-query':
            return_results(get_query_command(client, URL_SUFFIX['GET_COLUMN'], args))
        elif command == 'logsign-get-count-query':
            return_results(get_query_command(client, URL_SUFFIX['GET_COUNT'], args))
        elif command == 'test-module':
            result = api_check_command(client)
            return_results(result)
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
