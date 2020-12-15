# import demistomock as demisto
from CommonServerPython import *
from datetime import datetime

import urllib3
import dateparser
import traceback
from typing import Any, Dict, List, Optional, Tuple, cast, Iterable

urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_EVENTS_TO_FETCH = 50
COGNNI_SEVERITIES = ['Low', 'Medium', 'High', 'Critical']
SUNDAY_ISO_WEEKDAY = 7

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def fetch_key(self, api_key: str) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=f"/api/v1/login/key/{api_key}"
        )

    def graphql(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not variables:
            variables = {}

        graphql_operation = {
            "query": query,
            "variables": variables
        }

        res = self._http_request(
            method='POST',
            url_suffix='/intelligence/data/graphql',
            json_data=graphql_operation
        )
        return res['data']

    def ping(self) -> Dict[str, Any]:
        query = "{ping}"

        return self.graphql(
            query=query
        )

    def fetch_events(self, min_severity: int, start_time: str, events_limit: int, offset: int) -> List[Dict[str, Any]]:
        query = """
            query($severityValue:String!, $pagination:Pagination) {
              events(
                filter: {
                  coordinates: [
                    {
                      x: {
                        type: None,
                        value: "none"
                      },
                      y: {
                        type: Severity,
                        value: $severityValue
                      },
                      z: {
                        type:Week,
                        values:[\"""" + start_time + """\"]
                      }
                    }
                ]
                  pagination: $pagination
                }
            ) {
                eventId: id
                description
                severity
                sourceApplication
                date
                items {
                    itemId: id
                    externalId
                    type
                    name
                    clusterUID
                    data
                    createdAt
                    labels {
                        name
                    }
                }
                insights {
                    name
                }
            }
        }
        """

        variables = {
            "pagination": {
                "limit": events_limit,
                "offset": offset,
                "direction": "Ascend"
            },
            "severityValue": str(min_severity),
        }
        res = self.graphql(
            query=query,
            variables=variables
        )
        return res['events']

    def get_event(self, event_id: str) -> Dict[str, Any]:
        query = """
            query ($event_id: ID!) {
                event(id: $event_id){
                    id
                    description
                    sourceApplication
                    date
                }
            }
        """

        variables = {
            "event_id": event_id
        }

        res = self.graphql(
            query=query,
            variables=variables
        )
        return res['event']

    def fetch_insights(self, min_severity: int) -> List[Dict[str, Any]]:
        query = """
             query ($min_severity: Int) {
                 insights(minSeverity: $min_severity){
                     id
                     description
                     name
                     severity
                 }
             }
         """

        variables = {
            "min_severity": int(min_severity)
        }

        res = self.graphql(
            query=query,
            variables=variables
        )
        return res['insights']

    def get_insight(self, insight_id: str) -> Dict[str, Any]:
        query = """
            query ($insight_id: ID!) {
              insight(id: $insight_id) {
                  id
                  name
                  description
                  severity
              }
            }
        """

        variables = {
            "insight_id": insight_id
        }

        res = self.graphql(
            query=query,
            variables=variables
        )
        return res['insight']


''' HELPER FUNCTIONS '''


def convert_to_demisto_severity(severity: str) -> int:
    """Maps Cognni severity to Cortex XSOAR severity

    Converts the Cognni alert severity level ('Low', 'Medium',
    'High', 'Critical') to Cortex XSOAR incident severity (1 to 4)
    for mapping.

    :type severity: ``str``
    :param severity: severity as returned from the Cognni API (str)

    :return: Cortex XSOAR Severity (1 to 4)
    :rtype: ``int``
    """
    return {
        'Low': 1,  # low severity
        'Medium': 2,  # medium severity
        'High': 3,  # high severity
        'Critical': 4  # critical severity
    }[severity]


def convert_to_demisto_severity_int(severity: int) -> int:
    """Maps Cognni severity to Cortex XSOAR severity

    Converts the Cognni alert severity level ('Low', 'Medium',
    'High', 'Critical') to Cortex XSOAR incident severity (1 to 4)
    for mapping.

    :type severity: ``str``
    :param severity: severity as returned from the Cognni API (str)

    :return: Cortex XSOAR Severity (1 to 4)
    :rtype: ``int``
    """

    return severity


def arg_to_int(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:
    """Converts an XSOAR argument to a Python int

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` type. It will throw a ValueError
    if the input is invalid. If the input is None, it will throw a ValueError
    if required is ``True``, or ``None`` if required is ``False.

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :return:
        returns an ``int`` if arg can be converted
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None
    if isinstance(arg, str):
        if arg.isdigit():
            return int(arg)
        raise ValueError(f'Invalid number: "{arg_name}"="{arg}"')
    if isinstance(arg, int):
        return arg
    raise ValueError(f'Invalid number: "{arg_name}"')


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:
    """Converts an XSOAR argument to a timestamp (seconds from epoch)

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` containing a timestamp (seconds
    since epoch). It will throw a ValueError if the input is invalid.
    If the input is None, it will throw a ValueError if required is ``True``,
    or ``None`` if required is ``False.

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :return:
        returns an ``int`` containing a timestamp (seconds from epoch) if conversion works
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None

    if isinstance(arg, str) and arg.isdigit():
        return int(arg)
    if isinstance(arg, str):
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
        if date is None:
            raise ValueError(f'Invalid date: {arg_name}')

        return int(date.timestamp())
    if isinstance(arg, (int, float)):
        return int(arg)
    raise ValueError(f'Invalid date: "{arg_name}"')


def flatten_event_file_items(event: Dict[str, Any]):
    if not event or not event['items']:
        return []

    return list(map(lambda item: {
        "eventId": event.get('eventId'),
        "fileName": item.get('name'),
        "fileId": item.get('itemId'),
        "name": item.get('name'),
        "eventType": item.get('type'),
        "description": event.get('description'),
        "date": event.get('date'),
        "severity": event.get('severity'),
        "sourceApplication": event.get('sourceApplication')
    }, event['items']))


def convert_file_event_to_incident(file_event: Dict[str, Any]):
    return {
        'name': file_event.get('name'),
        'details': file_event['description'],
        'occurred': file_event.get('date'),
        'rawJSON': json.dumps(file_event),
        'severity': convert_to_demisto_severity_int(file_event.get('severity', 1)),
    }


def convert_events_to_incidents(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not events:
        return []

    file_events: List[Dict[str, Any]] = sum(map(flatten_event_file_items, events), [])

    incidents = list(map(convert_file_event_to_incident, file_events))

    return incidents


def find_latest_event(events: Iterable[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    last_date = 0
    latest_event = None

    for event in events:
        event_date = date_to_timestamp(
            date_str_or_dt=event.get('date', ''),
            date_format='%Y-%m-%dT%H:%M:%S.000Z')
        if last_date < event_date:
            last_date = event_date
            latest_event = event

    return latest_event


''' COMMAND FUNCTIONS '''


def test_module(client: Client, api_key: str, first_fetch:str) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param client: Cognni client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    try:
        answer = ''
        fetch_key_res = client.fetch_key(api_key)
    except ValueError:
        answer += 'The api key is invalid'
    try:
        datetime.datetime.strptime(first_fetch, '%Y-%m-%d')
    except ValueError:
        answer += 'Incorrect first fetch time format, should be YYYY-MM-DD'

    if not answer:
        return 'ok'
    else:
        return answer


def fetch_incidents(client: Client, last_run: Dict[str, int],
                    first_fetch_time: Optional[int],
                    events_limit: int,
                    min_severity: int
                    ) -> Tuple[Dict[str, int], List[dict]]:
    """This function retrieves new alerts every interval (default is 1 minute).

    This function has to implement the logic of making sure that incidents are
    fetched only once and no incidents are missed. By default it's invoked by
    XSOAR every minute. It will use last_run to save the timestamp of the last
    incident it processed. If last_run is not provided, it should use the
    integration parameter first_fetch_time to determine when to start fetching
    the first time.

    :param events_limit:
    :type client: ``Client``
    :param client: Cognni client to use

    :type last_run: ``Optional[Dict[str, int]]``
    :param last_run:
        A dict with a key containing the latest incident created time we got
        from last fetch

    :type first_fetch_time: ``Optional[int]``
    :param first_fetch_time:
        If last_run is None (first time we are fetching), it contains
        the timestamp in milliseconds on when to start fetching incidents

    :type min_severity: ``str``
    :param min_severity:
        minimum severity of the alert to search for.
        Options are: "Low", "Medium", "High", "Critical"

    :return:
        A tuple containing two elements:
            next_run (``Dict[str, int]``): Contains the timestamp that will be
                    used in ``last_run`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR

    :rtype: ``Tuple[Dict[str, int], List[dict]]``
    """

    last_fetch = last_run.get('last_fetch', None)
    is_initial_run = last_run.get('is_initial_run', True)
    offset = last_run.get('offset')
    if last_fetch is None:
        last_fetch = first_fetch_time
    else:
        last_fetch = int(last_fetch)

    latest_created_time = cast(int, last_fetch)

    if offset is None or (
        not is_initial_run
            and datetime.utcnow().isoweekday() == SUNDAY_ISO_WEEKDAY
            and datetime.utcfromtimestamp(latest_created_time).isoweekday() != SUNDAY_ISO_WEEKDAY):
        offset = 0

    events = client.fetch_events(
        events_limit=events_limit,
        offset=offset,
        start_time=timestamp_to_datestring(timestamp=latest_created_time * 1000, is_utc=True),
        min_severity=min_severity
    )

    if not events:
        next_run = {'last_fetch': latest_created_time, 'offset': offset, 'is_initial_run': False}
        return next_run, list()

    latest_event = find_latest_event(events)
    if latest_event:
        latest_created_time = int(date_to_timestamp(
            date_str_or_dt=latest_event.get('date', latest_created_time),
            date_format='%Y-%m-%dT%H:%M:%S.000Z'
        ) / 1000)

    incidents = convert_events_to_incidents(events)

    next_run = {'last_fetch': latest_created_time,
                'offset': offset + len(events),
                'is_initial_run': is_initial_run}

    return next_run, incidents


def get_event_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """cognni-get-event command: Returns a Cognni event

    :type client: ``Client``
    :param client: Cognni client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['event_id']`` alert ID to return

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains an alert

    :rtype: ``CommandResults``
    """

    event_id = args.get('event_id', None)
    if not event_id:
        raise ValueError('event_id not specified')

    event = client.get_event(event_id=event_id)
    readable_output = tableToMarkdown(f'Cognni event {event_id}', event)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Cognni.event',
        outputs_key_field='id',
        outputs=event
    )


def fetch_insights_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    min_severity = int(args.get('min_severity', 2))

    insights = client.fetch_insights(min_severity=min_severity)

    readable_output = tableToMarkdown(f'Cognni {len(insights)} insights', insights)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Cognni.insights',
        outputs_key_field='id',
        outputs=insights
    )


def get_insight_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """cognni-get-insight command: Returns a Cognni event

    :type client: ``Client``
    :param client: Cognni client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['event_id']`` alert ID to return

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains an alert

    :rtype: ``CommandResults``
    """

    insight_id = args.get('insight_id', None)
    if not insight_id:
        raise ValueError('insight_id not specified')

    insight = client.get_insight(insight_id=insight_id)

    readable_output = tableToMarkdown(f'Cognni event {insight_id}', insight)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Cognni.insight',
        outputs_key_field='id',
        outputs=insight
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get('apikey')

    # get the service API url
    base_url = demisto.params()['url']

    verify_certificate = not demisto.params().get('insecure', False)

    first_fetch_time = arg_to_timestamp(
        arg=demisto.params().get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    assert isinstance(first_fetch_time, int)
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, api_key, first_fetch_time)
            return_results(result)

        else:
            fetch_key_res = client.fetch_key(api_key)
            access_token = fetch_key_res['token']

            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json',
            }
            client = Client(
                base_url=base_url,
                verify=verify_certificate,
                headers=headers,
                proxy=proxy)

            if demisto.command() == 'fetch-incidents':
                min_severity = demisto.params().get('min_severity', None)

                max_fetch = arg_to_int(
                    arg=demisto.params().get('max_fetch'),
                    arg_name='max_fetch',
                    required=False
                )
                if not max_fetch or max_fetch > MAX_EVENTS_TO_FETCH:
                    max_fetch = MAX_EVENTS_TO_FETCH

                next_run, incidents = fetch_incidents(
                    client=client,
                    events_limit=max_fetch,
                    last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                    first_fetch_time=first_fetch_time,
                    min_severity=convert_to_demisto_severity(min_severity)
                )
                demisto.setLastRun(next_run)
                demisto.incidents(incidents)

            elif demisto.command() == 'cognni-get-event':
                return_results(get_event_command(client, demisto.args()))

            elif demisto.command() == 'cognni-fetch-insights':
                return_results(fetch_insights_command(client, demisto.args()))

            elif demisto.command() == 'cognni-get-insight':
                return_results(get_insight_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
