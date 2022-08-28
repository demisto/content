import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
PRODUCT = 'testing'
VENDOR = 'proofpoint'

RAW_TEST = [
  {
    "id": 1,
    "summary": "Darya RAW",
    "description": "EvilScheme test message",
    "score": 4200,
    "state": "Open",
    "created_at": "2018-05-26T21:07:17Z",
    "event_count": 3,
    "event_sources": [
      "Proofpoint TAP"
    ],
    "users": [
      "nbadguy"
    ],
    "assignee": "Unassigned",
    "team": "Unassigned",
    "hosts": {
      "attacker": [
        "54.214.13.31",
        "http://tapdemo.evilscheme.org/files/313532373336373133382e33.pdf"
      ],
      "forensics": [
        "http://tapdemo.evilscheme.org/files/313532373336373133382e33.pdf",
        "tapdemo.evilscheme.org"
      ]
    },
    "incident_field_values": [
      {
        "name": "Classification",
        "value": "Darya"
      },
      {
        "value": "Spam"
      },
      {
        "name": "Severity",
        "value": "Critical"
      }
    ],
    "events": [
      {
        "id": 3,
        "category": "malware",
        "severity": "Info",
        "source": "Darya",
        "threatname": "Infection.PDF.File.Exploit.CVE-2010-0188_LibTIFF.",
        "classified": False,
        "state": "Linked",
        "description": "Infection.PDF.File.Exploit.CVE-2010-0188_LibTIFF.",
        "attackDirection": "inbound",
        "received": "2018-05-26T21:07:17Z",
        "malwareName": "Infection.PDF.File.Exploit.CVE-2010-0188_LibTIFF."
      },
      {
        "name": "Classification",
        "id": 1,
        "category": "spam",
        "severity": "Critical",
        "source": "Proofpoint TAP",
        "threatname": "Unsolicited Bulk Email",
        "classified": False,
        "state": "Linked",
        "attackDirection": "inbound",
        "received": "2018-05-26T21:07:17Z"
      },
      {
        "id": 2,
        "category": "spam",
        "severity": "Critical",
        "source": "Proofpoint TAP",
        "threatname": "Unsolicited Bulk Email",
        "classified": False,
        "state": "Linked",
        "attackDirection": "inbound",
        "received": "2018-05-26T21:07:17Z"
      }
    ],
    "quarantine_results": [],
    "successful_quarantines": 0,
    "failed_quarantines": 0,
    "pending_quarantines": 0
  },
  {
    "id": 2,
    "summary": "Darya 2",
    "description": "",
    "score": 5200,
    "state": "Open",
    "created_at": "2018-06-01T17:57:09Z",
    "event_count": 2,
    "event_sources": [
      "Abuse Mailbox 1",
      "Proofpoint TAP"
    ],
    "users": ['Darya'],
    "assignee": "Unassigned",
    "team": "Unassigned",
    "hosts": {
      "attacker": [
        "54.214.13.31",
        "http://tapdemo.evilscheme.org/files/313532373837353631342e3137.pdf"
      ],
      "cnc": [
        "54.214.13.31"
      ],
      "url": [
        "http://tapdemo.evilscheme.org/files/313532373837353631342e3137.pdf",
        "https://urldefense.proofpoint.com/v2/url?"
      ],
      "forensics": [
        "http://tapdemo.evilscheme.org/files/313532373837353631342e3137.pdf",
        "tapdemo.evilscheme.org"
      ]
    },
    "incident_field_values": [
      {
        "name": "Attack Vector",
        "value": "Email"
      },
      {
        "name": "Severity",
        "value": "Critical"
      },
      {
        "name": "Classification",
        "value": "Darya 2"
      },
      {
        "value": "Reported Abuse"
      },
      {
        "name": "Abuse Disposition",
        "value": "Malicious"
      }
    ],
    "events": [
      {
        "id": 8,
        "category": "malware",
        "severity": "Info",
        "source": "Darya 2 for test",
        "threatname": "Malicious content dropped during execution",
        "classified": False,
        "state": "Linked",
        "description": "Malicious content dropped during execution",
        "attackDirection": "inbound",
        "received": "2018-06-01T18:02:10Z",
        "malwareName": "Malicious content dropped during execution"
      },
      {
        "name": "Classification",
        "id": 6,
        "category": "malware",
        "severity": "Info",
        "source": "Proofpoint TAP",
        "threatname": "Example signature to fire on TAP demo evilness",
        "classified": False,
        "state": "Linked",
        "description": "Example signature to fire on TAP demo evilness",
        "attackDirection": "inbound",
        "received": "2018-06-01T17:57:10Z",
        "malwareName": "Example signature to fire on TAP demo evilness"
      }
    ],
    "quarantine_results": [
      {
        "alertSource": "Not Available",
        "startTime": "2018-06-01T18:17:43.941Z",
        "endTime": "2018-06-01T18:17:44.001Z",
        "status": "successful",
        "recipientType": "Search",
        "recipient": "jsmith@company.com",
        "messageId": "<20180601175356.GA30914@tapdemo.evilscheme.org>",
        "isRead": "true",
        "wasUndone": "true",
        "details": "Success"
      }
    ],
    "successful_quarantines": 1,
    "failed_quarantines": 0,
    "pending_quarantines": 0
  }
]


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def get_incidents_request(self, query_params):
        """Perform an API request to get incidents from ProofPoint.

        Args:
            query_params(dict): The params of the request

        Returns:
            list. The incidents returned from the API call
        """
        # raw_response = self._http_request(
        #     method='GET',
        #     url_suffix='api/incidents',
        #     params=query_params,
        # )
        raw_response = RAW_TEST
        return raw_response


def test_module(client, first_fetch):
    """Perform API call to check that the API is accessible.

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    query_params = {
        'created_after': first_fetch,
        'state': 'open'
    }

    client.get_incidents_request(query_params)
    return 'ok'


def create_incidents_human_readable(human_readable_message, incidents_list):
    """Creates the human readable entry for incidents

    Args:
        human_readable_message (str): The title of the human readable table
        incidents_list (list): The incidents list to insert to the table

    Returns:
        str. The incidents human readable in markdown format
    """
    human_readable = []
    human_readable_headers = ['ID', 'Created At', 'Type', 'Summary', 'Score', 'Event Count', 'Assignee',
                              'Successful Quarantines', 'Failed Quarantines', 'Pending Quarantines']
    for incident in incidents_list:
        human_readable.append({
            'Created At': incident.get('created_at'),
            'ID': incident.get('id'),
            'Type': incident.get('type'),
            'Summary': incident.get('summary'),
            'Score': incident.get('score'),
            'Event Count': incident.get('event_count'),
            'Assignee': incident.get('assignee'),
            'Successful Quarantines': incident.get('successful_quarantine'),
            'Failed Quarantines': incident.get('failed_quarantines'),
            'Pending Quarantines': incident.get('pending_quarantines')
        })

    return tableToMarkdown(human_readable_message, human_readable, human_readable_headers, removeNull=True)


def list_incidents_command(client, args):
    """ Retrieves incidents from ProofPoint API """
    limit = arg_to_number(args.pop('limit'))

    raw_response = client.get_incidents_request(args)

    incidents_list = raw_response[:limit]
    human_readable = create_incidents_human_readable('List Incidents Results:', incidents_list)

    return incidents_list, human_readable, raw_response


def pass_sources_list_filter(incident, sources_list):
    """Checks whether the event sources of the incident contains at least one of the sources in the sources list.

    Args:
        incident (dict): The incident to check
        sources_list (list): The list of sources from the customer

    Returns:
        bool. Whether the incident has passed the filter or not
    """
    if len(sources_list) == 0:
        return True

    for source in sources_list:
        if source in incident.get("event_sources"):
            return True

    return False


def pass_abuse_disposition_filter(incident, abuse_disposition_values):
    """Checks whether the incident's 'Abuse Disposition' value is in the abuse_disposition_values list.

    Args:
        incident (dict): The incident to check
        abuse_disposition_values (list): The list of relevant values from the customer

    Returns:
        bool. Whether the incident has passed the filter or not
    """
    if len(abuse_disposition_values) == 0:
        return True

    for incident_field in incident.get('incident_field_values', []):
        if incident_field['name'] == 'Abuse Disposition':
            if incident_field['value'] in abuse_disposition_values:
                return True

    return False


def filter_incidents(incidents_list):
    """Filters the incidents list by 'abuse disposition' and 'source list' values

    Args:
        incidents_list (list): The incidents list to filter

    Returns:
        list. The filtered incidents list
    """
    filtered_incidents_list = []
    params = demisto.params()
    sources_list = argToList(params.get('event_sources'))
    abuse_disposition_values = argToList(params.get('abuse_disposition'))

    if not sources_list and not abuse_disposition_values:
        return incidents_list

    for incident in incidents_list:
        if pass_sources_list_filter(incident, sources_list) and pass_abuse_disposition_filter(incident,
                                                                                              abuse_disposition_values):
            filtered_incidents_list.append(incident)

    return filtered_incidents_list


def get_time_delta(fetch_delta):
    """Gets the time delta from a string that is combined with a number and a string of (minute/hour)
    Args:
        fetch_delta(str): The fetch delta param.
    Returns:
        The time delta.
    """
    fetch_delta_split = fetch_delta.strip().split(' ')
    if len(fetch_delta_split) != 2:
        raise Exception(
            'The fetch_delta is invalid. Please make sure to insert both the number and the unit of the fetch delta.')

    unit = fetch_delta_split[1].lower()
    number = int(fetch_delta_split[0])

    if unit not in ['minute', 'minutes',
                    'hour', 'hours',
                    ]:
        raise Exception('The unit of fetch_delta is invalid. Possible values are "minutes" or "hours".')

    if 'hour' in unit:
        time_delta = timedelta(hours=number)  # batch by hours
    else:
        time_delta = timedelta(minutes=number)  # batch by minutes
    return time_delta


def get_new_incidents(client, request_params, last_fetched_id):
    """Perform an API request to get incidents from ProofPoint , filters then according to params, order them and
    return only the new incidents.

    As the api does not return the results in an specific order, we query the api on specific time frames using
    created_before and created_after using the fetch delta parameter.
    Args:
        request_params(dict): The params of the request
        last_fetched_id(int): The ID of the last incident that was fetched in the previous fetch.
    Returns:
        list. The incidents returned from after the necessary actions.
    """
    incidents = client.get_incidents_request(request_params)
    filtered_incidents_list = filter_incidents(incidents)
    ordered_incidents = sorted(filtered_incidents_list, key=lambda k: (k['created_at'], k['id']))
    return list(filter(lambda incident: int(incident.get('id')) > last_fetched_id, ordered_incidents))


def get_incidents_batch_by_time_request(client, params):
    """Perform an API request to get incidents from ProofPoint in batches to prevent a timeout.

    As the api does not return the results in an specific order, we query the api on specific time frames using
    created_before and created_after using the fetch delta parameter.
    Args:
        params(dict): The params of the request

    Returns:
        list. The incidents returned from the API call
    """
    incidents_list = []  # type:list

    fetch_delta = params.get('fetch_delta', '6 hours')
    fetch_limit = arg_to_number(params.get('fetch_limit', '100'))
    last_fetched_id = arg_to_number(params.get('last_fetched_id', '0'))

    current_time = datetime.now()

    time_delta = get_time_delta(fetch_delta)

    created_after = datetime.strptime(params.get('created_after'), TIME_FORMAT)
    created_before = created_after + time_delta

    request_params = {
        'state': params.get('state'),
        'created_after': created_after.isoformat().split('.')[0] + 'Z',
        'created_before': created_before.isoformat().split('.')[0] + 'Z'
    }

    # while loop relevant for fetching old incidents
    while created_before < current_time and len(incidents_list) < fetch_limit:
        demisto.info(
            f"Entered the batch loop , with fetch_limit {fetch_limit} and incidents list "
            f"{[incident.get('id') for incident in incidents_list]} and incident length {len(incidents_list)} "
            f"with created_after {request_params['created_after']} and "
            f"created_before {request_params['created_before']}")

        new_incidents = get_new_incidents(client, request_params, last_fetched_id)
        incidents_list.extend(new_incidents)

        # advancing fetch time by given fetch delta time
        created_after = created_before
        created_before = created_before + time_delta

        # updating params according to the new times
        request_params['created_after'] = created_after.isoformat().split('.')[0] + 'Z'
        request_params['created_before'] = created_before.isoformat().split('.')[0] + 'Z'
        demisto.debug(f"End of the current batch loop with {str(len(incidents_list))} incidents")

    # fetching the last batch when created_before is bigger then current time = fetching new incidents
    if len(incidents_list) < fetch_limit:
        # fetching the last batch
        request_params['created_before'] = current_time.isoformat().split('.')[0] + 'Z'
        new_incidents = get_new_incidents(client, request_params, last_fetched_id)
        incidents_list.extend(new_incidents)

        demisto.info(
            f"Finished the last batch, with fetch_limit {fetch_limit} and incidents list:"
            f" {[incident.get('id') for incident in incidents_list]} and incident length {len(incidents_list)}")

    incidents_list_limit = incidents_list[:fetch_limit]
    return incidents_list_limit


def fetch_events_command(client, first_fetch, last_run, fetch_limit, fetch_delta, incidents_states):
    """
        Fetches incidents from the ProofPoint API.
    """
    last_fetch = last_run.get('last_fetch', {})
    last_fetched_id = last_run.get('last_fetched_incident_id', {})

    for state in incidents_states:
        if not last_fetch.get(state):
            last_fetch[state] = first_fetch
        if not last_fetched_id.get(state):
            last_fetched_id[state] = '0'

    incidents = []
    for state in incidents_states:
        request_params = {
            'created_after': last_fetch[state],
            'last_fetched_id': last_fetched_id[state],
            'fetch_delta': fetch_delta,
            'state': state,
            'fetch_limit': fetch_limit
        }
        id = last_fetched_id[state]
        incidents = get_incidents_batch_by_time_request(client, request_params)

        if incidents:
            id = incidents[-1].get('id')
            last_fetch_time = incidents[-1]['created_at']
            last_fetch[state] = \
                (datetime.strptime(last_fetch_time, TIME_FORMAT) - timedelta(minutes=1)).isoformat().split('.')[0] + 'Z'
            last_fetched_id[state] = id

    demisto.debug(f"End of current fetch function with last_fetch {str(last_fetch)} and last_fetched_id"
                  f" {str(last_fetched_id)}")

    last_run = {
        'last_fetch': last_fetch,
        'last_fetched_incident_id': last_fetched_id
    }

    demisto.info(f'extracted {len(incidents)} incidents')

    return incidents, last_run


def main():  # pragma: no cover
    """main function, parses params and runs command functions
        """
    args = demisto.args()
    command = demisto.command()
    params = demisto.params()

    api_key = params.get('credentials', {}).get('password')
    base_url = demisto.params().get('url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    # How many time before the first fetch to retrieve incidents
    first_fetch, _ = parse_date_range(params.get('first_fetch', '3 days') or '3 days',
                                      date_format=TIME_FORMAT)
    fetch_limit = params.get('fetch_limit', '100')
    fetch_delta = params.get('fetch_delta', '6 hours')
    incidents_states = params.get('states')

    demisto.debug('Command being called is {}'.format(command))

    try:
        headers = {
            'Content-Type': 'application/json',
            'Authorization': api_key
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
        )
        if command == 'test-module':
            return_results(test_module(client, first_fetch))

        elif command in ('proofpoint-trap-get-events', 'fetch-events'):

            if command == 'proofpoint-trap-get-events':
                should_push_events = argToBoolean(args.pop('should_push_events'))
                # events, human_readable, raw_response = list_incidents_command(client, args)
                # results = CommandResults(raw_response=raw_response, readable_output=human_readable)

                prev_last_run = demisto.getLastRun()
                events, last_run = fetch_events_command(
                    client,
                    first_fetch,
                    prev_last_run,
                    fetch_limit,
                    fetch_delta,
                    incidents_states,
                )
                demisto.setLastRun(last_run)
                human_readable = f'{len(events)=}, {last_run=}, {prev_last_run=}'
                results = CommandResults(raw_response=events, readable_output=human_readable)

                return_results(results)

            else:  # command == 'fetch-events':
                should_push_events = True
                last_run = demisto.getLastRun()
                events, last_run = fetch_events_command(
                    client,
                    first_fetch,
                    last_run,
                    fetch_limit,
                    fetch_delta,
                    incidents_states,
                )
                demisto.setLastRun(last_run)

            if should_push_events:
                send_events_to_xsiam(
                    events,
                    VENDOR,
                    PRODUCT
                )

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Error: {e} {traceback.format_exc()}')


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
