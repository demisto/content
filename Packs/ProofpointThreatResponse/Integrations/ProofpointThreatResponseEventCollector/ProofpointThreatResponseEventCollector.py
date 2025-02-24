import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import copy
from datetime import timedelta, datetime, timezone

# Disable insecure warnings
import urllib3

urllib3.disable_warnings()

TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
PRODUCT = 'threat_response'
VENDOR = 'proofpoint'
FIRST_ID = '0'
LOOKBACK_OPTIONS = ['1 day', '2 days', '3 days']


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any logic.
    Should only do requests and return data.
    """

    def get_incidents_request(self, query_params):
        """Perform an API request to get incidents from ProofPoint.

        Args:
            query_params(dict): The params of the request

        Returns:
            list. The incidents returned from the API call
        """
        raw_response = self._http_request(
            method='GET',
            url_suffix='api/incidents',
            params=query_params,
        )
        demisto.debug(f"######## got from api {raw_response}")
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
            'State': incident.get('state'),
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


def list_incidents_command(client, args, look_back):
    """ Retrieves incidents from ProofPoint API """
    limit = arg_to_number(args.pop('limit'))
    
    if 'created_after' not in args:
        current = datetime.strptime(datetime.now(timezone.utc).strftime(TIME_FORMAT), TIME_FORMAT).replace(tzinfo=timezone.utc)
        args['created_after'] = (current-get_lookback_delta(look_back)).strftime(TIME_FORMAT)
        args["created_before"] = current.strftime(TIME_FORMAT)
    
    raw_response = client.get_incidents_request(args)

    incidents_list = raw_response[:limit]
    events = get_events_from_incidents(incidents_list)
    demisto.debug(f"########## got {len(events)} from incidents")
    human_readable = create_incidents_human_readable('List Incidents Results:', events)

    return events, human_readable, raw_response


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

    return any(source in incident.get('event_sources') for source in sources_list)


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
        if incident_field['name'] == 'Abuse Disposition' and incident_field['value'] in abuse_disposition_values:
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
    while created_before < current_time and len(incidents_list) < fetch_limit:  # type: ignore[operator]
        demisto.info(
            f"Entered the batch loop , with fetch_limit {fetch_limit} and events list "
            f"{[incident.get('id') for incident in incidents_list]} and event length {len(incidents_list)} "
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
        
        demisto.debug(f"End of the current batch loop with {str(len(incidents_list))} events")
        
    # fetching the last batch when created_before is bigger then current time = fetching new events
    if len(incidents_list) < fetch_limit:  # type: ignore[operator]
        # fetching the last batch
        request_params['created_before'] = current_time.isoformat().split('.')[0] + 'Z'
        new_incidents = get_new_incidents(client, request_params, last_fetched_id)
        incidents_list.extend(new_incidents)

        demisto.debug(
            f"Finished the last batch, with fetch_limit {fetch_limit} and events list:"
            f" {[incident.get('id') for incident in incidents_list]} and event length {len(incidents_list)}")

    incidents_list_limit = incidents_list[:fetch_limit]
    return incidents_list_limit


def get_lookback_delta(look_back):
    if look_back not in LOOKBACK_OPTIONS:
        raise DemistoException(f'Maximum lookback should be one of the following: {LOOKBACK_OPTIONS}')
    lst = look_back.split(' ')
    return timedelta(days=int(lst[0]))


def fetch_events_command(client, first_fetch, last_run, fetch_limit, fetch_delta, incidents_states, look_back):
    """
        Fetches incidents from the ProofPoint API.
    """
    last_fetch = last_run.get('last_fetch', {})
    last_fetched_id = last_run.get('last_fetched_incident_id', {})
    current_ts = datetime.now(timezone.utc).strftime(TIME_FORMAT)
    look_back_delta = get_lookback_delta(look_back)

    for state in incidents_states:
        if not last_fetch.get(state):
            last_fetch[state] = first_fetch
        if not last_fetched_id.get(state):
            last_fetched_id[state] = FIRST_ID
        
        utc_str_current = datetime.strptime(current_ts, TIME_FORMAT).replace(tzinfo=timezone.utc)
        utc_str_last_fetch = datetime.strptime(last_fetch[state], TIME_FORMAT).replace(tzinfo=timezone.utc)
        if utc_str_current - utc_str_last_fetch > look_back_delta:
            last_fetch[state] = (utc_str_current - look_back_delta).strftime(TIME_FORMAT)
            demisto.debug(f'last_fetch of state {state} is older than 3 days, setting last_fetch to {utc_str_current}',
                          f'- {look_back_delta} = {utc_str_current - look_back_delta}')

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
        incidents_list = get_incidents_batch_by_time_request(client, request_params)
        incidents.extend(incidents_list)

        if incidents_list:
            id = incidents_list[-1].get('id')
            last_fetch_time = incidents_list[-1]['created_at']
            last_fetch[state] = \
                (datetime.strptime(last_fetch_time, TIME_FORMAT) - timedelta(minutes=1)).isoformat().split('.')[0] + 'Z'
            last_fetched_id[state] = id

    demisto.debug(f"End of current fetch function with last_fetch {str(last_fetch)} and last_fetched_id"
                  f" {str(last_fetched_id)}")

    demisto.debug(f'Fetched {len(incidents)} events')
    events = get_events_from_incidents(incidents)
    
    last_run = {
        'last_fetch': last_fetch,
        'last_fetched_incident_id': last_fetched_id
    }
    
    return events, last_run


def get_events_from_incidents(incidents):
    """
    Parses events from incidents.
    Each incident contains list of events:
    {'id':1,
    'updated_at': '01-01-2020',
    'events': [first_event_data, second_event_data, ...]
    'additional_fields': ...
    }

    The function parses the data in the following way:
    {'id':1,
    'updated_at': '01-01-2020',
    'event': first_event_data
    'additional_fields': ...
    },
    {'id':1,
    'updated_at': '01-01-2020',
    'events': second_event_data
    'additional_fields': ...
    }
    ....

    :param incidents: list of incidents that contains events.
    :return: parsed events.
    """
    fetched_events = []
    for incident in incidents:
        if events := incident.get('events'):
            for event in events:
                new_incident = copy.deepcopy(incident)
                del new_incident['events']
                new_incident['event'] = event
                fetched_events.append(new_incident)
        else:
            del incident['events']
            incident['event'] = {}
            fetched_events.append(incident)
    return fetched_events


def main():  # pragma: no cover
    """main function, parses params and runs command functions
        """
    args = demisto.args()
    command = demisto.command()
    params = demisto.params()

    api_key = params.get('credentials', {}).get('password')
    base_url = params.get('url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    # How many time before the first fetch to retrieve incidents
    first_fetch, _ = parse_date_range(params.get('first_fetch', '3 days') or '3 days',
                                      date_format=TIME_FORMAT)
    fetch_limit = params.get('fetch_limit', '100')
    fetch_delta = params.get('fetch_delta', '6 hours')
    incidents_states = argToList(params.get('states', ['new', 'open', 'assigned', 'closed', 'ignored']))
    look_back = params.get('look_back', '1 day')
    demisto.debug(f'Command being called is {command}')

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

        elif command == 'proofpoint-trap-get-events':
            should_push_events = args.pop('should_push_events')
            events, human_readable, raw_response = list_incidents_command(client, args, look_back)
            results = CommandResults(raw_response=raw_response, readable_output=human_readable)
            return_results(results)
            if argToBoolean(should_push_events):
                send_events_to_xsiam(
                    events,
                    VENDOR,
                    PRODUCT
                )

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            demisto.debug(f'last_run before fetch_events_command {last_run=}')
            events, last_run = fetch_events_command(
                client,
                first_fetch,
                last_run,
                fetch_limit,
                fetch_delta,
                incidents_states,
                look_back
            )

            send_events_to_xsiam(
                events,
                VENDOR,
                PRODUCT
            )
            demisto.debug(f'Fetched event ids: {[event.get("id") for event in events]}')
            demisto.debug(f'last_run after fetch_events_command {last_run=}')
            demisto.setLastRun(last_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
