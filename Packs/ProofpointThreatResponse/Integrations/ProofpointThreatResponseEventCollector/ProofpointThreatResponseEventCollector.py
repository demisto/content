import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import copy
from datetime import timedelta

# Disable insecure warnings
import urllib3

urllib3.disable_warnings()

TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
PRODUCT = 'threat_response'
VENDOR = 'proofpoint'


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


def find_and_remove_large_entry(event):
    """
        Finds and removes all large size values.
    """
    keys_to_remove = []

    for key, value in list(event.items()):
        if isinstance(value, dict):
            find_and_remove_large_entry(value)
        elif isinstance(value, str) and sys.getsizeof(value) > XSIAM_EVENT_CHUNK_SIZE_LIMIT:
            demisto.debug(f'Found key {key} with value exceeding chunk size limit, its size is {sys.getsizeof(value)}')
            keys_to_remove.append(key)
        else:
            demisto.debug('Value is not dict nor str, trying to convert')
            value_str = str(value)
            if sys.getsizeof(value_str) > XSIAM_EVENT_CHUNK_SIZE_LIMIT:
                keys_to_remove.append(key)

    for key in keys_to_remove:
        demisto.info(f'Replacing {key} with None as its value exceeded chunk size limit')
        event[key] = ""


def remove_large_events(events):
    """
        Removing keys with large values from events.
    """
    for event in events:
        event_str = json.dumps(event)
        if sys.getsizeof(event_str) > XSIAM_EVENT_CHUNK_SIZE_LIMIT:
            demisto.debug('found event with value larger than allowed')
            find_and_remove_large_entry(event)


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


def list_incidents_command(client, args):
    """ Retrieves incidents from ProofPoint API """
    limit = arg_to_number(args.pop('limit'))

    raw_response = client.get_incidents_request(args)

    incidents_list = raw_response[:limit]
    events = get_events_from_incidents(incidents_list)
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


def get_incidents_per_state(client, params):
    """Perform an API request to get incidents from ProofPoint by state.

    As the api does not return the results in an specific order, we query the api on specific time frames using
    created_before and created_after.
    Args:
        params(dict): The params of the request

    Returns:
        list. The incidents returned from the API call
    """

    fetch_limit = arg_to_number(params.get('fetch_limit', '100'))
    last_fetched_id = arg_to_number(params.get('last_fetched_id', '0'))

    current_time = datetime.now()

    created_after = datetime.strptime(params.get('created_after'), TIME_FORMAT)

    request_params = {
        'state': params.get('state'),
        'created_after': created_after.isoformat().split('.')[0] + 'Z',
        'created_before': current_time.isoformat().split('.')[0] + 'Z'
    }

    demisto.debug(f"Fetching incidents, with fetch_limit {fetch_limit}"
                  f"with created_after {request_params['created_after']} and"
                  f"created_before {request_params['created_before']}")

    incidents_list = get_new_incidents(client, request_params, last_fetched_id)

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
        demisto.debug(f"Fetching incidents for state {state}")
        request_params = {
            'created_after': last_fetch[state],
            'last_fetched_id': last_fetched_id[state],
            'fetch_delta': fetch_delta,
            'state': state,
            'fetch_limit': fetch_limit
        }
        id = last_fetched_id[state]
        incidents_list = get_incidents_per_state(client, request_params)
        incidents.extend(incidents_list)

        if incidents:
            demisto.debug(f"found {len(incidents)} incidents")
            id = incidents[-1].get('id')
            last_fetch_time = incidents[-1]['created_at']
            last_fetch[state] = \
                (datetime.strptime(last_fetch_time, TIME_FORMAT) - timedelta(minutes=1)).isoformat().split('.')[0] + 'Z'
            last_fetched_id[state] = id
        else:
            demisto.debug(f"No incidents were fetched, setting next run for state {state} to be now.")
            last_fetch[state] = (datetime.now() - timedelta(minutes=2)).isoformat().split('.')[0] + 'Z'

    demisto.debug(f"End of current fetch function with last_fetch {str(last_fetch)} and last_fetched_id"
                  f" {str(last_fetched_id)}")

    last_run = {
        'last_fetch': last_fetch,
        'last_fetched_incident_id': last_fetched_id
    }

    demisto.debug(f'Fetched {len(incidents)} events')

    events = get_events_from_incidents(incidents)
    demisto.debug("Removing all large size values from events")
    remove_large_events(events)
    demisto.debug("Finished removing all large size values from events")

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

        elif command == 'proofpoint-trap-get-events':
            should_push_events = args.pop('should_push_events')
            events, human_readable, raw_response = list_incidents_command(client, args)
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
            events, last_run = fetch_events_command(
                client,
                first_fetch,
                last_run,
                fetch_limit,
                fetch_delta,
                incidents_states,
            )

            send_events_to_xsiam(
                events,
                VENDOR,
                PRODUCT
            )
            demisto.setLastRun(last_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
