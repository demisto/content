import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import requests
import urllib3
from datetime import date

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
INCIDENT_SEVERITY = {
    'unknown': 0,
    'informational': 1,
    'low': 2,
    'medium': 3,
    'high': 4,
    'critical': 5
}

LIMIT_EVENT_ITEMS = 50
MAX_EVENT_ITEMS = 50


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def get_event_types(self, method, etypeurl, params):
        """
        Fetch event types and alias using given parameters
        :param method: requests method to perform the desired action to be performed
        :param etypeurl: event type URL path
        :param params: parameters to be used as part of request
        :return: event types along with alias as a JSON
        """
        eventTypeAlias = None

        payload = {}
        headers = {
            'X-API-KEY': '{}'.format(params['token'])
        }
        url = urljoin(self._base_url, etypeurl)

        response = requests.request(method, url, headers=headers, data=payload)
        try:
            resp = response.json()

            if 'success' in resp.keys() and resp['success'] is True:
                eventTypeAlias = resp['data']
            else:
                demisto.error("Error trying to Fetch EventTypess {}".format(resp))
        except Exception as e:
            demisto.error("Exception with Fetch EventTypes [{}]".format(e))

        return eventTypeAlias

    def get_iocs(self, method, iocurl, params):
        """
        Fetch the IOC's for the given parameters
        :param method: Requests method to be used
        :param iocurl: API URL Suffix to be used
        :param params: parameters to be used as part of request
        :return:indicator details as JSON
        """
        ioc_data = None

        payload = {
            'token': '{}'.format(params['token']),
            'from': int(params['from']),
            'limit': int(params['limit']),
            'start_date': '{}'.format(params['start_date']),
            'end_date': '{}'.format(params['end_date']),
            'type': '{}'.format(params['type']),
            'keyword': '{}'.format(params['keyword'])
        }
        files = []
        headers = {
            "Cookie": "XSRF-TOKEN={}".format(params['token'])
        }
        url = urljoin(self._base_url, iocurl)

        response = requests.request('{}'.format(str(method).upper()), url, headers=headers, data=payload, files=files)
        resp = response.json()

        try:
            if 'count' in resp.keys():
                ioc_data = resp
            else:
                demisto.error("Error trying to Fetch IOC's {}".format(resp))
        except Exception as e:
            demisto.error("[{}] exception seen for response [{}]".format(e, resp))

        return ioc_data

    def get_alerts(self, method, eventurl, params):
        """
        Fetch the Events for the given parameters
        :param method: Requests method to be used
        :param eventurl: API URL Suffix to be used
        :param params: parameters to be used as part of request
        :return: alert details as list
        """

        events_data = None
        payload = json.dumps({
            'from': params['from'],
            'limit': params['limit'],
            'start_date': params['start_date'],
            'end_date': params['end_date'],
            'order_by': params['order_by']
        })
        headers = {
            'X-API-KEY': '{}'.format(params['token']),
            'Content-Type': 'application/json'
        }

        url = urljoin(self._base_url, eventurl)
        response = requests.request('{}'.format(str(method).upper()), url, headers=headers, data=payload)

        try:
            resp = response.json()

            if 'success' in resp.keys() and resp['success'] is True:
                events_data = resp['data']['results']
            else:
                demisto.error("Error trying to Fetch Events {}".format(resp))
        except Exception as e:
            demisto.error("Exception with Fetch Events [{}]".format(e))

        return events_data

    def get_event_details(self, method, eventurl, params, events_data):
        """
        Fetch the Event details for given event ID and Type
        :param method: Requests method to be used
        :param eventurl: API URL Suffix to be used
        :param params: parameters to be used
        :param events_data: Event item details store
        :return:
        """

        payload = json.dumps({
            'from': params['from'],
            'limit': params['limit']
        })
        headers = {
            'X-API-KEY': '{}'.format(params['token']),
            'Content-Type': 'application/json'
        }

        url = urljoin(self._base_url, eventurl)
        response = requests.request('{}'.format(str(method).upper()), url, headers=headers, data=payload)

        resp = {}
        try:
            if response.status_code == 200:
                resp = response.json()
        except Exception as e:
            demisto.error('Exception while fetching the event details {}'.format(e))

        if response.status_code == 200 and 'success' in resp.keys() and resp['success'] is True:
            events_data.extend(resp['events'])
            if resp['total_count'] != len(events_data) and len(events_data) <= MAX_EVENT_ITEMS:
                params['from'] += params['limit']
                time.sleep(0.05)
                self.get_event_details(method, eventurl, params, events_data)
        else:
            demisto.error("Fetch event detail error (code:{}, reason:{})".format(response.status_code, response.reason))


def get_test_response(client, method, token):
    """
    Test the integration state
    :param client: client instance
    :param method: Requests method to be used
    :param token: API access token
    :return: test response
    """
    params = {
        'token': token
    }
    eventtypes_url = r'/api/v2/events/types'
    eventTypes = client.get_event_types(method, eventtypes_url, params)

    if eventTypes is not None:
        return 'ok'
    else:
        demisto.error("Failed to connect")
        return 'fail'


def get_event_types(client, method, token):
    """
    Call the client module to fetch event types using the input parameters
    :param client: instace of client to communicate with server
    :param method: Requests method to be used
    :param token: server access token
    :return: alert event types
    """
    eTypeAlias = {}
    params = {
        'token': token
    }
    eventtypes_url = r'/api/v2/events/types'
    eventTypes = client.get_event_types(method, eventtypes_url, params)

    if eventTypes != None:
        for eachone in eventTypes:
            eTypeAlias[eachone['type']] = eachone['alias']

    return eTypeAlias


def cyble_fetch_iocs(client, method, args):
    """
    Call the client module to fetch IOCs using the input parameters
    :param client: instace of client to communicate with server
    :param method: Requests method to be used
    :param args: parameters for fetching indicators
    :return: indicators from server
    """
    params = {
        'token': args['token'],
        'from': int(args['from']),
        'limit': int(args['limit']),
        'start_date': args['start_date'],
        'end_date': args['end_date'],
        'type': args['type'] if 'type' in args.keys() else "",
        'keyword': args['keyword'] if 'keyword' in args.keys() else ""
    }

    ioc_url = r'/api/iocs'
    result = client.get_iocs(method, ioc_url, params)

    if result is not None:
        return result
    else:
        return 'Failed to Fetch IOCs !!'


def format_incidents(resp, eventTypes):
    """
    Format the incidents to feed into XSOAR
    :param resp: events fetched from the server
    :param eventTypes: event types available
    :return: incidents to feed into XSOAR
    """
    alerts: List[Dict[str, Any]] = []
    try:
        for eachalert in resp['data']:
            for e_type in list(eachalert['alert']['services'].keys()):
                e_id = eachalert['alert']['id']
                e_priority = eachalert['alert']['priority']
                e_created = eachalert['alert']['created_at']
                e_keyword = eachalert['alert']['tag_name']
                e_bucket = eachalert['alert']['bucket']['name']

                alert_details = {
                    "name": "Cyble Intel Alert on {}".format(eventTypes[e_type]),
                    "cybleeventtype": "{}".format(e_type),
                    "severity": INCIDENT_SEVERITY[e_priority.lower()],
                    "occurred": "{}".format(e_created),
                    "cybleeventid": "{}".format(e_id),
                    "cybleeventname": "Incident of {} type".format(eventTypes[e_type]),
                    "cybleeventbucket": "{}".format(e_bucket),
                    "cybleeventkeyword": "{}".format(e_keyword),
                    "cybleeventalias": "{}".format(eventTypes[e_type]),

                }

                alerts.append(alert_details)

        return alerts
    except Exception as e:
        return "Format incident issue"


def cyble_fetch_events(client, method, args):
    """
    Fetch alert details from server for creating incidents in XSOAR
    :param client: instace of client to communicate with server
    :param method: Requests method to be used
    :param args: parameters for fetching event details
    :return: events from the server
    """
    params = {
        'token': args['token'],
        'from': int(args['from']),
        'limit': int(args['limit']),
        'start_date': args['start_date'],
        'end_date': args['end_date'],
        'order_by': args['order_by']
    }

    events_url = r'/api/v2/events/all'
    result = client.get_alerts(method, events_url, params)

    incidents: List[Dict[str, Any]] = []
    if result is not None:
        eventTypes = get_event_types(client, "GET", args['token'])
        incidents = format_incidents(result, eventTypes)

    return incidents


def fetch_alert_details(client, args):
    """
    Fetch alert details using the arguments from server
    :param client: instace of client to communicate with server
    :param args: arguments for fetching alert details
    :return: alert details
    """
    fetch_from = 0
    eventtype = args.get('event_type', None)
    eventid = args.get('event_id', None)
    if not eventtype:
        raise ValueError('Event Type not specified')
    if not eventid:
        raise ValueError('Event ID not specified')
    events_url = r'/api/v2/events/{}/{}'.format(eventtype, eventid)
    results = []
    params = {
        'token': args.get('token', None),
        'from': fetch_from,
        'limit': LIMIT_EVENT_ITEMS
    }
    client.get_event_details("POST", events_url, params, results)

    if results:
        return results
    else:
        demisto.error('Fetch event details for {} with ID {}'.format(eventtype, eventid))
        return []


def fetch_incidents(client, method, token, maxResults):
    """
    Fetch alert details from server for creating incidents in XSOAR
    :param client: instace of client to communicate with server
    :param method: Requests method to be used
    :param token: server access token 
    :param maxResults: limit for single fetch from server
    :return: incidents from server
    """""
    last_run = demisto.getLastRun()

    if 'total_alert_count' not in last_run.keys():
        last_run['total_alert_count'] = 0
    if 'fetched_alert_count' not in last_run.keys():
        last_run['fetched_alert_count'] = 0
    if 'event_pull_start_date' not in last_run.keys():
        last_run['event_pull_start_date'] = date.today().strftime("%Y/%m/%d")

    params = {
        'token': token,
        'from': int(last_run['fetched_alert_count']),
        'limit': int(MAX_EVENT_ITEMS) if maxResults > 50 else int(maxResults),
        'start_date': last_run['event_pull_start_date'],
        'end_date': date.today().strftime("%Y/%m/%d"),
        'order_by': 'Ascending'
    }

    events_url = r'/api/v2/events/all'
    result = client.get_alerts(method, events_url, params)

    incidents: List[Dict[str, Any]] = []
    if result is not None:
        last_run['total_alert_count'] = result['total_count']
        last_run['fetched_alert_count'] += len(result['data'])
        eventTypes = get_event_types(client, "GET", token)
        events = format_incidents(result, eventTypes)

        try:
            for eachinci in events:
                inci = {
                    'name': eachinci['name'],
                    'severity': eachinci['severity'],
                    'occurred': eachinci['occurred'],
                    'rawJSON': json.dumps(eachinci)
                }
                incidents.append(inci)

        except Exception as e:
            demisto.error("Error formating incidents, {}".format(e))

        if last_run['event_pull_start_date'] < date.today().strftime("%Y/%m/%d"):
            last_run['event_pull_start_date'] = date.today().strftime("%Y/%m/%d")
            last_run['total_alert_count'] = 0
            last_run['fetched_alert_count'] = 0
        demisto.setLastRun(last_run)

    return incidents


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """

    # get the service API url
    base_url = demisto.params().get('url')
    token = demisto.params().get('token')

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)

        args = demisto.args()
        args['token'] = token

        if demisto.command() == 'test-module':
            resp = get_test_response(client, 'GET', token)
            # request was succesful
            return_results(resp)

        elif demisto.command() == 'fetch-incidents':
            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_results = arg_to_number(
                arg=demisto.params().get('max_fetch'),
                arg_name='max_fetch',
                required=True
            )

            # This is the call made when cyble-fetch-events command.
            incidents = fetch_incidents(
                client=client,
                method='POST',
                token=token,
                maxResults=max_results
            )
            demisto.incidents(incidents)

        elif demisto.command() == 'cyble-vision-fetch-iocs':
            # This is the call made when cyble-fetch-iocs command.
            if 'start_date' not in args.keys():
                args['start_date'] = datetime.today().strftime('%Y-%m-%d')
            if 'end_date' not in args.keys():
                args['end_date'] = datetime.today().strftime('%Y-%m-%d')

            if args['token'] is not None:
                command_results = CommandResults(
                    outputs_prefix='CybleEvents.IoCs',
                    outputs_key_field='data',
                    outputs=cyble_fetch_iocs(client, 'POST', args)
                )
                return_results(command_results)
            else:
                demisto.error("Error fetching Threat Indicators.")

        elif demisto.command() == 'cyble-vision-fetch-events':
            # This is the call made when cyble-fetch-events command.
            args['order_by'] = str(args['order_by']).title()
            if 'start_date' not in args.keys():
                args['start_date'] = datetime.today().strftime('%Y/%m/%d')
            if 'end_date' not in args.keys():
                args['end_date'] = datetime.today().strftime('%Y/%m/%d')

            if args['token'] is not None:
                command_results = CommandResults(
                    outputs_prefix='CybleEvents.Events',
                    outputs_key_field=['cybleeventid', 'cybleeventtype'],
                    outputs=cyble_fetch_events(client, 'POST', args)
                )
                return_results(command_results)
            else:
                demisto.error("Error fetching Incident alerts.")

        elif demisto.command() == "cyble-vision-fetch-event-detail":
            # Fetch event detail.
            if args['token'] is not None:
                command_results = CommandResults(
                    outputs_prefix='CybleEvents.Events',
                    outputs_key_field='Details',
                    outputs=fetch_alert_details(client, args)
                )
                return_results(command_results)
            else:
                demisto.error("Error fetching Incident alert details.")

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()