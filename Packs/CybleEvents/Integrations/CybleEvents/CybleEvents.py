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
        event_type_alias = None

        payload: Dict[str, Any] = {}
        headers = {
            'X-API-KEY': '{}'.format(params.get('token', ''))
        }
        url = urljoin(self._base_url, etypeurl)

        response = requests.request(method, url, headers=headers, data=payload)
        try:
            resp = response.json()

            if resp.get('success') or False:
                event_type_alias = resp['data']
            else:
                demisto.error("Error trying to Fetch EventTypess {}".format(resp))
        except Exception as e:
            demisto.error("Exception with Fetch EventTypes [{}]".format(e))
            raise e

        return event_type_alias

    def get_iocs(self, method, iocurl, params):
        """
        Fetch the IOC's for the given parameters
        :param method: Requests method to be used
        :param iocurl: API URL Suffix to be used
        :param params: parameters to be used as part of request
        :return:indicator details as JSON
        """
        ioc_data = {}
        token = params.get('token', '')
        payload = {
            'token': '{}'.format(token),
            'from': arg_to_number(params.get('from', '0')),
            'limit': arg_to_number(params.get('limit', '50')),
            'start_date': '{}'.format(params.get('start_date')),
            'end_date': '{}'.format(params.get('end_date')),
            'type': '{}'.format(params.get('type')),
            'keyword': '{}'.format(params.get('keyword'))
        }
        files: List[Any] = []
        headers = {
            "Cookie": "XSRF-TOKEN={}".format(token)
        }
        url = urljoin(self._base_url, iocurl)

        response = requests.request('{}'.format(str(method).upper()), url, headers=headers, data=payload, files=files)

        try:
            resp = response.json()
            if resp.get('count'):
                ioc_data = resp
            else:
                ioc_data = {"error": "Failed to Fetch Taxiis !!"}
                demisto.error("Error trying to Fetch IOC's {}".format(resp))
        except Exception as e:
            demisto.error("Error: [{}] for response [{}]".format(e, resp))
            raise e

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
            'from': params.get('from'),
            'limit': params.get('limit', '50'),
            'start_date': params.get('start_date'),
            'end_date': params.get('end_date'),
            'order_by': params.get('order_by')
        })
        headers = {
            'X-API-KEY': '{}'.format(params.get('token')),
            'Content-Type': 'application/json'
        }

        url = urljoin(self._base_url, eventurl)
        response = requests.request('{}'.format(str(method).upper()), url, headers=headers, data=payload)

        try:
            resp = response.json()

            if 'success' in resp.keys() and (resp.get('success') or False):
                events_data = resp.get('data', {}).get('results')
            else:
                demisto.error("Error trying to Fetch Events {}".format(resp))
        except Exception as e:
            demisto.error("Exception with Fetch Events [{}]".format(e))
            raise e

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
            'from': params.get('from'),
            'limit': params.get('limit', '50')
        })
        headers = {
            'X-API-KEY': '{}'.format(params.get('token')),
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

        if response.status_code == 200 and (resp.get('success') or False):
            events_data.extend(resp.get('events', []))
            if resp.get('total_count') != len(events_data) and len(events_data) <= MAX_EVENT_ITEMS:
                params['from'] += params.get('limit', '50')
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

    if eventTypes:
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

    if eventTypes:
        for eachone in eventTypes:
            eTypeAlias[eachone['type']] = eachone.get('alias')

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
        'token': args.get('token', ''),
        'from': arg_to_number(args.get('from')),
        'limit': arg_to_number(args.get('limit', '50')),
        'start_date': args.get('start_date'),
        'end_date': args.get('end_date'),
        'type': args.get('type') or '',
        'keyword': args.get('keyword') or '',
    }

    ioc_url = r'/api/iocs'
    if args.get('token'):
        result = client.get_iocs(method, ioc_url, params)
    else:
        result = {"error": "Invalid token !!"}

    command_results = CommandResults(
        outputs_prefix='CybleEvents.IoCs',
        outputs_key_field='data',
        outputs=result
    )
    return command_results


def format_incidents(resp, eventTypes):
    """
    Format the incidents to feed into XSOAR
    :param resp: events fetched from the server
    :param eventTypes: event types available
    :return: incidents to feed into XSOAR
    """
    events: List[Dict[str, Any]] = []
    try:
        alerts = resp.get('data') or []
        for alert in alerts:
            alert_data = alert.get('alert', {})
            alert_id = alert_data.get('id')
            alert_priority = alert_data.get('priority')
            alert_created_at = alert_data.get('created_at')
            alert_keyword = alert_data.get('tag_name')
            alert_bucket_name = alert_data.get('bucket', {}).get('name')
            for e_type in list(alert_data.get('services', {}).keys()):
                event_type = eventTypes.get(e_type)
                alert_details = {
                    "name": "Cyble Intel Alert on {}".format(event_type),
                    "cybleeventstype": "{}".format(e_type),
                    "severity": INCIDENT_SEVERITY.get(alert_priority.lower()),
                    "occurred": "{}".format(alert_created_at),
                    "cybleeventsid": "{}".format(alert_id),
                    "cybleeventsname": "Incident of {} type".format(event_type),
                    "cybleeventsbucket": "{}".format(alert_bucket_name),
                    "cybleeventskeyword": "{}".format(alert_keyword),
                    "cybleeventsalias": "{}".format(event_type)
                }
                events.append(alert_details)
        return events
    except Exception as e:
        demisto.debug('Unable to format incidents, error: {}'.format(e))
        return []


def cyble_fetch_events(client, method, args):
    """
    Fetch alert details from server for creating incidents in XSOAR
    :param client: instace of client to communicate with server
    :param method: Requests method to be used
    :param args: parameters for fetching event details
    :return: events from the server
    """
    params = {
        'token': args.get('token'),
        'from': arg_to_number(args.get('from', '0')),
        'limit': arg_to_number(args.get('limit', '50')),
        'start_date': args.get('start_date'),
        'end_date': args.get('end_date'),
        'order_by': args.get('order_by')
    }

    events_url = r'/api/v2/events/all'
    if args.get('token'):
        result = client.get_alerts(method, events_url, params)
    else:
        result = {}

    incidents: List[Dict[str, Any]] = []
    if result:
        eventTypes = get_event_types(client, "GET", args['token'])
        incidents = format_incidents(result, eventTypes)

    command_results = CommandResults(
        outputs_prefix='CybleEvents.Events',
        outputs_key_field=['cybleeventsid', 'cybleeventstype'],
        outputs=incidents
    )

    return command_results


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
    results: List[Any] = []
    params = {
        'token': args.get('token', None),
        'from': fetch_from,
        'limit': LIMIT_EVENT_ITEMS
    }
    if args.get('token'):
        client.get_event_details("POST", events_url, params, results)

    command_results = CommandResults(
        outputs_prefix='CybleEvents.Events',
        outputs_key_field='Details',
        outputs=results
    )

    return command_results


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
        'from': arg_to_number(last_run.get('fetched_alert_count', '0')),
        'limit': int(MAX_EVENT_ITEMS) if maxResults > 50 else int(maxResults),
        'start_date': last_run.get('event_pull_start_date', '0'),
        'end_date': date.today().strftime("%Y/%m/%d"),
        'order_by': 'Ascending'
    }

    events_url = r'/api/v2/events/all'
    result = client.get_alerts(method, events_url, params)

    incidents: List[Dict[str, Any]] = []
    if result:
        last_run['total_alert_count'] = result.get('total_count', 0)
        last_run['fetched_alert_count'] += len(result.get('data', 0))
        eventTypes = get_event_types(client, "GET", token)
        events = format_incidents(result, eventTypes)

        try:
            for event in events:
                inci = {
                    'name': event.get('name'),
                    'severity': event.get('severity'),
                    'occurred': event.get('occurred'),
                    'rawJSON': json.dumps(event)
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
    params = demisto.params()
    base_url = params.get('url')
    token = params.get('token')

    verify_certificate = not params.get('insecure', False)

    proxy = params.get('proxy', False)

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
                arg=params.get('max_fetch'),
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
            if not args.get('start_date'):
                args['start_date'] = datetime.today().strftime('%Y/%m/%d')
            if not args.get('end_date'):
                args['end_date'] = datetime.today().strftime('%Y/%m/%d')

            return_results(cyble_fetch_iocs(client, 'POST', args))

        elif demisto.command() == 'cyble-vision-fetch-events':
            # This is the call made when cyble-fetch-events command.
            args['order_by'] = (args.get('order_by') or '').title()
            if not args.get('start_date'):
                args['start_date'] = datetime.today().strftime('%Y-%m-%d')
            if not args.get('end_date'):
                args['end_date'] = datetime.today().strftime('%Y-%m-%d')

            return_results(cyble_fetch_events(client, 'POST', args))

        elif demisto.command() == "cyble-vision-fetch-event-detail":
            # Fetch event detail.
            return_results(fetch_alert_details(client, args))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
