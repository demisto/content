from CommonServerPython import *

''' IMPORTS '''
import requests
from datetime import datetime, timezone
import urllib3
from typing import Dict

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

MAX_ALERTS = 1000
LIMIT_EVENT_ITEMS = 1000
INCIDENT_SEVERITY = {
    'unknown': 0,
    'informational': 0.5,
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4
}

ROUTES = {
    "services": r"/apollo/api/v1/y/services",
    "alerts-groups": r"/apollo/api/v1/y/alerts/groups",
    "alerts": r"/apollo/api/v1/y/alerts",
    "iocs": r"/engine/api/v2/y/iocs",
    "test": r"/apollo/api/v1/y/services",
}

COMMAND = {
    "cyble-vision-fetch-alert-groups": "alerts-groups",
    "cyble-vision-fetch-alerts": "alerts",
    "cyble-vision-subscribed-services": "services",
    "cyble-vision-fetch-iocs": "iocs",
    "test-module": "test",
    "fetch-incidents": "alerts"
}


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def get_response(self, url, headers, payload, method='POST'):
        """
        Generic call to the API for all the methods
        :param url: Contains the API url
        :param headers: Contains the headers for the API auth
        :param method: Contains the request method
        :param payload: Contains the request body
        """

        try:

            if method == 'POST':
                response = requests.request(method, url, headers=headers, json=payload).json()
            else:
                response = requests.request(method, url, headers=headers, params=payload).json()

            return response['data']
        except Exception:
            return []


def set_request(client, method, token, input_params, url):
    """
    Generic function to fetch data from server
    Args:
        client: instance of client to communicate with server
        method: Requests method to be used
        token: server access token
        input_params:
        url: final url for the request

    Returns: return data from server

    """
    headers = {'Authorization': 'Bearer ' + token}
    response = client.get_response(url, headers, input_params, method)
    return response


def test_response(client, method, base_url, token):
    """
    Test the integration state
    Args:
        client: client instance
        method: Requests method to be used
        base_url: base url for the server
        token: API access token

    Returns: test response

    """
    fetch = fetch_subscribed_services(client, method, base_url, token)
    if fetch:
        return 'ok'
    else:
        demisto.error("Failed to connect")
        raise Exception("failed to connect")


def fetch_subscribed_services_alert(client, method, base_url, token):
    """
    Fetch cyble subscribed services
    Args:
        client: instance of client to communicate with server
        method: Requests method to be used
        base_url: base url for the server
        token: server access token

    Returns: subscribed service list

    """
    get_subscribed_service_url = base_url + str(ROUTES[COMMAND['cyble-vision-subscribed-services']])
    subscribed_services = set_request(client, method, token, {}, get_subscribed_service_url)
    service_name_list = []

    for subscribed_service in subscribed_services:
        service_name_list.append({"name": subscribed_service['name']})

    markdown = tableToMarkdown('Alerts Group Details:', service_name_list, )
    return CommandResults(
        readable_output=markdown,
        outputs_prefix='CybleEvents.ServiceList',
        raw_response=service_name_list,
        outputs=service_name_list
    )


def fetch_subscribed_services(client, method, base_url, token):
    """
    Fetch cyble subscribed services
    Args:
        client: instance of client to communicate with server
        method: Requests method to be used
        base_url: base url for the server
        token: server access token

    Returns: subscribed service list

    """
    get_subscribed_service_url = base_url + str(ROUTES[COMMAND['cyble-vision-subscribed-services']])
    subscribed_services = set_request(client, method, token, {}, get_subscribed_service_url)
    service_name_list = []

    for subscribed_service in subscribed_services:
        service_name_list.append({"name": subscribed_service['name']})

    return service_name_list


def cyble_alert_group(client, method, token, url, args):
    """
    Call the client module to fetch alert group using the input parameters
    Args:
        client: instance of client to communicate with server
        method: Requests method to be used
        token: API access token
        url: URL
        input_params: input parameter for api

    Returns: alert group from server

    """

    input_params_alerts_group: Dict[str, Any] = {
        "orderBy": [
            {
                "created_at": args.get('order_by', "desc")
            }
        ],
        "skip": arg_to_number(args.get('from', 0)),
        "take": arg_to_number(args.get('limit', 10)),
        "include": {
            "tags": True
        }
    }

    if args.get('start_date', '') and args.get('end_date', ''):
        input_params_alerts_group['where'] = {}
        input_params_alerts_group['where']['created_at'] = {}

    if args.get('start_date', ''):
        input_params_alerts_group['where']['created_at']['gte'] = datetime.strptime(
            args.get('start_date', ''), '%Y-%m-%dT%H:%M:%S%z').astimezone().isoformat()

    if args.get('end_date', ''):
        input_params_alerts_group['where']['created_at']['lte'] = \
            datetime.strptime(args.get('end_date', ''), '%Y-%m-%dT%H:%M:%S%z').astimezone().isoformat()

    alert_groups = set_request(client, method, token, input_params_alerts_group, url)
    lst_alert_group = []

    if alert_groups:

        for alert_group in alert_groups:
            lst_alert_group.append({'service': "{}".format(alert_group['service']),
                                    'keyword': "{}".format
                                    (alert_group['metadata']['entity']['keyword']['tag_name']),
                                    'alert_group_id': "{}".format(alert_group['id']),
                                    'severity': "{}".format(alert_group['severity']),
                                    'status': "{}".format(alert_group['status']),
                                    'total_alerts': "{}".format(alert_group['total_alerts']),
                                    'created_at': "{}".format(alert_group['created_at'])})

        markdown = tableToMarkdown('Alerts Group Details:', lst_alert_group, )

        return CommandResults(
            readable_output=markdown,
            outputs_prefix='CybleEvents.AlertsGroup',
            raw_response=lst_alert_group,
            outputs=lst_alert_group
        )
    else:

        return CommandResults(
            readable_output="There aren't alerts."
        )


def cyble_fetch_iocs(client, method, token, args, url):
    """
    Call the client module to fetch IOCs using the input parameters
    Args:
        client: instance of client to communicate with server
        method: Requests method to be used
        token: API access token
        url: url for end point
        args: input parameter for api

    Returns: indicators from server

    """

    input_params_alerts_iocs = {
        'ioc': args.get('ioc', ''),
        'page': args.get('from', ''),
        'limit': args.get('limit', ''),
        'sortBy': args.get('sort_by', ''),
        'order': args.get('order', ''),
        'tags': args.get('tags')
    }

    if args.get('ioc_type', ''):
        input_params_alerts_iocs['iocType'] = args.get('ioc_type', '')

    if args.get('start_date'):
        input_params_alerts_iocs['startDate'] = args.get('start_date')

    if args.get('end_date'):
        input_params_alerts_iocs['endDate'] = args.get('end_date')

    iocs = set_request(client, method, token, input_params_alerts_iocs, url)

    try:
        lst_iocs = []
        for ioc in iocs['result']:

            lst_attack = []
            lst_tags = []

            for attack_details in ioc['attack_id']:
                lst_attack.append(attack_details['attack_id'])

            for ioc_tags in ioc['ioc_tags']:
                lst_tags.append(ioc_tags['name'])

            lst_iocs.append({'ioc': "{}".format(ioc['ioc']),
                             'first_seen': "{}".format(ioc['first_seen']),
                             'last_seen': "{}".format(ioc['last_seen']),
                             'risk_rating': "{}".format(ioc['risk_rating']),
                             'confident_rating': "{}".format(ioc['confident_rating']),
                             'ioc_type': "{}".format(ioc['ioc_type']['name']),
                             'attack': "{}".format(lst_attack),
                             'tags': "{}".format(lst_tags)
                             })
    except Exception as e:
        raise Exception("Error: [{}] for response [{}]".format(e, iocs))

    markdown = tableToMarkdown('Indicator of Compromise:', lst_iocs, )

    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix='CybleEvents.IoCs',
        raw_response=lst_iocs,
        outputs=lst_iocs)

    return command_results


def format_incidents(alerts):
    """
    Format the incidents to feed into XSOAR
    :param alerts events fetched from the server
    :return: incidents to feed into XSOAR
    """
    events: List[Dict[str, Any]] = []
    try:
        for alert in alerts:
            alert_details = {
                "name": "Cyble Vision Alert on {}".format(alert['service']),
                "event_type": "{}".format(alert['service']),
                "severity": INCIDENT_SEVERITY.get(alert['severity'].lower()),
                "alert_group_id": "{}".format(alert['alert_group_id']),
                "event_id": "{}".format(alert['id']),
                "data_message": "{}".format(alert['data_message']),
                "keyword": "{}".format(alert['metadata']['entity']['keyword']['tag_name']),
                "created_at": "{}".format(alert['created_at'])
            }

            events.append(alert_details)

        return events
    except Exception as e:
        demisto.debug('Unable to format incidents, error: {}'.format(e))
        raise Exception("Error: [{}] for response [{}]".format(e, alerts))


def cyble_events(client, method, token, url, args, base_url, last_run, skip=True):
    """
    Fetch alert details from server for creating incidents in XSOAR
    Args:
        last_run: get last run details
        base_url: base url for subscribed services
        client: instance of client to communicate with server
        method: Requests method to be used
        token: API access token
        url: end point URL
        args: input args
        skip: skip the validation for fetch incidnet

    Returns: events from the server

    """

    input_params = {}

    input_params['order_by'] = args.get('order_by', "desc")
    input_params['from_da'] = arg_to_number(args.get('from', 0))

    if skip:
        validate_input(args, False)

        input_params['limit'] = arg_to_number(args.get('limit', 10))
        input_params['start_date'] = args.get('start_date', '')
        input_params['end_date'] = args.get('end_date', '')

        if not args.get('end_date', ''):
            input_params['end_date'] = datetime.now().astimezone().replace(microsecond=0).isoformat()

    else:
        initial_interval = demisto.params().get('first_fetch_timestamp', 1)

        if 'event_pull_start_date' not in last_run.keys():
            event_pull_start_date = datetime.utcnow() - timedelta(days=int(initial_interval))
            input_params['start_date'] = event_pull_start_date.astimezone().replace(microsecond=0).isoformat()
        else:
            input_params['start_date'] = last_run['event_pull_start_date']

        # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
        max_results = arg_to_number(demisto.params().get('max_fetch', 0))

        if not max_results or max_results > MAX_ALERTS:
            input_params['limit'] = MAX_ALERTS
        else:
            input_params['limit'] = max_results

        input_params['end_date'] = datetime.now().astimezone().replace(microsecond=0).isoformat()

    latest_created_time = input_params['start_date']

    final_input_structure = alert_input_structure(input_params)

    alerts = set_request(client, method, token, final_input_structure, url)
    incidents = []

    if alerts:
        events = format_incidents(alerts)

        for event in events:
            incident_created_time = datetime.strptime(event.get('created_at'),
                                                      "%Y-%m-%dT%H:%M:%S.%fZ").astimezone().isoformat()
            inci = {
                'name': event.get('name'),
                'severity': event.get('severity'),
                'rawJSON': json.dumps(event),
                'alert_group_id': event.get('alert_group_id'),
                'event_id': event.get('event_id'),
                'keyword': event.get('keyword'),
                'created': event.get('created_at'),
            }
            incidents.append(inci)

            if incident_created_time > latest_created_time:
                latest_created_time = incident_created_time

        next_run = {'event_pull_start_date': latest_created_time}

        return incidents, next_run
    else:
        return [], {'event_pull_start_date': latest_created_time}


def validate_input(args, is_iocs=False):
    """
    Check if the input params for the command are valid. Return an error if any
    :param args: dictionary of input params
    :param is_iocs: check if the params are for iocs command
    """
    try:
        # we assume all the params to be non-empty, as cortex ensures it
        if int(args.get('from')) < 0:
            raise ValueError(f"The parameter from has a negative value, from: {arg_to_number(args.get('from'))}'")
        limit = int(args.get('limit', 1))

        if is_iocs:
            date_format = "%Y-%m-%d"
            if args.get('start_date') and args.get('end_date'):
                _start_date = datetime.strptime(args.get('start_date'), date_format)
                _end_date = datetime.strptime(args.get('end_date'), date_format)
            else:
                _start_date = datetime(1, 1, 1, 0, 0)
                _end_date = datetime(1, 1, 1, 0, 0)

            if limit <= 0 or limit > 1000:
                raise ValueError(
                    f"The limit argument should contain a positive number, up to 1000, limit: {limit}")

            if _start_date > datetime.utcnow():
                raise ValueError(
                    f"Start date must be a date before or equal to {datetime.today().strftime(date_format)}")
            if _end_date > datetime.utcnow():
                raise ValueError(f"End date must be a date before or equal to {datetime.today().strftime(date_format)}")
            if _start_date > _end_date:
                raise ValueError(f"Start date {args.get('start_date')} cannot be after end date {args.get('end_date')}")

        else:
            date_format = "%Y-%m-%dT%H:%M:%S%z"
            _start_date = datetime.strptime(args.get('start_date'), date_format)
            _end_date = datetime.strptime(args.get('end_date'), date_format)
            if limit <= 0 or limit > LIMIT_EVENT_ITEMS:
                raise ValueError(f"The limit argument should contain a positive number, up to 1000, limit: {limit}")

            if _start_date > datetime.now(tz=timezone.utc):
                raise ValueError(
                    f"Start date must be a date before or equal to {datetime.now(tz=timezone.utc).strftime(date_format)}")
            if _end_date > datetime.now(tz=timezone.utc):
                raise ValueError(
                    f"End date must be a date before or equal to {args.get('end_date')}")
            if _start_date > _end_date:
                raise ValueError(f"Start date {args.get('start_date')} cannot be after end date {args.get('end_date')}")

        return None
    except Exception as e:
        demisto.error("Exception with validating inputs [{}]".format(e))
        raise e


def fetch_service_details(client, base_url, token):
    service_name_lists = fetch_subscribed_services(client, "GET", base_url, token)

    lst = []
    for service_name_list in service_name_lists:
        lst.append(service_name_list['name'])

    return lst


def alert_input_structure(input_params):

    input_params_alerts: Dict[str, Any] = {
        "orderBy": [
            {
                "created_at": input_params['order_by']
            }
        ],
        "select": {
            "alert_group_id": True,
            "archive_date": True,
            "archived": True,
            "assignee_id": True,
            "assignment_date": True,
            "created_at": True,
            "data_id": True,
            "deleted_at": True,
            "description": True,
            "hash": True,
            "id": True,
            "metadata": True,
            "risk_score": True,
            "service": True,
            "severity": True,
            "status": True,
            "tags": True,
            "updated_at": True,
            "user_severity": True
        },
        "skip": input_params['from_da'],
        "take": input_params['limit'],
        "withDataMessage": True,
        "where": {
            "created_at": {
                "gte": input_params['start_date'],
                "lte": input_params['end_date'],
            },
            "severity": {
                "in": [
                    "HIGH",
                    "MEDIUM",
                    "LOW"
                ]
            },
            "status": {
                "in": [
                    "VIEWED",
                    "UNREVIEWED",
                    "CONFIRMED_INCIDENT",
                    "UNDER_REVIEW",
                    "INFORMATIONAL"
                ]
            }
        }
    }
    return input_params_alerts


def main():
    """
         PARSE AND VALIDATE INTEGRATION PARAMS
     """

    # get the service API url
    params = demisto.params()
    base_url = params.get('base_url')
    token = demisto.params().get('credentials', {}).get('password', "")
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    demisto.debug(f'Command being called is {params}')

    try:

        client = Client(
            base_url=params.get('base_url'),
            verify=verify_certificate,
            proxy=proxy)
        args = demisto.args()

        if demisto.command() == "test-module":
            # request was successful
            return_results(test_response(client, "GET", base_url, token))

        elif demisto.command() == 'fetch-incidents':
            # This is the call made when cyble-fetch-events command.
            last_run = demisto.getLastRun()

            url = base_url + str(ROUTES[COMMAND[demisto.command()]])
            data, next_run = cyble_events(client, 'POST', token, url, args, base_url, last_run, False)

            demisto.setLastRun(next_run)
            demisto.incidents(data)

        elif demisto.command() == "cyble-vision-subscribed-services":
            # This is the call made when subscribed-services command.
            return_results(fetch_subscribed_services_alert(client, "GET", base_url, token))

        elif demisto.command() == "cyble-vision-fetch-alert-groups":
            # Fetch alert group.

            validate_input(args, False)
            url = base_url + str(ROUTES[COMMAND[demisto.command()]])
            return_results(cyble_alert_group(client, 'POST', token, url, args))

        elif demisto.command() == 'cyble-vision-fetch-iocs':
            # This is the call made when cyble-vision-v2-fetch-iocs command.

            validate_input(args, True)
            url = base_url + str(ROUTES[COMMAND[demisto.command()]])
            command_results = cyble_fetch_iocs(client, 'GET', token, args, url)

            return_results(command_results)

        elif demisto.command() == 'cyble-vision-fetch-alerts':
            # This is the call made when cyble-vision-v2-fetch-alerts command.

            url = base_url + str(ROUTES[COMMAND[demisto.command()]])
            lst_alerts, next_run = cyble_events(client, 'POST', token, url, args, base_url, {}, True)

            markdown = tableToMarkdown('Alerts Details:', lst_alerts)

            return_results(CommandResults(
                readable_output=markdown,
                outputs_prefix='CybleEvents.Alerts',
                raw_response=lst_alerts,
                outputs=lst_alerts
            ))
        else:
            raise NotImplementedError(f'{demisto.command()} command is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
