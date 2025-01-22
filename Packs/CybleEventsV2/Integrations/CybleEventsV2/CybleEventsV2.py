from CommonServerPython import *

''' IMPORTS '''
import requests
from datetime import datetime
import pytz
import urllib3
import json

UTC = pytz.UTC

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

MAX_ALERTS = 1600
LIMIT_EVENT_ITEMS = 1600
MAX_RETRIES = 3
INCIDENT_SEVERITY = {
    'unknown': 0,
    'informational': 0.5,
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4
}
INCIDENT_STATUS = {
    "Unreviewed": "UNREVIEWED",
    "Viewed": "VIEWED",
    "False Positive": "FALSE_POSITIVE",
    "Confirmed Incident": "CONFIRMED_INCIDENT",
    "Under Review": "UNDER_REVIEW",
    "Informational": "INFORMATIONAL",
    "Resolved": "RESOLVED",
    "Remediation in Progress": "REMEDIATION_IN_PROGRESS",
    "Remediation not Required": "REMEDIATION_NOT_REQUIRED"
}
SEVERITIES = {
    "Low": "LOW",
    "Medium": "MEDIUM",
    "High": "HIGH"
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
    "fetch-incidents": "alerts",
    "update-remote-system": "alerts",
    'get-mapping-fields': "alerts"
}


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def get_response(self, url, headers, payload, method):
        """
        Generic call to the API for all the methods
        :param url: Contains the API url
        :param headers: Contains the headers for the API auth
        :param method: Contains the request method
        :param payload: Contains the request body
        """

        for _ in range(MAX_RETRIES):
            try:
                if method == 'POST' or method == 'PUT':
                    response = requests.request(method, url, headers=headers, json=payload)
                else:
                    response = requests.request(method, url, headers=headers, params=payload)

                response.raise_for_status()

                response_json = response.json()
                return response_json['data']
            except Exception:
                pass
        return None


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

            if limit <= 0 or limit > 100:
                raise ValueError(
                    f"The limit argument should contain a positive number, up to 100, limit: {limit}")

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
            if _start_date > datetime.now(tz=UTC):
                raise ValueError(
                    f"Start date must be a date before or equal to {datetime.now(tz=UTC).strftime(date_format)}")
            if _end_date > datetime.now(tz=UTC):
                raise ValueError(
                    f"End date must be a date before or equal to {args.get('end_date')}")
            if _start_date > _end_date:
                raise ValueError(f"Start date {args.get('start_date')} cannot be after end date {args.get('end_date')}")
        return
    except Exception as e:
        demisto.error(f"Exception with validating inputs [{e}]")
        raise e


def alert_input_structure(input_params):
    input_params_alerts: dict[str, Any] = {
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


def format_incidents(alerts, hide_cvv_expiry):
    """
    Format the incidents to feed into XSOAR
    :param alerts events fetched from the server
    :return: incidents to feed into XSOAR
    """
    events: List[dict[str, Any]] = []
    for alert in alerts:
        try:
            if hide_cvv_expiry and alert['service'] == 'compromised_cards':
                alert['data_message']['data']['bank']['card']['cvv'] = "xxx"
                alert['data_message']['data']['bank']['card']['expiry'] = "xx/xx/xxxx"

            keyword = ""
            if alert.get('metadata') and alert['metadata'].get('entity'):
                if alert['metadata']['entity'].get('keyword') and alert['metadata']['entity']['keyword']['tag_name']:
                    keyword = alert['metadata']['entity']['keyword']['tag_name']

            alert_details = {
                "name": "Cyble Vision Alert on {}".format(alert.get('service')),
                "event_type": "{}".format(alert.get('service')),
                "severity": INCIDENT_SEVERITY.get(alert.get('severity').lower()),
                "alert_group_id": "{}".format(alert.get('alert_group_id')),
                "event_id": "{}".format(alert.get('id')),
                "data_message": json.dumps(alert.get('data_message')),
                "keyword": "{}".format(keyword),
                "created_at": "{}".format(alert.get('created_at')),
                "status": "{}".format(alert.get('status')),
                "mirrorInstance": demisto.integrationInstance()
            }

            if alert.get('service') == 'compromised_cards':

                card_details = alert['data_message']['data']['bank']['card']
                alert_details.update({
                    "card_brand": card_details.get('brand'),
                    "card_no": card_details.get('card_no'),
                    "card_cvv": card_details.get('cvv'),
                    "card_expiry": card_details.get('expiry'),
                    "card_level": card_details.get('level'),
                    "card_type": card_details.get('type')
                })
            elif alert.get('service') == 'stealer_logs':
                content = alert['data_message']['data'].get('content')
                if content:
                    alert_details.update({
                        "application": content.get('Application'),
                        "password": content.get('Password'),
                        "url": content.get('URL'),
                        "username": content.get('Username')
                    })
                alert_details.update({
                    "filename": alert['data_message']['data']['filename']
                })

            events.append(alert_details)
        except Exception as e:
            demisto.debug(f'Unable to format incidents, error: {e}')
            continue
    return events


def fetch_service_details(client, base_url, token):
    service_name_lists = fetch_subscribed_services(client, "GET", base_url, token)
    lst = []
    for service_name_list in service_name_lists:
        lst.append(service_name_list['name'])
    return lst


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

    if subscribed_services:
        for subscribed_service in subscribed_services:
            service_name_list.append({"name": subscribed_service['name']})
    return service_name_list


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


def cyble_events(client, method, token, url, args, last_run, hide_cvv_expiry, incident_collections, incident_severity, skip=True):
    """
    Fetch alert details from server for creating incidents in XSOAR
    Args:
        client: instance of client to communicate with server
        method: Requests method to be used
        token: API access token
        url: end point URL
        args: input args
        last_run: get last run details
        hide_cvv_expiry: hide expiry / cvv number from cards
        incident_collections: list of collections to be fetched
        incident_severity: list of severities to be fetched
        skip: skip the validation for fetch incidnet

    Returns: events from the server

    """

    input_params = {}
    input_params['order_by'] = args.get('order_by', "asc")
    input_params['from_da'] = arg_to_number(args.get('from', 0))
    input_params['limit'] = MAX_ALERTS
    max_fetch = arg_to_number(demisto.params().get('max_fetch', 1))

    if skip:
        validate_input(args, False)
        input_params['start_date'] = args.get('start_date', '')
        input_params['end_date'] = args.get('end_date', '')
        if not args.get('end_date', ''):
            input_params['end_date'] = datetime.utcnow().astimezone().isoformat()
    else:
        initial_interval = demisto.params().get('first_fetch_timestamp', 1)
        if 'event_pull_start_date' not in last_run.keys():
            event_pull_start_date = datetime.utcnow() - timedelta(days=int(initial_interval))
            input_params['start_date'] = event_pull_start_date.astimezone().isoformat()
        else:
            input_params['start_date'] = last_run['event_pull_start_date']
        input_params['end_date'] = datetime.utcnow().astimezone().isoformat()

    latest_created_time = input_params['start_date']
    final_input_structure = alert_input_structure(input_params)

    if len(incident_collections) > 0 and "All collections" not in incident_collections:
        fetch_services = []
        if "Darkweb Marketplaces" in incident_collections:
            fetch_services.append("darkweb_marketplaces")
        if "Data Breaches" in incident_collections:
            fetch_services.append("darkweb_data_breaches")
        if "Compromised Endpoints" in incident_collections:
            fetch_services.append("stealer_logs")
        if "Compromised Cards" in incident_collections:
            fetch_services.append("compromised_cards")
        final_input_structure['where']['service'] = {
            "in": fetch_services
        }

    if len(incident_severity) > 0 and "All severities" not in incident_severity:
        fetch_severities = []
        for severity in incident_severity:
            fetch_severities.append(SEVERITIES.get(severity))
        final_input_structure['where']['severity'] = {
            "in": fetch_severities
        }

    all_alerts = set_request(client, method, token, final_input_structure, url)
    timestamp_count = {}   # type: ignore

    if not all_alerts:
        return [], {'event_pull_start_date': latest_created_time}

    for alert in all_alerts:
        timestamp = alert['created_at']
        if timestamp in timestamp_count:
            timestamp_count[timestamp] += 1
        else:
            timestamp_count[timestamp] = 1

    alert_count = 0
    prev_timestamp = all_alerts[0].get('created_at')
    last_timestamp = all_alerts[-1].get('created_at')

    alerts = []
    for alert in all_alerts:
        current_timestamp = alert.get('created_at')
        if current_timestamp == prev_timestamp:
            alerts.append(alert)
        else:
            alert_count += timestamp_count[prev_timestamp]
            prev_timestamp = current_timestamp

            if alert_count + timestamp_count[current_timestamp] <= max_fetch and current_timestamp != last_timestamp:
                alerts.append(alert)
            else:
                break

    del all_alerts
    del timestamp_count

    incidents = []

    if alerts:
        timestamp_str = alerts[-1].get('created_at')
        original_datetime = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%fZ")
        updated_datetime = original_datetime + timedelta(microseconds=1000)
        latest_created_time = updated_datetime.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        events = format_incidents(alerts, hide_cvv_expiry)

        for event in events:
            inci = {
                'name': event.get('name'),
                'severity': event.get('severity'),
                'rawJSON': json.dumps(event),
                'alert_group_id': event.get('alert_group_id'),
                'event_id': event.get('event_id'),
                'keyword': event.get('keyword'),
                'created': event.get('created_at')
            }
            incidents.append(inci)
        next_run = {'event_pull_start_date': latest_created_time}

        return incidents, next_run
    else:
        return [], {'event_pull_start_date': latest_created_time}


def update_remote_system(client, method, token, args, url):
    """
    Updates any changes in any mappable incident to remote server
    Args:
        client: instance of client to communicate with server
        method: Requests method to be used
        token: API access token
        url: end point URL
        args: input args

    Returns: None
    """

    parsed_args = UpdateRemoteSystemArgs(args)
    if parsed_args.delta:
        severities = {
            "1": "LOW",
            "2": "MEDIUM",
            "3": "HIGH",
            "4": "CRITICAL"
        }
        data = parsed_args.data
        incident_id = data.get('id')
        status = data.get('status')
        assignee_id = data.get('assignee_id')
        updated_severity = str(data.get('severity'))

        updated_event = {
            "id": incident_id
        }
        if status in INCIDENT_STATUS:
            updated_event["status"] = INCIDENT_STATUS.get(status)
        if assignee_id:
            updated_event["assignee_id"] = assignee_id
        if updated_severity:
            if updated_severity == "0.5" or updated_severity == "0":
                updated_event["user_severity"] = None
            else:
                updated_event["user_severity"] = severities.get(updated_severity)

        body = {
            "alerts": [updated_event]
        }
        set_request(client, method, token, body, url)


def get_mapping_fields(client, token, url):
    """
    Fetches all the fields associated with incidents for creating outgoing mapper
    Args:
        client: instance of client to communicate with server
        token: API access token
        url: end point URL

    Returns: None
    """

    input_params: dict[str, Any] = {}

    input_params['order_by'] = "asc"
    input_params['from_da'] = 0
    input_params['limit'] = 500

    initial_interval = 1
    event_pull_start_date = datetime.utcnow() - timedelta(days=int(initial_interval))

    input_params['start_date'] = event_pull_start_date.astimezone().isoformat()
    input_params['end_date'] = datetime.utcnow().astimezone().isoformat()
    final_input_structure = alert_input_structure(input_params)

    alerts = set_request(client, 'POST', token, final_input_structure, url)

    fields = {}
    for alert in alerts:
        for key in alert:
            fields[key] = alert[key]

    incident_type_scheme = SchemeTypeMapping(type_name='cyble_outgoing_mapper')

    for field, description in fields.items():
        incident_type_scheme.add_field(field, description)

    return GetMappingFieldsResponse([incident_type_scheme])


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

    input_params_alerts_group: dict[str, Any] = {
        "orderBy": [
            {
                "created_at": args.get('order_by', "asc")
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

    response = set_request(client, method, token, input_params_alerts_iocs, url)

    try:
        lst_iocs = []
        for ioc in response['iocs']:

            sources = []
            behaviour_tags = []
            target_countries = []
            target_regions = []
            target_industries = []
            related_malwares = []
            related_threat_actors = []

            if ioc.get('sources'):
                for source in ioc.get('sources'):
                    sources.append(source)

            if ioc.get('behaviour_tags'):
                for behaviour_tag in ioc.get('behaviour_tags'):
                    behaviour_tags.append(behaviour_tag)

            if ioc.get('target_countries'):
                for target_country in ioc.get('target_countries'):
                    target_countries.append(target_country)

            if ioc.get('target_regions'):
                for target_region in ioc.get('target_regions'):
                    target_regions.append(target_region)

            if ioc.get('target_industries'):
                for target_industry in ioc.get('target_industries'):
                    target_industries.append(target_industry)

            if ioc.get('related_malware'):
                for related_malware in ioc.get('related_malware'):
                    related_malwares.append(related_malware)

            if ioc.get('related_threat_actors'):
                for related_threat_actor in ioc.get('related_threat_actors'):
                    related_threat_actors.append(related_threat_actor)

            lst_iocs.append({'ioc': "{}".format(ioc['ioc']),
                             'ioc_type': "{}".format(ioc['ioc_type']),
                             'first_seen': "{}".format(ioc['first_seen']),
                             'last_seen': "{}".format(ioc['last_seen']),
                             'risk_score': "{}".format(ioc['risk_score']),
                             'confidence_rating': "{}".format(ioc['confidence_rating']),
                             'sources': f"{sources}",
                             'behaviour_tags': f"{behaviour_tags}",
                             'target_countries': f"{target_countries}",
                             'target_regions': f"{target_regions}",
                             'target_industries': f"{target_industries}",
                             'related_malware': f"{related_malwares}",
                             'related_threat_actors': f"{related_threat_actors}",
                             })
    except Exception as e:
        raise Exception(f"Error: [{e}] for response [{response}]")

    markdown = tableToMarkdown('Indicator of Compromise:', lst_iocs, )

    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix='CybleEvents.IoCs',
        raw_response=lst_iocs,
        outputs=lst_iocs)

    return command_results


def main():     # pragma: no cover
    """
         PARSE AND VALIDATE INTEGRATION PARAMS
     """

    # get the service API url
    params = demisto.params()
    base_url = params.get('base_url')
    token = demisto.params().get('credentials', {}).get('password', "")
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    hide_cvv_expiry = params.get('hide_data', False)
    demisto.debug(f'Command being called is {params}')
    mirror = params.get('mirror', False)
    incident_collections = params.get("incident_collections", [])
    incident_severity = params.get("incident_severity", [])

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
            data, next_run = cyble_events(client, 'POST', token, url, args, last_run,
                                          hide_cvv_expiry, incident_collections, incident_severity, False)

            demisto.setLastRun(next_run)
            demisto.incidents(data)

        elif demisto.command() == 'update-remote-system':
            # Updates changes in incidents to remote system
            if mirror:
                url = base_url + str(ROUTES[COMMAND[demisto.command()]])
                return_results(update_remote_system(client, 'PUT', token, args, url))

            return

        elif demisto.command() == 'get-mapping-fields':
            # Fetches mapping fields for outgoing mapper
            url = base_url + str(ROUTES[COMMAND[demisto.command()]])

            return_results(get_mapping_fields(client, token, url))

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
            lst_alerts, next_run = cyble_events(client, 'POST', token, url, args, {},
                                                hide_cvv_expiry, incident_collections, incident_severity, True)

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
