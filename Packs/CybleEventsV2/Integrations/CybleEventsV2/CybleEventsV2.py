from CommonServerPython import *

''' IMPORTS '''
import requests
from datetime import datetime, timedelta
import pytz
import urllib3
import dateparser
import json
from dateutil.parser import isoparse
from dateutil.parser import parse as parse_date

import traceback

from collections.abc import Sequence
import concurrent.futures

UTC = pytz.UTC

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

MAX_ALERTS = 500
LIMIT_EVENT_ITEMS = 500
MAX_RETRIES = 3
MAX_THREADS = 5
MIN_MINUTES_TO_FETCH = 10
DEFAULT_REQUEST_TIMEOUT = 600
DEFAULT_TAKE_LIMIT = 5
DEFAULT_STATUSES = ["VIEWED", "UNREVIEWED", "CONFIRMED_INCIDENT", "UNDER_REVIEW", "INFORMATIONAL"]
SAMPLE_ALERTS = 10
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
    "services": r"/y/tpi/cortex/alerts/services",
    "alerts-groups": r"/apollo/api/v1/y/alerts/groups",
    "alerts": r"/y/tpi/cortex/alerts",
    "iocs": r"/engine/api/v2/y/iocs",
    "test": r"/y/tpi/cortex/alerts/services",
}

COMMAND = {
    "cyble-vision-fetch-alert-groups": "alerts-groups",
    "cyble-vision-fetch-alerts": "alerts",
    "cyble-vision-subscribed-services": "services",
    "cyble-vision-fetch-iocs": "iocs",
    "test-module": "test",
    "fetch-incidents": "alerts",
    "update-remote-system": "alerts",
    'get-mapping-fields': "alerts",
    'get-modified-remote-data': "alerts",
    'get-remote-data': "alerts"
}

HEADERS = lambda alerts_api_key: {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {alerts_api_key}"
}
ENCODED_HEADER = lambda headers: {k: v.encode('utf-8') for k, v in headers.items()}


def get_event_format(event):
    """
    Converts an event from Cyble to a format suitable for Demisto.
    :param event: The event to format
    :return: A dictionary with the event's information
    """
    return {
        'name': event.get('name'),
        'severity': event.get('severity'),
        'rawJSON': json.dumps(event),
        'event_id': event.get('event_id'),
        'keyword': event.get('keyword'),
        'created': event.get('created_at')
    }


def get_alert_payload(service, input_params: dict[str, any], is_update=False):
    """
    Generate the payload for a call to the Cyble alerts API.

    :param service: The service to fetch alerts for
    :param input_params: A dictionary of parameters for the API call
    :param is_update: If True, use `updated_at` instead of `created_at`
    :return: A dictionary containing the payload for the API call
    """
    try:
        # Determine the timestamp field based on `is_update`
        timestamp_field = "updated_at" if is_update else "created_at"

        return {
            "filters": {
                "service": [service],
                timestamp_field: {  # Use dynamic field based on `is_update`
                    "gte": ensure_aware(datetime.fromisoformat(input_params["gte"])).strftime(
                        "%Y-%m-%dT%H:%M:%S+00:00"),
                    "lte": ensure_aware(datetime.fromisoformat(input_params["lte"])).strftime("%Y-%m-%dT%H:%M:%S+00:00")

                },
                "status": ["VIEWED", "UNREVIEWED", "CONFIRMED_INCIDENT", "UNDER_REVIEW", "INFORMATIONAL"],
                "severity": input_params["severity"]
            },
            "orderBy": [{timestamp_field: input_params["order_by"]}],
            "skip": input_params["skip"],
            "take": input_params["take"],
            "countOnly": False,
            "taggedAlert": False,
            "withDataMessage": True,
        }
    except Exception as e:
        demisto.error(f"Error in formatting: {e}")


def get_alert_payload_by_id(
        client,
        alert_id: str,
        token: str,
        url: str,
        incident_collections: dict,
        incident_severity: dict,
        hide_cvv_expiry: bool
) -> dict:
    demisto.debug(f"[get_alert_payload_by_id] Called with alert_id: {alert_id}")

    try:
        alert = get_alert_by_id(client, alert_id, token, url)
        if not alert or 'service' not in alert:
            demisto.error(f"[get_alert_payload_by_id] Alert ID {alert_id} is missing required data.")
            return {}

        demisto.debug("[get_alert_payload_by_id] Alert fetched successfully")

        incidents = format_incidents([alert], hide_cvv_expiry)
        if not incidents:
            demisto.debug(f"[get_alert_payload_by_id] Formatting failed for alert ID {alert_id}")
            return {}

        incident = incidents[0]
        incident["rawJSON"] = json.dumps(alert)

        demisto.debug("[get_alert_payload_by_id] Converted alert to incident using format_incidents")
        return incident

    except Exception as e:
        demisto.error(f"[get_alert_payload_by_id] Exception occurred: {e}")
        return {}


def time_diff_in_mins(gte: datetime, lte: datetime):
    """
    Calculates the difference in minutes between two datetime objects.

    :param gte: The start date time
    :param lte: The end date time
    :return: The difference in minutes
    """
    diff = (lte - gte).total_seconds() / 60
    return diff


def format_incidents(alerts, hide_cvv_expiry):
    """
    Format the incidents to feed into XSOAR
    :param alerts events fetched from the server
    :return: incidents to feed into XSOAR
    """
    events = []
    for alert in alerts:
        try:
            if hide_cvv_expiry and alert['service'] == 'compromised_cards':
                alert['data']['bank']['card']['cvv'] = "xxx"
                alert['data']['bank']['card']['expiry'] = "xx/xx/xxxx"
            alert_details = {
                "name": "Cyble Vision Alert on {}".format(alert.get('service')),
                "event_type": "{}".format(alert.get('service')),
                "severity": INCIDENT_SEVERITY.get(alert.get('severity').lower()),
                "event_id": "{}".format(alert.get('id')),
                "data_message": json.dumps(alert.get('data')),
                "keyword": "{}".format(alert.get('keyword_name')),
                "created_at": "{}".format(alert.get('created_at')),
                "status": "{}".format(alert.get('status')),
                "mirrorInstance": demisto.integrationInstance()
            }
            if alert.get('service') == 'compromised_cards':
                card_details = alert['data']['bank']['card']
                alert_details.update({
                    "card_brand": card_details.get('brand'),
                    "card_no": card_details.get('card_no'),
                    "card_cvv": card_details.get('cvv'),
                    "card_expiry": card_details.get('expiry'),
                    "card_level": card_details.get('level'),
                    "card_type": card_details.get('type')
                })
            elif alert.get('service') == 'stealer_logs':
                content = alert['data'].get('content')
                if content:
                    alert_details.update({
                        "application": content.get('Application'),
                        "password": content.get('Password'),
                        "url": content.get('URL'),
                        "username": content.get('Username')
                    })
                alert_details.update({"filename": alert['data']['filename']})
            events.append(alert_details)
        except Exception as e:
            demisto.debug(f'Unable to format incidents, error: {e}')
    return events


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

    def make_request(self, url, api_key, method='GET', payload_json=None, params=None):
        """
        Makes an HTTP request to the specified host and path with the specified API key,
        method, and payload_json. Returns the response object.

        :param host: The host to make the request to
        :param path: The path to make the request to
        :param api_key: The API key to use for the request
        :param method: The HTTP method to use for the request (default: GET)
        :param payload_json: The JSON payload to send with the request (default: None)
        :param params: The query parameters to send with the request (default: None)
        :return: The response object
        """
        headers = HEADERS(api_key)
        encoded_headers = ENCODED_HEADER(headers)
        return requests.request(method, url, data=payload_json, headers=encoded_headers, params=params,
                                timeout=DEFAULT_REQUEST_TIMEOUT)

    def get_data(self, service, input_params, is_update=False):
        """
        Sends an HTTP POST request to the given host with the provided payload and API key,
        and logs errors if the request fails.

        Logs the final payload, URL, API key, and checks the response.

        :param service: The service to fetch data from
        :param input_params: A dictionary containing parameters for the API call
        :param is_update: Whether this is an update fetch (based on updated_at instead of created_at)
        :return: The JSON response from the request as a dictionary, or an empty dictionary if the request fails
        """

        try:

            payload = get_alert_payload(service, input_params, is_update)

            payload_json = json.dumps(payload)

            # Extract the URL and API key
            url, alerts_api_key = input_params["url"], input_params["api_key"]

            # Send the HTTP POST request
            response = self.make_request(url, alerts_api_key, 'POST', payload_json)

            # Check if the response status code is 200
            if response.status_code != 200:
                raise Exception(f"Wrong status code: {response.status_code}")

            # Return the JSON response
            response_json = response.json()
            return response_json

        except Exception as e:
            demisto.debug(f"Failed to get Alert data: {str(e)}")
            return {}

    def get_all_services(self, api_key, url):
        """
        Requests the list of all services from the Cyble API with the given API key and logs errors if the request fails.

        :param api_key: The API key to be used for the request
        :param ew: An event writer object for logging
        :return: A list of service dictionaries, or an empty list if the request fails
        """
        try:
            url = url + "/services"
            response = self.make_request(url, api_key)
            if response.status_code != 200:
                raise Exception("Wrong status code: %s" % response.status_code)
            response = response.json()

            if 'data' in response and isinstance(response['data'], Sequence):
                return ['compromised_files']
                # services = []
                # for each_service in response['data']:
                #     if each_service["name"] not in EXCLUDED_SERVICES:
                #         services.append(each_service["name"])
                # return services
            else:
                raise Exception("Wrong Format for services response")
        except Exception as e:
            demisto.debug("Failed to get services: %s" % str(e))

        return []

    def insert_data_in_cortex(self, service, input_params, is_update):
        """
        Fetches and inserts data into Cortex XSOAR from the given service based on the given parameters.

        :param service: The service to fetch data from
        :param input_params: A dictionary containing parameters for the API call, including the API key, base URL, skip, take, and time range
        :return: The latest created time of the data inserted
        """
        latest_created_time = datetime.utcnow()
        input_params.update({
            "skip": 0,
            "take": input_params["limit"]
        })

        all_incidents = []

        try:
            while True:
                response = self.get_data(service, input_params, is_update)
                input_params["skip"] += input_params["take"]

                if 'data' in response and isinstance(response['data'], Sequence):
                    if len(response["data"]) == 0:
                        break

                    latest_created_time = parse_date(response['data'][-1].get('created_at')) + timedelta(microseconds=1)

                    events, incidentsArr = format_incidents(response['data'], input_params["hce"]), []
                    for event in events:
                        incident = get_event_format(event)
                        incidentsArr.append(incident)

                    all_incidents.extend(incidentsArr)
                    demisto.incidents(incidentsArr)

                else:
                    raise Exception(
                        f"Unable to fetch data for gte: {input_params['gte']} to lte: {input_params['lte']} and skip: {input_params['skip']} and take: {input_params['take']}")

        except Exception as e:
            demisto.debug(f"Failed to process insert_data_in_cortex: {str(e)}")

        return all_incidents, latest_created_time

    def get_data_with_retry(self, service, input_params, is_update=False):
        """
        Recursively splits time ranges and fetches data, inserting it into Cortex.
        Returns a tuple of (alerts, latest_created_time).
        """
        gte = parse_date(input_params["gte"])
        lte = parse_date(input_params["lte"])

        que = [[gte, lte]]
        latest_created_time = datetime.utcnow()
        all_alerts = []

        while que:
            current_gte, current_lte = que.pop(0)

            # Copy input_params to avoid mutating original in multithreaded contexts
            current_params = input_params.copy()
            current_params['gte'] = current_gte.isoformat()
            current_params['lte'] = current_lte.isoformat()

            response = self.get_data(service, current_params, is_update=is_update)

            if 'data' in response:
                curr_alerts, curr_time = self.insert_data_in_cortex(service, current_params, is_update)
                all_alerts.extend(curr_alerts)
                latest_created_time = max(latest_created_time, curr_time)

            elif time_diff_in_mins(current_gte, current_lte) >= MIN_MINUTES_TO_FETCH:
                mid_datetime = current_gte + (current_lte - current_gte) / 2
                que.extend([
                    [current_gte, mid_datetime],
                    [mid_datetime + timedelta(microseconds=1), current_lte]
                ])
            else:
                demisto.debug(f"Unable to fetch data for gte: {current_gte} to lte: {current_lte}")

        return all_alerts, latest_created_time + timedelta(microseconds=1)

    def get_ids_with_retry(self, service, input_params, is_update=False):
        """
        Recursively splits time ranges and fetches data, inserting it into Cortex.
        Returns a tuple of (alerts, latest_created_time).
        """
        gte = parse_date(input_params["gte"])
        lte = parse_date(input_params["lte"])

        que, latest_created_time = [[gte, lte]], datetime.utcnow()
        ids = []

        while que:
            current_gte, current_lte = que.pop(0)

            # Serialize datetime objects to strings BEFORE placing in input_params
            input_params['gte'] = current_gte.isoformat()
            input_params['lte'] = current_lte.isoformat()

            response = self.get_data(service, input_params, is_update=is_update)
            if 'data' in response:
                for alert in response['data']:
                    ids.append(alert.get('id'))
            elif time_diff_in_mins(current_gte, current_lte) >= MIN_MINUTES_TO_FETCH:
                mid_datetime = current_gte + (current_lte - current_gte) / 2
                que.extend([
                    [current_gte, mid_datetime],
                    [mid_datetime + timedelta(microseconds=1), current_lte]
                ])
            else:
                demisto.debug(f"Unable to fetch data for gte: {current_gte} to lte: {current_lte}")

        return ids

    def update_alert(self, payload, url, api_key):
        """
        Updates the alert with the given payload and API key.

        :param payload: A dictionary of key-value pairs containing the alert data to be updated.
        :param url: The URL of the Cyble API endpoint to be used for the request.
        :param api_key: The API key to be used for the request.
        :return: None
        :raises Exception: If the request fails.
        """
        try:
            payload_json = json.dumps(payload)
            response = self.make_request(url, api_key, 'PUT', payload_json)
            if response.status_code != 200:
                raise Exception("Wrong status code: %s" % response.status_code)
        except Exception as e:
            demisto.debug("Failed to process update_alert with %s" % str(e))


def validate_iocs_input(args):
    """
    Validates the input arguments for the fetch-iocs command.

    :param args: A dictionary of input arguments.
    :return: None
    :raises ValueError: If the input arguments are invalid.
    """
    try:
        if int(args.get('from')) < 0:
            raise ValueError(f"The parameter from has a negative value, from: {arg_to_number(args.get('from'))}'")
        limit, date_format = int(args.get('limit', 1)), "%Y-%m-%d"
        if args.get('start_date') and args.get('end_date'):
            _start_date, _end_date = datetime.strptime(args.get('start_date'), date_format), datetime.strptime(
                args.get('end_date'), date_format)
        else:
            _start_date, _end_date = datetime(1, 1, 1, 0, 0), datetime(1, 1, 1, 0, 0)
        if limit <= 0 or limit > 100:
            raise ValueError(f"The limit argument number should, up to 100, given limit: {limit}")
        if _start_date > _end_date:
            raise ValueError(f"Start date {args.get('start_date')} cannot be after end date {args.get('end_date')}")
    except Exception as e:
        demisto.error("Failed to process validate_iocs_input with %s" % str(e))


def validate_alerts_input(args):
    """
    Validates the input arguments for the fetch-alerts command.

    :param args: A dictionary of input arguments.
    :return: None
    :raises ValueError: If the input arguments are invalid.
    """
    try:
        if int(args.get('from')) < 0:
            raise ValueError(f"The parameter from has a negative value, from: {arg_to_number(args.get('from'))}'")
        limit, date_format = int(args.get('limit', 1)), "%Y-%m-%dT%H:%M:%S%z"
        if limit <= 0 or limit > LIMIT_EVENT_ITEMS:
            raise ValueError(f"The limit argument number should, up to 1000, limit: {limit}")
        _start_date, _end_date = datetime.strptime(args.get('start_date'), date_format), datetime.strptime(
            args.get('end_date'), date_format)
        if _start_date > _end_date:
            raise ValueError(f"Start date {args.get('start_date')} cannot be after end date {args.get('end_date')}")
    except Exception as e:
        demisto.error("Failed to process validate_alerts_input with %s" % str(e))


def alert_input_structure(input_params):
    input_params_alerts = {
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


def fetch_service_details(client, base_url, token):
    """
    Fetches the names of all subscribed services from the Cyble API.

    Args:
        client: An instance of the client to communicate with the server.
        base_url: The base URL for the server.
        token: The server access token.

    Returns:
        A list of names of the subscribed services.
    """

    service_name_lists = fetch_subscribed_services(client, "GET", base_url, token)
    lst = []
    for service_name_list in service_name_lists:
        lst.append(service_name_list['name'])
    return lst


def ensure_aware(dt: datetime) -> datetime:
    """Ensure datetime is timezone-aware in UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=pytz.UTC)
    return dt.astimezone(pytz.UTC)


def get_alert_data(client, token, url, args):
    """
    Fetch alert details from the Cyble server for updating in XSOAR.
    Args:
        client: Instance of client to communicate with server.
        token: API access token.
        url: Endpoint URL for fetching alerts.
        args: Arguments passed from XSOAR (like alert ID).
    Returns:
        dict: Fetched alert details.
    """
    alert_id = args.get('id')
    if not alert_id:
        raise ValueError("Alert ID is required to fetch data.")
    input_params = {
        "where": {
            "id": {
                "in": [alert_id]
            }
        },
        "select": {
            "id": True,
            "created_at": True,
            "updated_at": True,
            "description": True,
            "severity": True,
            "status": True,
            "service": True
        },
        "skip": 0,
        "take": 1
    }
    #  Fetch data using the client
    response = client.get_data(url, token, input_params)
    if 'data' in response and response['data']:
        alert = response['data'][0]
        #  Directly map Cyble Vision status using status_map
        alert['status'] = status_map.get(alert['status'], 'New')
        return alert
    else:
        raise ValueError(f"No alert found with ID {alert_id}")


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
    subscribed_services, service_name_list = client.get_all_services(token), []
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
    try:
        fetch = client.get_all_services(token, base_url)
        if fetch:
            return 'ok'
    except Exception as e:
        demisto.error(f"Failed to connect: {e}")
        raise Exception(f"failed to connect: {e}")


def migrate_data(client: Client, input_params: dict[str, any], is_update=False):
    """
    Migrates data from cyble to demisto cortex.

    Args:
        client: instance of client to communicate with server
        input_params: dict containing the parameters for the migration, including services and their associated parameters
        is_update: Boolean flag indicating whether this is an update (used for get-modified-remote-data)

    Returns: the max of the last fetched timestamp
    """
    chunkedServices = [input_params["services"][i:i + MAX_THREADS] for i in
                       range(0, len(input_params["services"]), MAX_THREADS)]
    last_fetched = datetime.utcnow()
    all_alerts = []

    try:
        for chunk in chunkedServices:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = [
                    executor.submit(client.get_data_with_retry, service, input_params, is_update)
                    for service in chunk
                ]
            for future in concurrent.futures.as_completed(futures):
                try:
                    alerts, fetched_time = future.result()
                    all_alerts.extend(alerts)
                    if isinstance(fetched_time, datetime):
                        last_fetched = max(last_fetched, fetched_time)
                except Exception as inner_e:
                    demisto.debug(f"Error while processing future in migrate_data: {str(inner_e)}")

    except Exception as e:
        demisto.debug(f"Issue in migrate_data, Error: {str(e)}")

    return all_alerts, last_fetched


def fetch_few_alerts(client, input_params, services, url, token, is_update=False):
    demisto.debug("[fetch_few_alerts] Starting fetch")

    result = []
    input_params["take"] = SAMPLE_ALERTS  # override limit for sample
    demisto.debug(f"[fetch_few_alerts] Updated 'take' to SAMPLE_ALERTS ({SAMPLE_ALERTS})")

    for service in services:
        demisto.debug(f"[fetch_few_alerts] Fetching from service: {service}")
        try:
            # Append transport details only for internal use by get_data
            input_params_with_context = input_params.copy()
            input_params_with_context["url"] = url
            input_params_with_context["api_key"] = token

            response = client.get_data(service, input_params_with_context, is_update=is_update)
            if 'data' in response and isinstance(response['data'], Sequence):
                demisto.debug(f"[fetch_few_alerts] Received {len(response['data'])} alerts")

                hce = input_params.get("hce", False)
                events = format_incidents(response['data'], hce)

                for event in events:
                    formatted_event = get_event_format(event)
                    result.append(formatted_event)
            else:
                demisto.debug("[fetch_few_alerts] No valid data in response")
        except Exception as e:
            demisto.error(f"[fetch_few_alerts] Error fetching data: {e}")
            continue

        if result:
            break

    demisto.debug(f"[fetch_few_alerts] Total alerts returned: {len(result)}")
    return result


def build_get_alert_payload(alert_id):
    """
    Builds the payload for fetching an alert by ID.
    """
    return {
        "filters": {
            "id": [alert_id]
        },
        "excludes": {
            "status": ["FALSE_POSITIVE"]
        },
        "orderBy": [
            {
                "created_at": "desc"
            }
        ],
        "skip": 0,
        "take": 1,
        "taggedAlert": False,
        "withDataMessage": True,
        "countOnly": False
    }


def build_auth_headers(token):
    """
    Builds the authorization headers for the API request.
    """
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }


def get_alert_by_id(client, alert_id, token, url):
    """
    Fetches a specific alert by its ID.
    """
    demisto.debug(f"[get_alert_by_id] Fetching alert with ID: {alert_id}")

    payload = build_get_alert_payload(alert_id)
    headers = build_auth_headers(token)

    demisto.debug("[get_alert_by_id] Final payload being sent:")
    demisto.debug(json.dumps(payload, indent=2))

    try:
        response = client._http_request(
            method='POST',
            url_suffix='/y/tpi/cortex/alerts',
            headers=headers,
            json_data=payload,
            timeout=30
        )

        demisto.debug("[get_alert_by_id] Raw response:")
        demisto.debug(json.dumps(response, indent=2))

        data = response.get("data", [])
        if data:
            demisto.debug(f"[get_alert_by_id] Alert found: ID {alert_id}")
            return data[0]

        demisto.debug(f"[get_alert_by_id] No alert found for ID: {alert_id}")
        return None

    except Exception as e:
        demisto.error(f"[get_alert_by_id] Error during HTTP request: {e}")
        return None


def get_fetch_service_list(client, incident_collections, service_url, token):
    """
    Determines the list of services to fetch based on provided incident collections.

    Args:
        client: An instance of the client to communicate with the server.
        incident_collections: A list of incident collection names to filter the services.
        service_url: The base URL for the server.
        token: The API access token.

    If specific incident collections are provided (excluding "All collections"),
    it appends corresponding service names to `fetch_services`. Otherwise, it fetches
    all services using the client.
    """
    fetch_services = []
    if len(incident_collections) > 0 and "All collections" not in incident_collections:
        if "Darkweb Marketplaces" in incident_collections:
            fetch_services.append({"name": "darkweb_marketplaces"})
        if "Data Breaches" in incident_collections:
            fetch_services.append({"name": "darkweb_data_breaches"})
        if "Compromised Endpoints" in incident_collections:
            fetch_services.append({"name": "stealer_logs"})
        if "Compromised Cards" in incident_collections:
            fetch_services.append({"name": "compromised_cards"})
    else:
        fetch_services = client.get_all_services(token, service_url)
    return fetch_services


def get_fetch_severities(incident_severity):
    """
    Determines the list of severities to fetch based on provided incident severities.

    Args:
        incident_severity: A list of incident severity levels to filter the results.

    Returns:
        A list of severities to fetch. If specific severities are provided (excluding "All severities"),
        it returns the corresponding severities from the SEVERITIES mapping. Otherwise, it defaults to
        ["LOW", "MEDIUM", "HIGH"].
    """
    fetch_severities = []
    if len(incident_severity) > 0 and "All severities" not in incident_severity:
        for severity in incident_severity:
            fetch_severities.append(SEVERITIES.get(severity))
    else:
        fetch_severities = ["LOW", "MEDIUM", "HIGH"]
    return fetch_severities


def cyble_events(client, method, token, url, args, last_run, hide_cvv_expiry, incident_collections, incident_severity,
                 skip=True):
    """
    Entry point for fetching alerts from Cyble Vision.
    Calls the appropriate fetch function based on manual or scheduled execution.
    """
    demisto.debug("[cyble_events] Function called")

    if skip:
        return manual_fetch(client, args, token, url, incident_collections, incident_severity)

    input_params = {
        "order_by": args.get('order_by', "asc"),
        "skip": 0,
        "limit": MAX_ALERTS
    }

    initial_interval = demisto.params().get('first_fetch_timestamp', 1)
    if 'event_pull_start_date' not in last_run.keys():
        event_pull_start_date = datetime.utcnow() - timedelta(days=int(initial_interval))
        input_params['gte'] = event_pull_start_date.astimezone().isoformat()
    else:
        input_params['gte'] = last_run['event_pull_start_date']

    input_params['lte'] = datetime.utcnow().astimezone().isoformat()

    fetch_services = get_fetch_service_list(client, incident_collections, url, token)
    fetch_severities = get_fetch_severities(incident_severity)

    input_params.update({
        "severity": fetch_severities,
        "take": input_params["limit"],
        "services": fetch_services or [],
        "url": url,
        "hce": hide_cvv_expiry,
        "api_key": token,
        "lte": input_params['lte'],
        "gte": input_params['gte']
    })

    all_alerts, latest_created_time = migrate_data(client, input_params, False)
    last_run = {'event_pull_start_date': latest_created_time.astimezone().isoformat()}
    return all_alerts, last_run


def get_modified_remote_data_command(client, url, token, args, hide_cvv_expiry, incident_collections,
                                     incident_severity):
    demisto.debug("[get-modified-remote-data] Starting command...")

    try:
        remote_args = GetModifiedRemoteDataArgs(args)
        last_update = dateparser.parse(remote_args.last_update, settings={'TIMEZONE': 'UTC'})
        if last_update.tzinfo is None:
            last_update = last_update.replace(tzinfo=pytz.UTC)
        else:
            last_update = last_update.astimezone(pytz.UTC)

    except Exception as e:
        demisto.error(f"[get-modified-remote-data] Error parsing last_update: {e}")
        return GetModifiedRemoteDataResponse([])

    services = get_fetch_service_list(client, incident_collections, url, token)
    severities = get_fetch_severities(incident_severity)

    input_params = {
        "order_by": args.get('order_by', "asc"),
        "skip": 0,
        "limit": MAX_ALERTS,
        "take": MAX_ALERTS,
        "url": url,
        "api_key": token,
        "hce": hide_cvv_expiry,
        "services": services or [],
        "severity": severities or [],
        "gte": last_update.isoformat(),
        "lte": datetime.utcnow().replace(tzinfo=pytz.UTC).isoformat()
    }

    ids = client.get_ids_with_retry(
        service=services,
        input_params=input_params,
        is_update=True
    )

    if isinstance(ids, list):
        return GetModifiedRemoteDataResponse(ids)
    else:
        demisto.error("[get-modified-remote-data] Invalid response format")
        return GetModifiedRemoteDataResponse([])


def get_remote_data_command(client, url, token, args, incident_collections, incident_severity, hide_cvv_expiry):
    demisto.debug("[get-remote-data] Starting command")

    try:
        remote_args = GetRemoteDataArgs(args)
        alert_id = remote_args.remote_incident_id
        demisto.debug(f"[get-remote-data] Parsed alert_id: {alert_id}")
    except Exception as e:
        demisto.error(f"[get-remote-data] Error parsing args: {e}")
        return_error(f"[get-remote-data] Invalid arguments: {e}")
        return

    try:
        updated_incident = get_alert_payload_by_id(
            client=client,
            alert_id=alert_id,
            token=token,
            url=url,
            incident_collections=incident_collections,
            incident_severity=incident_severity,
            hide_cvv_expiry=hide_cvv_expiry
        )
    except Exception as e:
        demisto.error(f"[get-remote-data] Failed to fetch alert payload: {e}")
        return_error(f"[get-remote-data] Failed to fetch alert payload: {e}")
        return

    if not updated_incident:
        demisto.debug("[get-remote-data] No incident payload returned")
        return GetRemoteDataResponse(mirrored_object={}, entries=[])

    demisto.debug("[get-remote-data] Payload successfully retrieved")
    return GetRemoteDataResponse(
        mirrored_object=updated_incident,
        entries=[]
    )


def manual_fetch(client, args, token, url, incident_collections, incident_severity):
    demisto.debug("[manual_fetch] Manual run detected")

    gte = args.get('start_date')
    lte = args.get('end_date') or datetime.utcnow().astimezone().isoformat()

    try:
        gte = datetime.fromisoformat(gte).isoformat()
        lte = datetime.fromisoformat(lte).isoformat()
    except ValueError as e:
        raise DemistoException(f"[manual_fetch] Invalid date format: {e}")

    services = get_fetch_service_list(client, incident_collections, url, token) or []
    demisto.debug(f"[manual_fetch] Services to fetch: {services}")

    # Build the payload to be passed to the API, excluding transport-related values
    api_input_params = {
        "gte": gte,
        "lte": lte,
        "severity": get_fetch_severities(incident_severity),
        "order_by": args.get('order_by', "asc"),
        "skip": 0,
        "take": int(args.get("limit", DEFAULT_TAKE_LIMIT)),
    }

    alerts = fetch_few_alerts(client, api_input_params, services, url, token, is_update=False) or []

    return alerts


def scheduled_fetch(client, method, token, url, args, last_run, hide_cvv_expiry, incident_collections,
                    incident_severity):
    demisto.debug("[scheduled_fetch] Started with migrate_data")
    order_by = args.get('order_by', "asc")
    max_fetch = arg_to_number(demisto.params().get('max_fetch', 1))
    initial_interval = demisto.params().get('first_fetch_timestamp', 1)

    # Get the last fetch start date (event_pull_start_date)
    gte = last_run.get('event_pull_start_date')
    if not gte:
        gte = (datetime.utcnow() - timedelta(days=int(initial_interval))).astimezone()
    else:
        gte = isoparse(gte)  # Parse the date using isoparse (if not None)

    # Set the "lte" value to the current UTC time
    lte = datetime.utcnow().astimezone()

    input_params = {
        'gte': gte,
        'lte': lte,
        'order_by': order_by,
        'limit': MAX_ALERTS,
        'status': DEFAULT_STATUSES,
        'services': []
    }

    # Determine which services to fetch based on selected incident collections
    if incident_collections and "All collections" not in incident_collections:
        if "Darkweb Marketplaces" in incident_collections:
            input_params['services'].append("darkweb_marketplaces")
        if "Data Breaches" in incident_collections:
            input_params['services'].append("darkweb_data_breaches")
        if "Compromised Endpoints" in incident_collections:
            input_params['services'].append("stealer_logs")
        if "Compromised Cards" in incident_collections:
            input_params['services'].append("compromised_cards")

    # Determine severities
    if incident_severity and "All severities" not in incident_severity:
        input_params['severity'] = [SEVERITIES.get(sev) for sev in incident_severity]

    # Migrate data and get last fetched timestamp
    alerts, last_fetched = migrate_data(client, input_params, False)

    # Ensure that last_fetched is a datetime object
    if isinstance(last_fetched, tuple):
        last_fetched = last_fetched[0]  # Unpack if it's a tuple

    # Format the last fetched timestamp to ISO format
    new_last_run = {'event_pull_start_date': last_fetched.strftime("%Y-%m-%dT%H:%M:%S.%fZ")}
    demisto.debug(f"[scheduled_fetch] Completed migrate_data. New last_run: {new_last_run}")


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
            "0": "LOW",
            "0.5": "LOW",
            "1": "LOW",
            "2": "MEDIUM",
            "3": "HIGH",
            "4": "CRITICAL"
        }
        data = parsed_args.data
        incident_id, status, service, assignee_id, updated_severity = data.get('id'), data.get('status'), data.get(
            'service'), data.get('assignee_id'), str(data.get('severity'))
        updated_event = {
            "id": incident_id,
            "service": service
        }
        if status in INCIDENT_STATUS:
            updated_event["status"] = INCIDENT_STATUS.get(status)
        if assignee_id:
            updated_event["assignee_id"] = assignee_id
        if updated_severity:
            updated_event["user_severity"] = severities.get(updated_severity)

        client.update_alert({"alerts": [updated_event]}, url, token)


def get_mapping_fields(client, token, url):  # need to be refactored - @TODO
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
    subscribed_services = client.get_all_services(token, base_url)
    service_name_list = []

    for subscribed_service in subscribed_services:
        service_name_list.append({"name": subscribed_service['name']})

    markdown = tableToMarkdown('Alerts Group Details:', service_name_list)
    return CommandResults(
        readable_output=markdown,
        outputs_prefix='CybleEvents.ServiceList',
        raw_response=service_name_list,
        outputs=service_name_list
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


def main():
    """
    Main function to execute Cyble Events commands in Cortex XSOAR.

    This function initializes the client using parameters provided in the
    integration settings, and executes commands based on the input from
    the Cortex XSOAR platform. Commands supported include testing the
    integration, fetching incidents, updating remote systems, fetching
    mapping fields, and various Cyble Vision specific commands such as
    fetching subscribed services, alert groups, IOCs, and alerts.

    Raises:
        NotImplementedError: If a command is not implemented.
        Exception: If there is an error executing a command.

    Returns: None
    """

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
            proxy=proxy
        )
        args = demisto.args()

        if demisto.command() == "test-module":
            url = base_url + str(ROUTES[COMMAND[demisto.command()]])
            return_results(test_response(client, "GET", url, token))

        elif demisto.command() == 'fetch-incidents':
            last_run = demisto.getLastRun()

            url = base_url + str(ROUTES[COMMAND[demisto.command()]])
            data, next_run = cyble_events(client, 'POST', token, url, args, last_run,
                                          hide_cvv_expiry, incident_collections, incident_severity, False)

            demisto.setLastRun(next_run)
            demisto.incidents(data)

        elif demisto.command() == 'update-remote-system':
            if mirror:
                url = base_url + str(ROUTES[COMMAND[demisto.command()]])
                return_results(update_remote_system(client, 'PUT', token, args, url))
            return

        elif demisto.command() == 'get-mapping-fields':
            url = base_url + str(ROUTES[COMMAND[demisto.command()]])
            return_results(get_mapping_fields(client, token, url))

        elif demisto.command() == "cyble-vision-subscribed-services":
            return_results(fetch_subscribed_services_alert(client, "GET", base_url, token))

        elif demisto.command() == 'cyble-vision-fetch-iocs':
            validate_iocs_input(args)
            url = base_url + str(ROUTES[COMMAND[demisto.command()]])
            command_results = cyble_fetch_iocs(client, 'GET', token, args, url)
            return_results(command_results)



        elif demisto.command() == 'cyble-vision-fetch-alerts':
            url = base_url + str(ROUTES[COMMAND[demisto.command()]])
            lst_alerts = cyble_events(client, 'POST', token, url, args, {},
                                      hide_cvv_expiry, incident_collections, incident_severity, False)
            return_results(CommandResults(
                readable_output="Fetched alerts successfully.",
                outputs_prefix='CybleEvents.Alerts',
                raw_response=lst_alerts,
                outputs=lst_alerts
            ))


        elif demisto.command() == 'get-modified-remote-data':
            url = base_url + str(ROUTES[COMMAND[demisto.command()]])
            return_results(
                get_modified_remote_data_command(client, url, token, args, hide_cvv_expiry, incident_collections,
                                                 incident_severity)
            )


        elif demisto.command() == 'get-remote-data':
            url = base_url + str(ROUTES[COMMAND[demisto.command()]])
            return_results(
                get_remote_data_command(
                    client, url, token, args, incident_collections, incident_severity, hide_cvv_expiry
                )
            )

        else:
            raise NotImplementedError(f'{demisto.command()} command is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()