from CommonServerPython import *
from typing import Any

""" IMPORTS """
import requests
from datetime import datetime, timedelta
import pytz
import urllib3
import dateparser
import json
from collections.abc import Sequence

from dateutil.parser import parse as parse_date

import concurrent.futures

UTC = pytz.UTC

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

MAX_ALERTS = 500
LIMIT_EVENT_ITEMS = 200
MAX_RETRIES = 3
MAX_THREADS = 1
MIN_MINUTES_TO_FETCH = 10
DEFAULT_REQUEST_TIMEOUT = 600
DEFAULT_TAKE_LIMIT = 5
DEFAULT_STATUSES = ["VIEWED", "UNREVIEWED", "CONFIRMED_INCIDENT", "UNDER_REVIEW", "INFORMATIONAL"]
SAMPLE_ALERTS = 10
INCIDENT_SEVERITY = {"unknown": 0, "informational": 0.5, "low": 1, "medium": 2, "high": 3, "critical": 4}
INCIDENT_STATUS = {
    "Unreviewed": "UNREVIEWED",
    "Viewed": "VIEWED",
    "False Positive": "FALSE_POSITIVE",
    "Confirmed Incident": "CONFIRMED_INCIDENT",
    "Under Review": "UNDER_REVIEW",
    "Informational": "INFORMATIONAL",
    "Resolved": "RESOLVED",
    "Remediation in Progress": "REMEDIATION_IN_PROGRESS",
    "Remediation not Required": "REMEDIATION_NOT_REQUIRED",
}
SEVERITIES = {"Low": "LOW", "Medium": "MEDIUM", "High": "HIGH", "Critical": "HIGH", "Informational": "LOW", "Unknown": "LOW"}
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
    "get-mapping-fields": "alerts",
    "get-modified-remote-data": "alerts",
    "get-remote-data": "alerts",
}


def get_headers(alerts_api_key: str) -> dict:
    return {"Content-Type": "application/json", "Authorization": f"Bearer {alerts_api_key}"}


def encode_headers(headers: dict) -> dict:
    return {k: v.encode("utf-8") for k, v in headers.items()}


def get_event_format(event):
    """
    Converts an event from Cyble to a format suitable for Demisto.
    :param event: The event to format
    :return: A dictionary with the event's information
    """
    return {
        "name": event.get("name"),
        "severity": event.get("severity"),
        "rawJSON": json.dumps(event),
        "event_id": event.get("event_id"),
        "keyword": event.get("keyword"),
        "created": event.get("created_at"),
    }


def get_alert_payload(service, input_params: dict[str, Any], is_update=False):
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
                    "gte": ensure_aware(datetime.fromisoformat(input_params["gte"])).strftime("%Y-%m-%dT%H:%M:%S+00:00"),
                    "lte": ensure_aware(datetime.fromisoformat(input_params["lte"])).strftime("%Y-%m-%dT%H:%M:%S+00:00"),
                },
                "status": [
                    "VIEWED",
                    "UNREVIEWED",
                    "CONFIRMED_INCIDENT",
                    "UNDER_REVIEW",
                    "INFORMATIONAL",
                    "REMEDIATION_IN_PROGRESS",
                    "REMEDIATION_NOT_REQUIRED",
                    "FALSE_POSITIVE",
                ],
                "severity": input_params["severity"],
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
    client, alert_id: str, token: str, url: str, incident_collections: dict, incident_severity: dict, hide_cvv_expiry: bool
) -> dict:
    demisto.debug(f"[get_alert_payload_by_id] Called with alert_id: {alert_id}")

    try:
        alert = get_alert_by_id(client, alert_id, token, url)
        if not alert:
            error_msg = f"[get_alert_payload_by_id] Alert with ID {alert_id} could not be fetched."
            demisto.error(error_msg)
            raise ValueError(error_msg)

        if "service" not in alert:
            error_msg = f"[get_alert_payload_by_id] Alert ID {alert_id} is missing required 'service' field."
            demisto.error(error_msg)
            raise ValueError(error_msg)

        demisto.debug("[get_alert_payload_by_id] Alert fetched successfully")

        incidents = format_incidents([alert], hide_cvv_expiry)
        if not incidents:
            error_msg = f"[get_alert_payload_by_id] Formatting failed for alert ID {alert_id}"
            demisto.error(error_msg)
            raise ValueError(error_msg)

        incident = incidents[0]
        incident["rawJSON"] = json.dumps(alert)

        demisto.debug("[get_alert_payload_by_id] Converted alert to incident using format_incidents")
        return incident

    except Exception as e:
        # Keep the log for debugging
        demisto.error(f"[get_alert_payload_by_id] Exception occurred: {str(e)}")
        raise  # Propagate the exception to the caller


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
            if hide_cvv_expiry and alert["service"] == "compromised_cards":
                alert["data"]["bank"]["card"]["cvv"] = "xxx"
                alert["data"]["bank"]["card"]["expiry"] = "xx/xx/xxxx"
            alert_details = {
                "name": "Cyble Vision Alert on {}".format(alert.get("service")),
                "event_type": "{}".format(alert.get("service")),
                "severity": INCIDENT_SEVERITY.get((alert.get("user_severity") or alert.get("severity") or "").lower()),
                "event_id": "{}".format(alert.get("id")),
                "data_message": json.dumps(alert.get("data")),
                "keyword": "{}".format(alert.get("keyword_name")),
                "created_at": "{}".format(alert.get("created_at")),
                "status": REVERSE_INCIDENT_STATUS.get(alert.get("status")),
                "mirrorInstance": demisto.integrationInstance(),
            }
            if alert.get("service") == "compromised_cards":
                card_details = alert["data"]["bank"]["card"]
                alert_details.update(
                    {
                        "card_brand": card_details.get("brand"),
                        "card_no": card_details.get("card_no"),
                        "card_cvv": card_details.get("cvv"),
                        "card_expiry": card_details.get("expiry"),
                        "card_level": card_details.get("level"),
                        "card_type": card_details.get("type"),
                    }
                )
            elif alert.get("service") == "stealer_logs":
                content = alert["data"].get("content")
                if content:
                    alert_details.update(
                        {
                            "application": content.get("Application"),
                            "password": content.get("Password"),
                            "url": content.get("URL"),
                            "username": content.get("Username"),
                        }
                    )
                alert_details.update({"filename": alert["data"]["filename"]})
            events.append(alert_details)
        except Exception as e:
            error_msg = f"Unable to format alert (ID: {alert.get('id', 'unknown')}), error: {e}"
            demisto.error(error_msg)
            raise

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
                if method == "POST" or method == "PUT":
                    response = requests.request(method, url, headers=headers, json=payload)
                else:
                    response = requests.request(method, url, headers=headers, params=payload)

                response.raise_for_status()

                response_json = response.json()
                return response_json["data"]
            except Exception:
                pass
        return None

    def make_request(self, url, api_key, method="GET", payload_json=None, params=None):
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
        headers = get_headers(api_key)
        encoded_headers = encode_headers(headers)
        return requests.request(
            method, url, data=payload_json, headers=encoded_headers, params=params, timeout=DEFAULT_REQUEST_TIMEOUT
        )

    def get_data(self, service, input_params, is_update=False):
        """
        Sends an HTTP POST request to the given host with the provided payload and API key,
        and logs errors if the request fails.

        Logs the final payload, URL, API key, and checks the response.

        :param service: The service to fetch data from
        :param input_params: A dictionary containing parameters for the API call
        :param is_update: Whether this is an update fetch (based on updated_at
         instead of created_at)
        :return: The JSON response from the request as a dictionary,
         or an empty dictionary if the request fails
        """
        payload = get_alert_payload(service, input_params, is_update)
        payload_json = json.dumps(payload)
        url = input_params.get("url")
        alerts_api_key = input_params.get("api_key")

        demisto.debug(f"[get_data] Sending request to {url} for service: {service}, is_update: {is_update}")

        if not url or not alerts_api_key:
            raise ValueError("Missing required URL or API key in input_params.")
        try:
            demisto.debug(f"[get_data] final payload is: {payload_json}")
            response = self.make_request(url, alerts_api_key, "POST", payload_json)
            demisto.debug(f"[get_data] Response status code: {response.status_code}")

        except Exception as request_error:
            raise Exception(f"HTTP request failed for service '{service}': {str(request_error)}")

        if response.status_code != 200:
            raise Exception(
                f"Failed to fetch data from {service}. Status code: {response.status_code}, Response text: {response.text}"
            )

        try:
            json_response = response.json()
            demisto.debug(f"[get_data] JSON response received with keys: {list(json_response.keys())}")
            return json_response
        except ValueError as json_error:
            raise Exception(f"Invalid JSON response from {service}: {str(json_error)}")

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
                raise Exception(f"Wrong status code: {response.status_code}")
            response = response.json()

            if "data" in response and isinstance(response["data"], Sequence):
                demisto.debug(f"Received services: {json.dumps(response['data'], indent=2)}")
                return response["data"]

            else:
                raise Exception("Wrong Format for services response")
        except Exception as e:
            raise Exception(f"Failed to get services: {str(e)}")

    def insert_data_in_cortex(self, service, input_params, is_update):
        """
        Fetches and inserts data into Cortex XSOAR from the given service based on the given parameters.

        :param service: The service to fetch data from
        :param input_params: A dictionary containing parameters for the API call,
        including the API key, base URL, skip, take, and time range
        :return: The latest created time of the data inserted
        """
        latest_created_time = datetime.utcnow().astimezone(pytz.UTC)
        input_params.update({"skip": 0, "take": int(input_params["limit"])})
        all_incidents = []

        try:
            while True:
                try:
                    response = self.get_data(service, input_params, is_update)
                    demisto.debug(
                        "[insert_data_in_cortex] Received response for "
                        f"skip: {input_params['skip']}, "
                        f"items: {len(response.get('data', [])) if 'data' in response else 'N/A'}"
                    )

                except Exception as e:
                    demisto.error(f"[insert_data_in_cortex] get_data failed for service: {service} with error: {str(e)}")
                    raise

                input_params["skip"] += input_params["take"]

                if "data" in response and isinstance(response["data"], Sequence):
                    if not response["data"]:
                        demisto.debug("[insert_data_in_cortex] No more data, exiting loop")
                        break

                    try:
                        latest_created_time = parse_date(response["data"][-1].get("created_at")) + timedelta(microseconds=1)
                        demisto.debug(f"[insert_data_in_cortex] Updated latest_created_time: {latest_created_time}")

                    except Exception as e:
                        demisto.error(f"[insert_data_in_cortex] Failed to parse created_at: {str(e)}")
                        raise

                    try:
                        events, incidentsArr = format_incidents(response["data"], input_params["hce"]), []
                        demisto.debug(f"[insert_data_in_cortex] Formatting incidents, total events: {len(events)}")
                        for event in events:
                            try:
                                incident = get_event_format(event)
                                incidentsArr.append(incident)
                            except Exception as e:
                                demisto.error(f"[insert_data_in_cortex] get_event_format failed: {str(e)}")
                                continue
                    except Exception as e:
                        demisto.error(f"[insert_data_in_cortex] format_incidents failed: {str(e)}")
                        raise

                    all_incidents.extend(incidentsArr)
                    demisto.debug(f"[insert_data_in_cortex] Pushing {len(incidentsArr)} incidents to Cortex")
                    demisto.incidents(incidentsArr)

                else:
                    raise Exception(
                        "[insert_data_in_cortex] Unable to fetch data for "
                        f"gte: {input_params['gte']}, "
                        f"lte: {input_params['lte']}, "
                        f"skip: {input_params['skip']}, "
                        f"take: {input_params['take']}"
                    )

        except Exception as e:
            demisto.error(f"[insert_data_in_cortex] Failed for service '{service}': {str(e)}")
            raise

        demisto.debug(f"[insert_data_in_cortex] Completed. Total incidents pushed: {len(all_incidents)}")
        return all_incidents, latest_created_time

    def get_data_with_retry(self, service, input_params, is_update=False):
        """
        Splits time range into 1-day chunks and fetches data, inserting it into Cortex.
        Returns a tuple of (alerts, latest_created_time).
        """

        gte = parse_date(input_params["gte"])
        lte = parse_date(input_params["lte"])
        demisto.debug(f"[get_data_with_retry] Full time range: gte={gte}, lte={lte}")

        latest_created_time = None
        all_alerts = []

        current_start = gte
        while current_start <= lte:
            current_end = min(current_start + timedelta(days=1), lte)

            demisto.debug(f"[get_data_with_retry] Processing 1-day chunk: {current_start} to {current_end}")

            current_params = {**input_params, "gte": current_start.isoformat(), "lte": current_end.isoformat()}
            response = self.get_data(service, current_params, is_update=is_update)

            if "data" in response:
                curr_alerts, curr_time = self.insert_data_in_cortex(service, current_params, is_update)
                demisto.debug(f"[get_data_with_retry] Retrieved {len(curr_alerts)} alerts, curr_time: {curr_time}")

                all_alerts.extend(curr_alerts)

                if latest_created_time is None:
                    latest_created_time = curr_time
                else:
                    latest_created_time = max(latest_created_time, curr_time)
            else:
                demisto.debug(f"[get_data_with_retry] No data returned for chunk: {current_start} to {current_end}")

            current_start = current_end + timedelta(microseconds=1)

        if latest_created_time is None:
            latest_created_time = datetime.utcnow()
            demisto.debug("No data processed, using current time as latest_created_time")

        demisto.debug(
            f"[get_data_with_retry] Finished. Total alerts: {len(all_alerts)}, latest_created_time: {latest_created_time}"
        )
        return all_alerts, latest_created_time + timedelta(microseconds=1)

    def get_ids_with_retry(self, service, input_params, is_update=False):
        """
        Recursively splits time ranges and fetches data, inserting it into Cortex.
        Returns a tuple of (alerts, latest_created_time).
        """

        gte = parse_date(input_params["gte"])
        lte = parse_date(input_params["lte"])

        que = [[gte, lte]]
        ids = []

        while que:
            current_gte, current_lte = que.pop(0)

            # Serialize datetime objects to strings BEFORE placing in input_params
            input_params["gte"] = current_gte.isoformat()
            input_params["lte"] = current_lte.isoformat()

            response = self.get_data(service, input_params, is_update=is_update)
            if "data" in response:
                for alert in response["data"]:
                    alert_id = alert.get("id")
                    if isinstance(alert_id, str) and alert_id.strip():
                        ids.append(alert_id)
            elif time_diff_in_mins(current_gte, current_lte) >= MIN_MINUTES_TO_FETCH:
                mid_datetime = current_gte + (current_lte - current_gte) / 2
                que.extend([[current_gte, mid_datetime], [mid_datetime + timedelta(microseconds=1), current_lte]])
            else:
                demisto.debug(f"Unable to fetch data for gte: {current_gte} to lte: {current_lte}")
        demisto.debug(f"ids:{ids}")

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
            response = self.make_request(url, api_key, "PUT", payload_json)
            if response.status_code != 200:
                return_error(f"[update_alert] Unexpected status code: {response.status_code}, response: {response.text}")
        except Exception as e:
            return_error(f"[update_alert] Exception while updating alert: {str(e)}")


def validate_iocs_input(args):
    """
    Validates the input arguments for the fetch-iocs command.

    :param args: A dictionary of input arguments.
    :return: None
    :raises ValueError: If the input arguments are invalid.
    """
    try:
        if int(args.get("from")) < 0:
            raise ValueError(f"The parameter from has a negative value, from: {arg_to_number(args.get('from'))}'")
        limit, date_format = int(args.get("limit", 1)), "%Y-%m-%d"
        if args.get("start_date") and args.get("end_date"):
            _start_date, _end_date = (
                datetime.strptime(args.get("start_date"), date_format),
                datetime.strptime(args.get("end_date"), date_format),
            )
        else:
            _start_date, _end_date = datetime(1, 1, 1, 0, 0), datetime(1, 1, 1, 0, 0)
        if limit <= 0 or limit > 100:
            raise ValueError(f"The limit argument number should, up to 100, given limit: {limit}")
        if _start_date > _end_date:
            raise ValueError(f"Start date {args.get('start_date')} cannot be after end date {args.get('end_date')}")
    except Exception as e:
        demisto.error(f"Failed to process validate_iocs_input with {str(e)}")


def alert_input_structure(input_params):
    input_params_alerts = {
        "orderBy": [{"created_at": input_params["order_by"]}],
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
            "user_severity": True,
        },
        "skip": input_params["from_da"],
        "take": input_params["limit"],
        "withDataMessage": True,
        "where": {
            "created_at": {
                "gte": input_params["start_date"],
                "lte": input_params["end_date"],
            },
            "status": {"in": ["VIEWED", "UNREVIEWED", "CONFIRMED_INCIDENT", "UNDER_REVIEW", "INFORMATIONAL"]},
        },
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
    headers = {"Authorization": "Bearer " + token}
    response = client.get_response(url, headers, input_params, method)
    return response


def ensure_aware(dt: datetime) -> datetime:
    """Ensure datetime is timezone-aware in UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=pytz.UTC)
    return dt.astimezone(pytz.UTC)


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
    subscribed_services = client.get_all_services(token, base_url)
    service_name_list = []
    if subscribed_services:
        for subscribed_service in subscribed_services:
            service_name_list.append({"name": subscribed_service["name"]})
    return service_name_list


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
            fetch_services.append("darkweb_marketplaces")
        if "Data Breaches" in incident_collections:
            fetch_services.append("darkweb_data_breaches")
        if "Compromised Endpoints" in incident_collections:
            fetch_services.append("stealer_logs")
        if "Compromised Cards" in incident_collections:
            fetch_services.append("compromised_cards")
    else:
        subscribed_services = client.get_all_services(token, service_url)
        if subscribed_services:
            fetch_services = [service["name"] for service in subscribed_services]

    return fetch_services


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
    try:
        subscribed_services = client.get_all_services(token, base_url)
        service_name_list = []

        for subscribed_service in subscribed_services:
            service_name_list.append({"name": subscribed_service["name"]})

        markdown = tableToMarkdown("Alerts Group Details:", service_name_list)
        return CommandResults(
            readable_output=markdown,
            outputs_prefix="CybleEvents.ServiceList",
            raw_response=service_name_list,
            outputs=service_name_list,
        )
    except Exception as e:
        return_error(f"Failed to fetch subscribed services: {str(e)}")


def test_response(client, method, base_url, token):
    """
    Test the integration state
    """
    try:
        # The test mocks this specific endpoint
        url_suffix = "/y/tpi/cortex/alerts"
        headers = {"Authorization": f"Bearer {token}"}

        response = client._http_request(method=method, url_suffix=url_suffix, headers=headers)

        if response:
            return "ok"
        else:
            raise Exception("failed to connect")
    except Exception as e:
        demisto.error(f"Failed to connect: {e}")
        raise Exception("failed to connect")


def migrate_data(client: Client, input_params: dict[str, Any], is_update=False):
    """
    Migrates data from cyble to demisto cortex.

    Args:
        client: instance of client to communicate with server
        input_params: dict containing the parameters for the migration, including services and their associated parameters
        is_update: Boolean flag indicating whether this is an update (used for get-modified-remote-data)

    Returns: the max of the last fetched timestamp
    """
    # Add type check and default value to prevent indexing errors

    demisto.debug(f"[migrate_data] Function called with is_update={is_update}")
    demisto.debug(f"[migrate_data] input_params: {json.dumps(input_params)}")

    services = input_params.get("services", [])
    if not services:
        demisto.debug("[migrate_data] No services found in input_params. Returning empty alert list.")
        demisto.debug("No services found in input_params")
        return [], datetime.utcnow()

    demisto.debug(f"[migrate_data] Services to process: {services}")

    chunkedServices = [services[i : i + MAX_THREADS] for i in range(0, len(services), MAX_THREADS)]
    last_fetched = ensure_aware(datetime.utcnow())

    all_alerts = []

    try:
        for chunk in chunkedServices:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = [executor.submit(client.get_data_with_retry, service, input_params, is_update) for service in chunk]
            for future in concurrent.futures.as_completed(futures):
                try:
                    alerts, fetched_time = future.result()
                    demisto.debug(f"[migrate_data] Fetched {len(alerts)} alerts. fetched_time: {fetched_time}")
                    all_alerts.extend(alerts)
                    if isinstance(fetched_time, datetime):
                        last_fetched = max(last_fetched, ensure_aware(fetched_time))
                except Exception as inner_e:
                    demisto.error(f"[migrate_data] Error in future: {str(inner_e)}")
                    return_error(f"[migrate_data] Failed to process service thread: {str(inner_e)}")

    except Exception as e:
        return_error(f"[migrate_data] Migration failed: {str(e)}")

    return all_alerts, last_fetched


def fetch_few_alerts(client, input_params, services, url, token, is_update=False):
    result = []
    input_params["take"] = SAMPLE_ALERTS  # override limit for sample
    demisto.debug(f"[fetch_few_alerts] Updated 'take' to SAMPLE_ALERTS ({SAMPLE_ALERTS})")

    for service in services:
        try:
            # Append transport details only for internal use by get_data
            input_params_with_context = input_params.copy()
            input_params_with_context["url"] = url
            input_params_with_context["api_key"] = token

            response = client.get_data(service, input_params_with_context, is_update=is_update)

            if "data" in response and isinstance(response["data"], Sequence):
                demisto.debug(f"[fetch_few_alerts] Received {len(response['data'])} alerts")

                hce = input_params.get("hce", False)
                events = format_incidents(response["data"], hce)

                for event in events:
                    formatted_event = get_event_format(event)
                    result.append(formatted_event)
            else:
                demisto.debug("[fetch_few_alerts] No valid data in response")
        except Exception as e:
            return_error(f"[fetch_few_alerts] Failed to fetch data from service {service}: {e}")

        if result:
            break

    demisto.debug(f"[fetch_few_alerts] Total alerts returned: {len(result)}")
    return result


def build_get_alert_payload(alert_id):
    """
    Builds the payload for fetching an alert by ID.
    """
    return {
        "filters": {"id": [alert_id]},
        "excludes": {"status": ["FALSE_POSITIVE"]},
        "orderBy": [{"created_at": "desc"}],
        "skip": 0,
        "take": 1,
        "taggedAlert": False,
        "withDataMessage": True,
        "countOnly": False,
    }


def build_auth_headers(token):
    """
    Builds the authorization headers for the API request.
    """
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


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
            method="POST", url_suffix="/y/tpi/cortex/alerts", headers=headers, json_data=payload, timeout=30
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
        raise DemistoException(f"[get_alert_by_id] Error during HTTP request: {str(e)}")


def update_alert_data_command(client: Client, url: str, token: str, args: Dict[str, Any]) -> CommandResults:
    """
    Update alert data (status/severity) on Cyble Vision platform for one or more alerts.
    """
    demisto.debug(f"[update_alert_data_command] Raw args: {args}")

    ids = argToList(args.get("ids"))
    statuses = argToList(args.get("status")) if args.get("status") else []
    severities = argToList(args.get("severity")) if args.get("severity") else []

    demisto.debug(f"[update_alert_data_command] Parsed ids: {ids}")
    demisto.debug(f"[update_alert_data_command] Parsed statuses: {statuses}")
    demisto.debug(f"[update_alert_data_command] Parsed severities: {severities}")

    if not statuses and not severities:
        raise DemistoException("At least one of 'status' or 'severity' must be provided.")

    if statuses and len(statuses) not in [1, len(ids)]:
        raise DemistoException("Number of statuses must be 1 or equal to the number of ids.")
    if severities and len(severities) not in [1, len(ids)]:
        raise DemistoException("Number of severities must be 1 or equal to the number of ids.")

    alerts_payload = []

    for idx, alert_id in enumerate(ids):
        demisto.debug(f"[update_alert_data_command] Processing alert ID: {alert_id}")

        alert = get_alert_by_id(client, alert_id, token, url)
        if not alert:
            demisto.debug(f"Alert ID {alert_id} not found. Skipping.")
            continue

        alert_payload = {"id": alert_id, "service": alert.get("service")}

        if statuses:
            alert_payload["status"] = statuses[0] if len(statuses) == 1 else statuses[idx]
        if severities:
            alert_payload["user_severity"] = severities[0] if len(severities) == 1 else severities[idx]

        demisto.debug(f"[update_alert_data_command] Payload for alert ID {alert_id}: {alert_payload}")

        alerts_payload.append(alert_payload)

    if not alerts_payload:
        raise DemistoException("No valid alerts found to update.")

    payload = {"alerts": alerts_payload}
    update_url = url + "/y/tpi/cortex/alerts"

    demisto.debug(f"[update_alert_data_command] Final Payload: {payload}")

    client.update_alert(payload, update_url, token)

    return CommandResults(
        readable_output=f"✅ Updated {len(alerts_payload)} alert(s) successfully.",
        outputs_prefix="CybleEvents.AlertUpdate",
        outputs_key_field="id",
        outputs=alerts_payload,
    )


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


def get_gte_limit(curr_gte: str) -> str:
    server_gte = datetime.utcnow() - timedelta(days=7)
    return max(curr_gte, server_gte.astimezone(pytz.UTC).isoformat())


def cyble_events(client, method, token, url, args, last_run, hide_cvv_expiry, incident_collections, incident_severity, skip=True):
    """
    Entry point for fetching alerts from Cyble Vision.
    Calls the appropriate fetch function based on manual or scheduled execution.
    """
    demisto.debug("[cyble_events] Function called")

    if skip:
        return manual_fetch(client, args, token, url, incident_collections, incident_severity)

    input_params = {"order_by": args.get("order_by", "asc"), "skip": 0, "limit": MAX_ALERTS}
    demisto.debug("[cyble_events] skip=False, proceeding with scheduled fetch")
    demisto.debug(f"[cyble_events] Initial input_params: {input_params}")

    initial_interval = demisto.params().get("first_fetch_timestamp", 1)
    if "event_pull_start_date" not in last_run:
        event_pull_start_date = datetime.utcnow().astimezone(pytz.UTC) - timedelta(days=int(initial_interval))
        input_params["gte"] = get_gte_limit(event_pull_start_date.isoformat())
        demisto.debug(f"[cyble_events] event_pull_start_date not in last_run, setting to: {event_pull_start_date.isoformat()}")

    else:
        input_params["gte"] = get_gte_limit(last_run["event_pull_start_date"])
        demisto.debug(f"[cyble_events] event_pull_start_date found in last_run: {input_params['gte']}")

    input_params["lte"] = datetime.utcnow().astimezone(pytz.UTC).isoformat()

    fetch_services = get_fetch_service_list(client, incident_collections, url, token)

    demisto.debug(f"[cyble_events] Retrieved fetch_services: {fetch_services}")

    fetch_severities = get_fetch_severities(incident_severity)
    demisto.debug(f"[cyble_events] Retrieved fetch_severities: {fetch_severities}")

    demisto.debug(f"[cyble_events] gte: {input_params['gte']}, lte: {input_params['lte']}")

    input_params.update(
        {
            "severity": fetch_severities,
            "take": input_params["limit"],
            "services": fetch_services or [],
            "url": url,
            "hce": hide_cvv_expiry,
            "api_key": token,
            "lte": input_params["lte"],
            "gte": input_params["gte"],
        }
    )
    demisto.debug(f"[cyble_events] Final input_params after update: {json.dumps(input_params)}")

    all_alerts, latest_created_time = migrate_data(client, input_params, False)
    demisto.debug(
        f"[cyble_events] migrate_data returned {len(all_alerts)} alerts, latest_created_time: {latest_created_time.isoformat()}"
    )

    last_run = {"event_pull_start_date": latest_created_time.astimezone().isoformat()}
    demisto.debug(f"[cyble_events] Updated last_run: {last_run}")

    return all_alerts, last_run


def get_modified_remote_data_command(client, url, token, args, hide_cvv_expiry, incident_collections, incident_severity):
    demisto.debug("[get-modified-remote-data] Starting command...")

    try:
        remote_args = GetModifiedRemoteDataArgs(args)
        last_update = dateparser.parse(remote_args.last_update, settings={"TIMEZONE": "UTC"})

        if last_update is None:
            demisto.error("[get-modified-remote-data] last_update is None after parsing")
            return GetModifiedRemoteDataResponse([])

        if last_update.tzinfo is None:
            last_update = last_update.replace(tzinfo=pytz.UTC)
        else:
            last_update = last_update.astimezone(pytz.UTC)

    except Exception as e:
        return_error(f"[get-modified-remote-data] Error parsing last_update: {e}")

    services = get_fetch_service_list(client, incident_collections, url, token)
    severities = get_fetch_severities(incident_severity)

    if last_update is None:
        raise ValueError("Missing required parameter: 'last_update' must not be None")

    input_params = {
        "order_by": args.get("order_by", "asc"),
        "skip": 0,
        "limit": MAX_ALERTS,
        "take": MAX_ALERTS,
        "url": url,
        "api_key": token,
        "hce": hide_cvv_expiry,
        "services": services or [],
        "severity": severities or [],
        "gte": last_update.isoformat(),
        "lte": datetime.utcnow().replace(tzinfo=pytz.UTC).isoformat(),
    }
    ids = client.get_ids_with_retry(service=services, input_params=input_params, is_update=True)

    if isinstance(ids, list):
        return GetModifiedRemoteDataResponse(ids)
    else:
        return_error("[get-modified-remote-data] Invalid response format: Expected list of IDs")
    return GetModifiedRemoteDataResponse([])


SEVERITY_MAP = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

REVERSE_INCIDENT_STATUS = {
    "UNREVIEWED": "Unreviewed",
    "VIEWED": "Viewed",
    "FALSE_POSITIVE": "False Positive",
    "FALSE POSITIVE": "False Positive",
    "CONFIRMED_INCIDENT": "Confirmed Incident",
    "CONFIRMED INCIDENT": "Confirmed Incident",
    "UNDER_REVIEW": "Under Review",
    "UNDER REVIEW": "Under Review",
    "INFORMATIONAL": "Informational",
    "RESOLVED": "Resolved",
    "REMEDIATION_IN_PROGRESS": "Remediation in Progress",
    "REMEDIATION IN PROGRESS": "Remediation in Progress",
    "REMEDIATION_NOT_REQUIRED": "Remediation not Required",
    "REMEDIATION NOT REQUIRED": "Remediation not Required",
}


def get_remote_data_command(client, url, token, args, incident_collections, incident_severity, hide_cvv_expiry):
    demisto.debug("[get-remote-data] Starting command")

    try:
        remote_args = GetRemoteDataArgs(args)
        alert_id = remote_args.remote_incident_id
        demisto.debug(f"[get-remote-data] Parsed alert_id: {alert_id}")
    except Exception as e:
        return_error(f"[get-remote-data] Invalid arguments: {e}")
        return None

    try:
        updated_incident = get_alert_payload_by_id(
            client=client,
            alert_id=alert_id,
            token=token,
            url=url,
            incident_collections=incident_collections,
            incident_severity=incident_severity,
            hide_cvv_expiry=hide_cvv_expiry,
        )
    except Exception as e:
        demisto.error(f"[get-remote-data] Failed to fetch alert payload: {e}")
        return_error(f"[get-remote-data] Failed to fetch alert payload: {e}")
        return None

    if not updated_incident:
        demisto.debug("[get-remote-data] No incident payload returned")
        return GetRemoteDataResponse(mirrored_object={}, entries=[])

    demisto.debug("[get-remote-data] Payload successfully retrieved")

    severity = updated_incident.get("severity")
    if severity is not None:
        demisto.debug(f"[get-remote-data] Received severity: {severity}")
    else:
        demisto.debug("[get-remote-data] Missing severity field in incident payload")

    # Map status from Cyble to human-readable format
    status = updated_incident.get("status")
    demisto.debug(f"[get-remote-data] status before : {status}")

    if status:
        status = status.upper()
        demisto.debug(f"[get-remote-data] status upper: {status}")
    else:
        demisto.debug("[get-remote-data] status is None or empty, skipping upper conversion")

    if status in REVERSE_INCIDENT_STATUS:
        updated_incident["cybleeventsv2status"] = REVERSE_INCIDENT_STATUS[status]
        demisto.debug(f"[get-remote-data] Received status: {REVERSE_INCIDENT_STATUS[status]}")
    else:
        demisto.debug(f"[get-remote-data] Unknown status received: {status}")
    demisto.debug(f"[get-remote-data] updated_incident: {updated_incident}")

    return GetRemoteDataResponse(mirrored_object=updated_incident, entries=[])


def manual_fetch(client, args, token, url, incident_collections, incident_severity):
    demisto.debug("[manual_fetch] Manual run detected")

    gte = args.get("start_date")
    lte = args.get("end_date") or datetime.utcnow().astimezone().isoformat()

    try:
        gte = datetime.fromisoformat(gte).isoformat()
        lte = datetime.fromisoformat(lte).isoformat()
    except ValueError as e:
        raise DemistoException(f"[manual_fetch] Invalid date format: {e}")

    services = get_fetch_service_list(client, incident_collections, url, token) or []

    # Build the payload to be passed to the API, excluding transport-related values
    api_input_params = {
        "gte": gte,
        "lte": lte,
        "severity": get_fetch_severities(incident_severity),
        "order_by": args.get("order_by", "asc"),
        "skip": 0,
        "take": int(args.get("limit", DEFAULT_TAKE_LIMIT)),
    }

    alerts = fetch_few_alerts(client, api_input_params, services, url, token, is_update=False) or []

    return alerts


def update_remote_system(client, method, token, args, url):
    """
    Pushes status or severity changes to Cyble Vision for bi-directional mirroring.

    Args:
        client: Client instance
        method: HTTP method (unused here)
        token: API key for Cyble Vision
        args: Incoming args from Cortex XSOAR
        url: Cyble Vision API endpoint

    Returns:
        str: ID of updated incident
    """
    try:
        parsed_args = UpdateRemoteSystemArgs(args)
        incident_id = parsed_args.remote_incident_id or parsed_args.data.get("id")

        if not incident_id:
            return_error("[update_remote_system] Missing incident ID, cannot update")

        demisto.debug(f"[update_remote_system] Parsed args: [{parsed_args.__dict__}]")

        if not parsed_args.delta:
            demisto.debug(f"[update_remote_system] No delta provided for incident [{incident_id}], skipping update.")
            return incident_id

        service = parsed_args.data.get("service")
        if not service:
            demisto.debug(f"[update_remote_system] No service found for incident [{incident_id}], cannot update.")
            return incident_id

        demisto.debug(f"[update_remote_system] Delta received: {parsed_args.delta}")

        update_payload = {"id": incident_id, "service": service}

        # Handle status
        status = parsed_args.delta.get("status")

        if status:
            mapped_status = INCIDENT_STATUS.get(status)
            if mapped_status:
                update_payload["status"] = mapped_status
                demisto.debug(f"[update_remote_system] mapped status : {mapped_status}")
            else:
                demisto.debug(f"[update_remote_system] Unmapped status received in delta: {status}")

        # Handle severity conversion
        severity = parsed_args.delta.get("severity")
        if severity is not None:
            try:
                severity = float(severity)
                if severity in (0, 0.5, 1):
                    update_payload["user_severity"] = "LOW"
                elif severity == 2:
                    update_payload["user_severity"] = "MEDIUM"
                elif severity in (3, 4):
                    update_payload["user_severity"] = "HIGH"
                else:
                    demisto.debug(f"[update_remote_system] Severity value [{severity}] does not map to known levels.")
            except ValueError:
                demisto.debug(f"[update_remote_system] Invalid numeric severity: {severity}")

        # If no valid fields beyond ID and service, skip
        if len(update_payload) <= 2:
            demisto.debug(f"[update_remote_system] No valid status or severity to update for incident [{incident_id}].")
            return incident_id

        final_payload = {"alerts": [update_payload]}
        demisto.debug(f"[update_remote_system] Sending update payload: {final_payload}")

        client.update_alert(final_payload, url, token)

        return incident_id

    except Exception as e:
        return_error(f"[update_remote_system] Failed to update alert: {str(e)}")


def get_mapping_fields(client, token, url):
    """
    Defines fields available for outgoing mirroring to Cyble Vision.

    Args:
        client: Client instance
        token: API token
        url: API endpoint

    Returns:
        GetMappingFieldsResponse: Field structure for outgoing mapper
    """
    incident_type_scheme = SchemeTypeMapping(type_name="cyble_outgoing_mapper")

    incident_type_scheme.add_field("status", "The status of the alert in Cyble Vision")
    incident_type_scheme.add_field("severity", "The severity of the alert in Cyble Vision")

    return GetMappingFieldsResponse([incident_type_scheme])


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
        "ioc": args.get("ioc", ""),
        "page": args.get("from", ""),
        "limit": args.get("limit", ""),
        "sortBy": args.get("sort_by", ""),
        "order": args.get("order", ""),
        "tags": args.get("tags"),
    }

    if args.get("ioc_type", ""):
        input_params_alerts_iocs["iocType"] = args.get("ioc_type", "")

    if args.get("start_date"):
        input_params_alerts_iocs["startDate"] = args.get("start_date")

    if args.get("end_date"):
        input_params_alerts_iocs["endDate"] = args.get("end_date")

    response = set_request(client, method, token, input_params_alerts_iocs, url)

    try:
        lst_iocs = []
        for ioc in response["iocs"]:
            sources = []
            behaviour_tags = []
            target_countries = []
            target_regions = []
            target_industries = []
            related_malwares = []
            related_threat_actors = []

            if ioc.get("sources"):
                for source in ioc.get("sources"):
                    sources.append(source)

            if ioc.get("behaviour_tags"):
                for behaviour_tag in ioc.get("behaviour_tags"):
                    behaviour_tags.append(behaviour_tag)

            if ioc.get("target_countries"):
                for target_country in ioc.get("target_countries"):
                    target_countries.append(target_country)

            if ioc.get("target_regions"):
                for target_region in ioc.get("target_regions"):
                    target_regions.append(target_region)

            if ioc.get("target_industries"):
                for target_industry in ioc.get("target_industries"):
                    target_industries.append(target_industry)

            if ioc.get("related_malware"):
                for related_malware in ioc.get("related_malware"):
                    related_malwares.append(related_malware)

            if ioc.get("related_threat_actors"):
                for related_threat_actor in ioc.get("related_threat_actors"):
                    related_threat_actors.append(related_threat_actor)

            lst_iocs.append(
                {
                    "ioc": "{}".format(ioc["ioc"]),
                    "ioc_type": "{}".format(ioc["ioc_type"]),
                    "first_seen": "{}".format(ioc["first_seen"]),
                    "last_seen": "{}".format(ioc["last_seen"]),
                    "risk_score": "{}".format(ioc["risk_score"]),
                    "confidence_rating": "{}".format(ioc["confidence_rating"]),
                    "sources": f"{sources}",
                    "behaviour_tags": f"{behaviour_tags}",
                    "target_countries": f"{target_countries}",
                    "target_regions": f"{target_regions}",
                    "target_industries": f"{target_industries}",
                    "related_malware": f"{related_malwares}",
                    "related_threat_actors": f"{related_threat_actors}",
                }
            )
    except Exception as e:
        raise Exception(f"Error: [{e}] for response [{response}]")

    markdown = tableToMarkdown(
        "Indicator of Compromise:",
        lst_iocs,
    )

    command_results = CommandResults(
        readable_output=markdown, outputs_prefix="CybleEvents.IoCs", raw_response=lst_iocs, outputs=lst_iocs
    )

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
    base_url = params.get("base_url")
    token = demisto.params().get("credentials", {}).get("password", "")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    hide_cvv_expiry = params.get("hide_data", False)
    demisto.debug(f"params are: {params}")
    incident_collections = params.get("incident_collections", [])
    incident_severity = params.get("incident_severity", [])

    try:
        client = Client(base_url=params.get("base_url"), verify=verify_certificate, proxy=proxy)
        args = demisto.args()

        if demisto.command() == "test-module":
            demisto.debug(f"command being called is: {demisto.command()}")
            url = base_url + str(ROUTES[COMMAND[demisto.command()]])
            return_results(test_response(client, "POST", url, token))

        elif demisto.command() == "fetch-incidents":
            last_run = demisto.getLastRun()
            demisto.debug(f"command being called is: {demisto.command()}")
            url = base_url + str(ROUTES[COMMAND[demisto.command()]])
            data, next_run = cyble_events(
                client, "POST", token, url, args, last_run, hide_cvv_expiry, incident_collections, incident_severity, False
            )

            demisto.setLastRun(next_run)
            demisto.incidents(data)

        elif demisto.command() == "update-alert-data":
            demisto.debug(f"command being called is: {demisto.command()}")
            return_results(update_alert_data_command(client, base_url, token, args))

        elif demisto.command() == "get-mapping-fields":
            demisto.debug(f"command being called is: {demisto.command()}")
            url = base_url + str(ROUTES[COMMAND[demisto.command()]])
            return_results(get_mapping_fields(client, token, url))

        elif demisto.command() == "cyble-vision-subscribed-services":
            demisto.debug(f"command being called is: {demisto.command()}")
            return_results(fetch_subscribed_services_alert(client, "GET", base_url, token))

        elif demisto.command() == "cyble-vision-fetch-iocs":
            demisto.debug(f"command being called is: {demisto.command()}")
            validate_iocs_input(args)
            url = base_url + str(ROUTES[COMMAND[demisto.command()]])
            command_results = cyble_fetch_iocs(client, "GET", token, args, url)
            return_results(command_results)

        elif demisto.command() == "cyble-vision-fetch-alerts":
            demisto.debug(f"command being called is: {demisto.command()}")
            url = base_url + str(ROUTES[COMMAND[demisto.command()]])
            lst_alerts = cyble_events(
                client, "POST", token, url, args, {}, hide_cvv_expiry, incident_collections, incident_severity, True
            )
            return_results(
                CommandResults(
                    readable_output="Fetched alerts successfully.",
                    outputs_prefix="CybleEvents.Alerts",
                    raw_response=lst_alerts,
                    outputs=lst_alerts,
                )
            )

        elif demisto.command() == "get-modified-remote-data":
            demisto.debug(f"command being called is: {demisto.command()}")
            url = base_url + str(ROUTES[COMMAND[demisto.command()]])
            return_results(
                get_modified_remote_data_command(
                    client, url, token, args, hide_cvv_expiry, incident_collections, incident_severity
                )
            )

        elif demisto.command() == "get-remote-data":
            demisto.debug(f"command being called is: {demisto.command()}")
            url = base_url + str(ROUTES[COMMAND[demisto.command()]])
            return_results(
                get_remote_data_command(client, url, token, args, incident_collections, incident_severity, hide_cvv_expiry)
            )

        else:
            raise NotImplementedError(f"{demisto.command()} command is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
