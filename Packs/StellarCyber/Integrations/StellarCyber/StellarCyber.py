"""Stellar Cyber Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""
import demistomock as demisto
from CommonServerUserPython import *
from CommonServerPython import *

# from typing import Any, Dict
import dateparser
import requests
import json
import urllib3
import base64
import time
from datetime import datetime, timedelta

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

# _STELLAR_DP_ = None
# _INCIDENT_API_PORT_ = None
# _ALERT_API_USER_ = ""
# _ALERT_API_TOKEN_ = ""
# _MINUTES_AGO_ = None
# # _INCIDENTS_OR_CASES_ = ""
# VALIDATE_CERT = False
# _OAUTH_: dict = {}
# _TENANTID_ = None


""" CLIENT CLASS """


class AccessToken:
    def __init__(self, token: str, expiration: int):
        self._expiration = expiration
        self._token = token

    def __str__(self):
        return self._token

    @property
    def expired(self) -> bool:
        return self._expiration < int(datetime.utcnow().timestamp())


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def __init__(self, dp_host: str, username: str, password: str, verify: bool, proxy, tenantid):
        self.dp_host = dp_host
        super().__init__(base_url=f"https://{dp_host}", verify=verify, proxy=proxy)
        self._tenantid = tenantid
        self._is_saas = True
        self._basic = base64.b64encode(bytes(username + ":" + password, "utf-8")).decode("utf-8")
        # self._auth = (username, password)
        self._token: AccessToken = AccessToken("", 0)

    def _get_auth_header(self):
        if self._is_saas:
            if self._token.expired:
                headers = {"Accept": "application/json", "Content-type": "application/json"}
                headers["Authorization"] = f"Basic {self._basic}"
                token_url = f"https://{self.dp_host}/connect/api/v1/access_token"
                response = self._http_request(method="POST", full_url=token_url, headers=headers)
                current_token = response.get("access_token", "")
                current_exp = int(response.get("exp", 0))
                self._token = AccessToken(current_token, current_exp)
                header_string = f"Bearer {current_token}"
            else:
                header_string = f"Bearer {self._token}"
        else:
            header_string = f"Basic {self._basic}"

        return header_string

    def test_incidents(self):
        incident_url = f"https://{self.dp_host}/connect/api/data/aella-ser-*/_search?q=fidelity:<0"
        headers = {"Accept": "application/json", "Content-type": "application/json"}
        headers["Authorization"] = self._get_auth_header()
        response = self._http_request(method="GET", full_url=incident_url, headers=headers)
        return True

    def get_new_incidents(self, last_run: int):
        if self._tenantid:
            incident_url = f"https://{self.dp_host}/connect/api/v1/incidents?tenantid={self._tenantid}&FROM~created_at={last_run}&sort=created_at&order=asc"
        else:
            # incident_url = f"https://{self.dp_host}/connect/api/v1/incidents?FROM~modified_at={last_run}&sort=modified_at&order=asc"
            incident_url = f"https://{self.dp_host}/connect/api/v1/incidents?FROM~created_at={last_run}&sort=created_at&order=asc"

        headers = {"Accept": "application/json", "Content-type": "application/json"}
        headers["Authorization"] = self._get_auth_header()
        response = self._http_request(method="GET", full_url=incident_url, headers=headers)
        return response["data"]["incidents"]

    def get_updated_incidents(self, last_run: int):
        if self._tenantid:
            incident_url = f"https://{self.dp_host}/connect/api/v1/incidents?tenantid={self._tenantid}&FROM~modified_at={last_run}&sort=modified_at&order=asc"
        else:
            incident_url = (
                f"https://{self.dp_host}/connect/api/v1/incidents?FROM~modified_at={last_run}&sort=modified_at&order=asc"
            )

        headers = {"Accept": "application/json", "Content-type": "application/json"}
        headers["Authorization"] = self._get_auth_header()
        response = self._http_request(method="GET", full_url=incident_url, headers=headers)
        response_incidents = response["data"].get("incidents", [])
        if len(response_incidents):
            incident_ids = [i["ticket_id"] for i in response_incidents]
        else:
            incident_ids = []
        return incident_ids

    def get_incident(self, ticket_id: int):
        incident_url = f"https://{self.dp_host}/connect/api/v1/incidents?ticket_id={ticket_id}"

        headers = {"Accept": "application/json", "Content-type": "application/json"}
        headers["Authorization"] = self._get_auth_header()
        response = self._http_request(method="GET", full_url=incident_url, headers=headers)
        response_incidents = response["data"].get("incidents", [])
        if len(response_incidents):
            return response_incidents[0]
        else:
            return {}
    
    def get_incident_summary(self, incident_id: str):
        incident_summary_url = f"https://{self.dp_host}/connect/api/v1/cases/{incident_id}/summary?formatted=true"
        headers = {"Accept": "application/json", "Content-type": "application/json"}
        headers["Authorization"] = self._get_auth_header()
        response = self._http_request(method="GET", full_url=incident_summary_url, headers=headers)

        return response["data"]

    def get_alert(self, alert_id: str, alert_index: str):
        hit = {}
        alert_url = f"https://{self.dp_host}/connect/api/data/{alert_index}/_search?q=_id:{alert_id}"
        headers = {"Accept": "application/json", "Content-type": "application/json"}
        headers["Authorization"] = self._get_auth_header()
        response = self._http_request(method="GET", full_url=alert_url, headers=headers)
        hits = response.get("hits", None).get("hits", None)
        timed_out = response.get("timed_out", False)
        if hits:
            hit = hits[0].get("_source", None)
            alert_index = hits[0].get("_index", "")
            hit = demisto_normalization(hit, alert_id, alert_index, self.dp_host)
        
        return hit

    def update_case(
        self,
        case_id,
        case_severity=None,
        case_status=None,
        case_assignee=None,
        case_tags_add=[],
        case_tags_remove=[],
    ):
        update_data = {}
        if case_severity:
            update_data["priority"] = str(case_severity)
        if case_status:
            update_data["status"] = str(case_status)
        if case_assignee:
            update_data["assignee"] = str(case_assignee)
        if len(case_tags_add) or len(case_tags_remove):
            update_data["tags"] = {}
            if len(case_tags_add):
                update_data["tags"]["add"] = case_tags_add
            if len(case_tags_remove):
                update_data["tags"]["delete"] = case_tags_remove

        incident_url = f"https://{self.dp_host}/connect/api/v1/incidents?id={case_id}"
        headers = {"Accept": "application/json", "Content-type": "application/json"}
        headers["Authorization"] = self._get_auth_header()
        response = self._http_request(method="POST", full_url=incident_url, headers=headers, json_data=update_data)
        return response
    
    def close_case(self, case_id, close_reason):
        incident_url = f"https://{self.dp_host}/connect/api/v1/incidents?id={case_id}"
        headers = {"Accept": "application/json", "Content-type": "application/json"}
        headers["Authorization"] = self._get_auth_header()

        update_data = {
            "status": "Resolved",
            "resolution": f"{close_reason}",
        }
        response = self._http_request(method="POST", full_url=incident_url, headers=headers, json_data=update_data)
        return response

""" HELPER FUNCTIONS """

def get_xsoar_severity(severity):
    sev_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    return sev_map[severity]


def demisto_normalization(alert, alert_id, alert_index, dp_host):
    """
    Normalizes an alert from Stellar Cyber into a format that can be ingested by Demisto.

    Args:
        alert (dict): The alert from Stellar Cyber.
        alert_id (str): The ID of the alert.
        alert_index (str): The index of the alert.
        dp_host (str): The hostname of the Stellar Cyber platform.

    Returns:
        dict: The normalized alert in a format that can be ingested by Demisto.
    """
    ret_alert = {
        "alert_metadata": alert["xdr_event"],
        "alert_id": alert_id,
        "alert_index": alert_index,
        "tenant_id": alert["tenantid"],
        "tenant_name": alert["tenant_name"],
        "detected_field": alert.get("detected_field", ""),
        "detected_value": alert.get("detected_value", ""),
        "xdr_tactic_name": alert["xdr_event"].get("tactic", {}).get("name", ""),
        "xdr_tactic_id": alert["xdr_event"].get("tactic", {}).get("id", ""),
        "xdr_technique_name": alert["xdr_event"].get("technique", {}).get("name", ""),
        "xdr_technique_id": alert["xdr_event"].get("technique", {}).get("id", ""),
        "display_name": alert["xdr_event"].get("display_name", ""),
        "description": alert["xdr_event"].get("description", ""),
        "alert_url": f"https://{dp_host}/alerts/alert/{alert_index}/amsg/{alert_id}",
    }

    # workaround for some alerts (e.g.: uncommon process anomaly)
    if not ret_alert["detected_field"]:
        ret_alert["detected_field"] = alert.get("detected_fields", [])
        ret_alert["detected_value"] = alert.get("detected_values", [])

    return ret_alert


""" COMMAND FUNCTIONS """


def fetch_incidents(client: Client, params: dict):
    """
    Retrieves incidents from the Stellar Cyber platform and maps them to XSOAR incidents.

    Returns:
        List[dict]: A list of XSOAR incidents.
    """
    last_run = demisto.getLastRun()
    demisto.debug(f"Last run: {last_run}")
    last_incident_ids = last_run.get("last_incidents", [])
    first_fetch_time = params.get("first_fetch", "3 days").strip()
    last_fetch = last_run.get("last_fetch", None)
    new_last_fetch = int(datetime.utcnow().timestamp() * 1000)
    if not last_fetch:
        first_fetch = dateparser.parse(first_fetch_time)
        assert first_fetch is not None
        last_fetch = int(first_fetch.timestamp() * 1000)
    else:
        last_fetch = int(last_fetch)  # Convert last_fetch to an integer
    incidents = client.get_new_incidents(last_run=last_fetch)
    demisto_incidents = []

    number_of_incidents = len(incidents)
    demisto.info(f"Retrieved incidents: [{number_of_incidents}]")

    incident_ids = []

    for incident in incidents:
        incident_id = incident["_id"]
        cust_id = incident["cust_id"]
        incident["case_url"] = f"https://{client.dp_host}/cases/case-detail/{incident_id}"
        incident_ticket_id = str(incident["ticket_id"])
        if len(incident['metadata'].get('name_auto', [])):
            incident_name = incident['metadata']['name_auto'][0]
        else:
            incident_name = incident['name']
        incident_ts = incident["created_at"]
        if last_fetch < incident_ts:
            last_fetch = incident_ts

        incident_summary = client.get_incident_summary(incident_id)
        incident["summary"] = incident_summary
        event_ids = incident.get("event_ids", None)
        security_event_cnt = len(event_ids)
        demisto.info(
            "Pulling security event info for incident: [{}] [ticket id: {}] [event_cnt: [{}]".format(
                incident_id, incident_ticket_id, security_event_cnt
            )
        )
        incident["security_alerts"] = []
        for event in event_ids:
            incident["security_alerts"].append(client.get_alert(alert_id=event["_id"], alert_index=event["_index"]))
        case_severity = get_xsoar_severity(incident["priority"])
        incident["severity"] = case_severity
        incident["mirror_direction"] = "In"
        incident["mirror_instance"] = demisto.integrationInstance()
        if incident_ticket_id not in last_incident_ids:
            incident_ids.append(incident_ticket_id)
            demisto_incident = {
                # "name": incident_name,
                # "dbotMirrorId": str(incident["ticket_id"]),
                # "dbotMirrorDirection": "In",
                # "dbotMirrorInstance": demisto.integrationInstance(),
                # "mirror_direction": "Incoming",
                # "mirror_instance": demisto.integrationInstance(),
                "occurred": timestamp_to_datestring(incident_ts),
                "rawJSON": json.dumps(incident)
            }
            demisto_incidents.append(demisto_incident)
    
    if len(incident_ids) == 0:
        incident_ids = last_incident_ids

    demisto.setLastRun({"last_fetch": last_fetch, "last_incidents": incident_ids})
    return demisto_incidents


# def simple_query_command(client: Client, stellar_index, stellar_field, stellar_value):
#     """
#     Retrieves an alert from the Stellar Cyber platform by its ID.

#     Args:
#         stellar_index (str): The index to query
#         stellar_field (str): The field to query
#         stellar_value (str): The value to query

#     Returns:
#         list: A list of dictionaries with the results of the query. or None

#     Raises:
#         Exception: If there is an issue with retrieving the query results.
#     """
#     pass


def get_alert_command(client: Client, args: dict):
    """
    Retrieves an alert from the Stellar Cyber platform by its ID.

    Args:
        alert_id (str): The ID of the alert to retrieve.

    Returns:
        dict: A dictionary containing the details of the retrieved alert.

    Raises:
        Exception: If there is an issue with retrieving the alert.
    """
    alert_id = demisto.args().get("alert_id", None)
    demisto.info(f"Getting alert: {alert_id}")
    hit = client.get_alert(alert_id, "stellar-index-v1-ser-*")
    results = CommandResults(
        outputs_prefix='StellarCyber.Alert',
        outputs_key_field='alert_id',
        outputs=[hit]
    )
    return_results(results)
    return hit


def test_module_command(client: Client):
    try:
        if client.test_incidents():
            return "ok"
        else:
            return "failed"
    except Exception as e:
        return f"Test failed with the following error: {repr(e)}"


def close_case_command(client: Client, args: dict):
    case_id = args.get("stellar_case_id")
    close_reason = args.get("stellar_close_reason", "")
    demisto.info(f"Closing stellar case with id: [{case_id}]")
    client.close_case(case_id, close_reason)


def update_case_command(client: Client, args: dict):
    case_id = args.get("stellar_case_id", None)
    case_severity = args.get("stellar_case_severity", None)
    case_status = args.get("stellar_case_status", None)
    case_assignee = args.get("stellar_case_assignee", None)
    case_tags_add = args.get("stellar_case_tags_add", [])
    case_tags_remove = args.get("stellar_case_tags_remove", [])

    if not (case_severity or case_status or case_assignee or len(case_tags_add) or len(case_tags_remove)):
        raise Exception(f"No values to update for stellar case with id: [{case_id}]")

    demisto.info(f"Updating stellar case with id: [{case_id}]")
    client.update_case(
        case_id, case_severity, case_status, case_assignee, case_tags_add, case_tags_remove
    )


def get_remote_data_command(client: Client, args):
    demisto.debug(f"get_remote_data_command: {args}")
    parsed_args = GetRemoteDataArgs(args)
    demisto.debug(f"parsed_args: {parsed_args}")
    # mirror_last_sync = int(datetime.utcnow().timestamp() * 1000)
    try:
        remote_incident_id = parsed_args.remote_incident_id
        incident = client.get_incident(ticket_id=remote_incident_id)
        if len(incident):
            incident_id = incident["_id"]
            incident["case_url"] = f"https://{client.dp_host}/cases/case-detail/{incident_id}"
            incident_ticket_id = str(incident["ticket_id"])
            demisto.info(f"Retrieved case: {str(incident['ticket_id'])}")
            if len(incident['metadata'].get('name_auto', [])):
                incident_name = incident['metadata']['name_auto'][0]
            else:
                incident_name = incident['name']
            incident["name"] = incident_name
            incident_summary = client.get_incident_summary(incident_id)
            incident["summary"] = incident_summary
            event_ids = incident.get("event_ids", None)
            security_event_cnt = len(event_ids)
            demisto.info(
                "Pulling security event info for case: [{}] [ticket id: {}] [event_cnt: [{}]".format(
                    incident_id, incident_ticket_id, security_event_cnt
                )
            )
            incident["security_alerts"] = []
            for event in event_ids:
                incident["security_alerts"].append(client.get_alert(alert_id=event["_id"], alert_index=event["_index"]))
            case_severity = get_xsoar_severity(incident["priority"])
            incident["severity"] = case_severity
            incident["mirror_direction"] = "In"
            incident["mirror_instance"] = demisto.integrationInstance()

            return GetRemoteDataResponse(mirrored_object=incident, entries=[])
        else:
            return_error(f"Failed to retrieve case: {str(incident['ticket_id'])}")
    except Exception as e:
        if "Rate limit exceeded" in str(e):
            return_error("API rate limit")


def get_modified_remote_data_command(client: Client, args):
    demisto.debug(f"get_modified_remote_data_command: {args}")
    try:
        last_update = get_last_mirror_run().get("last_update") # type: ignore
        if not last_update:
            remote_args = GetModifiedRemoteDataArgs(args)
            last_update = remote_args.last_update
        demisto.debug(f"last_update: {last_update}")
        last_update_utc = dateparser.parse(last_update, settings={'TIMEZONE': 'UTC'}) # type: ignore
        demisto.debug(f"last_update_utc: {last_update_utc}")
        assert last_update_utc is not None
        last_run_ts = int((last_update_utc - timedelta(minutes=5)).timestamp() * 1000)
        modified_incident_ids = client.get_updated_incidents(last_run=last_run_ts)
        if len(modified_incident_ids):
            set_last_mirror_run({"last_update": str(int(datetime.utcnow().timestamp() * 1000))})
        else:
            set_last_mirror_run({"last_update": last_update})
        return GetModifiedRemoteDataResponse(modified_incident_ids)
    except Exception as e:
        return_error("skip update")

""" MAIN FUNCTION """

def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """
    try:
        _STELLAR_DP_ = demisto.params().get("stellar_dp", "")
        _ALERT_API_USER_ = demisto.getParam("credentials")["identifier"]  # type: ignore
        _ALERT_API_TOKEN_ = demisto.getParam("credentials")["password"]  # type: ignore
        # FIRST_FETCH = demisto.params().get("first_fetch", "3 days").strip()
        _VALIDATE_CERT_ = not demisto.params().get("insecure", True)
        _PROXY_ = demisto.params().get("proxy", False)
        _TENANTID_ = demisto.params().get("tenantid", None)

        client = Client(
            dp_host=_STELLAR_DP_,
            username=_ALERT_API_USER_,
            password=_ALERT_API_TOKEN_,
            verify=_VALIDATE_CERT_,
            proxy=_PROXY_,
            tenantid=_TENANTID_
        )

        demisto.info(f"Command is {demisto.command()}")

        if demisto.command() == "test-module":
            # test_connection()
            result = test_module_command(client)
            return_results(result)

        elif demisto.command() == "fetch-incidents":
            incidents = fetch_incidents(client, params=demisto.params())
            demisto.incidents(incidents)
        elif demisto.command() == "stellar-get-alert":
            return_results(get_alert_command(client, demisto.args()))
        # elif demisto.command() == 'stellar-simple-query':
        #     return_results(simple_query_command(client, demisto.args()['stellar_index'], demisto.args()['stellar_field'], demisto.args()['stellar_value']))
        elif demisto.command() == "stellar-close-case":
            close_case_command(client, demisto.args())
            return_results("ok")
        elif demisto.command() == "stellar-update-case":
            update_case_command(client, demisto.args())
            return_results("ok")
        elif demisto.command() == "get-modified-remote-data":
            demisto.debug("get-modified-remote-data being called...")
            raise NotImplementedError
            return_results(get_modified_remote_data_command(client, demisto.args()))
        elif demisto.command() == "get-remote-data":
            demisto.debug("get-remote-data being called...")
            return_results(get_remote_data_command(client, demisto.args()))

    except Exception as e:
        demisto.info(str(e))
        return_error(str(e))

""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
