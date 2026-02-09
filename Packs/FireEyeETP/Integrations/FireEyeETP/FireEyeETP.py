import demistomock as demisto
from CommonServerPython import *

from CommonServerUserPython import *

"""
IMPORTS
"""

import base64
import copy
import json
import os
import re
import time
from datetime import datetime, UTC
import requests
import urllib3

urllib3.disable_warnings()

"""
GLOBAL VARS
"""

PARAMS = demisto.params()

ALERT_INCIDENT_TYPE_NAME = "trellix_alerts"
"""
Cloud REST APIs are rate-limited to 60 requests per minute per API route
(e.g., /trace, /alert, /quarantine) per customer.
The fetch command uses:
    - 1 request to retrieve the list of alerts
    - 1 additional request per alert to retrieve its severity
As a result, a maximum of 59 alerts can be fetched per minute.
"""
MAX_FETCHED_ALERT = min(int(PARAMS.get("incidents_per_fetch", 59)), 59)
FETCH_TIME = PARAMS.get("fetch_time", "1 minutes")

CLIENT_ID = PARAMS.get("credentials", {}).get("identifier", "")
CLIENT_SECRET = PARAMS.get("credentials", {}).get("password", "")
SCOPES = PARAMS.get(
    "oauth_scopes",
    (
        "etp.conf.ro etp.trce.rw etp.admn.ro etp.domn.ro etp.accs.rw etp.quar.rw "
        "etp.domn.rw etp.rprt.rw etp.accs.ro etp.quar.ro etp.alrt.rw etp.rprt.ro "
        "etp.conf.rw etp.trce.ro etp.alrt.ro etp.admn.rw"
    ),
).strip()
API_KEY = PARAMS.get("credentials_api_key", {}).get("password") or PARAMS.get("api_key")

BASE_PATH_V1 = "{}/api/v1".format(PARAMS.get("server"))  # Deprecated endpoint
BASE_PATH_V2 = "{}/api/v2".format(PARAMS.get("server"))


HTTP_HEADERS = {"Content-Type": "application/json"}
USE_SSL = not PARAMS.get("unsecure")
MESSAGE_STATUS = argToList(PARAMS.get("message_status"))

# OAuth2 token constants
OAUTH_TOKEN_KEY = "oauth_access_token"
OAUTH_EXPIRES_KEY = "oauth_token_expires_at"

"""
SEARCH ATTRIBUTES VALID VALUES
"""

REJECTION_REASONS = [
    "ETP102",
    "ETP103",
    "ETP104",
    "ETP200",
    "ETP201",
    "ETP203",
    "ETP204",
    "ETP205",
    "ETP300",
    "ETP301",
    "ETP302",
    "ETP401",
    "ETP402",
    "ETP403",
    "ETP404",
    "ETP405",
]

STATUS_VALUES = [
    "accepted",
    "deleted",
    "delivered",
    "delivered (retroactive)",
    "dropped",
    "dropped oob",
    "dropped (oob retroactive)",
    "permanent failure",
    "processing",
    "quarantined",
    "rejected",
    "temporary failure",
]

ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
"""
BASIC FUNCTIONS
"""


def is_iso_utc(date_str) -> bool:
    if not date_str:
        return False
    try:
        datetime.strptime(date_str, ISO_FORMAT)
        return True
    except ValueError:
        return False


def fetch_oauth_token():
    """
    Fetch OAuth 2.0 access token
    """
    # Trellix OAuth2 endpoint
    token_url = "https://auth.trellix.com/auth/realms/IAM/protocol/openid-connect/token"
    credentials = f"{CLIENT_ID}:{CLIENT_SECRET}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()

    headers = {"Content-Type": "application/x-www-form-urlencoded", "Authorization": f"Basic {encoded_credentials}"}

    data = {"grant_type": "client_credentials", "scope": SCOPES}

    try:
        response = requests.post(token_url, headers=headers, data=data, verify=USE_SSL)
        response.raise_for_status()

        result = response.json()
        access_token = result.get("access_token")
        expires_in = result.get("expires_in", 600)  # Default is 10 minutes

        if not access_token:
            raise DemistoException("Failed to retrieve access token from OAuth response")

        # Store token and expiration time in integration context
        expires_at = time.time() + expires_in
        ctx = get_integration_context() or {}
        ctx[OAUTH_TOKEN_KEY] = access_token
        ctx[OAUTH_EXPIRES_KEY] = expires_at
        set_integration_context(ctx)

        demisto.debug(f"OAuth token fetched successfully, expires in {expires_in} seconds")
        return access_token

    except Exception as e:
        raise DemistoException(f"OAuth authentication failed: {str(e)}")


def is_oauth_token_expired(ctx):
    """
    Check if the current OAuth token is expired or about to expire (within 60 seconds)
    """
    expires_at = ctx.get(OAUTH_EXPIRES_KEY, 0)
    current_time = time.time()

    # Consider token expired if it expires within the next 60 seconds
    is_expired = current_time >= (expires_at - 60)
    return is_expired


def get_valid_oauth_token():
    """
    Get a valid OAuth token, refreshing if necessary
    """
    ctx = get_integration_context() or {}
    access_token = ctx.get(OAUTH_TOKEN_KEY)

    if not access_token:
        demisto.debug("No OAuth token found, fetching new one")
    elif is_oauth_token_expired(ctx):
        demisto.debug("OAuth token expired, fetching new one")
    else:
        demisto.debug("Using existing valid OAuth token")
        return access_token

    return fetch_oauth_token()


def validate_authentication_params():
    """
    Validate authentication parameters and determine which method to use.
    The SCOPES parameter is required only for OAuth2.
    Returns: 'oauth2' for Client ID/Secret, 'api_key' for API Key
    Raises: ValueError if authentication configuration is invalid or over-configured.
    """
    has_client_id = bool(CLIENT_ID)
    has_client_secret = bool(CLIENT_SECRET)
    has_api_key = bool(API_KEY)
    has_scopes = bool(SCOPES)

    # 1. CHECK FOR AMBIGUOUS OVER-CONFIGURATION
    if has_client_id and has_client_secret and has_api_key:
        raise ValueError(
            "Both OAuth2 (Client ID/Secret) and API Key were provided. " "Please configure only one authentication method."
        )

    # 2. OAUTH2 VALIDATION
    if has_client_id and has_client_secret:
        # Check for required SCOPES when using OAuth2
        if not has_scopes:
            raise ValueError(
                "Client ID and Client Secret provided, but the 'OAuth Scopes' parameter is missing. "
                "Scopes are required for OAuth2 authentication."
            )

        demisto.info("Authentication: Using OAuth2 (Client ID/Secret)")
        return "oauth2"

    # 3. API KEY VALIDATION
    if has_api_key and not has_client_id and not has_client_secret:
        demisto.info("Authentication: Using API Key")
        return "api_key"

    # 4. INCOMPLETE OAUTH2 CONFIGURATION
    if has_client_id and not has_client_secret:
        raise ValueError(
            "Client ID provided but Client Secret is missing. "
            "Both Client ID and Client Secret are required for OAuth2 authentication."
        )

    if has_client_secret and not has_client_id:
        raise ValueError(
            "Client Secret provided but Client ID is missing. "
            "Both Client ID and Client Secret are required for OAuth2 authentication."
        )

    # 5. NO AUTHENTICATION METHOD PROVIDED
    raise ValueError("No authentication credentials provided.")


def get_auth_headers():
    """Get authentication headers based on available authentication method."""
    auth_method = validate_authentication_params()

    if auth_method == "oauth2":
        access_token = get_valid_oauth_token()
        return {"Content-Type": "application/json", "Authorization": f"Bearer {access_token}"}
    elif auth_method == "api_key":
        return {"Content-Type": "application/json", "x-fireeye-api-key": API_KEY}
    else:
        raise ValueError("Unknown authentication method")


class Client(BaseClient):
    def get_alerts_request_v2(self, size=None, start_time=None, end_time=None, pagination_token=None, body={}):
        """
        size (int, optional): Maximum number of alerts to return.
        start_time (str, optional): Start time in ISO 8601 UTC format (e.g., 2025-01-18T14:34:59Z).
        end_time (str, optional): End time in ISO 8601 UTC format (e.g., 2025-01-19T14:34:59Z).
        pagination_token (str, optional): Token used for pagination.
        body (dict, optional): Additional request body parameters.

        """
        url = "/public/alerts/search"
        body["sort"] = {"order": "asc"}
        if size:
            body["size"] = int(size)
        if start_time and end_time:
            body["date_range"] = {"from": start_time, "to": end_time}
        if pagination_token:
            body["sort"]["search_after"] = pagination_token

        response = self._http_request(method="POST", url_suffix=url, json_data=body)
        return response

    def get_alert_request_v2(self, alert_id):
        url = f"/public/alerts/{alert_id}"
        response = self._http_request(method="GET", url_suffix=url)
        return response

    def get_artifacts_v2(self, alert_id):
        url = f"/public/alerts/{alert_id}/casefile"
        response = self._http_request(method="GET", url_suffix=url, resp_type="response")
        return response

    def get_artifacts(self, alert_id):
        url = f"/alerts/{alert_id}/downloadzip"
        response = self._http_request(method="POST", url_suffix=url, resp_type="response")
        return response

    def get_yara_rulesets(self, policy_uuid):
        url = f"/policies/{policy_uuid}/configuration/rules/yara/rulesets"
        response = self._http_request(method="GET", url_suffix=url)
        return response

    def get_yara_file(self, policy_uuid, ruleset_uuid):
        url = f"/policies/{policy_uuid}/configuration/rules/yara/rulesets/{ruleset_uuid}/file"
        response = self._http_request(method="GET", url_suffix=url, resp_type="response")
        return response

    def upload_yara_file(self, policy_uuid, ruleset_uuid, files):
        url = f"/policies/{policy_uuid}/configuration/rules/yara/rulesets/{ruleset_uuid}/file"
        response = self._http_request(method="PUT", url_suffix=url, files=files, resp_type="response")
        return response

    def get_events_data(self, message_id):
        url = f"/events/{message_id}"

        response = self._http_request(method="GET", url_suffix=url, resp_type="json")
        return response

    def quarantine_release(self, message_id):
        url = f"/quarantine/release/{message_id}"

        response = self._http_request(method="POST", url_suffix=url, resp_type="response")
        return response


def set_proxies():
    if not PARAMS.get("proxy", False):
        del os.environ["HTTP_PROXY"]
        del os.environ["HTTPS_PROXY"]
        del os.environ["http_proxy"]
        del os.environ["https_proxy"]


def listify(comma_separated_list):
    if isinstance(comma_separated_list, list):
        return comma_separated_list
    return comma_separated_list.split(",")


def http_request(method, url, body=None, headers={}, url_params=None):
    """
    returns the http response
    """

    # Use proper authentication method
    auth_headers = get_auth_headers()
    demisto.debug(f"Headers before update: {headers}")
    headers.update(auth_headers)
    demisto.debug(f"Headers after update: {headers}")

    request_kwargs = {"headers": headers, "verify": USE_SSL}

    # add optional arguments if specified
    if body is not None:
        request_kwargs["data"] = json.dumps(body)
    if url_params is not None:
        request_kwargs["params"] = json.dumps(url_params)

    LOG(f"attempting {method} request sent to {url} with body:\n{json.dumps(body, indent=4)}")
    response = requests.request(method, url, **request_kwargs)
    # handle request failure
    if response.status_code not in range(200, 205):
        raise ValueError(f"Request failed with status code {response.status_code}\n{response.text}")
    return response.json()


def return_error_entry(message):
    entry = {
        "Type": entryTypes["error"],
        "Contents": str(message),
        "ContentsFormat": formats["text"],
    }
    demisto.results(entry)


def to_search_attribute_object(value, filter=None, is_list=False, valid_values=None):
    values = listify(value) if is_list else value
    if valid_values:
        for val in values:
            if val not in valid_values:
                raise ValueError(f"{val} is not a valid value")

    attribute = {"value": values, "includes": ["SMTP", "HEADER"]}
    if filter:
        attribute["filter"] = filter

    return attribute


def format_search_attributes(
    from_email=None,
    from_email_not_in=None,
    recipients=None,
    recipients_not_in=None,
    subject=None,
    from_accepted_date_time=None,
    to_accepted_date_time=None,
    rejection_reason=None,
    sender_ip=None,
    status=None,
    status_not_in=None,
    last_modified_date_time=None,
    domains=None,
):
    search_attributes = {}  # type: Dict

    # handle from_email attribute
    if from_email and from_email_not_in:
        raise ValueError("Only one of the followings can be specified: from_email, from_email_not_in")
    if from_email:
        search_attributes["fromEmail"] = to_search_attribute_object(from_email, filter="in", is_list=True)
    elif from_email_not_in:
        search_attributes["fromEmail"] = to_search_attribute_object(from_email_not_in, filter="not in", is_list=True)

    # handle recipients attributes
    if recipients and recipients_not_in:
        raise ValueError("Only one of the followings can be specified: recipients, recipients_not_in")
    if recipients:
        search_attributes["recipients"] = to_search_attribute_object(recipients, filter="in", is_list=True)
    elif recipients_not_in:
        search_attributes["recipients"] = to_search_attribute_object(recipients_not_in, filter="not in", is_list=True)

    # handle status attributes
    if status and status_not_in:
        raise ValueError("Only one of the followings can be specified: status, status_not_in")
    if status:
        search_attributes["status"] = to_search_attribute_object(status, filter="in", is_list=True, valid_values=STATUS_VALUES)
    elif status_not_in:
        search_attributes["status"] = to_search_attribute_object(status, filter="in", is_list=True, valid_values=STATUS_VALUES)

    if subject:
        search_attributes["subject"] = to_search_attribute_object(subject, filter="in", is_list=True)
    if rejection_reason:
        search_attributes["rejectionReason"] = to_search_attribute_object(
            rejection_reason, is_list=True, valid_values=REJECTION_REASONS
        )
    if sender_ip:
        search_attributes["senderIP"] = to_search_attribute_object(sender_ip, filter="in", is_list=True)
    if domains:
        search_attributes["domains"] = to_search_attribute_object(domains, is_list=True)
    if from_accepted_date_time and to_accepted_date_time:
        search_attributes["period"] = {
            "range": {"fromAcceptedDateTime": from_accepted_date_time, "toAcceptedDateTime": to_accepted_date_time}
        }
    if last_modified_date_time:
        # try to parse '>timestamp' | '>=timestamp' | '<timestamp' | '<=timestamp'
        operator_ends_at = 0 if last_modified_date_time.find("=") == 1 else 1
        search_attributes["lastModifiedDateTime"] = {
            "value": last_modified_date_time[operator_ends_at:],
            "filter": last_modified_date_time[:operator_ends_at],
        }
    return search_attributes


def readable_message_data(message):
    return {
        "Message ID": message["id"],
        "Accepted Time": message["acceptedDateTime"],
        "From": message["from"],
        "Recipients": message.get("recipients"),
        "Subject": message["subject"],
        "Message Status": message["status"],
    }


def message_context_data(message):
    context_data = copy.deepcopy(message)

    # remove 'attributes' level
    context_data.update(context_data.pop("attributes", {}))

    # parse email sddresses
    match = re.search("<(.*)>", context_data["senderHeader"].replace('\\"', ""))
    context_data["from"] = match.group() if match else context_data["senderHeader"]

    if context_data.get("recipientHeader") is None:
        context_data["recipients"] = []
        return context_data

    recipients = []
    for recipient_header in context_data.get("recipientHeader", []):
        match = re.search("<(.*)>", recipient_header)
        recipient_address = match.group() if match else recipient_header
        recipients.append(recipient_address)
    context_data["recipients"] = ",".join(recipients)

    return context_data


def search_messages_request(attributes={}, has_attachments=None, max_message_size=None):
    url = f"{BASE_PATH_V1}/messages/trace"
    body = {"attributes": attributes, "type": "MessageAttributes", "size": max_message_size or 20}
    if has_attachments is not None:
        body["hasAttachments"] = has_attachments
    response = http_request("POST", url, body=body, headers=HTTP_HEADERS)
    # no results
    if response["meta"]["total"] == 0:
        return []
    return response["data"]


def search_messages_command():
    args = demisto.args()
    if "size" in args:
        # parse to int
        args["size"] = int(args["size"])
    if args.get("has_attachments") is not None:
        # parse to boolean
        args["hasAttachments"] = args["hasAttachments"] == "true"

    search_attributes = format_search_attributes(
        from_email=args.get("from_email"),
        from_email_not_in=args.get("from_email_not_in"),
        recipients=args.get("recipients"),
        recipients_not_in=args.get("recipients_not_in"),
        subject=args.get("subject"),
        from_accepted_date_time=args.get("from_accepted_date_time"),
        to_accepted_date_time=args.get("to_accepted_date_time"),
        rejection_reason=args.get("rejection_reason"),
        sender_ip=args.get("sender_ip"),
        status=args.get("status"),
        status_not_in=args.get("status_not_in"),
        last_modified_date_time=args.get("last_modified_date_time"),
        domains=args.get("domains"),
    )

    # raw data
    messages_raw = search_messages_request(search_attributes, args.get("hasAttachments"), args.get("size"))

    # create context data
    messages_context = [message_context_data(message) for message in messages_raw]

    # create readable data
    messages_readable_data = [readable_message_data(message) for message in messages_context]
    md_table = tableToMarkdown("Trellix Email Security - Cloud - Search Messages", messages_readable_data, removeNull=True)

    entry = {
        "Type": entryTypes["note"],
        "Contents": messages_raw,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": md_table,
        "EntryContext": {"FireEyeETP.Messages(obj.id==val.id)": messages_context},
    }
    demisto.results(entry)


def get_message_request(message_id):
    url = f"{BASE_PATH_V1}/messages/{message_id}"
    response = http_request("GET", url)
    if response["meta"]["total"] == 0:
        return {}
    return response["data"][0]


def get_message_command():
    # get raw data
    raw_message = get_message_request(demisto.args()["message_id"])

    if raw_message:
        # create context data
        context_data = message_context_data(raw_message)

        # create readable data
        message_readable_data = readable_message_data(context_data)
        messages_md_headers = ["Message ID", "Accepted Time", "From", "Recipients", "Subject", "Message Status"]
        md_table = tableToMarkdown(
            "Trellix Email Security - Cloud - Get Message", message_readable_data, headers=messages_md_headers
        )

        entry = {
            "Type": entryTypes["note"],
            "Contents": raw_message,
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": md_table,
            "EntryContext": {"FireEyeETP.Messages(obj.id==val.id)": context_data},
        }
        demisto.results(entry)
    # no results
    else:
        entry = {
            "Type": entryTypes["note"],
            "Contents": {},
            "ContentsFormat": formats["text"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": "### Trellix Email Security - Cloud - Get Message \n no results",
        }
        demisto.results(entry)


def get_search_alert_summary_v2(alert):
    return {
        "Alert ID": alert.get("id"),
        "Sha256": alert.get("sha256"),
        "md5": alert.get("md5"),
        "Domain": alert.get("domain"),
        "Original": alert.get("original"),
        "Report id": alert.get("report_id"),
        "Alert date": alert.get("alert_date"),
        "Malware name": [item.get("name") for item in alert.get("malware")],
        "Malware stype": [item.get("stype") for item in alert.get("malware")],
        "Email status": alert.get("email_status"),
    }


def alert_readable_data_summery(alert):
    return {
        "Alert ID": alert.get("id"),
        "Alert Timestamp": alert.get("alert").get("timestamp"),
        "From": alert.get("email").get("headers").get("from"),
        "Recipients": "{}|{}".format(alert.get("email").get("headers").get("to"), alert.get("email").get("headers").get("cc")),
        "Subject": alert.get("email").get("headers").get("subject"),
        "MD5": alert.get("alert").get("malware_md5"),
        "URL/Attachment": alert.get("email").get("attachment"),
        "Email Status": alert.get("email").get("status"),
        "Email Accepted": alert.get("email").get("timestamp").get("accepted"),
        "Threat Intel": alert.get("ati"),
    }


def alert_readable_data(alert):
    return {
        "Alert ID": alert.get("id"),
        "Alert Timestamp": alert.get("alert").get("timestamp"),
        "From": alert.get("email").get("headers").get("from"),
        "Recipients": "{}|{}".format(alert.get("email").get("headers").get("to"), alert.get("email").get("headers").get("cc")),
        "Subject": alert.get("email").get("headers").get("subject"),
        "MD5": alert.get("alert").get("malware_md5"),
        "URL/Attachment": alert.get("email").get("attachment"),
        "Email Status": alert.get("email").get("status"),
        "Email Accepted": alert.get("email").get("timestamp").get("accepted"),
        "Sevirity": alert.get("alert").get("severity"),
    }


def get_single_alert_summary_v2(alert):
    return {
        "Alert ID": alert.get("id"),
        "Domain": alert.get("domain"),
        "Msg": alert.get("msg"),
        "Traffic type": alert.get("traffic_type"),
        "Verdict": alert.get("verdict"),
        "Report id": alert.get("report_id"),
        "Alert date": alert.get("alert_date"),
        "Product": alert.get("product"),
        "Occurred": alert.get("alert").get("occurred"),
        "Name": alert.get("alert").get("name"),
        "Attack time": alert.get("alert").get("attack-time"),
        "Severity": alert.get("alert").get("severity"),
    }


def malware_readable_data_v2(malware):
    return {
        "Name": malware.get("name"),
        "Domain": malware.get("domain"),
        "Downloaded At": malware.get("downloaded-at"),
        "Executed At": malware.get("executed-at"),
        "Type": malware.get("stype"),
        "Submitted At": malware.get("submitted-at"),
    }


def malware_readable_data(malware):
    return {
        "Name": malware.get("name"),
        "Domain": malware.get("domain"),
        "Downloaded At": malware.get("downloaded_at"),
        "Executed At": malware.get("executed_at"),
        "Type": malware.get("stype"),
        "Submitted At": malware.get("submitted_at"),
        "SID": malware.get("sid"),
    }


def alert_context_data(alert):
    context_data = copy.deepcopy(alert)
    # remove 'attributes' level
    context_data.update(context_data.pop("attributes", {}))
    return context_data


# Deprecated endpoint
def get_alerts_request(legacy_id=None, from_last_modified_on=None, etp_message_id=None, size=None, raw_response=False):
    url = f"{BASE_PATH_V1}/alerts"

    # constract the body for the request
    body = {}
    attributes = {}
    if legacy_id:
        attributes["legacy_id"] = legacy_id
    if etp_message_id:
        attributes["etp_message_id"] = etp_message_id
    if attributes:
        body["attribute"] = attributes
    if size:
        body["size"] = size
    if from_last_modified_on:
        body["fromLastModifiedOn"] = from_last_modified_on

    response = http_request("POST", url, body=body, headers=HTTP_HEADERS)
    if raw_response:
        return response
    if response["meta"]["total"] == 0:
        return []
    return response["data"]


# Deprecated command
def get_alerts_command():
    args = demisto.args()

    if "size" in args:
        args["size"] = int(args["size"])

    if "legacy_id" in args:
        args["legacy_id"] = int(args["legacy_id"])

    # get raw data
    alerts_raw = get_alerts_request(
        legacy_id=args.get("legacy_id"),
        from_last_modified_on=args.get("from_last_modified_on"),
        etp_message_id=args.get("etp_message_id"),
        size=args.get("size"),
    )

    # create context data
    alerts_context = [alert_context_data(alert) for alert in alerts_raw]

    # create readable data
    alerts_readable_data = [alert_readable_data_summery(alert) for alert in alerts_context]
    alerts_summery_headers = [
        "Alert ID",
        "Alert Timestamp",
        "Email Accepted",
        "From",
        "Recipients",
        "Subject",
        "MD5",
        "URL/Attachment",
        "Email Status",
        "Threat Intel",
    ]
    md_table = tableToMarkdown(
        "Trellix Email Security - Cloud - Get Alerts", alerts_readable_data, headers=alerts_summery_headers
    )
    entry = {
        "Type": entryTypes["note"],
        "Contents": alerts_raw,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": md_table,
        "EntryContext": {"FireEyeETP.Alerts(obj.id==val.id)": alerts_context},
    }
    demisto.results(entry)


def upload_yara_file_command(client, args):
    entry_id = args.get("entryID")
    policy_uuid = args.get("policy_uuid")
    ruleset_uuid = args.get("ruleset_uuid")

    file_obj = demisto.getFilePath(entry_id)
    file_path = file_obj["path"]

    with open(file_path, "rb") as file:
        data = file.read()
        files = {"file": ("new.yara", data)}
        response = client.upload_yara_file(policy_uuid, ruleset_uuid, files)
        if response.status_code == 202:
            return CommandResults(readable_output="Upload of Yara file succesfully.")
        else:
            return CommandResults(readable_output="Upload of Yara file failed.")


def get_events_data_command(client, args):
    message_id = args.get("message_id")

    response = client.get_events_data(message_id)

    result_output = {}
    result_output["Logs"] = response["data"][message_id]

    for log in result_output["Logs"]:
        if log["action_on_msg"] == "MTA_RCPT_DELIVERED_OUTBOUND":
            result_output["Delivered_msg"] = log["display_msg"]
            result_output["Delivered_status"] = "Delivered"
            result_output["InternetMessageId"] = result_output["Delivered_msg"].split("<")[1].split(">")[0]
        if log["action_on_msg"] == "MTA_RCPT_DELIVERY_PERM_FAILURE_OUTBOUND":
            result_output["Delivered_msg"] = log["display_msg"]
            result_output["Delivered_status"] = "Failed"

    command_results = CommandResults(
        outputs=result_output,
        readable_output=tableToMarkdown(
            "Events", result_output, headers=["Logs", "Delivered_msg", "Delivered_status"], is_auto_json_transform=True
        ),
        outputs_prefix="FireEyeETP.Events",
    )
    return command_results


# Deprecated command
def download_alert_artifacts_command(client, args):
    alert_id = args.get("alert_id")

    response = client.get_artifacts(alert_id)
    file_entry = fileResult(alert_id + ".zip", data=response.content, file_type=EntryType.FILE)

    return [CommandResults(readable_output="Download alert artifact completed successfully"), file_entry]


def download_alert_case_files(client: Client, args):
    alert_id = args.get("alert_id")

    response = client.get_artifacts_v2(alert_id)
    file_entry = fileResult(alert_id + ".zip", data=response.content, file_type=EntryType.FILE)
    return [CommandResults(readable_output="Download alert artifact completed successfully"), file_entry]


def list_yara_rulesets_command(client, args):
    policy_uuid = args.get("policy_uuid")

    response = client.get_yara_rulesets(policy_uuid)

    command_results = CommandResults(
        outputs=response["data"]["rulesets"],
        readable_output=tableToMarkdown(
            "Rulesets", response["data"]["rulesets"], headers=["name", "description", "uuid", "yara_file_name"]
        ),
        outputs_prefix=f"FireEyeETP.Policy.{policy_uuid}",
    )

    return command_results


def download_yara_file_command(client, args):
    policy_uuid = args.get("policy_uuid")
    ruleset_uuid = args.get("ruleset_uuid")

    response = client.get_yara_file(policy_uuid, ruleset_uuid)

    file_entry = fileResult("original.yara", data=response.content, file_type=EntryType.FILE)

    return [CommandResults(readable_output="Download yara file completed successfully."), file_entry]


# Deprecated endpoint
def get_alert_request(alert_id):
    url = f"{BASE_PATH_V1}/alerts/{alert_id}"
    response = http_request("GET", url)
    if response["meta"]["total"] == 0:
        return {}
    return response["data"][0]


def create_request_body_alert_search_endpoint(args):
    body = assign_params(
        domain=argToList(args.get("domain")),
        domain_group=argToList(args.get("domain_group")),
        is_read=argToBoolean(args.get("is_read")) if args.get("is_read") else None,
        is_retro=argToBoolean(args.get("is_retro")) if args.get("is_retro") else None,
        malwarename=argToList(args.get("malwarename")),
        malwarestype=argToList(args.get("malwarestype")),
        md5=argToList(args.get("md5")),
        mta_msg_id=argToList(args.get("mta_msg_id")),
        traffic_type=args.get("traffic_type"),
        verdict=argToList(args.get("verdict")),
    )

    email_header_subject = argToList(args.get("email_header_subject"))
    if email_header_subject:
        body["email-header"] = {"subject": email_header_subject}

    return body


def quarantine_release_command(client, args):
    message_id = args.get("message_id")

    response = client.quarantine_release(message_id)

    command_results = CommandResults(
        readable_output=tableToMarkdown(
            "Quarantine", response.json()["data"], headers=["type", "operation", "successful_message_ids"]
        )
    )

    return command_results


def get_single_alert_entry(alert_id, client: Client):
    alert = client.get_alert_request_v2(alert_id)
    alert_summary = get_single_alert_summary_v2(alert)
    readable_output = tableToMarkdown("Alert Details", alert_summary)

    return CommandResults(
        readable_output=readable_output, outputs_prefix="FireEyeETP.Alerts", outputs_key_field="id", outputs=alert
    )


def get_alerts_entry(args, client: Client):
    body = create_request_body_alert_search_endpoint(args)
    size = args.get("limit")
    start_time = args.get("date_from")
    end_time = args.get("date_to")
    if start_time and not is_iso_utc(start_time):
        start_time = parse_date_range(start_time)[0].strftime("%Y-%m-%dT%H:%M:%SZ")
    if end_time and not is_iso_utc(end_time):
        end_time = parse_date_range(end_time)[0].strftime("%Y-%m-%dT%H:%M:%SZ")
    if start_time and not end_time:
        end_time = datetime.now(UTC).strftime(ISO_FORMAT)

    response = client.get_alerts_request_v2(size=size, start_time=start_time, end_time=end_time, body=body)
    alerts = response.get("data") or []
    alerts_summaries = [get_search_alert_summary_v2(alert) for alert in alerts]
    readable_output = tableToMarkdown("Trellix Email Security - Cloud - Get Alerts", alerts_summaries)

    return CommandResults(
        readable_output=readable_output, outputs_prefix="FireEyeETP.Alerts", outputs_key_field="id", outputs=alerts
    )


def get_alert_list(client: Client):
    args = demisto.args()
    alert_id = args.get("alert_id")

    # In case alert_id is provided, calling: GET /api/v2/public/alerts/<alert_id>
    if alert_id:
        command_result = get_single_alert_entry(alert_id, client)

    # alert_id is not provided, POST calling: /api/v2/public/alerts/search
    else:
        command_result = get_alerts_entry(args, client)

    return command_result


# Deprecated command
def get_alert_command():
    # get raw data
    alert_raw = get_alert_request(demisto.args()["alert_id"])
    if alert_raw:
        # create context data
        alert_context = alert_context_data(alert_raw)

        # create readable data
        readable_data = alert_readable_data(alert_context)
        alert_md_table = tableToMarkdown("Alert Details", readable_data)
        data = alert_context["alert"]["explanation"]["malware_detected"]["malware"]
        malware_data = [malware_readable_data(malware) for malware in data]
        malware_md_table = tableToMarkdown("Malware Details", malware_data)

        entry = {
            "Type": entryTypes["note"],
            "Contents": alert_raw,
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": f"## Trellix Email Security - Cloud - Get Alert\n{alert_md_table}\n{malware_md_table}",
            "EntryContext": {"FireEyeETP.Alerts(obj.id==val.id)": alert_context},
        }
        demisto.results(entry)
    # no results
    else:
        entry = {
            "Type": entryTypes["note"],
            "Contents": {},
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": "### Trellix Email Security - Cloud - Get Alert\nno results",
        }
        demisto.results(entry)


def parse_string_in_iso_format_to_datetime(iso_format_string):
    alert_last_modified = None
    try:
        alert_last_modified = datetime.strptime(iso_format_string, "%Y-%m-%dT%H:%M:%S.%f")
    except ValueError:
        try:
            alert_last_modified = datetime.strptime(iso_format_string, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            alert_last_modified = datetime.strptime(iso_format_string, "%Y-%m-%dT%H:%M")
    return alert_last_modified


def convert_to_demisto_severity(severity: str) -> int:
    """
    Converts the FireEyeETP alert severity level ('Low', 'Medium', 'High', 'Critical') to Cortex XSOAR alert
    severity (1 to 4).

    Args:
        severity (str): severity as returned from the FireEyeETP API.

    Returns:
        int: Cortex XSOAR Severity (1 to 4)
    """

    return {
        "crit": IncidentSeverity.CRITICAL,
        "majr": IncidentSeverity.HIGH,
        "minr": IncidentSeverity.LOW,
        "unkn": IncidentSeverity.UNKNOWN,
    }.get(severity, IncidentSeverity.UNKNOWN)


def parse_alert_to_incident(response):
    """
    Creates an incident from an alert with proper field mapping.

    Args:
        alert: The alert from the search API (first API call)
        detailed_alert: The detailed alert from the get alert API (second API call)

    Returns:
        Incident dictionary with mapped fields
    """
    occurred = arg_to_datetime(arg=response.get("alert", {}).get("occurred", ""))
    occurred = occurred.strftime(ISO_FORMAT) if occurred else None

    severity = response.get("alert", {}).get("severity")
    return {
        "name": response.get("id", ""),
        "occurred": occurred,
        "severity": convert_to_demisto_severity(severity),
        "rawJSON": json.dumps(response),
        "incident_type": ALERT_INCIDENT_TYPE_NAME,
    }


def fetch_incidents(client: Client):
    last_run = demisto.getLastRun()
    demisto.debug(f"[FireEyeETP - fetch_incidents] last_run before fetching:\n{last_run}")

    # The start time does not change, progress happens using the pagination token.
    start_time_dt = arg_to_datetime(FETCH_TIME)
    start_time = start_time_dt.strftime("%Y-%m-%dT%H:%M:%SZ") if start_time_dt else None
    now_utc = datetime.now(UTC).strftime(ISO_FORMAT)
    pagination_token = last_run.get("pagination_token")

    demisto.debug("[FireEyeETP - fetch_incidents] calling /api/v2/public/alerts/search")
    alerts_response = client.get_alerts_request_v2(
        size=MAX_FETCHED_ALERT, start_time=start_time, end_time=now_utc, pagination_token=pagination_token
    )

    # When no alerts are found, there is no search_after token in the response.
    if not alerts_response or not alerts_response.get("data"):
        demisto.debug("[FireEyeETP - fetch_incidents] No incident found.")
        return [], last_run

    pagination_token = alerts_response.get("meta", {}).get("search_after")
    if pagination_token:
        demisto.debug(f"[FireEyeETP - fetch_incidents] response includes a pagination token.\n{pagination_token}")
        last_run["pagination_token"] = pagination_token

    total_alert_fetched = alerts_response.get("meta", {}).get("size")
    demisto.debug(
        f"[FireEyeETP - fetch_incidents] Total incidents fetched from /api/v2/public/alerts/search: {total_alert_fetched}."
    )

    alerts = alerts_response.get("data", [])
    incidents = []
    for alert in alerts:
        alert_id = alert.get("id")
        email_status = alert.get("email_status")

        if MESSAGE_STATUS and email_status not in MESSAGE_STATUS:
            demisto.debug(f"[FireEyeETP - fetch_incidents] alert: {alert_id} with status {email_status} filtered out.")
            continue

        demisto.debug(f"[FireEyeETP - fetch_incidents] calling /api/v2/public/alerts/{alert_id}")
        alert_info = client.get_alert_request_v2(alert_id)
        incidents.append(parse_alert_to_incident(alert_info))

    if not incidents:
        demisto.debug("[FireEyeETP - fetch_incidents] all alerts filtered out, 0 alerts left.")
        return [], last_run

    demisto.debug(f"[FireEyeETP - fetch_incidents] Total incidents left after filtering: {len(incidents)}.")
    return incidents, last_run


def test_module(client: Client):
    params = demisto.params()
    try:
        if params.get("isFetch"):
            fetch_incidents(client)
        else:
            client.get_alerts_request_v2(size=1)

    except Exception as e:
        return f"test-module failed: {str(e)}"
    return "ok"


def main():
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    proxy = params.get("proxy", False)

    verify_certificate = not params.get("unsecure", False)

    set_proxies()

    try:
        # Validate authentication configuration
        validate_authentication_params()
        headers = get_auth_headers()

        command = demisto.command()

        if command == "test-module":
            client = Client(base_url=BASE_PATH_V2, verify=verify_certificate, headers=headers, proxy=proxy)
            result = test_module(client)
            return_results(result)
        elif command == "fetch-incidents":
            client = Client(base_url=BASE_PATH_V2, verify=verify_certificate, headers=headers, proxy=proxy)
            incidents, last_run = fetch_incidents(client)
            demisto.setLastRun(last_run)
            demisto.incidents(incidents)
        elif command == "fireeye-etp-search-messages":
            search_messages_command()
        elif command == "fireeye-etp-get-message":
            get_message_command()
        elif command == "fireeye-etp-get-alerts":
            get_alerts_command()
        elif command == "fireeye-etp-get-alert":
            get_alert_command()
        elif command == "fireeye-etp-list-alerts":
            client = Client(base_url=BASE_PATH_V2, verify=verify_certificate, headers=headers, proxy=proxy)
            return_results(get_alert_list(client))
        elif command == "fireeye-etp-download-alert-artifact":
            client = Client(base_url=BASE_PATH_V1, verify=verify_certificate, headers=headers, proxy=proxy)
            return_results(download_alert_artifacts_command(client, args))
        elif command == "fireeye-etp-download-alert-case-files":
            client = Client(base_url=BASE_PATH_V2, verify=verify_certificate, headers=headers, proxy=proxy)
            return_results(download_alert_case_files(client, args))
        elif command == "fireeye-etp-list-yara-rulesets":
            client = Client(base_url=BASE_PATH_V1, verify=verify_certificate, headers=headers, proxy=proxy)
            return_results(list_yara_rulesets_command(client, args))
        elif command == "fireeye-etp-download-yara-file":
            client = Client(base_url=BASE_PATH_V1, verify=verify_certificate, headers=headers, proxy=proxy)
            return_results(download_yara_file_command(client, args))
        elif command == "fireeye-etp-upload-yara-file":
            client = Client(base_url=BASE_PATH_V1, verify=verify_certificate, headers=headers, proxy=proxy)
            return_results(upload_yara_file_command(client, args))
        elif command == "fireeye-etp-get-events-data":
            client = Client(base_url=BASE_PATH_V1, verify=verify_certificate, headers=headers, proxy=proxy)
            return_results(get_events_data_command(client, args))
        elif command == "fireeye-etp-quarantine-release":
            client = Client(base_url=BASE_PATH_V1, verify=verify_certificate, headers=headers, proxy=proxy)
            return_results(quarantine_release_command(client, args))
    except ValueError as e:
        LOG(e)
        LOG.print_log()
        return_error_entry(e)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
