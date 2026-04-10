import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401s
from CommonServerUserPython import *
import hashlib
import hmac
import json
import traceback
from datetime import datetime, UTC
from typing import Any, cast
from collections.abc import Mapping

import dateparser
import urllib3

"""Darktrace Integration for Cortex XSOAR (aka Demisto)"""

# Disable insecure warnings
urllib3.disable_warnings()

"""*****CONSTANTS*****"""
EMAIL_ENDPOINT = "/agemail/api/v1.0"
SEARCH_EMAILS_ENDPOINT = f"{EMAIL_ENDPOINT}/emails/search"
GET_EMAIL_ENDPOINT = f"{EMAIL_ENDPOINT}/emails"
EMAIL_TAGS_ENDPOINT = f"{EMAIL_ENDPOINT}/resources/tags"
EMAIL_FILTERS_ENDPOINT = f"{EMAIL_ENDPOINT}/resources/filters"
EMAIL_FILTERS = {
    "anomaly_score": "Email.Antigena Email Anomaly",
    "action_taken": "Action.Action Taken",
    "tag": "Antigena Tag",
    "tag_severity": "Model Tag Severity",
    "direction": "Connection.Direction",
}
EMAIL_SEVERITY_MAPPER = {"Critical": "critical", "Warning": "warn", "Informational": "info"}

ITEMS_PER_PAGE = 20
MIN_SCORE_TO_FETCH = 0
MAX_INCIDENTS_TO_FETCH = 50
PLEASE_CONTACT = "Please contact your Darktrace representative."
EMAIL_ACTION_UNDETERMINED = "Could not execute the hold action on this email."
EMAIL_ACTION_REASON = "This is because the email was previously"
EMAIL_ACTION_RELEASED = "Email Released"
EMAIL_ACTION_RELEASE_RESPONSE = "Email added to queue"
TRIAD = tuple[str, float | str, str]


DARKTRACE_API_ERRORS = {
    "SIGNATURE_ERROR": "API Signature Error. You have invalid credentials in your config.",
    "DATE_ERROR": "API Date Error. Check that the time on this machine matches that of the Darktrace instance.",
    "ENDPOINT_ERROR": f"Invalid Endpoint. - {PLEASE_CONTACT}",
    "PRIVILEGE_ERROR": "User has insufficient permissions to access the API endpoint.",
    "UNDETERMINED_ERROR": f"Darktrace was unable to process your request - {PLEASE_CONTACT}",
    "FAILED_TO_PARSE": "N/A",
    "CONFLICT_ERROR": "A conflict was created by your request.",
    "HOLD_ACTION_FAIL": "Failed to hold email - Previously Held or Released",
    "EMAIL_NOT_FOUND_ERROR": "Email could not be found. Ensure the UUID provided is correct.",
    "RESOURCE_LOCATION_ERROR": "Request not completed - Resource could not be found",
}


"""*****CLIENT CLASS*****
Wraps all the code that interacts with the Darktrace API."""


class Client(BaseClient):
    """Client class to interact with the Darktrace API
    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def get(self, query_uri: str, params: dict[str, str] = None):
        """Handles Darktrace GET API calls"""
        return self._darktrace_api_call(query_uri, method="GET", params=params)

    def post(self, query_uri: str, data: dict = None, json: dict = None):
        """Handles Darktrace POST API calls"""
        response = self._darktrace_api_call(query_uri, method="POST", data=data, json=json)
        return response

    def _darktrace_api_call(
        self,
        query_uri: str,
        method: str,
        params: dict = None,
        data: dict = None,
        json: dict = None,
        headers: dict[str, str] = None,
    ):
        """Handles Darktrace API calls"""
        headers = {
            **self._create_headers(query_uri, params or data or json or None, is_json=bool(json)),
            **(headers or {}),
        }

        try:
            res = self._http_request(
                method,
                url_suffix=query_uri,
                params=params,
                data=data,
                json_data=json,
                resp_type="response",
                headers=headers,
                error_handler=self.error_handler,
            )

            if res.status_code not in [200, 204, 409]:
                raise Exception(
                    "Your request failed with the following error: "
                    + str(res.content)
                    + ". Response Status code: "
                    + str(res.status_code)
                )

            if res.status_code == 409:
                return {"resp": EMAIL_ACTION_UNDETERMINED}

        except Exception as e:
            raise Exception(e)
        try:
            return res.json()
        except Exception as e:
            raise ValueError(f"Failed to process the API response - {str(e)}")

    def error_handler(self, res: requests.Response):
        """Handles authentication errors"""
        if res.status_code == 400:
            values = res.json().values()
            if "API SIGNATURE ERROR" in values:
                raise Exception(DARKTRACE_API_ERRORS["SIGNATURE_ERROR"])
            elif "API DATE ERROR" in values:
                raise Exception(DARKTRACE_API_ERRORS["DATE_ERROR"])
        elif res.status_code == 409:
            error = res.json().get("error", "")
            if error != DARKTRACE_API_ERRORS["HOLD_ACTION_FAIL"]:
                raise Exception(f"{DARKTRACE_API_ERRORS['CONFLICT_ERROR']} {error}")
        elif res.status_code == 404:
            error = res.json().get("error", "")
            if "Email not found" in error:
                raise Exception(DARKTRACE_API_ERRORS["EMAIL_NOT_FOUND_ERROR"])
            else:
                raise Exception(DARKTRACE_API_ERRORS["RESOURCE_LOCATION_ERROR"])
        elif res.status_code == 302:
            # Valid hmac but invalid endpoint (should not happen)
            if res.text == "Found. Redirecting to /login":
                raise Exception(DARKTRACE_API_ERRORS["ENDPOINT_ERROR"])
            # Insufficient permissions but valid hmac
            elif res.text == "Found. Redirecting to /403":
                raise Exception(DARKTRACE_API_ERRORS["PRIVILEGE_ERROR"])
        elif res.status_code >= 300:
            raise Exception(DARKTRACE_API_ERRORS["UNDETERMINED_ERROR"])

    def _create_headers(self, query_uri: str, query_data: dict = None, is_json: bool = False) -> dict[str, str]:
        """Create headers required for successful authentication"""
        public_token, _ = self._auth
        date = (datetime.now(UTC)).isoformat(timespec="auto")
        signature = _create_signature(self._auth, query_uri, date, query_data, is_json=is_json)
        return {"DTAPI-Token": public_token, "DTAPI-Date": date, "DTAPI-Signature": signature}

    def get_email(self, uuid: str) -> dict[str, Any]:
        """Get a specific Email given it's Darktrace UUID.
        :type uuid: ``str``
        :param uuid: Darktrace UUID of desired Email.
        :return: dictionary with Email info.
        :rtype: Dict[str, Any]
        """
        query_uri = f"{GET_EMAIL_ENDPOINT}/{uuid}"
        email = self.get(query_uri)
        return email

    def search_emails(
        self, min_score: float, actioned: bool, tag_severity: list[str], start_time: int, end_time: int, direction: str | None
    ) -> list[dict[str, Any]]:
        """Searches for Darktrace emails using the '/emails/search' API endpoint
        :type min_score: ``float``
        :param min_score: min score of the email to search for. Range [0, 1].
        :type start_time: ``int``
        :type actioned: ``bool``
        :param actioned: if True only fetch emails that have been actioned.
        :type tag_severity: ``List[str]``
        :param tag_severity: emails with tags of the listed severity level will be fetched.
        :param start_time: start timestamp (epoch in seconds) for the email search
        :type end_time: ``int``
        :param end_time: end timestamp (epoch in seconds) for the email search
        :type direction: ``str | None``
        :param direction: emails with the corresponding direction will be fetched.
        :return: list containing the found Darktrace emails as dicts
        :rtype: ``List[Dict[str, Any]]``
        """
        tag_mapper = self.tag_mapper
        query_uri = SEARCH_EMAILS_ENDPOINT
        filter_triads: list[TRIAD] = [("anomaly_score", min_score, ">")]
        if len(tag_severity) == 1:
            filter_triads.append(("tag_severity", tag_severity[0], "="))
        if direction:
            filter_triads.append(("direction", direction, "="))

        page = 0
        all_emails = []
        while page < 100:
            params = email_query_builder(page, filter_triads, start_time, end_time)
            emails = self.post(query_uri, json=params)
            for email in emails:
                email_actioned = bool(len(email["rcpts"][0]["rcpt_actions_taken"]))
                email_tag_severities = [tag_mapper[tag] for tag in email["rcpts"][0]["tags"]]
                if actioned and not email_actioned:
                    pass
                elif len(tag_severity) == 2 and not set(email_tag_severities).intersection(tag_severity):
                    pass
                else:
                    all_emails.append((email.get("uuid"), email.get("dtime_unix")))
            if len(emails) < ITEMS_PER_PAGE:
                break
            page += 1
        all_emails_details = [self.get(f"{GET_EMAIL_ENDPOINT}/{email[0]}?dtime={email[1]}") for email in all_emails]
        return all_emails_details

    def action_email(self, uuid: str, action: str = "hold", recipients: str = None) -> dict[str, Any]:
        """Apply a given action to the specified Email.
        :type uuid: ``str``
        :param uuid: Unique ID of Email to apply action to.
        :type action: ``str``
        :param action: Specific action to apply.  Default action is to 'hold' email.
        :return: API response
        :rtype: ``Dict[str, Any]``
        """
        previous_status = ""
        if not recipients or recipients == "None" or action == "hold":
            email = self.get_email(uuid)
            recipients = email["rcpts"][0]["rcpt_to"]
            previous_status = email["rcpts"][0]["rcpt_status"]
        query_uri = f"{GET_EMAIL_ENDPOINT}/{uuid}/action"
        params = {"action": action, "recipients": [recipients]}
        response = self.post(query_uri, json=params)
        response["previous_status"] = previous_status
        return response

    def get_tag_mapper(self):
        """Get a list of all available tags with their details.
        :return: dictionary containing the tag IDs as keys and the human readable tag Name as values.
        :rtype: Dict[str, str]
        """
        query_uri = EMAIL_TAGS_ENDPOINT
        tags = self.get(query_uri)
        if isinstance(tags, list) and all(isinstance(tag, dict) for tag in tags):
            tag_mapper = {tag.get("name"): tag.get("status") for tag in tags}
            self.tag_mapper = tag_mapper


"""*****HELPER FUNCTIONS****"""


def email_query_builder(page: int, filter_triads: list[TRIAD], init_date: int, end_date: int) -> dict[str, Any]:
    """
    Summary:
        Function to build the dictionary used to query the API given certain API filters.
    Inputs:
        page: int: required,
        filter_triads: List[tuple[Any]]: required,
        init_date: int: required,
        end_date: int: required,
    Defaults:
        init_date: 24 hours ago
        end_date: current time
    Returns:
        Dictionary: Containing the page number, items per page, start and end times,
        and query parameters such as the API filter and value to compare query results to.
    """
    criteria_list = []
    for triad in filter_triads:
        api_filter, value, operator = triad
        criteria_list.append({"apiFilter": f"{EMAIL_FILTERS[api_filter]}", "value": f"{value}", "operator": f"{operator}"})
    return {
        "page": page,
        "itemsPerPage": ITEMS_PER_PAGE,
        "timeFrom": init_date,
        "timeTo": end_date,
        "query": {"criteriaList": criteria_list, "mode": "and"},
    }


def format_timestamp(timestamp: int) -> str:
    return datetime.strftime(datetime.fromtimestamp(timestamp), "%Y-%m-%dT%H:%M:%SZ")


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> int | None:
    """Converts an XSOAR argument to a timestamp (seconds from epoch)
    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` containing a timestamp (seconds
    since epoch). It will throw a ValueError if the input is invalid.
    If the input is None, it will throw a ValueError if required is ``True``,
    or ``None`` if required is ``False.
    :type arg: ``Any``
    :param arg: argument to convert
    :type arg_name: ``str``
    :param arg_name: argument name
    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None
    :return:
        returns an ``int`` containing a timestamp (seconds from epoch) if conversion works
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """
    if arg is None:
        if required is True:
            raise ValueError(f"Missing '{arg_name}'")
        return None

    if isinstance(arg, str) and arg.isdigit():
        # timestamp is a str containing digits - we just convert it to int
        return int(arg)
    if isinstance(arg, str):
        # we use dateparser to handle strings either in ISO8601 format, or
        # relative time stamps.
        # For example: format 2019-10-23T00:00:00 or "3 days", etc
        date = dateparser.parse(arg, settings={"TIMEZONE": "UTC"})
        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError(f"Invalid date: {arg_name}")

        return int(date.timestamp())
    if isinstance(arg, int | float):
        # Convert to int if the input is a float
        return int(arg)
    raise ValueError(f"Invalid date: '{arg_name}'")


def stringify_data(data: Mapping) -> str:
    """Stringify a params or data dict without encoding"""
    return "&".join([f"{k}={v}" for k, v in data.items()])


def check_required_fields(args, *fields):
    """Checks that required fields are found, raises a value error otherwise"""
    for field in fields:
        if field not in args:
            raise ValueError(f"Argument error could not find {field} in {args}")


def _create_signature(tokens: tuple, query_uri: str, date: str, query_data: dict = None, is_json: bool = False) -> str:
    """Create signature from Darktrace private token"""
    public_token, private_token = tokens
    if is_json:
        query_string = f"?{json.dumps(query_data)}"
    else:
        query_string = f"?{stringify_data(query_data)}" if query_data else ""

    return hmac.new(
        private_token.encode("ASCII"),
        f"{query_uri}{query_string}\n{public_token}\n{date}".encode("ASCII"),
        hashlib.sha1,
    ).hexdigest()


def format_JSON_for_email(email: dict[str, Any], tag_mapper: dict[str, str]) -> dict[str, Any]:
    """Formats JSON for get-email command.
    :type email: ``Dict[str, Any]``
    :param email: JSON email as returned by /emails/{uuid} API endpoint.
    :type tag_mapper: ``Dict[str, str]``
    :param tag_mapper: dictionary containing the tag IDs as keys and the human readable tag Name as values.
    :return: Formatted JSON containing only relevant fields for context.
    :rtype: ``Dict[str, Any]``
    """
    relevant_info = {}

    relevant_info["uuid"] = email.get("uuid")
    relevant_info["direction"] = email.get("direction", "").capitalize()
    relevant_info["time"] = email.get("dtime")
    relevant_info["timestamp"] = email.get("dtime_unix")
    relevant_info["sender"] = email.get("header_from_email")
    relevant_info["subject"] = email.get("header_subject")
    relevant_info["score"] = email.get("model_score")
    relevant_info["darktrace_url"] = f"{demisto.params().get('url', '')}/agemail/?uuid={email.get('uuid')}"
    relevant_info["attachments"] = email.get("n_attachments")
    relevant_info["links"] = email.get("n_links")
    recipient = email.get("rcpts", [None])[0]
    relevant_info["recipient"] = recipient.get("rcpt_to")
    relevant_info["receipt_status"] = recipient.get("rcpt_status").capitalize()
    relevant_info["read_status"] = str(recipient.get("is_read")).capitalize()
    all_tags = recipient["tags"]
    relevant_info["tags"] = all_tags
    relevant_info["tags_critical"] = [tag for tag in all_tags if tag_mapper[tag] == "critical"]
    relevant_info["tags_warning"] = [tag for tag in all_tags if tag_mapper[tag] == "warn"]
    relevant_info["tags_informational"] = [tag for tag in all_tags if tag_mapper[tag] == "info"]
    relevant_info["summary"] = " ".join(recipient.get("summary"))
    relevant_info["actions"] = ", ".join(recipient.get("rcpt_actions_taken", []))
    relevant_info["action_status"] = str(recipient.get("action_status")).capitalize()
    relevant_info["release_requested"] = bool(recipient.get("requestedRelease"))
    return relevant_info


def _compute_xsoar_severity(tags: list["str"], actions: list["str"], score: int, tag_mapper: dict) -> int:
    """Translates Darktrace email tags into XSOAR Severity"""
    if "critical" in [tag_mapper[tag] for tag in tags if tag_mapper[tag]] and score > 75 and "Hold message" not in actions:
        return 4
    elif "critical" in [tag_mapper[tag] for tag in tags if tag_mapper[tag]] and score > 50 and "Hold message" not in actions:
        return 3
    elif (
        ("warn" in [tag_mapper[tag] for tag in tags if tag_mapper[tag]] and score > 50)
        or ("critical" in [tag_mapper[tag] for tag in tags if tag_mapper[tag]] and score < 50)
    ) and "Hold message" not in actions:
        return 2
    return 1


"""*****COMMAND FUNCTIONS****"""


def test_module(client: Client, first_fetch_time: int) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    :type client: ``Client``
    :param client:
        Darktrace Client
    :type first_fetch_time: ``int``
    :param first_fetch_time:
        First fetch time
    :return:
        A message to indicate the integration works as it is supposed to
    :rtype: ``str``
    """
    end_time = int(datetime.now().timestamp())
    try:
        client.search_emails(
            min_score=0,
            tag_severity=["critical", "info"],
            direction=None,
            actioned=True,
            start_time=first_fetch_time,
            end_time=end_time,
        )

    except DemistoException as e:
        if "Forbidden" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return "ok"


def fetch_incidents(
    client: Client,
    max_alerts: int,
    last_run: dict[str, int],
    first_fetch_time: int | None,
    min_score: int,
    actioned: bool,
    tag_severity: list[str],
    direction: str | None,
) -> tuple[dict[str, int], list[dict]]:
    """This function retrieves new model breaches every minute. It will use last_run
    to save the timestamp of the last incident it processed. If last_run is not provided,
    it should use the integration parameter first_fetch to determine when to start fetching
    the first time.
    :type client: ``Client``
    :param Client: Darktrace client to use
    :type max_alerts: ``int``
    :param max_alerts: Maximum numbers of incidents per fetch
    :type last_run: ``Dict[str, int]``
    :param last_run:
        A dict with a key containing the latest incident created time we got
        from last fetch
    :type first_fetch_time: ``Optional[int]``
    :param first_fetch_time:
        If last_run is None (first time we are fetching), it contains
        the timestamp in milliseconds on when to start fetching incidents
    :type min_score: ``int``
    :param min_score:
        min_score of model breaches to pull. Range is [0,100]
    :type actioned: ``bool``
    :param actioned:
        get actioned emails only
    :type tag_severity: ``List[str]``
    :param tag_severity:
        list of tag severities to filter by when fetching emails
    :type direction: ``str | None``
        :param direction: emails with the corresponding direction will be fetched.
    :return:
        A tuple containing two elements:
            next_run (``Dict[str, int]``): Contains the timestamp that will be
                    used in ``last_run`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR
    :rtype: ``Tuple[Dict[str, int], List[dict]]``
    """

    # Get the last fetch time, if exists
    # last_run is a dict with a single key, called last_fetch
    temp_last_fetch = last_run.get("last_fetch", None)
    # Handle first fetch time
    last_fetch: int
    if temp_last_fetch is None:
        last_fetch = first_fetch_time if isinstance(first_fetch_time, int) else int(datetime.now().timestamp())
    else:
        last_fetch = int(temp_last_fetch)

    # for type checking, making sure that latest_created_time is int
    latest_created_time = cast(int, last_fetch)

    # Each incident is a dict with a string as a key
    incidents: list[dict[str, Any]] = []

    # Get current time
    end_time = int(datetime.now().timestamp())

    # Get emails from timeframe
    emails = client.search_emails(
        min_score=min_score,
        actioned=actioned,
        tag_severity=tag_severity,
        direction=direction,
        start_time=last_fetch,
        end_time=end_time,
    )

    # Sort emails from oldest to newest
    emails = sorted(emails, key=lambda d: d["dtime_unix"])

    for email in emails:
        # If no created_time set is as epoch (0). We use time in ms, which
        # matches the Darktrace API response
        incident_created_time = int(email.get("dtime_unix", 0))
        email["time"] = timestamp_to_datestring(incident_created_time)

        # to prevent duplicates, we are only adding incidents with creation_time > last fetched incident
        if last_fetch and incident_created_time <= last_fetch:
            continue
        sender = email["header_from_email"]
        recipient = email["rcpts"][0]["rcpt_to"]
        score = int(email["model_score"])
        incident_name = f"DT Email from {sender} to {recipient} | Anomaly score {score}"

        formatted_JSON = format_JSON_for_email(email, client.tag_mapper)
        xsoar_severity = _compute_xsoar_severity(formatted_JSON["tags"], formatted_JSON["actions"], score, client.tag_mapper)

        incident = {
            "name": incident_name,
            "occurred": timestamp_to_datestring(incident_created_time),
            "rawJSON": json.dumps(formatted_JSON),
            "severity": xsoar_severity,
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

        if len(incidents) >= max_alerts:
            break

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {"last_fetch": latest_created_time}
    return next_run, incidents


def get_email_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """darktrace-email-get-email command: Return a Darktrace email

    :type client: ``Client``
    :param client: Darktrace client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['uuid']`` email UUID to return

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``, that contains an email.
    :rtype: ``CommandResults``
    """
    check_required_fields(args, "uuid")
    uuid = str(args.get("uuid"))
    email = client.get_email(uuid=uuid)

    # Format JSON for Context Output
    formatted_output = format_JSON_for_email(email, client.tag_mapper)

    readable_output = tableToMarkdown(f"Darktrace Email {uuid}", formatted_output)

    return CommandResults(
        readable_output=readable_output, outputs_prefix="Darktrace.Email", outputs_key_field="uuid", outputs=formatted_output
    )


def hold_email_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """darktrace-email-hold-email command: Apply 'hold' action to specified Email.

    :type client: ``Client``
    :param client: Darktrace client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['uuid']`` email UUID to return

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``, that contains a list of tags.
    :rtype: ``CommandResults``
    """
    uuid = str(args.get("uuid"))
    response = client.action_email(uuid=uuid)

    if response["resp"] == EMAIL_ACTION_UNDETERMINED:
        output_response = {"resp": f"{EMAIL_ACTION_UNDETERMINED} {EMAIL_ACTION_REASON} {response['previous_status']}."}
    else:
        output_response = {"resp": f"{response['resp']}"}

    readable_output = tableToMarkdown(f"Holding Email {uuid}", output_response)

    return CommandResults(
        readable_output=readable_output, outputs_prefix="Darktrace.Action", outputs_key_field="resp", outputs=response
    )


def release_email_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """darktrace-email-release-email command: Release a previously held Email.

    :type client: ``Client``
    :param client: Darktrace client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['uuid']`` email UUID to return

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``, that contains a list of tags.
    :rtype: ``CommandResults``
    """
    uuid = str(args.get("uuid"))
    recipients = str(args.get("recipient"))
    response = client.action_email(uuid=uuid, recipients=recipients, action="release")

    if response["resp"] == EMAIL_ACTION_RELEASE_RESPONSE:
        output_response = {"resp": EMAIL_ACTION_RELEASED}
    else:
        output_response = {"resp": response["resp"]}

    readable_output = tableToMarkdown(f"Releasing Email {uuid}", output_response)

    return CommandResults(
        readable_output=readable_output, outputs_prefix="Darktrace.Action", outputs_key_field="resp", outputs=response
    )


"""*****MAIN FUNCTIONS****
Takes care of reading the integration parameters via
the ``demisto.params()`` function, initializes the Client class and checks the
different options provided to ``demisto.commands()``, to invoke the correct
command function passing to it ``demisto.args()`` and returning the data to
``return_results()``. If implemented, ``main()`` also invokes the function
``fetch_incidents()``with the right parameters and passes the outputs to the
``demisto.incidents()`` function. ``main()`` also catches exceptions and
returns an error message via ``return_error()``.
"""


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions
    :return:
    :rtype:
    """

    # Collect Darktrace URL
    base_url = demisto.params().get("url")

    # Collect API tokens
    public_api_token = demisto.params().get("publicApiKey", "")
    private_api_token = demisto.params().get("privateApiKey", "")
    tokens = (public_api_token, private_api_token)

    # Client class inherits from BaseClient, so SSL verification is
    # handled out of the box by it. Pass ``verify_certificate`` to
    # the Client constructor.
    verify_certificate = not demisto.params().get("insecure", False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_timestamp(
        arg=demisto.params().get("first_fetch", "1 day"), arg_name="First fetch time", required=True
    )

    # Client class inherits from BaseClient, so system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get("proxy", False)

    # ``demisto.debug()``, ``demisto.info()``, prints information in the XSOAR server log.
    demisto.debug(f"Command being called is {demisto.command()}")

    try:
        client = Client(base_url=base_url, verify=verify_certificate, proxy=proxy, auth=tokens)
        client.get_tag_mapper()

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            start_time = first_fetch_time if isinstance(first_fetch_time, int) else int(datetime.now().timestamp())
            return_results(test_module(client, start_time))

        elif demisto.command() == "fetch-incidents":
            # Set and define the fetch incidents command to run after activated via integration settings.

            # Convert the argument to an int using helper function or set to MIN_SCORE_TO_FETCH
            min_score = arg_to_number(arg=demisto.params().get("min_score"), arg_name="min_score", required=False)
            if not min_score or min_score < MIN_SCORE_TO_FETCH:
                min_score = MIN_SCORE_TO_FETCH

            # Get actioned status argument
            actioned = demisto.params().get("actioned")

            # Get tag severities to filter by
            tag_severity = demisto.params().get("tag_severity")
            if isinstance(tag_severity, str):
                tag_severity = [EMAIL_SEVERITY_MAPPER[tag_severity]]
            elif isinstance(tag_severity, list):
                tag_severity = [EMAIL_SEVERITY_MAPPER[tag_sev] for tag_sev in tag_severity]

            # Get direction to filter by
            direction = demisto.params().get("direction", False)

            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_alerts = arg_to_number(
                arg=demisto.params().get("max_fetch", MAX_INCIDENTS_TO_FETCH), arg_name="max_fetch", required=False
            )
            if not max_alerts or max_alerts > MAX_INCIDENTS_TO_FETCH:
                max_alerts = MAX_INCIDENTS_TO_FETCH

            next_run, incidents = fetch_incidents(
                client=client,
                max_alerts=max_alerts,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=first_fetch_time,
                min_score=min_score,
                actioned=actioned,
                tag_severity=tag_severity,
                direction=direction,
            )

            # Use the variables defined above as the outputs of fetch_incidents to set up the next call and create incidents:
            # saves next_run for the time fetch-incidents is invoked
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to create
            demisto.incidents(incidents)

        elif demisto.command() == "darktrace-email-get-email":
            return_results(get_email_command(client, demisto.args()))

        elif demisto.command() == "darktrace-email-hold-email":
            return_results(hold_email_command(client, demisto.args()))

        elif demisto.command() == "darktrace-email-release-email":
            return_results(release_email_command(client, demisto.args()))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


"""*****ENTRY POINT****"""
if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
