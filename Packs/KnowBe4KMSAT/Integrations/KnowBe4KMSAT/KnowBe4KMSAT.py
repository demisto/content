"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import traceback
import urllib3
from typing import Dict

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

""" CLIENT CLASS """


class Client(BaseClient):
    """KMSAT Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, base_url, verify, proxy, headers=None, max_fetch=None):
        self.max_fetch = max_fetch
        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy)

    def kmsat_account_info(self):
        return self._http_request(
            method="GET", url_suffix="/account", resp_type="json", ok_codes=(200,)
        )

    def kmsat_account_risk_score_history(self, params):
        return self._http_request(
            method="GET",
            url_suffix="/account/risk_score_history",
            resp_type="json",
            ok_codes=(200,),
            params=params,
        )

    def kmsat_groups_risk_score_history(self, group_id, params):
        return self._http_request(
            method="GET",
            url_suffix=f"/groups/{group_id}/risk_score_history",
            resp_type="json",
            ok_codes=(200,),
            params=params,
        )

    def kmsat_users_risk_score_history(self, user_id, params):
        return self._http_request(
            method="GET",
            url_suffix=f"/users/{user_id}/risk_score_history",
            resp_type="json",
            ok_codes=(200,),
            params=params,
        )

    def kmsat_phishing_security_tests(self, params):
        return self._http_request(
            method="GET",
            url_suffix="/phishing/security_tests",
            resp_type="json",
            ok_codes=(200,),
            params=params,
        )

    def kmsat_phishing_security_tests_recipients(self, pst_id, params):
        return self._http_request(
            method="GET",
            url_suffix=f"/phishing/security_tests/{pst_id}/recipients",
            resp_type="json",
            ok_codes=(200,),
            params=params,
        )

    def kmsat_training_campaigns(self, params):
        return self._http_request(
            method="GET",
            url_suffix="/training/campaigns",
            resp_type="json",
            ok_codes=(200,),
            params=params,
        )

    def kmsat_training_enrollments(self, params):
        return self._http_request(
            method="GET",
            url_suffix="/training/enrollments",
            resp_type="json",
            ok_codes=(200,),
            params=params,
        )


class UserEventClient(BaseClient):
    """Client class to interact with the KMSAT User EventAPI"""

    def __init__(self, base_url, verify, proxy, headers=None, max_fetch=None):
        self.max_fetch = max_fetch

        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy)

    def user_events(self, args: dict, page: int = None, page_size: int = None):

        params = remove_empty_elements(
            {
                "event_type": args.get("event_type"),
                "target_user": args.get("target_user"),
                "external_id": args.get("external_id"),
                "source": args.get("source"),
                "occurred_date": args.get("occurred_date"),
                "risk_level": args.get("risk_level"),
                "risk_decay_mode": args.get("risk_decay_mode"),
                "risk_expire_date": args.get("risk_expire_date"),
                "order_by": args.get("order_by"),
                "order_direction": args.get("order_direction"),
                "page": page,
                "per_page": page_size,
            }
        )
        return self._http_request(
            method="GET",
            url_suffix="/events",
            resp_type="json",
            ok_codes=(200,),
            params=params,
        )

    def user_event_types(self, args: dict):
        params = remove_empty_elements({"name": args.get("name")})
        return self._http_request(
            method="GET",
            url_suffix="/event_types",
            resp_type="json",
            ok_codes=(200,),
            params=params,
        )

    def create_user_event(self, args: dict, page: int = None, page_size: int = None):
        params = remove_empty_elements(
            {
                "target_user": args.get("target_user"),
                "event_type": args.get("event_type"),
                "external_id": args.get("external_id"),
                "source": args.get("source"),
                "description": args.get("description"),
                "occurred_date": args.get("occurred_date"),
                "risk_decay_mode": args.get("risk_decay_mode"),
                "risk_expire_date": args.get("risk_expire_date"),
            }
        )

        if not args.get("risk_level"):
            risk_level: int = int(args["risk_level"])
            params["risk_level"] = risk_level

        return self._http_request(
            method="POST",
            url_suffix="/events",
            resp_type="json",
            ok_codes=(201,),
            json_data=params,
        )


""" HELPER FUNCTIONS """

""" COMMAND FUNCTIONS """


def get_pagination(args: dict):
    params = remove_empty_elements(
        {"page": args.get("page"), "per_page": args.get("per_page")}
    )
    return params


def get_account_info(client: Client) -> CommandResults:
    response = client.kmsat_account_info()
    markdown = tableToMarkdown(
        "Account Info",
        response,
        [
            "name",
            "type",
            "domain",
            "admins",
            "subscription_level",
            "number_of_seats",
            "current_risk_score",
        ],
    )
    if response is None:
        raise DemistoException(
            "Translation failed: the response from server did not include `account_info`.",
            res=response,
        )
    return CommandResults(
        outputs_prefix="Account.Info",
        outputs_key_field="name",
        raw_response=response,
        outputs=response,
        readable_output=markdown,
    )


def get_account_risk_score_history(client: Client, args: dict) -> CommandResults:
    params = get_pagination(args)
    response = client.kmsat_account_risk_score_history(params)
    if response is None:
        raise DemistoException(
            "Translation failed: the response from server did not include `account_risk_score_history`.",
            res=response,
        )
    markdown = tableToMarkdown(
        "Account Risk Score History", response, ["risk_score", "date"]
    )
    return CommandResults(
        outputs_prefix="AccountRiskScore.History",
        outputs_key_field="",
        raw_response=response,
        outputs=response,
        readable_output=markdown,
    )


def get_groups_risk_score_history(client: Client, args: dict) -> CommandResults:
    group_id = remove_empty_elements(args.get("group_id"))
    params = get_pagination(args)
    response = client.kmsat_groups_risk_score_history(group_id, params)
    markdown = tableToMarkdown(
        "Groups Risk Score History", response, headers=["risk_score", "date"]
    )
    if response is None:
        raise DemistoException(
            "Translation failed: the response from server did not include `groups_risk_score_history`.",
            res=response,
        )
    return CommandResults(
        outputs_prefix="GroupsRiskScore.History",
        outputs_key_field="id",
        raw_response=response,
        readable_output=markdown,
    )


def get_users_risk_score_history(client: Client, args: dict) -> CommandResults:
    user_id = remove_empty_elements(args.get("user_id"))
    params = get_pagination(args)
    response = client.kmsat_users_risk_score_history(user_id, params)
    markdown = tableToMarkdown(
        "Users Risk Score History", response, headers=["risk_score", "date"]
    )
    if response is None:
        raise DemistoException(
            "Translation failed: the response from server did not include `users_risk_score_history`.",
            res=response,
        )
    return CommandResults(
        outputs_prefix="UsersRiskScore.History",
        outputs_key_field="",
        raw_response=response,
        readable_output=markdown,
    )


def get_phishing_security_tests(client: Client, args: dict) -> CommandResults:
    params = get_pagination(args)
    response = client.kmsat_phishing_security_tests(params)
    markdown = tableToMarkdown(
        "Phishing Security Tests",
        response,
        headers=[
            "campaign_id",
            "pst_id",
            "status",
            "name",
            "groups",
            "phish_prone_percentage",
            "started_at",
            "duration",
            "categories",
            "template",
            "landing-page",
            "scheduled_count",
            "delivered_count",
            "opened_count",
            "clicked_count",
            "replied_count",
            "attachment_open_count",
            "macro_enabled_count",
            "data_entered_count",
            "qr_code_scanned_count",
            "reported_count",
            "bounced_count",
        ],
    )
    if response is None:
        raise DemistoException(
            "Translation failed: the response from server did not include `phishing_security_tests`.",
            res=response,
        )
    return CommandResults(
        outputs_prefix="Phishing.Security",
        outputs_key_field="campaign_id",
        raw_response=response,
        readable_output=markdown,
    )


def get_phishing_security_tests_recipients(client: Client, args) -> CommandResults:
    pst_id = remove_empty_elements(args.get("pst_id"))
    params = get_pagination(args)
    response = client.kmsat_phishing_security_tests_recipients(pst_id, params)
    markdown = tableToMarkdown(
        "Phishing Security Tests Recipients",
        response,
        headers=[
            "recipient_id",
            "pst_id",
            "user",
            "template",
            "scheduled_at",
            "delivered_at",
            "opened_at",
            "clicked_at",
            "replied_at",
            "attachment_opened_at",
            "macro_enabled_at",
            "data_entered_at",
            "qr_code_scanned",
            "reported_at",
            "bounced_at",
            "ip",
            "ip_location",
            "browser",
            "browser_version",
            "os",
        ],
    )
    if response is None:
        raise DemistoException(
            "Translation failed: the response from server did not include `phishing_security_tests_recipients`.",
            res=response,
        )
    return CommandResults(
        outputs_prefix="Phishing.Security",
        outputs_key_field="recipient_id",
        raw_response=response,
        readable_output=markdown,
    )


def get_training_campaigns(client: Client, args: dict) -> CommandResults:
    params = get_pagination(args)
    response = client.kmsat_training_campaigns(params)
    markdown = tableToMarkdown(
        "Training Campaigns",
        response,
        [
            "campaign_id",
            "name",
            "groups",
            "status",
            "content",
            "duration_type",
            "start_date",
            "end_date",
            "relative_duration",
            "auto_enroll",
            "allow_multiple_enrollments",
            "completion_percentage",
        ],
    )
    if response is None:
        raise DemistoException(
            "Translation failed: the response from server did not include `training_campaigns`.",
            res=response,
        )
    return CommandResults(
        outputs_prefix="Training.Campaigns",
        outputs_key_field="campaign_id",
        raw_response=response,
        readable_output=markdown,
    )


def get_training_enrollments(client: Client, args: dict) -> CommandResults:
    params = get_pagination(args)
    response = client.kmsat_training_enrollments(params)
    markdown = tableToMarkdown(
        "Training Enrollments",
        response,
        [
            "enrollment_id",
            "content_type",
            "module_name",
            "user",
            "campaign_name",
            "enrollment_date",
            "start_date",
            "completion_date",
            "status",
            "time_spent",
            "policy_acknowledged",
        ],
    )
    if response is None:
        raise DemistoException(
            "Translation failed: the response from server did not include `training_enrollments`.",
            res=response,
        )
    return CommandResults(
        outputs_prefix="Training.Enrollments",
        outputs_key_field="enrollment_id",
        raw_response=response,
        readable_output=markdown,
    )


def fetch_incidents(client, last_run, first_fetch_time):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client: KMSAT client
        last_run: The greatest incident created_time we fetched from last fetch
        first_fetch_time: If last_run is None then fetch all incidents since first_fetch_time

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Cortex XSOAR
    """
    # Get the last fetch time, if exists
    last_fetch = last_run.get("last_fetch")

    # Handle first time fetch
    if last_fetch is None:
        last_fetch, _ = dateparser.parse(first_fetch_time)
    else:
        last_fetch = dateparser.parse(last_fetch)

    latest_created_time = last_fetch
    incidents = []
    items = client.list_incidents()
    for item in items:
        incident_created_time = dateparser.parse(item["created_time"])
        incident = {
            "name": item["description"],
            "occurred": incident_created_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "rawJSON": json.dumps(item),
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    next_run = {"last_fetch": latest_created_time.strftime(DATE_FORMAT)}
    return next_run, incidents


def fetch_incidents_command(client: Client) -> None:
    """
    Function that calls the fetch incidents and writing all incidents to demisto.incidents

    args:
        client (Client): Phisher client
    """
    first_fetch_time = client.first_fetch_time
    fetch_limit = arg_to_number(client.max_fetch)
    next_run, incidents = fetch_incidents(
        client=client,
        last_run=demisto.getLastRun(),
        first_fetch_time=first_fetch_time,
        max_fetch=fetch_limit,
    )  # type: ignore
    demisto.setLastRun({"last_fetch": next_run})
    demisto.incidents(incidents)


def get_user_events(client: UserEventClient, args: dict) -> CommandResults:
    response = client.user_events(args, 1, 100)  # TODO: paging
    return_results(response)
    if response is None:
        raise DemistoException(
            "Translation failed: the response from server did not include user event `data`.",
            res=response,
        )
    data: List[Dict] = response.get("data") or []
    return CommandResults(
        outputs_prefix="KMSAT_User_Events_Returned",
        outputs_key_field="id",
        raw_response=response,
        outputs=data,
        readable_output=tableToMarkdown(name="KMSAT_User_Events", t=data),
    )


def get_user_event_types(client: UserEventClient, args: dict) -> CommandResults:
    response = client.user_event_types(args)
    return_results(response)
    if response is None:
        raise DemistoException(
            "Translation failed: the response from server did not include user event types`data`.",
            res=response,
        )
    data: List[Dict] = response.get("data") or []
    return CommandResults(
        outputs_prefix="KMSAT_User_Event_Types_Returned",
        outputs_key_field="id",
        raw_response=response,
        outputs=data,
        readable_output=tableToMarkdown(name="KMSAT_User_Event_Types", t=data),
    )


def post_user_event(client: UserEventClient, args: dict) -> CommandResults:
    response = client.create_user_event(args)
    return_results(response)
    if response is None:
        raise DemistoException(
            "Translation failed: the response from server did not include user event types`data`.",
            res=response,
        )
    data: List[Dict] = response.get("data") or []
    return CommandResults(
        outputs_prefix="KMSAT_Create_User_EvenReturned",
        outputs_key_field="id",
        raw_response=response,
        readable_output=tableToMarkdown(name="KMSAT_Create_User_Event", t=data),
    )


def test_module(client: Client, userEventClient: UserEventClient) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :return type: ``str``
    """

    message: str = ""
    try:
        client.kmsat_account_info()
        message = "ok"
    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization" in str(e):
            message = (
                "Authorization Error: make sure Reporting API Key is correctly set"
                + str(client._headers)
            )
        else:
            raise e

    try:
        params: Dict = {}
        userEventClient.user_event_types(params)
        message = "ok"
    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization" in str(e):
            message = (
                "Authorization Error: make sure User Event API Key is correctly set"
                + str(client._headers)
            )
        else:
            raise e
    return message


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    command = demisto.command()
    params = demisto.params()
    args = demisto.args()
    demisto.debug(f"Command being called is {command}")

    # get the service API url
    base_url = urljoin(demisto.params()["url"], "/v1")
    userEvents_base_url = demisto.params()["userEventsUrl"]

    # verify api key or credentials are specified
    if not params.get("apikey") or not (
        key := params.get("apikey", {}).get("password")
    ):
        raise DemistoException(
            "Missing Reporting API Key. Fill in a valid key in the integration configuration."
        )

    # verify User Events api key or credentials are specified
    if not params.get("userEventsApiKey") or not (
        userEventsApiKey := params.get("userEventsApiKey", {}).get("password")
    ):
        raise DemistoException(
            "Missing User Events API Key. Fill in a valid key in the integration configuration."
        )

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get("insecure", False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get("proxy", False)

    try:

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers={
                "Authorization": "Bearer " + key,
                "Content-Type": "application/json",
            },
            proxy=proxy,
        )

        userEventClient = UserEventClient(
            base_url=userEvents_base_url,
            verify=verify_certificate,
            headers={
                "Authorization": "Bearer " + userEventsApiKey,
                "Content-Type": "application/json",
            },
            proxy=proxy,
        )

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client, userEventClient)
            return_results(result)
        elif command == "fetch-incidents":
            fetch_incidents_command(client)
        elif command == "get-account-info":
            return_results(get_account_info(client))
        elif command == "get-account-risk-score-history":
            return_results(get_account_risk_score_history(client, args))
        elif command == "get-groups-risk-score-history":
            return_results(get_groups_risk_score_history(client, args))
        elif command == "get-users-risk-score-history":
            return_results(get_users_risk_score_history(client, args))
        elif command == "get-phishing-security-tests":
            return_results(get_phishing_security_tests(client, args))
        elif command == "get-phishing-security-tests-recipients":
            return_results(get_phishing_security_tests_recipients(client, args))
        elif command == "get-training-campaigns":
            return_results(get_training_campaigns(client, args))
        elif command == "get-training-enrollments":
            return_results(get_training_enrollments(client, args))
        elif command == "get-user-events":
            return_results(get_user_events(userEventClient, args))
        elif command == "get-user-event-types":
            return_results(get_user_event_types(userEventClient, args))
        elif command == "post-user-event":
            return_results(post_user_event(userEventClient, args))
        else:
            raise NotImplementedError(f"command {command} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        )


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
