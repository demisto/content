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

    def __init__(self, base_url, verify, proxy, headers=None):
        headers["X-KB4-Integration"] = "Cortex XSOAR KMSAT"
        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy)

    def kmsat_account_info(self):
        """ Returns account info

        Returns:
            dict: HTTP Response
        """
        return self._http_request(
            method="GET", url_suffix="/account", resp_type="json", ok_codes=(200,)
        )

    def kmsat_account_risk_score_history(self, params: dict):
        """ Returns account risk score history

        Args:
            params (dict): Params for account risk score history

        Returns:
            dict: HTTP Response
        """
        return self._http_request(
            method="GET",
            url_suffix="/account/risk_score_history",
            resp_type="json",
            ok_codes=(200,),
            params=params,
        )

    def kmsat_groups_list(self, params: dict):
        """ Returns groups

        Args:
            params (dict): Params for groups risk score history

        Returns:
            dict: HTTP Response
        """
        return self._http_request(
            method="GET",
            url_suffix="/groups",
            resp_type="json",
            ok_codes=(200,),
            params=params,
        )

    def kmsat_groups_risk_score_history(self, group_id: int, params: dict):
        """ Returns groups risk score history

        Args:
            group_id (int): Group ID
            params (dict): Params for groups risk score history

        Returns:
            dict: HTTP Response
        """
        return self._http_request(
            method="GET",
            url_suffix=f"/groups/{group_id}/risk_score_history",
            resp_type="json",
            ok_codes=(200, ),
            params=params,
        )

    def kmsat_groups_members(self, group_id: int, params: dict):
        """ Returns groups members

        Args:
            group_id (int): Group ID
            params (dict): Params for groups members

        Returns:
            dict: HTTP Response
        """
        return self._http_request(
            method="GET",
            url_suffix=f"/groups/{group_id}/members",
            resp_type="json",
            ok_codes=(200, ),
            params=params,
        )

    def kmsat_users_risk_score_history(self, user_id: int, params: dict):
        """ Returns user risk score history

        Args:
            user_id (int): User ID
            params (dict): Params for user risk score history

        Returns:
            dict: HTTP Response
        """
        return self._http_request(
            method="GET",
            url_suffix=f"/users/{user_id}/risk_score_history",
            resp_type="json",
            ok_codes=(200, ),
            params=params,
        )

    def kmsat_phishing_security_tests(self, params: dict):
        """ Returns phishing security tests

        Args:
            params (dict): Params for phishing security tests

        Returns:
            dict: HTTP Response
        """
        return self._http_request(
            method="GET",
            url_suffix="/phishing/security_tests",
            resp_type="json",
            ok_codes=(200,),
            params=params,
        )

    def kmsat_phishing_security_tests_recipients(self, pst_id, params):
        """ Returns recipients phishing security tests

        Args:
            pst_id (int): PST ID
            params (dict): Params for recipients phishing security tests

        Returns:
            dict: HTTP Response
        """
        return self._http_request(
            method="GET",
            url_suffix=f"/phishing/security_tests/{pst_id}/recipients",
            resp_type="json",
            ok_codes=(200, ),
            params=params,
        )

    def kmsat_phishing_campaign_security_tests(self, campaign_id: int, params: dict):
        """ Returns campaign phishing security tets

        Args:
            campaign_id (int): Campaign ID
            params (dict): Params for campaign phishing security tests

        Returns:
            dict: HTTP Response
        """
        return self._http_request(
            method="GET",
            url_suffix=f"/phishing/campaigns/{campaign_id}/security_tests",
            resp_type="json",
            ok_codes=(200, ),
            params=params,
        )

    def kmsat_training_campaigns(self, params: dict):
        """ Returns training campaigns

        Args:
            params (dict): Params for training campaigns

        Returns:
            dict: HTTP Response
        """
        return self._http_request(
            method="GET",
            url_suffix="/training/campaigns",
            resp_type="json",
            ok_codes=(200,),
            params=params,
        )

    def kmsat_training_enrollments(self, params):
        """ Returns training enrollments

        Args:
            params (dict): Params for training enrollment

        Returns:
            dict: HTTP Response
        """
        return self._http_request(
            method="GET",
            url_suffix="/training/enrollments",
            resp_type="json",
            ok_codes=(200,),
            params=params,
        )


class UserEventClient(BaseClient):
    """Client class to interact with the KMSAT User EventAPI"""

    def __init__(self, base_url, verify, proxy, headers=None):
        headers["X-KB4-Integration"] = "Cortex XSOAR KMSAT"
        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy)

    def user_events(self, args: dict):
        """ Returns user events

        Args:
            args (dict): Params for API call

        Returns:
            dict: HTTP Response
        """
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
                "page": args.get("page"),
                "per_page": args.get("per_page"),
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
        """ Returns user event types

        Args:
            args (dict): Params for API call

        Returns:
            dict: HTTP Response
        """
        params = remove_empty_elements({"name": args.get("name")})
        return self._http_request(
            method="GET",
            url_suffix="/event_types",
            resp_type="json",
            ok_codes=(200,),
            params=params,
        )

    def create_user_event(self, args: dict):
        """ Creates a user event

        Args:
            args (dict): Params for API call

        Returns:
            dict: HTTP Response
        """

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

        # Converts string to int if value is set
        if args.get("risk_level") is not None:
            risk_level: int = int(args["risk_level"])
            params["risk_level"] = risk_level

        return self._http_request(
            method="POST",
            url_suffix="/events",
            resp_type="json",
            ok_codes=(201,),
            json_data=params,
        )

    def delete_user_event(self, event_id: str):
        """ Deletes a user event

        Args:
            args (dict): Params for API call

        Returns:
            dict: HTTP Response
        """

        return self._http_request(
            method="DELETE",
            url_suffix=f"/events/{event_id}",
            resp_type="response",
            raise_on_status=True,
            ok_codes=(204,),
        )

    def user_event(self, event_id: str):
        """ Deletes a user event

        Args:
            args (dict): Params for API call

        Returns:
            dict: HTTP Response
        """

        return self._http_request(
            method="GET",
            url_suffix=f"/events/{event_id}",
            resp_type="json",
            raise_on_status=True,
            ok_codes=(200, ),
        )

    def user_event_status(self, request_id: str):
        """ gets a specific user event create request status

        Args:
            args (dict): Params for API call

        Returns:
            dict: HTTP Response
        """

        return self._http_request(
            method="GET",
            url_suffix=f"/statuses/{request_id}",
            resp_type="json",
            raise_on_status=True,
            ok_codes=(200, ),
        )

    def user_event_statuses(self, params: dict):
        """ gets a list of user event request statuses

        Args:
            args (dict): Params for API call

        Returns:
            dict: HTTP Response
        """

        return self._http_request(
            method="GET",
            url_suffix="/statuses",
            resp_type="json",
            raise_on_status=True,
            ok_codes=(200,),
            params=params,
        )


""" HELPER FUNCTIONS """


def get_pagination(args: dict):
    """ Returns pagination params

        Args:
            args (dict): Params for pagination

        Returns:
            list: Returns cleaned params for paging
        """

    return remove_empty_elements(
        {"page": args.get("page"), "per_page": args.get("per_page")}
    )


""" COMMAND FUNCTIONS """


def kmsat_account_info_list_command(client: Client, args: dict) -> CommandResults:
    """ Returns account information

    Args:
        client (Client): Report Client

    Raises:
        DemistoException: Raises Demisto Exception

    Returns:
        CommandResults: Returns context data for account information
    """
    response = client.kmsat_account_info()
    markdown = tableToMarkdown(
        "Account Info",
        response,
        [
            "name",
            "type",
            "domains",
            "admins",
            "subscription_level",
            "subscription_end_date",
            "number_of_seats",
            "current_risk_score",
        ],
    )

    return CommandResults(
        outputs_prefix="KMSAT.AccountInfo",
        outputs_key_field="name",
        raw_response=response,
        outputs=response,
        readable_output=markdown,
    )


def kmsat_account_risk_score_history_list_command(
    client: Client, args: dict
) -> CommandResults:
    """ Lists account risk score history

    Args:
        client (Client): Report Client
        args (dict): Params for account risk score history

    Raises:
        DemistoException: Raises Demisto Exception

    Returns:
        CommandResults: Returns context data for account risk score history
    """
    params = get_pagination(args)
    response = client.kmsat_account_risk_score_history(params)

    markdown = tableToMarkdown(
        "Account Risk Score History", response, ["risk_score", "date"]
    )
    return CommandResults(
        outputs_prefix="KMSAT.AccountRiskScoreHistory",
        outputs_key_field="",
        raw_response=response,
        outputs=response,
        readable_output=markdown,
    )


def kmsat_groups_list_command(client: Client, args: dict) -> CommandResults:
    params = get_pagination(args)
    response = client.kmsat_groups_list(params)

    markdown = tableToMarkdown(
        "Groups ",
        response,
        [
            "id",
            "name",
            "group_type",
            "provisioning_guid",
            "member_count",
            "current_risk_score",
            "status"
        ]
    )

    return CommandResults(
        outputs_prefix="KMSAT.Groups",
        outputs_key_field="id",
        raw_response=response,
        outputs=response,
        readable_output=markdown,
    )


def kmsat_groups_risk_score_history_list_command(
    client: Client, args: dict
) -> CommandResults:
    """ Lists groups risk score history

    Args:
        client (Client): Report Client
        args (dict): Params for group risk score history

    Raises:
        DemistoException: Raises Demisto Exception

    Returns:
        CommandResults: Returns context data for training enrollments
    """
    group_id = remove_empty_elements(args.get("group_id"))
    params = get_pagination(args)
    response = client.kmsat_groups_risk_score_history(group_id, params)
    markdown = tableToMarkdown(
        "Groups Risk Score History", response, headers=["risk_score", "date"]
    )

    return CommandResults(
        outputs_prefix="KMSAT.GroupsRiskScoreHistory",
        outputs_key_field="id",
        raw_response=response,
        outputs=response,
        readable_output=markdown,
    )


def kmsat_groups_members_list_command(
    client: Client, args: dict
) -> CommandResults:
    """ Lists groups members

    Args:
        client (Client): Report Client
        args (dict): Params for groups members

    Raises:
        DemistoException: Raises Demisto Exception

    Returns:
        CommandResults: Returns context data for groups members
    """
    group_id = remove_empty_elements(args.get("group_id"))
    params = get_pagination(args)
    response = client.kmsat_groups_members(group_id, params)
    markdown = tableToMarkdown(
        "Groups Members",
        response,
        [
            "id",
            "employee_number",
            "first_name",
            "last_name",
            "job_title",
            "email",
            "phish_prone_percentage",
            "phone_number",
            "extension",
            "mobile_phone_number",
            "location",
            "division",
            "manager_name",
            "manager_email",
            "provisioning_managed",
            "provisioning_guid",
            "groups",
            "current_risk_score",
            "aliases",
            "joined_on",
            "last_sign_in",
            "status",
            "organization",
            "department",
            "language",
            "comment",
            "employee_start_date",
            "archived_at",
            "custom_field_1",
            "custom_field_2",
            "custom_field_3",
            "custom_field_4",
            "custom_date_1",
            "custom_date_2",
        ]
    )

    return CommandResults(
        outputs_prefix="KMSAT.GroupsMembers",
        outputs_key_field="id",
        raw_response=response,
        outputs=response,
        readable_output=markdown,
    )


def kmsat_users_risk_score_history_list_command(
    client: Client, args: dict
) -> CommandResults:
    """ Lists user risk score history

    Args:
        client (Client): Report Client
        args (dict): Params for user risk score history

    Raises:
        DemistoException: Raises Demisto Exception

    Returns:
        CommandResults: Returns context data for user risk score history
    """
    user_id = remove_empty_elements(args.get("user_id"))
    params = get_pagination(args)
    response = client.kmsat_users_risk_score_history(user_id, params)
    markdown = tableToMarkdown(
        "Users Risk Score History", response, headers=["risk_score", "date"]
    )

    return CommandResults(
        outputs_prefix="KMSAT.UsersRiskScoreHistory",
        outputs_key_field="",
        raw_response=response,
        outputs=response,
        readable_output=markdown,
    )


def kmsat_phishing_security_tests_list_command(
    client: Client, args: dict
) -> CommandResults:
    """ Lists phishing security tests

    Args:
        client (Client): Report Client
        args (dict): Params for phishing security tests

    Raises:
        DemistoException: Raises Demisto Exception

    Returns:
        CommandResults: Returns context data for phishing security
    """
    params = get_pagination(args)
    response = client.kmsat_phishing_security_tests(params)
    markdown = tableToMarkdown(
        "Phishing Security Tests",
        response,
        [
            "campaign_id",
            "pst_id",
            "status",
            "name",
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

    return CommandResults(
        outputs_prefix="KMSAT.PhishingSecurity",
        outputs_key_field="campaign_id",
        raw_response=response,
        outputs=response,
        readable_output=markdown,
    )


def kmsat_phishing_security_tests_recipients_list_command(
    client: Client, args: dict
) -> CommandResults:
    """ Lists KMSAT recipients phishing security tests

    Args:
        client (Client): Report Client
        args (_type_): Params for recipients phishing security tests

    Raises:
        DemistoException: Raises Demisto Exception

    Returns:
        CommandResults: Returns context data for recipients phishing security tests
    """
    pst_id = remove_empty_elements(args.get("pst_id"))
    params = get_pagination(args)
    response = client.kmsat_phishing_security_tests_recipients(pst_id, params)
    markdown = tableToMarkdown(
        "Phishing Security Tests Recipients",
        response,
        [
            "recipient_id",
            "pst_id",
            "user",
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
        ],
    )

    return CommandResults(
        outputs_prefix="KMSAT.PhishingSecurityPST",
        outputs_key_field="recipient_id",
        raw_response=response,
        outputs=response,
        readable_output=markdown,
    )


def kmsat_phishing_security_tests_failed_recipients_list_command(
    client: Client, args: dict
) -> CommandResults:
    """ Lists KMSAT recipients that have FAILED the phishing security tests

    Args:
        client (Client): Report Client
        args (dict): Params for recipients that failed security tests

    Raises:
        DemistoException: Raises Demisto Exception

    Returns:
        CommandResults: Returns context data for recipients that failed phishing security tests
    """

    pst_id = remove_empty_elements(args.get("pst_id"))
    params = get_pagination(args)
    response = client.kmsat_phishing_security_tests_recipients(pst_id, params)

    filtered_items_in_page = 0

    items_total = len(response)

    # Sets paging_end False if the response count is less than the per_page
    per_page = int(params.get('per_page')) if (params.get('per_page')) else 100

    paging_end = len(response) < per_page

    data = []
    for i in range(len(response)):
        clicked_at = response[i]['clicked_at']
        replied_at = response[i]['replied_at']
        attachment_opened_at = response[i]['attachment_opened_at']
        macro_enabled_at = response[i]['macro_enabled_at']
        data_entered_at = response[i]['data_entered_at']
        qr_code_scanned = response[i]['qr_code_scanned']

        if any([clicked_at, replied_at, attachment_opened_at, macro_enabled_at, data_entered_at, qr_code_scanned]):
            data.append(response[i])
            filtered_items_in_page += 1

    # Adds meta to the result set for paging
    metadata = {
        "paging_end": paging_end,
        "filtered_items_in_page": filtered_items_in_page,
        "items_total": items_total
    }

    d = {
        "data": data,
        "meta": metadata
    }

    markdown = tableToMarkdown(
        "Phishing Security Tests Recipients",
        d["data"],
        [
            "recipient_id",
            "pst_id",
            "user",
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
        ],
    )

    return CommandResults(
        outputs_prefix="KMSAT.PhishingSecurityPST",
        outputs_key_field="recipient_id",
        raw_response=d,
        outputs=d,
        readable_output=markdown,
    )


def kmsat_phishing_campaign_security_tests_list_command(client: Client, args) -> CommandResults:
    """ Lists KMSAT campaign phishing security tets

    Args:
        client (Client): Report Client
        args (_type_): Params for campaign phishing security tests

    Raises:
        DemistoException: Raises Demisto Exception

    Returns:
        CommandResults: Returns context data for phishing campaign security tests
    """
    campaign_id = remove_empty_elements(args.get("campaign_id"))
    params = get_pagination(args)
    response = client.kmsat_phishing_campaign_security_tests(campaign_id, params)
    markdown = tableToMarkdown(
        "Phishing Campaign Security Tests",
        response,
        [
            "campaign_id",
            "pst_id",
            "status",
            "started_at",
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
        ]
    )

    return CommandResults(
        outputs_prefix="KMSAT.CampaignPST",
        outputs_key_field="",
        raw_response=response,
        outputs=response,
        readable_output=markdown,
    )


def kmsat_training_campaigns_list_command(client: Client, args: dict) -> CommandResults:
    """ Lists KMSAT training campaigns

    Args:
        client (Client): Report Client
        args (dict): Params for training campaigns

    Raises:
        DemistoException: Raises Demisto Exception

    Returns:
        CommandResults: Returns context data for training campaigns
    """
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

    return CommandResults(
        outputs_prefix="KMSAT.TrainingCampaigns",
        outputs_key_field="campaign_id",
        raw_response=response,
        outputs=response,
        readable_output=markdown,
    )


def kmsat_training_enrollments_list_command(
    client: Client, args: dict
) -> CommandResults:
    """ Lists KMSAT training enrollments

    Args:
        client (Client): Report Client
        args (dict): Params for training enrollments

    Raises:
        DemistoException: Raises Demisto Exception

    Returns:
        CommandResults: Returns context data for training enrollments
    """
    status = remove_empty_elements(args.get("status"))
    params = get_pagination(args)
    response = client.kmsat_training_enrollments(params)

    data = []
    filtered_items_in_page = 0
    items_total = len(response)

    # Sets paging_end False if the response count is less than the per_page
    per_page = int(params.get('per_page')) if (params.get('per_page')) else 100

    paging_end = len(response) < per_page

    # Adds only the filtered items to the response with counts
    if status is not None:
        for i in range(len(response)):
            if response[i]['status'] == f"{status}":
                data.append(response[i])
                filtered_items_in_page += 1
    else:
        data = client.kmsat_training_enrollments(params)

    # Adds meta to the result set for paging
    metadata = {
        "paging_end": paging_end,
        "filtered_items_in_page": filtered_items_in_page,
        "items_total": items_total
    }

    d = {
        "data": data,
        "meta": metadata
    }

    markdown = tableToMarkdown(
        "Training Enrollments",
        d["data"],
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
        ]

    )
    return CommandResults(
        outputs_prefix="KMSAT.TrainingEnrollments",
        outputs_key_field="enrollment_id",
        raw_response=d,
        outputs=d,
        readable_output=markdown,
    )


def kmsat_user_events_list_command(
    client: UserEventClient, args: dict
) -> CommandResults:
    """ Lists the user events

    Args:
        client (UserEventClient): UserEventClient
        args (dict): Params for user events

    Raises:
        DemistoException: Raises Demisto Exception

    Returns:
        CommandResults: Returns context data for user events
    """
    response = client.user_events(args)

    data: List[dict] = response.get("data") or []
    return CommandResults(
        outputs_prefix="KMSAT.UserEvents",
        outputs_key_field="id",
        raw_response=response,
        outputs=data,
        readable_output=tableToMarkdown(name="KMSAT User Events", t=data),
    )


def kmsat_user_event_types_list_command(
    client: UserEventClient, args: dict
) -> CommandResults:
    """ Lists user event types

    Args:
        client (UserEventClient): UserEventClient
        args (dict): Params for user event types

    Raises:
        DemistoException: Raises Demisto Exception

    Returns:
        CommandResults: Returns context data for user event types
    """
    response = client.user_event_types(args)

    data: List[dict] = response.get("data") or []
    return CommandResults(
        outputs_prefix="KMSAT.UserEventTypes",
        outputs_key_field="id",
        raw_response=response,
        outputs=data,
        readable_output=tableToMarkdown(name="KMSAT User Event Types", t=data),
    )


def kmsat_user_event_create_command(
    client: UserEventClient, args: dict
) -> CommandResults:
    """ Creates a user event

    Args:
        client (UserEventClient): UserEventClient
        args (dict): Params for user even create

    Raises:
        DemistoException: Raises Demisto Exception

    Returns:
        CommandResults: Returns context data user create event
    """
    response = client.create_user_event(args)

    data: List[dict] = response.get("data") or []
    return CommandResults(
        outputs_prefix="KMSAT.UserEventCreate",
        outputs_key_field="id",
        raw_response=response,
        outputs=data,
        readable_output=tableToMarkdown(name="KMSAT Create User Event", t=data),
    )


def kmsat_user_event_delete_command(
    client: UserEventClient, args: dict
) -> CommandResults:
    """ Deletes a user event

    Args:
        client (UserEventClient): UserEventClient
        args (dict): Params for user even delete

    Returns:
        CommandResults: Returns message with deleted event ID
    """
    event_id: str = str(args.get("id"))
    client.delete_user_event(event_id)
    return CommandResults(
        readable_output=f"Successfully deleted event: {event_id}")


def kmsat_user_event_list_command(
    client: UserEventClient, args: dict
) -> CommandResults:
    """ list details for a user event

    Args:
        client (UserEventClient): UserEventClient
        args (dict): Params for user even create

    Raises:
        DemistoException: Raises Demisto Exception

    Returns:
        CommandResults: Returns context data user create event
    """
    event_id: str = str(args.get("id"))
    response = client.user_event(event_id)

    data: List[dict] = response.get("data") or []
    return CommandResults(
        outputs_prefix="KMSAT.UserEvent",
        outputs_key_field="id",
        raw_response=response,
        outputs=data,
        readable_output=tableToMarkdown(name="KMSAT User Event", t=data),
    )


def kmsat_user_event_status_list_command(
    client: UserEventClient, args: dict
) -> CommandResults:
    """ returns the status of a requested user event

    Args:
        client (UserEventClient): UserEventClient
        args (dict): Params for user events status

    Returns:
        CommandResults: Returns event status
    """

    request_id: str = str(args.get("id"))
    response = client.user_event_status(request_id)
    data: List[dict] = response.get("data") or []
    markdown = tableToMarkdown(
        "KMSAT User Event Status",
        data,
        [
            "id",
            "details",
            "processed",
        ],
    )

    return CommandResults(
        outputs_prefix="KMSAT.UserEventStatus",
        outputs_key_field="id",
        raw_response=response,
        outputs=data,
        readable_output=markdown,
    )


def kmsat_user_event_statuses_list_command(
    client: UserEventClient, args: dict
) -> CommandResults:
    """ List the status of User Events

    Args:
        client (UserEventClient): UserEventClient
        args (dict): Params for user event status list

    Returns:
        CommandResults: Returns list of event statuses
    """
    params = get_pagination(args)
    params["processed"] = args.get("processed")
    params = remove_empty_elements(params)

    response = client.user_event_statuses(params)
    data: List[dict] = response.get("data") or []
    markdown = tableToMarkdown(
        "KMSAT User Event Statuses",
        data,
        [
            "id",
            "details",
            "processed",
        ],
    )

    return CommandResults(
        outputs_prefix="KMSAT.UserEventStatuses",
        outputs_key_field="id",
        raw_response=response,
        outputs=data,
        readable_output=markdown,
    )


def test_module(client: Client, userEventClient: UserEventClient) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use
    :type userEventClient: ``UserEventClient``
    :param userEventClient: event client to use


    :return: 'ok' if test passed, anything else will fail the test.
    :return type: ``str``
    """

    message: str = ""
    params: dict = {}
    try:
        client.kmsat_account_info()
        message = "ok"
    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization" in str(e):
            message = f"Authorization Error: make sure Reporting API Key is correctly set{str(client._headers)}"
        else:
            raise e

    try:
        userEventClient.user_event_types(params)
        message = "ok"
    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization" in str(e):
            message = f"Authorization Error: make sure Reporting API Key is correctly set{str(client._headers)}"
        else:
            raise e
    return message


""" MAIN FUNCTION """


def main() -> None:
    """Main

    Raises:
        DemistoException: Raises Demisto Exception for Reporting API
        DemistoException: Raises Demisto Exception for User Events API
        NotImplementedError: Raises no command implementation
    """

    command = demisto.command()
    params = demisto.params()
    args = demisto.args()
    demisto.debug(f"Command being called is {command}")

    # get the service API url
    base_url = urljoin(params.get("url"), "/v1")
    userEvents_base_url = params.get("userEventsUrl")

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
    verify_certificate = not params.get("insecure", False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get("proxy", False)

    try:

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            },
            proxy=proxy,
        )

        userEventClient = UserEventClient(
            base_url=userEvents_base_url,
            verify=verify_certificate,
            headers={
                "Authorization": f"Bearer {userEventsApiKey}",
                "Content-Type": "application/json",
            },
            proxy=proxy,
        )

        reportingCommands = {
            "kmsat-account-info-list": kmsat_account_info_list_command,
            "kmsat-account-risk-score-history-list": kmsat_account_risk_score_history_list_command,
            "kmsat-groups-list": kmsat_groups_list_command,
            "kmsat-groups-risk-score-history-list": kmsat_groups_risk_score_history_list_command,
            "kmsat-groups-members-list": kmsat_groups_members_list_command,
            "kmsat-users-risk-score-history-list": kmsat_users_risk_score_history_list_command,
            "kmsat-phishing-security-tests-list": kmsat_phishing_security_tests_list_command,
            "kmsat-phishing-security-tests-recipients-list": kmsat_phishing_security_tests_recipients_list_command,
            "kmsat-phishing-security-tests-failed-recipients-list": kmsat_phishing_security_tests_failed_recipients_list_command,
            "kmsat-phishing-campaigns-security-tests-list": kmsat_phishing_campaign_security_tests_list_command,
            "kmsat-training-campaigns-list": kmsat_training_campaigns_list_command,
            "kmsat-training-enrollments-list": kmsat_training_enrollments_list_command,
        }

        userEventCommands = {
            "kmsat-user-events-list": kmsat_user_events_list_command,
            "kmsat-user-event-list": kmsat_user_event_list_command,
            "kmsat-user-event-types-list": kmsat_user_event_types_list_command,
            "kmsat-user-event-create": kmsat_user_event_create_command,
            "kmsat-user-event-delete": kmsat_user_event_delete_command,
            "kmsat-user-event-status-list": kmsat_user_event_status_list_command,
            "kmsat-user-event-statuses-list": kmsat_user_event_statuses_list_command,
        }

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client, userEventClient))
        elif command in list(reportingCommands.keys()):
            return_results(reportingCommands[command](client, args))
        elif command in list(userEventCommands.keys()):
            return_results(userEventCommands[command](userEventClient, args))
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
