import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from copy import deepcopy
from collections.abc import Callable

from datetime import datetime

SERVICE_REQUEST = "service request"
CHANGE_REQUEST = "change request"
INCIDENT = "incident"
TASK = "task"
PROBLEM_INVESTIGATION = "problem investigation"
KNOWN_ERROR = "known error"
WORK_ORDER = "work order"

SERVICE_REQUEST_CONTEXT_MAPPER = {
    "SysRequestID": "RequestID",
    "Request Number": "DisplayID",
    "Submit Date": "CreateDate",
    "Next Target Date": "TargetDate",
    "Status": "Status",
    "Summary": "Summary",
    "Last Modified Date": "LastModifiedDate",
    "Request Type": "SubType",
    "Status_Reason": "StatusReason",
    "Details": "Details",
}
CHANGE_REQUEST_CONTEXT_MAPPER = {
    "Request ID": "RequestID",
    "Infrastructure Change ID": "DisplayID",
    "Submit Date": "CreateDate",
    "Next Target Date": "TargetDate",
    "Change Request Status": "Status",
    "Description": "Summary",
    "Risk Level": "RiskLevel",
    "Reason For Change": "ReasonForChange",
    "Last Modified Date": "LastModifiedDate",
    "Assigned To": "Assignee",
    "Detailed Description": "Details",
    "Change Type": "SubType",
    "Status Reason": "StatusReason",
}
INCIDENT_CONTEXT_MAPPER = {
    "Request ID": "RequestID",
    "Incident Number": "DisplayID",
    "Submit Date": "CreateDate",
    "Status": "Status",
    "Description": "Summary",
    "Contact Sensitivity": "ContactSensitivity",
    "Last Modified Date": "LastModifiedDate",
    "Detailed Decription": "Details",  # The product has typo in the response
    "VIP": "VIP",
    "Service Type": "SubType",
    "Reported Source": "ReportedSource",
    "Status_Reason": "StatusReason",
}

TASK_CONTEXT_MAPPER = {
    "Task Interface ID": "RequestID",
    "Task ID": "DisplayID",
    "Create Date": "CreateDate",
    "Modified Date": "LastModifiedDate",
    "Status": "Status",
    "Notes": "Details",
    "TaskType": "SubType",
    "Summary": "Summary",
    "Scheduled Start Date": "ScheduledStartDate",
    "Scheduled End Date": "ScheduledEndDate",
    "StatusReasonSelection": "StatusReason",
}

PROBLEM_INVESTIGATION_CONTEXT_MAPPER = {
    "Request ID": "RequestID",
    "Problem Investigation ID": "DisplayID",
    "Submit Date": "CreateDate",
    "Investigation Status": "Status",
    "Invesitgation Status Reason": "StatusReason",
    "Description": "Summary",
    "Last Modified Date": "LastModifiedDate",
    "Target Resolution Date": "TargetResolutionDate",
    "Detailed Decription": "Details",  # The product has typo in the response
    "Investigation Justification": "InvestigationJustification",
    "Investigation Driver": "Investigation Driver",
    "Temporary Workaround": "TemporaryWorkaround",
}

KNOWN_ERROR_CONTEXT_MAPPER = {
    "Request ID": "RequestID",
    "Known Error ID": "DisplayID",
    "Submit Date": "CreateDate",
    "Known Error Status": "Status",
    "Description": "Summary",
    "Last Modified Date": "LastModifiedDate",
    "Target Resolution Date": "TargetResolutionDate",
    "Detailed Decription": "Details",  # The product has typo in the response
    "Investigation Justification": "InvestigationJustification",
    "Investigation Driver": "InvestigationDriver",
    "Temporary Workaround": "TemporaryWorkaround",
    "View Access": "ViewAccess",
    "Stastus_Reason": "StatusReason",  # The product has typo in the response
}

WORK_ORDER_CONTEXT_MAPPER = {
    "Request ID": "RequestID",
    "Work Order ID": "DisplayID",
    "Submit Date": "CreateDate",
    "Status": "Status",
    "Description": "Summary",
    "Last Modified Date": "LastModifiedDate",
    "Detailed Description": "Details",
    "VIP": "VIP",
    "Reported Source": "ReportedSource",
    "Status Reason": "StatusReason",
    "ASCHG": "Assignee",
    "ASGRP": "Assigned Group",
    "ASCPY": "Assigned Support Company",
    "Support Organization": "Assigned Support Organization",
}

COMMON_PROPERTIES = [
    "Submitter",
    "Urgency",
    "Impact",
    "InstanceId",
    "Customer First Name",
    "Customer Last Name",
    "Customer Company",
    "Customer Organization",
    "Customer Department",
    "Customer Internet E-mail",
    "Customer Phone Number",
    "First Name",
    "Last Name",
    "Company",
    "Region",
    "Site",
    "Site Group",
    "Assignee",
    "Assignee Group",
    "Assigned Group",
    "Assigned Support Organization",
    "Assigned Support Company",
    "Request Type",
    "Priority",
    "Resolution",
    "Status-History",
]

TICKET_TYPE_TO_LIST_FORM = {
    SERVICE_REQUEST: "SRM:Request",
    CHANGE_REQUEST: "CHG:ChangeInterface",
    INCIDENT: "HPD:IncidentInterface",
    TASK: "TMS:Task",
    PROBLEM_INVESTIGATION: "PBM:ProblemInterface",
    KNOWN_ERROR: "PBM:KnownErrorInterface",
    WORK_ORDER: "WOI:WorkOrderInterface",
}

TICKET_TYPE_TO_DELETE_FORM = {
    CHANGE_REQUEST: "CHG:Infrastructure Change",
    INCIDENT: "HPD:Help Desk",
    TASK: "TMS:Task",
    PROBLEM_INVESTIGATION: "PBM:Problem Investigation",
    KNOWN_ERROR: "PBM:Known Error",
    WORK_ORDER: "WOI:WorkOrderInterface",
}

TICKET_TYPE_TO_STATUS_FIELD = {
    CHANGE_REQUEST: "Change Request Status",
    SERVICE_REQUEST: "Status",
    INCIDENT: "Status",
    PROBLEM_INVESTIGATION: "Investigation Status",
    KNOWN_ERROR: "Known Error Status",
    TASK: "Status",
    WORK_ORDER: "Status",
}

TICKET_TYPE_TO_CONTEXT_MAPPER = {
    SERVICE_REQUEST: SERVICE_REQUEST_CONTEXT_MAPPER,
    CHANGE_REQUEST: CHANGE_REQUEST_CONTEXT_MAPPER,
    INCIDENT: INCIDENT_CONTEXT_MAPPER,
    TASK: TASK_CONTEXT_MAPPER,
    PROBLEM_INVESTIGATION: PROBLEM_INVESTIGATION_CONTEXT_MAPPER,
    KNOWN_ERROR: KNOWN_ERROR_CONTEXT_MAPPER,
    WORK_ORDER: WORK_ORDER_CONTEXT_MAPPER,
}

TICKET_TYPE_TO_STATUS_KEY = {
    SERVICE_REQUEST: "Status",
    CHANGE_REQUEST: "Change Request Status",
    INCIDENT: "Status",
    TASK: "Status",
    PROBLEM_INVESTIGATION: "Investigation Status",
    KNOWN_ERROR: "Known Error Status",
    WORK_ORDER: "Status",
}

TICKET_TYPE_TO_SUMMARY_KEY = {
    SERVICE_REQUEST: "Summary",
    CHANGE_REQUEST: "Description",
    INCIDENT: "Description",
    TASK: "Summary",
    PROBLEM_INVESTIGATION: "Description",
    KNOWN_ERROR: "Description",
    WORK_ORDER: "Description",
}

TICKET_TYPE_TO_REQUEST_ID_KEY = {
    SERVICE_REQUEST: "SysRequestID",
    CHANGE_REQUEST: "Request ID",
    INCIDENT: "Request ID",
    TASK: "Task ID",
    PROBLEM_INVESTIGATION: "Request ID",
    KNOWN_ERROR: "Request ID",
    WORK_ORDER: "Work Order ID",
}

TICKET_TYPE_TO_CREATE_QUERY = {
    SERVICE_REQUEST: "values(SysRequestID,Request Number,Submit Date)",
    CHANGE_REQUEST: "values(Change_Entry_ID,Infrastructure Change Id,Create Date)",
    INCIDENT: "values(Incident_Entry_ID,Incident Number,Create Date)",
    TASK: "values(Task ID,Create Date)",
    PROBLEM_INVESTIGATION: "values(Request ID,Problem Investigation ID,Create Date)",
    KNOWN_ERROR: "values(Request ID,Known Error ID,Create Date)",
    WORK_ORDER: "values(Request ID,WorkOrder_ID,Create Date)",
}

FIELD_DELIMITER = ";"
VALUE_DELIMITER = "="
REQUEST_NUM_PREFIX_TO_TICKET_TYPE = {
    "REQ": SERVICE_REQUEST,
    "CRQ": CHANGE_REQUEST,
    "INC": INCIDENT,
    "TAS": TASK,
    "PBI": PROBLEM_INVESTIGATION,
    "PKE": KNOWN_ERROR,
    "WO0": WORK_ORDER,
}

CREATE_CONTEXT_MAPPER = {
    "SysRequestID": "RequestID",
    "Request ID": "RequestID",
    "Change_Entry_ID": "RequestID",
    "Infrastructure Change Id": "DisplayID",
    "Request Number": "DisplayID",
    "Incident Number": "DisplayID",
    "Problem Investigation ID": "DisplayID",
    "Known Error ID": "DisplayID",
    "Submit Date": "CreateDate",
    "Create Date": "CreateDate",
    "Task ID": "DisplayID",
    "WorkOrder_ID": "DisplayID",
}

TICKET_TYPE_TO_DISPLAY_ID = {
    INCIDENT: "Incident Number",
    PROBLEM_INVESTIGATION: "Problem Investigation ID",
    KNOWN_ERROR: "Known Error ID",
    WORK_ORDER: "Work Order ID",
}
ID_QUERY_MAPPER_KEY = "IDS"
EQUAL_QUERY_MAPPER_KEY = "EQUAL"
LIKE_QUERY_MAPPER_KEY = "LIKE"
DEFAULT_MAX_FETCH = 50
DEFAULT_LIMIT = 50
ALL_OPTION = "All"
TOKEN_EXPIRE_TIME = 3600
TICKET_PREFIX_LEN = 3
COMMON_TICKET_CONTEXT_FIELDS = {prop_name: prop_name for prop_name in COMMON_PROPERTIES}
ALL_TICKETS = [
    SERVICE_REQUEST,
    CHANGE_REQUEST,
    INCIDENT,
    TASK,
    PROBLEM_INVESTIGATION,
    KNOWN_ERROR,
    WORK_ORDER,
]
TICKET_INCIDENT_TYPES = [
    "BMC Change-Request",
    "BMC Incident",
    "BMC Problem - Known Error",
    "BMC Problem Investigation incident",
    "BMC Service Request",
    "BMC Task",
    "BMC Work Order",
]

TICKET_TYPE_TO_INCIDENT_TYPE = {
    SERVICE_REQUEST: "BMC Service Request",
    CHANGE_REQUEST: "BMC Change-Request",
    INCIDENT: "BMC Incident",
    PROBLEM_INVESTIGATION: "BMC Problem Investigation incident",
    KNOWN_ERROR: "BMC Problem - Known Error",
    TASK: "BMC Task",
    WORK_ORDER: "BMC Work Order",
}

MIRRORING_COMMON_FIELDS = [
    "Summary",
    "Status",
    "StatusReason",
    "Urgency",
    "Impact",
    "Details",
    "CloseReason",
]

TICKET_TYPE_TO_ADDITIONAL_MIRRORING_FIELDS = {
    SERVICE_REQUEST: [],
    CHANGE_REQUEST: ["Priority", "RiskLevel"],
    INCIDENT: ["Priority"],
    TASK: ["Priority"],
    PROBLEM_INVESTIGATION: ["Priority"],
    KNOWN_ERROR: ["Priority"],
    WORK_ORDER: ["Priority"],
}

MIRROR_DIRECTION_MAPPING = {
    "None": None,
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}


class Client(BaseClient):
    """
    BmcITSM API Client
    """

    def __init__(self, server_url: str, username: str, password: str, verify: str, proxy: str):
        """initializing a client instance with authentication header"""
        super().__init__(base_url=urljoin(server_url, "api"), verify=verify, proxy=proxy)
        jwt_token = self.retrieve_access_token(username, password)
        self._headers = {}
        self._headers["Authorization"] = f"AR-JWT {jwt_token}"

    def retrieve_access_token(self, username: str, password: str) -> str:
        """
        Retrieve JWT token from BmcITSM API.

        Args:
            username (str): Client username.
            password (str): Client password.

        Returns:
            str: Authorized access token.
        """
        integration_context = get_integration_context()
        now = int(datetime.now().timestamp())
        if integration_context.get("token") and integration_context.get("expires_in") and now < integration_context["expires_in"]:
            return integration_context["token"]

        try:
            token = self._http_request(
                "POST",
                "jwt/login",
                data={
                    "username": username,
                    "password": password
                },
                resp_type="text",
            )

            integration_context = {
                "token": token,
                "expires_in": now + 3600,
            }  # token expires in an hour

            set_integration_context(integration_context)
            return token
        except DemistoException as exception:
            raise ValueError(
                f"Authentication failed. Please Check the server url or validate your crdentials. {str(exception)}"
            ) from exception

    def list_request(self, form: str, query: str = None) -> Dict[str, Any]:
        """
        List BmcITSM resources request.

        Args:
            form (str): The resource name to list.
            query (str): Query qualification.

        Returns:
            Dict[str, Any]: API respnse from BmcITSM.
        """
        params = remove_empty_elements({"q": query})
        response = self._http_request("GET", f"arsys/v1/entry/{form}", params=params)
        return response

    def ticket_delete_request(self, ticket_form: str, ticket_id: str) -> str:
        """
        BmcITSM ticket delete request.

        Args:
            ticket_form (str): The ticket form to delete by.
            ticket_id (str): The ID of the ticket to delete.

        Returns:
            str: API respnse from BmcITSM.
        """

        response = self._http_request("DELETE",
                                      f"arsys/v1/entry/{ticket_form}/{ticket_id}",
                                      resp_type="text")
        return response

    def create_service_request_request(
        self,
        srd_instance_id: str,
        summary: str,
        urgency: str,
        impact: str,
        first_name: str,
        last_name: str,
        login_id: str,
        status: str,
        **additional_fields,
    ) -> Dict[str, Any]:
        """
        Service request create request.

        Args:
            srd_instance_id (str): Service request definition instance ID.
            summary (str): Ticket summary.
            urgency (str): Ticket urgency.
            impact (str): Ticket impact.
            first_name (str): Requester first name.
            last_name (str): Requester last name.
            login_id (str): Requester login ID.
            status (str): Request status.

        Returns:
            Dict[str, Any]: API respnse from BmcITSM.
        """

        properties = remove_empty_elements({
            "z1D Action": "CREATE",
            "Source Keyword": "blank",
            "First Name": first_name,
            "Last Name": last_name,
            "Login ID": login_id,
            "TitleInstanceID": srd_instance_id,
            "AppRequestSummary": summary,
            "Urgency": urgency,
            "Impact": impact,
            "Status": status,
            **additional_fields,
        })
        data = {"values": properties}

        params = {"fields": TICKET_TYPE_TO_CREATE_QUERY[SERVICE_REQUEST]}
        response = self._http_request(
            "POST",
            "arsys/v1/entry/SRM:RequestInterface_Create",
            json_data=data,
            params=params,
        )

        return response

    def service_request_update_request(
        self,
        service_request_id: str,
        summary,
        status: str,
        urgency: str,
        impact: str,
        customer_first_name: str,
        customer_last_name: str,
        location_company,
        site_group: str,
        region: str,
        site: str,
        assignee: str,
        status_reason: str,
        **additional_fields,
    ):
        """
        Service request update request.

        Args:
            service_request_id (str): The ID of the ticket to update.
            status (str): The ticket status to update.
            urgency (str): The ticket urgency to update.
            impact (str): The ticket impact to update.
            first_name (str): The requester first name to update.
            last_name (str): The requester last name to update.
            customer_first_name (str): Customer first name.
            customer_last_name (str): Customer last name.
            company (str): company.
            department (str): department.
            site_group (str): site group.
            region (str): region.
            site (str): site.
            assignee (str) : Ticket assignee.
            status_reason (str): Reasin for status change.

            Returns:
            str: API respnse from BmcITSM.

        """

        properties = remove_empty_elements({
            "Customer First Name": customer_first_name,
            "Customer Last Name": customer_last_name,
            "Impact": impact,
            "Location Company": location_company,
            "Region": region,
            "Site": site,
            "Site Group": site_group,
            "Status": status,
            "Urgency": urgency,
            "Summary": summary,
            "Assignee": assignee,
            "Status_Reason": status_reason,
            **additional_fields,
        })
        data = {"values": properties}

        self._http_request(
            "PUT",
            f"arsys/v1/entry/SRM:RequestInterface/{service_request_id}",
            json_data=data,
            resp_type="text",
        )

    def create_incident_request(
        self,
        template_instance_id: str,
        first_name: str,
        last_name: str,
        summary: str,
        status: str,
        urgency: str,
        impact: str,
        service_type: str,
        reported_source: str,
        details: str,
        company: str,
        assigned_support_organization: str,
        assigned_support_company: str,
        assigned_group: str,
        assignee: str,
        assignee_login_id: str,
        site_group: str,
        site: str,
        region: str,
        **additional_fields,
    ) -> Dict[str, Any]:
        """
        Create incident request.

        Args:
            template_instance_id (str): Incident template instance ID.
            first_name (str): Requester first name.
            last_name (str): Requester last name.
            summary (str): Ticket summary.
            location_company (str): Company assoiciated with ticet process.
            status (str): Ticket status.
            urgency (str): Ticket urgency.
            impact (str): Ticket impact.
            priority (str): Ticket priority.
            risk_level (str): Ticket risk level.
            change_type (str): Ticket change type.
            customer_first_name (str): Customer first name.
            customer_last_name (str): Customer last name.

        Returns:
            Dict[str, Any]: API respnse from BmcITSM.
        """
        properties = remove_empty_elements({
            "First_Name": first_name,
            "Last_Name": last_name,
            "TemplateID": template_instance_id,
            "Description": summary,
            "Detailed_Decription": details,
            "Company": company,
            "Urgency": urgency,
            "Impact": impact,
            "Status": status,
            "Reported Source": reported_source,
            "Service_Type": service_type,
            "Assigned Support Organization": assigned_support_organization,
            "Assigned Group": assigned_group,
            "Assignee": assignee,
            "Assignee Login ID": assignee_login_id,
            "Assigned Support Company": assigned_support_company,
            "Site Group": site_group,
            "Region": region,
            "Site": site,
            **additional_fields,
        })
        data = {"values": properties}
        params = {"fields": TICKET_TYPE_TO_CREATE_QUERY[INCIDENT]}

        response = self._http_request(
            "POST",
            "arsys/v1/entry/HPD:IncidentInterface_Create",
            params=params,
            json_data=data,
        )

        return response

    def update_incident_request(
        self,
        request_id: str,
        first_name: str,
        last_name: str,
        summary: str,
        status: str,
        urgency: str,
        impact: str,
        service_type: str,
        reported_source: str,
        details: str,
        company: str,
        assigned_support_organization: str,
        assigned_support_company: str,
        assigned_group: str,
        assignee: str,
        assignee_login_id: str,
        site_group: str,
        site: str,
        region: str,
        status_reason: str,
        resolution: str,
        **additional_fields,
    ):
        """
          Update incident request.

        Args:
            request_id (str): Ticket request ID.
            first_name (str): First name.
            last_name (str): Last name.
            summary (str): Ticket Summary.
            status (str): Ticket Status.
            urgency (str): Ticket Urgency.
            impact (str): Ticket Impact.
            service_type (str): Ticket service type.
            reported_source (str): Ticket reported source.
            details (str): Ticket detailed description.
            company (str): Ticket company.
            assigned_support_organization (str): Assignee organization.
            assigned_support_company (str):  Assignee company.
            assigned_group (str):  Assignee group name.
            assignee (str): Ticket assignee.
            assignee_login_id (str): Tixcket assignee login ID.
            site_group (str): Site group.
            site (str): Site.
            region (str): Region.
            status_reason (str): Reason for changing the status.
            resolution (str): Ticket resolution.
        Returns:
            str: API respnse from BmcITSM.
        """

        properties = remove_empty_elements({
            "First_Name": first_name,
            "Last_Name": last_name,
            "Description": summary,
            "Detailed_Decription": details,
            "Company": company,
            "Urgency": urgency,
            "Impact": impact,
            "Status": status,
            "Reported Source": reported_source,
            "Service_Type": service_type,
            "Assigned Support Organization": assigned_support_organization,
            "Assigned Group": assigned_group,
            "Assignee": assignee,
            "Assignee Login ID": assignee_login_id,
            "Assigned Support Company": assigned_support_company,
            "Site": site,
            "Site Group": site_group,
            "Region": region,
            "Status_Reason": status_reason,
            "Resolution": resolution,
            **additional_fields,
        })
        data = {"values": properties}

        response = self._http_request(
            "PUT",
            f"arsys/v1/entry/HPD:IncidentInterface/{request_id}",
            json_data=data,
            resp_type="text",
        )

        return response

    def change_request_create_request(
        self,
        template_instance_id: str,
        first_name: str,
        last_name: str,
        summary: str,
        location_company: str,
        status: str,
        urgency: str,
        impact: str,
        priority: str,
        risk_level: str,
        change_type: str,
        customer_first_name: str,
        customer_last_name: str,
        **additional_fields,
    ) -> Dict[str, Any]:
        """
        change request ticket create request.

        Args:
            template_instance_id (str): Change request template instance ID.
            first_name (str): Requester first name.
            last_name (str): Requester last name.
            summary (str): Ticket summary.
            location_company (str): Company assoiciated with ticet process.
            status (str): Ticket status.
            urgency (str): Ticket urgency.
            impact (str): Ticket impact.
            priority (str): Ticket priority.
            risk_level (str): Ticket risk level.
            change_type (str): Ticket change type.
            customer_first_name (str): Customer first name.
            customer_last_name (str): Customer last name.

        Returns:
            Dict[str, Any]: API respnse from BmcITSM.
        """
        properties = remove_empty_elements({
            "First Name": first_name,
            "Last Name": last_name,
            "Customer First Name": customer_first_name,
            "Customer Last Name": customer_last_name,
            "TemplateID": template_instance_id,
            "Description": summary,
            "Location Company": location_company,
            "Urgency": urgency,
            "Impact": impact,
            "Status": status,
            "Change Type": change_type,
            "Risk Level": risk_level,
            "Priority": priority,
            **additional_fields,
        })
        data = {"values": properties}
        params = {"fields": TICKET_TYPE_TO_CREATE_QUERY[CHANGE_REQUEST]}

        response = self._http_request(
            "POST",
            "arsys/v1/entry/CHG:ChangeInterface_Create",
            json_data=data,
            params=params,
        )
        return response

    def change_request_update_request(
        self,
        change_request_id: str,
        first_name: str,
        last_name: str,
        summary: str,
        location_company: str,
        status: str,
        urgency: str,
        impact: str,
        priority: str,
        risk_level: str,
        change_type: str,
        customer_first_name: str,
        customer_last_name: str,
        details: str,
        status_reason: str,
        organization: str,
        department: str,
        site_group: str,
        site: str,
        support_organization: str,
        support_group_name: str,
        region: str,
        company: str,
        **additional_fields,
    ):
        """
        Change request update ticket.

        Args:
            change_request_id (str): Change request ID.
            first_name (str): Requester first name.
            last_name (str):Requester last name.
            summary (str): Ticket summary.
            location_company (str): Company assoiciated with ticet process.
            status (str): Ticket status.
            urgency (str): Ticket urgency.
            impact (str): Ticket impact.
            priority (str): Ticket priority.
            risk_level (str): Ticket risk level.
            change_type (str): Ticket change type.
            customer_first_name (str): Customer first name.
            customer_last_name (str): Customer last name.
            details (str): Ticket detailed description.
            status_reason (str): Ticket status reason.
            organization (str): Ticket organization.
            department (str): Ticket department.
            site_group (str): Site group.
            site (str): Site.
            support_organization (str): Support organization.
            support_group_name (str): Support group name.
            region (str): Region.
            company (str): Company.
        Returns:
            str: API respnse from BmcITSM.


        """
        properties = remove_empty_elements({
            "First Name": first_name,
            "Last Name": last_name,
            "Customer First Name": customer_first_name,
            "Customer Last Name": customer_last_name,
            "Description": summary,
            "Location Company": location_company,
            "Urgency": urgency,
            "Impact": impact,
            "Change Request Status": status,
            "Change Type": change_type,
            "Risk Level": risk_level,
            "Priority": priority,
            "Detailed Description": details,
            "Status Reason": status_reason,
            "Department": department,
            "Site Group": site_group,
            "Region": region,
            "Site": site,
            "Organization": organization,
            "Support Organization": support_organization,
            "Support Group Name": support_group_name,
            "Company": company,
            **additional_fields,
        })
        data = {"values": properties}

        response = self._http_request(
            "PUT",
            f"arsys/v1/entry/CHG:ChangeInterface/{change_request_id}",
            json_data=data,
            resp_type="text",
        )
        return response

    def create_task_request(
        self,
        template_instance_id: str,
        root_request_instance_id: str,
        root_request_name: str,
        root_request_id: str,
        first_name: str,
        last_name: str,
        summary: str,
        details: str,
        status: str,
        priority: str,
        task_type: str,
        support_company: str,
        location_company: str,
        assignee: str,
        root_request_mode: str,
        root_ticket_type: str,
        assigned_support_organization: str,
        assigned_support_group_name: str,
        impact: str,
        urgency: str,
        scedulded_start_date: str,
        scedulded_end_date: str,
        customer_company: str,
        **additional_fields,
    ) -> Dict[str, Any]:
        """
        Create task request.

        Args:
            template_instance_id (str): Task template instance ID.
            root_request_instance_id (str): Parent ticket instance ID.
            root_request_name (str): Parent ticket name.
            root_request_id (str): Parent ticket request ID.
            first_name (str): Requester first name.
            last_name (str): Requester last name.
            summary (str): Ticket summary.
            details (str): Ticket detailed descirption.
            status (str): Ticket status.
            priority (str): Ticket priority.
            task_type (str): Task type.
            support_company (str): Assignee company.
            location_company (str): Company assoiciated with ticet process.
            assignee (str): Assignee.
            root_request_mode (str): Root request mode.
            root_ticket_type (str): Parent ticket type.
            assigned_support_organization (str): Assignee organization.
            assigned_support_group_name (str): Assignee group.
            impact (str): Ticket impact.
            urgency (str): Ticket urgency.
            scedulded_start_date (str): Schedulded start date.
            scedulded_end_date (str):  Schedulded end date.
            customer_company (str): Customer company name.

        Returns:
            Dict[str, Any]: API respnse from BmcITSM.
        """

        properties = remove_empty_elements({
            "TemplateID": template_instance_id,
            "RootRequestInstanceID": root_request_instance_id,
            "RootRequestID": root_request_id,
            "First Name": first_name,
            "Last Name": last_name,
            "Summary": summary,
            "TaskName": summary,
            "Notes": details,
            "Location Company": location_company,
            "Status": status,
            "TaskType": task_type,
            "RootRequestName": root_request_name,
            "RootRequestMode": root_request_mode,
            "Support Company": support_company,
            "RootRequestFormName": root_ticket_type,
            "Assignee Group": assigned_support_group_name,
            "Assignee Organization": assigned_support_organization,
            "Impact": impact,
            "Urgency": urgency,
            "State": "Active",
            "Parent Linked": "Active",
            "Customer Company": customer_company,
            "Assigned To": assignee,
            "Scheduled Start Date": scedulded_start_date,
            "Scheduled End Date": scedulded_end_date,
            "Priority": priority,
            **additional_fields,
        })
        data = {"values": properties}
        params = {"fields": TICKET_TYPE_TO_CREATE_QUERY[TASK]}
        response = self._http_request("POST",
                                      "arsys/v1/entry/TMS:Task",
                                      json_data=data,
                                      params=params)
        return response

    def update_task_request(
        self,
        task_id: str,
        root_request_name: str,
        summary: str,
        details: str,
        status: str,
        status_reason: str,
        priority: str,
        task_type: str,
        company: str,
        assignee: str,
        assigned_support_organization: str,
        assigned_support_company: str,
        assigned_support_group_name: str,
        location_company: str,
        scedulded_start_date: str,
        schedulded_end_date: str,
        customer_company: str,
        **additional_fields,
    ):
        """
        Task update request.

        Args:
            task_id (str): Task request ID.
            root_request_name (str): Parent ticket name.
            summary (str): Ticket summary.
            details (str): Ticket details.
            status (str): Ticket status.
            status_reason (str): The reason for changing the status.
            priority (str): Ticket priority.
            task_type (str): Task type.
            company (str): Ticket company.
            assignee (str): Assignee.
            assigned_support_organization (str): Assignee organization.
            assigned_support_company (str): Assignee company.
            assigned_support_group_name (str): Assignee group name.
            location_company (str): Company assoiciated with ticet process.
            scedulded_start_date (str): Schedulded start date.
            scedulded_end_date (str):  Schedulded end date.
            customer_company (str):  Customer company name.
        Returns:
            str: API respnse from BmcITSM.
        """

        properties = remove_empty_elements({
            "Summary": summary,
            "Notes": details,
            "Location Company": location_company,
            "Status": status,
            "StatusReasonSelection": status_reason,
            "TaskType": task_type,
            "Priority": priority,
            "RootRequestName": root_request_name,
            "Assignee Company": assigned_support_company,
            "Assignee Organization": assigned_support_organization,
            "Assignee Group": assigned_support_group_name,
            "Company": company,
            "Assigned To": assignee,
            "Assignee": assignee,
            "Scheduled Start Date": scedulded_start_date,
            "Scheduled End Date": schedulded_end_date,
            "Customer Company": customer_company,
            **additional_fields,
        })
        data = {"values": properties}
        response = self._http_request(
            "PUT",
            f"arsys/v1/entry/TMS:TaskInterface/{task_id}",
            json_data=data,
            resp_type="text",
        )

        return response

    def create_problem_investigation_request(
        self,
        problem_type: str,
        summary: str,
        status: str,
        urgency: str,
        impact: str,
        details: str,
        company: str,
        assigned_support_organization: str,
        assigned_support_company: str,
        assigned_support_group_name: str,
        assignee: str,
        site_group: str,
        site: str,
        region: str,
        assigned_group_pbm_mgr: str,
        support_company_pbm_mgr: str,
        support_organization_pbm_mgr: str,
        assignee_pbm_mgr: str,
        temporary_workaround: str,
        target_resolution_date: str,
        investigation_justification: str = None,
        investigation_driver: str = None,
        view_access: str = None,
        resolution: str = None,
        first_name: str = None,
        last_name: str = None,
        **additional_fields,
    ):
        """
        Problem investigation ticket create reuqest.

        Args:
            problem_type (str): Ptoblem type - known error or ptoblem investigation.
            summary (str): Ticket summary.
            status (str): Ticket status.
            urgency (str): Ticket urgency.
            impact (str): Ticket impact.
            details (str): Ticket detailed descirption.
            company (str): Requester company.
            assigned_support_organization (str): Assignee organization.
            assigned_support_company (str): Assignee company.
            assigned_support_group_name (str):Assignee support group.
            assignee (str): Assignee.
            site_group (str): Site group.
            site (str): Site.
            region (str): Region.
            assigned_group_pbm_mgr (str): Problem coordinator group.
            support_company_pbm_mgr (str): Problem coordinator company.
            support_organization_pbm_mgr (str): Problem coordinator organization.
            assignee_pbm_mgr (str): Problem coordinator assignee.
            temporary_workaround (str): Ticket workaround.
            target_resolution_date (str): Ticket resolution date.
            investigation_justification (str, optional): Investigation justification. Defaults to None.
            investigation_driver (str, optional):  Investigation driver. Defaults to None.
            view_access (str, optional): View access. Defaults to None.
            resolution (str, optional): Resolution. Defaults to None.
            first_name (str, optional): Requester first name. Defaults to None.
            last_name (str, optional): Request last name. Defaults to None.
        Returns:
            Dict[str, Any]: API respnse from BmcITSM.
        """

        action = "PROBLEM" if problem_type == PROBLEM_INVESTIGATION else "KNOWNERROR"
        status_key = ("Status" if problem_type == PROBLEM_INVESTIGATION else "Known Error Status")

        properties = remove_empty_elements({
            "z1D_Action": action,
            status_key: status,
            "First Name": first_name,
            "Last Name": last_name,
            "Description": summary,
            "Detailed Decription": details,
            "Company": company,
            "Urgency": urgency,
            "Impact": impact,
            "Assigned Support Organization": assigned_support_organization,
            "Assigned Group": assigned_support_group_name,
            "Assignee": assignee,
            "Assigned Support Company": assigned_support_company,
            "Site": site,
            "Site Group": site_group,
            "Region": region,
            "Target Resolution Date": target_resolution_date,
            "Investigation Driver": investigation_driver,
            "Temporary Workaround": temporary_workaround,
            "Assigned Group Pblm Mgr": assigned_group_pbm_mgr,
            "Support Company Pblm Mgr": support_company_pbm_mgr,
            "Support Organization Pblm Mgr": support_organization_pbm_mgr,
            "Assignee Pblm Mgr": assignee_pbm_mgr,
            "Investigation Justification": investigation_justification,
            "View Access": view_access,
            "Resolution": resolution,
            **additional_fields,
        })
        data = {"values": properties}
        params = {"fields": TICKET_TYPE_TO_CREATE_QUERY[problem_type]}

        response = self._http_request(
            "POST",
            "arsys/v1/entry/PBM:ProblemInterface_Create",
            params=params,
            json_data=data,
        )
        return response

    def update_problem_investigation_request(
        self,
        problem_investigation_id,
        first_name: str,
        last_name: str,
        summary: str,
        status: str,
        status_reason: str,
        urgency: str,
        impact: str,
        details: str,
        company: str,
        assigned_support_organization: str,
        assigned_support_company: str,
        assigned_support_group_name: str,
        assignee: str,
        assignee_login_id: str,
        site_group: str,
        site: str,
        region: str,
        assigned_group_pbm_mgr: str,
        support_company_pbm_mgr: str,
        support_organization_pbm_mgr: str,
        temporary_workaround: str,
        resolution: str,
        target_resolution_date: str,
        investigation_justification: str,
        investigation_driver: str,
        **additional_fields,
    ):
        """
        Problem investigation update request.

        Args:
            problem_investigation_id (_type_): Ticket reuqest ID.
            first_name (str): Requester first name.
            last_name (str): Requester last name.
            summary (str): Ticket summary.
            status (str): Ticket status.
            status_reason (str): Reason for changing status.
            impact (str): Ticket impact.
            urgency (str): Ticket urgency.
            details (str): Ticket detailed descirption.
            company (str): Requester company.
            assigned_support_organization (str): Assignee organization.
            assigned_support_company (str): Assignee company.
            assigned_support_group_name (str): Assignee group.
            assignee (str): Assignee.
            assignee_login_id (str): Assignee login ID.
            site_group (str): Site group.
            site (str): Site group.
            region (str): Region.
            assigned_group_pbm_mgr (str): Assignee group problem coordinator.
            support_company_pbm_mgr (str): Assignee company problem coordinator.
            support_organization_pbm_mgr (str): Assignee organization problem coordinator.
            temporary_workaround (str): Temporary workaround.
            resolution (str): Ticket resolution.
            target_resolution_date (str): Ticket resolution date.
            investigation_justification (str): Problem Investigation justification.
            investigation_driver (str): Problem Investigation driver.

        Returns:
            Dict[str, Any]: API respnse from BmcITSM.
        """
        properties = remove_empty_elements({
            "First Name": first_name,
            "Last Name": last_name,
            "Description": summary,
            "Detailed Decription": details,
            "Company": company,
            "Urgency": urgency,
            "Impact": impact,
            "Investigation Status": status,
            "Invesitgation Status Reason": status_reason,
            "Assigned Support Organization": assigned_support_organization,
            "Assigned Group": assigned_support_group_name,
            "Assignee": assignee,
            "Assignee Login ID": assignee_login_id,
            "Assigned Support Company": assigned_support_company,
            "Site": site,
            "Site Group": site_group,
            "Region": region,
            "Target Resolution Date": target_resolution_date,
            "Investigation Driver": investigation_driver,
            "Resolution": resolution,
            "Temporary Workaround": temporary_workaround,
            "Assigned Group Pblm Mgr": assigned_group_pbm_mgr,
            "Support Company Pblm Mgr": support_company_pbm_mgr,
            "Support Organization Pblm Mgr": support_organization_pbm_mgr,
            "Investigation Justification": investigation_justification,
            **additional_fields,
        })
        data = {"values": properties}
        response = self._http_request(
            "PUT",
            f"arsys/v1/entry/PBM:ProblemInterface/{problem_investigation_id}",
            json_data=data,
            resp_type="text",
        )

        return response

    def update_known_error_request(
        self,
        known_error_id,
        summary: str,
        status: str,
        urgency: str,
        impact: str,
        details: str,
        assigned_support_organization: str,
        assigned_support_company: str,
        assigned_support_group_name: str,
        assignee: str,
        assigned_group_pbm_mgr: str,
        support_company_pbm_mgr: str,
        support_organization_pbm_mgr: str,
        assignee_pbm_mgr: str,
        target_resolution_date: str,
        status_reason: str,
        temporary_workaround: str,
        view_access: str,
        resolution: str,
        **additional_fields,
    ):
        """
        Update known error request.


        Args:
            known_error_id (_type_): Known error request ID.
            summary (str): Known error summary.
            status (str): Ticket status.
            urgency (str): Ticket urgency.
            impact (str): Ticket impact.
            details (str): Ticket details.
            assigned_support_organization (str): Assignee organization.
            assigned_support_company (str): Assignee company.
            assigned_support_group_name (str): Assignee group.
            assignee (str): Assignee.
            assigned_group_pbm_mgr (str): Assignee group problem coordinator.
            support_company_pbm_mgr (str): Assignee company problem coordinator.
            support_organization_pbm_mgr (str): Assignee organization problem coordinator.
            assignee_pbm_mgr (str): Assignee problem coordinator.
            target_resolution_date (str): Ticket resolution date.
            status_reason (str): Reason for changing the status.
            temporary_workaround (str): Temporary workaround.
            view_access (str): View access.
            resolution (str): Resolution.

        Returns:
            str: API respnse from BmcITSM.
        """
        properties = remove_empty_elements({
            "Detailed Decription": details,
            "Description": summary,
            "Urgency": urgency,
            "Impact": impact,
            "Known Error Status": status,
            "Stastus_Reason": status_reason,
            "Assigned Support Organization": assigned_support_organization,
            "Assigned Group": assigned_support_group_name,
            "Assignee": assignee,
            "Assigned Support Company": assigned_support_company,
            "Target Resolution Date": target_resolution_date,
            "Assigned Group Pblm Mgr": assigned_group_pbm_mgr,
            "Support Company Pblm Mgr": support_company_pbm_mgr,
            "Support Organization Pblm Mgr": support_organization_pbm_mgr,
            "Assignee Pblm Mgr": assignee_pbm_mgr,
            "Temporary Workaround": temporary_workaround,
            "View Access": view_access,
            "Resolution": resolution,
            **additional_fields,
        })
        data = {"values": properties}

        response = self._http_request(
            "PUT",
            f"arsys/v1/entry/PBM:KnownErrorInterface/{known_error_id}",
            json_data=data,
            resp_type="text",
        )

        return response

    def create_work_order_request(
        self,
        template_guid: str,
        first_name: str,
        last_name: str,
        customer_person_id: str,
        customer_first_name: str,
        customer_last_name: str,
        customer_company: str,
        summary: str,
        detailed_description: str,
        status: str,
        priority: str,
        work_order_type: str,
        location_company: str,
        scedulded_start_date: str,
        scedulded_end_date: str,
        **additional_fields,
    ) -> Dict[str, Any]:
        """
        Create work order request.

        Args:
            template_guid (str): Work order template GUID.
            first_name (str): Requester first name.
            last_name (str): Requester last name.
            customer_person_id (str): Customer person id (in case first/last pair in ambiguous),
            customer_first_name (str): Customer first name
            customer_last_name (str): Customer last name
            customer_company (str): Customer company
            summary (str): Work order summary.
            detailed_description (str): Work order detailed descirption.
            status (str): Ticket status.
            priority (str): Ticket priority.
            work_order_type (str): Work order type.
            location_company (str): Company assoiciated with work order process.
            scedulded_start_date (str): Schedulded start date.
            scedulded_end_date (str):  Schedulded end date.

        Returns:
            Dict[str, Any]: API respnse from BmcITSM.
        """

        properties = remove_empty_elements({
            "TemplateID": template_guid,
            "First Name": first_name,
            "Last Name": last_name,
            "Customer Person ID": customer_person_id,
            "Customer First Name": customer_first_name,
            "Customer Last Name": customer_last_name,
            "Customer Company": customer_company,
            "Summary": summary,
            "Detailed Description": detailed_description,
            "Status": status,
            "Priority": priority,
            "Work Order Type": work_order_type,
            "Location Company": location_company,
            "Scheduled Start Date": scedulded_start_date,
            "Scheduled End Date": scedulded_end_date,
            "z1D_Action": "CREATE",
            **additional_fields,
        })
        data = {"values": properties}
        params = {"fields": TICKET_TYPE_TO_CREATE_QUERY[WORK_ORDER]}
        response = self._http_request("POST",
                                      "arsys/v1/entry/WOI:WorkOrderInterface_Create",
                                      json_data=data,
                                      params=params)
        return response

    def update_work_order_request(
        self,
        request_id: str,
        summary: str,
        detailed_description: str,
        status: str,
        status_reason: str,
        priority: str,
        work_order_type: str,
        company: str,
        assignee: str,
        support_organization: str,
        support_group_name: str,
        location_company: str,
        scedulded_start_date: str,
        schedulded_end_date: str,
        **additional_fields,
    ):
        """
        Work order update request.

        Args:
            request_id (str): Work order request ID.
            summary (str): Work order summary.
            detailed_description (str): Work order details.
            status (str): Work order status.
            status_reason (str): The reason for changing the status.
            priority (str): Work order priority.
            work_order_type (str): Work order type.
            company (str): Work order company.
            assignee (str): Assignee.
            support_organization (str): Support organization.
            support_group_name (str): Support group name.
            location_company (str): Company assoiciated with ticet process.
            scedulded_start_date (str): Schedulded start date.
            scedulded_end_date (str):  Schedulded end date.
        Returns:
            str: API respnse from BmcITSM.
        """

        properties = remove_empty_elements({
            "Summary": summary,
            "Detailed Description": detailed_description,
            "Location Company": location_company,
            "Status": status,
            "Status Reason": status_reason,
            "Work Order Type": work_order_type,
            "Priority": priority,
            "Support Organization": support_organization,
            "Support Group Name": support_group_name,
            "Company": company,
            "Request Assignee": assignee,
            "Assigned To": assignee,
            "Scheduled Start Date": scedulded_start_date,
            "Scheduled End Date": schedulded_end_date,
            **additional_fields,
        })
        data = {"values": properties}
        response = self._http_request(
            "PUT",
            f"arsys/v1/entry/WOI:WorkOrder/{request_id}",
            json_data=data,
            resp_type="text",
        )

        return response


def list_command(
    client: Client,
    args: Dict[str, Any],
    form_name: str,
    context_output_mapper: Dict[str, Any],
    header_prefix: str,
    outputs_prefix: str,
    outputs_key_field: str,
    arranger: Callable = None,
    headers: List[str] = None,
    record_id_key: str = None,
    ticket_type: str = None,
) -> CommandResults:
    """Generic function to handle BmcITSM list commands.

    Args:
        client: Client: BmcITSM API client.
        args (Dict[str, Any]): Command arguments.
        form_name (Callable): The BmcITSM resource to list.
        context_output_mapper (Dict[str, Any]): Mapper for context output.
        header_prefix (str): HR header prefix.
        outputs_prefix (str): Command results context output prefix.
        outputs_key_field (str): Command results context output key field.

    Returns:
        CommandResults: Command reuslts.
    """
    query: str = args.get("query")  # type: ignore[assignment]
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))
    validate_pagination_args(page, page_size, limit)
    filtering_mapper = generate_query_filter_mapper_by_args(args,
                                                            record_id_key,
                                                            ticket_type=ticket_type)
    query_with_filtering = generate_query_with_filtering(query, filtering_mapper)

    response = client.list_request(form_name,
                                   query_with_filtering if query_with_filtering else None)
    relevant_records, header_suffix = get_paginated_records_with_hr(response.get("entries"), limit,  # type: ignore[arg-type]
                                                                    page, page_size)
    outputs = format_command_output(relevant_records, context_output_mapper, arranger)
    readable_output = tableToMarkdown(
        header_prefix,
        metadata=header_suffix,
        t=outputs,
        headers=headers or list(context_output_mapper.values()),
        headerTransform=pascalToSpace,
    )
    if not outputs:
        command_results = CommandResults(
            readable_output="No results were found for the given arguments.")
    else:
        command_results = CommandResults(
            outputs_prefix=outputs_prefix,
            outputs_key_field=outputs_key_field,
            outputs=outputs,
            raw_response=response,
            readable_output=readable_output,
        )

    return command_results


def user_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """List BmcITSM users command.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    context_output_mapper = {
        "Person ID": "Id",
        "First Name": "FirstName",
        "Last Name": "LastName",
        "Company": "Company",
        "Department": "Department",
        "Site Group": "SiteGroup",
        "Region": "Region",
        "Site": "Site",
        "Organization": "Organization",
    }
    args["ids"] = argToList(args.get("user_ids"))
    command_results = list_command(
        client,
        args,
        "CTM:People",
        context_output_mapper,
        header_prefix="List Users.",
        outputs_prefix="BmcITSM.User",
        outputs_key_field="Id",
        record_id_key="Person ID",
    )
    return command_results


def company_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """List BmcITSM companies command.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    context_output_mapper = {
        "Company Entry ID": "Id",
        "Company": "Name",
        "Company Type": "Type",
    }
    args["ids"] = argToList(args.get("company_ids"))
    command_results = list_command(
        client,
        args,
        "COM:Company",
        context_output_mapper,
        header_prefix="List Companies.",
        outputs_prefix="BmcITSM.Company",
        outputs_key_field="Id",
        record_id_key="Company Entry ID",
    )
    return command_results


def ticket_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """List BmcITSM tickets command.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    ticket_type: str = args["ticket_type"]

    context_output_mapper = generate_ticket_context_data_mapper(ticket_type)
    args["ids"] = argToList(args.get("ticket_ids"))
    command_results = list_command(
        client,
        args,
        TICKET_TYPE_TO_LIST_FORM[ticket_type],
        context_output_mapper,
        header_prefix="List Tickets.",
        outputs_prefix="BmcITSM.Ticket",
        outputs_key_field="DisplayID",
        arranger=arrange_ticket_context_data,
        headers=[
            "Type",
            "RequestID",
            "DisplayID",
            "Summary",
            "Status",
            "Urgency",
            "Impact",
            "CreateDate",
            "LastModifiedDate",
        ],
        record_id_key=TICKET_TYPE_TO_REQUEST_ID_KEY[ticket_type],
        ticket_type=ticket_type,
    )
    return command_results


def ticket_delete_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """BmcITSM ticket delete command.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    ticket_type = args["ticket_type"]
    ticket_ids: List[str] = argToList(args["ticket_ids"])
    commands_results: List[CommandResults] = []
    for ticket_id in ticket_ids:
        try:
            client.ticket_delete_request(TICKET_TYPE_TO_DELETE_FORM[ticket_type], ticket_id)

            readable_output = f"{ticket_type} {ticket_id} was deleted successfully."
            commands_results.append(CommandResults(readable_output=readable_output))

        except Exception as error:
            error_results = CommandResults(readable_output=f"**{str(error)}**")
            commands_results.append(error_results)
    return commands_results


def service_request_definition_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """List BmcITSM service request definitions command.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    context_output_mapper = {
        "Request ID": "Id",
        "Description": "Description",
        "InstanceId": "InstanceID",
    }
    args["ids"] = argToList(args.get("srd_ids"))
    command_results = list_command(
        client,
        args,
        "SRD:ServiceRequestDefinition",
        context_output_mapper,
        header_prefix="List service request definitions.",
        outputs_prefix="BmcITSM.ServiceRequestDefinition",
        outputs_key_field="Id",
        record_id_key="Request ID",
    )
    return command_results


def incident_template_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """List BmcITSM incident templates command.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    context_output_mapper = {
        "HPD Template ID": "Id",
        "Description": "Description",
        "InstanceId": "InstanceID",
    }
    args["ids"] = argToList(args.get("template_ids"))
    command_results = list_command(
        client,
        args,
        "HPD:Template",
        context_output_mapper,
        header_prefix="List incident templates.",
        outputs_prefix="BmcITSM.IncidentTemplate",
        outputs_key_field="Id",
        record_id_key="HPD Template ID",
    )
    return command_results


def change_request_template_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """List BmcITSM change request templates command.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    context_output_mapper = {
        "CHG Template ID": "Id",
        "Description": "Description",
        "InstanceId": "InstanceID",
    }
    args["ids"] = argToList(args.get("template_ids"))
    command_results = list_command(
        client,
        args,
        "CHG:Template",
        context_output_mapper,
        header_prefix="List change request templates.",
        outputs_prefix="BmcITSM.ChangeRequestTemplate",
        outputs_key_field="Id",
        record_id_key="CHG Template ID",
    )
    return command_results


def task_template_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """List BmcITSM task templates command.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    context_output_mapper = {
        "Template ID": "Id",
        "TaskName": "TaskName",
        "InstanceId": "InstanceID",
    }

    args["ids"] = argToList(args.get("template_ids"))
    command_results = list_command(
        client,
        args,
        "TMS:TaskTemplate",
        context_output_mapper,
        header_prefix="List task templates.",
        outputs_prefix="BmcITSM.TaskTemplate",
        outputs_key_field="Id",
        record_id_key="Template ID",
    )
    return command_results


def service_request_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Create BmcITSM service request command.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    srd_instance_id = args["srd_instance_id"]
    summary = args.get("summary")
    status = args.get("status")
    urgency = args.get("urgency")
    impact = args.get("impact")
    first_name = args.get("first_name")
    last_name = args.get("last_name")
    login_id = args.get("login_id")

    additional_fields = extract_args_from_additional_fields_arg(args.get("additional_fields"),  # type: ignore[arg-type]
                                                                "additional_fields")
    service_request_definition_params = extract_args_from_additional_fields_arg(
        args.get("service_request_definition_params"),  # type: ignore[arg-type]
        "service_request_definition_params",
    )
    validate_related_arguments_provided(first_name=first_name,
                                        last_name=last_name,
                                        login_id=login_id)

    response = client.create_service_request_request(  # type: ignore[arg-type,call-arg]
        srd_instance_id,
        summary,  # type: ignore[arg-type]
        urgency,  # type: ignore[arg-type]
        impact,  # type: ignore[arg-type]
        first_name,  # type: ignore[arg-type]
        last_name,  # type: ignore[arg-type]
        login_id,  # type: ignore[arg-type]
        status,  # type: ignore[arg-type]
        **additional_fields,
        **service_request_definition_params,
    )

    outputs = format_create_ticket_outputs(response.get("values"))  # type: ignore[arg-type]
    readable_output = tableToMarkdown("Service Request successfully Created",
                                      outputs,
                                      headerTransform=pascalToSpace)
    command_results = CommandResults(
        outputs_prefix="BmcITSM.ServiceRequest",
        outputs_key_field="RequestID",
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output,
    )

    return command_results


def service_request_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Update BmcITSM service request command.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    service_request_id = args.get("ticket_request_id")
    customer_first_name = args.get("customer_first_name")
    customer_last_name = args.get("customer_last_name")
    status = args.get("status")
    summary = args.get("summary")
    status = args.get("status")
    status_reason = args.get("status_reason")
    urgency = args.get("urgency")
    impact = args.get("impact")
    assignee = args.get("assignee")
    location_company = args.get("location_company")
    site_group = args.get("site_group")
    region = args.get("region")
    site = args.get("site")
    additional_fields = extract_args_from_additional_fields_arg(args.get("additional_fields"),  # type: ignore[arg-type]
                                                                "additional_fields")

    formatted_service_request_id = format_ticket_request_id(service_request_id)  # type: ignore[arg-type]
    validate_related_arguments_provided(status=status, status_reason=status_reason)
    validate_related_arguments_provided(customer_first_name=customer_first_name,
                                        customer_last_name=customer_last_name)

    client.service_request_update_request(  # type: ignore[arg-type,call-arg]
        formatted_service_request_id,
        summary,
        status,  # type: ignore[arg-type]
        urgency,  # type: ignore[arg-type]
        impact,  # type: ignore[arg-type]
        customer_first_name,  # type: ignore[arg-type]
        customer_last_name,  # type: ignore[arg-type]
        location_company,
        site_group,  # type: ignore[arg-type]
        region,  # type: ignore[arg-type]
        site,  # type: ignore[arg-type]
        assignee,  # type: ignore[arg-type]
        status_reason,  # type: ignore[arg-type]
        **additional_fields,
    )
    command_results = CommandResults(
        readable_output=f"Service Request: {service_request_id} was successfully updated.")

    return command_results


def incident_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Create BmcITSM incident command.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    template_id = args.get("template_instance_id")
    summary = args.get("summary")
    status = args.get("status")
    urgency = args.get("urgency")
    impact = args.get("impact")
    first_name = args.get("first_name")
    last_name = args.get("last_name")
    service_type = args.get("service_type")
    reported_source = args.get("reported_source")
    details = args.get("details")
    company = args.get("location_company")
    assigned_support_organization = args.get("assigned_support_organization")
    assigned_support_company = args.get("assigned_support_company")
    assigned_group = args.get("assigned_group")
    assignee_login_id = args.get("assignee_login_id")
    assignee = args.get("assignee")
    site_group = args.get("site_group")
    site = args.get("site")
    region = args.get("region")

    additional_fields = extract_args_from_additional_fields_arg(args.get("additional_fields"),  # type: ignore[arg-type]
                                                                "additional_fields")

    validate_related_arguments_provided(assignee_login_id=assignee_login_id, assignee=assignee)
    if not template_id:
        validate_related_arguments_provided(summary=summary,
                                            service_type=service_type,
                                            reported_source=reported_source)

    response = client.create_incident_request(  # type: ignore[arg-type,call-arg]
        template_id,  # type: ignore[arg-type]
        first_name,  # type: ignore[arg-type]
        last_name,  # type: ignore[arg-type]
        summary,  # type: ignore[arg-type]
        urgency=urgency,  # type: ignore[arg-type]
        impact=impact,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        service_type=service_type,  # type: ignore[arg-type]
        reported_source=reported_source,  # type: ignore[arg-type]
        details=details,  # type: ignore[arg-type]
        company=company,  # type: ignore[arg-type]
        assigned_support_organization=assigned_support_organization,  # type: ignore[arg-type]
        assigned_support_company=assigned_support_company,  # type: ignore[arg-type]
        assigned_group=assigned_group,  # type: ignore[arg-type]
        assignee=assignee,  # type: ignore[arg-type]
        assignee_login_id=assignee_login_id,  # type: ignore[arg-type]
        site_group=site_group,  # type: ignore[arg-type]
        site=site,  # type: ignore[arg-type]
        region=region,  # type: ignore[arg-type]
        **additional_fields,
    )

    incident_request_id = extract_ticket_request_id_following_create(
        client, INCIDENT, response)  # The right request ID is not retrieved by the create endpoint.
    outputs = format_create_ticket_outputs(response.get("values"))  # type: ignore[arg-type]
    outputs["RequestID"] = incident_request_id

    readable_output = tableToMarkdown("Incident ticket successfully Created",
                                      outputs,
                                      headerTransform=pascalToSpace)
    command_results = CommandResults(
        outputs_prefix="BmcITSM.Incident",
        outputs_key_field="RequestID",
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output,
    )

    return command_results


def incident_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Update BmcITSM service request command.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    incident_request_id = args.get("ticket_request_id")

    summary = args.get("summary")
    status = args.get("status")
    urgency = args.get("urgency")
    impact = args.get("impact")
    first_name = args.get("first_name")
    last_name = args.get("last_name")
    service_type = args.get("service_type")
    reported_source = args.get("reported_source")
    details = args.get("details")
    company = args.get("location_company")
    assigned_support_organization = args.get("assigned_support_organization")
    assigned_support_company = args.get("assigned_support_company")
    assigned_group = args.get("assigned_group")
    assignee_login_id = args.get("assignee_login_id")
    assignee = args.get("assignee")
    site_group = args.get("site_group")
    site = args.get("site")
    region = args.get("region")
    resolution = args.get("resolution")
    status_reason = args.get("status_reason")

    additional_fields = extract_args_from_additional_fields_arg(args.get("additional_fields"),  # type: ignore[arg-type]
                                                                "additional_fields")

    validate_related_arguments_provided(first_name=first_name, last_name=last_name)
    validate_related_arguments_provided(assignee_login_id=assignee_login_id, assignee=assignee)
    validate_related_arguments_provided(status=status,
                                        status_reason=status_reason,
                                        resolution=resolution)

    client.update_incident_request(  # type: ignore[arg-type,call-arg]
        format_ticket_request_id(incident_request_id),  # type: ignore[arg-type]
        first_name,  # type: ignore[arg-type]
        last_name,  # type: ignore[arg-type]
        summary,  # type: ignore[arg-type]
        urgency=urgency,  # type: ignore[arg-type]
        impact=impact,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        service_type=service_type,  # type: ignore[arg-type]
        reported_source=reported_source,  # type: ignore[arg-type]
        details=details,  # type: ignore[arg-type]
        company=company,  # type: ignore[arg-type]
        assigned_support_organization=assigned_support_organization,  # type: ignore[arg-type]
        assigned_support_company=assigned_support_company,  # type: ignore[arg-type]
        assigned_group=assigned_group,  # type: ignore[arg-type]
        assignee=assignee,  # type: ignore[arg-type]
        assignee_login_id=assignee_login_id,  # type: ignore[arg-type]
        site_group=site_group,  # type: ignore[arg-type]
        site=site,  # type: ignore[arg-type]
        region=region,  # type: ignore[arg-type]
        status_reason=status_reason,  # type: ignore[arg-type]
        resolution=resolution,  # type: ignore[arg-type]
        **additional_fields,
    )

    command_results = CommandResults(
        readable_output=f"Incident: {incident_request_id} was successfully updated.")

    return command_results


def change_request_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Create BmcITSM change request command.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    template_id = args.get("template_id")
    summary = args.get("summary")
    status = args.get("status")
    urgency = args.get("urgency")
    impact = args.get("impact")
    first_name = args.get("first_name")
    last_name = args.get("last_name")
    customer_first_name = args.get("customer_first_name")
    customer_last_name = args.get("customer_last_name")
    priority = args.get("priority")
    risk_level = args.get("risk_level")
    change_type = args.get("change_type")
    location_company = args.get("location_company")
    additional_fields = extract_args_from_additional_fields_arg(args.get("additional_fields"),  # type: ignore[arg-type]
                                                                "additional_fields")
    if not template_id:
        validate_related_arguments_provided(
            first_name=first_name,
            last_name=last_name,
            summary=summary,
            location_company=location_company,
        )

    response = client.change_request_create_request(  # type: ignore[arg-type,call-arg]
        template_id,  # type: ignore[arg-type]
        first_name,  # type: ignore[arg-type]
        last_name,  # type: ignore[arg-type]
        summary,  # type: ignore[arg-type]
        location_company,  # type: ignore[arg-type]
        urgency=urgency,  # type: ignore[arg-type]
        impact=impact,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        risk_level=risk_level,  # type: ignore[arg-type]
        change_type=change_type,  # type: ignore[arg-type]
        customer_first_name=customer_first_name,  # type: ignore[arg-type]
        customer_last_name=customer_last_name,  # type: ignore[arg-type]
        priority=priority,  # type: ignore[arg-type]
        **additional_fields,
    )

    outputs = format_create_ticket_outputs(response.get("values"))  # type: ignore[arg-type]

    readable_output = tableToMarkdown(
        "Change Request ticket successfully Created",
        outputs,
        headerTransform=pascalToSpace,
    )
    command_results = CommandResults(
        outputs_prefix="BmcITSM.ChangeRequest",
        outputs_key_field="RequestID",
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output,
    )

    return command_results


def change_request_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Update BmcITSM change request command.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    change_request_id = args.get("ticket_request_id")
    summary = args.get("summary")
    details = args.get("details")
    status = args.get("status")
    status_reason = args.get("status_reason")
    urgency = args.get("urgency")
    impact = args.get("impact")
    first_name = args.get("first_name")
    last_name = args.get("last_name")
    customer_first_name = args.get("customer_first_name")
    customer_last_name = args.get("customer_last_name")
    priority = args.get("priority")
    risk_level = args.get("risk_level")
    change_type = args.get("change_type")
    location_company = args.get("location_company")
    organization = args.get("organization")
    department = args.get("department")
    site_group = args.get("site_group")
    site = args.get("site")
    support_organization = args.get("support_organization")
    support_group_name = args.get("support_group_name")
    company = args.get("company")
    region = args.get("region")

    additional_fields = extract_args_from_additional_fields_arg(args.get("additional_fields"),  # type: ignore[arg-type]
                                                                "additional_fields")

    validate_related_arguments_provided(first_name=first_name, last_name=last_name)

    validate_related_arguments_provided(status=status, status_reason=status_reason)

    client.change_request_update_request(  # type: ignore[arg-type,call-arg]
        format_ticket_request_id(change_request_id),  # type: ignore[arg-type]
        first_name,  # type: ignore[arg-type]
        last_name,  # type: ignore[arg-type]
        summary,  # type: ignore[arg-type]
        location_company,  # type: ignore[arg-type]
        urgency=urgency,  # type: ignore[arg-type]
        impact=impact,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        risk_level=risk_level,  # type: ignore[arg-type]
        change_type=change_type,  # type: ignore[arg-type]
        customer_first_name=customer_first_name,  # type: ignore[arg-type]
        customer_last_name=customer_last_name,  # type: ignore[arg-type]
        priority=priority,  # type: ignore[arg-type]
        details=details,  # type: ignore[arg-type]
        status_reason=status_reason,  # type: ignore[arg-type]
        organization=organization,  # type: ignore[arg-type]
        department=department,  # type: ignore[arg-type]
        site_group=site_group,  # type: ignore[arg-type]
        site=site,  # type: ignore[arg-type]
        support_organization=support_organization,  # type: ignore[arg-type]
        support_group_name=support_group_name,  # type: ignore[arg-type]
        company=company,  # type: ignore[arg-type]
        region=region,  # type: ignore[arg-type]
        **additional_fields,
    )

    command_results = CommandResults(
        readable_output=f"Change Request: {change_request_id} was successfully updated.")

    return command_results


def task_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Create BmcITSM task command.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    template_id = args.get("template_id")
    root_request_id = args.get("root_request_id")
    root_request_name = args.get("root_request_name")
    root_request_mode = args.get("root_request_mode")
    first_name = args.get("first_name")
    last_name = args.get("last_name")
    summary = args.get("summary")
    details = args.get("details")
    status = args.get("status")
    task_type = args.get("task_type")
    priority = args.get("priority")
    impact = args.get("impact")
    urgency = args.get("urgency")
    support_company = args.get("support_company")
    customer_company = args.get("customer_company")

    assigned_support_organization = args.get("assigned_support_organization")
    assigned_support_group_name = args.get("assigned_support_group")
    assignee = args.get("assignee")
    company = args.get("location_company")
    root_ticket_type = TICKET_TYPE_TO_DELETE_FORM[args.get("root_ticket_type")]  # type: ignore[index]
    scedulded_start_date: datetime = arg_to_datetime(args.get("scedulded_start_date"))  # type: ignore[assignment]
    scedulded_end_date: datetime = arg_to_datetime(args.get("scedulded_end_date"))  # type: ignore[assignment]

    additional_fields = extract_args_from_additional_fields_arg(args.get("additional_fields"),  # type: ignore[arg-type]
                                                                "additional_fields")
    parent_ticket = get_ticket(client, args.get("root_ticket_type"), root_request_id)  # type: ignore[arg-type]
    response = client.create_task_request(  # type: ignore[arg-type,call-arg]
        template_id,  # type: ignore[arg-type]
        parent_ticket.get("InstanceId"),  # type: ignore[arg-type]
        root_request_name or parent_ticket.get("DisplayID"),  # type: ignore[arg-type]
        parent_ticket.get("DisplayID"),  # type: ignore[arg-type]
        first_name,  # type: ignore[arg-type]
        last_name,  # type: ignore[arg-type]
        summary,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        impact=impact,  # type: ignore[arg-type]
        urgency=urgency,  # type: ignore[arg-type]
        priority=priority,  # type: ignore[arg-type]
        details=details,  # type: ignore[arg-type]
        task_type=task_type,  # type: ignore[arg-type]
        support_company=support_company,  # type: ignore[arg-type]
        assignee=assignee,  # type: ignore[arg-type]
        location_company=company,  # type: ignore[arg-type]
        root_request_mode=root_request_mode,  # type: ignore[arg-type]
        root_ticket_type=root_ticket_type,
        assigned_support_group_name=assigned_support_group_name,  # type: ignore[arg-type]
        assigned_support_organization=assigned_support_organization,  # type: ignore[arg-type]
        scedulded_start_date=scedulded_start_date.isoformat() if scedulded_start_date else None,  # type: ignore[arg-type]
        scedulded_end_date=scedulded_end_date.isoformat() if scedulded_end_date else None,  # type: ignore[arg-type]
        customer_company=customer_company,  # type: ignore[arg-type]
        **additional_fields,
    )

    outputs = format_create_ticket_outputs(response.get("values"))  # type: ignore[arg-type]
    outputs["RequestID"] = outputs["DisplayID"]
    readable_output = tableToMarkdown("Task ticket successfully Created.",
                                      outputs,
                                      headerTransform=pascalToSpace)
    command_results = CommandResults(
        outputs_prefix="BmcITSM.Task",
        outputs_key_field="RequestID",
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output,
    )

    return command_results


def task_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Update BmcITSM task command.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    task_id = args.get("ticket_request_id")
    root_request_name = args.get("root_request_name")
    summary = args.get("summary")
    details = args.get("details")
    status = args.get("status")
    status_reason = args.get("status_reason")
    task_type = args.get("task_type")
    priority = args.get("priority")
    company = args.get("company")
    location_company = args.get("location_company")

    priority = args.get("priority")
    organization = args.get("organization")
    department = args.get("department")
    site_group = args.get("site_group")
    site = args.get("site")
    support_company = args.get("support_company")
    assigned_support_organization = args.get("assigned_support_organization")
    assigned_support_group_name = args.get("assigned_group")
    assignee = args.get("assignee")
    scedulded_start_date: datetime = arg_to_datetime(args.get("scedulded_start_date"))  # type: ignore[assignment]
    schedulded_end_date: datetime = arg_to_datetime(args.get("schedulded_end_date"))  # type: ignore[assignment]
    customer_company = args.get("customer_company")  # type: ignore[assignment]

    additional_fields = extract_args_from_additional_fields_arg(args.get("additional_fields"),  # type: ignore[arg-type]
                                                                "additional_fields")
    client.update_task_request(  # type: ignore[arg-type,call-arg]
        format_ticket_request_id(task_id),  # type: ignore[arg-type]
        root_request_name,  # type: ignore[arg-type]
        summary=summary,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        priority=priority,  # type: ignore[arg-type]
        details=details,  # type: ignore[arg-type]
        task_type=task_type,  # type: ignore[arg-type]
        organization=organization,
        department=department,
        site_group=site_group,
        site=site,
        assigned_support_company=support_company,  # type: ignore[arg-type]
        assignee=assignee,  # type: ignore[arg-type]
        company=company,  # type: ignore[arg-type]
        location_company=location_company,  # type: ignore[arg-type]
        status_reason=status_reason,  # type: ignore[arg-type]
        assigned_support_organization=assigned_support_organization,  # type: ignore[arg-type]
        assigned_support_group_name=assigned_support_group_name,  # type: ignore[arg-type]
        scedulded_start_date=scedulded_start_date.isoformat() if scedulded_start_date else None,  # type: ignore[arg-type]
        schedulded_end_date=schedulded_end_date.isoformat if schedulded_end_date else None,  # type: ignore[arg-type]
        customer_company=customer_company,  # type: ignore[arg-type]
        **additional_fields,
    )

    command_results = CommandResults(readable_output=f"Task: {task_id} was successfully updated.")

    return command_results


def problem_investigation_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Create BmcITSM problem investigation command.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    summary = args.get("summary")
    status = args.get("status")
    urgency = args.get("urgency")
    impact = args.get("impact")
    first_name = args.get("first_name")
    last_name = args.get("last_name")
    details = args.get("details")
    company = args.get("company")
    site_group = args.get("site_group")
    site = args.get("site")
    region = args.get("region")
    assigned_support_organization = args.get("assigned_support_organization")
    assigned_support_company = args.get("assigned_support_company")
    assigned_support_group_name = args.get("assigned_group")
    assignee = args.get("assignee")
    assigned_group_pbm_mgr = args.get("assigned_group_pbm_mgr")
    support_company_pbm_mgr = args.get("support_company_pbm_mgr")
    support_organization_pbm_mgr = args.get("support_organization_pbm_mgr")
    assignee_pbm_mgr = args.get("assignee_pbm_mgr")
    temporary_workaround = args.get("temporary_workaround")
    target_resolution_date: datetime = arg_to_datetime(args.get("target_resolution_date"))  # type: ignore[assignment]
    resolution = args.get("resolution")
    investigation_justification = args.get("investigation_justification")
    investigation_driver = args.get("investigation_driver")
    additional_fields = extract_args_from_additional_fields_arg(args.get("additional_fields"),  # type: ignore[arg-type]
                                                                "additional_fields")

    validate_related_arguments_provided(company=company,
                                        site=site,
                                        site_group=site_group,
                                        region=region)
    validate_related_arguments_provided(
        assigned_support_organization=assigned_support_organization,
        assigned_support_company=assigned_support_company,
        assigned_support_group_name=assigned_support_group_name,
    )

    validate_related_arguments_provided(
        assigned_group_pbm_mgr=assigned_group_pbm_mgr,
        support_company_pbm_mgr=support_company_pbm_mgr,
        support_organization_pbm_mgr=support_organization_pbm_mgr,
    )

    response = client.create_problem_investigation_request(  # type: ignore[arg-type]
        PROBLEM_INVESTIGATION,
        summary,  # type: ignore[arg-type]
        first_name=first_name,
        last_name=last_name,
        urgency=urgency,  # type: ignore[arg-type]
        impact=impact,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        details=details,  # type: ignore[arg-type]
        company=company,  # type: ignore[arg-type]
        assigned_support_organization=assigned_support_organization,  # type: ignore[arg-type]
        assigned_support_company=assigned_support_company,  # type: ignore[arg-type]
        assigned_support_group_name=assigned_support_group_name,  # type: ignore[arg-type]
        assignee=assignee,  # type: ignore[arg-type]
        site_group=site_group,  # type: ignore[arg-type]
        site=site,  # type: ignore[arg-type]
        region=region,  # type: ignore[arg-type]
        assigned_group_pbm_mgr=assigned_group_pbm_mgr,  # type: ignore[arg-type]
        support_company_pbm_mgr=support_company_pbm_mgr,  # type: ignore[arg-type]
        support_organization_pbm_mgr=support_organization_pbm_mgr,  # type: ignore[arg-type]
        temporary_workaround=temporary_workaround,  # type: ignore[arg-type]
        target_resolution_date=target_resolution_date.isoformat()  # type: ignore[arg-type]
        if target_resolution_date else None,
        investigation_justification=investigation_justification,
        investigation_driver=investigation_driver,
        resolution=resolution,
        assignee_pbm_mgr=assignee_pbm_mgr,  # type: ignore[arg-type]
        **additional_fields,
    )

    incident_request_id = extract_ticket_request_id_following_create(
        client, PROBLEM_INVESTIGATION,
        response)  # The right request ID is not retrieved by the create endpoint.
    outputs = format_create_ticket_outputs(response.get("values"))
    outputs["RequestID"] = incident_request_id

    readable_output = tableToMarkdown(
        "Problem Investigation  ticket successfully Created",
        outputs,
        headerTransform=pascalToSpace,
    )
    command_results = CommandResults(
        outputs_prefix="BmcITSM.ProblemInvestigation",
        outputs_key_field="RequestID",
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output,
    )

    return command_results


def problem_investigation_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Update BmcITSM problem investigation command.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    problem_investigation_id = args.get("ticket_request_id")
    summary = args.get("summary")
    status = args.get("status")
    status_reason = args.get("status_reason")
    urgency = args.get("urgency")
    impact = args.get("impact")
    first_name = args.get("first_name")
    last_name = args.get("last_name")
    details = args.get("details")
    company = args.get("company")
    site_group = args.get("site_group")
    site = args.get("site")
    region = args.get("region")
    assigned_support_organization = args.get("assigned_support_organization")
    assigned_support_company = args.get("assigned_support_company")
    assigned_support_group_name = args.get("assigned_group")
    assignee_login_id = args.get("assignee_login_id")
    assignee = args.get("assigned_to")
    assigned_group_pbm_mgr = args.get("assigned_group_pbm_mgr")
    support_company_pbm_mgr = args.get("support_company_pbm_mgr")
    support_organization_pbm_mgr = args.get("support_organization_pbm_mgr")
    assignee_pbm_mgr = args.get("assignee_pbm_mgr")
    temporary_workaround = args.get("temporary_workaround")
    resolution = args.get("resolution")
    target_resolution_date: datetime = arg_to_datetime(args.get("target_resolution_date"))  # type: ignore[assignment]
    investigation_justification = args.get("investigation_justification")
    investigation_driver = args.get("investigation_driver")
    additional_fields = extract_args_from_additional_fields_arg(args.get("additional_fields"),  # type: ignore[arg-type]
                                                                "additional_fields")

    validate_related_arguments_provided(company=company,
                                        site=site,
                                        site_group=site_group,
                                        region=region)
    validate_related_arguments_provided(
        assigned_support_organization=assigned_support_organization,
        assigned_support_company=assigned_support_company,
        assigned_support_group_name=assigned_support_group_name,
    )

    validate_related_arguments_provided(
        assigned_group_pbm_mgr=assigned_group_pbm_mgr,
        support_company_pbm_mgr=support_company_pbm_mgr,
        support_organization_pbm_mgr=support_organization_pbm_mgr,
    )

    client.update_problem_investigation_request(  # type: ignore[arg-type,call-arg]
        format_ticket_request_id(problem_investigation_id),  # type: ignore[arg-type]
        first_name,  # type: ignore[arg-type]
        last_name,  # type: ignore[arg-type]
        summary,  # type: ignore[arg-type]
        urgency=urgency,  # type: ignore[arg-type]
        impact=impact,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        status_reason=status_reason,  # type: ignore[arg-type]
        details=details,  # type: ignore[arg-type]
        company=company,  # type: ignore[arg-type]
        assigned_support_organization=assigned_support_organization,  # type: ignore[arg-type]
        assigned_support_company=assigned_support_company,  # type: ignore[arg-type]
        assigned_support_group_name=assigned_support_group_name,  # type: ignore[arg-type]
        assignee=assignee,  # type: ignore[arg-type]
        assignee_login_id=assignee_login_id,  # type: ignore[arg-type]
        site_group=site_group,  # type: ignore[arg-type]
        site=site,  # type: ignore[arg-type]
        region=region,  # type: ignore[arg-type]
        assigned_group_pbm_mgr=assigned_group_pbm_mgr,  # type: ignore[arg-type]
        support_company_pbm_mgr=support_company_pbm_mgr,  # type: ignore[arg-type]
        support_organization_pbm_mgr=support_organization_pbm_mgr,  # type: ignore[arg-type]
        temporary_workaround=temporary_workaround,  # type: ignore[arg-type]
        resolution=resolution,  # type: ignore[arg-type]
        target_resolution_date=target_resolution_date.isoformat()  # type: ignore[arg-type]
        if target_resolution_date else None,
        investigation_justification=investigation_justification,  # type: ignore[arg-type]
        investigation_driver=investigation_driver,  # type: ignore[arg-type]
        assignee_pbm_mgr=assignee_pbm_mgr,
        **additional_fields,
    )
    readable_msg = f"Problem Investigation: {problem_investigation_id} was successfully updated."
    command_results = CommandResults(readable_output=readable_msg)
    return command_results


def known_error_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Create BmcITSM Known Error command.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    summary = args.get("summary")
    status = args.get("status")
    urgency = args.get("urgency")
    impact = args.get("impact")
    details = args.get("details")
    company = args.get("company")
    site_group = args.get("site_group")
    site = args.get("site")
    region = args.get("region")
    assigned_support_organization = args.get("assigned_support_organization")
    assigned_support_company = args.get("assigned_support_company")
    assigned_support_group_name = args.get("assigned_group")
    assignee = args.get("assignee")
    assigned_group_pbm_mgr = args.get("assigned_group_pbm_mgr")
    support_company_pbm_mgr = args.get("support_company_pbm_mgr")
    support_organization_pbm_mgr = args.get("support_organization_pbm_mgr")
    assignee_pbm_mgr = args.get("assignee_pbm_mgr")
    temporary_workaround = args.get("temporary_workaround")
    resolution = args.get("resolution")
    target_resolution_date = arg_to_datetime(args.get("target_resolution_date")).isoformat()  # type: ignore[union-attr]
    view_access = args.get("view_access")
    additional_fields = extract_args_from_additional_fields_arg(args.get("additional_fields"),  # type: ignore[arg-type]
                                                                "additional_fields")

    validate_related_arguments_provided(
        assigned_support_organization=assigned_support_organization,
        assigned_support_company=assigned_support_company,
        assigned_support_group_name=assigned_support_group_name,
    )

    validate_related_arguments_provided(
        assigned_group_pbm_mgr=assigned_group_pbm_mgr,
        support_company_pbm_mgr=support_company_pbm_mgr,
        support_organization_pbm_mgr=support_organization_pbm_mgr,
    )
    response = client.create_problem_investigation_request(  # type: ignore[arg-type]
        KNOWN_ERROR,
        summary,  # type: ignore[arg-type]
        urgency=urgency,  # type: ignore[arg-type]
        impact=impact,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        details=details,  # type: ignore[arg-type]
        company=company,  # type: ignore[arg-type]
        assigned_support_organization=assigned_support_organization,  # type: ignore[arg-type]
        assigned_support_company=assigned_support_company,  # type: ignore[arg-type]
        assigned_support_group_name=assigned_support_group_name,  # type: ignore[arg-type]
        assignee=assignee,  # type: ignore[arg-type]
        site_group=site_group,  # type: ignore[arg-type]
        site=site,  # type: ignore[arg-type]
        region=region,  # type: ignore[arg-type]
        assigned_group_pbm_mgr=assigned_group_pbm_mgr,  # type: ignore[arg-type]
        support_company_pbm_mgr=support_company_pbm_mgr,  # type: ignore[arg-type]
        support_organization_pbm_mgr=support_organization_pbm_mgr,  # type: ignore[arg-type]
        temporary_workaround=temporary_workaround,  # type: ignore[arg-type]
        resolution=resolution,
        target_resolution_date=target_resolution_date,
        view_access=view_access,
        assignee_pbm_mgr=assignee_pbm_mgr,  # type: ignore[arg-type]
        **additional_fields,
    )

    known_error_id = extract_ticket_request_id_following_create(
        client, KNOWN_ERROR,
        response)  # The right request ID is not retrieved by the create endpoint.
    outputs = format_create_ticket_outputs(response.get("values"))
    outputs["RequestID"] = known_error_id

    readable_output = tableToMarkdown(
        "Known Error ticket successfully Created",
        outputs,
        headerTransform=pascalToSpace,
    )
    command_results = CommandResults(
        outputs_prefix="BmcITSM.KnownError",
        outputs_key_field="RequestID",
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output,
    )

    return command_results


def known_error_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Update BmcITSM known error command.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    known_error_id = args.get("ticket_request_id")
    summary = args.get("summary")
    status = args.get("status")
    urgency = args.get("urgency")
    impact = args.get("impact")
    details = args.get("details")
    status_reason = args.get("status_reason")
    assigned_support_organization = args.get("assigned_support_organization")
    assigned_support_company = args.get("assigned_support_company")
    assigned_support_group_name = args.get("assigned_group")
    assignee = args.get("assignee")
    assignee_pbm_mgr = args.get("assignee_pbm_mgr")
    assigned_group_pbm_mgr = args.get("assigned_group_pbm_mgr")
    support_company_pbm_mgr = args.get("support_company_pbm_mgr")
    support_organization_pbm_mgr = args.get("support_organization_pbm_mgr")
    temporary_workaround = args.get("temporary_workaround")
    resolution = args.get("resolution")
    target_resolution_date = arg_to_datetime(args.get("target_resolution_date"))
    view_access = args.get("view_access")

    target_resolution_date: datetime = arg_to_datetime(args.get("target_resolution_date"))  # type: ignore[no-redef]
    additional_fields = extract_args_from_additional_fields_arg(args.get("additional_fields"),  # type: ignore[arg-type]
                                                                "additional_fields")

    validate_related_arguments_provided(
        assigned_support_organization=assigned_support_organization,
        assigned_support_company=assigned_support_company,
        assigned_support_group_name=assigned_support_group_name,
    )

    validate_related_arguments_provided(
        assigned_group_pbm_mgr=assigned_group_pbm_mgr,
        support_company_pbm_mgr=support_company_pbm_mgr,
        support_organization_pbm_mgr=support_organization_pbm_mgr,
    )

    validate_related_arguments_provided(status=status, status_reason=status_reason)

    client.update_known_error_request(  # type: ignore[arg-type,call-arg]
        format_ticket_request_id(known_error_id),  # type: ignore[arg-type]
        summary,  # type: ignore[arg-type]
        urgency=urgency,  # type: ignore[arg-type]
        impact=impact,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        details=details,  # type: ignore[arg-type]
        assigned_support_organization=assigned_support_organization,  # type: ignore[arg-type]
        assigned_support_company=assigned_support_company,  # type: ignore[arg-type]
        assigned_support_group_name=assigned_support_group_name,  # type: ignore[arg-type]
        assignee=assignee,  # type: ignore[arg-type]
        assigned_group_pbm_mgr=assigned_group_pbm_mgr,  # type: ignore[arg-type]
        support_company_pbm_mgr=support_company_pbm_mgr,  # type: ignore[arg-type]
        support_organization_pbm_mgr=support_organization_pbm_mgr,  # type: ignore[arg-type]
        target_resolution_date=target_resolution_date.isoformat()  # type: ignore[arg-type]
        if target_resolution_date else None,
        status_reason=status_reason,  # type: ignore[arg-type]
        assignee_pbm_mgr=assignee_pbm_mgr,  # type: ignore[arg-type]
        temporary_workaround=temporary_workaround,  # type: ignore[arg-type]
        resolution=resolution,  # type: ignore[arg-type]
        view_access=view_access,  # type: ignore[arg-type]
        **additional_fields,
    )

    command_results = CommandResults(
        readable_output=f"Known Error: {known_error_id} was successfully updated.")

    return command_results


def support_group_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """List BmcITSM support groups.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    context_output_mapper = {
        "Support Group ID": "SupportGroupID",
        "Company": "Company",
        "Support Organization": "SupportOrganization",
        "Support Group Name": "SupportGroupName"
    }

    command_results = list_command(
        client,
        args,
        "CTM:Support Group",
        context_output_mapper,
        header_prefix="List support groups.",
        outputs_prefix="BmcITSM.SupportGroup",
        outputs_key_field="SupportGroupID",
        record_id_key="SupportGroupID",
    )
    return command_results


def work_order_template_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """List BmcITSM work order templates.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    context_output_mapper = {
        "Request ID": "Id",
        "Template Name": "Name",
        "GUID": "GUID",
    }

    args["ids"] = argToList(args.get("template_ids"))
    command_results = list_command(
        client,
        args,
        "WOI:Template",
        context_output_mapper,
        header_prefix="List work order templates.",
        outputs_prefix="BmcITSM.WorkOrderTemplate",
        outputs_key_field="Id",
        record_id_key="GUID",
    )
    return command_results


def work_order_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Create BmcITSM work order.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    template_guid = args.get("template_guid")
    first_name = args.get("first_name")
    last_name = args.get("last_name")
    customer_person_id = args.get("customer_person_id")
    customer_first_name = args.get("customer_first_name")
    customer_last_name = args.get("customer_last_name")
    customer_company = args.get("customer_company")
    summary = args.get("summary")
    detailed_description = args.get("detailed_description")
    status = args.get("status")
    priority = args.get("priority")
    work_order_type = args.get("work_order_type")
    location_company = args.get("location_company")
    scedulded_start_date: datetime = arg_to_datetime(args.get("scedulded_start_date"))  # type: ignore[assignment]
    scedulded_end_date: datetime = arg_to_datetime(args.get("scedulded_end_date"))  # type: ignore[assignment]

    additional_fields = extract_args_from_additional_fields_arg(args.get("additional_fields"),  # type: ignore[arg-type]
                                                                "additional_fields")
    response = client.create_work_order_request(  # type: ignore[arg-type,call-arg]
        template_guid,  # type: ignore[arg-type]
        first_name,  # type: ignore[arg-type]
        last_name,  # type: ignore[arg-type]
        customer_person_id,  # type: ignore[arg-type]
        customer_first_name,  # type: ignore[arg-type]
        customer_last_name,  # type: ignore[arg-type]
        customer_company,  # type: ignore[arg-type]
        summary,  # type: ignore[arg-type]
        detailed_description,  # type: ignore[arg-type]
        status,  # type: ignore[arg-type]
        priority,  # type: ignore[arg-type]
        work_order_type,  # type: ignore[arg-type]
        location_company,  # type: ignore[arg-type]
        scedulded_start_date=scedulded_start_date.isoformat() if scedulded_start_date else None,  # type: ignore[arg-type]
        scedulded_end_date=scedulded_end_date.isoformat() if scedulded_end_date else None,  # type: ignore[arg-type]
        **additional_fields,
    )

    outputs = format_create_ticket_outputs(response.get("values"))  # type: ignore[arg-type]
    # Fixing API returning RequestID in form 000...NNN instead of WO0...NNN
    outputs["RequestID"] = "WO0" + outputs["RequestID"][3:]
    readable_output = tableToMarkdown("Work order ticket successfully created.",
                                      outputs,
                                      headerTransform=pascalToSpace)
    command_results = CommandResults(
        outputs_prefix="BmcITSM.WorkOrder",
        outputs_key_field="RequestID",
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output,
    )

    return command_results


def work_order_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Update BmcITSM work order.

    Args:
        client (Client): BmcITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    request_id = args.get("request_id")
    summary = args.get("summary")
    detailed_description = args.get("detailed_description")
    status = args.get("status")
    status_reason = args.get("status_reason")
    priority = args.get("priority")
    work_order_type = args.get("work_order_type")
    company = args.get("company")
    assignee = args.get("assignee")
    support_organization = args.get("support_organization")
    support_group = args.get("support_group")
    location_company = args.get("location_company")
    scedulded_start_date: datetime = arg_to_datetime(args.get("scedulded_start_date"))  # type: ignore[assignment]
    schedulded_end_date: datetime = arg_to_datetime(args.get("schedulded_end_date"))  # type: ignore[assignment]

    additional_fields = extract_args_from_additional_fields_arg(args.get("additional_fields"),  # type: ignore[arg-type]
                                                                "additional_fields")

    validate_related_arguments_provided(support_organization=support_organization, support_group=support_group)

    client.update_work_order_request(  # type: ignore[arg-type,call-arg]
        request_id,  # type: ignore[arg-type]
        summary=summary,  # type: ignore[arg-type]
        detailed_description=detailed_description,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        status_reason=status_reason,  # type: ignore[arg-type]
        priority=priority,  # type: ignore[arg-type]
        work_order_type=work_order_type,  # type: ignore[arg-type]
        company=company,  # type: ignore[arg-type]
        assignee=assignee,  # type: ignore[arg-type]
        support_organization=support_organization,  # type: ignore[arg-type]
        support_group_name=support_group,  # type: ignore[arg-type]
        location_company=location_company,  # type: ignore[arg-type]
        scedulded_start_date=scedulded_start_date.isoformat() if scedulded_start_date else None,  # type: ignore[arg-type]
        schedulded_end_date=schedulded_end_date.isoformat if schedulded_end_date else None,  # type: ignore[arg-type]
        **additional_fields,
    )

    command_results = CommandResults(readable_output=f"Work Order: {request_id} was successfully updated.")

    return command_results


def format_command_output(records: List[dict],
                          mapper: Dict[str, Any],
                          context_data_arranger: Callable = None) -> Dict[str, Any]:
    """
    Format the returned records from the API according to the provided mapper.
    The main objective is to extract relevant attributes from the response to
    the root level of the context data.

    Args:
        records (List[dict]): List of resource which returned from BmcITSM API.
        mapper (Dict[str, Any]): In charge of the which attributes to extract to root level.
        context_data_arranger (Callable): Function which responsible for arranging the
        data according to the required context output.

    Returns:
        Dict[str, Any]: Formatted command output.
    """
    outputs = []
    for record in records:
        formatted_record = {}
        record_attributes = record.get("values")

        for origin_attrib_name, formatted_attrib_name in mapper.items():
            if origin_attrib_name in record_attributes:  # type: ignore[operator]
                if formatted_attrib_name in (
                        "RequestID",
                        "ID",
                ):  # extract request ID out of pattern: <id|id> -> id

                    formatted_record[formatted_attrib_name] = extract_ticket_request_id(
                        record_attributes[origin_attrib_name])  # type: ignore[index]

                elif ("Date" in formatted_attrib_name and record_attributes[origin_attrib_name]):  # type: ignore[index]
                    formatted_record[formatted_attrib_name] = FormatIso8601(
                        arg_to_datetime(record_attributes[origin_attrib_name]))  # type: ignore[index]

                else:
                    formatted_record[formatted_attrib_name] = record_attributes[origin_attrib_name]  # type: ignore[index]
        if context_data_arranger:
            context_data_arranger(formatted_record)
        outputs.append(formatted_record)

    return outputs  # type: ignore[return-value]


def get_paginated_records_with_hr(
    raw_data: List[dict],
    limit: Optional[int],
    page: int = None,
    page_size: int = None,
) -> tuple[list, str]:
    """
    Retrieve the required page either with Automatic or Manual pagination,
    and the matching readable output header.

    Args:
        raw_data (List[dict]): Records of resources from BmcITSM.
        page (int): Page number.
        page_size (int): Page size.
        limit (Optional[int]): Limit.

    Returns:
        tuple: Requested page& matching readable output header.
    """
    header = ""
    rows_count = len(raw_data)
    if page and page_size:
        total_pages = rows_count // page_size + (rows_count % page_size != 0)
        from_index = min((page - 1) * page_size, rows_count)
        to_index = min(from_index + page_size, rows_count)
        relevant_raw_data = raw_data[from_index:to_index]
        header = (f"Showing page {page} out of {total_pages} total pages."
                  f" Current page size: {page_size}.")
    else:
        relevant_raw_data = raw_data[:min(rows_count, limit)]  # type: ignore[type-var]
        header = f"Showing {len(relevant_raw_data)} records out of {rows_count}."

    return relevant_raw_data, header if relevant_raw_data else ""


def extract_ticket_request_id(request_id: str) -> str:
    """
    Extracts the raw request ID. In some use case, BmcITSM tickets are retrieved with
    request ID property in the format of "ID|ID". Since the integration works with ID only,
    an alignment is needed. For example, for the provided request_id="1111|1111" this function will return "1111".
    In any other case no extra processing is needed.

    Args:
        request_id (str): The request ID which returned from the BmcITSM API.

    Returns:
        str: the raw ticket request ID.
    """
    return request_id.split("|")[0]


def format_ticket_request_id(request_id: str) -> str:
    """
    Formats raw Request ID in the pattern of: ID|ID.
    Useful for sevreal API endpoints.

    Args:
        request_id (str): Raw ticket request ID.

    Returns:
        str: Formatted request ID.
    """
    if "|" not in request_id:
        return f"{request_id}|{request_id}"
    return request_id


def validate_related_arguments_provided(**related_args):
    """
    Validates that the passed keyword arguments provided together:
    all of them have non None value or all of them have None value.

    Raises:
        ValueError: In case when one of the argument have non None value and
        another one has None value.

    """
    at_least_one_is_provided = any(related_args.values())
    at_least_one_is_not_provided = not all(related_args.values())
    if at_least_one_is_not_provided and at_least_one_is_provided:
        raise ValueError(
            f"The arguments: {list(related_args.keys())} either all should all have value,\
                         or none should have value.")


def extract_args_from_additional_fields_arg(additional_fields: str,
                                            field_name: str) -> tuple[Any, List[str]]:
    """
    Extract dictionary structure from additional field argument.

    Args:
        additional_fields (str): Free text argument for additional fields.
        field_name (str): The name of the field.

    Raises:
        ValueError: If format of the field is invalid.

    Returns:
        Tuple[Any, List[str]]: Tuple containing dictionary and list.
    """

    formatted_additional_fields = {}
    if not additional_fields:
        return {}  # type: ignore[return-value]
    try:
        fields = additional_fields.split(FIELD_DELIMITER)
        for each_field in fields:
            key, value = each_field.split(VALUE_DELIMITER)
            if value and value.strip() != "":
                formatted_additional_fields[key.strip()] = value
    except ValueError as error:
        raise ValueError(
            f'Please validate the format of the argument: {field_name}. For example: "fieldname1=value;fieldname2=value".  '
        ) from error
    return formatted_additional_fields  # type: ignore[return-value]


def arrange_ticket_context_data(ticket: Dict[str, Any]) -> Dict[str, Any]:
    """
    Arranges the ticket context data.

    Args:
        ticket (Dict[str, Any]): ticket context data before arrangement.

    Returns:
        Dict[str, Any]: Arranged ticket context data.
    """
    customer = {}
    requester = {}
    assignee = {}
    customer_mapper = {
        "FirstName": "Customer First Name",
        "LastName": "Customer Last Name",
        "Company": "Customer Company",
        "Organization": "Customer Organization",
        "Department": "Customer Department",
        "E-mail": "Customer Internet E-mail",
        "PhoneNumber": "Customer Phone Number",
    }

    requester_mapper = {
        "FirstName": "First Name",
        "LastName": "Last Name",
        "Company": "Company",
        "Region": "Region",
        "Site": "Site",
        "SiteGroup": "Site Group",
    }

    assignee_mapper = {
        "FullName": "Assignee",
        "Group": "Assignee Group",
        "SupportOrganization": "Assigned Support Organization",
        "SupportCompany": "Assigned Support Company",
        "AssignedGroup": "Assigned Group",
    }

    customer = generate_complex_entity_for_context_data(ticket, customer_mapper)
    requester = generate_complex_entity_for_context_data(ticket, requester_mapper)
    assignee = generate_complex_entity_for_context_data(ticket, assignee_mapper)

    ticket["Type"] = get_ticket_type_by_display_id(ticket["DisplayID"])
    if ticket["Type"] == "incident":
        customer.update({key: requester[key] for key in ["FirstName", "LastName", "Company"]})
    ticket["RequestID"] = ticket.get("RequestID", ticket["DisplayID"])
    ticket["Customer"] = customer if not all_keys_empty(customer) else None
    ticket["Requester"] = requester if not all_keys_empty(requester) else None
    ticket["Assignee"] = assignee if not all_keys_empty(assignee) else None

    return ticket


def generate_complex_entity_for_context_data(raw_data: Dict[str, Any],
                                             mapper: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generates non-Flatten context key for the context Data.

    Args:
        raw_data (Dict[str, Any]): The raw data extract relevant data from.
        mapper (Dict[str, Any]): Mapper from context data key to the original key.

    Returns:
        Dict[str, Any]: A non-Flatten context key for the context Data.
    """
    complex_entitiy = {}
    for context_attrib_name, origin_attrib_name in mapper.items():
        complex_entitiy[context_attrib_name] = raw_data.pop(origin_attrib_name, None)
    return complex_entitiy


def generate_ticket_context_data_mapper(ticket_type: str) -> Dict[str, Any]:
    """
    Generates mapper of ticket context data. Based on unique and common
    ticket properties.

    Args:
        ticket_type (str): Ticket type.

    Returns:
        Dict[str, Any]: Mapper from response to context data.
    """
    context_data_mapper = TICKET_TYPE_TO_CONTEXT_MAPPER.get(ticket_type, {})
    return {**context_data_mapper, **COMMON_TICKET_CONTEXT_FIELDS}


def get_ticket_type_by_display_id(request_num: str) -> str:
    """
    Get the ticket type based on the prefix of the Display ID.
    For example for DisplayID=REQ0000000001 the output will be "service request"

    Args:
        request_num (str): Ticket display ID.

    Returns:
        str: ticket type.
    """
    prefix = request_num[:TICKET_PREFIX_LEN]
    return REQUEST_NUM_PREFIX_TO_TICKET_TYPE[prefix]


def get_ticket_type_by_request_id(request_num: str) -> str:
    """
    Get the ticket type based on the prefix of the Request ID.
    For example for DisplayID=CRQ0000000001 the output will be "change request".
    For service request ticket, the request ID is a number-
    without ticket type identifier as prefix.

    Args:
        request_num (str): Ticket display ID.

    Returns:
        str: ticket type.
    """
    prefix = request_num[:TICKET_PREFIX_LEN]
    return REQUEST_NUM_PREFIX_TO_TICKET_TYPE.get(prefix) or SERVICE_REQUEST


def generate_query_filter_mapper_by_args(args: Dict[str, Any], record_id_key: Optional[str],
                                         ticket_type: Optional[str]) -> Dict[str, Any]:
    """
    Generates mapper of filter argument name in BMC search qualification query
    to it's provided value.
    The mapper takes into consideration the filters by ids, filter by '='
    operator and filters by 'LIKE' operator.
    Args:
        args (Dict[str, Any]): Command arguments.
        record_id_key (Optional[str]): The attribute name of the record ID.
        ticket_type  (Optional[str]): The ticket type.

    Returns:
        Dict[str, Any]: mapper of filter argument name to it's value.
    """

    ids_filter_mapper = {record_id_key: args.get("ids")}
    status_key = TICKET_TYPE_TO_STATUS_FIELD.get(ticket_type, "Status")  # type: ignore[arg-type]
    summary = TICKET_TYPE_TO_SUMMARY_KEY.get(ticket_type, "Summary")  # type: ignore[arg-type]
    equal_filter_mapper = {
        status_key: args.get("status"),
        "Impact": args.get("impact"),
        "Urgency": args.get("urgency"),
        "Risk Level": args.get("risk_level"),
        "Priority": args.get("priority"),
        "Change Type": args.get("change_type"),
    }

    like_filter_mapper = {
        "Description": args.get("description"),
        summary: args.get("summary"),
        "First Name": args.get("first_name"),
        "Last Name": args.get("last_name"),
        "Company": args.get("company"),
        "Department": args.get("department"),
        "Organization": args.get("organization"),
        "Company Type": args.get("company_type"),
        "TaskName": args.get("task_name"),
        "Template Name": args.get("template_name"),
        "Support Organization": args.get("support_organization"),
        "Support Group Name": args.get("support_group"),
    }
    return {
        ID_QUERY_MAPPER_KEY: ids_filter_mapper,
        LIKE_QUERY_MAPPER_KEY: like_filter_mapper,
        EQUAL_QUERY_MAPPER_KEY: equal_filter_mapper,
    }


def generate_query_with_filtering(custom_query: str, filter_mapper: Dict[str, Any]) -> str:
    """
    Generates BMC search qualification query according to the user command arguments.
    It takes into consideration the custom query, the ids filter,
    the filters by '=' operator and the filters by 'LIKE' operator.

    Returns:
        str: BMC search qualification query.
    """
    sub_queries = []
    ids_filter: dict = remove_empty_elements(filter_mapper.get(ID_QUERY_MAPPER_KEY))
    equal_oper_filters: dict = remove_empty_elements(filter_mapper.get(EQUAL_QUERY_MAPPER_KEY))
    like_oper_filters: dict = remove_empty_elements(filter_mapper.get(LIKE_QUERY_MAPPER_KEY))
    records_id_name = next(iter(ids_filter), None)
    records_ids = ids_filter.get(records_id_name) or []

    ids_query = gen_single_filters_statement(records_id_name, records_ids, "=", " OR ")  # type: ignore[arg-type]

    equal_oper_filter_query = gen_multi_filters_statement(equal_oper_filters, "=", " AND ")

    like_oper_filter_query = gen_multi_filters_statement(like_oper_filters, "LIKE", " AND ")

    sub_queries = [
        custom_query,
        ids_query,
        equal_oper_filter_query,
        like_oper_filter_query,
    ]
    return " AND ".join(filter(None, sub_queries))


def fetch_incidents(
    client: Client,
    max_fetch: int,
    first_fetch: str,
    last_run: Dict[str, Any],
    ticket_type_filter: List[str],
    status_filter: List[str],
    impact_filter: List[str],
    urgency_filter: List[str],
    custom_query: str,
    mirror_direction: str,
) -> tuple:
    """
    Fetch BMC ITSM tickets as incidetns.

    Args:
        client (Client): BMC ITSM API client.
        max_fetch (int): Max number of tickets to fetch.
        first_fetch (str): From which time ro fetch.
        last_run (Dict[str, Any]): Last run info.
        ticket_type_filter (List[str]): The ticket types to fetch.
        status_filter (List[str]): The tickets with status values to fetch.
        impact_filter (List[str]): The tickets with impact values to fetch.
        urgency_filter (List[str]): The ticket with urgency values to fetch.
        custom_query (str): Custom query given by the user.

    Returns:
        tuple: Incidents and last run info.
    """

    first_fetch_epoch = (date_to_epoch_for_fetch(arg_to_datetime(first_fetch))
                         if not last_run else None)

    last_run = init_last_run(first_fetch_epoch) if first_fetch_epoch else last_run
    current_time = date_to_epoch_for_fetch(arg_to_datetime("now"))

    relevant_tickets, ticket_type_to_last_epoch = fetch_relevant_tickets(
        client,
        ticket_type_filter,
        max_fetch,
        last_run,
        current_time,
        status_filter,
        impact_filter,
        urgency_filter,
        custom_query,
    )

    incidents = []
    for incident in relevant_tickets:
        incident["mirror_direction"] = mirror_direction
        incident["mirror_instance"] = demisto.integrationInstance()
        incidents.append({
            "name": incident.get("Summary"),
            "occured": incident.get("CreateDate"),
            "rawJSON": json.dumps(incident),
        })
    if incidents:
        last_run = update_last_run(last_run, ticket_type_to_last_epoch)
    return incidents, last_run


def fetch_relevant_tickets(
    client: Client,
    ticket_types: List[str],
    max_fetch: int,
    last_run: dict,
    t_epoch_to: int,
    status_filter: List[str],
    impact_filter: List[str],
    urgency_filter: List[str],
    custom_query: str,
) -> tuple[list, dict]:
    """
    Fetch the relevant tickets according to the provided filter arguments.
    The Tickets are fetched Iteratively, by their ticket type until the capacity
    of the tickets (max_fetch) is fullfiled or no more tickets left to fetch.


    Args:
        client (Client): BMC ITSM API Client.
        ticket_types (List[str]): List of the tickets types to fetch.
        max_fetch (int): Maximum number of tickets to fetch.
        last_run (Dict[str,Any]): Contains last ticket create time per ticket type.
        t_epoch_to (int): Time epoch in seconds to fetch until.
        status_filter (List[str]): List of the ticket statuses to fetch.
        impact_filter (List[str]): List of the ticket impacts to fetch.
        urgency_filter (List[str]): List of the ticket uregencies to fetch.
        custom_query (str): User custom query.

    Returns:
        Tuple[list, dict]: Relevant fetched tickets and ticket_type_to_last_epoch mapping.
    """
    total_tickets = []
    ticket_type_to_last_epoch = {}
    tickets_capacity = max_fetch
    for ticket_type in ticket_types:
        fetched_tickets = fetch_relevant_tickets_by_ticket_type(
            client,
            ticket_type,
            max_fetch,
            last_run,
            t_epoch_to,
            status_filter,
            impact_filter,
            urgency_filter,
            custom_query,
        )

        tickets_amount = min(tickets_capacity, len(fetched_tickets))
        total_tickets += fetched_tickets[:tickets_amount]
        tickets_capacity -= tickets_amount

        if fetched_tickets:
            ticket_type_to_last_epoch[ticket_type] = max(
                [date_to_epoch_for_fetch(arg_to_datetime(ticket.get("CreateDate")))
                 for ticket in total_tickets])
        if tickets_capacity <= 0:  # no more tickets to retrieve in the current fetch
            break

    return total_tickets, ticket_type_to_last_epoch


def fetch_relevant_tickets_by_ticket_type(
    client: Client,
    ticket_type: str,
    max_fetch: int,
    last_run: dict,
    t_epoch_to: int,
    status_filter: List[str],
    impact_filter: List[str],
    urgency_filter: List[str],
    custom_query: str,
) -> List[dict]:
    """
    Fetches tickets of one type.

    Args:
        client (Client): BMC ITSM API Client.
        ticket_types (List[str]): List of the tickets types to fetch.
        max_fetch (int): Maximum number of tickets to fetch.
        last_run (Dict[str,Any]): Contains last ticket create time per ticket type.
        t_epoch_to (int): Time epoch in seconds to fetch until.
        status_filter (List[str]): List of the ticket statuses to fetch.
        impact_filter (List[str]): List of the ticket impacts to fetch.
        urgency_filter (List[str]): List of the ticket uregencies to fetch.
        custom_query (str): User custom query.
    Returns:
        List[dict]: Fetched tickets of the specified type.
    """

    ticket_form = TICKET_TYPE_TO_LIST_FORM[ticket_type]
    t_epoch_from = dict_safe_get(last_run, [ticket_type, "last_create_time"])
    fetch_query = gen_fetch_incidents_query(
        ticket_type,
        t_epoch_from,
        t_epoch_to,
        status_filter,
        impact_filter,
        urgency_filter,
        custom_query,
    )

    response = client.list_request(ticket_form, fetch_query)
    relevant_records, _ = get_paginated_records_with_hr(response.get("entries"), max_fetch)  # type: ignore[arg-type]
    outputs: List[dict] = format_command_output(  # type: ignore[assignment]
        deepcopy(relevant_records),
        generate_ticket_context_data_mapper(ticket_type),
        arrange_ticket_context_data,
    )
    return outputs


def update_last_run(last_run: Dict[str, Any], ticket_type_to_last_epoch: Dict[str, Any]):
    """
    Update last run object.

    Args:
        last_run (Dict[str, Any]): _description_
        formatted_incidents (List[dict]): _description_

    Returns:
        _type_: _description_
    """
    for ticket_type, last_epoch in ticket_type_to_last_epoch.items():
        last_run[ticket_type]["last_create_time"] = last_epoch
    return last_run


def all_keys_empty(dict_obj: Dict[str, Any]) -> bool:
    """
    Checks whether all of the the keys of the given dict object have a None value.

    Args:
        dict_obj (Dict[str, Any]): The dict object to check.

    Returns:
        bool: Wheter or not all keys have None value.
    """
    return all(not value for value in dict_obj.values())


def gen_multi_filters_statement(filter_mapper: Dict[str, Any], oper_in_filter: str,
                                oper_between_filters: str) -> str:
    """
    Generates statement for BMC search qualifcation query by multiple filters.
    Against each filter key and value the oper_in_filter will be made and between each of them
    an oper_between_filters will be made.

    Args:
        filter_mapper (Dict[str, Any]): Key,value pairs of filter name and value.
        oper_in_filter (str): Operation to do inside a filter.
        oper_between_filters (str): Operation to do between filters.

    Returns:
        str: statment for BMC search qualifcation.
    """

    stmt = oper_between_filters.join(
        f"'{filter_key}' {oper_in_filter} \"{wrap_filter_value(filter_val,oper_in_filter)}\""
        for filter_key, filter_val in (filter_mapper).items())
    return stmt


def gen_single_filters_statement(filter_key: str, values: list, oper_in_filter: str,
                                 oper_between_filters: str) -> str:
    """
    Generates statement for BMC search qualifcation query by single filter.
    Against one filter key and each value in values argument,  the oper_in_filter will be made and between each of them
    an oper_between_filters will be made.

    Args:
        filter_key (str): Filter by.
        values (str): Filter values values.
        oper_in_filter (str): Operation to do inside a filter.
        oper_between_filters (str): Operation to do between filters.

    Returns:
        str: statment for BMC search qualifcation.
    """

    stmt = oper_between_filters.join(f"'{filter_key}' {oper_in_filter} \"{resource_id}\""
                                     for resource_id in (values))
    return f'({stmt})' if stmt else ''


def wrap_filter_value(filter_value: str, operation: str) -> str:
    """
    Wraps value in BMC  statemnt according the specified operation.
    For example, for LIKE operation , the value should be wraped with %<value>%.

    Args:
        filter_value (str): filter_value
        operation (str): operation

    Returns:
        str: Wrapped value.
    """

    return f"%{filter_value}%" if operation == "LIKE" else filter_value


def gen_processed_query(*sub_queries) -> str:
    """
    Generates a query based on given statements to make an "AND" operation between them.

    Returns:
        str: Processed query.
    """
    return " AND ".join(sub_query for sub_query in sub_queries if sub_query)


def gen_fetch_incidents_query(
    ticket_type: str,
    t_epoch_from: int,
    t_epoch_to: int,
    status_filter: List[str],
    impact_filter: List[str],
    urgency_filter: List[str],
    custom_query: str,
) -> str:
    """
    Generates the query based on the user params and custom query in order to fetch tickets as incidents.

    Args:
        ticket_type (str): Ticket type to fethc.
        t_epoch_from (int): The start interval time to fetch the tickets by.
        t_epoch_to (int): The end interval time to fetch the tickets by.
        status_filter (List[str]): status filter to fetch tickets by.
        impact_filter (List[str]): impact filter to fetch tickets by.
        urgency_filter (List[str]): urgency filter to fetch tickets by.
        custom_query (str): User custom query.

    Returns:
        str: query to fetch a certain ticket type.
    """
    create_time_prop = "Create Date" if ticket_type == "task" else "Submit Date"
    time_filter = f"('{create_time_prop}' <= \"{t_epoch_to}\" AND '{create_time_prop}' >\"{t_epoch_from}\")"

    status_statement = gen_single_filters_statement(TICKET_TYPE_TO_STATUS_KEY[ticket_type],
                                                    status_filter, "=", " OR ")
    urgency_statement = gen_single_filters_statement("Urgency", urgency_filter, "=", " OR ")
    impact_statement = gen_single_filters_statement("Impact", impact_filter, "=", " OR ")
    return gen_processed_query(time_filter, custom_query, status_statement, urgency_statement,
                               impact_statement)


def validate_pagination_args(page: Optional[int], page_size: Optional[int], limit: Optional[int]):
    """
    Validates values of pagination arguments in list commands.

    Args:
        page (Optional[int]): Page number to validate.
        page_size (Optional[int]): Page size to validate.
        limit (Optional[int]): Limit for automatic pagination to validate.

    Raises:
        ValueError: In case where one of the provided pagination arguments is not valid.
    """
    validate_related_arguments_provided(page=page, page_size=page_size)
    for arg in filter(None, [page, page_size, limit]):
        if not isinstance(arg, int) or arg < 1:
            raise ValueError(
                "Please validate the pagination arguments. page, page_size and limit arguments must be integers greater than 0."
            )


def init_last_run(first_fetch_epoch: int) -> Dict[str, Any]:
    """
    Initialize the last run object when the first fetch
    is executed.

    Args:
        first_fetch_epoch (int): First fetch in seconds.

    Returns:
        Dict[str,Any]: Initialized last run object.
    """
    last_run = {}
    for ticket_type in ALL_TICKETS:
        last_run[ticket_type] = {
            "last_create_time": first_fetch_epoch,
            "last_tickets": [],
        }
    return last_run


def date_to_epoch_for_fetch(date: Optional[datetime]) -> int:
    """
    Converts datetime object to date in epoch timestamp (in seconds),
    for fetch command.

    Args:
        date (Optional[datetime]): The datetime to convert.

    Returns:
        int: date in epoch timestamp.
    """
    return date_to_timestamp(date) // 1000


def extract_ticket_request_id_following_create(client: Client, ticket_type: str,
                                               ticket_create_response: Dict[str, Any]) -> str:
    """
    Extract the ticket request ID for tickets in cases where the create request do not return
    The request ID which is important for accessing the ticket in other commands.

    Args:
        client (Client): BMC iTSM client.
        ticket_type (str): The ticket type to extract the request ID from.
        ticket_create_response (Dict[str, Any]): The BMC ITSM API response upon create request.

    Returns:
        str: Ticket request ID.
    """
    form_name = TICKET_TYPE_TO_LIST_FORM[ticket_type]
    display_id_prop_name = TICKET_TYPE_TO_DISPLAY_ID[ticket_type]
    display_id = dict_safe_get(ticket_create_response, ["values", display_id_prop_name])
    response = client.list_request(form_name, f"'{display_id_prop_name}' = \"{display_id}\"")

    request_id = dict_safe_get(response["entries"][0], ["values", "Request ID"])
    return extract_ticket_request_id(request_id)


def format_create_ticket_outputs(outputs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Formats the response of the create command.

    Args:
        outputs (Dict[str, Any]): Response from ticket create request.

    Returns:
        Dict[str, Any]: Output for ticket create command.
    """
    formatted_outputs = {}
    for k, v in outputs.items():
        if k in CREATE_CONTEXT_MAPPER:
            formatted_outputs[CREATE_CONTEXT_MAPPER[k]] = v
    formatted_outputs["CreateDate"] = FormatIso8601(arg_to_datetime(
        formatted_outputs["CreateDate"]))
    return formatted_outputs


def get_ticket(client: Client,
               ticket_type: str,
               root_request_id: str,
               query: str = None) -> Dict[str, Any]:
    """
    Get ticket by request ID. Useful whem we want to use get ticket command for other commands.

    Args:
        client (Client): BMC ITSM API client.
        ticket_type (str): The ticket type to get.
        root_request_id (str): The ticket reuqest ID to get by.

    Raises:
        ValueError: In case the requested ticket do not exist.

    Returns:
        Dict[str, Any]: Get ticket command output ( ticket data).
    """
    command_results: CommandResults = ticket_list_command(client, {
        "ticket_type": ticket_type,
        "ticket_ids": root_request_id,
        "limit": 1
    })
    outputs = command_results.outputs
    if not outputs:
        raise ValueError(
            f"The ticket type: {ticket_type} with request ID: {root_request_id} does not exist.")
    return next(iter(outputs))  # type: ignore[call-overload]


def get_remote_data_command(client: Client, args: Dict[str, Any],
                            close_incident: str) -> GetRemoteDataResponse:
    """
    Gets new information about the incidents in the remote system
    and updates existing incidents in Cortex XSOAR.
    Args:
        client: BMC ITSM API client.
        args (Dict[str, Any]): command arguments.
    Returns:
        List[Dict[str, Any]]: first entry is the incident (which can be completely empty) and the new entries.
    """
    parsed_args = GetRemoteDataArgs(args)
    entries = []
    ticket_id = parsed_args.remote_incident_id
    last_update = date_to_epoch_for_fetch(arg_to_datetime(parsed_args.last_update))
    ticket_type = get_ticket_type_by_request_id(ticket_id)
    mirrored_ticket = get_ticket(client, ticket_type, ticket_id)
    ticket_last_update = date_to_epoch_for_fetch(
        arg_to_datetime(mirrored_ticket.get("LastModifiedDate")))
    if last_update > ticket_last_update:
        mirrored_ticket = {}
    if mirrored_ticket.get("Status") == "Closed" and close_incident:
        entries.append({
            "Type": EntryType.NOTE,
            "Contents": {
                "dbotIncidentClose": True,
                "closeReason": "Closed from BMC Helix ITSM.",
            },
            "ContentsFormat": EntryFormat.JSON,
        })

    return GetRemoteDataResponse(mirrored_ticket, entries)


def get_modified_remote_data(client: Client, args: Dict[str, Any]) -> GetModifiedRemoteDataResponse:
    """
    Queries for incidents that were modified since the last update.

    Args:
        client: BMC ITSM API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        GetModifiedRemoteDataResponse: modified tickets from BMC HELIX ITSM.
    """
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update = remote_args.last_update
    last_update_utc = date_to_epoch_for_fetch(
        arg_to_datetime(last_update))  # converts to a UTC timestamp

    modified_tickets = []  # type: ignore[var-annotated]
    modified_ticket_ids = []

    for ticket_type in ALL_TICKETS:
        time_filter_name = ("Modified Date" if ticket_type == TASK else "Last Modified Date")
        modified_tickets_by_type = ticket_list_command(
            client,
            {
                "ticket_type": ticket_type,
                "query": f"'{time_filter_name}' >= \"{last_update_utc}\"",
                "limit": 100,
            },
        ).outputs
        if modified_tickets_by_type:
            modified_tickets += modified_tickets_by_type  # type: ignore[arg-type]

    for raw_ticket in modified_tickets:
        ticket_id = raw_ticket.get("RequestID")
        modified_ticket_ids.append(ticket_id)

    return GetModifiedRemoteDataResponse(modified_ticket_ids)


def update_remote_system(client: Client, args: Dict[str, Any], close_ticket: str) -> str:
    """
    This command pushes local changes to the remote system.
    Args:
        client:  XSOAR Client to use.
        args:
            args['data']: the data to send to the remote system.
            args['entries']: the entries to send to the remote system.
            args['incident_changed']: boolean telling us if the local incident indeed changed or not.
            args['remote_incident_id']: the remote incident id.
    Returns: The remote incident id - ticket_id
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    ticket_id = parsed_args.remote_incident_id
    ticket_type = get_ticket_type_by_request_id(ticket_id)

    if parsed_args.delta:
        demisto.debug(f"Got the following delta keys {str(list(parsed_args.delta.keys()))}")

    else:
        demisto.debug("There is no delta fields in BMC Helix ITSM")

    try:
        demisto.debug(
            f"Sending incident with remote ID [{parsed_args.remote_incident_id}] to remote system\n"
        )

        if parsed_args.incident_changed:
            demisto.debug(f"Incident changed: {parsed_args.incident_changed}")

            update_args = fit_update_args(parsed_args.delta, parsed_args.data, ticket_id)
            if parsed_args.inc_status == IncidentStatus.DONE and close_ticket:

                handle_close_remote_ticket(ticket_type, update_args,
                                           parsed_args.delta.get("CloseReason"))

            demisto.debug(f"Sending incident with remote ID [{ticket_id}] to BMC Helix ITSM\n")
            update_remote_ticket(client, ticket_type, update_args)

        demisto.info(f"remote data of {ticket_id}: {parsed_args.data}")
    except Exception as error:
        demisto.info(f"Error in BMC Helix ITSM outgoing mirror for incident {ticket_id} \n"
                     f"Error message: {str(error)}")

    finally:
        return ticket_id


def fit_update_args(delta: dict, data: dict, ticket_id: str) -> dict:
    """
    Change the updated field names to fit the ticket update command.
    Args:
        delta (dict): Updated fields from XSOAR incident mirroring.
        data (dict): Incident source fields from XSOAR incident mirroring.
        ticket_id (str): The ticket ID of the incident to mirror.
    Returns:
        dict: Updated argument information.
    """
    arguments = {
        "summary": delta.get("Summary"),
        "details": delta.get("Details"),
        "impact": delta.get("Impact"),
        "urgency": delta.get("Urgency"),
        "status_reason": delta.get("StatusReason"),
        "status": delta.get("Status"),
        "priority": delta.get("Priority"),
        "risk_level": delta.get("RiskLevel"),
        "ticket_request_id": ticket_id,
    }
    return arguments


def handle_close_remote_ticket(ticket_type: str, update_args: Dict[str, Any], close_reason: str):
    """
    Modifies the required fields for the update command (when closing an incident)
    according to the remote ticket type.

    Args:
        ticket_type (str): The type of the remote ticket tp update.
        update_args (Dict[str, Any]): The update args to modify.
    """
    update_args["status"] = "Closed"
    update_args["status_reason"] = close_reason
    if ticket_type == INCIDENT:
        update_args["resolution"] = close_reason


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    """
    Pulls the remote schema for the different incident types, and their associated incident fields, from the remote system.

    Returns:
    GetMappingFieldsResponse: Dictionary with keys as field names.
    """

    mapping_response = GetMappingFieldsResponse()
    for ticket_type, incident_type in TICKET_TYPE_TO_INCIDENT_TYPE.items():
        incident_type_scheme = SchemeTypeMapping(type_name=incident_type)
        outgoing_fields = MIRRORING_COMMON_FIELDS + \
            TICKET_TYPE_TO_ADDITIONAL_MIRRORING_FIELDS[ticket_type]  # type: ignore[union-attr,operator]
        for field in outgoing_fields:
            incident_type_scheme.add_field(field)

        mapping_response.add_scheme_type(incident_type_scheme)

    return mapping_response


def update_remote_ticket(client: Client, ticket_type: str, args: Dict[str, Any]):
    """
    Updates the remote ticket in outgoing mirroring phase according to the
    the specified fields of args.

    Args:
        client (Client): BMC ITSM API client.
        ticket_type (str): The type of the rmeote ticket to update.
        args (Dict[str, Any]): The relevant args for the update commands.
    """
    ticket_type_to_update_command = {
        SERVICE_REQUEST: service_request_update_command,
        CHANGE_REQUEST: change_request_update_command,
        INCIDENT: incident_update_command,
        PROBLEM_INVESTIGATION: problem_investigation_update_command,
        KNOWN_ERROR: known_error_update_command,
        TASK: task_update_command,
    }

    ticket_type_to_update_command[ticket_type](client, args)


def test_module(client: Client) -> None:
    """
    Validates the correctness of the instance parameter and connectivity to
    BMC ITSM API service.

    Args:
        client (Client): BMC ITSM API client.
    """
    client.list_request('COM:Company')
    return_results("ok")


def main() -> None:
    """
    Main function
    """
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params["url"]
    verify_certificate: bool = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    credentials = params.get("credentials")
    username = credentials.get("identifier")  # type: ignore[union-attr]
    password = credentials.get("password")  # type: ignore[union-attr]

    max_fetch = arg_to_number(params.get("max_fetch", DEFAULT_MAX_FETCH))
    first_fetch = params.get("first_fetch")
    ticket_types = argToList(params.get("ticket_type"))
    ticket_statuses = argToList(params.get("ticket_status"))
    ticket_impacts = argToList(params.get("ticket_impact"))
    ticket_urgencies = argToList(params.get("ticket_urgency"))
    ticket_custom_query = params.get("query")
    mirror_direction = MIRROR_DIRECTION_MAPPING[params.get("mirror_direction")]  # type: ignore[index]
    close_incident = params.get("close_incident")
    close_ticket = params.get("close_ticket")

    ticket_type_filter = ALL_TICKETS if ALL_OPTION in ticket_types else ticket_types
    ticket_status_filter = [] if ALL_OPTION in ticket_statuses else ticket_statuses
    ticket_impact_filter = [] if ALL_OPTION in ticket_impacts else ticket_impacts
    ticket_urgency_filter = [] if ALL_OPTION in ticket_urgencies else ticket_urgencies
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        client: Client = Client(url, username, password, verify=verify_certificate, proxy=proxy)  # type: ignore[arg-type]

        commands = {
            "bmc-itsm-ticket-list": ticket_list_command,
            "bmc-itsm-ticket-delete": ticket_delete_command,
            "bmc-itsm-user-list": user_list_command,
            "bmc-itsm-company-list": company_list_command,
            "bmc-itsm-service-request-create": service_request_create_command,
            "bmc-itsm-service-request-definition-list": service_request_definition_list_command,
            "bmc-itsm-service-request-update": service_request_update_command,
            "bmc-itsm-change-request-template-list": change_request_template_list_command,
            "bmc-itsm-change-request-create": change_request_create_command,
            "bmc-itsm-change-request-update": change_request_update_command,
            "bmc-itsm-incident-template-list": incident_template_list_command,
            "bmc-itsm-incident-create": incident_create_command,
            "bmc-itsm-incident-update": incident_update_command,
            "bmc-itsm-task-template-list": task_template_list_command,
            "bmc-itsm-task-create": task_create_command,
            "bmc-itsm-task-update": task_update_command,
            "bmc-itsm-problem-investigation-create": problem_investigation_create_command,
            "bmc-itsm-problem-investigation-update": problem_investigation_update_command,
            "bmc-itsm-known-error-create": known_error_create_command,
            "bmc-itsm-known-error-update": known_error_update_command,
            "bmc-itsm-support-group-list": support_group_list_command,
            "bmc-itsm-work-order-template-list": work_order_template_list_command,
            "bmc-itsm-work-order-create": work_order_create_command,
            "bmc-itsm-work-order-update": work_order_update_command,
        }

        if command == "test-module":
            test_module(client)
        elif command == "fetch-incidents":
            incidents, last_run = fetch_incidents(
                client,
                max_fetch,  # type: ignore[arg-type]
                first_fetch,  # type: ignore[arg-type]
                demisto.getLastRun(),
                ticket_type_filter,
                ticket_status_filter,
                ticket_impact_filter,
                ticket_urgency_filter,
                ticket_custom_query,  # type: ignore[arg-type]
                mirror_direction,  # type: ignore[arg-type]
            )

            demisto.setLastRun(last_run)
            demisto.incidents(incidents)
        elif command == "get-remote-data":
            return_results(get_remote_data_command(client, args, close_incident))  # type: ignore[arg-type]
        elif command == "get-modified-remote-data":
            return_results(get_modified_remote_data(client, args))
        elif command == "update-remote-system":
            return_results(update_remote_system(client, args, close_ticket))  # type: ignore[arg-type]
        elif command == "get-mapping-fields":
            return_results(get_mapping_fields_command())
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as error:
        error_msg = str(error)
        if "Internal Server Error" in error_msg:
            return_error(
                f"Please validate the provided values in the command arguments.\n{error_msg}")
        if "Not Found" in error_msg:
            return_error(f"The requested resource does not exist.\n{error_msg}")
        else:
            return_error(error_msg)


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
