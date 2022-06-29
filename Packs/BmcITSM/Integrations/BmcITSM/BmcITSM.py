from copy import deepcopy
from typing import Callable, Tuple

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import datetime

SERVICE_REQUEST = 'service request'
CHANGE_REQUEST = 'change request'
INCIDENT = 'incident'
TASK = 'task'
PROBLEM_INVESTIGATION = 'problem investigation'
KNOWN_ERROR = 'known error'
SERVICE_REQUEST_CONTEXT_MAPPER = {
    'Request ID': 'RequestID',
    'Request Number': 'DisplayID',
    'Submit Date': 'CreateDate',
    'Next Target Date': 'TargetDate',
    'Status': 'Status',
    'Summary': 'Summary',
    'Last Modified Date': 'LastModifiedDate',
    'Request Type': 'SubType',
}
CHANGE_REQUEST_CONTEXT_MAPPER = {
    'Request ID': 'RequestID',
    'Infrastructure Change ID': 'DisplayID',
    'Submit Date': 'CreateDate',
    'Next Target Date': 'TargetDate',
    'Change Request Status': 'Status',
    'Description': 'Summary',
    'Risk Level': 'RiskLevel',
    'Reason For Change': 'ReasonForChange',
    'Last Modified Date': 'LastModifiedDate',
    'Assigned To': 'Assignee',
    'Detailed Description': 'Details',
    'Change Type': 'SubType',
}
INCIDENT_CONTEXT_MAPPER = {
    'Request ID': 'RequestID',
    'Incident Number': 'DisplayID',
    'Submit Date': 'CreateDate',
    'Status': 'Status',
    'Description': 'Summary',
    'Contact Sensitivity': 'ContactSensitivity',
    'Last Modified Date': 'LastModifiedDate',
    'Detailed Decription': 'Details',  #The product has typo in the response
    'Contact Sensitivity': 'ContactSensitivity',
    'VIP': 'VIP',
    'Service Type': 'SubType',
    'Reported Source': 'ReportedSource'
}

TASK_CONTEXT_MAPPER = {
    'Task Interface ID': 'RequestID',
    'Task ID': 'DisplayID',
    "Create Date": 'CreateDate',
    "Modified Date": 'LastModifiedDate',
    'Status': 'Status',
    'Notes': 'Details',
    'TaskType': 'SubType',
    'Summary': 'Summary',
    "Scheduled Start Date": "ScheduledStartDate",
    "Scheduled End Date": "ScheduledEndDate"
}

PROBLEM_INVESTIGATION_CONTEXT_MAPPER = {
    'Request ID': 'RequestID',
    'Problem Investigation ID': 'DisplayID',
    'Submit Date': 'CreateDate',
    'Investigation Status': 'Status',
    "Invesitgation Status Reason": "StatusReason",
    'Description': 'Summary',
    'Last Modified Date': 'LastModifiedDate',
    'Target Resolution Date': 'TargetResolutionDate',
    'Detailed Decription': 'Details',  #The product has typo in the response
    "Investigation Justification": "InvestigationJustification",
    "Investigation Driver": "Investigation Driver",
    "Temporary Workaround": "TemporaryWorkaround"
}

KNOWN_ERROR_CONTEXT_MAPPER = {
    'Request ID': 'RequestID',
    'Known Error ID': 'DisplayID',
    'Submit Date': 'CreateDate',
    'Known Error Status': 'Status',
    'Description': 'Summary',
    'Last Modified Date': 'LastModifiedDate',
    'Target Resolution Date': 'TargetResolutionDate',
    'Detailed Decription': 'Details',  #The product has typo in the response
    "Investigation Justification": "InvestigationJustification",
    "Investigation Driver": "InvestigationDriver",
    "Temporary Workaround": "TemporaryWorkaround",
    "View Access": "ViewAccess"
}
COMMON_PROPERTIES = [
    'Submitter',
    'Urgency',
    'Impact',
    'InstanceId',
    'Customer First Name',
    'Customer Last Name',
    'Customer Company',
    'Customer Organization',
    'Customer Department',
    'Customer Internet E-mail',
    'Customer Phone Number',
    'First Name',
    'Last Name',
    'Company',
    'Region',
    'Site',
    'Site Group',
    'Assignee',
    'Assignee Group',
    'Assigned Group',
    'Assigned Support Organization',
    'Assigned Support Company',
    'Request Type',
    'Priority',
    'Resolution',
    'Status-History',
]

TICKET_TYPE_TO_LIST_FORM = {
    'service request': 'SRM:RequestInterface',
    'change request': 'CHG:ChangeInterface',
    'incident': 'HPD:IncidentInterface',
    'task': 'TMS:Task',
    'problem investigation': 'PBM:ProblemInterface',
    'known error': 'PBM:KnownErrorInterface',
}

TICKET_TYPE_TO_DELETE_FORM = {
    'change request': 'CHG:Infrastructure Change',
    'incident': 'HPD:Help Desk',
    'task': 'TMS:Task',
    'problem investigation': 'PBM:Problem Investigation',
    'known error': 'PBM:Known Error',
}

TICKET_TYPE_TO_STATUS_FIELD = {
    CHANGE_REQUEST: "Change Request Status",
    SERVICE_REQUEST: 'Status',
    INCIDENT: "Status",
    PROBLEM_INVESTIGATION: 'Investigation Status',
    KNOWN_ERROR: 'Known Error Status',
    TASK: "Status"
}

TICKET_TYPE_TO_CONTEXT_MAPPER = {
    'service request': SERVICE_REQUEST_CONTEXT_MAPPER,
    'change request': CHANGE_REQUEST_CONTEXT_MAPPER,
    'incident': INCIDENT_CONTEXT_MAPPER,
    'task': TASK_CONTEXT_MAPPER,
    'problem investigation': PROBLEM_INVESTIGATION_CONTEXT_MAPPER,
    'known error': KNOWN_ERROR_CONTEXT_MAPPER,
}

TICKET_TYPE_TO_STATUS_KEY = {
    'service request': 'Status',
    'change request': 'Change Request Status',
    'incident': 'Status',
    'task': 'Status',
    'problem investigation': 'Investigation Status',
    'known error': 'Known Error Status',
}

FIELD_DELIMITER = ';'
VALUE_DELIMITER = '='
VALIDATE_JSON = r'(\w+=[^;=]+;( )?)*\w+=[^;=]+'
REQUEST_NUM_PREFIX_TO_TICKET_TYPE = {
    'REQ': 'service request',
    'CRQ': 'change request',
    'INC': 'incident',
    'TAS': 'task',
    'PBI': 'problem investigation',
    'PKE': 'known error',
}

CREATE_CONTEXT_MAPPER = {
    'SysRequestID': 'RequestID',
    'Request ID': 'RequestID',
    'Change_Entry_ID': 'RequestID',
    'Infrastructure Change Id': 'DisplayID',
    'Request Number': 'DisplayID',
    'Incident Number': 'DisplayID',
    'Problem Investigation ID': 'DisplayID',
    "Known Error ID": 'DisplayID',
    'Submit Date': 'CreateDate',
    'Create Date': 'CreateDate',
    "Task ID": 'DisplayID'
}

TICKET_TYPE_TO_DISPLAY_ID = {
    INCIDENT: 'Incident Number',
    PROBLEM_INVESTIGATION: 'Problem Investigation ID',
    KNOWN_ERROR: 'Known Error ID'
}
ID_QUERY_MAPPER_KEY = 'IDS'
EQUAL_QUERY_MAPPER_KEY = 'EQUAL'
LIKE_QUERY_MAPPER_KEY = 'LIKE'
DEFAULT_FETCH = 50
DEFAULT_LIMIT = 50
ALL_OPTION = 'All'
TOKEN_EXPIRE_TIME = 3600
TICKET_PREFIX_LEN = 3
COMMON_TICKET_CONTEXT_FIELDS = {prop_name: prop_name for prop_name in COMMON_PROPERTIES}
ALL_TICKETS = [
    'service request', 'change request', 'incident', 'task', 'problem investigation', 'known error'
]


class Client(BaseClient):
    """
    BmcITSM API Client
    """
    def __init__(self, server_url, username, password, verify, proxy):
        """initializing a client instance with authentication header"""
        super().__init__(base_url=f'{server_url}/api', verify=verify, proxy=proxy)
        jwt_token = self.retrieve_access_token(username, password)
        self._headers = {}
        self._headers['Authorization'] = f'AR-JWT {jwt_token}'
        # print(username, jwt_token)

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
        if integration_context.get('token') and integration_context.get('expires_in'):
            if now < integration_context['expires_in']:
                return integration_context['token']

        try:
            token = self._http_request('POST',
                                       f'jwt/login',
                                       data={
                                           'username': username,
                                           'password': password
                                       },
                                       resp_type='text')

            integration_context = {
                'token': token,
                'expires_in': now + 3600
            }  # token expires in an hour

            set_integration_context(integration_context)
            return token
        except DemistoException as exception:
            raise ValueError(
                f'Authentication failed. Please Check the server url or validate your crdentials. {str(exception)}'
            )

    def list_request(self, form: str, query: str = None) -> Dict[str, Any]:
        """
        List BmcITSM resources request.

        Args:
            form (str): The resource name to list. 
            query (str): Query qualification.

        Returns:
            Dict[str, Any]: API respnse from BmcITSM. 
        """
        try:
            params = remove_empty_elements({'q': query})
            response = self._http_request('GET', f'arsys/v1/entry/{form}', params=params)
            return response
        except Exception as e:
            return_error(f"{query}. {str(e)}")

    def ticket_delete_request(self, ticket_form: str, ticket_id: str) -> Dict[str, Any]:
        """
        BmcITSM ticket delete request.

        Args:
            ticket_type (str): The ticket type to delete.
            ticket_id (str): The ID of the ticket to delete.

        Returns:
            Dict[str, Any]: API respnse from BmcITSM. 
        """

        response = self._http_request('DELETE',
                                      f'arsys/v1/entry/{ticket_form}/{ticket_id}',
                                      resp_type='text')
        return response

    def create_service_request_request(self, srd_instance_id: str, summary: str, urgency: str,
                                       impact: str, first_name: str, last_name: str, login_id: str,
                                       status: str, **additional_fields):
        """
        Service request create request. 

        Args:
            srd_instance_id (str): The ID of the service request definition.
            offering_title (str): Service request title.
            short_description (str): Service request description. 
            status (str): The ticket status.
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
        """

        properties = remove_empty_elements({
            'z1D Action': 'CREATE',
            'Source Keyword': 'blank',
            'First Name': first_name,
            'Last Name': last_name,
            'Login ID': login_id,
            'TitleInstanceID': srd_instance_id,
            'AppRequestSummary': summary,
            'Urgency': urgency,
            'Impact': impact,
            'Status': status,
            **additional_fields
        })
        data = {'values': properties}

        params = {'fields': 'values(SysRequestID,Request Number,Submit Date)'}
        response = self._http_request(
            'POST',
            'arsys/v1/entry/SRM:RequestInterface_Create',
            json_data=data,
            params=params,
        )

        return response

    def service_request_update_request(self, service_request_id: str, summary, status: str,
                                       urgency: str, impact: str, customer_first_name: str,
                                       customer_last_name: str, location_company, site_group: str,
                                       region: str, site: str, assignee: str, status_reason: str,
                                       **additional_fields) -> None:
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
        """

        properties = remove_empty_elements({
            'Customer First Name': customer_first_name,
            'Customer Last Name': customer_last_name,
            'Impact': impact,
            'Location Company': location_company,
            'Region': region,
            'Site': site,
            'Site Group': site_group,
            'Status': status,
            'Urgency': urgency,
            'Summary': summary,
            'Assignee': assignee,
            'Status_Reason': status_reason,
            **additional_fields
        })
        data = {'values': properties}

        self._http_request('PUT',
                           f'arsys/v1/entry/SRM:RequestInterface/{service_request_id}',
                           json_data=data,
                           resp_type='text')

    def create_incident_request(self, template_instance_id: str, first_name: str, last_name: str,
                                summary: str, status: str, urgency: str, impact: str,
                                service_type: str, reported_source: str, details: str, company: str,
                                assigned_support_organization: str, assigned_support_company: str,
                                assigned_support_group_name: str, assignee: str,
                                assignee_login_id: str, site_group: str, site: str, region: str,
                                **additional_fields):
        """_summary_

        Args:
            template_instance_id (str): _description_
            first_name (str): _description_
            last_name (str): _description_
            summary (str): _description_
            location_company (str): _description_
            status (str): _description_
            urgency (str): _description_
            impact (str): _description_
            priority (str): _description_
            risk_level (str): _description_
            change_type (str): _description_
            customer_first_name (str): _description_
            customer_last_name (str): _description_

        Returns:
            _type_: _description_
        """
        properties = remove_empty_elements({
            'First_Name': first_name,
            'Last_Name': last_name,
            'TemplateID': template_instance_id,
            'Description': summary,
            'Detailed_Decription': details,
            'Company': company,
            'Urgency': urgency,
            'Impact': impact,
            'Status': status,
            'Reported Source': reported_source,
            'Service_Type': service_type,
            "Assigned Support Organization": assigned_support_organization,
            "Assigned Group": assigned_support_group_name,
            "Assignee": assignee,
            "Assignee Login ID": assignee_login_id,
            "Assigned Support Company": assigned_support_company,
            "Site": site,
            "Site Group": site_group,
            "Region": region,
            "Site": site,
            **additional_fields
        })
        data = {'values': properties}
        params = {'fields': 'values(Incident_Entry_ID,Incident Number,Create Date)'}

        response = self._http_request(
            'POST',
            'arsys/v1/entry/HPD:IncidentInterface_Create',
            params=params,
            json_data=data,
        )

        return response

    def update_incident_request(self, request_id: str, first_name: str, last_name: str,
                                summary: str, status: str, urgency: str, impact: str,
                                service_type: str, reported_source: str, details: str, company: str,
                                assigned_support_organization: str, assigned_support_company: str,
                                assigned_support_group_name: str, assignee: str,
                                assignee_login_id: str, site_group: str, site: str, region: str,
                                status_reason: str, resolution: str, **additional_fields):
        """_summary_

        Args:
            template_instance_id (str): _description_
            first_name (str): _description_
            last_name (str): _description_
            summary (str): _description_
            location_company (str): _description_
            status (str): _description_
            urgency (str): _description_
            impact (str): _description_
            priority (str): _description_
            risk_level (str): _description_
            change_type (str): _description_
            customer_first_name (str): _description_
            customer_last_name (str): _description_

        Returns:
            _type_: _description_
        """
        properties = remove_empty_elements({
            'First_Name': first_name,
            'Last_Name': last_name,
            'Description': summary,
            'Detailed_Decription': details,
            'Company': company,
            'Urgency': urgency,
            'Impact': impact,
            'Status': status,
            'Reported Source': reported_source,
            'Service_Type': service_type,
            "Assigned Support Organization": assigned_support_organization,
            "Assigned Group": assigned_support_group_name,
            "Assignee": assignee,
            "Assignee Login ID": assignee_login_id,
            "Assigned Support Company": assigned_support_company,
            "Site": site,
            "Site Group": site_group,
            "Region": region,
            "Site": site,
            "Status_Reason": status_reason,
            "Resolution": resolution,
            **additional_fields
        })
        data = {'values': properties}

        response = self._http_request('PUT',
                                      f'arsys/v1/entry/HPD:IncidentInterface/{request_id}',
                                      json_data=data,
                                      resp_type='text')

        return response

    def change_request_create_request(self, template_instance_id: str, first_name: str,
                                      last_name: str, summary: str, location_company: str,
                                      status: str, urgency: str, impact: str, priority: str,
                                      risk_level: str, change_type: str, customer_first_name: str,
                                      customer_last_name: str, **additional_fields):
        """_summary_

        Args:
            template_instance_id (str): _description_
            first_name (str): _description_
            last_name (str): _description_
            summary (str): _description_
            location_company (str): _description_
            status (str): _description_
            urgency (str): _description_
            impact (str): _description_
            priority (str): _description_
            risk_level (str): _description_
            change_type (str): _description_
            customer_first_name (str): _description_
            customer_last_name (str): _description_

        Returns:
            _type_: _description_
        """
        properties = remove_empty_elements({
            'First Name': first_name,
            'Last Name': last_name,
            'Customer First Name': customer_first_name,
            'Customer Last Name': customer_last_name,
            'TemplateID': template_instance_id,
            'Description': summary,
            'Location Company': location_company,
            'Urgency': urgency,
            'Impact': impact,
            'Status': status,
            'Change Type': change_type,
            'Risk Level': risk_level,
            'Priority': priority,
            **additional_fields
        })
        data = {'values': properties}
        params = {'fields': 'values(Change_Entry_ID,Infrastructure Change Id,Create Date)'}

        response = self._http_request('POST',
                                      'arsys/v1/entry/CHG:ChangeInterface_Create',
                                      json_data=data,
                                      params=params)
        return response

    def change_request_update_request(self, change_request_id: str, first_name: str, last_name: str,
                                      summary: str, location_company: str, status: str,
                                      urgency: str, impact: str, priority: str, risk_level: str,
                                      change_type: str, customer_first_name: str,
                                      customer_last_name: str, details: str, status_reason: str,
                                      organization: str, department: str, site_group: str,
                                      site: str, support_organization: str, support_group_name: str,
                                      region: str, company: str, **additional_fields):
        """

        Args:
            change_request_id (str): _description_
            first_name (str): _description_
            last_name (str): _description_
            summary (str): _description_
            location_company (str): _description_
            status (str): _description_
            urgency (str): _description_
            impact (str): _description_
            priority (str): _description_
            risk_level (str): _description_
            change_type (str): _description_
            customer_first_name (str): _description_
            customer_last_name (str): _description_

        Returns:
            _type_: _description_
        """
        properties = remove_empty_elements({
            'First Name': first_name,
            'Last Name': last_name,
            'Customer First Name': customer_first_name,
            'Customer Last Name': customer_last_name,
            'Description': summary,
            'Location Company': location_company,
            'Urgency': urgency,
            'Impact': impact,
            'Change Request Status': status,
            'Change Type': change_type,
            'Risk Level': risk_level,
            'Priority': priority,
            'Detailed Description': details,
            'Status Reason': status_reason,
            'Department': department,
            'Site Group': site_group,
            'Region': region,
            'Site': site,
            'Organization': organization,
            'Support Organization': support_organization,
            'Support Group Name': support_group_name,
            'Company': company,
            **additional_fields
        })
        data = {'values': properties}

        response = self._http_request('PUT',
                                      f'arsys/v1/entry/CHG:ChangeInterface/{change_request_id}',
                                      json_data=data,
                                      resp_type='text')
        return response

    def create_task_request(self, template_instance_id: str, root_request_instance_id: str,
                            root_request_name: str, root_request_id: str, first_name: str,
                            last_name: str, summary: str, details: str, status: str, priority: str,
                            task_type: str, support_company: str, location_company: str,
                            assignee: str, root_request_mode: str, root_ticket_type: str,
                            assigned_support_organization: str, assigned_support_group_name: str,
                            impact: str, urgency: str, scedulded_start_date: str,
                            scedulded_end_date: str, **additional_fields):

        properties = remove_empty_elements({
            'TemplateID': template_instance_id,
            "RootRequestInstanceID": root_request_instance_id,
            "RootRequestID": root_request_id,
            'First Name': first_name,
            'Last Name': last_name,
            "Summary": summary,
            'TaskName': summary,
            "Notes": details,
            'Location Company': location_company,
            'Status': status,
            'TaskType': task_type,
            "RootRequestName": root_request_name,
            "RootRequestMode": root_request_mode,
            'Support Company': support_company,
            "RootRequestFormName": root_ticket_type,
            "Assignee Group": assigned_support_group_name,
            "Assignee Organization": assigned_support_organization,
            "Support Company": support_company,
            "Impact": impact,
            "Urgency": urgency,
            "State": "Active",
            "Parent Linked": "Active",
            "Customer Company": "Calbro Services",
            "Assigned To": assignee,
            "Scheduled Start Date": scedulded_start_date,
            "Scheduled End Date": scedulded_end_date,
            **additional_fields
        })
        data = {"values": properties}
        params = {'fields': 'values(Task ID,Create Date)'}
        response = self._http_request('POST',
                                      'arsys/v1/entry/TMS:Task',
                                      json_data=data,
                                      params=params)
        return response

    fileResult

    def update_task_request(self, task_id: str, root_request_name: str, summary: str, details: str,
                            status: str, status_reason: str, priority: str, task_type: str,
                            company: str, assignee: str, assigned_support_organization: str,
                            assigned_support_company: str, assigned_support_group_name: str,
                            location_company: str, scedulded_start_date: str,
                            schedulded_end_date: str, **additional_fields):
        properties = remove_empty_elements({
            "Summary": summary,
            'Notes': details,
            'Location Company': location_company,
            'Status': status,
            'StatusReasonSelection': status_reason,
            'TaskType': task_type,
            'Priority': priority,
            "RootRequestName": root_request_name,
            "Assignee Company": assigned_support_company,
            "Assignee Organization": assigned_support_organization,
            "Assignee Group": assigned_support_group_name,
            'Company': company,
            "Assigned To": assignee,
            "Assignee": assignee,
            "Scheduled Start Date": scedulded_start_date,
            "Scheduled End Date": schedulded_end_date,
            **additional_fields
        })
        data = {'values': properties}
        response = self._http_request('PUT',
                                      f'arsys/v1/entry/TMS:TaskInterface/{task_id}',
                                      json_data=data,
                                      resp_type='text')

        return response

    def create_problem_investigation_request(self,
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
                                             **additional_fields):
        """_summary_

        Args:
            problem_type (str): _description_
            first_name (str): _description_
            last_name (str): _description_
            summary (str): _description_
            status (str): _description_
            urgency (str): _description_
            impact (str): _description_
            details (str): _description_
            company (str): _description_
            assigned_support_organization (str): _description_
            assigned_support_company (str): _description_
            assigned_support_group_name (str): _description_
            assignee (str): _description_
            assignee_login_id (str): _description_
            site_group (str): _description_
            site (str): _description_
            region (str): _description_
            assigned_group_pbm_mgr (str): _description_
            support_company_pbm_mgr (str): _description_
            support_organization_pbm_mgr (str): _description_
            temporary_workaround (str): _description_
            resolution (str): _description_
            target_resolution_date (str): _description_
            investigation_justification (str): _description_
            investigation_driver (str): _description_
            view_access (str): _description_

        Returns:
            _type_: _description_
        """
        properties = remove_empty_elements({
            "z1D_Action":
            "PROBLEM" if problem_type == PROBLEM_INVESTIGATION else "KNOWNERROR",
            'First Name':
            first_name,
            'Last Name':
            last_name,
            'Description':
            summary,
            'Detailed Decription':
            details,
            'Company':
            company,
            'Urgency':
            urgency,
            'Impact':
            impact,
            "Status" if problem_type == PROBLEM_INVESTIGATION else "Known Error Status":
            status,
            "Assigned Support Organization":
            assigned_support_organization,
            "Assigned Group":
            assigned_support_group_name,
            "Assignee":
            assignee,
            "Assigned Support Company":
            assigned_support_company,
            "Site":
            site,
            "Site Group":
            site_group,
            "Region":
            region,
            "Site":
            site,
            "Target Resolution Date":
            target_resolution_date,
            "Investigation Driver":
            investigation_driver,
            "Temporary Workaround":
            temporary_workaround,
            "Assigned Group Pblm Mgr":
            assigned_group_pbm_mgr,
            "Support Company Pblm Mgr":
            support_company_pbm_mgr,
            "Support Organization Pblm Mgr":
            support_organization_pbm_mgr,
            "Assignee Pblm Mgr":
            assignee_pbm_mgr,
            "Investigation Justification":
            investigation_justification,
            "View Access":
            view_access,
            "Resolution":
            resolution,
            **additional_fields
        })
        data = {'values': properties}
        if problem_type == PROBLEM_INVESTIGATION:
            params = {'fields': 'values(Request ID,Problem Investigation ID,Create Date)'}
        else:
            params = {'fields': 'values(Request ID,Known Error ID,Create Date)'}

        response = self._http_request(
            'POST',
            'arsys/v1/entry/PBM:ProblemInterface_Create',
            params=params,
            json_data=data,
        )
        return response

    def update_problem_investigation_request(
            self, problem_investigation_id, first_name: str, last_name: str, summary: str,
            status: str, status_reason: str, urgency: str, impact: str, details: str, company: str,
            assigned_support_organization: str, assigned_support_company: str,
            assigned_support_group_name: str, assignee: str, assignee_login_id: str,
            site_group: str, site: str, region: str, assigned_group_pbm_mgr: str,
            support_company_pbm_mgr: str, support_organization_pbm_mgr: str,
            temporary_workaround: str, resolution: str, target_resolution_date: str,
            investigation_justification: str, investigation_driver: str, **additional_fields):
        """_summary_

            Args:
                template_instance_id (str): _description_
                first_name (str): _description_
                last_name (str): _description_
                summary (str): _description_
                location_company (str): _description_
                status (str): _description_
                urgency (str): _description_
                impact (str): _description_
                priority (str): _description_
                risk_level (str): _description_
                change_type (str): _description_
                customer_first_name (str): _description_
                customer_last_name (str): _description_

            Returns:
                _type_: _description_
            """
        properties = remove_empty_elements({
            'First Name': first_name,
            'Last Name': last_name,
            'Description': summary,
            'Detailed Decription': details,
            'Company': company,
            'Urgency': urgency,
            'Impact': impact,
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
            "Site": site,
            "Target Resolution Date": target_resolution_date,
            "Investigation Driver": investigation_driver,
            "Resolution": resolution,
            "Temporary Workaround": temporary_workaround,
            "Assigned Group Pblm Mgr": assigned_group_pbm_mgr,
            "Support Company Pblm Mgr": support_company_pbm_mgr,
            "Support Organization Pblm Mgr": support_organization_pbm_mgr,
            "Investigation Justification": investigation_justification,
            **additional_fields
        })
        data = {'values': properties}
        response = self._http_request(
            'PUT',
            f'arsys/v1/entry/PBM:ProblemInterface/{problem_investigation_id}',
            json_data=data,
            resp_type='text')

        return response

    def update_known_error_request(self, known_error_id, summary: str, status: str, urgency: str,
                                   impact: str, details: str, assigned_support_organization: str,
                                   assigned_support_company: str, assigned_support_group_name: str,
                                   assignee: str, assigned_group_pbm_mgr: str,
                                   support_company_pbm_mgr: str, support_organization_pbm_mgr: str,
                                   assignee_pbm_mgr: str, target_resolution_date: str,
                                   status_reason: str, temporary_workaround: str, view_access: str,
                                   resolution: str, **additional_fields):
        """_summary_

            Args:
                template_instance_id (str): _description_
                first_name (str): _description_
                last_name (str): _description_
                summary (str): _description_
                location_company (str): _description_
                status (str): _description_
                urgency (str): _description_
                impact (str): _description_
                priority (str): _description_
                risk_level (str): _description_
                change_type (str): _description_
                customer_first_name (str): _description_
                customer_last_name (str): _description_

            Returns:
                _type_: _description_
            """
        properties = remove_empty_elements({
            'Detailed Decription': details,
            'Description': summary,
            'Urgency': urgency,
            'Impact': impact,
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
            **additional_fields
        })
        data = {'values': properties}

        response = self._http_request('PUT',
                                      f'arsys/v1/entry/PBM:KnownErrorInterface/{known_error_id}',
                                      json_data=data,
                                      resp_type='text')

        return response


def list_command(client: Client,
                 args: Dict[str, Any],
                 form_name: str,
                 context_output_mapper: Dict[str, Any],
                 header_prefix: str,
                 outputs_prefix: str,
                 outputs_key_field: str,
                 arranger: Callable = None,
                 headers: List[str] = None,
                 record_id_key: str = None,
                 ticket_type: str = None) -> CommandResults:
    """ Generic function to handle BmcITSM list commands. 

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
    query = args.get('query')
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit'))
    validate_pagination_args(page, page_size, limit)
    filtering_mapper = generate_query_filter_mapper_by_args(args,
                                                            record_id_key,
                                                            ticket_type=ticket_type)
    query_with_filtering = generate_query_with_filtering(query, filtering_mapper)

    # print(query_with_filtering)

    response = client.list_request(form_name, query_with_filtering)
    # print(response)
    relevant_records, header_suffix = get_paginated_records_with_hr(response.get('entries'), limit,
                                                                    page, page_size)
    outputs = format_command_output(relevant_records, context_output_mapper, arranger)
    readable_output = tableToMarkdown(header_prefix,
                                      metadata=header_suffix,
                                      t=outputs,
                                      headers=headers or list(context_output_mapper.values()),
                                      headerTransform=pascalToSpace)

    command_results = CommandResults(outputs_prefix=outputs_prefix,
                                     outputs_key_field=outputs_key_field,
                                     outputs=outputs,
                                     raw_response=response,
                                     readable_output=readable_output)

    return command_results


def user_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ List BmcITSM users command. 

    Args:
        client (Client): BmcITSM API client. 
        args (Dict[str, Any]): command arguments. 

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    context_output_mapper = {
        'Person ID': 'Id',
        'First Name': 'FirstName',
        'Last Name': 'LastName',
        'Company': 'Company',
        'Department': 'Department',
        'Site Group': 'SiteGroup',
        'Region': 'Region',
        'Site': 'Site',
        'Organization': 'Organization'
    }
    args['ids'] = argToList(args.get('user_ids'))
    command_results = list_command(client,
                                   args,
                                   'CTM:People',
                                   context_output_mapper,
                                   header_prefix='List Users.',
                                   outputs_prefix='BmcITSM.User',
                                   outputs_key_field='Id',
                                   record_id_key='Person ID')
    return command_results


def company_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ List BmcITSM companies command. 

    Args:
        client (Client): BmcITSM API client. 
        args (Dict[str, Any]): command arguments. 

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    context_output_mapper = {'Company Entry ID': 'Id', 'Company': 'Name', 'Company Type': 'Type'}
    args['ids'] = argToList(args.get('company_ids'))
    command_results = list_command(client,
                                   args,
                                   'COM:Company',
                                   context_output_mapper,
                                   header_prefix='List Companies.',
                                   outputs_prefix='BmcITSM.Company',
                                   outputs_key_field='Id',
                                   record_id_key='Company Entry ID')
    return command_results


def ticket_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ List BmcITSM tickets command. 

    Args:
        client (Client): BmcITSM API client. 
        args (Dict[str, Any]): command arguments. 

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    ticket_type = args.get('ticket_type')

    context_output_mapper = generate_ticket_context_data_mapper(ticket_type)
    args['ids'] = argToList(args.get('ticket_ids'))
    command_results = list_command(client,
                                   args,
                                   TICKET_TYPE_TO_LIST_FORM[ticket_type],
                                   context_output_mapper,
                                   header_prefix='List Tickets.',
                                   outputs_prefix='BmcITSM.Ticket',
                                   outputs_key_field='DisplayID',
                                   arranger=arrange_ticket_context_data,
                                   headers=[
                                       'Type', 'RequestID', 'DisplayID', 'Summary', 'Status',
                                       'Urgency', 'Impact', 'CreateDate', 'LastModifiedDate'
                                   ],
                                   record_id_key="Task ID" if ticket_type == TASK else 'Request ID',
                                   ticket_type=ticket_type)
    return command_results


def ticket_delete_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """ BmcITSM ticket delete command. 

    Args:
        client (Client): BmcITSM API client. 
        args (Dict[str, Any]): command arguments. 

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    ticket_type = args.get('ticket_type')
    ticket_ids: List[str] = argToList(args.get('ticket_ids'))
    commands_results: List[CommandResults] = []
    for ticket_id in ticket_ids:
        try:
            client.ticket_delete_request(TICKET_TYPE_TO_DELETE_FORM[ticket_type], ticket_id)

            readable_output = f'{ticket_type} {ticket_id} was deleted successfully'
            commands_results.append(CommandResults(readable_output=readable_output))

        except Exception as error:
            error_results = CommandResults(readable_output=f'**{str(error)}**')
            commands_results.append(error_results)
    return commands_results


def service_request_definition_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ List BmcITSM service request definitions command. 

    Args:
        client (Client): BmcITSM API client. 
        args (Dict[str, Any]): command arguments. 

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    context_output_mapper = {
        'Request ID': 'Id',
        'Description': 'Description',
        'InstanceId': 'InstanceID'
    }
    args['ids'] = argToList(args.get('srd_ids'))
    command_results = list_command(client,
                                   args,
                                   'SRD:ServiceRequestDefinition',
                                   context_output_mapper,
                                   header_prefix='List service request definitions.',
                                   outputs_prefix='BmcITSM.ServiceRequestDefinition',
                                   outputs_key_field='Id',
                                   record_id_key='Request ID')
    return command_results


def incident_template_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ List BmcITSM incident templates command. 

    Args:
        client (Client): BmcITSM API client. 
        args (Dict[str, Any]): command arguments. 

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    context_output_mapper = {
        'HPD Template ID': 'Id',
        'Description': 'Description',
        'InstanceId': 'InstanceID'
    }
    args['ids'] = argToList(args.get('template_ids'))
    command_results = list_command(
        client,
        args,
        'HPD:Template',
        context_output_mapper,
        header_prefix='List incident templates.',
        outputs_prefix='BmcITSM.IncidentTemplate',
        outputs_key_field='Id',
        record_id_key='HPD Template ID',
    )
    return command_results


def change_request_template_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ List BmcITSM change request templates command. 

    Args:
        client (Client): BmcITSM API client. 
        args (Dict[str, Any]): command arguments. 

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    context_output_mapper = {
        'CHG Template ID': 'Id',
        'Description': 'Description',
        'InstanceId': 'InstanceID'
    }
    args['ids'] = argToList(args.get('template_ids'))
    command_results = list_command(client,
                                   args,
                                   'CHG:Template',
                                   context_output_mapper,
                                   header_prefix='List change request templates.',
                                   outputs_prefix='BmcITSM.ChangeRequestTemplate',
                                   outputs_key_field='Id',
                                   record_id_key='CHG Template ID')
    return command_results


def task_template_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ List BmcITSM task templates command. 

    Args:
        client (Client): BmcITSM API client. 
        args (Dict[str, Any]): command arguments. 

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    context_output_mapper = {
        'Template ID': 'Id',
        'TaskName': 'TaskName',
        'InstanceId': 'InstanceID'
    }

    args['ids'] = argToList(args.get('template_ids'))
    command_results = list_command(client,
                                   args,
                                   'TMS:TaskTemplate',
                                   context_output_mapper,
                                   header_prefix='List task templates.',
                                   outputs_prefix='BmcITSM.TaskTemplate',
                                   outputs_key_field='Id',
                                   record_id_key='Template ID')
    return command_results


def service_request_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Create BmcITSM service request command. 

    Args:
        client (Client): BmcITSM API client. 
        args (Dict[str, Any]): command arguments. 

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    srd_instance_id = args['srd_instance_id']
    summary = args.get('summary')
    status = args.get('status')
    urgency = args.get('urgency')
    impact = args.get('impact')
    first_name = args.get('first_name')
    last_name = args.get('last_name')
    login_id = args.get('login_id')

    additional_fields = extract_args_from_additional_fields_arg(args.get('additional_fields'),
                                                                'additional_fields')
    service_request_definition_params = extract_args_from_additional_fields_arg(
        args.get('service_request_definition_params'), 'service_request_definition_params')
    validate_related_arguments_provided(first_name=first_name,
                                        last_name=last_name,
                                        login_id=login_id)

    response = client.create_service_request_request(srd_instance_id, summary, urgency, impact,
                                                     first_name, last_name, login_id, status,
                                                     **additional_fields,
                                                     **service_request_definition_params)

    outputs = format_create_ticket_outputs(response.get('values'))
    readable_output = tableToMarkdown('Service Request successfully Created',
                                      outputs,
                                      headerTransform=pascalToSpace)
    command_results = CommandResults(outputs_prefix='BmcITSM.ServiceRequest',
                                     outputs_key_field='RequestID',
                                     outputs=outputs,
                                     raw_response=response,
                                     readable_output=readable_output)

    return command_results


def service_request_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Update BmcITSM service request command. 

    Args:
        client (Client): BmcITSM API client. 
        args (Dict[str, Any]): command arguments. 

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    service_request_id = args.get('service_request_id')
    customer_first_name = args.get('customer_first_name')
    customer_last_name = args.get('customer_last_name')
    status = args.get('status')
    summary = args.get('summary')
    status = args.get('status')
    status_reason = args.get('status_reason')
    urgency = args.get('urgency')
    impact = args.get('impact')
    assignee = args.get('assignee')
    location_company = args.get('location_company')
    site_group = args.get('site_group')
    region = args.get('region')
    site = args.get('site')
    additional_fields = extract_args_from_additional_fields_arg(args.get('additional_fields'),
                                                                'additional_fields')

    formatted_service_request_id = format_ticket_request_id(service_request_id)
    validate_related_arguments_provided(status=status, status_reason=status_reason)
    validate_related_arguments_provided(customer_first_name=customer_first_name,
                                        customer_last_name=customer_last_name)

    response = client.service_request_update_request(formatted_service_request_id, summary, status,
                                                     urgency, impact, customer_first_name,
                                                     customer_last_name, location_company,
                                                     site_group, region, site, assignee,
                                                     status_reason, **additional_fields)
    command_results = CommandResults(
        readable_output=f'Service Request: {service_request_id} was successfully updated.')

    return command_results


def incident_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Create BmcITSM incident command. 

    Args:
        client (Client): BmcITSM API client. 
        args (Dict[str, Any]): command arguments. 

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    template_id = args.get('template_instance_id')
    summary = args.get('summary')
    status = args.get('status')
    urgency = args.get('urgency')
    impact = args.get('impact')
    first_name = args.get('first_name')
    last_name = args.get('last_name')
    service_type = args.get('service_type')
    reported_source = args.get('reported_source')
    details = args.get('details')
    company = args.get('location_company')
    assigned_support_organization = args.get('assigned_support_organization')
    assigned_support_company = args.get('assigned_support_company')
    assigned_support_group_name = args.get('support_group_name')
    assignee_login_id = args.get('assignee_login_id')
    assignee = args.get('assignee')
    site_group = args.get('site_group')
    site = args.get('site')
    region = args.get('region')

    additional_fields = extract_args_from_additional_fields_arg(args.get('additional_fields'),
                                                                'additional_fields')

    validate_related_arguments_provided(assignee_login_id=assignee_login_id, assignee=assignee)
    if not template_id:
        validate_related_arguments_provided(summary=summary,
                                            service_type=service_type,
                                            reported_source=reported_source)

    response = client.create_incident_request(
        template_id,
        first_name,
        last_name,
        summary,
        urgency=urgency,
        impact=impact,
        status=status,
        service_type=service_type,
        reported_source=reported_source,
        details=details,
        company=company,
        assigned_support_organization=assigned_support_organization,
        assigned_support_company=assigned_support_company,
        assigned_support_group_name=assigned_support_group_name,
        assignee=assignee,
        assignee_login_id=assignee_login_id,
        site_group=site_group,
        site=site,
        region=region,
        **additional_fields)

    incident_request_id = extract_ticket_request_id_following_create(
        client, INCIDENT, response)  #The right request ID is not retrieved by the create endpoint.
    outputs = format_create_ticket_outputs(response.get('values'))
    outputs['RequestID'] = incident_request_id

    readable_output = tableToMarkdown('Incident ticket successfully Created',
                                      outputs,
                                      headerTransform=pascalToSpace)
    command_results = CommandResults(outputs_prefix='BmcITSM.Incident',
                                     outputs_key_field='RequestID',
                                     outputs=outputs,
                                     raw_response=response,
                                     readable_output=readable_output)

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
    incident_request_id = args.get('request_id')

    summary = args.get('summary')
    status = args.get('status')
    urgency = args.get('urgency')
    impact = args.get('impact')
    first_name = args.get('first_name')
    last_name = args.get('last_name')
    service_type = args.get('service_type')
    reported_source = args.get('reported_source')
    details = args.get('details')
    company = args.get('location_company')
    assigned_support_organization = args.get('assigned_support_organization')
    assigned_support_company = args.get('assigned_support_company')
    assigned_support_group_name = args.get('support_group_name')
    assignee_login_id = args.get('assignee_login_id')
    assignee = args.get('assignee')
    site_group = args.get('site_group')
    site = args.get('site')
    region = args.get('region')
    resolution = args.get('resolution')
    status_reason = args.get('status_reason')

    additional_fields = extract_args_from_additional_fields_arg(args.get('additional_fields'),
                                                                'additional_fields')

    validate_related_arguments_provided(first_name=first_name, last_name=last_name)
    validate_related_arguments_provided(assignee_login_id=assignee_login_id, assignee=assignee)
    validate_related_arguments_provided(status=status,
                                        status_reason=status_reason,
                                        resolution=resolution)

    response = client.update_incident_request(
        format_ticket_request_id(incident_request_id),
        first_name,
        last_name,
        summary,
        urgency=urgency,
        impact=impact,
        status=status,
        service_type=service_type,
        reported_source=reported_source,
        details=details,
        company=company,
        assigned_support_organization=assigned_support_organization,
        assigned_support_company=assigned_support_company,
        assigned_support_group_name=assigned_support_group_name,
        assignee=assignee,
        assignee_login_id=assignee_login_id,
        site_group=site_group,
        site=site,
        region=region,
        status_reason=status_reason,
        resolution=resolution,
        **additional_fields)

    command_results = CommandResults(
        readable_output=f'Incident: {incident_request_id} was successfully updated.')

    return command_results


def change_request_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Create BmcITSM change request command. 

    Args:
        client (Client): BmcITSM API client. 
        args (Dict[str, Any]): command arguments. 

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    template_id = args.get('template_id')
    summary = args.get('summary')
    status = args.get('status')
    urgency = args.get('urgency')
    impact = args.get('impact')
    first_name = args.get('first_name')
    last_name = args.get('last_name')
    customer_first_name = args.get('customer_first_name')
    customer_last_name = args.get('customer_last_name')
    priority = args.get('priority')
    risk_level = args.get('risk_level')
    change_type = args.get('change_type')
    location_company = args.get('location_company')
    additional_fields = extract_args_from_additional_fields_arg(args.get('additional_fields'),
                                                                'additional_fields')
    if not template_id:
        validate_related_arguments_provided(first_name=first_name,
                                            last_name=last_name,
                                            summary=summary,
                                            location_company=location_company)

    response = client.change_request_create_request(template_id,
                                                    first_name,
                                                    last_name,
                                                    summary,
                                                    location_company,
                                                    urgency=urgency,
                                                    impact=impact,
                                                    status=status,
                                                    risk_level=risk_level,
                                                    change_type=change_type,
                                                    customer_first_name=customer_first_name,
                                                    customer_last_name=customer_last_name,
                                                    priority=priority,
                                                    **additional_fields)

    outputs = format_create_ticket_outputs(response.get('values'))

    readable_output = tableToMarkdown('Change Request ticket successfully Created',
                                      outputs,
                                      headerTransform=pascalToSpace)
    command_results = CommandResults(outputs_prefix='BmcITSM.ChangeRequest',
                                     outputs_key_field='RequestID',
                                     outputs=outputs,
                                     raw_response=response,
                                     readable_output=readable_output)

    return command_results


def change_request_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Update BmcITSM change request command. 

    Args:
        client (Client): BmcITSM API client. 
        args (Dict[str, Any]): command arguments. 

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    change_request_id = args.get('request_id')
    summary = args.get('summary')
    details = args.get('details')
    status = args.get('status')
    status_reason = args.get('status_reason')
    urgency = args.get('urgency')
    impact = args.get('impact')
    first_name = args.get('first_name')
    last_name = args.get('last_name')
    customer_first_name = args.get('customer_first_name')
    customer_last_name = args.get('customer_last_name')
    priority = args.get('priority')
    risk_level = args.get('risk_level')
    change_type = args.get('change_type')
    location_company = args.get('location_company')
    organization = args.get('organization')
    department = args.get('department')
    site_group = args.get('site_group')
    site = args.get('site')
    support_organization = args.get('support_organization')
    support_group_name = args.get('support_group_name')
    company = args.get('company')
    region = args.get('region')

    additional_fields = extract_args_from_additional_fields_arg(args.get('additional_fields'),
                                                                'additional_fields')

    validate_related_arguments_provided(first_name=first_name, last_name=last_name)

    validate_related_arguments_provided(status=status, status_reason=status_reason)

    response = client.change_request_update_request(format_ticket_request_id(change_request_id),
                                                    first_name,
                                                    last_name,
                                                    summary,
                                                    location_company,
                                                    urgency=urgency,
                                                    impact=impact,
                                                    status=status,
                                                    risk_level=risk_level,
                                                    change_type=change_type,
                                                    customer_first_name=customer_first_name,
                                                    customer_last_name=customer_last_name,
                                                    priority=priority,
                                                    details=details,
                                                    status_reason=status_reason,
                                                    organization=organization,
                                                    department=department,
                                                    site_group=site_group,
                                                    site=site,
                                                    support_organization=support_organization,
                                                    support_group_name=support_group_name,
                                                    company=company,
                                                    region=region,
                                                    **additional_fields)

    command_results = CommandResults(
        readable_output=f'Change Request: {change_request_id} was successfully updated.')

    return command_results


def task_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    template_id = args.get('template_id')
    root_request_id = args.get('root_request_id')
    root_request_name = args.get('root_request_name')
    root_request_mode = args.get('root_request_mode')
    first_name = args.get('first_name')
    last_name = args.get('last_name')
    summary = args.get('summary')
    details = args.get('details')
    status = args.get('status')
    task_type = args.get('task_type')
    priority = args.get('priority')
    impact = args.get('impact')
    urgency = args.get('urgency')
    support_company = args.get('support_company')

    assigned_support_organization = args.get('assigned_support_organization')
    assigned_support_group_name = args.get('assigned_support_group')
    assignee = args.get('assignee')
    company = args.get('location_company')
    root_ticket_type = TICKET_TYPE_TO_DELETE_FORM[args.get('root_ticket_type')]
    scedulded_start_date: datetime = arg_to_datetime(args.get('scedulded_start_date'))
    scedulded_end_date: datetime = arg_to_datetime(args.get('scedulded_end_date'))

    additional_fields = extract_args_from_additional_fields_arg(args.get('additional_fields'),
                                                                'additional_fields')
    parent_ticket = get_ticket(client, args.get('root_ticket_type'), root_request_id)
    response = client.create_task_request(
        template_id,
        parent_ticket.get('InstanceId'),
        root_request_name or parent_ticket.get('DisplayID'),
        parent_ticket.get('DisplayID'),
        first_name,
        last_name,
        summary,
        status=status,
        impact=impact,
        urgency=urgency,
        priority=priority,
        details=details,
        task_type=task_type,
        support_company=support_company,
        assignee=assignee,
        location_company=company,
        root_request_mode=root_request_mode,
        root_ticket_type=root_ticket_type,
        assigned_support_group_name=assigned_support_group_name,
        assigned_support_organization=assigned_support_organization,
        scedulded_start_date=scedulded_start_date.isoformat() if scedulded_start_date else None,
        scedulded_end_date=scedulded_end_date.isoformat if scedulded_end_date else None,
        **additional_fields)

    outputs = format_create_ticket_outputs(response.get('values'))
    outputs['RequestID'] = outputs['DisplayID']
    readable_output = tableToMarkdown('Task ticket successfully Created.',
                                      outputs,
                                      headerTransform=pascalToSpace)
    command_results = CommandResults(outputs_prefix='BmcITSM.Task',
                                     outputs_key_field='RequestID',
                                     outputs=outputs,
                                     raw_response=response,
                                     readable_output=readable_output)

    return command_results


def task_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    task_id = args.get('task_id')
    root_request_name = args.get('root_request_name')
    summary = args.get('summary')
    details = args.get('details')
    status = args.get('status')
    status_reason = args.get('status_reason')
    task_type = args.get('task_type')
    priority = args.get('priority')
    company = args.get('company')
    location_company = args.get('location_company')

    priority = args.get('priority')
    organization = args.get('organization')
    department = args.get('department')
    site_group = args.get('site_group')
    site = args.get('site')
    support_company = args.get('support_company')
    assigned_support_organization = args.get('assigned_support_organization')
    assigned_support_group_name = args.get('assigned_group')
    assignee = args.get('assignee')
    scedulded_start_date: datetime = arg_to_datetime(args.get('scedulded_start_date'))
    schedulded_end_date: datetime = arg_to_datetime(args.get('schedulded_end_date'))

    additional_fields = extract_args_from_additional_fields_arg(args.get('additional_fields'),
                                                                'additional_fields')
    response = client.update_task_request(
        format_ticket_request_id(task_id),
        root_request_name,
        summary=summary,
        status=status,
        priority=priority,
        details=details,
        task_type=task_type,
        organization=organization,
        department=department,
        site_group=site_group,
        site=site,
        assigned_support_company=support_company,
        assignee=assignee,
        company=company,
        location_company=location_company,
        status_reason=status_reason,
        assigned_support_organization=assigned_support_organization,
        assigned_support_group_name=assigned_support_group_name,
        scedulded_start_date=scedulded_start_date.isoformat() if scedulded_start_date else None,
        schedulded_end_date=schedulded_end_date.isoformat if schedulded_end_date else None,
        **additional_fields)

    command_results = CommandResults(readable_output=f'Task: {task_id} was successfully updated.')

    return command_results


def problem_investigation_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Create BmcITSM incident command. 

    Args:
        client (Client): BmcITSM API client. 
        args (Dict[str, Any]): command arguments. 

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    summary = args.get('summary')
    status = args.get('status')
    urgency = args.get('urgency')
    impact = args.get('impact')
    first_name = args.get('first_name')
    last_name = args.get('last_name')
    details = args.get('details')
    company = args.get('company')
    site_group = args.get('site_group')
    site = args.get('site')
    region = args.get('region')
    assigned_support_organization = args.get('assigned_support_organization')
    assigned_support_company = args.get('assigned_support_company')
    assigned_support_group_name = args.get('assigned_group')
    assignee = args.get('assignee')
    assigned_group_pbm_mgr = args.get('assigned_group_pbm_mgr')
    support_company_pbm_mgr = args.get('support_company_pbm_mgr')
    support_organization_pbm_mgr = args.get('support_organization_pbm_mgr')
    assignee_pbm_mgr = args.get('assignee_pbm_mgr')
    temporary_workaround = args.get('temporary_workaround')
    target_resolution_date: datetime = arg_to_datetime(args.get('target_resolution_date'))
    resolution = args.get('resolution')
    investigation_justification = args.get('investigation_justification')
    investigation_driver = args.get('investigation_driver')
    additional_fields = extract_args_from_additional_fields_arg(args.get('additional_fields'),
                                                                'additional_fields')

    validate_related_arguments_provided(company=company,
                                        site=site,
                                        site_group=site_group,
                                        region=region)
    validate_related_arguments_provided(assigned_support_organization=assigned_support_organization,
                                        assigned_support_company=assigned_support_company,
                                        assigned_support_group_name=assigned_support_group_name)

    validate_related_arguments_provided(assigned_group_pbm_mgr=assigned_group_pbm_mgr,
                                        support_company_pbm_mgr=support_company_pbm_mgr,
                                        support_organization_pbm_mgr=support_organization_pbm_mgr)

    response = client.create_problem_investigation_request(
        PROBLEM_INVESTIGATION,
        summary,
        first_name=first_name,
        last_name=last_name,
        urgency=urgency,
        impact=impact,
        status=status,
        details=details,
        company=company,
        assigned_support_organization=assigned_support_organization,
        assigned_support_company=assigned_support_company,
        assigned_support_group_name=assigned_support_group_name,
        assignee=assignee,
        site_group=site_group,
        site=site,
        region=region,
        assigned_group_pbm_mgr=assigned_group_pbm_mgr,
        support_company_pbm_mgr=support_company_pbm_mgr,
        support_organization_pbm_mgr=support_organization_pbm_mgr,
        temporary_workaround=temporary_workaround,
        target_resolution_date=target_resolution_date.isoformat()
        if target_resolution_date else None,
        investigation_justification=investigation_justification,
        investigation_driver=investigation_driver,
        resolution=resolution,
        assignee_pbm_mgr=assignee_pbm_mgr,
        **additional_fields)

    incident_request_id = extract_ticket_request_id_following_create(
        client, PROBLEM_INVESTIGATION,
        response)  #The right request ID is not retrieved by the create endpoint.
    outputs = format_create_ticket_outputs(response.get('values'))
    outputs['RequestID'] = incident_request_id

    readable_output = tableToMarkdown('Problem Investigation  ticket successfully Created',
                                      outputs,
                                      headerTransform=pascalToSpace)
    command_results = CommandResults(outputs_prefix='BmcITSM.ProblemInvestigation',
                                     outputs_key_field='RequestID',
                                     outputs=outputs,
                                     raw_response=response,
                                     readable_output=readable_output)

    return command_results


def problem_investigation_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Update BmcITSM incident command. 

    Args:
        client (Client): BmcITSM API client. 
        args (Dict[str, Any]): command arguments. 

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    problem_investigation_id = args.get('problem_investigation_id')
    summary = args.get('summary')
    status = args.get('status')
    status_reason = args.get('status_reason')
    urgency = args.get('urgency')
    impact = args.get('impact')
    first_name = args.get('first_name')
    last_name = args.get('last_name')
    details = args.get('details')
    company = args.get('company')
    site_group = args.get('site_group')
    site = args.get('site')
    region = args.get('region')
    assigned_support_organization = args.get('assigned_support_organization')
    assigned_support_company = args.get('assigned_support_company')
    assigned_support_group_name = args.get('assigned_group')
    assignee_login_id = args.get('assignee_login_id')
    assignee = args.get('assigned_to')
    assigned_group_pbm_mgr = args.get('assigned_group_pbm_mgr')
    support_company_pbm_mgr = args.get('support_company_pbm_mgr')
    support_organization_pbm_mgr = args.get('support_organization_pbm_mgr')
    assignee_pbm_mgr = args.get('assignee_pbm_mgr')
    temporary_workaround = args.get('temporary_workaround')
    resolution = args.get('resolution')
    target_resolution_date: datetime = arg_to_datetime(args.get('target_resolution_date'))
    investigation_justification = args.get('investigation_justification')
    investigation_driver = args.get('investigation_driver')
    additional_fields = extract_args_from_additional_fields_arg(args.get('additional_fields'),
                                                                'additional_fields')

    validate_related_arguments_provided(company=company,
                                        site=site,
                                        site_group=site_group,
                                        region=region)
    validate_related_arguments_provided(assigned_support_organization=assigned_support_organization,
                                        assigned_support_company=assigned_support_company,
                                        assigned_support_group_name=assigned_support_group_name)

    validate_related_arguments_provided(assigned_group_pbm_mgr=assigned_group_pbm_mgr,
                                        support_company_pbm_mgr=support_company_pbm_mgr,
                                        support_organization_pbm_mgr=support_organization_pbm_mgr)

    response = client.update_problem_investigation_request(
        format_ticket_request_id(problem_investigation_id),
        first_name,
        last_name,
        summary,
        urgency=urgency,
        impact=impact,
        status=status,
        status_reason=status_reason,
        details=details,
        company=company,
        assigned_support_organization=assigned_support_organization,
        assigned_support_company=assigned_support_company,
        assigned_support_group_name=assigned_support_group_name,
        assignee=assignee,
        assignee_login_id=assignee_login_id,
        site_group=site_group,
        site=site,
        region=region,
        assigned_group_pbm_mgr=assigned_group_pbm_mgr,
        support_company_pbm_mgr=support_company_pbm_mgr,
        support_organization_pbm_mgr=support_organization_pbm_mgr,
        temporary_workaround=temporary_workaround,
        resolution=resolution,
        target_resolution_date=target_resolution_date.isoformat()
        if target_resolution_date else None,
        investigation_justification=investigation_justification,
        investigation_driver=investigation_driver,
        assignee_pbm_mgr=assignee_pbm_mgr,
        **additional_fields)

    command_results = CommandResults(
        readable_output=
        f'Problem Investigation: {problem_investigation_id} was successfully updated.')

    return command_results


def known_error_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Create BmcITSM Known Error command. 

    Args:
        client (Client): BmcITSM API client. 
        args (Dict[str, Any]): command arguments. 

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    summary = args.get('summary')
    status = args.get('status')
    urgency = args.get('urgency')
    impact = args.get('impact')
    details = args.get('details')
    company = args.get('company')
    site_group = args.get('site_group')
    site = args.get('site')
    region = args.get('region')
    assigned_support_organization = args.get('assigned_support_organization')
    assigned_support_company = args.get('assigned_support_company')
    assigned_support_group_name = args.get('assigned_group')
    assignee = args.get('assignee')
    assigned_group_pbm_mgr = args.get('assigned_group_pbm_mgr')
    support_company_pbm_mgr = args.get('support_company_pbm_mgr')
    support_organization_pbm_mgr = args.get('support_organization_pbm_mgr')
    assignee_pbm_mgr = args.get('assignee_pbm_mgr')
    temporary_workaround = args.get('temporary_workaround')
    resolution = args.get('resolution')
    target_resolution_date = arg_to_datetime(args.get('target_resolution_date')).isoformat()
    view_access = args.get('view_access')
    additional_fields = extract_args_from_additional_fields_arg(args.get('additional_fields'),
                                                                'additional_fields')

    validate_related_arguments_provided(assigned_support_organization=assigned_support_organization,
                                        assigned_support_company=assigned_support_company,
                                        assigned_support_group_name=assigned_support_group_name)

    validate_related_arguments_provided(assigned_group_pbm_mgr=assigned_group_pbm_mgr,
                                        support_company_pbm_mgr=support_company_pbm_mgr,
                                        support_organization_pbm_mgr=support_organization_pbm_mgr)
    response = client.create_problem_investigation_request(
        KNOWN_ERROR,
        summary,
        urgency=urgency,
        impact=impact,
        status=status,
        details=details,
        company=company,
        assigned_support_organization=assigned_support_organization,
        assigned_support_company=assigned_support_company,
        assigned_support_group_name=assigned_support_group_name,
        assignee=assignee,
        site_group=site_group,
        site=site,
        region=region,
        assigned_group_pbm_mgr=assigned_group_pbm_mgr,
        support_company_pbm_mgr=support_company_pbm_mgr,
        support_organization_pbm_mgr=support_organization_pbm_mgr,
        temporary_workaround=temporary_workaround,
        resolution=resolution,
        target_resolution_date=target_resolution_date,
        view_access=view_access,
        assignee_pbm_mgr=assignee_pbm_mgr,
        **additional_fields)

    known_error_id = extract_ticket_request_id_following_create(
        client, KNOWN_ERROR,
        response)  #The right request ID is not retrieved by the create endpoint.
    outputs = format_create_ticket_outputs(response.get('values'))
    outputs['RequestID'] = known_error_id

    readable_output = tableToMarkdown('Known Error ticket successfully Created',
                                      outputs,
                                      headerTransform=pascalToSpace)
    command_results = CommandResults(outputs_prefix='BmcITSM.KnownError',
                                     outputs_key_field='RequestID',
                                     outputs=outputs,
                                     raw_response=response,
                                     readable_output=readable_output)

    return command_results


def known_error_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Update BmcITSM incident command. 

    Args:
        client (Client): BmcITSM API client. 
        args (Dict[str, Any]): command arguments. 

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    known_error_id = args.get('known_error_id')
    summary = args.get('summary')
    status = args.get('status')
    urgency = args.get('urgency')
    impact = args.get('impact')
    details = args.get('details')
    status_reason = args.get('status_reason')
    assigned_support_organization = args.get('assigned_support_organization')
    assigned_support_company = args.get('assigned_support_company')
    assigned_support_group_name = args.get('assigned_group')
    assignee = args.get('assignee')
    assignee_pbm_mgr = args.get('assignee_pbm_mgr')
    assigned_group_pbm_mgr = args.get('assigned_group_pbm_mgr')
    support_company_pbm_mgr = args.get('support_company_pbm_mgr')
    support_organization_pbm_mgr = args.get('support_organization_pbm_mgr')
    temporary_workaround = args.get('temporary_workaround')
    resolution = args.get('resolution')
    target_resolution_date = arg_to_datetime(args.get('target_resolution_date'))
    view_access = args.get('view_access')

    target_resolution_date: datetime = arg_to_datetime(args.get('target_resolution_date'))
    additional_fields = extract_args_from_additional_fields_arg(args.get('additional_fields'),
                                                                'additional_fields')

    validate_related_arguments_provided(assigned_support_organization=assigned_support_organization,
                                        assigned_support_company=assigned_support_company,
                                        assigned_support_group_name=assigned_support_group_name)

    validate_related_arguments_provided(assigned_group_pbm_mgr=assigned_group_pbm_mgr,
                                        support_company_pbm_mgr=support_company_pbm_mgr,
                                        support_organization_pbm_mgr=support_organization_pbm_mgr)

    validate_related_arguments_provided(status=status, status_reason=status_reason)

    response = client.update_known_error_request(
        format_ticket_request_id(known_error_id),
        summary,
        urgency=urgency,
        impact=impact,
        status=status,
        details=details,
        assigned_support_organization=assigned_support_organization,
        assigned_support_company=assigned_support_company,
        assigned_support_group_name=assigned_support_group_name,
        assignee=assignee,
        assigned_group_pbm_mgr=assigned_group_pbm_mgr,
        support_company_pbm_mgr=support_company_pbm_mgr,
        support_organization_pbm_mgr=support_organization_pbm_mgr,
        target_resolution_date=target_resolution_date.isoformat()
        if target_resolution_date else None,
        status_reason=status_reason,
        assignee_pbm_mgr=assignee_pbm_mgr,
        temporary_workaround=temporary_workaround,
        resolution=resolution,
        view_access=view_access,
        **additional_fields)

    command_results = CommandResults(
        readable_output=f'Known Error: {known_error_id} was successfully updated.')

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
        context_data_arranger (Callable): Function which responsible for arranging the data according to the required context output. 

    Returns:
        Dict[str, Any]: Formatted command output. 
    """
    outputs = []
    for record in records:
        formatted_record = {}
        record_attributes = record.get('values')
        for k, v in mapper.items():
            if k in record_attributes:
                if v == 'RequestID' or v == 'Id':  # extract request ID out of pattern: <id|id> -> id
                    formatted_record[v] = extract_ticket_request_id(record_attributes[k])
                elif 'Date' in v and record_attributes[k]:
                    formatted_record[v] = FormatIso8601(arg_to_datetime(record_attributes[k]))
                else:
                    formatted_record[v] = record_attributes[k]
        if context_data_arranger:
            context_data_arranger(formatted_record)
        outputs.append(formatted_record)

    return outputs


def get_paginated_records_with_hr(
    raw_data: List[dict],
    limit: int,
    page: int = None,
    page_size: int = None,
) -> Tuple[list, str]:
    """
    Retrieve the required page either with Automatic or Manual pagination,
    and the matching readable output header. 

    Args:
        raw_data (List[dict]): Records of resources from BmcITSM. 
        page (int): Page number.
        page_size (int): Page size. 
        limit (int): Limit.

    Returns:
        tuple: Requested page& matching readable output header. 
    """
    header = ''
    rows_count = len(raw_data)
    if page and page_size:
        total_pages = rows_count // page_size + (rows_count % page_size != 0)
        from_index = min((page - 1) * page_size, rows_count)
        to_index = min(from_index + page_size, rows_count)
        relevant_raw_data = raw_data[from_index:to_index]
        header = f'Showing page {page} out of {total_pages} total pages.' \
                           f' Current page size: {page_size}.'
    else:
        relevant_raw_data = raw_data[:min(rows_count, limit)]
        header = f'Showing {len(relevant_raw_data)} records out of {rows_count}.'

    return relevant_raw_data, header if relevant_raw_data else ''


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
    return request_id.split('|')[0]


def format_ticket_request_id(request_id: str) -> str:
    """
    Formats raw Request ID in the pattern of: ID|ID. 
    Useful for sevreal API endpoints. 

    Args:
        request_id (str): Raw ticket request ID. 

    Returns:
        str: Formatted request ID. 
    """
    if '|' not in request_id:
        return f'{request_id}|{request_id}'
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
        raise ValueError(f'The arguments: {list(related_args.keys())} should be provided together.')


def extract_args_from_additional_fields_arg(additional_fields: str,
                                            field_name: str) -> Tuple[Any, List[str]]:
    """
    Get dictionary structure
    :type data: ``str``
    :param data: String from which dictionary will be made.
    :type field: ``str``
    :param field: String containing field to raise exception.
    :return: Tuple containing dictionary and list.
    :rtype: ``tuple``
    :raises ValueError: If format of data is invalid.
    """
    formatted_additional_fields = {}
    regex_to_validate_json = re.compile(r'{}'.format(VALIDATE_JSON))
    if not additional_fields:
        return {}
    if not regex_to_validate_json.fullmatch(additional_fields):
        raise ValueError(f'Invalid data format of {field_name} argument.')

    fields = additional_fields.split(FIELD_DELIMITER)
    for each_field in fields:
        key, value = each_field.split(VALUE_DELIMITER)
        if value and value.strip() != '':
            formatted_additional_fields[key.strip()] = value
    return formatted_additional_fields


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
    customer['FirstName'] = ticket.pop('Customer First Name', None)
    customer['LastName'] = ticket.pop('Customer Last Name', None)
    customer['Company'] = ticket.pop('Customer Company', None)
    customer['Organization'] = ticket.pop('Customer Organization', None)
    customer['Department'] = ticket.pop('Customer Department', None)
    customer['E-mail'] = ticket.pop('Customer Internet E-mail', None)
    customer['PhoneNumber'] = ticket.pop('Customer Phone Number', None)

    requester['FirstName'] = ticket.pop('First Name', None)
    requester['LastName'] = ticket.pop('Last Name', None)
    requester['Company'] = ticket.pop('Company', None)
    requester['Region'] = ticket.pop('Region', None)
    requester['Site'] = ticket.pop('Site', None)
    requester['SiteGroup'] = ticket.pop('Site Group', None)

    assignee['FullName'] = ticket.pop('Assignee', None)
    assignee['Group'] = ticket.pop('Assignee Group', None)
    assignee['SupportOrganization'] = ticket.pop('Assigned Support Organization', None)
    assignee['SupportCompany'] = ticket.pop('Assigned Support Company', None)
    assignee['AssignedGroup'] = ticket.pop('Assigned Group', None)

    ticket['Type'] = get_ticket_type_by_request_number(ticket['DisplayID'])
    if ticket['Type'] == 'incident':
        customer.update({key: requester[key] for key in ['FirstName', 'LastName', 'Company']})
    ticket['RequestID'] = ticket.get('RequestID', ticket['DisplayID'])
    ticket['Customer'] = customer if not all_keys_empty(customer) else None
    ticket['Requester'] = requester if not all_keys_empty(requester) else None
    ticket['Assignee'] = assignee if not all_keys_empty(assignee) else None

    return ticket


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


def get_ticket_type_by_request_number(request_num: str) -> str:
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


def generate_query_filter_mapper_by_args(args: Dict[str, Any], record_id_key: str,
                                         ticket_type: str) -> Dict[str, Any]:
    """
    Generates mapper of filter argument name in BMC search qualification query
    to it's provided value.
    The mapper takes into consideration the filters by ids, filter by '='
    operator and filters by 'LIKE' operator. 
    Args:
        args (Dict[str, Any]): Command arguments. 

    Returns:
        Dict[str, Any]: mapper of filter argument name to it's value. 
    """

    ids_filter_mapper = {record_id_key: args.get('ids')}
    status_key = TICKET_TYPE_TO_STATUS_FIELD.get(ticket_type, 'Status')
    equal_filter_mapper = {
        status_key: args.get('status'),
        'Impact': args.get('impact'),
        'Urgency': args.get('urgency'),
        'Risk Level': args.get('risk_level'),
        'Priority': args.get('priority'),
        'Change Type': args.get('change_type'),
    }

    like_filter_mapper = {
        'Summary': args.get('summary'),
        'Description': args.get('description'),
        'First Name': args.get('first_name'),
        'Last Name': args.get('last_name'),
        'Company': args.get('company'),
        'Department': args.get('department'),
        'Organization': args.get('organization'),
        'Company Type': args.get('company_type'),
        'Company Type': args.get('company_type'),
        'TaskName': args.get('task_name'),
    }

    return {
        ID_QUERY_MAPPER_KEY: ids_filter_mapper,
        LIKE_QUERY_MAPPER_KEY: like_filter_mapper,
        EQUAL_QUERY_MAPPER_KEY: equal_filter_mapper
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

    ids_query = ' OR '.join(f"'{records_id_name}' =\"{resource_id}\""
                            for resource_id in (records_ids))

    equal_oper_filter_query = ' AND '.join(
        f"'{filter_key}' = \"{filter_val}\""
        for filter_key, filter_val in (equal_oper_filters).items())

    like_oper_filter_query = ' AND '.join(f"'{filter_key}' LIKE \"%{filter_val}%\""
                                          for filter_key, filter_val in (like_oper_filters).items())

    sub_queries = [custom_query, ids_query, equal_oper_filter_query, like_oper_filter_query]
    return ' AND '.join(filter(None, sub_queries))


def fetch_incidents(client: Client, max_fetch: int, first_fetch: str, last_run: Dict[str, Any],
                    ticket_type_filter: List[str], status_filter: List[str],
                    impact_filter: List[str], urgency_filter: List[str],
                    custom_query: str) -> tuple:
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

    first_fetch_epoch = date_to_epoch_for_fetch(
        arg_to_datetime(first_fetch)) if not last_run else None

    last_run = init_last_run(first_fetch_epoch) if first_fetch_epoch else last_run
    current_time = date_to_epoch_for_fetch(arg_to_datetime("now"))

    relevant_tickets, ticket_type_to_last_epoch = fetch_relevant_tickets(
        client, ticket_type_filter, max_fetch, last_run, current_time, status_filter, impact_filter,
        urgency_filter, custom_query)

    incidents = []
    for incident in relevant_tickets:
        incidents.append({
            'name': incident.get('Summary'),
            'occured': incident.get('CreateDate'),
            'rawJSON': json.dumps(incident)
        })
    if incidents:
        last_run = update_last_run(last_run, ticket_type_to_last_epoch)
    return incidents, last_run


def fetch_relevant_tickets(client: Client, ticket_types: List[str], max_fetch: int, last_run: dict,
                           t_epoch_to: int, status_filter: List[str], impact_filter: List[str],
                           urgency_filter: List[str], custom_query: str) -> Tuple[list, dict]:
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
        ticket_form = TICKET_TYPE_TO_LIST_FORM[ticket_type]
        t_epoch_from = dict_safe_get(last_run, [ticket_type, 'last_create_time'])
        fetch_query = gen_fetch_incidents_query(ticket_type, t_epoch_from, t_epoch_to,
                                                status_filter, impact_filter, urgency_filter,
                                                custom_query)

        response = client.list_request(ticket_form, fetch_query)
        relevant_records, _ = get_paginated_records_with_hr(response.get('entries'), max_fetch)
        outputs: List[dict] = format_command_output(
            deepcopy(relevant_records), generate_ticket_context_data_mapper(ticket_type),
            arrange_ticket_context_data)

        tickets_amount = min(tickets_capacity, len(outputs))
        total_tickets += outputs[:tickets_amount]
        tickets_capacity -= tickets_amount
        if outputs:
            last_ticket_create_time = total_tickets[-1].get('CreateDate')
            ticket_type_to_last_epoch[ticket_type] = date_to_epoch_for_fetch(
                arg_to_datetime(last_ticket_create_time))
        if tickets_capacity <= 0:
            break

    return total_tickets, ticket_type_to_last_epoch


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
        last_run[ticket_type]['last_create_time'] = last_epoch
    return last_run


def all_keys_empty(dict_obj: Dict[str, Any]) -> bool:
    """
    Checks whether all of the the keys of the given dict object have a None value. 

    Args:
        dict_obj (Dict[str, Any]): The dict object to check.

    Returns:
        bool: Wheter or not all keys have None value. 
    """
    for value in dict_obj.values():
        if value:
            return False
    return True


def gen_or_statement(filter_name: str, values: List[str]) -> str:
    """
    Generate OR statement in BMC ITSM search qualifaction syntax. 

    Args:
        filter_name (str): The name of the filter in the query. 
        values (List[str]): List of values to implement the OR operations between them. 

    Returns:
        str: Generated OR statement. 
    """

    return ' OR '.join(f"'{filter_name}' =\"{resource_id}\"" for resource_id in (values))


def gen_processed_query(*sub_queries) -> str:
    """
    Generates a query based on given statements to make an "AND" operation between them. 

    Returns:
        str: Processed query. 
    """
    return ' AND '.join(sub_query for sub_query in sub_queries if sub_query)


def gen_fetch_incidents_query(ticket_type: str, t_epoch_from: int, t_epoch_to: int,
                              status_filter: List[str], impact_filter: List[str],
                              urgency_filter: List[str], custom_query: str) -> str:
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
    # print(t_epoch_from, t_epoch_to)
    create_time_prop = 'Assign Time' if ticket_type == 'task' else 'Submit Date'
    time_filter = f"'{create_time_prop}' <= \"{t_epoch_to}\" AND '{create_time_prop}' >\"{t_epoch_from}\""

    status_statement = gen_or_statement(TICKET_TYPE_TO_STATUS_KEY[ticket_type], status_filter)
    urgency_statement = gen_or_statement('Urgency', urgency_filter)
    impact_statement = gen_or_statement('Impact', impact_filter)
    return gen_processed_query(time_filter, custom_query, status_statement, urgency_statement,
                               impact_statement)


def validate_pagination_args(page: int, page_size: int, limit: int):
    """
    Validates values of pagination arguments in list commands. 

    Args:
        page (int): Page number to validate.
        page_size (int): Page size to validate. 
        limit (int): Limit for automatic pagination to validate. 

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
        last_run[ticket_type] = {'last_create_time': first_fetch_epoch, 'last_tickets': []}
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


def extract_ticket_request_id_following_create(client: Client, ticket_type,
                                               ticket_create_response: Dict[str, Any]) -> str:
    form_name = TICKET_TYPE_TO_LIST_FORM[ticket_type]
    display_id_prop_name = TICKET_TYPE_TO_DISPLAY_ID[ticket_type]
    display_id = dict_safe_get(ticket_create_response, ['values', display_id_prop_name])
    response = client.list_request(form_name, f"'{display_id_prop_name}' = \"{display_id}\"")

    request_id = dict_safe_get(response['entries'][0], ['values', 'Request ID'])
    return extract_ticket_request_id(request_id)


def format_create_ticket_outputs(outputs: Dict[str, Any]) -> Dict[str, Any]:

    formatted_outputs = {}
    for k, v in outputs.items():
        if k in CREATE_CONTEXT_MAPPER:
            formatted_outputs[CREATE_CONTEXT_MAPPER[k]] = v
    formatted_outputs['CreateDate'] = FormatIso8601(arg_to_datetime(
        formatted_outputs['CreateDate']))
    return formatted_outputs


def get_ticket(client: Client, ticket_type: str, root_request_id: str) -> Dict[str, Any]:
    command_results: CommandResults = ticket_list_command(client, {
        "ticket_type": ticket_type,
        'ticket_ids': root_request_id,
        'limit': 1
    })
    outputs = command_results.outputs
    if not outputs:
        raise ValueError(
            f"The ticket type: {ticket_type} with request ID: {root_request_id} does not exist.")
    return outputs[0]


def test_module(client: Client) -> None:
    """
    Validates the correctness of the instance parameter and connectivity to
    BMC ITSM API service. 

    Args:
        client (Client): BMC ITSM API client. 
    """
    return_results('ok')


def main() -> None:

    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params['url']
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    credentials = params.get('credentials')
    username = credentials.get('identifier')
    password = credentials.get('password')

    max_fetch = arg_to_number(params.get('max_fetch', DEFAULT_FETCH))
    first_fetch = params.get('first_fetch')
    ticket_types = argToList(params.get('ticket_type'))
    ticket_statuses = argToList(params.get('ticket_status'))
    ticket_impacts = argToList(params.get('ticket_impact'))
    ticket_urgencies = argToList(params.get('ticket_urgency'))
    ticket_custom_query = params.get('query')

    ticket_type_filter = ALL_TICKETS if ALL_OPTION in ticket_types else ticket_types
    ticket_status_filter = [] if ALL_OPTION in ticket_statuses else ticket_statuses
    ticket_impact_filter = [] if ALL_OPTION in ticket_impacts else ticket_impacts
    ticket_urgency_filter = [] if ALL_OPTION in ticket_urgencies else ticket_urgencies

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client: Client = Client(url, username, password, verify=verify_certificate, proxy=proxy)

        commands = {
            'bmc-itsm-ticket-list': ticket_list_command,
            'bmc-itsm-ticket-delete': ticket_delete_command,
            'bmc-itsm-user-list': user_list_command,
            'bmc-itsm-company-list': company_list_command,
            'bmc-itsm-service-request-create': service_request_create_command,
            'bmc-itsm-service-request-definition-list': service_request_definition_list_command,
            'bmc-itsm-service-request-update': service_request_update_command,
            'bmc-itsm-change-request-template-list': change_request_template_list_command,
            'bmc-itsm-change-request-create': change_request_create_command,
            'bmc-itsm-change-request-update': change_request_update_command,
            'bmc-itsm-incident-template-list': incident_template_list_command,
            'bmc-itsm-incident-create': incident_create_command,
            'bmc-itsm-incident-update': incident_update_command,
            'bmc-itsm-task-template-list': task_template_list_command,
            'bmc-itsm-task-create': task_create_command,
            'bmc-itsm-task-update': task_update_command,
            'bmc-itsm-problem-investigation-create': problem_investigation_create_command,
            'bmc-itsm-problem-investigation-update': problem_investigation_update_command,
            'bmc-itsm-known-error-create': known_error_create_command,
            'bmc-itsm-known-error-update': known_error_update_command,
        }

        if command == 'test-module':
            test_module(client)
        if command == 'fetch-incidents':
            incidents, last_run = fetch_incidents(client, max_fetch, first_fetch,
                                                  demisto.getLastRun(), ticket_type_filter,
                                                  ticket_status_filter, ticket_impact_filter,
                                                  ticket_urgency_filter, ticket_custom_query)

            demisto.setLastRun(last_run)
            demisto.incidents(incidents)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        error_msg = str(e)
        if 'Internal Server Error' in error_msg:
            return_error(f'Please validate the provided values in the command arguments.\n{e}')
        if 'Not Found' in error_msg:
            return_error(f'The requested resource does not exist.\n{e}')
        else:
            return_error(e)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
