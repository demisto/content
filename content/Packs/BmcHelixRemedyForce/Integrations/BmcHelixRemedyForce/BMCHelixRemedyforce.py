from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]

# IMPORTS
from datetime import datetime
from typing import Dict, Callable, Any, List, Tuple, Union, Optional
from requests import Response
from requests.exceptions import MissingSchema, InvalidSchema
import urllib3
import contextlib
import traceback
import xml.etree.ElementTree as ElementTree
import dateparser

# Disable insecure warnings
urllib3.disable_warnings()
requests.packages.urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

ALLOWED_DATE_FORMAT_1 = '%Y-%m-%d'  # sample - 2020-08-23
ALLOWED_DATE_FORMAT_2 = '%Y-%m-%dT%H:%M:%S.%fZ'  # sample - 2020-08-23T08:53:00.000Z
ALLOWED_DATE_FORMAT_3 = '%Y-%m-%dT%H:%M:%S.%f%z'  # sample - 2020-08-23T08:53:00.000+0530

DISPLAY_DATE_FORMAT = '%B %d, %Y, %I:%M %p'

LOGIN_API_VERSION = '35.0'
BMC_API_VERSION = '1.0'
SALESFORCE_API_VERSION = 'v48.0'

FIELD_DELIMITER = ";"
VALUE_DELIMITER = "="
VALIDATE_JSON = r"(\w+=[^;=]+;( )?)*\w+=[^;=]+"
DATE_AND_TIME = 'Date & Time [UTC]'
HEADER_SECTION_TYPE = 'header section'

MESSAGES: Dict[str, str] = {
    'TRACEBACK_MESSAGE': 'Error when calling {} - ',
    'BAD_REQUEST_ERROR': 'An error occurred while fetching the data. Reason: {}',
    'AUTHENTICATION_ERROR': 'Unauthenticated. Check the configured Username and Password instance parameters.',
    'AUTHENTICATION_CONFIG_ERROR': 'Error authenticating with Remedyforce/Salesforce API. Please check configuration '
                                   'parameters.',
    'FORBIDDEN': 'Access to the requested resource is forbidden. Reason: {}',
    'NOT_FOUND_ERROR': 'Requested resource not found. Reason: {}',
    'INTERNAL_SERVER_ERROR': 'Encountered an internal server error with Remedyforce API, unable to complete '
                             'your request. Reason: {}',
    'REQUEST_TIMEOUT_VALIDATION': 'HTTP(S) Request Timeout parameter must be a positive number.',
    'REQUEST_TIMEOUT_EXCEED_ERROR': 'Value is too large for HTTP(S) Request Timeout parameter. Maximum value allowed '
                                    'is 120 seconds.',
    'MISSING_SCHEMA_ERROR': 'Invalid API URL. No schema supplied: http(s).',
    'INVALID_SCHEMA_ERROR': 'Invalid API URL. Supplied schema is invalid, supports http(s).',
    'CONNECTION_ERROR': 'Connectivity failed. Check your internet connection, the API URL or try increasing the HTTP(s)'
                        ' Request Timeout.',
    'PROXY_ERROR': 'Proxy error - cannot connect to proxy. Either try clearing the \'Use system proxy\' checkbox or '
                   'check the host, authentication details and connection details for the proxy.',
    'DATA_PARSING_ERROR': 'Failed parsing response data.',
    'GET_OUTPUT_MESSAGE': 'Total retrieved {0}: {1}',
    'FAILED_MESSAGE': 'The request to {0} {1} has failed.',
    'INVALID_MAX_INCIDENT_ERROR': 'Parameter Max Incidents must be positive integer.',
    'MULTIPLE_WHERE_CLAUSE_ERROR': 'Multiple "where" clauses are not allowed inside query parameter.',
    'PARAMETER_TYPE_EMPTY_ERROR': 'Parameter Type is mandatory.',
    'SERVICE_REQ_DEF_NOT_FOUND': 'Can not find a service request definition "{}".',
    'INVALID_FIELDS_ERROR': 'Fields \'{}\' are not allowed to pass in \'{}\' argument.',
    'INVALID_FORMAT_ERROR': 'Invalid data format of {} argument, enter format like - \'{}\'.',
    'UNEXPECTED_ERROR': 'An unexpected error occurred.',
    'CREATE_SERVICE_REQUEST_WARNING': 'The service request {} is created but failed to set following fields '
                                      '\'{}\' into service request due to reason: {}.',
    'UPDATE_SERVICE_REQUEST_WARNING': 'The service request {} is updated but failed to update following fields: {} '
                                      'into service request due to reason: {}.',
    'NOT_FOUND_SERVICE_REQUEST': 'Can not find service request {}.',
    'NOT_FOUND_INCIDENT': 'Can not find incident {}.',
    'INVALID_DATA_FORMAT': 'Invalid data format of {} argument.',
    'NOTE_CREATE_FAIL': 'Can not find Service request/Incident {}.',
    'INVALID_ENTITY_NAME': 'No records found for {} "{}".',
    'NO_ENTITY_FOUND': 'No {} found on configured instance of BMC Helix Remedyforce.',
    'INVALID_ADDITIONAL_ARGUMENT': 'Additional arguments field contains following the default argument(s) for this '
                                   'command: {}.',
    'INVALID_FETCH_INCIDENT_QUERY_ERROR': 'The provided query is invalid.',
    'INVALID_TYPE_FOR_CATEGORIES': 'The given value for {} is invalid. Valid {}: {}.',
    'EMPTY_SERVICE_REQUEST': '\'service_request_number\' can not be empty.',
    'EMPTY_REQUIRED_ARGUMENT': '\'{}\' can not be empty.',
    'DATE_PARSE_ERROR': 'Cannot parse datetime for field - {}. Expected format is yyyy-MM-ddTHH:mm:ss.SSS+/-HHmm or '
                        'yyyy-MM-ddTHH:mm:ss.SSSZ.',
    'DATE_VALIDATION_ERROR': '{} must be later than the {}.',
    'MAX_INCIDENT_LIMIT': 'Values allowed for {} is 1 to 500.'
}

POSSIBLE_CATEGORY_TYPES = ["All", "Service Request", "Incident"]

HR_MESSAGES: Dict[str, str] = {
    'NOTE_CREATE_SUCCESS': 'The service request/incident {} is successfully updated with the note.',
    'GET_COMMAND_DETAILS_SUCCESS': 'Total retrieved {}: {}',
    'SERVICE_REQUEST_CREATE_SUCCESS': 'The service request {} is successfully created.',
    'SERVICE_REQUEST_UPDATE_SUCCESS': 'The service request {} is successfully updated.',
    'CREATE_INCIDENT_SUCCESS': 'The incident {} is successfully created.',
    'CREATE_INCIDENT_WARNING': 'The incident {} is created but failed to set following fields '
                               '\'{}\' into incident due to reason: {}',
    'CREATE_INCIDENT_FAILURE': 'The request to create the incident failed due to the following reason: {}',
    'UPDATE_INCIDENT_SUCCESS': 'The incident {} is successfully updated.',
    'COMMAND_FAILURE': 'Failed to execute {} command. Error: {}',
    'UPDATE_INCIDENT_FAILURE': 'Error: The request to update incident failed due to the following reason: {}.',
    'NO_QUEUE_FOUND': 'No queue details found for the given argument(s).',
    'NO_USERS_FOUND': 'No user(s) found for the given argument(s).',
    'NO_ASSETS_FOUND': 'No asset(s) found for the given argument(s).',
    'NO_BROADCAST_DETAILS_FOUND': 'No broadcast details found for the given argument(s).',
    'NOT_FOUND_FOR_ARGUMENTS': 'No {} found for the given argument(s).',
    'NOT_FOUND_SERVICE_REQUEST_DEF': 'No records found for service_request_definition_name "{}".',
    'NO_INCIDENT_DETAILS_FOUND': 'No incident(s) for the given argument(s).',
    'NO_SERVICE_REQUEST_DETAILS_FOUND': 'No service request(s) found for the given argument(s).'
}

URL_SUFFIX: Dict[str, str] = {
    'TEST_MODULE': f'/services/apexrest/BMCServiceDesk/{BMC_API_VERSION}/ServiceUtil/UserDetail',
    'GET_SERVICE_REQUEST_DEFINITION': f'/services/apexrest/BMCServiceDesk/{BMC_API_VERSION}/ServiceRequestDefinition',
    'CREATE_NOTE_COMMAND': '/services/apexrest/BMCServiceDesk/{}/ServiceRequest/{}/clientnote',
    'SALESFORCE_QUERY': f'/services/data/{SALESFORCE_API_VERSION}/query',
    'FETCH_SRD': f'/services/apexrest/BMCServiceDesk/{BMC_API_VERSION}/ServiceRequestDefinition',
    'UPDATE_INCIDENT': f'services/data/{SALESFORCE_API_VERSION}/sobjects/BMCServiceDesk__Incident__c',
    'SERVICE_REQUEST': f'services/apexrest/BMCServiceDesk/{BMC_API_VERSION}/ServiceRequest',
    'CREATE_INCIDENT': f'/services/apexrest/BMCServiceDesk/{BMC_API_VERSION}/Incident',
    'DOWNLOAD_ATTACHMENT': '/sfc/servlet.shepherd/document/download/{}?operationContext=S1'
}

PRIORITY_TO_SEVERITY_MAP = {
    '5': 0,
    '4': 1,
    '3': 2,
    '2': 3,
    '1': 4

}
OUTPUT_PREFIX: Dict[str, str] = {
    'SERVICE_REQUEST': 'BmcRemedyforce.ServiceRequest',
    # Using this in return_warning for setting context.
    'SERVICE_REQUEST_WARNING': 'BmcRemedyforce.ServiceRequest(val.Number === obj.Number)',
    'NOTE': 'BmcRemedyforce.Note',
    'SERVICE_REQUEST_DEFINITION': 'BmcRemedyforce.ServiceRequestDefinition',
    'TEMPLATE': 'BmcRemedyforce.Template',
    'USER': 'BmcRemedyforce.User',
    'SERVICE_OFFERING': 'BmcRemedyforce.ServiceOffering',
    'IMPACT': 'BmcRemedyforce.Impact',
    'INCIDENT': 'BmcRemedyforce.Incident',
    # Using this in return_warning for setting context.
    'INCIDENT_WARNING': 'BmcRemedyforce.Incident(val.Id === obj.Id)',
    'ASSET': 'BmcRemedyforce.Asset',
    'ACCOUNT': 'BmcRemedyforce.Account',
    'STATUS': 'BmcRemedyforce.Status',
    'URGENCY': 'BmcRemedyforce.Urgency',
    'CATEGORY': 'BmcRemedyforce.Category',
    'QUEUE': 'BmcRemedyforce.Queue',
    'BROADCAST': 'BmcRemedyforce.Broadcast'
}

SALESFORCE_QUERIES: Dict[str, str] = {
    'SERVICE_REQUEST_DEF_NAME': 'select id,name from BMCServiceDesk__SRM_RequestDefinition__c where name=\'{}\'',
    'GET_ID_FROM_NAME': 'select id from BMCServiceDesk__Incident__c where name=\'{}\'',
    'GET_TEMPLATE_DETAILS': 'select id,name,BMCServiceDesk__description__c,'
                            'BMCServiceDesk__HasRecurrence__c from BMCServiceDesk__SYSTemplate__c '
                            'where IsDeleted=false and BMCServiceDesk__inactive__c = false '
                            'and BMCServiceDesk__systemTemplate__c = false '
                            'and BMCServiceDesk__templateFor__c = \'Incident\' ',
    'GET_USER_DETAILS': 'select id,name, firstname, lastname, username, email, phone, companyname, '
                        'division, department, title, BMCServiceDesk__IsStaffUser__c, BMCServiceDesk__Account_Name__c '
                        'from user where isactive=true and BMCServiceDesk__User_License__c != null',
    'GET_USER_DETAILS_USING_QUEUE': 'id IN (SELECT userOrGroupId FROM groupmember WHERE group.name =\'{}\')',
    "GET_ID_FROM_SERVICE_REQUEST_NUMBER": "select id, name, BMCServiceDesk__isServiceRequest__c from "
                                          "BMCServiceDesk__Incident__c where name = '{}'",
    "GET_IMPACTS": 'select id,name from BMCServiceDesk__Impact__c where IsDeleted=false and '
                   'BMCServiceDesk__inactive__c = false',
    "FETCH_INCIDENT_QUERY": "select  lastmodifieddate,BMCServiceDesk__FKOpenBy__r.name,"
                            " BMCServiceDesk__outageto__c,BMCServiceDesk__outagefrom__c,"
                            "BMCServiceDesk__FKbmc_baseelement__r.name,BMCServiceDesk__FKserviceoffering__r.name,"
                            "BMCServiceDesk__FKBusinessservice__r.name,BMCServiceDesk__closedatetime__c,"
                            "BMCServiceDesk__opendatetime__c, BMCServiceDesk__respondeddatetime__c,"
                            " BMCServiceDesk__FKBroadcast__r.name,BMCServiceDesk__incidentResolution__c,"
                            " BMCServiceDesk__FKRequestDefinition__r.name,"
                            "BMCServiceDesk__FKTemplate__r.name,LastModifiedById,"
                            "BMCServiceDesk__FKTemplate__c,id,BMCServiceDesk__Priority_ID__c,"
                            "BMCServiceDesk__Type__c,name, CreatedDate,"
                            " BMCServiceDesk__incidentDescription__c,"
                            "BMCServiceDesk__Category_ID__c, BMCServiceDesk__Impact_Id__c,"
                            " BMCServiceDesk__Urgency_ID__c, BMCServiceDesk__Status_ID__c,"
                            " BMCServiceDesk__dueDateTime__c, BMCServiceDesk__queueName__c,"
                            " BMCServiceDesk__Client_Account__c, BMCServiceDesk__Client_Name__c,"
                            " BMCServiceDesk__isServiceRequest__c from BMCServiceDesk__Incident__c "
                            "where {0} IsDeleted=false and BMCServiceDesk__inactive__c = false "
                            "and BMCServiceDesk__isServiceRequest__c = {1} and"
                            " BMCServiceDesk__ServiceRequest__c = \'{2}\' "
                            "and LastModifiedDate > {3} ORDER BY LastModifiedDate ASC NULLS LAST LIMIT {4}",
    'GET_SERVICE_OFFERING_DETAILS': 'select id,name from BMCServiceDesk__BMC_BaseElement__c '
                                    'where BMCServiceDesk__ServiceType__c = \'Offering\' '
                                    'and IsDeleted=false and BMCServiceDesk__inactive__c = false ',
    'GET_ASSET_DETAILS': 'select id,name,BMCServiceDesk__Description__c,BMCServiceDesk__ClassName__c,'
                         'BMCServiceDesk__CITag__c,BMCServiceDesk__InstanceType__c '
                         'from BMCServiceDesk__BMC_BaseElement__c '
                         'where IsDeleted=false and BMCServiceDesk__inactive__c = false ',
    'GET_URGENCY_DETAILS': 'select id,name from BMCServiceDesk__Urgency__c where IsDeleted=false '
                           'and BMCServiceDesk__inactive__c = false ',
    'FILTER_ASSET_CLASSES': ' and (BMCServiceDesk__InstanceType__c=\'Asset\' or'
                            ' BMCServiceDesk__InstanceType__c=\'CI / Asset\')',
    'FILTER_CI_CLASSES': ' and (BMCServiceDesk__InstanceType__c=\'CI\' or '
                         'BMCServiceDesk__InstanceType__c=\'CI / Asset\')',
    'FILTER_WITH_NAME': ' and name =\'{}\'',
    'ORDER_BY_NAME': ' ORDER by name',
    'GET_ACCOUNT_DETAILS': 'select id,name from Account where BMCServiceDesk__inactive__c=false '
                           'and BMCServiceDesk__Remedyforce_Account__c = true ',
    'GET_STATUS': 'select id,name from BMCServiceDesk__Status__c where BMCServiceDesk__inactive__c=false and '
                  'BMCServiceDesk__appliesToIncident__c=true',
    'GET_CATEGORIES': 'select id,name, BMCServiceDesk__children__c from BMCServiceDesk__Category__c '
                      'where BMCServiceDesk__inactive__c = false',
    'GET_QUEUE_DETAIL': 'select id, name, email from group where type=\'queue\' {}',
    'GET_QUEUE_DETAIL_FOR_SPECIFIC_TYPE': 'SELECT QueueId, Queue.Name, Queue.email FROM '
                                          ' QueueSobject WHERE SobjectType = \'{}\'',
    'GET_BROADCAST_DETAILS': 'select id,name,BMCServiceDesk__Priority_ID__c,BMCServiceDesk__Urgency_ID__c,'
                             'BMCServiceDesk__Impact_ID__c,BMCServiceDesk__broadcastDescription__c,'
                             'BMCServiceDesk__Category_ID__c,BMCServiceDesk__Status_ID__c'
                             ' from BMCServiceDesk__Broadcasts__c where BMCServiceDesk__inactive__c=false',
    'QUERY_AND': ' and ',
    'GET_ATTACHMENTS': 'select Id, ContentDocumentId, ContentDocument.Title, ContentDocument.Description, '
                       'ContentDocument.CreatedDate, ContentDocument.CreatedBy.Name from ContentDocumentLink '
                       'where LinkedEntityId = \'{}\'',
    'GET_NOTES': 'select BMCServiceDesk__note__c, CreatedBy.Name, CreatedDate, '
                 'BMCServiceDesk__incidentId__c,Name,BMCServiceDesk__actionId__c, '
                 'BMCServiceDesk__description__c from BMCServiceDesk__IncidentHistory__c '
                 'where BMCServiceDesk__incidentId__c=\'{}\' and IsDeleted=false',
    'GET_INCIDENTS': "select lastmodifieddate,BMCServiceDesk__FKOpenBy__r.name,"
                     " BMCServiceDesk__outageto__c,BMCServiceDesk__outagefrom__c,"
                     "BMCServiceDesk__FKbmc_baseelement__r.name,BMCServiceDesk__FKserviceoffering__r.name,"
                     "BMCServiceDesk__FKBusinessservice__r.name,BMCServiceDesk__closedatetime__c,"
                     "BMCServiceDesk__opendatetime__c, BMCServiceDesk__respondeddatetime__c,"
                     " BMCServiceDesk__FKBroadcast__r.name,BMCServiceDesk__incidentResolution__c,"
                     " BMCServiceDesk__FKRequestDefinition__r.name,"
                     "BMCServiceDesk__FKTemplate__r.name,"
                     "id,BMCServiceDesk__Priority_ID__c,"
                     "BMCServiceDesk__Type__c,name, CreatedDate,"
                     " BMCServiceDesk__incidentDescription__c,"
                     "BMCServiceDesk__Category_ID__c, BMCServiceDesk__Impact_Id__c,"
                     " BMCServiceDesk__Urgency_ID__c, BMCServiceDesk__Status_ID__c,"
                     " BMCServiceDesk__dueDateTime__c, BMCServiceDesk__queueName__c,"
                     " BMCServiceDesk__Client_Account__c, BMCServiceDesk__Client_Name__c"
                     " from BMCServiceDesk__Incident__c "
                     "where {} IsDeleted=false and BMCServiceDesk__inactive__c = false "
                     "and BMCServiceDesk__isServiceRequest__c = {} and"
                     " BMCServiceDesk__ServiceRequest__c = \'{}\' ORDER BY LastModifiedDate DESC NULLS LAST ",
    'GET_SERVICE_REQUEST': "select lastmodifieddate,BMCServiceDesk__FKOpenBy__r.name,"
                           " BMCServiceDesk__outageto__c,BMCServiceDesk__outagefrom__c,"
                           "BMCServiceDesk__FKbmc_baseelement__r.name,BMCServiceDesk__FKserviceoffering__r.name,"
                           "BMCServiceDesk__FKBusinessservice__r.name,BMCServiceDesk__closedatetime__c,"
                           "BMCServiceDesk__opendatetime__c, BMCServiceDesk__respondeddatetime__c,"
                           " BMCServiceDesk__FKBroadcast__r.name,BMCServiceDesk__incidentResolution__c,"
                           " BMCServiceDesk__FKRequestDefinition__r.name,"
                           "BMCServiceDesk__FKTemplate__r.name,"
                           "id,BMCServiceDesk__Priority_ID__c,"
                           "BMCServiceDesk__Type__c,name, CreatedDate,"
                           " BMCServiceDesk__incidentDescription__c,"
                           "BMCServiceDesk__Category_ID__c, BMCServiceDesk__Impact_Id__c,"
                           " BMCServiceDesk__Urgency_ID__c, BMCServiceDesk__Status_ID__c,"
                           " BMCServiceDesk__dueDateTime__c, BMCServiceDesk__queueName__c,"
                           " BMCServiceDesk__Client_Account__c, BMCServiceDesk__Client_Name__c"
                           " from BMCServiceDesk__Incident__c "
                           "where {} IsDeleted=false and BMCServiceDesk__inactive__c = false "
                           "and BMCServiceDesk__isServiceRequest__c = {} and"
                           " BMCServiceDesk__ServiceRequest__c = \'{}\' ORDER BY LastModifiedDate DESC NULLS LAST "
}

# in seconds
REQUEST_TIMEOUT_MAX_VALUE = 120

AVAILABLE_FIELD_LIST = ["category_id", "queue_id", "staff_id", "status_id", "urgency_id", "client_id", 'impact_id']
DEFAULT_INCIDENT_ARGUMENTS = ['client_id', 'description', 'open_datetime', 'due_datetime', 'queue_id', 'template_id',
                              'category_id', 'urgency_id', 'status_id', 'staff_id', 'impact_id']

ALL_INSTANCE_TYPE: Dict[str, str] = {
    'all_classes': 'All Classes',
    'asset_classes': 'Asset Classes',
    'ci_classes': 'CI Classes'
}
SERVICE_REQUEST_CATEGORY_OBJECT = "BMCServiceDesk__AvailableForServiceCatalog__c"
INCIDENT_CATEGORY_OBJECT = "BMCServiceDesk__AvailableForIncidents__c"
MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS: Dict[str, str] = {
    "client_id": "BMCServiceDesk__FKClient__c",
    "template_id": "BMCServiceDesk__FKTemplate__c",
    "service_request_definition_id": "BMCServiceDesk__FKRequestDefinition__c",
    "category_id": "BMCServiceDesk__FKCategory__c",
    "broadcast_id": "BMCServiceDesk__FKBroadcast__c",
    "description": "BMCServiceDesk__incidentDescription__c",
    "resolution_id": "BMCServiceDesk__incidentResolution__c",
    "impact_id": "BMCServiceDesk__FKImpact__c",
    "urgency_id": "BMCServiceDesk__FKUrgency__c",
    "priority_id": "BMCServiceDesk__FKPriority__c",
    "status_id": "BMCServiceDesk__FKStatus__c",
    "opened_date": "BMCServiceDesk__openDateTime__c",
    "responded_date": "BMCServiceDesk__respondedDateTime__c",
    "due_date": "BMCServiceDesk__dueDateTime__c",
    "closed_date": "BMCServiceDesk__closeDateTime__c",
    "service_id": "BMCServiceDesk__FKBusinessService__c",
    "service_offering_id": "BMCServiceDesk__FKServiceOffering__c",
    "asset_id": "BMCServiceDesk__FKBMC_BaseElement__c",
    "outage_start": "BMCServiceDesk__outageFrom__c",
    "outage_end": "BMCServiceDesk__outageTo__c",
    "queue_id": "OwnerId",
    "staff_id": "BMCServiceDesk__FKOpenBy__c",
    "account_id": "BMCServiceDesk__FKAccount__c",
    "account_name": "BMCServiceDesk__Account_Name__c",
    "is_staff": "BMCServiceDesk__IsStaffUser__c",
    'category': 'BMCServiceDesk__Category_ID__c',
    'impact': 'BMCServiceDesk__Impact_Id__c',
    'urgency': 'BMCServiceDesk__Urgency_ID__c',
    'status': 'BMCServiceDesk__Status_ID__c',
    'queue': 'BMCServiceDesk__queueName__c',
    'description_object': 'BMCServiceDesk__description__c',
    'asset_description_object': 'BMCServiceDesk__Description__c',
    'has_recurrence': 'BMCServiceDesk__HasRecurrence__c',
    'ci_tag': 'BMCServiceDesk__CITag__c',
    'class_name_object': 'BMCServiceDesk__ClassName__c',
    'instance_type_object': 'BMCServiceDesk__InstanceType__c',
    'incident_priority': 'BMCServiceDesk__Priority_ID__c',
    'incident_client_name': 'BMCServiceDesk__Client_Name__c'
}
FIELD_MAPPING_FOR_GET_INCIDENTS = {
    'LastModifiedDate': 'LastUpdatedDate',
    'BMCServiceDesk__FKOpenBy__r': 'Staff',
    'BMCServiceDesk__FKServiceOffering__r': 'ServiceOffering',
    'BMCServiceDesk__FKBusinessService__r': 'BusinessService',
    'BMCServiceDesk__closeDateTime__c': 'closeDateTime',
    'BMCServiceDesk__openDateTime__c': 'OpenDateTime',
    'BMCServiceDesk__FKBroadcast__r': 'Broadcast',
    'BMCServiceDesk__incidentResolution__c': 'Resolution',
    'BMCServiceDesk__FKRequestDefinition__r': 'ServiceRequestDefinition',
    'BMCServiceDesk__FKTemplate__r': 'Template',
    'LastModifiedById': 'LastModifiedBy',
    'Id': 'Id',
    'BMCServiceDesk__Priority_ID__c': 'Priority',
    'BMCServiceDesk__Type__c': 'Type',
    'Name': 'Number',
    'CreatedDate': 'CreatedDate',
    'BMCServiceDesk__incidentDescription__c': 'Description',
    'BMCServiceDesk__Category_ID__c': 'Category',
    'BMCServiceDesk__Impact_Id__c': 'Impact',
    'BMCServiceDesk__Urgency_ID__c': 'Urgency',
    'BMCServiceDesk__Status_ID__c': 'Status',
    'BMCServiceDesk__dueDateTime__c': 'DueDateTime',
    'BMCServiceDesk__queueName__c': 'Queue',
    'BMCServiceDesk__Client_Account__c': 'ClientAccount',
    'BMCServiceDesk__Client_Name__c': 'ClientID'
}
INCIDENT_PREFIX = {
    'Incident': 'IN',
    'Service Request': 'SR'
}

QUEUE_TYPES = {
    'Incident/Service Request': 'BMCServiceDesk__Incident__c'
}

SOAP_LOGIN_URL = f'https://login.salesforce.com/services/Soap/u/{LOGIN_API_VERSION}'


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, username: str, password: str, request_timeout: int, *args, **kwargs):
        """
        BMCRemedyForceClient implements logic to authenticate each http request with bearer token
        :param soap_login_url: Salesforce soap login url, with default value
        """
        super().__init__(*args, **kwargs)
        self._username = username
        self._password = password
        self._request_timeout = request_timeout
        self.proxies = handle_proxy()

        # Throws a ValueError if Proxy is empty in configuration.
        if kwargs.get('proxy', False) and not self.proxies.get('https', ''):
            raise ValueError(MESSAGES['PROXY_ERROR'])

    def http_request(self, method, url_suffix, headers=None, json_data=None, params=None):
        """
        Overrides Base client's _http_request function to authenticate each request with Bearer authorization
        token containing valid session id which is cached in integration context

        :type method: ``str``
        :param method: The HTTP method, for example: GET, POST, and so on.

        :type url_suffix: ``str``
        :param url_suffix: The API endpoint.

        :type headers: ``dict``
        :param headers: Headers to send in the request. If None, will use self._headers.

        :type json_data: ``dict``
        :param json_data: The dictionary to send in a 'POST' request.

        :type params: ``dict``
        :param params: URL parameters to specify the query.

        :return: http response or json content of the response
        :rtype: ``dict`` or ``requests.Response``

        :raises ConnectionError: If there is proxy error or connection error while making the http call.
        :raises DemistoException: If there is any other issues while making the http call.

        """
        session_id = self.get_session_id()
        default_headers = {
            'Authorization': f'Bearer {session_id}'
        }

        if headers:
            default_headers.update(headers)

        # Passing "response" in resp_type, to ensure we always get the full response object and deal with
        # the response type here
        # Passing specific ok_codes from here, to keep the control of dealing with ok codes from this wrapper method
        with http_exception_handler():
            resp = self._http_request(method=method, url_suffix=url_suffix, headers=default_headers,
                                      json_data=json_data, params=params, timeout=self._request_timeout,
                                      resp_type='response', ok_codes=(200, 201, 202, 204, 400, 401, 403, 404, 500),
                                      proxies=self.proxies)
        if resp.ok:
            if resp.status_code == 204:  # Handle empty response
                return resp
            else:
                return resp.json()
        else:
            handle_error_response(resp)

    def get_session_id(self):
        """
        Get session id from Demisto integration context. If not found in integration context or expired,
        generate a new session, set integration context and return session id
        :return: a valid session id to be used as a bearer token to access remedyforce and salesforce api
        """
        integration_context = demisto.getIntegrationContext()
        session_id = integration_context.get('sessionId')
        valid_until = integration_context.get('validUntil')

        # Return session id from integration context, if found and not expired
        if session_id and valid_until and time.time() < valid_until:
            return session_id

        # Generate session and set integration context
        resp = self.get_salesforce_session()
        if resp.status_code == 200:
            resp_root = ElementTree.fromstring(resp.content)
            for session_id in resp_root.iter('{urn:partner.soap.sforce.com}sessionId'):
                integration_context['sessionId'] = session_id.text
            for session_seconds_valid in resp_root.iter('{urn:partner.soap.sforce.com}sessionSecondsValid'):
                shorten_by = 5  # Shorten token validity period by 5 seconds for safety
                if session_seconds_valid.text:
                    integration_context['validUntil'] = time.time() + (float(session_seconds_valid.text) - shorten_by)

            demisto.setIntegrationContext(integration_context)
            return integration_context['sessionId']
        else:
            raise DemistoException(MESSAGES['AUTHENTICATION_CONFIG_ERROR'])

    def get_salesforce_session(self):
        """
        Get salesforce soap login response from soap_login_url for the auth credentials provided in instance parameters
        :return: Xml response from login SOAP call

        :raises ConnectionError: If there is proxy error or connection error while making the http call.
        :raises DemistoException: If there is any other issues while making the http call.
        """

        headers = {
            'Content-Type': 'text/xml',
            'SOAPAction': 'Login'
        }

        request_payload = f"""<env:Envelope xmlns:xsd=" http://www.w3.org/2001/XMLSchema "
            xmlns:xsi=" http://www.w3.org/2001/XMLSchema-instance "
            xmlns:env="http://schemas.xmlsoap.org/soap/envelope/">
          <env:Body>
            <n1:login xmlns:n1="urn:partner.soap.sforce.com">
              <n1:username>{self._username}</n1:username>
              <n1:password>{self._password}</n1:password>
            </n1:login>
          </env:Body>
        </env:Envelope>"""

        with http_exception_handler():
            return self._http_request('POST', '', full_url=SOAP_LOGIN_URL, data=request_payload, headers=headers,
                                      timeout=self._request_timeout, ok_codes=(200, 201, 202, 204, 400, 401, 404, 500),
                                      resp_type='response')


''' HELPER FUNCTIONS '''


@contextlib.contextmanager
def http_exception_handler():
    """
    Exception handler for handling different exceptions while making http calls.
    :return: None

    :raises ConnectionError: If there is proxy error or connection error while making the http call.
    :raises DemistoException: If there is any other issues while making the http call.
    """
    try:
        yield
    except MissingSchema:
        raise DemistoException(MESSAGES['MISSING_SCHEMA_ERROR'])
    except InvalidSchema:
        raise DemistoException(MESSAGES['INVALID_SCHEMA_ERROR'])
    except DemistoException as e:
        if 'Proxy Error' in str(e):
            raise ConnectionError(MESSAGES['PROXY_ERROR'])
        elif 'ConnectionError' in str(e) or 'ConnectTimeout' in str(e):
            raise ConnectionError(MESSAGES['CONNECTION_ERROR'])
        else:
            raise e


def handle_error_response(response: Response) -> None:
    """
    Handles http error response and raises DemistoException with appropriate message.
    :param response: Http response
    :return: None
    :raises DemistoException: With proper error message for different error scenarios
    """
    if response.status_code == 401:
        # Invalidate session from integration context.
        integration_context = demisto.getIntegrationContext()
        integration_context['sessionId'] = None
        integration_context['validUntil'] = 0
        demisto.setIntegrationContext(integration_context)

    error_message = ''
    try:
        if isinstance(response.json(), Dict):
            error_message = response.json().get('message', MESSAGES['UNEXPECTED_ERROR'])
        elif isinstance(response.json(), list) and isinstance(response.json()[0], Dict):
            error_message = response.json()[0].get('message', MESSAGES['UNEXPECTED_ERROR'])
    except ValueError:  # ignoring json parsing errors
        pass

    status_code_messages = {
        400: MESSAGES['BAD_REQUEST_ERROR'].format(error_message),
        401: MESSAGES['AUTHENTICATION_ERROR'],
        404: MESSAGES['NOT_FOUND_ERROR'].format(error_message),
        403: MESSAGES['FORBIDDEN'].format(error_message),
        500: MESSAGES['INTERNAL_SERVER_ERROR'].format(error_message)
    }

    if response.status_code in status_code_messages:
        LOG('Response Code: {}, Reason: {}'.format(response.status_code, status_code_messages[response.status_code]))
        raise DemistoException(status_code_messages[response.status_code])
    else:
        response.raise_for_status()


def is_service_request_number_blank(service_request_number: str) -> str:
    """
    Check if service_request_number is empty or None then raise the exception.

    :param service_request_number: service_request_number
    :type service_request_number: ``str``

    :return: service_request_number
    :rtype: ``str``

    :raises ValueError: if service_request_number is empty or None.
    """
    if service_request_number:
        service_request_number = remove_prefix("sr", service_request_number)
        return service_request_number
    else:
        raise ValueError(MESSAGES["EMPTY_SERVICE_REQUEST"])


def is_parameter_blank(parameter: str, parameter_name: str) -> str:
    """
    Check if parameter is empty or None then raise the exception.

    :param parameter: Parameter
    :type parameter: ``str``

    :param parameter_name: Name of the parameter in string
    :type parameter_name: ``str``

    :return: parameter
    :rtype: ``str``

    :raises ValueError: if parameter is empty or None.
    """
    if not parameter:
        raise ValueError(MESSAGES["EMPTY_REQUIRED_ARGUMENT"].format(parameter_name))
    else:
        return parameter


def get_request_timeout():
    """
    Validate and return the request timeout parameter.
    The parameter must be a positive integer.
    Default value is set to 60 seconds for API request timeout.
    :return: request_timeout: Request timeout value.

    :raises ValueError: if timeout parameter is not a positive integer or exceeds the maximum allowed value
    """
    try:
        request_timeout = int(demisto.params().get('request_timeout'))
    except ValueError:
        raise ValueError(MESSAGES['REQUEST_TIMEOUT_VALIDATION'])

    if request_timeout <= 0:
        raise ValueError(MESSAGES['REQUEST_TIMEOUT_VALIDATION'])
    elif request_timeout > REQUEST_TIMEOUT_MAX_VALUE:
        raise ValueError(MESSAGES['REQUEST_TIMEOUT_EXCEED_ERROR'])
    return request_timeout


def validate_max_incidents(max_incidents: str) -> None:
    """
    Validates the value of max_incident parameter.

    :params max_incidents: In fetch-incident maximum number of incidents to return.
    :raises ValueError: if max incidents parameter is not a positive integer.
    :return: None
    """
    try:
        max_incidents_int = int(max_incidents)
        if max_incidents_int <= 0:
            raise ValueError
    except ValueError:
        raise ValueError(MESSAGES['INVALID_MAX_INCIDENT_ERROR'])


def prepare_query_for_fetch_incidents(params: Dict[str, str], start_time: int) -> str:
    """
    Prepares a query for fetch-incidents.

    :param params: Dictionary contains parameters.
    :param start_time: Timestamp to start fetch after.
    :raises ValueError: if query is none as well as type parameter is none.
    :return: string query.
    """
    start_time = timestamp_to_datestring(start_time, is_utc=True)
    if params.get('query', ''):
        # If query parameter is provided.
        query = params['query'].lower()
        where_count = query.count('where')

        if where_count > 1:
            raise ValueError(MESSAGES['MULTIPLE_WHERE_CLAUSE_ERROR'])
        elif where_count == 0:
            if query.count('from'):
                from_search_end = re.search(pattern='from \\w+', string=query).end()  # type: ignore
                return query[:from_search_end] + ' where LastModifiedDate > {}' \
                    .format(start_time) + query[from_search_end:]
            raise ValueError(MESSAGES['INVALID_FETCH_INCIDENT_QUERY_ERROR'])

        where_search_end = re.search(pattern='where', string=query).end()  # type: ignore
        return query[:where_search_end] + ' LastModifiedDate > {} and'.format(
            start_time) + query[where_search_end:]

    max_incidents = params.get('max_fetch', '10')
    validate_max_incidents(max_incidents)

    if not params.get('type', ''):
        raise ValueError(MESSAGES['PARAMETER_TYPE_EMPTY_ERROR'])

    fetch_type = ('false', 'No') if params['type'] == 'BMC Remedyforce Incident' else ('true', 'Yes')

    fields = ''
    for param_key, param_val in params.items():
        if param_key in ['category', 'impact', 'urgency', 'status', 'queue'] and param_val:
            fields += '{0}=\'{1}\''.format(MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS[param_key], param_val)
            fields += SALESFORCE_QUERIES['QUERY_AND']

    return SALESFORCE_QUERIES['FETCH_INCIDENT_QUERY'].format(fields, *fetch_type,
                                                             start_time,
                                                             max_incidents)


def prepare_iso_date_string(date_string: str) -> str:
    """
    Prepares iso date string from date string.

    :param date_string: String representing date.
    :return: string representing date in iso format.
    """
    if date_string:
        parsed_date = dateparser.parse(date_string)
        return parsed_date.isoformat() if parsed_date else ''
    return ''


def prepare_date_or_markdown_fields_for_fetch_incidents(fields: Dict[str, Any]) -> None:
    """
    Prepares the date and markdown fields for incident or service request.

    :param fields: fields received in response of incident or service requests.
    :returns: None
    """

    fields['BMCServiceDesk__closeDateTime__c'] = prepare_iso_date_string(
        fields.get('BMCServiceDesk__closeDateTime__c', ''))
    fields['BMCServiceDesk__dueDateTime__c'] = prepare_iso_date_string(
        fields.get('BMCServiceDesk__dueDateTime__c', ''))
    fields['CreatedDate'] = prepare_iso_date_string(fields.get('CreatedDate', ''))
    fields['BmcLastModifiedDate'] = prepare_iso_date_string(fields.get('LastModifiedDate', ''))
    fields['BMCServiceDesk__openDateTime__c'] = prepare_iso_date_string(
        fields.get('BMCServiceDesk__openDateTime__c', ''))
    fields['BMCServiceDesk__outageFrom__c'] = prepare_iso_date_string(fields.get('BMCServiceDesk__outageFrom__c', ''))
    fields['BMCServiceDesk__outageTo__c'] = prepare_iso_date_string(fields.get('BMCServiceDesk__outageTo__c', ''))
    fields['BMCServiceDesk__respondedDateTime__c'] = prepare_iso_date_string(
        fields.get('BMCServiceDesk__respondedDateTime__c', ''))
    fields['Attachments'] = tableToMarkdown('', fields.get('attachments', []),
                                            headers=['File', 'Download Link', DATE_AND_TIME, 'Created By'])
    fields['Notes'] = tableToMarkdown('', fields.get('notes', []),
                                      ['Incident History ID', 'Action~', DATE_AND_TIME, 'Sender',
                                       'Description',
                                       'Note'])
    fields['ServiceRequest'] = tableToMarkdown('', fields.get('service_request_details', {}))
    remove_nulls_from_dictionary(fields)


def validate_params_for_fetch_incidents(params: Dict[str, Any]) -> None:
    """
    Validates parameters for fetch-incidents command.

    :param params: parameters dictionary.
    """
    if params.get('isFetch', False):
        query = params.get('query', '')
        if query:
            from_count = query.count('from')
            if from_count < 1:
                raise ValueError(MESSAGES['INVALID_FETCH_INCIDENT_QUERY_ERROR'])
            where_count = query.count('where')
            if where_count > 1:
                raise ValueError(MESSAGES['MULTIPLE_WHERE_CLAUSE_ERROR'])
        else:
            validate_max_incidents(params.get('max_fetch', 10))
            if not params.get('type', ''):
                raise ValueError(MESSAGES['PARAMETER_TYPE_EMPTY_ERROR'])


def prepare_incident_for_fetch_incidents(record: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prepares incident dictionary as per demisto standard.

    :param record: Dictionary containing information of incident.
    :param params: Demisto parameters.
    :return: Dictionary containing information related to incident.
    """
    record = remove_empty_elements(record)

    name = record.get('Name', '')
    if record.get('BMCServiceDesk__Type__c', ''):
        name = '{0}{1}'.format(INCIDENT_PREFIX.get(record['BMCServiceDesk__Type__c'], ''),
                               record.get('Name', ''))

    prepare_date_or_markdown_fields_for_fetch_incidents(record)

    # Setting severity from priority
    record['Bmc Severity'] = PRIORITY_TO_SEVERITY_MAP.get(record.get('BMCServiceDesk__Priority_ID__c', 0), 0)

    incident = {
        'name': name,
        'rawJSON': json.dumps(record),
        'details': json.dumps(record) if params.get('query', '') else ''
    }

    remove_nulls_from_dictionary(incident)
    return incident


def prepare_outputs_for_categories(records: List[Dict[str, Any]]) -> \
        Tuple[List[Dict[str, Optional[Any]]], List[Dict[str, Optional[Any]]]]:
    """
    Prepares human readables and context output for 'bmc-remedy-category-details-get' command.

    :param records: List containing records of categories from rest API.
    :return: Tuple containing human-readable and context-ouputs.
    """
    outputs = list()
    hr_output = list()
    for each_record in records:
        temp = dict()
        temp1 = dict()
        temp["Id"] = temp1["Id"] = each_record.get("Id")
        temp["Name"] = temp1["Name"] = each_record.get("Name")
        temp["Children Count"] = temp1["ChildrenCount"] = each_record.get("BMCServiceDesk__children__c")
        hr_output.append(temp)
        outputs.append(temp1)
    return hr_output, outputs


def prepare_broadcast_details_get_output(broadcast_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Prepares context output for broadcast_details_get command.

    :param broadcast_records: List containing dictionaries of user records.
    :return: prepared context output list.
    """
    return [{'Id': record.get('Id', ''),
             'Name': record.get('Name', ''),
             'Description': record.get('BMCServiceDesk__broadcastDescription__c', ''),
             'Category': record.get('BMCServiceDesk__Category_ID__c', ''),
             'Status': record.get('BMCServiceDesk__Status_ID__c', ''),
             'Priority': record.get('BMCServiceDesk__Priority_ID__c', ''),
             'Urgency': record.get('BMCServiceDesk__Urgency_ID__c', ''),
             'Impact': record.get('BMCServiceDesk__Impact_ID__c', ''),
             } for record in broadcast_records]


def prepare_query_for_queue_details_get(args: Dict[str, Any]) -> str:
    """
    Prepares query for bmc-remedyforce-queue-details-get-command.

    :param args: Command arguments.
    :return: query string.
    """
    queue_name = args.get('queue_name', '')
    queue_type = args.get('type', '')
    if queue_type:
        queue_name = ' and queue.name = \'{}\''.format(queue_name) if queue_name else ''
        return SALESFORCE_QUERIES['GET_QUEUE_DETAIL_FOR_SPECIFIC_TYPE'].format(
            QUEUE_TYPES.get(queue_type, queue_type)) + queue_name

    queue_name = ' and name = \'{}\''.format(queue_name) if queue_name else ''
    return SALESFORCE_QUERIES['GET_QUEUE_DETAIL'].format(queue_name)


def prepare_queue_details_get_output(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Prepares context output for queue_details_get command.

    :param records: List containing dictionaries of queue records.
    :return: prepared context output list.
    """
    return [{'Id': record.get('QueueId', '') if record.get('QueueId', '') else record.get('Id', ''),
             'Name': record.get('Queue', {}).get('Name', '') if record.get('Queue', {}) else record.get('Name', ''),
             'Email': record.get('Queue', {}).get('Email', '') if record.get('Queue', {}) else record.get('Email', '')
             } for record in records]


''' REQUESTS FUNCTIONS '''


@logger
def process_single_service_request_definition(res) -> dict:
    """
    Process single service request definition response object
    :param res: service request definition object
    :return: processed object for context
    """
    # Removing unnecessary fields from questions objects
    required_question_fields = ['IsRequired', 'Text', 'Type', 'Id']
    filtered_questions = [{key: value for (key, value) in question.items() if key in required_question_fields} for
                          question in res.get('Questions', [])]

    srd_context = {
        'Id': res.get('Id', ''),
        'CategoryId': res.get('CategoryId', ''),
        'IsProblem': res.get('IsProblem', ''),
        'LastModifiedDate': res.get('LastModifiedDate', ''),
        'CreatedDate': res.get('CreatedDate', ''),
        'Questions': createContext(data=filtered_questions, removeNull=True),
        'Conditions': createContext(data=res.get('Conditions', []), removeNull=True)
    }

    # For checking each name in field, to ensure the standard keys are not replaced in the context,
    # e.g. there is a field called 'id' in the fields objects
    standard_key_set = set(key.strip().lower() for key in srd_context)

    # Creating a dictionary of Name: Value pairs for fields where name and value fields exist
    fields = {field['Name']: field['Value'] for field in res.get('Fields', []) if
              'Name' in field and 'Value' in field and field['Name'].strip().lower() not in standard_key_set}

    # Merge fields with context output
    srd_context.update(fields)

    return srd_context


def process_single_service_request_definition_output(res) -> dict:
    """
    Process single service request definition response object for output
    :param res: service request definition object
    :return: processed object for output
    """
    service_request_definition_name = ''
    for field in res.get('Fields', []):
        if field.get('Name', '') == 'title':
            service_request_definition_name = field.get('Value', '')

    questions = ''
    for question in res.get('Questions', []):
        questions += (('\n\n' if len(questions) > 0 else '')
                      + 'Id: ' + question.get('Id', '')
                      + '\nQuestion: ' + question.get('Text', '')
                      + '\nIs Required: ' + ('Yes' if question.get('IsRequired', False) else 'No'))

    return {
        'Service Request Definition Id': res.get('Id', ''),
        'Service Request Definition Name': service_request_definition_name,
        'Questions': questions
    }


def prepare_context_for_get_service_request_definitions(resp: dict) -> list:
    """
    Prepare context for get service request definition command.
    :param resp: Dictionary of response of the API.
    :return: List of objects for Context.
    """

    return [process_single_service_request_definition(resp.get('Result')) if isinstance(resp.get('Result'), dict)
            else process_single_service_request_definition(res) for res in resp.get('Result', [])]


def prepare_hr_output_for_get_service_request_definitions(resp: dict):
    """
    Prepare hr output for get service request definition command.

    :param resp: Dictionary of response of the API.
    :return: List of objects or dictionary for output.
    """
    if isinstance(resp.get('Result'), dict):
        return process_single_service_request_definition_output(resp.get('Result'))
    else:
        return [process_single_service_request_definition_output(res) for res in resp.get('Result', [])]


def get_service_request_def_id_from_name(name, client) -> str:
    """
    Get service request definition id for the passed name
    :param name: Service request definition name
    :param client: client object
    :return: Service request definition id if found, else an empty string
    :raises ConnectionError: If there is proxy error or connection error while making the http call.
    :raises DemistoException: If there is any other issues while making the http call or id could not be found in
                    the response
    """
    if name is None or len(name.strip()) < 1:
        return ''

    query = SALESFORCE_QUERIES['SERVICE_REQUEST_DEF_NAME'].format(name.strip())
    query_response = client.http_request(method="GET", url_suffix=URL_SUFFIX['SALESFORCE_QUERY'], params={'q': query})
    if len(query_response.get('records', [])) > 0 and isinstance(query_response.get('records', [])[0], Dict):
        return query_response.get('records', [])[0].get('Id', 0)
    else:
        return ''


def get_id_from_incident_number(client: Client, request_number: str, incident_type: Optional[str] = None):
    """
    Retrieve id of input request_number

    :param client: client object
    :param request_number: incident or service request number
    :param incident_type: incident type - IN/SR, default value being None
    :return: string: id of incident or service request number
    """

    query = SALESFORCE_QUERIES.get('GET_ID_FROM_NAME', '')
    query = query.format(request_number)

    if incident_type == 'IN':
        query += ' and BMCServiceDesk__isServiceRequest__c=false'
    elif incident_type == 'SR':
        query += ' and BMCServiceDesk__isServiceRequest__c=true'

    url_suffix = URL_SUFFIX.get('SALESFORCE_QUERY', '')

    params = {'q': query}
    api_response = client.http_request('GET', url_suffix=url_suffix, params=params)
    if api_response.get('totalSize', 0) == 0:
        raise ValueError(MESSAGES['NOTE_CREATE_FAIL'].format(request_number))

    output_records = api_response.get('records', '')

    ids = []
    for record in output_records:
        if record.get('Id', ''):
            ids.append({
                'Id': record.get('Id', '')
            })

    if not ids:
        raise ValueError(MESSAGES['NOT_FOUND_ERROR'])
    return ids[0].get('Id', '')


def input_data_create_note(summary: str, notes: str) -> Dict:
    """
    Format input data for create note.

    :param summary: summary passed by user
    :param notes: note passed by user
    :return Dict
    """
    return {
        "ActivityLog": [
            {
                'Summary': summary,
                'Notes': notes
            }
        ]
    }


def get_request_params(data: Dict[str, str], params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate request params from given data.

    :type data: ``dict``
    :param data: Dictionary having data of additional_fields argument.

    :type params: ``dict``
    :param params: Dictionary having data of rest of the arguments.

    :return: Dictionary having data in combinations of additional_fields and rest of the arguments.
    :rtype: ``dict``
    """
    for each_field in data.keys():
        if data.get(each_field):
            params[each_field] = data.get(each_field)
    return params


def generate_params(param: str, param_object: str, body: Dict[str, str]) -> Dict[str, str]:
    """
    Generate Dictionary having key as Mapping object of field mentioned in "param_object" and value as param.

    :type param: ``str``
    :param param: String containing value which will be assigned as value of key mentioned in param_object in body.

    :type param_object: ``str``
    :param param_object: Key for dictionary object.

    :type body: ``dict``
    :param body:

    :rtype: ``dict``
    """
    if MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS.get(param_object):
        body[MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS[param_object]] = param
    else:
        body[param_object] = param
    return body


def get_valid_arguments(data: str, field: str) -> Tuple[Any, List[str]]:
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
    excluded_fields = list()
    temp = dict()
    regex_to_validate_json = re.compile(r"{}".format(VALIDATE_JSON))
    if data:
        if regex_to_validate_json.fullmatch(data):
            fields = data.split(FIELD_DELIMITER)
            for each_field in fields:
                key, value = each_field.split(VALUE_DELIMITER)
                if value and value.strip() != "":
                    temp[key.strip()] = value
                else:
                    excluded_fields.append(key)
            return temp, excluded_fields
        else:
            raise ValueError("{}".format(MESSAGES["INVALID_DATA_FORMAT"]).format(field))
    else:
        return data, excluded_fields


def remove_prefix(prefix: str, field: str) -> str:
    """
    Remove the prefix from given field.

    :type prefix: ``str``
    :param prefix: Prefix which will be removed from field.

    :type field: ``str``
    :param field: String from which prefix will be removed.

    :return: Field after removing prefix from it.
    :rtype: ``str``
    """
    prefix = prefix.upper()
    field_prefix = field[:2]
    field_prefix = field_prefix.upper()
    if field_prefix == prefix:
        field = field[2:]
    return field


def create_service_request(client: Client, service_request_definition: str, answers: List[Dict[str, Any]],
                           excluded_fields: List[str], additional_fields: Optional[Dict[str, Any]],
                           default_args: Dict[str, Any]) -> None:
    """
    Create service request and update rest of the fields in that service request and also update context output.

    :type client: ``object``
    :param client: Instance of Client class.

    :type service_request_definition: ``str``
    :param service_request_definition: Name of service request definition.

    :type answers: ``list``
    :param answers: List of dictionaries containing answers as value of key having respective question_id.

    :type excluded_fields: ``list``
    :param excluded_fields: List of the fields which will not updated in service request.

    :type additional_fields: ``dict``
    :param additional_fields: Dictionary containing key-value pairs which will be passed as "additional_fields"
                              argument.

    :type default_args: ``dict``
    :param default_args: Dictionary containing key-value pairs of default arguments of command.

    :raises DemistoException: If any issues will occur while making the http call to create service request.
    """
    category_id = default_args.get("category_id")
    queue_id = default_args.get("queue_id")
    staff_id = default_args.get("staff_id")
    status_id = default_args.get("status_id")
    urgency_id = default_args.get("urgency_id")
    client_id = default_args.get("client_id")
    body = {
        "Fields": [
            {
                "Name": "requestDefinitionId",
                "Value": service_request_definition
            },
            {
                "Name": "client",
                "Value": client_id if client_id else ""
            }
        ],
        "Answers": answers
    }
    headers = {
        "Content-Type": "application/json"
    }
    response = client.http_request(method='POST', url_suffix=URL_SUFFIX["SERVICE_REQUEST"], headers=headers,
                                   json_data=body)
    if response and response.get("Success"):
        outputs = {
            "Number": response.get('Result', {}).get('Number', 0),
            "Id": response.get('Result', {}).get('Id', 0),
            "CreatedDate": datetime.now().strftime(DATE_FORMAT)
        }
        markdown_message = "{}".format(HR_MESSAGES["SERVICE_REQUEST_CREATE_SUCCESS"]).format(
            response.get('Result', {}).get('Number', 0))
        params = {
            "category_id": category_id,
            "queue_id": queue_id,
            "staff_id": staff_id,
            "status_id": status_id,
            "urgency_id": urgency_id,
            "client_id": client_id
        }
        if additional_fields:
            params = get_request_params(data=additional_fields, params=params)
        params = remove_empty_elements(params)
        resp = update_incident(client, response.get('Result', {}).get('Id', 0), params=params)
        if resp and resp.get("message"):
            markdown_message = "{}".format(MESSAGES["CREATE_SERVICE_REQUEST_WARNING"]).format(
                response.get('Result', {}).get('Number', 0), ", ".join(params.keys()), resp.get("message"))
            hr_output = {
                OUTPUT_PREFIX['SERVICE_REQUEST_WARNING']: outputs
            }

            return_warning(
                message=markdown_message,
                exit=True,
                warning=markdown_message,
                outputs=hr_output,
                ignore_auto_extract=True)
        elif excluded_fields:
            markdown_message = "{}".format(MESSAGES["CREATE_SERVICE_REQUEST_WARNING"]).format(
                response.get('Result', {}).get('Number', 0), ", ".join(excluded_fields), MESSAGES["UNEXPECTED_ERROR"])
            hr_output = {
                OUTPUT_PREFIX['SERVICE_REQUEST_WARNING']: outputs
            }
            return_warning(
                message=markdown_message,
                exit=True,
                warning=markdown_message,
                outputs=hr_output,
                ignore_auto_extract=True)

        return_results(CommandResults(
            outputs_prefix=OUTPUT_PREFIX["SERVICE_REQUEST"],
            outputs_key_field='Number',
            outputs=outputs,
            readable_output=markdown_message,
            raw_response=response
        ))
    elif response:
        raise DemistoException(response.get("ErrorMessage", MESSAGES["UNEXPECTED_ERROR"]))


def update_service_request(client: Client, service_request_number: str, excluded_fields: List[str],
                           additional_fields: Optional[Dict[str, str]], default_args: Dict[str, str]) -> None:
    """
    Fetch respective id from given service request number and update service request and
    return valid context output.

    :type client: ``object``
    :param client: Instance of Client class.

    :type service_request_number: ``str``
    :param service_request_number: Service request number

    :type excluded_fields: ``list``
    :param excluded_fields: List containing field which will not be updated.

    :type category_id: ``str``
    :param category_id: Category Id

    :type urgency_id: ``str``
    :param urgency_id: Urgency Id

    :type client_id: ``str``
    :param client_id: Client Id

    :type queue_id: ``str``
    :param queue_id: Queue Id

    :type staff_id: ``str``
    :param staff_id: Staff Id

    :type status_id: ``str``
    :param status_id: Status Id

    :type additional_fields: ``dict``
    :param additional_fields: Dictionary containing values of rest of the fields which will be updated.

    :type default_args: ``dict``
    :param default_args: Dictionary containing values of default fields which will be updated.

    :raises DemistoException: If request to update rest of the fields will fail.
    :raises DemistoException: If service_request_number is invalid.
    """
    category_id = default_args.get("category_id")
    queue_id = default_args.get("queue_id")
    staff_id = default_args.get("staff_id")
    status_id = default_args.get("status_id")
    urgency_id = default_args.get("urgency_id")
    client_id = default_args.get("client_id")

    endpoint_to_get_id = SALESFORCE_QUERIES["GET_ID_FROM_SERVICE_REQUEST_NUMBER"].format(service_request_number)

    # Check it is service request or not and if it is then find id from Service request number
    response = client.http_request(method='GET', url_suffix=URL_SUFFIX["SALESFORCE_QUERY"],
                                   params={'q': endpoint_to_get_id})
    if response.get('records') and response.get('records', [])[0].get('BMCServiceDesk__isServiceRequest__c'):
        service_request_id = response.get('records', [])[0].get('Id')
    else:
        raise DemistoException("{}".format(MESSAGES["NOT_FOUND_SERVICE_REQUEST"]).format(service_request_number))
    request_params = {
        "category_id": category_id,
        "queue_id": queue_id,
        "staff_id": staff_id,
        "status_id": status_id,
        "urgency_id": urgency_id,
        "client_id": client_id
    }
    if additional_fields:
        request_params = get_request_params(data=additional_fields, params=request_params)
    request_params = remove_empty_elements(request_params)
    resp = update_incident(
        client,
        service_request_id,
        params=request_params
    )
    resp["outputs"]["Number"] = service_request_number
    resp["outputs"]["Id"] = service_request_id
    if resp.get("message"):
        readable_output = HR_MESSAGES['COMMAND_FAILURE'].format(demisto.command(), resp["message"])
        context_output = {
            OUTPUT_PREFIX['SERVICE_REQUEST_WARNING']: resp["outputs"]
        }

        return_error(
            message=readable_output,
            error=readable_output,
            outputs=context_output)
    else:
        if excluded_fields:
            markdown_message = "{}".format(
                MESSAGES["UPDATE_SERVICE_REQUEST_WARNING"]).format(
                service_request_number, ", ".join(excluded_fields), MESSAGES["UNEXPECTED_ERROR"])
            outputs = {
                OUTPUT_PREFIX['SERVICE_REQUEST_WARNING']: resp["outputs"]
            }

            return_warning(
                message=markdown_message,
                exit=True,
                warning=markdown_message,
                outputs=outputs,
                ignore_auto_extract=True)
        else:
            return_results(CommandResults(
                outputs_prefix=OUTPUT_PREFIX["SERVICE_REQUEST"],
                outputs_key_field='Number',
                outputs=resp["outputs"],
                readable_output="{}".format(
                    HR_MESSAGES["SERVICE_REQUEST_UPDATE_SUCCESS"]).format(service_request_number)
            ))


def update_incident(client: Client, incident_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Common method to update incident/service request.

    :type client: ``object``
    :param client: Instance of Client class.

    :type incident_id: ``str``
    :param incident_id: Incident Id.

    :type params: ``dict``
    :param params: Http request params.

    :return: Dictionary containing context output and error messages.
    :rtype: ``dict``
    """
    body: Dict[str, str] = {}
    outputs = {}
    endpoint = "{}/{}".format(URL_SUFFIX["UPDATE_INCIDENT"], incident_id)
    params = remove_empty_elements(params)
    for each_param in params:
        body = generate_params(params[each_param], each_param, body)
    headers = {
        "Content-Type": "application/json",
    }
    try:
        http_response = client.http_request(method='PATCH', url_suffix=endpoint, headers=headers,
                                            json_data=body)
        if isinstance(http_response, Response) and http_response.status_code == 204 and not http_response.text:
            outputs["LastUpdatedDate"] = datetime.now().strftime(DATE_FORMAT)
        return {
            "outputs": outputs
        }
    except DemistoException as e:
        message = str(e) if str(e) else MESSAGES['UNEXPECTED_ERROR']
        return {
            "outputs": outputs,
            "message": message
        }


def create_template_output(result: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Prepares data for context and human readable

    :param result: list of raw data
    :return: list
    """
    template_readable_list = []

    for result_row in result:
        template_readable_list.append({
            'Id': result_row.get('Id', ''),
            'Name': result_row.get('Name', ''),
            'Description': result_row.get(MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['description_object'], ''),
            'Recurring': result_row.get(MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['has_recurrence'], '')
        })
    return template_readable_list


def create_hr_context_output(result: list) -> list:
    """
    For creating context and human readable

    :param result: list of raw data
    :return: list
    """
    hr_context_output_list = []
    for result_row in result:
        hr_context_output_list.append({
            'Id': result_row.get('Id', ''),
            'Name': result_row.get('Name', '')
        })
    return hr_context_output_list


def get_update_incident_payload(args: Dict[str, str]) -> Tuple[Dict[str, Any], List[str]]:
    """
    Processes command arguments for update incident api call payload
    :param args: Command arguments
    :return: Tuple containing dictionary of update request payload and list of field names to be updated
    """

    # Update request body for default arguments
    update_request_body = \
        {MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS[key]: value for (key, value) in args.items() if
         len(value.strip()) > 0 and key in MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS.keys()
         and key != 'additional_fields'}

    # List of user friendly fields list
    fields = list(args.keys())

    if args.get('additional_fields', '').strip() == '':
        return update_request_body, fields

    additional_fields = get_valid_arguments(args.get('additional_fields', ''), 'additional_fields')[0]

    additional_fields_body = {
        (MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS[key] if
         key in MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS.keys() else key): value for (key, value) in
        additional_fields.items()
    }

    # Throw error if additional fields contain default argument fields
    invalid_fields = [key for (key, value) in additional_fields.items() if key in DEFAULT_INCIDENT_ARGUMENTS]
    if len(invalid_fields) > 0:
        raise DemistoException(MESSAGES['INVALID_ADDITIONAL_ARGUMENT'].format(', '.join(invalid_fields)))

    # Merge default fields and fields found in additional arguments
    update_request_body.update(additional_fields_body)

    fields = fields + list(additional_fields.keys())
    fields.remove("additional_fields")

    return update_request_body, fields


def validate_and_get_date_argument(args: Dict[str, Any], key: str, field_name: str) -> Optional[datetime]:
    """
    Validates and gets a key as per one of the ALLOWED_DATE_FORMATs from the arguments, if exists.

    :param args: Dictionary containing date field
    :param key: key that contains date field
    :param field_name: user-friendly name of the date field
    :return: Date, if one could be parsed, else None

    :raises ValueError: if data for a date field key exists but cannot be parsed.
    """
    if key in args:
        try:
            try:
                date = datetime.strptime(args[key], ALLOWED_DATE_FORMAT_1)
            except ValueError:
                try:
                    date = datetime.strptime(args[key], ALLOWED_DATE_FORMAT_2)
                except ValueError:
                    date = datetime.strptime(args[key], ALLOWED_DATE_FORMAT_3)

            return date
        except ValueError:
            raise ValueError(MESSAGES['DATE_PARSE_ERROR'].format(field_name))
    return None


def validate_incident_update_payload(payload: Dict[str, Any]) -> None:
    """
    Validates incident update payload.

    :param payload: incident update payload dictionary
    :return: None

    :raises ValueError: If the provided data is not valid for updating an incident.
    """
    opened_date = validate_and_get_date_argument(payload,
                                                 MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['opened_date'],
                                                 'opened_date')
    due_date = validate_and_get_date_argument(payload,
                                              MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['due_date'], 'due_date')
    outage_start = validate_and_get_date_argument(payload,
                                                  MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['outage_start'],
                                                  'outage_start')
    outage_end = validate_and_get_date_argument(payload,
                                                MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['outage_end'], 'outage_end')

    if opened_date and due_date and not opened_date < due_date:
        raise ValueError(MESSAGES['DATE_VALIDATION_ERROR'].format('due_date', 'opened_date'))

    if outage_start and outage_end and not outage_start < outage_end:
        raise ValueError(MESSAGES['DATE_VALIDATION_ERROR'].format('outage_end', 'outage_start'))


def remove_extra_space_from_args(args: Dict[str, str]) -> Dict[str, str]:
    """
    Remove leading and trailing spaces from all the arguments and remove empty arguments
    :param args: Dictionary of arguments
    :return: Dictionary of arguments
    """
    return {key: value.strip() for (key, value) in args.items() if value and len(value.strip()) > 0}


def create_asset_output(result: List[Dict[str, Any]], output_type: str) -> List[Dict[str, str]]:
    """
    Prepares data for context and human readable

    :param result: list of raw data
    :param output_type:to check creating context or human readable
    :return: list
    """
    asset_readable_list = []
    if output_type == 'hr':
        for result_row in result:
            asset_readable_list.append({
                'Id': result_row.get('Id', ''),
                'Name': result_row.get('Name', ''),
                'Description': result_row.get(MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['asset_description_object'],
                                              ''),
                'Asset #': result_row.get(MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['ci_tag'], ''),
                'Class Name': result_row.get(MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['class_name_object'], ''),
                'Instance Type': result_row.get(MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['instance_type_object'], ''),
            })
    else:
        for result_row in result:
            asset_readable_list.append({
                'Id': result_row.get('Id', ''),
                'Name': result_row.get('Name', ''),
                'Description': result_row.get(MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['asset_description_object'],
                                              ''),
                'Asset_Number': result_row.get(MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['ci_tag'], ''),
                'Class_Name': result_row.get(MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['class_name_object'], ''),
                'Instance_Type': result_row.get(MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['instance_type_object'], ''),
            })

    return asset_readable_list


def create_asset_query(asset_name: str, instance_type: str) -> str:
    """
    Prepare query with asset_name and instance_type

    :param asset_name: asset name
    :param instance_type: asset's instance type
    :return: string
    """
    append_query = ''
    if asset_name:
        append_query = append_query + SALESFORCE_QUERIES['FILTER_WITH_NAME'].format(asset_name)
    if instance_type == ALL_INSTANCE_TYPE['asset_classes']:
        append_query = append_query + SALESFORCE_QUERIES['FILTER_ASSET_CLASSES']
    elif instance_type == ALL_INSTANCE_TYPE['ci_classes']:
        append_query = append_query + SALESFORCE_QUERIES['FILTER_CI_CLASSES']
    elif instance_type and instance_type != "All Classes":
        append_query = append_query + 'and BMCServiceDesk__InstanceType__c=\'{}\' '.format(instance_type)

    return append_query


def prepare_query_for_user_details_get(args: Dict[str, Any]) -> str:
    """
    Prepares query for bmc-remedyforce-user-details-get-command.

    :param args: Command arguments.
    :return: query string.
    """
    query = ''
    for arg_key, arg_val in args.items():
        if arg_val:
            query += SALESFORCE_QUERIES['QUERY_AND'] if query else ''
            if arg_key in ['email', 'username', 'account_name']:
                query += '{0}=\'{1}\''.format(
                    MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS.get(arg_key, arg_key),
                    arg_val.lower())
            elif arg_key == 'queue_name':
                query += SALESFORCE_QUERIES['GET_USER_DETAILS_USING_QUEUE'].format(arg_val)
            elif arg_key == 'is_staff':
                query += '{0}={1}'.format(MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS.get(arg_key, arg_key),
                                          arg_val.lower())

    query = SALESFORCE_QUERIES['QUERY_AND'] + query if query else ''

    return SALESFORCE_QUERIES['GET_USER_DETAILS'] + query


def prepare_user_details_get_output(users_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Prepares context output for user_details_get command.

    :param users_records: List containing dictionaries of user records.
    :return: prepared context output list.
    """
    return [{'Id': record.get('Id', ''),
             'Name': record.get('Name', ''),
             'FirstName': record.get('FirstName', ''),
             'LastName': record.get('LastName', ''),
             'Username': record.get('Username', ''),
             'Email': record.get('Email', ''),
             'Phone': record.get('Phone', ''),
             'Account': record.get('BMCServiceDesk__Account_Name__c', ''),
             'CompanyName': record.get('CompanyName', ''),
             'Division': record.get('Division', ''),
             'Department': record.get('Department', ''),
             'Title': record.get('Title', ''),
             'IsStaff': record.get('BMCServiceDesk__IsStaffUser__c', ''),
             } for record in users_records]


def prepare_note_create_output(record: Dict) -> Dict:
    """
    Prepares context output for user_details_get command.

    :param record: Dict containing note record.
    :return: prepared context output Dict.
    """
    return {
        'Id': record.get('Id', ''),
        'WorkInfoType': record.get('WorkInfoType', ''),
        'ViewAccess': record.get('ViewAccess', ''),
        'Summary': record.get('Summary', ''),
        'Submitter': record.get('Submitter', ''),
        'srId': record.get('srId', ''),
        'Notes': record.get('Notes', ''),
        'ModifiedDate': record.get('ModifiedDate', ''),
        'CreatedDate': record.get('CreatedDate', '')
    }


def get_service_request_details(client: Client, service_request_id: str) -> Dict[str, str]:
    """
    Get service request details for given service_request_id
    :param client: Instance of Client class.
    :param service_request_id: service_request id
    :return: Processed details of service request
    """
    service_request_details: Dict[str, str] = {}
    if not service_request_id or len(service_request_id.strip()) < 1:
        return service_request_details
    response = client.http_request('GET', url_suffix="{}/{}".format(URL_SUFFIX["SERVICE_REQUEST"], service_request_id))
    if response and response.get("Success") and response.get("Result"):
        results = response["Result"]
        if results.get("Answers"):
            answers = results["Answers"]
            for each_answer in answers:
                if each_answer.get("Type") != HEADER_SECTION_TYPE:
                    service_request_details[each_answer['QuestionText']] = each_answer['Text']
    return service_request_details


def process_attachment_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Processes single record of attachment to convert as per the custom incident layout
    :param record: attachment record
    :return: processed attachment record for markdown
    """
    date_time = dateparser.parse(record.get('ContentDocument', {}).get('CreatedDate', ''))
    date = date_time.strftime(DISPLAY_DATE_FORMAT)
    download_url = demisto.params()['url'] + URL_SUFFIX['DOWNLOAD_ATTACHMENT'].format(
        record.get('ContentDocumentId', ''))
    attachment = {
        'File': record.get('ContentDocument', {}).get('Title', 'NA'),
        'Download Link': download_url,
        DATE_AND_TIME: date,
        'Created By': record.get('ContentDocument', {}).get('CreatedBy', {}).get('Name', '')
    }
    return attachment


def get_attachments_for_incident(client: Client, incident_id: str) -> List[Dict[str, Any]]:
    """
    Get attachments for the given incident/service request id
    :param client: Instance of Client class.
    :param incident_id: incident/service_request id
    :return: Processed list of attachments
    """
    attachments: List[Dict] = []
    if not incident_id or len(incident_id.strip()) < 1:
        return attachments

    response = client.http_request('GET', url_suffix=URL_SUFFIX['SALESFORCE_QUERY'],
                                   params={'q': SALESFORCE_QUERIES['GET_ATTACHMENTS'].format(incident_id)})

    records = response.get('records', [])

    return [process_attachment_record(record) for record in records]


def process_notes_record(record: Dict[str, Any]) -> Dict[str, str]:
    """
    Process Note(s) record.

    :type record: ``str``
    :param record: list of notes.

    :return: list
    """
    date_time = dateparser.parse(record.get('CreatedDate', ''))
    date = date_time.strftime(DISPLAY_DATE_FORMAT)
    notes = {
        'Note': record.get('BMCServiceDesk__note__c', ''),
        DATE_AND_TIME: date,
        'Incident History ID': record.get('Name', ''),
        'Action~': record.get('BMCServiceDesk__actionId__c', ''),
        'Description': record.get('BMCServiceDesk__description__c', ''),
        'Sender': record.get('CreatedBy', {}).get('Name', '')

    }
    return notes


def get_notes_for_incident(client: Client, incident_number: str) -> List[Dict[str, Any]]:
    """
    Gets Note(s) from incident or service request.

    :type client: ``object``
    :param client: Instance of Client class.

    :type incident_number: ``str``
    :param incident_number: Incident or service request number.

    :return: list
    """
    notes: List[Dict] = []
    if not incident_number or len(incident_number.strip()) < 1:
        return notes
    response = client.http_request('GET', url_suffix=URL_SUFFIX['SALESFORCE_QUERY'],
                                   params={'q': SALESFORCE_QUERIES['GET_NOTES'].format(incident_number)})

    records = response.get('records', [])
    notes = [process_notes_record(record) for record in records]

    return notes


def create_output_for_incident(result: list) -> list:
    """
    For creating hr and context of incident

    :param result: list of raw data
    :return: list
    """
    hr_output_list = []
    for result_row in result:
        result_row = remove_empty_elements(result_row)
        hr_output_list.append({
            'Number': result_row.get('Name', ''),
            'Priority': result_row.get(MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['incident_priority'], ''),
            'Description': result_row.get(MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS["description"], ''),
            'ClientID': result_row.get(MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['incident_client_name'], ''),
            'Status': result_row.get(MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['status'], ''),
            'Staff': result_row.get('BMCServiceDesk__FKOpenBy__r', {}).get('Name', ''),
            'Queue': result_row.get(MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS['queue'], ''),
            'Id': result_row.get('Id', ''),
            'Category': result_row.get('BMCServiceDesk__Category_ID__c', ''),
            'Urgency': result_row.get('BMCServiceDesk__Urgency_ID__c', ''),
            'dueDateTime': result_row.get('BMCServiceDesk__dueDateTime__c', ''),
            'ClientAccount': result_row.get('BMCServiceDesk__Client_Account__c', ''),
            'Broadcast': result_row.get('BMCServiceDesk__FKBroadcast__r', {}).get('Name', ''),
            'closeDateTime': result_row.get('BMCServiceDesk__closeDateTime__c', ''),
            'Asset': result_row.get('BMCServiceDesk__FKBMC_BaseElement__r', {}).get('Name', ''),
            'CreatedDate': result_row.get('CreatedDate', ''),
            'LastModifiedDate': result_row.get('LastModifiedDate', ''),
            'openDateTime': result_row.get('BMCServiceDesk__openDateTime__c', ''),
            'outageTo': result_row.get('BMCServiceDesk__outageTo__c', ''),
            'outageFrom': result_row.get('BMCServiceDesk__outageFrom__c', ''),
            'Resolution': result_row.get('BMCServiceDesk__incidentResolution__c', ''),
            'respondedDateTime': result_row.get('BMCServiceDesk__respondedDateTime__c', ''),
            'Service': result_row.get('BMCServiceDesk__FKBusinessService__r', {}).get('Name', ''),
            'ServiceOffering': result_row.get('BMCServiceDesk__FKServiceOffering__r', {}).get('Name', ''),
            'Template': result_row.get('BMCServiceDesk__FKTemplate__r', {}).get('Name', ''),
            'Type': result_row.get('BMCServiceDesk__Type__c', ''),
            'Impact': result_row.get('BMCServiceDesk__Impact_Id__c', '')
        })
    return hr_output_list


def prepare_outputs_for_get_service_request(records: List[Dict]) -> Tuple[List, List]:
    """
    Prepares context output and human readable output for service_requests_get command.

    :param records: List containing dictionaries of records.
    :return: tuple containing context output and human readable output.
    """
    outputs: List[Dict] = []
    hr_outputs: List[Dict] = []
    for each_record in records:
        context_dict: Dict[str, str] = {}
        hr_dict: Dict[str, str] = {}
        for each_field in FIELD_MAPPING_FOR_GET_INCIDENTS:
            if each_record.get(each_field):
                if isinstance(each_record[each_field], dict):
                    context_dict[FIELD_MAPPING_FOR_GET_INCIDENTS[each_field]] = each_record[each_field]["Name"]
                else:
                    context_dict[FIELD_MAPPING_FOR_GET_INCIDENTS[each_field]] = each_record[each_field]
        hr_dict['Number'] = each_record["Name"]
        hr_dict['Priority'] = each_record["BMCServiceDesk__Priority_ID__c"]
        hr_dict['Description'] = each_record["BMCServiceDesk__incidentDescription__c"]
        hr_dict['ClientID'] = each_record["BMCServiceDesk__Client_Name__c"]
        hr_dict['Status'] = each_record["BMCServiceDesk__Status_ID__c"]
        hr_dict['Queue'] = each_record["BMCServiceDesk__queueName__c"]
        if each_record.get("BMCServiceDesk__FKOpenBy__r"):
            hr_dict['Staff'] = each_record["BMCServiceDesk__FKOpenBy__r"]["Name"]

        hr_outputs.append(hr_dict)
        outputs.append(context_dict)
    return outputs, hr_outputs


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> None:
    """
    Setting 'ok' result indicates that the integration works like it is supposed to. Connection to the salesforce
    service is successful and we can retrieve user information from the session id generated using provided parameters.

    Args:
        client: BMCHelixRemedyForce client

    Returns: None
    """
    client.http_request('GET', URL_SUFFIX['TEST_MODULE'])
    return_results('ok')


@logger
def fetch_incidents(client: Client, params: Dict[str, Any], last_run: Dict[str, Any], first_fetch: int) -> \
        Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    This function retrieves new incidents every interval.

    :param client: Client object.
    :param params: Parameters for fetch-incidents.
    :param last_run:  A dictionary with a key containing the latest incident modified time which we got from last run.
    :param first_fetch: It contains the timestamp in milliseconds on when to start fetching
                        incidents, if last_run is not provided.
    :returns: Tuple containing two elements. incidents list and timestamp.
    """
    # Retrieving last run time if not none, otherwise first_fetch will be considered.
    start_time = last_run.get('start_time', None)
    start_time = int(start_time) if start_time else first_fetch

    incidents: List[Dict[str, Any]] = []

    query = prepare_query_for_fetch_incidents(params, start_time)
    response = client.http_request('GET', url_suffix=URL_SUFFIX['SALESFORCE_QUERY'], params={'q': query})

    for record in response.get('records', []):
        if record.get('Id'):
            record['attachments'] = get_attachments_for_incident(client, record.get('Id'))
            if record.get('BMCServiceDesk__isServiceRequest__c'):
                record["service_request_details"] = get_service_request_details(client, record.get('Id'))

        if params.get('fetch_note', False):
            record['notes'] = get_notes_for_incident(client, record.get('Name', ''))

        incident = prepare_incident_for_fetch_incidents(record, params)
        incidents.append(incident)

        if record.get('LastModifiedDate', ''):
            latest_modified = date_to_timestamp(record['LastModifiedDate'], date_format='%Y-%m-%dT%H:%M:%S.%f%z')
            if latest_modified > start_time:
                start_time = latest_modified

    next_run = {'start_time': start_time}
    return next_run, incidents


@logger
def bmc_remedy_update_service_request_command(client: Client, args: Dict[str, str]) -> None:
    """
    To update a service request.

    :type client: ``object``
    :param client: Instance of Client class.

    :type args: ``dict``
    :param args: The command arguments provided by user.

    :raises AttributeError: If default argument fields are passed in additional_fields argument.
    :raises ValueError: If any invalid formatted value is given in the addition_fields argument.
    """
    args = remove_extra_space_from_args(args)
    service_request_number = is_service_request_number_blank(args.get("service_request_number", ""))
    additional_fields, excluded_fields = get_valid_arguments(args.get("additional_fields", ""), "additional_fields")
    if additional_fields:
        if isinstance(safe_load_json(additional_fields), dict):
            invalid_fields = list()
            for each_field in additional_fields:
                if each_field in AVAILABLE_FIELD_LIST:
                    invalid_fields.append(each_field)
            if invalid_fields:
                raise AttributeError("{}".format(MESSAGES["INVALID_FIELDS_ERROR"]).format(
                    ", ".join(invalid_fields), "additional_fields"))
        else:
            raise ValueError("{}".format(MESSAGES["INVALID_FORMAT_ERROR"]).format("additional_fields",
                                                                                  "field_id1=value_1; field_2=value_2"))
    update_service_request(client, service_request_number, excluded_fields=excluded_fields,
                           additional_fields=additional_fields, default_args=args)


@logger
def bmc_remedy_create_service_request_command(client: Client, args: Dict[str, str]) -> None:
    """
    To create a service request.

    :type client: ``object``
    :param client: Instance of Client class.

    :type args: ``dict``
    :param args: The command arguments provided by user.

    :raises AttributeError: If any pre-available fields are passed in the additional_fields argument.
    :raises ValueError: If any invalid formatted value is given in the addition_fields or
                        service_request_definition_params argument.
    """
    args = remove_extra_space_from_args(args)
    answers_list = list()
    service_request_definition = is_parameter_blank(args.get("service_request_definition_id", ""),
                                                    "service_request_definition_id")
    answers, excluded_answers = get_valid_arguments(args.get("service_request_definition_params", ""),
                                                    "service_request_definition_params")
    additional_fields, excluded_fields = get_valid_arguments(args.get("additional_fields", ""), "additional_fields")
    if answers and isinstance(safe_load_json(answers), dict):
        for each_answer in answers:
            temp: Dict[str, Any] = dict()
            temp["Values"] = list()
            temp["QuestionId"] = each_answer
            temp["Values"].append(answers[each_answer])
            answers_list.append(temp)
    elif answers:
        raise ValueError("{}".format(MESSAGES["INVALID_FORMAT_ERROR"]).format(
            "service_request_definition_params", "param1=value1; param2=value2"))
    if additional_fields and isinstance(safe_load_json(additional_fields), dict):
        invalid_fields = list()
        for each_field in additional_fields:
            if each_field in AVAILABLE_FIELD_LIST:
                invalid_fields.append(each_field)
        if invalid_fields:
            raise AttributeError("{}".format(MESSAGES["INVALID_FIELDS_ERROR"]).format(
                ", ".join(invalid_fields), "additional_fields"))
    elif additional_fields:
        raise ValueError("{}".format(MESSAGES["INVALID_FORMAT_ERROR"]).format(
            "additional_fields", "field_id1=value_1; field_2=value_2"))
    create_service_request(client, service_request_definition, answers=answers_list,
                           additional_fields=additional_fields,
                           excluded_fields=excluded_fields, default_args=args)


@logger
def bmc_remedy_incident_create_command(client: Client, args: Dict[str, str]) -> None:
    """
    Creates an incident.

    :param client: Client instance
    :param args: Command arguments
    :return:
    """
    # Request body for create incident api call
    args = remove_extra_space_from_args(args)

    if "client_id" not in args:
        raise DemistoException(MESSAGES['EMPTY_REQUIRED_ARGUMENT'].format("client_id"))

    create_request_body = {'Description': args.pop('description', '')}

    # Prepare update request payload and get field names from additional arguments
    update_payload, fields = get_update_incident_payload(args)

    validate_incident_update_payload(update_payload)

    # Call create incident api
    api_response = client.http_request('POST', url_suffix=URL_SUFFIX['CREATE_INCIDENT'], json_data=create_request_body)

    create_result = api_response.get('Result')

    if not api_response.get('Success', False) or not create_result or 'Id' not in create_result:
        raise DemistoException(HR_MESSAGES['CREATE_INCIDENT_FAILURE'].format(
            api_response.get('ErrorMessage', MESSAGES['UNEXPECTED_ERROR'])))

    try:
        id_suffix = '/{}'.format(create_result.get('Id', ''))
        update_api_response = client.http_request('PATCH', URL_SUFFIX['UPDATE_INCIDENT'] + id_suffix,
                                                  json_data=update_payload)

        if isinstance(update_api_response, Response) and update_api_response.status_code == 204:
            readable_output = HR_MESSAGES['CREATE_INCIDENT_SUCCESS'].format(create_result.get('Number', ''))

            return_results(CommandResults(
                outputs_prefix=OUTPUT_PREFIX['INCIDENT'],
                outputs_key_field='Id',
                outputs=create_result,
                readable_output=readable_output,
                raw_response=api_response
            ))

    except Exception as e:
        readable_output = HR_MESSAGES['CREATE_INCIDENT_WARNING'].format(create_result.get('Number', ''),
                                                                        ", ".join(fields), str(e))
        warning_output = create_result
        context_output = {
            OUTPUT_PREFIX['INCIDENT_WARNING']: warning_output
        }
        demisto.error(
            MESSAGES['TRACEBACK_MESSAGE'].format(demisto.command()) + traceback.format_exc())  # print the traceback
        return_warning(
            message=readable_output,
            exit=True,
            warning=readable_output,
            outputs=context_output,
            ignore_auto_extract=True)


@logger
def bmc_remedy_incident_update_command(client: Client, args: Dict[str, str]) -> None:
    args = remove_extra_space_from_args(args)
    incident_number = args.pop('incident_number', '')
    incident_number = incident_number[2:] if incident_number.startswith("IN") else incident_number

    endpoint_to_get_id = SALESFORCE_QUERIES["GET_ID_FROM_SERVICE_REQUEST_NUMBER"].format(incident_number)

    # Get id from incident number
    response = client.http_request(method='GET', url_suffix=URL_SUFFIX["SALESFORCE_QUERY"],
                                   params={'q': endpoint_to_get_id})
    if response.get('records') and not response.get('records', [])[0].get('BMCServiceDesk__isServiceRequest__c'):
        incident_id = response.get('records', [])[0].get('Id')
    else:
        raise DemistoException("{}".format(MESSAGES['NOT_FOUND_INCIDENT']).format(incident_number))

    if not incident_id or incident_id.strip() == '':
        raise ValueError(MESSAGES['NOT_FOUND_ERROR'])

    # Prepare update request payload and get field names from additional arguments
    update_payload, fields = get_update_incident_payload(args)

    validate_incident_update_payload(update_payload)

    context_output = {
        "Id": incident_id,
        "Number": incident_number
    }

    id_suffix = '/{}'.format(incident_id)
    update_api_response = client.http_request('PATCH', URL_SUFFIX['UPDATE_INCIDENT'] + id_suffix,
                                              json_data=update_payload)
    context_output["LastUpdatedDate"] = datetime.now().strftime(DATE_FORMAT)

    if isinstance(update_api_response, Response) and update_api_response.status_code == 204:
        readable_output = HR_MESSAGES['UPDATE_INCIDENT_SUCCESS'].format(incident_number)

        return_results(CommandResults(
            outputs_prefix=OUTPUT_PREFIX['INCIDENT'],
            outputs_key_field='Id',
            outputs=context_output,
            readable_output=readable_output,
            raw_response=context_output
        ))


@logger
def bmc_remedy_note_create_command(client: Client, args: Dict[str, str]) -> Optional[CommandResults]:
    """
    Create a note for incident or service request.

    :param client: client object.
    :param args: Demisto argument(s) provided by user.
    :return: CommandResults which returns detailed results to war room and set context data.
    """
    args = remove_extra_space_from_args(args)
    request_number = is_parameter_blank(args.get('request_number', ''), "request_number")
    prefix = request_number[0:2]
    if prefix == 'IN' or prefix[0:2] == 'SR':
        request_number = remove_prefix(prefix, request_number)
    incident_id = get_id_from_incident_number(client, request_number)

    summary = args.get('summary', '')
    notes = args.get('note', '')
    json_data = input_data_create_note(summary, notes)
    url_suffix = URL_SUFFIX.get('CREATE_NOTE_COMMAND', '')
    url_suffix = url_suffix.format(BMC_API_VERSION, incident_id)

    response = client.http_request('POST', url_suffix, json_data=json_data)
    result_flag = response.get('Result', '')
    result = result_flag.get('ActivityLog', [])[0]
    context_result = prepare_note_create_output(result)

    # set readable output
    readable_output = HR_MESSAGES['NOTE_CREATE_SUCCESS'].format(args.get('request_number', request_number))

    # set Output
    custom_ec = createContext(data=context_result, removeNull=True)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["NOTE"],
        outputs_key_field='Id',
        outputs=custom_ec,
        readable_output=readable_output,
        raw_response=response
    )


@logger
def bmc_remedy_service_request_definition_get_command(client: Client, args: Dict[str, str]) -> Optional[CommandResults]:
    """
    Gets service request definitions.

    :param client: Client instance
    :param args: Command arguments
    :return: CommandResults which returns detailed results to war room.
    """

    args = remove_extra_space_from_args(args)
    service_request_definition_suffix = ''

    if 'service_request_definition_name' in args:
        service_request_definition_name = args.get('service_request_definition_name')
        service_request_definition_id = get_service_request_def_id_from_name(service_request_definition_name, client)
        if service_request_definition_id == '':
            return CommandResults(
                readable_output=HR_MESSAGES['NOT_FOUND_SERVICE_REQUEST_DEF'].format(
                    args.get('service_request_definition_name')))
        else:
            service_request_definition_suffix = '/' + service_request_definition_id

    # call api
    api_response = \
        client.http_request(
            'GET',
            url_suffix=URL_SUFFIX['GET_SERVICE_REQUEST_DEFINITION'] + service_request_definition_suffix)
    success = api_response.get('Success', '')
    if not success:
        raise DemistoException(MESSAGES['FAILED_MESSAGE'].format('get', 'service request definition'))
    else:
        # prepare context
        outputs = prepare_context_for_get_service_request_definitions(api_response)
        custom_ec = createContext(data=outputs, removeNull=True)

        # prepare output
        output_header = MESSAGES['GET_OUTPUT_MESSAGE'].format('service request definition(s)',
                                                              1 if isinstance(api_response.get('Result'), dict)
                                                              else len(api_response.get('Result', [])))
        output_content = prepare_hr_output_for_get_service_request_definitions(api_response)

        # set readable output
        readable_output = tableToMarkdown(output_header, output_content,
                                          headers=['Service Request Definition Id',
                                                   'Service Request Definition Name',
                                                   'Questions'], removeNull=True)

        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX["SERVICE_REQUEST_DEFINITION"],
            outputs_key_field='Id',
            outputs=custom_ec,
            readable_output=readable_output,
            raw_response=api_response
        )


@logger
def bmc_remedy_template_details_get_command(client: Client, args: Dict[str, str]) -> Union[CommandResults, str, None]:
    """
    Gets template details.

    :param client: client object.
    :param args: Demisto argument(s) provided by user.
    :return: CommandResults which returns detailed results to war room and set context data.
    """
    args = remove_extra_space_from_args(args)
    template_name = args.get('template_name', '')

    query = SALESFORCE_QUERIES.get('GET_TEMPLATE_DETAILS', '')
    if template_name:
        template_name = template_name.strip()
        query = query + SALESFORCE_QUERIES['FILTER_WITH_NAME'].format(template_name)

    params = {
        'q': query + SALESFORCE_QUERIES['ORDER_BY_NAME']
    }
    url_suffix = URL_SUFFIX.get('SALESFORCE_QUERY', '')

    response = client.http_request('GET', url_suffix=url_suffix, params=params)

    result = response.get('records', '')

    if result:
        template_result_list = create_template_output(result)
        custom_ec = createContext(data=template_result_list, removeNull=True)

        readable_output = tableToMarkdown(
            HR_MESSAGES['GET_COMMAND_DETAILS_SUCCESS'].format('template(s)', len(template_result_list)),
            template_result_list,
            headers=['Id', 'Name', 'Description', 'Recurring'],
            removeNull=True)
        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX["TEMPLATE"],
            outputs_key_field='Id',
            outputs=custom_ec,
            readable_output=readable_output,
            raw_response=response
        )
    else:
        if template_name:
            return MESSAGES['INVALID_ENTITY_NAME'].format('template_name', template_name)
        else:
            return MESSAGES['NO_ENTITY_FOUND'].format('template(s)')


@logger
def bmc_remedy_service_offering_details_get_command(client: Client, args: Dict) -> Union[CommandResults, str, None]:
    """
    Gets service offering details

    :param client: client object.
    :param args: Demisto argument(s) provided by user.
    :return: CommandResults which returns detailed results to war room and set context data.
    """
    args = remove_extra_space_from_args(args)
    service_offering_name = args.get('service_offering_name', '')

    query = SALESFORCE_QUERIES.get('GET_SERVICE_OFFERING_DETAILS', '')
    if service_offering_name:
        query = query + SALESFORCE_QUERIES['FILTER_WITH_NAME'].format(service_offering_name)

    params = {
        'q': query + SALESFORCE_QUERIES['ORDER_BY_NAME']
    }
    url_suffix = URL_SUFFIX.get('SALESFORCE_QUERY', '')

    response = client.http_request('GET', url_suffix=url_suffix, params=params)

    result = response.get('records')
    if result:
        service_offering_result_list = create_hr_context_output(result)
        custom_ec = createContext(data=service_offering_result_list, removeNull=True)

        readable_output = tableToMarkdown(
            HR_MESSAGES['GET_COMMAND_DETAILS_SUCCESS'].format('service offering(s)',
                                                              len(service_offering_result_list)),
            service_offering_result_list,
            headers=['Id', 'Name'],
            removeNull=True)
        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX['SERVICE_OFFERING'],
            outputs_key_field='Id',
            outputs=custom_ec,
            readable_output=readable_output,
            raw_response=response
        )
    else:
        if service_offering_name:
            return MESSAGES['INVALID_ENTITY_NAME'].format('service_offering_name', service_offering_name)
        else:
            return MESSAGES['NO_ENTITY_FOUND'].format('service offering(s)')


@logger
def bmc_remedy_asset_details_get_command(client: Client, args: Dict[str, str]) -> Union[CommandResults, str, None]:
    """
    Gets asset details.

    :param client: Client instance
    :param args: Command arguments
    :return: CommandResults which returns detailed results to war room.
    """
    args = remove_extra_space_from_args(args)
    asset_name = args.get('asset_name', '')
    instance_type = args.get('instance_type', ALL_INSTANCE_TYPE['all_classes'])

    query = SALESFORCE_QUERIES.get('GET_ASSET_DETAILS', '')
    query = query + create_asset_query(asset_name, instance_type)

    url_suffix = URL_SUFFIX.get('SALESFORCE_QUERY', '')
    params = {
        'q': query + SALESFORCE_QUERIES['ORDER_BY_NAME']
    }

    response = client.http_request('GET', url_suffix=url_suffix, params=params)

    result = response.get('records', '')
    if result:
        assets_result_list_hr = create_asset_output(result, 'hr')
        assets_result_list_context = create_asset_output(result, 'ct')
        custom_ec = createContext(data=assets_result_list_context, removeNull=True)

        readable_output = tableToMarkdown(
            HR_MESSAGES['GET_COMMAND_DETAILS_SUCCESS'].format('asset(s)', len(assets_result_list_hr)),
            assets_result_list_hr,
            headers=['Id', 'Name', 'Description', 'Asset #', 'Class Name', 'Instance Type'], removeNull=True)
        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX['ASSET'],
            outputs_key_field='Id',
            outputs=custom_ec,
            readable_output=readable_output,
            raw_response=response
        )
    else:
        if asset_name or (instance_type and instance_type != ALL_INSTANCE_TYPE['all_classes']):
            return HR_MESSAGES['NO_ASSETS_FOUND']
        else:
            return MESSAGES['NO_ENTITY_FOUND'].format('asset(s)')


@logger
def bmc_remedy_impact_details_get_command(client: Client, args: Dict[str, str]) \
        -> Optional[Union[CommandResults, str, None]]:
    """
    To get details of impact.

    :type client: ``object``
    :param client: Instance of Client class.

    :type args: ``dict``
    :param args: The command arguments provided by user.

    :raises DemistoException: If no records will be found for impacts.
    :raises DemistoException: If any error occurs while execution of API to get impacts.
    """
    args = remove_extra_space_from_args(args)
    endpoint_to_get_impacts = SALESFORCE_QUERIES["GET_IMPACTS"]
    impact_name = args.get("impact_name")
    if impact_name:
        impact_name = impact_name.strip()
        endpoint_to_get_impacts = "{} and name='{}'".format(endpoint_to_get_impacts, impact_name)

    api_response = client.http_request('GET', url_suffix=URL_SUFFIX["SALESFORCE_QUERY"],
                                       params={'q': endpoint_to_get_impacts})

    records = api_response.get("records")
    if records:
        outputs = list()
        for each_record in records:
            temp = dict()
            temp["Id"] = each_record.get("Id")
            temp["Name"] = each_record.get("Name")
            outputs.append(temp)
        markdown = HR_MESSAGES['GET_COMMAND_DETAILS_SUCCESS'].format('impact(s)', len(outputs))
        readable_output = tableToMarkdown(
            markdown, outputs, headers=["Id", "Name"], removeNull=True)
        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX["IMPACT"],
            outputs_key_field="Id",
            outputs=outputs,
            readable_output=readable_output,
            raw_response=records
        )
    else:
        if impact_name:
            return MESSAGES['INVALID_ENTITY_NAME'].format('impact_name', impact_name)
        else:
            return MESSAGES['NO_ENTITY_FOUND'].format('impact(s)')


@logger
def bmc_remedy_account_details_get_command(client: Client, args: Dict[str, str]) -> Union[CommandResults, str, None]:
    """
    Gets account details.

    :param client: Client instance
    :param args: Command arguments
    :return: CommandResults which returns detailed results to war room.
    """
    args = remove_extra_space_from_args(args)
    account_name = args.get('account_name', '')
    query = SALESFORCE_QUERIES.get('GET_ACCOUNT_DETAILS', '')
    if account_name:
        query = query + ' and name =\'{}\''.format(account_name)

    url_suffix = URL_SUFFIX.get('SALESFORCE_QUERY', '')
    params = {
        'q': query + SALESFORCE_QUERIES['ORDER_BY_NAME']
    }

    response = client.http_request('GET', url_suffix=url_suffix, params=params)

    result = response.get('records', '')

    if result:
        accounts_result_list = create_hr_context_output(result)
        custom_ec = createContext(data=accounts_result_list, removeNull=True)

        readable_output = tableToMarkdown(
            HR_MESSAGES['GET_COMMAND_DETAILS_SUCCESS'].format('account(s)', len(result)), accounts_result_list,
            headers=['Id', 'Name'], removeNull=True)
        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX['ACCOUNT'],
            outputs_key_field='Id',
            outputs=custom_ec,
            readable_output=readable_output,
            raw_response=response
        )
    else:
        if account_name:
            return MESSAGES['INVALID_ENTITY_NAME'].format('account_name', account_name)
        else:
            return MESSAGES['NO_ENTITY_FOUND'].format('account(s)')


@logger
def bmc_remedy_status_details_get_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
    Get status details.

    :param client: Client object.
    :param args: Demisto arguments.
    :return: CommandResult object.
    """
    args = remove_extra_space_from_args(args)
    query = SALESFORCE_QUERIES['GET_STATUS']
    query += ' and name=\'{}\''.format(args['status_name']) if 'status_name' in args else ''

    api_response = client.http_request('GET', url_suffix=URL_SUFFIX['SALESFORCE_QUERY'], params={'q': query})
    records = api_response.get('records', [])

    if len(records) == 0:
        if 'status_name' in args:
            return CommandResults(readable_output=HR_MESSAGES['NOT_FOUND_FOR_ARGUMENTS'].format("status"))
        else:
            return CommandResults(readable_output=MESSAGES['NO_ENTITY_FOUND'].format("status"))

    output = [{key: value for (key, value) in record.items() if key == 'Name' or key == 'Id'} for record in records]

    markdown = HR_MESSAGES['GET_COMMAND_DETAILS_SUCCESS'].format('status', len(output))
    readable_output = tableToMarkdown(markdown, output, headers=['Id', 'Name'], removeNull=True)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX['STATUS'],
        outputs_key_field='Id',
        outputs=output,
        readable_output=readable_output,
        raw_response=records)


@logger
def bmc_remedy_urgency_details_get_command(client: Client, args: Dict[str, str]) -> Union[CommandResults, str, None]:
    """
    Gets urgency details.

    :param client: Client instance
    :param args: Command arguments
    :return: CommandResults which returns detailed results to war room.
    """
    args = remove_extra_space_from_args(args)
    urgency_name = args.get('urgency_name', '')

    query = SALESFORCE_QUERIES.get('GET_URGENCY_DETAILS', '')
    if urgency_name:
        query = query + SALESFORCE_QUERIES['FILTER_WITH_NAME'].format(urgency_name)

    params = {
        'q': query
    }
    url_suffix = URL_SUFFIX.get('SALESFORCE_QUERY', '')
    response = client.http_request('GET', url_suffix=url_suffix, params=params)

    result = response.get('records')
    if result:
        urgency_result_list = create_hr_context_output(result)
        custom_ec = createContext(data=urgency_result_list, removeNull=True)

        readable_output = tableToMarkdown(
            HR_MESSAGES['GET_COMMAND_DETAILS_SUCCESS'].format('urgencies',
                                                              len(urgency_result_list)),
            urgency_result_list,
            headers=['Id', 'Name'],
            removeNull=True)
        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX['URGENCY'],
            outputs_key_field='Id',
            outputs=custom_ec,
            readable_output=readable_output,
            raw_response=response
        )
    else:
        if urgency_name:
            return MESSAGES['INVALID_ENTITY_NAME'].format('urgency_name', urgency_name)
        else:
            return MESSAGES['NO_ENTITY_FOUND'].format('urgency')


@logger
def bmc_remedy_category_details_get_command(client: Client, args: Dict[str, str]) \
        -> Optional[Union[CommandResults, str, None]]:
    """
    To get details of categories.

    :type client: ``object``
    :param client: Instance of Client class.

    :type args: ``dict``
    :param args: The command arguments provided by user.

    :raises DemistoException: If exception will occur while rest calls.
    :raises ValueError: If any invalid value is given in the type argument.
    """
    args = remove_extra_space_from_args(args)
    category_type = args.get("type")
    category_name = args.get("category_name")
    endpoint_to_get_category = SALESFORCE_QUERIES["GET_CATEGORIES"]
    error_message = MESSAGES['NO_ENTITY_FOUND'].format('category')
    if category_name:
        endpoint_to_get_category = "{} and name=\'{}\'".format(
            endpoint_to_get_category, category_name)
        error_message = HR_MESSAGES['NOT_FOUND_FOR_ARGUMENTS'].format('category')
    if category_type in POSSIBLE_CATEGORY_TYPES:
        if category_type == "Service Request":
            endpoint_to_get_category = "{} and {}= true".format(
                endpoint_to_get_category, SERVICE_REQUEST_CATEGORY_OBJECT
            )
        elif category_type == "Incident":
            endpoint_to_get_category = "{} and {}= true".format(
                endpoint_to_get_category, INCIDENT_CATEGORY_OBJECT
            )
    elif category_type:
        raise ValueError("{}".format(
            MESSAGES["INVALID_TYPE_FOR_CATEGORIES"]).format("type", "type", ", ".join(POSSIBLE_CATEGORY_TYPES)))

    api_response = client.http_request('GET', url_suffix=URL_SUFFIX["SALESFORCE_QUERY"],
                                       params={'q': endpoint_to_get_category})
    records = api_response.get("records")
    if records:
        hr_output, outputs = prepare_outputs_for_categories(records)
        markdown = HR_MESSAGES['GET_COMMAND_DETAILS_SUCCESS'].format('categories', len(hr_output))
        readable_output = tableToMarkdown(
            markdown, hr_output, headers=["Id", "Name", "Children Count"], removeNull=True)
        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX["CATEGORY"],
            outputs_key_field="Id",
            outputs=outputs,
            readable_output=readable_output,
            raw_response=api_response
        )
    else:
        return error_message


@logger
def bmc_remedy_queue_details_get_command(client: Client, args: Dict[str, Any]) -> Union[CommandResults, str]:
    """
    Get queue(s) details.

    :param client: Client object.
    :param args: demisto arguments.
    :return: Command Result.
    """
    args = remove_extra_space_from_args(args)
    query = prepare_query_for_queue_details_get(args)
    response = client.http_request(method='GET', url_suffix=URL_SUFFIX['SALESFORCE_QUERY'], params={'q': query})

    if not response.get('totalSize', 0):
        return HR_MESSAGES['NO_QUEUE_FOUND']

    output = prepare_queue_details_get_output(response.get('records', []))
    custom_ec = createContext(output, removeNull=True)

    readable_output = tableToMarkdown(
        HR_MESSAGES['GET_COMMAND_DETAILS_SUCCESS'].format('queue(s)', response.get('totalSize', 0)), custom_ec,
        ['Id', 'Name', 'Email'], removeNull=True)
    return CommandResults(outputs_prefix=OUTPUT_PREFIX['QUEUE'], outputs_key_field='Id', outputs=custom_ec,
                          readable_output=readable_output, raw_response=response)


@logger
def bmc_remedy_user_details_get_command(client: Client, args: Dict[str, Any]) -> Union[CommandResults, str]:
    """
    Get user details.

    :param client: Client object.
    :param args: command arguments.
    :return: CommandResults object with context and human-readable.
    """
    args = remove_extra_space_from_args(args)
    query = prepare_query_for_user_details_get(args)
    response = client.http_request(method='GET', url_suffix=URL_SUFFIX['SALESFORCE_QUERY'], params={'q': query})

    if not response.get('totalSize', 0):
        return HR_MESSAGES['NO_USERS_FOUND']

    output = prepare_user_details_get_output(response.get('records', []))
    custom_ec = createContext(output, removeNull=True)
    readable_output = tableToMarkdown(
        HR_MESSAGES['GET_COMMAND_DETAILS_SUCCESS'].format('user(s)', response.get('totalSize', 0)), custom_ec,
        ['Id', 'Username', 'FirstName', 'LastName', 'Account', 'Phone', 'Email', 'Title', 'CompanyName', 'Division',
         'Department', 'IsStaff'], removeNull=True,
        headerTransform=pascalToSpace)

    return CommandResults(outputs_prefix=OUTPUT_PREFIX['USER'], outputs_key_field='Id', outputs=custom_ec,
                          readable_output=readable_output, raw_response=response)


@logger
def bmc_remedy_broadcast_details_get_command(client: Client, args: Dict[str, str]) -> Union[CommandResults, str, None]:
    """
    Get broadcast details.

    :type client: ``object``
    :param client: Instance of Client class.

    :type args: ``dict``
    :param args: The command arguments provided by user.

    :raises DemistoException: If exception will occur while rest calls.
    """
    args = remove_extra_space_from_args(args)
    endpoint_to_get_broadcast = SALESFORCE_QUERIES["GET_BROADCAST_DETAILS"]
    broadcast_name = args.get('broadcast_name')
    category_name = args.get('category_name')
    if broadcast_name:
        endpoint_to_get_broadcast = "{}{}name=\'{}\'".format(
            endpoint_to_get_broadcast, SALESFORCE_QUERIES["QUERY_AND"], broadcast_name
        )
    if category_name:
        endpoint_to_get_broadcast = "{}{}{}=\'{}\'".format(
            endpoint_to_get_broadcast,
            SALESFORCE_QUERIES["QUERY_AND"],
            MAPPING_OF_FIELDS_WITH_SALESFORCE_COLUMNS["category"],
            category_name
        )

    response = client.http_request(method='GET', url_suffix=URL_SUFFIX["SALESFORCE_QUERY"],
                                   params={'q': endpoint_to_get_broadcast})

    if response.get('records'):
        output = prepare_broadcast_details_get_output(response.get('records'))
        custom_ec = createContext(output, removeNull=True)
        markdown_message = HR_MESSAGES['GET_COMMAND_DETAILS_SUCCESS'].format(
            'broadcast(s)', len(response.get('records')))
        readable_output = tableToMarkdown(
            markdown_message,
            custom_ec,
            headers=['Id', 'Name', 'Description', 'Priority', 'Urgency', 'Impact', 'Category', 'Status'],
            removeNull=True, headerTransform=pascalToSpace)
        return CommandResults(outputs_prefix=OUTPUT_PREFIX['BROADCAST'], outputs_key_field='Id', outputs=custom_ec,
                              readable_output=readable_output, raw_response=response)
    else:
        return HR_MESSAGES["NO_BROADCAST_DETAILS_FOUND"]


@logger
def bmc_remedy_incident_get_command(client: Client, args: Dict[str, str]) -> Union[CommandResults, str, None]:
    """
    Gets Incident details.

    :param client: Client instance
    :param args: Command arguments
    :return: CommandResults which returns detailed results to war room.
    """
    args = remove_extra_space_from_args(args)
    incident_time = args.get('last_fetch_time')
    incident_number = args.get('incident_number')
    maximum_incident = args.get('maximum_incident', 50)
    query = ''
    if incident_number:
        incident_number = remove_prefix("IN", incident_number)
        query = query + ' name=\'{}\'{}'.format(incident_number, SALESFORCE_QUERIES['QUERY_AND'])

    if incident_time:
        start_time, _ = parse_date_range(incident_time, date_format=DATE_FORMAT, utc=True)
        query = query + 'LastModifiedDate > {}{}'.format(start_time, SALESFORCE_QUERIES['QUERY_AND'])
    final_query = SALESFORCE_QUERIES.get('GET_INCIDENTS', '').format(query, 'false', 'No')
    if maximum_incident:
        try:
            maximum_incident_int = int(maximum_incident)
        except ValueError:
            raise ValueError(MESSAGES['MAX_INCIDENT_LIMIT'].format('maximum_incident'))
        if not (1 <= int(maximum_incident_int) <= 500):
            raise ValueError(MESSAGES['MAX_INCIDENT_LIMIT'].format('maximum_incident'))
        final_query = final_query + ' LIMIT {}'.format(maximum_incident_int)

    response = client.http_request('GET', url_suffix=URL_SUFFIX['SALESFORCE_QUERY'], params={'q': final_query})

    if response and response.get('records', ''):
        records = response['records']

        incident_result_output = create_output_for_incident(records)
        incident_result_ec = createContext(data=incident_result_output, removeNull=True)

        readable_output = tableToMarkdown(
            HR_MESSAGES['GET_COMMAND_DETAILS_SUCCESS'].format('incident(s)',
                                                              len(incident_result_output)),
            incident_result_output,
            headers=['Number', 'Priority', 'Description', 'ClientID', 'Status', 'Staff', 'Queue'],
            removeNull=True, headerTransform=pascalToSpace)
        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX['INCIDENT'],
            outputs_key_field='Id',
            outputs=incident_result_ec,
            readable_output=readable_output,
            raw_response=response
        )
    else:
        return HR_MESSAGES["NO_INCIDENT_DETAILS_FOUND"]


def bmc_remedy_service_request_get_command(client: Client, args: Dict[str, Any]) -> Union[CommandResults, str, None]:
    """
    Get service request details.

    :type client: ``object``
    :param client: Instance of Client class.

    :type args: ``dict``
    :param args: The command arguments provided by user.

    :raises DemistoException: If exception will occur during http calls.
    :raises ValueError: If value of 'maximum_service_request' parameter will be invalid.
    """
    args = remove_extra_space_from_args(args)
    query = ""
    service_request_number = args.get("service_request_number")
    from_time = args.get("last_fetch_time")
    maximum_service_request = args.get("maximum_service_request", 50)
    if from_time:
        start_time, _ = parse_date_range(from_time, date_format=DATE_FORMAT, utc=True)
        query = "{} LastModifiedDate > {}{}".format(query, start_time, SALESFORCE_QUERIES["QUERY_AND"])
    if service_request_number:
        service_request_number = remove_prefix("sr", service_request_number.strip())
        query = "{}name=\'{}\'{}".format(query, service_request_number, SALESFORCE_QUERIES["QUERY_AND"])
    final_query = SALESFORCE_QUERIES['GET_SERVICE_REQUEST'].format(query, 'true', 'Yes')
    if maximum_service_request:
        try:
            maximum_service_request_int = int(maximum_service_request)
        except ValueError:
            raise ValueError(MESSAGES["MAX_INCIDENT_LIMIT"].format('maximum_service_request'))
        if not (1 <= maximum_service_request_int <= 500):
            raise ValueError(MESSAGES["MAX_INCIDENT_LIMIT"].format('maximum_service_request'))
        final_query = '{} LIMIT {}'.format(final_query, maximum_service_request_int)

    response = client.http_request('GET', url_suffix=URL_SUFFIX['SALESFORCE_QUERY'], params={'q': final_query})

    if response and response.get('records'):
        records = response['records']
        outputs, hr_outputs = prepare_outputs_for_get_service_request(records)
        custom_ec = createContext(hr_outputs, removeNull=True)
        markdown_message = HR_MESSAGES['GET_COMMAND_DETAILS_SUCCESS'].format(
            'service request(s)', len(records))
        readable_output = tableToMarkdown(
            markdown_message,
            custom_ec,
            headers=['Number', 'Priority', 'Description', 'ClientID', 'Status', 'Staff', 'Queue'],
            removeNull=True, headerTransform=pascalToSpace)
        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX['SERVICE_REQUEST'],
            outputs_key_field='Number',
            outputs=outputs,
            readable_output=readable_output,
            raw_response=response
        )
    else:
        return HR_MESSAGES["NO_SERVICE_REQUEST_DETAILS_FOUND"]


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """

    # Commands dictionary
    commands: Dict[str, Callable] = {
        'bmc-remedy-service-request-definition-get': bmc_remedy_service_request_definition_get_command,
        'bmc-remedy-note-create': bmc_remedy_note_create_command,
        'bmc-remedy-service-offering-details-get': bmc_remedy_service_offering_details_get_command,
        'bmc-remedy-template-details-get': bmc_remedy_template_details_get_command,
        'bmc-remedy-impact-details-get': bmc_remedy_impact_details_get_command,
        'bmc-remedy-asset-details-get': bmc_remedy_asset_details_get_command,
        'bmc-remedy-queue-details-get': bmc_remedy_queue_details_get_command,
        'bmc-remedy-account-details-get': bmc_remedy_account_details_get_command,
        'bmc-remedy-user-details-get': bmc_remedy_user_details_get_command,
        'bmc-remedy-status-details-get': bmc_remedy_status_details_get_command,
        'bmc-remedy-urgency-details-get': bmc_remedy_urgency_details_get_command,
        'bmc-remedy-category-details-get': bmc_remedy_category_details_get_command,
        'bmc-remedy-broadcast-details-get': bmc_remedy_broadcast_details_get_command,
        'bmc-remedy-incident-get': bmc_remedy_incident_get_command,
        'bmc-remedy-service-request-get': bmc_remedy_service_request_get_command
    }

    commands_without_return_result: Dict[str, Callable] = {
        "bmc-remedy-service-request-create": bmc_remedy_create_service_request_command,
        "bmc-remedy-service-request-update": bmc_remedy_update_service_request_command,
        "bmc-remedy-incident-create": bmc_remedy_incident_create_command,
        "bmc-remedy-incident-update": bmc_remedy_incident_update_command
    }
    command = demisto.command()
    LOG(f'Command being called is {command}')
    try:

        # Username and password from credentials
        username = demisto.params().get('username')
        password = demisto.params().get('password')

        # Get the service API base url
        base_url = demisto.params()['url']

        # Certificate verification setting
        verify_certificate = not demisto.params().get('insecure', False)

        # System proxy settings
        proxy = demisto.params().get('proxy', False)

        # Get request timeout
        request_timeout = get_request_timeout()

        # Validating params for fetch-incidents.
        validate_params_for_fetch_incidents(demisto.params())

        # Get first fetch time from integration params.
        first_fetch_time = demisto.params().get('first_fetch')

        # getting numeric value from string representation
        start_time, _ = parse_date_range(first_fetch_time, date_format=DATE_FORMAT, utc=True)

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            username=username,
            password=password,
            request_timeout=request_timeout)
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            test_module(client)
        if command == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client=client,
                params=demisto.params(),
                last_run=demisto.getLastRun(),
                first_fetch=date_to_timestamp(start_time, date_format=DATE_FORMAT)
            )

            # saves next_run for the time fetch-incidents is invoked.
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command in commands_without_return_result:
            commands_without_return_result[command](client, demisto.args())

        elif command in commands:
            return_results(commands[command](client, demisto.args()))

        # Log exceptions
    except Exception as e:
        demisto.error(
            MESSAGES['TRACEBACK_MESSAGE'].format(demisto.command()) + traceback.format_exc())  # print the traceback
        if command == 'test-module':
            return_error(str(e))
        else:
            return_error(HR_MESSAGES['COMMAND_FAILURE'].format(demisto.command(), str(e)))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
