from requests import Response

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from enum import Enum

import urllib3
import re
from CommonServerUserPython import *

from typing import Any
from MicrosoftApiModule import *  # noqa: E402

#  disable insecure warnings
DEFAULT_KEYS_TO_REPLACE = {'createdDateTime': 'CreatedDate'}
urllib3.disable_warnings()

APP_NAME = 'ms-graph-security'
API_V2 = "Alerts v2"
API_V1 = "Legacy Alerts"
LEGACY_API_ENDPOINT = 'security/alerts'
API_V2_ENDPOINT = 'security/alerts_v2'
CMD_URL = API_V2_ENDPOINT
API_VER = API_V2
PAGE_SIZE_LIMIT_DICT = {API_V2: 2000, API_V1: 1000}
API_V1_PAGE_LIMIT = 500
THREAT_ASSESSMENT_URL_PREFIX = 'informationProtection/threatAssessmentRequests'
MAX_ITEMS_PER_RESPONSE = 50

DataSourceType = {
    'USER': {
        'type': 'User',
        'url_suffix': 'userSources',
        'unique_table_headers': ['IncludedSources'],
        'outputs_prefix': 'CustodianUserSource'
    },
    'SITE': {
        'type': 'Site',
        'url_suffix': 'siteSources',
        'unique_table_headers': [],
        'outputs_prefix': 'CustodianSiteSource'
    },
    'NON_CUSTODIAL': {
        'type': 'Data',
        'url_suffix': 'noncustodialDataSources',
        'unique_table_headers': ['LastModifiedDateTime', 'ReleasedDateTime', 'Status'],
        'outputs_prefix': 'NoncustodialDataSource'
    }
}

EMAIL_REGEX = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"


class HoldAction(Enum):
    APPLY = 'apply'
    REMOVE = 'remove'


POSSIBLE_FIELDS_TO_INCLUDE = ["All", "NetworkConnections", "Processes", "RegistryKeys", "UserStates", "HostStates",
                              "FileStates",
                              "CloudAppStates", "MalwareStates", "CustomerComments", "Triggers", "VendorInformation",
                              "VulnerabilityStates"]

RELEVANT_DATA_TO_UPDATE_PER_VERSION = {API_V1: {'assigned_to': 'assignedTo', 'closed_date_time': 'closedDateTime',
                                                'comments': 'comments', 'feedback': 'feedback', 'status': 'status',
                                                'tags': 'tags'},
                                       API_V2: {'assigned_to': 'assignedTo', 'determination': 'determination',
                                                'classification': 'classification', 'status': 'status'}
                                       }


class MsGraphClient:
    """
    Microsoft Graph Mail Client enables authorized access to a user's Office 365 mail data in a personal account.
    """

    def __init__(self, tenant_id, proxy,
                 certificate_thumbprint: str | None = None, api_version: str = "", **kwargs):
        self.ms_client = MicrosoftClient(
            tenant_id=tenant_id,
            proxy=proxy, certificate_thumbprint=certificate_thumbprint,
            managed_identities_resource_uri=Resources.graph,
            command_prefix=APP_NAME, **kwargs
        )
        if api_version == API_V1:
            global CMD_URL, API_VER
            API_VER = API_V1
            CMD_URL = LEGACY_API_ENDPOINT

    def get(self, url, **kwargs):
        return self.ms_client.http_request(method='GET', url_suffix=url, **kwargs)

    def search_alerts(self, params):
        cmd_url = CMD_URL
        demisto.debug(f'Fetching MS Graph Security incidents with params: {params}')
        response = self.ms_client.http_request(method='GET', url_suffix=cmd_url, params=params)
        return response

    def get_alert_details(self, alert_id):
        cmd_url = f'{CMD_URL}/{alert_id}'
        response = self.ms_client.http_request(method='GET', url_suffix=cmd_url)
        return response

    def update_alert(self, alert_id, params):
        cmd_url = f'{CMD_URL}/{alert_id}'
        self.ms_client.http_request(method='PATCH', url_suffix=cmd_url, json_data=params, resp_type="text")

    def get_users(self):
        cmd_url = 'users'
        response = self.ms_client.http_request(method='GET', url_suffix=cmd_url)
        return response

    def get_user(self, user_id):
        cmd_url = f'users/{user_id}'
        response = self.ms_client.http_request(method='GET', url_suffix=cmd_url)
        return response

    def create_alert_comment(self, alert_id, params):
        cmd_url = f'{CMD_URL}/{alert_id}/comments'
        response = self.ms_client.http_request(method='POST', url_suffix=cmd_url, json_data=params)
        return response

    def list_ediscovery_cases(self, case_id: str | None):
        url = 'security/cases/ediscoveryCases'
        if case_id:
            url += f'/{case_id}'
        return self.ms_client.http_request(method='GET', url_suffix=url)

    def create_edsicovery_case(self, display_name, description, external_id):
        url = 'security/cases/ediscoveryCases'
        return self.ms_client.http_request(method='POST', url_suffix=url, json_data={
            'displayName': display_name,
            'description': description,
            'externalId': external_id
        })

    def update_edsicovery_case(self, case_id, display_name, description, external_id):
        url = f'security/cases/ediscoveryCases/{case_id}'
        req = {'displayName': display_name,
               'description': description,
               'externalId': external_id}

        remove_nulls_from_dictionary(req)
        self.ms_client.http_request(ok_codes=[204], method='PATCH', url_suffix=url, json_data=req, resp_type='text')

    def close_edsicovery_case(self, case_id):
        url = f'security/cases/ediscoveryCases/{case_id}/close'
        self.ms_client.http_request(ok_codes=[204], method='POST', url_suffix=url, resp_type='text')

    def reopen_edsicovery_case(self, case_id):
        url = f'security/cases/ediscoveryCases/{case_id}/reopen'
        self.ms_client.http_request(ok_codes=[204], method='POST', url_suffix=url, resp_type='text')

    def release_edsicovery_custodian(self, case_id, custodian_id):
        url = f'security/cases/ediscoveryCases/{case_id}/custodians/{custodian_id}/release'
        self.ms_client.http_request(ok_codes=[202], method='POST', url_suffix=url, resp_type='text')

    def activate_edsicovery_custodian(self, case_id, custodian_id):
        url = f'security/cases/ediscoveryCases/{case_id}/custodians/{custodian_id}/activate'
        self.ms_client.http_request(ok_codes=[202], method='POST', url_suffix=url, resp_type='text')

    def delete_edsicovery_case(self, case_id):
        url = f'security/cases/ediscoveryCases/{case_id}'
        self.ms_client.http_request(ok_codes=[204], method='DELETE', url_suffix=url, resp_type='text')

    def create_edsicovery_custodian(self, case_id, email):
        url = f'security/cases/ediscoveryCases/{case_id}/custodians'
        return self.ms_client.http_request(method='POST', url_suffix=url, json_data={'email': email})

    def list_ediscovery_custodians(self, case_id, custodian_id):
        url = f'security/cases/ediscoveryCases/{case_id}/custodians'
        if custodian_id:
            url += f'/{custodian_id}'
        return self.ms_client.http_request(method='GET', url_suffix=url)

    def create_edsicovery_custodian_user_source(self, case_id, custodian_id, email, included_sources):
        url = f'security/cases/ediscoveryCases/{case_id}/custodians/{custodian_id}/userSources'
        return self.ms_client.http_request(method='POST', url_suffix=url, json_data={
            'email': email,
            'includedSources': included_sources
        })

    def create_edsicovery_custodian_site_source(self, case_id, custodian_id, site):
        url = f'security/cases/ediscoveryCases/{case_id}/custodians/{custodian_id}/siteSources'
        return self.ms_client.http_request(method='POST', url_suffix=url, json_data={
            'site': {
                'webUrl': site,
            }
        })

    def list_ediscovery_custodians_sources(self, case_id, custodian_id, source_id, source_type):
        url = f'security/cases/ediscoveryCases/{case_id}/custodians/{custodian_id}/{source_type["url_suffix"]}'
        if source_id:
            url += f'/{source_id}'
        return self.ms_client.http_request(method='GET', url_suffix=url)

    def create_ediscovery_non_custodial_data_source(self, case_id, site, email):
        url = f'security/cases/ediscoveryCases/{case_id}/noncustodialDataSources'
        body = {
            "dataSource": {"@odata.type": "microsoft.graph.security.userSource", "email": email}
        } if email else {
            "dataSource": {"@odata.type": "microsoft.graph.security.siteSource",
                           "site": {"webUrl": site}}}
        return self.ms_client.http_request(method='POST', url_suffix=url, json_data=body)

    def list_ediscovery_noncustodial_datasources(self, case_id, source_id):
        url = f'security/cases/ediscoveryCases/{case_id}/noncustodialDataSources'
        if source_id:
            url += f'/{source_id}'
        return self.ms_client.http_request(method='GET', url_suffix=url)

    def update_hold_ediscovery_custodian(self, case_id: str, custodian_id: str, hold_action: HoldAction):
        url = f'security/cases/ediscoveryCases/{case_id}/custodians/{hold_action.value}Hold'
        body = {
            'ids': custodian_id.split(',')
        }
        return self.ms_client.http_request(method='POST', url_suffix=url, resp_type='response', json_data=body)

    def create_ediscovery_search(self, case_id, display_name, description, query, data_source_scopes):
        url = f'/security/cases/ediscoveryCases/{case_id}/searches'
        body = {
            'displayName': display_name,
            'description': description,
            'contentQuery': query,
            'dataSourceScopes': data_source_scopes
        }
        return self.ms_client.http_request(method='POST', url_suffix=url, json_data=body)

    def update_ediscovery_search(self, case_id, search_id, display_name, description, query, data_source_scopes):
        url = f'/security/cases/ediscoveryCases/{case_id}/searches/{search_id}'
        body = {
            'displayName': display_name,
            'description': description,
            'contentQuery': query,
            'dataSourceScopes': data_source_scopes
        }
        remove_nulls_from_dictionary(body)
        self.ms_client.http_request(ok_codes=[204], method='PATCH', url_suffix=url, json_data=body, resp_type='text')

    def list_ediscovery_search(self, case_id, search_id):
        url = f'security/cases/ediscoveryCases/{case_id}/searches'
        if search_id:
            url += f'/{search_id}'
        return self.ms_client.http_request(method='GET', url_suffix=url)

    def delete_ediscovery_search(self, case_id, search_id):
        url = f'security/cases/ediscoveryCases/{case_id}/searches/{search_id}'
        self.ms_client.http_request(ok_codes=[204], method='DELETE', url_suffix=url, resp_type='text')

    def purge_ediscovery_data(self, case_id, search_id, purge_type, purge_areas):
        url = f'security/cases/ediscoveryCases/{case_id}/searches/{search_id}/purgeData'
        body = {
            'purgeType': purge_type,
            'purgeAreas': purge_areas
        }
        return self.ms_client.http_request(method='POST', url_suffix=url, json_data=body, resp_type='response')

    def create_mail_assessment_request(self, recipient_email, expected_assessment, category, user_id, message_id):
        body = {
            "@odata.type": "#microsoft.graph.mailAssessmentRequest",
            "recipientEmail": recipient_email,
            "expectedAssessment": expected_assessment,
            "category": category,
            "messageUri": f"https://graph.microsoft.com/v1.0/users/{user_id}/messages/{message_id}"
        }
        return self.ms_client.http_request(method='POST', url_suffix=THREAT_ASSESSMENT_URL_PREFIX, json_data=body)

    def get_user_id(self, email):
        return self.ms_client.http_request(method='GET', url_suffix='users', params={'$filter': f"mail eq '{email}'"})

    def get_threat_assessment_request(self, request_id):
        return self.ms_client.http_request(method='GET',
                                           url_suffix=f'{THREAT_ASSESSMENT_URL_PREFIX}/{request_id}',
                                           params={'$expand': 'results'})

    def get_threat_assessment_request_status(self, request_id):
        return self.ms_client.http_request(method='GET',
                                           url_suffix=f'{THREAT_ASSESSMENT_URL_PREFIX}/{request_id}',
                                           params={'$select': 'status'})

    def create_email_file_assessment_request(self, recipient_email, expected_assessment, category, content_data):
        body = {
            "@odata.type": "#microsoft.graph.emailFileAssessmentRequest",
            "recipientEmail": recipient_email,
            "expectedAssessment": expected_assessment,
            "category": category,
            "contentData": content_data
        }
        return self.ms_client.http_request(method='POST', url_suffix=THREAT_ASSESSMENT_URL_PREFIX, json_data=body)

    def create_file_assessment_request(self, expected_assessment, category, file_name, content_data):
        body = {
            "@odata.type": "#microsoft.graph.fileAssessmentRequest",
            "expectedAssessment": expected_assessment,
            "category": category,
            "fileName": file_name,
            "contentData": content_data
        }
        return self.ms_client.http_request(method='POST', url_suffix=THREAT_ASSESSMENT_URL_PREFIX, json_data=body)

    def create_url_assessment_request(self, expected_assessment, category, url):
        body = {
            "@odata.type": "#microsoft.graph.urlAssessmentRequest",
            "expectedAssessment": expected_assessment,
            "category": category,
            "url": url,
        }
        return self.ms_client.http_request(method='POST', url_suffix=THREAT_ASSESSMENT_URL_PREFIX, json_data=body)

    def list_threat_assessment_requests(self, filters=None, order_by=None, sort_order=None, next_token=None):
        params = {}
        if next_token:
            return self.ms_client.http_request(method='GET', url_suffix=THREAT_ASSESSMENT_URL_PREFIX,
                                               params={'$skipToken': next_token}, retries=1, status_list_to_retry=[405])
        if filters:
            params['$filter'] = filters
        if order_by:
            params['$orderby'] = order_by
            if sort_order:
                params['$orderby'] = f"{order_by} {sort_order}"

        return self.ms_client.http_request(method='GET', url_suffix=THREAT_ASSESSMENT_URL_PREFIX,
                                           params=params, retries=1, status_list_to_retry=[405])

    def advanced_hunting_request(self, query: str, timeout: int):
        """
        POST request to the advanced hunting API:
        Args:
            query (str): query advanced hunting query language
            timeout (int): The amount of time (in seconds) that a request will wait for a client to
                     establish a connection to a remote machine before a timeout occurs.

        Returns:
            The response object contains three top-level properties:

                Stats - A dictionary of query performance statistics.
                Schema - The schema of the response, a list of Name-Type pairs for each column.
                Results - A list of advanced hunting events.
        """
        return self.ms_client.http_request(method='POST', url_suffix='security/runHuntingQuery', json_data={"Query": query},
                                           timeout=timeout)

    def get_incidents_request(self, url_suffix: str, timeout: int, ) -> dict:
        """
        Perform a GET request to retrieve incidents.

        Args:
            url_suffix (str): The URL suffix for the request, including any filters or additional parameters.
            timeout (int): The timeout for the request in seconds.

        Returns:
            dict: The request results as a dictionary, containing:
                - '@odata.context'
                - 'value': The updated incident(s).
        """

        incident = self.ms_client.http_request(
            method='GET', url_suffix=url_suffix, timeout=timeout)
        return incident

    def update_incident_request(self, incident_id: int, status: Optional[str], assigned_to: Optional[str],
                                classification: Optional[str],
                                determination: Optional[str], custom_tags: Optional[List[str]], timeout: int) -> dict:
        """
        PATCH request to update single incident.
        Args:
            incident_id (int): incident's id
            status (str): Specifies the current status of the alert. Possible values are: (Active, Resolved or Redirected)
            assigned_to (str): Owner of the incident.
            classification (str): Specification of the alert. Possible values are: Unknown, FalsePositive, TruePositive.
            determination (str):  Specifies the determination of the alert. Possible values are: NotAvailable, Apt,
                                 Malware, SecurityPersonnel, SecurityTesting, UnwantedSoftware, Other.
            tags (list): Custom tags associated with an incident. Separated by commas without spaces (CSV)
                 for example: tag1,tag2,tag3.
            timeout (int): The amount of time (in seconds) that a request will wait for a client to
                establish a connection to a remote machine before a timeout occurs.
            comment (str): Comment to be added to the incident
       Returns( Dict): request results as dict:
                    { '@odata.context',
                      'value': updated incident,
                    }

        """
        body = assign_params(status=status, assignedTo=assigned_to, classification=classification,
                             determination=determination, customTags=custom_tags)

        updated_incident = self.ms_client.http_request(method='PATCH', url_suffix=f'security/incidents/{incident_id}',
                                                       json_data=body, timeout=timeout)
        return updated_incident


''' HELPER FUNCTIONS '''


def get_status_of_operation(client: MsGraphClient, res: Response) -> str:
    """
    Some responses from MSG where an action is called return a url in the headers that we can use to retrieve the status
    Args:
        client: Microsoft
        GraphClient
        res: the response from the api

    Returns:
        The status
    """
    location = res.headers.get('Location')
    status = 'success'  # if no location is returned then the custodian is already in this state/theres no data sources
    if location:
        location = 'security' + location.split('/security')[1]  # chop off the baseurl
        resp = client.get(location)
        demisto.debug(f'response from location get: {resp}')
        status = resp.get('status')
    return status


def create_search_alerts_filters(args, is_fetch=False):
    """
    Creates the relevant filters for the search_alerts function.
    Args:
        args (Dict): The command's arguments dictionary.
        is_fetch (bool): wether the search_alerts function is being called from fetch incidents or not.
    Returns:
        Dict: The filter dictionary to use
    """
    last_modified = args.get('last_modified')
    severity = args.get('severity')
    category = args.get('category')
    time_from = args.get('time_from')
    time_to = args.get('time_to')
    filter_query = args.get('filter')
    page = args.get('page')
    page_size = int(args.get('page_size', 50)) if is_fetch and args.get('page_size') or not is_fetch else 0
    filters = []
    params: dict[str, str] = {}
    if last_modified:
        last_modified_query_key: str = "lastModifiedDateTime" if API_VER == API_V1 else "lastUpdateDateTime"
        filters.append(f"{last_modified_query_key} gt {get_timestamp(last_modified)}")
    if category:
        filters.append(f"category eq '{category}'")
    if severity:
        filters.append(f"severity eq '{severity}'")
    if time_from:  # changed to ge and le in order to solve issue #27884
        filters.append(f"createdDateTime ge {time_from}")
    if time_to:
        filters.append(f"createdDateTime le {time_to}")
    if filter_query:
        filters.append(f"{filter_query}")
    if page_size:
        if PAGE_SIZE_LIMIT_DICT.get(API_VER, 1000) < page_size:
            raise DemistoException(
                f"Please note that the page size limit for {API_VER} is {PAGE_SIZE_LIMIT_DICT.get(API_VER)}")
        params['$top'] = str(page_size)
    if page and page_size:
        page = int(page)
        page = page * page_size
        if API_VER == API_V1 and page > API_V1_PAGE_LIMIT:
            raise DemistoException(f"Please note that the maximum amount of alerts you can skip in {API_VER} is"
                                   f" {API_V1_PAGE_LIMIT}")
        params['$skip'] = page
    if API_VER == API_V2:
        relevant_filters_v2 = ['classification', 'serviceSource', 'status']
        for key in relevant_filters_v2:
            if val := args.get(key):
                filters.append(f"{key} eq '{val}'")
    filters = " and ".join(filters)
    params['$filter'] = filters
    return params


def created_by_fields_to_hr(ret_context: dict):
    hr = ret_context.copy()
    hr['CreatedByName'] = dict_safe_get(ret_context, ['CreatedBy', "User", "DisplayName"])
    hr['CreatedByUPN'] = dict_safe_get(ret_context, ['CreatedBy', "User", "UserPrincipalName"])
    hr['CreatedByAppName'] = dict_safe_get(ret_context, ['CreatedBy', "Application", "DisplayName"])
    hr.pop("CreatedBy", None)
    return hr


def create_data_to_update(args):
    """
    Creates the data dictionary to update alert for the update_alert function according to the configured API version.
    Args:
        args (Dict): The command's arguments dictionary.
    Returns:
        Dict: A dictionary object containing the alert's fields to update.
    """
    relevant_data_to_update_per_version_dict: dict = RELEVANT_DATA_TO_UPDATE_PER_VERSION.get(API_VER, {})
    if all(not args.get(key) for key in list(relevant_data_to_update_per_version_dict.keys())):
        raise DemistoException(
            f"No data relevant for {API_VER} to update was provided, please provide at least one of the"
            f" following: {(', ').join(list(relevant_data_to_update_per_version_dict.keys()))}.")
    data: dict[str, Any] = {}
    if API_VER == API_V1:
        vendor_information = args.get('vendor_information')
        provider_information = args.get('provider_information')
        if not vendor_information or not provider_information:
            raise DemistoException(
                "When using Legacy Alerts, both vendor_information and provider_information must be provided.")
        data['vendorInformation'] = {
            'provider': provider_information,
            'vendor': vendor_information
        }
    if assigned_to := args.get('assigned_to'):
        data['assignedTo'] = assigned_to
    for relevant_args_key, relevant_data_key in relevant_data_to_update_per_version_dict.items():
        if val := args.get(relevant_args_key):
            if relevant_args_key == 'tags' or relevant_args_key == 'comments':
                data[relevant_data_key] = [val]
            else:
                data[relevant_data_key] = val
    return data


def validate_fields_list(fields_list):
    if unsupported_fields := (set(fields_list) - set(POSSIBLE_FIELDS_TO_INCLUDE)):
        raise DemistoException(f"The following fields are not supported by the commands as fields to include: "
                               f"{(', ').join(unsupported_fields)}.\nPlease make sure to enter only fields from the "
                               f"following list: {(', ').join(POSSIBLE_FIELDS_TO_INCLUDE)}.")


def get_timestamp(time_description):
    if time_description == 'Last24Hours':
        time_delta = 1
    elif time_description == 'Last48Hours':
        time_delta = 2
    else:
        time_delta = 7
    return datetime.strftime(datetime.now() - timedelta(time_delta), '%Y-%m-%d')


def capitalize_dict_keys_first_letter(response, keys_to_replace: dict = DEFAULT_KEYS_TO_REPLACE):
    """
    Recursively creates a data dictionary where all key starts with capital letters.
    Args:
        keys_to_replace: keys that should have custom replacements not according to capitalize_first_letter
        response (Dict / str): The dictionary to update.
    Returns:
        Dict: The updated dictionary.
    """
    if isinstance(response, str):
        return response
    parsed_dict: dict = {}
    if isinstance(response, dict):
        for key, value in response.items():
            if keys_to_replace and key in keys_to_replace:
                parsed_dict[keys_to_replace[key]] = value
            elif key == 'id':
                parsed_dict['ID'] = value
            elif isinstance(value, dict):
                parsed_dict[capitalize_first_letter(key)] = capitalize_dict_keys_first_letter(value)
            elif isinstance(value, list):
                parsed_dict[capitalize_first_letter(key)] = [capitalize_dict_keys_first_letter(list_item) for list_item
                                                             in value]
            else:
                parsed_dict[capitalize_first_letter(key)] = value
    return parsed_dict


def capitalize_first_letter(string):
    return string[:1].upper() + string[1:]


def list_ediscovery_custodian_sources(client: MsGraphClient, args, source_type):
    raw_res = client.list_ediscovery_custodians_sources(args.get('case_id'), args.get('custodian_id'),
                                                        args.get(f"{source_type['type']}_source_id".lower()),
                                                        source_type)
    if source_list := raw_res.get('value'):
        demisto.info(f'returned {len(source_list)} results from the api')
    else:
        source_list = [raw_res]  # api doesnt return a list if only 1 result

    if not argToBoolean(args.get('all_results', 'false')):
        source_list = source_list[:arg_to_number(args.get('limit', 50))]
    return ediscovery_source_command_results(source_list, source_type, raw_res)


def create_filter_query(filter_param: str, providers_param: str, service_sources_param: str):
    """
    Creates the relevant filters to the query filter according to the used API ver and the user's configured filter.
    Args:
        filter_param (str): configured user filter.
        providers_param (str): comma separated list of providers to fetch alerts by.
        service_sources_param (str): comma separated list of service_sources to fetch alerts by.
    Returns:
        str: filter query to use
    """
    filter_query = ""
    if filter_param:
        filter_query = filter_param
    else:
        if API_VER == API_V1 and providers_param:
            providers_query = []
            providers_lst = providers_param.split(',')
            for provider in providers_lst:
                providers_query.append(f"vendorInformation/provider eq '{provider}'")
            filter_query = (" or ".join(providers_query))
        elif API_VER == API_V2 and service_sources_param:
            service_sources_query = []
            service_sources_lst = service_sources_param.split(',')
            for service_source in service_sources_lst:
                service_sources_query.append(f"serviceSource eq '{service_source}'")
            filter_query = (" or ".join(service_sources_query))
    return filter_query


def to_cases_hr(ret_context: dict):
    hr = ret_context.copy()
    hr['LastModifiedByName'] = dict_safe_get(ret_context, ['LastModifiedBy', "User", "DisplayName"])
    hr['ClosedByName'] = dict_safe_get(ret_context, ['ClosedBy', "User", "DisplayName"])
    return hr


def ediscovery_cases_command_results(raw_case_list: list, raw_res=None) -> CommandResults:
    """
    Returns the CommandResults for a list of eDiscoveryCases from the API
    Args:
        raw_res: the raw_response to be used. If not provided assumed response==raw_res
        limit: max number of entries to return. Does not affect raw_result
        raw_case_list: the raw response from the api, as a list


    Returns: A CommandResults object

    """
    return to_msg_command_results(raw_object_list=raw_case_list,
                                  raw_res=raw_res,
                                  outputs_prefix='MsGraph.eDiscoveryCase',
                                  output_key_field='CaseId',
                                  raw_keys_to_replace={'status': 'CaseStatus', 'id': 'CaseId'},
                                  table_headers=['DisplayName', 'Description', 'ExternalId', 'CaseStatus', 'CaseId',
                                                 'CreatedDateTime', 'LastModifiedDateTime', 'LastModifiedByName',
                                                 'ClosedByName'],
                                  to_hr=to_cases_hr)


def custodian_to_hr(ret_context: dict):
    hr = ret_context.copy()
    hr['LastModifiedByName'] = dict_safe_get(ret_context, ['LastModifiedBy', "User", "DisplayName"])
    hr['ClosedByName'] = dict_safe_get(ret_context, ['ClosedBy', "User", "DisplayName"])
    return hr


def ediscovery_custodian_command_results(raw_custodian_list, raw_res=None):
    return to_msg_command_results(raw_object_list=raw_custodian_list,
                                  raw_res=raw_res,
                                  outputs_prefix='MsGraph.eDiscoveryCustodian',
                                  output_key_field='CustodianId',
                                  raw_keys_to_replace={'status': 'CustodianStatus', 'id': 'CustodianId'},
                                  table_headers=['DisplayName', 'Email', 'CustodianStatus', 'CustodianId',
                                                 'CreatedDateTime', 'LastModifiedDateTime', 'LastModifiedByName',
                                                 'ClosedByName', 'AcknowledgedDateTime',
                                                 'HoldStatus', 'ReleasedDateTime'],
                                  to_hr=custodian_to_hr)


def to_msg_command_results(raw_object_list, outputs_prefix, output_key_field, raw_keys_to_replace, raw_res=None,
                           table_headers=[], to_hr=lambda x: x):
    """
    General function to return command results for Microsoft Graph.

    Keys beginning with @ will be stripped from the response.
    Keys will be converted to CapitalCaseFormat
    Empty elements will be removed

    Args:
        raw_object_list: the list of objects from the api. One item will be converted to a list of one
        outputs_prefix: The outputs prefix for the command
        output_key_field: The key field for the CommandResults
        raw_keys_to_replace: Keys to replace with a specific alternative. EG { 'id' : 'CustomID' }
        raw_res: The raw response exactly as received from the API. Will assume same as raw_object_list if not provided
        table_headers: Headers to show in the human readable output
        to_hr: A function that will take a context dictionary as input and convert it to a human readable dictionary.
        Default is identity function

    Returns:
        A CommandResults object
    """
    raw_res = raw_res or raw_object_list
    if not isinstance(raw_object_list, list):
        raw_object_list = [raw_object_list]
    context_list = []
    human_readable_list = []
    for res in raw_object_list:
        context = capitalize_dict_keys_first_letter(res, keys_to_replace=raw_keys_to_replace)
        keys_to_del = [key for key in context if key.startswith('@')]
        for key in keys_to_del:
            del context[key]
        context = remove_empty_elements(context)
        context_list.append(context)
        human_readable_list.append(to_hr(context))
    return CommandResults(
        outputs_prefix=outputs_prefix,
        outputs_key_field=output_key_field,
        raw_response=raw_res,
        outputs=context_list,
        readable_output=tableToMarkdown('Results:', human_readable_list,
                                        headers=table_headers,
                                        headerTransform=pascalToSpace, removeNull=True))


def to_ediscovery_search_command_results(resp, raw_res=None):
    return to_msg_command_results(resp,
                                  raw_res=raw_res,
                                  output_key_field='SearchId',
                                  outputs_prefix='MsGraph.eDiscoverySearch',
                                  raw_keys_to_replace={'id': 'SearchId'},
                                  table_headers=['DisplayName', 'Description', 'DataSourceScopes', 'SearchId',
                                                 'CreatedByName', 'CreatedByAppName', 'CreatedByUPN', 'CreatedDateTime',
                                                 'LastModifiedDateTime', 'AdditionalSources'],
                                  to_hr=created_by_fields_to_hr)


def ediscovery_source_command_results(raw_case_list: list, source_type, raw_res=None):
    type_name = source_type["type"]
    demisto.debug(f'Returning command results for source {type_name}')

    output_key_field = f'{type_name}SourceId'
    return to_msg_command_results(raw_object_list=raw_case_list,
                                  raw_res=raw_res,
                                  outputs_prefix=f'MsGraph.{source_type["outputs_prefix"]}',
                                  output_key_field=output_key_field,
                                  raw_keys_to_replace={'id': output_key_field},
                                  table_headers=['DisplayName', 'Email', output_key_field, 'HoldStatus',
                                                 'CreatedDateTime', 'CreatedByName', 'CreatedByUPN', 'CreatedByAppName',
                                                 'SiteWebUrl'] + source_type['unique_table_headers'],
                                  to_hr=created_by_fields_to_hr)


def query_set_limit(query: str, limit: int) -> str:
    """
    Set the limit of a query if it doesn't already have a limit set.

    Args:
        query (str): The query string.
        limit (int): The limit to set.

    Returns:
        str: The modified query string with the limit set,
        or the original query if it already had a limit set or if the limit is less than 0.
    """
    if limit < 0 or "limit " in query or "take " in query:
        return query

    return f"{query} | limit {limit}"


def convert_list_incidents_to_readable(incidents_list: list) -> list:
    """
    Convert a list of raw incidents to a list of readable incidents.

    Args:
        incidents_list (list): The list of raw incidents to convert, expected to be in the format [incident1, incident2, ...].

    Returns:
        list: A list containing the converted readable incidents.
    """
    readable_incidents = []
    for incident in incidents_list:
        readable_incident = convert_single_incident_to_readable(incident)
        readable_incidents.append(readable_incident)
    return readable_incidents


def convert_single_incident_to_readable(raw_incident: dict) -> dict:
    """
    Converts incident received from Microsoft Graph Security to readable format
    Args:
        raw_incident (Dict): The incident as received from Microsoft Graph Security

    Returns: new dictionary with keys mapping.

    """
    if not raw_incident:
        raw_incident = {}

    return {
        'Display name': raw_incident.get('displayName'),
        'id': raw_incident.get('id'),
        'Severity': raw_incident.get('severity'),
        'Status': raw_incident.get('status'),
        'Assigned to': raw_incident.get('assignedTo', 'Unassigned'),
        'Custom tags': ', '.join(raw_incident.get('customTags', [])),
        'System tags': ', '.join(raw_incident.get('systemTags', [])),
        'Classification': raw_incident.get('classification'),
        'Determination': raw_incident.get('determination'),
        'Created date time': raw_incident.get('createdDateTime'),
        'Updated date time': raw_incident.get('lastUpdateDateTime'),
    }


def get_list_incidents(client: MsGraphClient, args: dict) -> list:
    """
    Retrieve a list of security incidents based on the provided arguments.

    Args:
        client (MsGraphClient): The Microsoft Graph client instance.
        args (dict): A dictionary containing the command arguments

    Returns:
        list: A list of security incidents.
    """
    timeout = arg_to_number(args['timeout'])  # default value is defined
    limit = arg_to_number(args['limit'])  # default value is defined
    url_suffix = set_url_suffix_list_incidents(args)  # type:ignore[arg-type]
    incidents_response = client.get_incidents_request(url_suffix, timeout)  # type:ignore[arg-type]
    incidents_list: list = incidents_response.get("value", [])

    count_incidents = len(incidents_list)
    nextLink = incidents_response.get("@odata.nextLink")

    while nextLink and count_incidents < limit:  # type:ignore[operator]
        url_suffix = f'security/{nextLink.split("/")[-1]}'
        top = limit - count_incidents  # type:ignore[operator]
        if top <= MAX_ITEMS_PER_RESPONSE:
            url_suffix += f"&$top={top}"
        new_incidents_respond = client.get_incidents_request(url_suffix, timeout)  # type:ignore[arg-type]
        incidents_list.extend(new_incidents_respond.get("value", []))
        count_incidents = len(incidents_list)
        nextLink = new_incidents_respond.get("@odata.nextLink")

    return incidents_list


def set_url_suffix_list_incidents(args: dict) -> str:
    """
    Set the URL suffix for retrieving a list of security incidents based on the provided arguments.

    Args:
        args (dict): A dictionary containing the command arguments:
            - 'limit' (str): The maximum number of incidents to retrieve.
            - 'status' (str): Filter by status.
            - 'assigned_to' (str): Filter by assigned user.
            - 'severity' (str): Filter by severity.
            - 'classification' (str): Filter by classification.
            - 'odata' (str): Filter by odata.

    Returns:
        str: The URL suffix for the request.
    """
    limit = arg_to_number(args['limit'])  # default value is defined
    top = limit if limit <= MAX_ITEMS_PER_RESPONSE else None  # type:ignore[operator]
    args_for_filter = {
        'status': args.get('status'),
        'assigned_to': args.get('assigned_to'),
        'severity': args.get('severity'),
        'classification': args.get('classification'),
        'odata': args.get('odata')
    }

    filters = []
    url_suffix = 'security/incidents?'
    if top:
        url_suffix += f'$top={str(top)}'
    if any(args_for_filter.values()):
        url_suffix += '&$filter='
        for key, value in args_for_filter.items():
            if value:
                filters.append(f'{key} eq \'{value}\'')
        url_suffix += ' and '.join(filters)

    return url_suffix


''' COMMAND FUNCTIONS '''


def fetch_incidents(client: MsGraphClient, fetch_time: str, fetch_limit: int, filter: str, providers: str,
                    service_sources: str) -> list:
    """
    This function will execute each interval (default is 1 minute).
    This function will return up to the given limit alerts according to the given filters using the search_alerts function.
    Args:
        client (MsGraphClient): MsGraphClient client object.
        fetch_time (str): time interval for fetch alerts.
        fetch_limit (int): limit for number of fetch alerts per fetch.
        filter (str): configured user filter.
        providers (str): comma separated list of providers to fetch alerts by.
        service_sources (str): comma separated list of service_sources to fetch alerts by.
    Returns:
        List: list of fetched alerts.
    """
    filter_query = create_filter_query(filter, providers, service_sources)
    severity_map = {'low': 1, 'medium': 2, 'high': 3, 'unknown': 0, 'informational': 0}

    last_run = demisto.getLastRun()
    timestamp_format = '%Y-%m-%dT%H:%M:%S.%fZ'
    new_last_run = last_run if last_run else {'time': parse_date_range(fetch_time, date_format=timestamp_format)[0]}
    demisto_incidents: list = []
    time_from = new_last_run.get('time')
    time_to = datetime.now().strftime(timestamp_format)

    # Get incidents from MS Graph Security
    demisto.debug(f'Fetching MS Graph Security incidents. From: {time_from}. To: {time_to}. Filter: {filter_query}')
    args = {'time_to': time_to, 'time_from': time_from, 'filter': filter_query}
    params = create_search_alerts_filters(args, is_fetch=True)
    incidents = client.search_alerts(params)['value']

    if incidents:
        count = 0
        incidents = sorted(incidents, key=lambda k: k['createdDateTime'])  # sort the incidents by time-increasing order
        last_incident_time = last_run.get('time', '0')
        demisto.debug(f'Incidents times: {[incidents[i]["createdDateTime"] for i in range(len(incidents))]}\n')
        for incident in incidents:
            incident_time = incident.get('createdDateTime')
            if incident_time > last_incident_time and count < fetch_limit:
                demisto_incidents.append({
                    'name': incident.get('title') + " - " + incident.get('id'),
                    'occurred': incident.get('createdDateTime'),
                    'severity': severity_map.get(incident.get('severity', ''), 0),
                    'rawJSON': json.dumps(incident),
                    "haIntegrationEventID": str(incident.get('id'))
                })
                count += 1
        if demisto_incidents:
            last_incident_time = demisto_incidents[-1].get('occurred')
            new_last_run.update({'time': last_incident_time})

    demisto.setLastRun(new_last_run)
    return demisto_incidents


def search_alerts_command(client: MsGraphClient, args):
    """
    Retrieve a list of alerts filtered by the given filter arguments.

    Args:
        client (MsGraphClient): MsGraphClient client object.
        args (Dict): The command's arguments dictionary.

    Returns:
        str, Dict, Dict: table of returned alerts, parsed outputs and request's response.
    """
    params = create_search_alerts_filters(args, is_fetch=False)
    alerts = client.search_alerts(params)['value']
    limit = int(args.get('limit'))
    if limit < len(alerts):
        alerts = alerts[:limit]
    outputs, table_headers = [], []
    if API_VER == API_V1:
        for alert in alerts:
            outputs.append({
                'ID': alert['id'],
                'Title': alert['title'],
                'Category': alert['category'],
                'Severity': alert['severity'],
                'CreatedDate': alert['createdDateTime'],
                'EventDate': alert['eventDateTime'],
                'Status': alert['status'],
                'Vendor': alert['vendorInformation']['vendor'],
                'Provider': alert['vendorInformation']['provider']
            })
        table_headers = ['ID', 'Vendor', 'Provider', 'Title', 'Category', 'Severity', 'CreatedDate', 'EventDate',
                         'Status']
    else:
        outputs = [capitalize_dict_keys_first_letter(alert) for alert in alerts]
        table_headers = ['ID', 'DetectionSource', 'ServiceSource', 'Title', 'Category', 'Severity', 'CreatedDate',
                         'LastUpdateDateTime', 'Status', 'IncidentId']
    ec = {
        'MsGraph.Alert(val.ID && val.ID === obj.ID)': outputs
    }
    human_readable = tableToMarkdown('Microsoft Security Graph Alerts', outputs, table_headers, removeNull=True)
    return human_readable, ec, alerts


def get_alert_details_command(client: MsGraphClient, args):
    """
    Retrieve information about an alert with the given id.

    Args:
        client (MsGraphClient): MsGraphClient client object.
        args (Dict): The command's arguments dictionary.

    Returns:
        str, Dict, Dict: Human readable output with information about the alert, parsed outputs and request's response.
    """
    alert_id = args.get('alert_id')

    alert_details = client.get_alert_details(alert_id)

    hr = f'## Microsoft Security Graph Alert Details - {alert_id}\n'
    if API_VER == API_V2:
        outputs = capitalize_dict_keys_first_letter(alert_details)
        table_headers = ['ID', 'DetectionSource', 'ServiceSource', 'Title', 'Category', 'Severity', 'CreatedDate',
                         'LastUpdateDateTime', 'Status', 'IncidentId']
        ec = {
            'MsGraph.Alert(val.ID && val.ID === obj.ID)': outputs
        }
        hr += tableToMarkdown('', outputs, table_headers, removeNull=True)
    else:
        fields_to_include = args.get('fields_to_include')
        if fields_to_include:
            fields_list = fields_to_include.split(',')
            validate_fields_list(fields_list)
        else:
            fields_list = []
        show_all_fields = 'All' in fields_list

        basic_properties_title = 'Basic Properties'
        basic_properties = {
            'ActivityGroupName': alert_details['activityGroupName'],
            'AssignedTo': alert_details['assignedTo'],
            'AzureTenantID': alert_details['azureTenantId'],
            'Category': alert_details['category'],
            'ClosedDate': alert_details['closedDateTime'],
            'Confidence': alert_details['confidence'],
            'CreatedDate': alert_details['createdDateTime'],
            'Description': alert_details['description'],
            'EventDate': alert_details['eventDateTime'],
            'LastModifiedDate': alert_details['eventDateTime'],
            'Severity': alert_details['severity'],
            'Status': alert_details['status'],
            'Title': alert_details['title']
        }
        hr += tableToMarkdown(basic_properties_title, basic_properties, removeNull=True)

        if 'CloudAppStates' in fields_list or show_all_fields:
            cloud_apps_states = alert_details['cloudAppStates']
            if cloud_apps_states:
                cloud_apps_hr = []
                for state in cloud_apps_states:
                    cloud_apps_hr.append({
                        'DestinationSerivceIP': state['destinationServiceIp'],
                        'DestinationSerivceName': state['destinationServiceName'],
                        'RiskScore': state['riskScore']
                    })
                cloud_apps_title = 'Cloud Application States for Alert'
                hr += tableToMarkdown(cloud_apps_title, cloud_apps_hr, removeNull=True)

        if 'CustomerComments' in fields_list or show_all_fields:
            comments = alert_details['comments']
            if comments:
                comments_hr = '### Customer Provided Comments for Alert\n'
                for comment in comments:
                    comments_hr += f'- {comment}\n'
                hr += comments_hr

        if 'FileStates' in fields_list or show_all_fields:
            file_states = alert_details['fileStates']
            if file_states:
                file_states_hr = []
                for state in file_states:
                    file_state = {
                        'Name': state['name'],
                        'Path': state['path'],
                        'RiskScore': state['riskScore']
                    }
                    file_hash = state.get('fileHash')
                    if file_hash:
                        file_state['FileHash'] = file_hash['hashValue']
                    file_states_hr.append(file_state)
                file_states_title = 'File Security States for Alert'
                hr += tableToMarkdown(file_states_title, file_states_hr, removeNull=True)

        if 'HostStates' in fields_list or show_all_fields:
            host_states = alert_details['hostStates']
            if host_states:
                host_states_hr = []
                for state in host_states:
                    host_state = {
                        'Fqdn': state['fqdn'],
                        'NetBiosName': state['netBiosName'],
                        'OS': state['os'],
                        'PrivateIPAddress': state['privateIpAddress'],
                        'PublicIPAddress': state['publicIpAddress']
                    }
                    aad_joined = state.get('isAzureAadJoined')
                    if aad_joined:
                        host_state['IsAsureAadJoined'] = aad_joined
                    aad_registered = state.get('isAzureAadRegistered')
                    if aad_registered:
                        host_state['IsAsureAadRegistered'] = aad_registered
                    risk_score = state.get('riskScore')
                    if risk_score:
                        host_state['RiskScore'] = risk_score
                    host_states_hr.append(host_state)
                host_states_title = 'Host Security States for Alert'
                hr += tableToMarkdown(host_states_title, host_states_hr, removeNull=True)

        if 'MalwareStates' in fields_list or show_all_fields:
            malware_states = alert_details['malwareStates']
            if malware_states:
                malware_states_hr = []
                for state in malware_states:
                    malware_states_hr.append({
                        'Category': state['category'],
                        'Familiy': state['family'],
                        'Name': state['name'],
                        'Severity': state['severity'],
                        'WasRunning': state['wasRunning']
                    })
                malware_states_title = 'Malware States for Alert'
                hr += tableToMarkdown(malware_states_title, malware_states_hr, removeNull=True)

        if 'NetworkConnections' in fields_list or show_all_fields:
            network_connections = alert_details['networkConnections']
            if network_connections:
                network_connections_hr = []
                for connection in network_connections:
                    connection_hr = {}
                    for key, value in connection.items():
                        if value or value is False:
                            connection_hr[capitalize_first_letter(key)] = value
                    network_connections_hr.append(connection_hr)
                network_connections_title = 'Network Connections for Alert'
                hr += tableToMarkdown(network_connections_title, network_connections_hr, removeNull=True)

        if 'Processes' in fields_list or show_all_fields:
            processes = alert_details['processes']
            if processes:
                processes_hr = []
                for process in processes:
                    process_hr = {}
                    for key, value in process.items():
                        if value or value is False:
                            process_hr[capitalize_first_letter(key)] = value
                    processes_hr.append(process_hr)
                processes_title = 'Processes for Alert'
                hr += tableToMarkdown(processes_title, processes_hr, removeNull=True)

        if 'Triggers' in fields_list or show_all_fields:
            triggers = alert_details['triggers']
            if triggers:
                triggers_hr = []
                for trigger in triggers:
                    triggers_hr.append({
                        'Name': trigger['name'],
                        'Type': trigger['type'],
                        'Value': trigger['value']
                    })
                triggers_title = 'Triggers for Alert'
                hr += tableToMarkdown(triggers_title, triggers_hr, removeNull=True)

        if 'UserStates' in fields_list or show_all_fields:
            user_states = alert_details['userStates']
            if user_states:
                user_states_hr = []
                for state in user_states:
                    state_hr = {}
                    for key, value in state.items():
                        if value or value is False:
                            state_hr[capitalize_first_letter(key)] = value
                    user_states_hr.append(state_hr)
                user_states_title = 'User Security States for Alert'
                hr += tableToMarkdown(user_states_title, user_states_hr, removeNull=True)

        if 'VendorInformation' in fields_list or show_all_fields:
            vendor_information = alert_details['vendorInformation']
            if vendor_information:
                vendor_info_hr = {
                    'Provider': vendor_information['provider'],
                    'ProviderVersion': vendor_information['providerVersion'],
                    'SubProvider': vendor_information['subProvider'],
                    'Vendor': vendor_information['vendor']
                }
                vendor_info_title = 'Vendor Information for Alert'
                hr += tableToMarkdown(vendor_info_title, vendor_info_hr, removeNull=True)

        if 'VulnerabilityStates' in fields_list or show_all_fields:
            vulnerability_states = alert_details['vulnerabilityStates']
            if vulnerability_states:
                vulnerability_states_hr = []
                for state in vulnerability_states:
                    vulnerability_states_hr.append({
                        'CVE': state['cve'],
                        'Severity': state['severity'],
                        'WasRunning': state['wasRunning']
                    })
                vulnerability_states_title = 'Vulnerability States for Alert'
                hr += tableToMarkdown(vulnerability_states_title, vulnerability_states_hr, removeNull=True)

        if 'RegistryKeys' in fields_list or show_all_fields:
            registry_keys = alert_details['registryKeyStates']
            if registry_keys:
                registry_keys_hr = []
                for r_key in registry_keys:
                    r_key_hr = {}
                    for key, value in r_key.items():
                        if value or value is False:
                            r_key_hr[capitalize_first_letter(key)] = value
                    registry_keys_hr.append(r_key_hr)
                registry_keys_title = 'Registry Keys for Alert'
                hr += tableToMarkdown(registry_keys_title, registry_keys_hr, removeNull=True)
        context = {
            'ID': alert_details['id'],
            'Title': alert_details['title'],
            'Category': alert_details['category'],
            'Severity': alert_details['severity'],
            'CreatedDate': alert_details['createdDateTime'],
            'EventDate': alert_details['eventDateTime'],
            'Status': alert_details['status'],
            'Vendor': alert_details['vendorInformation']['vendor'],
            'Provider': alert_details['vendorInformation']['provider']
        }
        ec = {
            'MsGraph.Alert(val.ID && val.ID === obj.ID)': context
        }
    return hr, ec, alert_details


def update_alert_command(client: MsGraphClient, args):
    alert_id = args.get('alert_id')
    status: str = args.get('status', "")
    if status == "newAlert" and API_VER == API_V2:
        args["status"] = "new"
        status = "new"
    provider_information = args.get('provider_information')
    params = create_data_to_update(args)
    client.update_alert(alert_id, params)
    context = {
        'ID': alert_id
    }
    if status:
        context['Status'] = status
    ec = {
        'MsGraph.Alert(val.ID && val.ID === obj.ID)': context
    }
    human_readable = f'Alert {alert_id} has been successfully updated.'
    if status and API_VER == API_V1 and provider_information in {'IPC', 'MCAS', 'Azure Sentinel'}:
        human_readable += f'\nUpdating status for alerts from provider {provider_information} gets updated across \
Microsoft Graph Security API integrated applications but not reflected in the provider`s management experience.\n \
        For more details, see the \
[Microsoft documentation](https://docs.microsoft.com/en-us/graph/api/resources/security-api-overview?view=graph-rest-1.0#alerts)'
    return human_readable, ec, context


def get_users_command(client: MsGraphClient, args):
    users = client.get_users()['value']
    outputs = []
    for user in users:
        outputs.append({
            'Name': user['displayName'],
            'Title': user['jobTitle'],
            'Email': user['mail'],
            'ID': user['id']
        })
    ec = {
        'MsGraph.User(val.ID && val.ID === obj.ID)': outputs
    }
    table_headers = ['Name', 'Title', 'Email', 'ID']
    human_readable = tableToMarkdown('Microsoft Graph Users', outputs, table_headers, removeNull=True)
    return human_readable, ec, users


def get_user_command(client: MsGraphClient, args):
    user_id = args.get('user_id')
    raw_user = client.get_user(user_id)
    user = {
        'Name': raw_user['displayName'],
        'Title': raw_user['jobTitle'],
        'Email': raw_user['mail'],
        'ID': raw_user['id']
    }
    ec = {
        'MsGraph.User(val.ID && val.ID === obj.ID)': user
    }
    table_headers = ['Name', 'Title', 'Email', 'ID']
    human_readable = tableToMarkdown('Microsoft Graph User ' + user_id, user, table_headers, removeNull=True)
    return human_readable, ec, raw_user


def create_alert_comment_command(client: MsGraphClient, args):
    """
    Adds a comment to an alert with the given id

    Args:
        client (MsGraphClient): MsGraphClient client object.
        args (Dict): The command's arguments dictionary.

    Returns:
        str, Dict, Dict: the human readable, parsed outputs and request's response.
    """
    if API_VER == API_V1:
        raise DemistoException("This command is available only for Alerts v2. If you"
                               " wish to add a comment to an alert with Legacy Alerts please use 'msg-update-alert' command.")
    alert_id = args.get('alert_id', '')
    comment = args.get('comment', '')
    params = {"comment": comment}
    res = client.create_alert_comment(alert_id, params)
    comments = [capitalize_dict_keys_first_letter(comment) for comment in res.get('value', [])]
    context = {
        'ID': alert_id,
        'Comments': comments
    }
    ec = {
        'MsGraph.AlertComment(val.ID && val.ID == obj.ID)': context
    }
    header = f'Microsoft Security Graph Create Alert Comment - {alert_id}\n'
    human_readable = tableToMarkdown(header, comments, removeNull=True)
    return human_readable, ec, res


def create_ediscovery_case_command(client: MsGraphClient, args: dict):
    """
    """
    res = client.create_edsicovery_case(args.get('display_name'), args.get('description'), args.get('external_id'))
    return ediscovery_cases_command_results([res], res)


def close_ediscovery_case_command(client: MsGraphClient, args):
    """
    """
    client.close_edsicovery_case(args.get('case_id'))
    return CommandResults(readable_output=f'Case with id {args.get("case_id")} was closed successfully.')


def reopen_ediscovery_case_command(client: MsGraphClient, args):
    """
    """
    client.reopen_edsicovery_case(args.get('case_id'))
    return CommandResults(readable_output=f'Case with id {args.get("case_id")} was reopened successfully.')


def update_ediscovery_case_command(client: MsGraphClient, args):
    """
    """
    client.update_edsicovery_case(args.get('case_id'), args.get('display_name'), args.get('description'),
                                  args.get('external_id'))
    return CommandResults(readable_output=f'Case with id {args.get("case_id")} was updated successfully.')


def release_ediscovery_custodian_command(client: MsGraphClient, args):
    """
    """
    client.release_edsicovery_custodian(args.get('case_id'), args.get('custodian_id'))
    return CommandResults(readable_output=f'Custodian with id {args.get("custodian_id")} was released from '
                                          f'case with id {args.get("case_id")} successfully.')


def activate_ediscovery_custodian_command(client: MsGraphClient, args):
    """
    """
    client.activate_edsicovery_custodian(args.get('case_id'), args.get('custodian_id'))
    return CommandResults(readable_output=f'Custodian with id {args.get("custodian_id")} Case was reactivated on '
                                          f'case with id {args.get("case_id")} successfully.')


def create_ediscovery_custodian_user_source_command(client: MsGraphClient, args):
    """
    """
    resp = client.create_edsicovery_custodian_user_source(args.get('case_id'), args.get('custodian_id'),
                                                          args.get('email'), args.get('included_sources'))
    return ediscovery_source_command_results(resp, DataSourceType['USER'])


def create_ediscovery_custodian_site_source_command(client: MsGraphClient, args):
    resp = client.create_edsicovery_custodian_site_source(args.get('case_id'), args.get('custodian_id'),
                                                          args.get('site'))
    return ediscovery_source_command_results(resp, DataSourceType['SITE'])


def create_ediscovery_non_custodial_data_source_command(client: MsGraphClient, args):
    site = args.get('site')
    email = args.get('email')
    if not (bool(site) ^ bool(email)):
        raise ValueError('One of either the site argument or the email argument must be provided, not both')

    resp = client.create_ediscovery_non_custodial_data_source(args.get('case_id'), site, email)

    return to_msg_command_results(raw_object_list=resp,
                                  outputs_prefix='MsGraph.NoncustodialDataSource',
                                  output_key_field='DataSourceId',
                                  raw_keys_to_replace={'status': 'DataSourceStatus', 'id': 'DataSourceId'})


def delete_ediscovery_case_command(client: MsGraphClient, args):
    client.delete_edsicovery_case(args.get('case_id'))
    return CommandResults(readable_output='Case was deleted successfully.')


def create_ediscovery_custodian_command(client: MsGraphClient, args):
    res = client.create_edsicovery_custodian(args.get('case_id'), args.get('email'))
    return ediscovery_custodian_command_results(res)


def list_ediscovery_case_command(client: MsGraphClient, args):
    raw_res = client.list_ediscovery_cases(args.get('case_id'))
    if case_list := raw_res.get('value'):
        demisto.info(f'returned {raw_res.get("@odata.count")} results from the api')
    else:
        case_list = [raw_res]  # api doesnt return a list if only 1 result
    if not argToBoolean(args.get('all_results', 'false')):
        case_list = case_list[:arg_to_number(args.get('limit', 50))]
    return ediscovery_cases_command_results(case_list, raw_res)


def list_ediscovery_custodian_command(client: MsGraphClient, args):
    raw_res = client.list_ediscovery_custodians(args.get('case_id'), args.get('custodian_id'))
    if custodian_list := raw_res.get('value'):
        demisto.info(f'returned {raw_res.get("@odata.count")} results from the api')
    else:
        custodian_list = [raw_res]  # api doesnt return a list if only 1 result
    if not argToBoolean(args.get('all_results', 'false')):
        custodian_list = custodian_list[:arg_to_number(args.get('limit', 50))]
    return ediscovery_custodian_command_results(custodian_list, raw_res)


def list_ediscovery_custodian_user_sources_command(client: MsGraphClient, args):
    return list_ediscovery_custodian_sources(client, args, DataSourceType['USER'])


def list_ediscovery_custodian_site_sources_command(client: MsGraphClient, args):
    return list_ediscovery_custodian_sources(client, args, DataSourceType['SITE'])


def list_ediscovery_non_custodial_data_source_command(client: MsGraphClient, args):
    raw_res = client.list_ediscovery_noncustodial_datasources(args.get('case_id'), args.get('data_source_id'))
    if source_list := raw_res.get('value'):
        demisto.info(f'returned {len(source_list)} results from the api')
    else:
        source_list = [raw_res]  # api doesnt return a list if only 1 result
    if not argToBoolean(args.get('all_results', 'false')):
        source_list = source_list[:arg_to_number(args.get('limit'))]
    return ediscovery_source_command_results(source_list, DataSourceType['NON_CUSTODIAL'], raw_res)


def update_hold_ediscovery_custodian_command(client: MsGraphClient, args, hold_action: HoldAction):
    demisto.debug(f'{hold_action.value=}')
    res = client.update_hold_ediscovery_custodian(args.get('case_id'), args.get('custodian_id'), hold_action)
    status = get_status_of_operation(client, res)
    return CommandResults(readable_output=f'{hold_action.value.capitalize()} hold status is {status}.')


def apply_hold_ediscovery_custodian_command(client: MsGraphClient, args):
    return update_hold_ediscovery_custodian_command(client, args, HoldAction.APPLY)


def remove_hold_ediscovery_custodian_command(client: MsGraphClient, args):
    return update_hold_ediscovery_custodian_command(client, args, HoldAction.REMOVE)


def update_ediscovery_search_command(client: MsGraphClient, args):
    client.update_ediscovery_search(args.get('case_id'), args.get('search_id'), args.get('display_name'),
                                    args.get('description'),
                                    args.get('query'), args.get('data_source_scopes'))

    return CommandResults(readable_output=f'eDiscovery search {args.get("search_id")} was updated successfully.')


def delete_ediscovery_search_command(client: MsGraphClient, args):
    client.delete_ediscovery_search(args.get('case_id'), args.get('search_id'))

    return CommandResults(readable_output=f'eDiscovery search {args.get("search_id")} was deleted successfully.')


def purge_ediscovery_data_command(client: MsGraphClient, args):
    resp = client.purge_ediscovery_data(args.get('case_id'), args.get('search_id'), args.get('purge_type'),
                                        args.get('purge_areas'))
    status = get_status_of_operation(client, resp)
    return CommandResults(readable_output=f'eDiscovery purge status is {status}.')


def create_ediscovery_search_command(client: MsGraphClient, args):
    resp = client.create_ediscovery_search(args.get('case_id'), args.get('display_name'), args.get('description'),
                                           args.get('query'), args.get('data_source_scopes'))

    return to_ediscovery_search_command_results(resp)


def list_ediscovery_search_command(client: MsGraphClient, args):

    raw_res = client.list_ediscovery_search(args.get('case_id'), args.get('search_id'))
    if case_list := raw_res.get('value'):
        demisto.info(f'returned {len(case_list)} results from the api')
    else:
        case_list = [raw_res]
    if not argToBoolean(args.get('all_results', 'false')):
        case_list = case_list[:arg_to_number(args.get('limit'))]
    return to_ediscovery_search_command_results(case_list, raw_res)


def test_auth_code_command(client: MsGraphClient, args):
    """
    Called to test authorization code flow (since integration context cant be accessed during test_module)
    Calls list cases with no arguments
    """
    permissions = args.get('permission_type', 'all')
    if permissions == 'all':
        permissions = "ediscovery, alerts, threat assessment"
    for permission in argToList(permissions):
        try:
            demisto.debug(f'checking permission {permission}')
            match permission:
                case 'ediscovery':
                    list_ediscovery_case_command(client, {})
                case 'alerts':
                    test_function(client, args, True)
                case 'threat assessment':
                    list_threat_assessment_requests_command(client, {})
        except Exception as e:
            raise DemistoException(f'Authorization was not successful for permission {permission} '
                                   'Check that you have the required permissions') from e
    return CommandResults(readable_output='Authentication was successful.')


def advanced_hunting_command(client: MsGraphClient, args: dict) -> list[CommandResults] | CommandResults:
    """
    Sends a query for the advanced hunting tool.
    Args:
        client(Client): Microsoft Graph Security's client to preform the API calls.
        args(Dict): Demisto arguments:
              - query (str) - The query to run (required)
              - limit (int) - number of entries in the result, -1 for no limit.
              - timeout (int) - waiting time for command execution.
    Returns:

    """
    query = args['query']  # required argument
    limit = arg_to_number(args['limit'])  # default value is defined
    timeout = arg_to_number(args['timeout'])  # default value is defined

    query = query_set_limit(query, limit)  # type:ignore[arg-type]

    response = client.advanced_hunting_request(query=query, timeout=timeout)  # type:ignore[arg-type]
    results = response.get('results')
    schema = response.get('schema', {})
    headers = [item.get('name') for item in schema]
    context_result = {'query': query, 'results': results}
    human_readable_table = tableToMarkdown(name=f" Result of query: {query}:", t=results,
                                           headers=headers)

    microsoft_365_defender_context = demisto.params().get("microsoft_365_defender_context")

    command_result_ms_graph = CommandResults(
        outputs_prefix='MsGraph.Hunt',
        outputs_key_field='query',
        outputs=context_result,
        readable_output=human_readable_table
    )

    if microsoft_365_defender_context:
        command_result_microsoft_defender = CommandResults(
            outputs_prefix='Microsoft365Defender.Hunt',
            outputs_key_field='query',
            outputs=context_result,
            readable_output="See Results Above"
        )
        return [command_result_ms_graph, command_result_microsoft_defender]

    return command_result_ms_graph


def get_list_security_incident_command(client: MsGraphClient, args: dict) -> CommandResults:
    """
    Retrieve a list of security incidents or a single incident based on the provided arguments.

    Args:
        client (MsGraphClient): The Microsoft Graph client object.
        args (dict): A dictionary containing the command arguments:
            - 'timeout' (str): The timeout for the request in seconds.
            - 'incident_id' (str): The ID of the incident to retrieve. If None, retrieves a list of incidents.

    Returns:
        CommandResults: The command results object containing the outputs and readable output.
    """
    timeout = arg_to_number(args['timeout'])  # default value is defined
    incident_id = arg_to_number(args.get('incident_id'))

    if incident_id:  # Case of single incident
        url_suffix = f'security/incidents/{incident_id}'
        incident_response = client.get_incidents_request(url_suffix, timeout)  # type:ignore[arg-type]
        if incident_response.get('@odata.context'):
            del incident_response['@odata.context']

        name = f'Incident No. {incident_id}:'
        readable_incident = convert_single_incident_to_readable(incident_response)
        headers = list(readable_incident)
        outputs = incident_response

    else:        # Case of list incidents
        incidents_list = get_list_incidents(client, args)
        name = 'Incidents:'
        readable_incident = convert_list_incidents_to_readable(incidents_list)  # type:ignore[assignment]
        headers = list(readable_incident[0])
        outputs = incidents_list  # type:ignore[assignment]

    human_readable_table = tableToMarkdown(name=name, t=readable_incident, headers=headers)
    return CommandResults(outputs_prefix='MsGraph.Incident', outputs_key_field='id',
                          outputs=outputs, readable_output=human_readable_table)


def update_incident_command(client: MsGraphClient, args: dict) -> CommandResults:
    """
    Update an incident.
    Args:
        client(Client): Microsoft Graph Security's client to preform the API calls.
        args(Dict): Demisto arguments:
              - incident_id (int) - incident's id (required)
              - status (str) - Specifies the current status of the alert. Possible values are: (Active, Resolved or Redirected)
              - assigned_to (str) - Owner of the incident.
              - classification (str) - Specification of the alert. Possible values are: Unknown, FalsePositive, TruePositive.
              - determination (str) -  Specifies the determination of the alert. Possible values are: NotAvailable, Apt,
                                 Malware, SecurityPersonnel, SecurityTesting, UnwantedSoftware, Other.
              - custom_tags - Custom tags associated with an incident. Separated by commas without spaces (CSV)
                       for example: tag1,tag2,tag3.

    Returns: CommandResults
    """
    incident_id = arg_to_number(args['incident_id'])  # required argument
    status = args.get('status')
    assigned_to = args.get('assigned_to')
    determination = args.get('determination')
    classification = args.get('classification')
    custom_tags = argToList(args.get('custom_tags'))
    timeout = arg_to_number(args['timeout'])    # default value is defined
    updated_incident = client.update_incident_request(incident_id=incident_id, status=status,  # type:ignore[arg-type]
                                                      assigned_to=assigned_to, classification=classification,
                                                      determination=determination, custom_tags=custom_tags,
                                                      timeout=timeout)  # type:ignore[arg-type]

    if updated_incident.get('@odata.context'):
        del updated_incident['@odata.context']

    readable_incident = convert_single_incident_to_readable(updated_incident)
    human_readable_table = tableToMarkdown(name=f"Updated incident No. {incident_id}:",
                                           t=readable_incident, headers=list(readable_incident))
    return CommandResults(outputs_prefix='MsGraph.Incident', outputs_key_field='id',
                          outputs=updated_incident, readable_output=human_readable_table)


def test_function(client: MsGraphClient, args, has_access_to_context=False):    # pragma: no cover
    """
    Args:
        has_access_to_context (bool): Whether this function is called from a command that allows this integration to access the
        context. When called from the test button on an integration, we dont have access to the integration context. Since auth
        code workflow depends on reading from and writing to the context, if we dont have access, this function cannot run
        successfully, so we will throw an exception.
       Performs basic GET request to check if the API is reachable and authentication is successful.
    Returns:
        'ok' if connection is successful.
    Raises:
        DemistoException: If using auth code flow and called from test_module
    """
    if not has_access_to_context and hasattr(client.ms_client, 'grant_type') \
            and client.ms_client.grant_type == AUTHORIZATION_CODE:
        raise DemistoException(
            "Test module is not available for the authorization code flow."
            " Use the msg-auth-test command instead.")

    response = client.ms_client.http_request(
        method='GET', url_suffix=CMD_URL, params={'$top': 1}, resp_type='response')
    try:
        data = response.json() if response.text else {}
        if not response.ok:
            return_error(f'API call to MS Graph Security failed. Please check authentication related parameters.'
                         f' [{response.status_code}] - {demisto.get(data, "error.message")}')

        params: dict = demisto.params()

        if params.get('isFetch'):
            fetch_time = params.get('fetch_time', '1 day')
            fetch_providers = params.get('fetch_providers', '')
            fetch_filter = params.get('fetch_filter', '')
            fetch_service_sources = params.get('fetch_service_sources', '')

            filter_query = create_filter_query(fetch_filter, fetch_providers, fetch_service_sources)
            timestamp_format = '%Y-%m-%dT%H:%M:%S.%fZ'
            time_from = parse_date_range(fetch_time, date_format=timestamp_format)[0]
            time_to = datetime.now().strftime(timestamp_format)
            args = {'time_to': time_to, 'time_from': time_from, 'filter': filter_query}
            params = create_search_alerts_filters(args, is_fetch=True)
            try:
                client.search_alerts(params)['value']
            except Exception as e:
                if 'Invalid ODATA query filter' in e.args[0]:
                    raise DemistoException("Wrong filter format, correct usage: {property} eq '{property-value}'"
                                           "\n\n" + e.args[0])
                raise e

        return 'ok', None, None

    except TypeError as ex:
        demisto.debug(str(ex))
        return_error(f'API call to MS Graph Security failed, could not parse result. '
                     f'Please check authentication related parameters. [{response.status_code}]')


def get_message_user(client, message_user):
    is_email = re.search(EMAIL_REGEX, message_user)
    if is_email:
        user_result = (client.get_user_id(message_user)).get('value')
        if not user_result:
            raise DemistoException(f'{message_user} is not a valid user')
        return user_result[0].get('id')
    return message_user


def is_base_64(string: str) -> bool:    # pragma: no cover
    """
    Validate if string is base 64 encoded.
    Args:
        string (str): String to validate.

    Returns:
        bool: True if the string is base 64 encoded ,  else False.

    """
    try:
        if isinstance(string, str):
            # If there's any unicode here, an exception will be thrown and the function will return false
            string_bytes = bytes(string, 'ascii')
        elif isinstance(string, bytes):
            string_bytes = string
        else:
            raise ValueError("Argument must be string or bytes")
        return base64.b64encode(base64.b64decode(string_bytes)) == string_bytes
    except Exception:
        return False


def get_content_data(entry_id, content_data):   # pragma: no cover

    if not (entry_id or content_data) or (entry_id and content_data):
        raise DemistoException('Just one of entry_id or content_data arguments has to be provided.')
    try:
        if entry_id:
            file = demisto.getFilePath(entry_id)
            file_path = file['path']
            with open(file_path, 'rb') as fp:
                content = base64.b64encode(fp.read())
                return str(content, encoding='utf-8')
        if content_data:
            return content_data if is_base_64(content_data) else base64.b64encode(content_data)

    except Exception as e:
        raise DemistoException(f'Failed loading content data: {e}')


def get_result_outputs(result) -> Dict:
    output = {
        'ID': result.get('id'),
        'Created DateTime': result.get('createdDateTime'),
        'Content Type': result.get('contentType'),
        'Expected Assessment': result.get('expectedAssessment'),
        'Category': result.get('category'),
        'Status': result.get('status'),
        'Request Source': result.get('requestSource'),
        'Recipient Email': result.get('recipientEmail'),
        'Destination Routing Reason': result.get('destinationRoutingReason'),
        'URL': result.get('url'),
        'File Name': result.get('fileName'),
    }
    if created_by := result.get('createdBy'):
        output['Created User ID'] = created_by.get('user', {}).get('id')
        output['Created Username'] = created_by.get('user', {}).get('displayName')

    if results := result.get('results'):
        output['Result Type'] = results[0].get('resultType')
        output['Result message'] = results[0].get('message')
    return output


def get_threat_assessment_request(client: MsGraphClient, request_id):
    result = client.get_threat_assessment_request(request_id)
    outputs = get_result_outputs(result)
    readable_output = tableToMarkdown('Threat assessment request:', outputs, removeNull=True)

    return [CommandResults(readable_output=readable_output,
                           raw_response=result,
                           outputs=outputs,
                           outputs_prefix='MSGraphMail.AssessmentRequest')]


@polling_function('msg-create-mail-assessment-request',
                  timeout=arg_to_number(demisto.args().get("timeout_in_seconds", 720)),
                  requires_polling_arg=False)
def create_mail_assessment_request_command(args, client: MsGraphClient) -> PollResult | CommandResults:

    if not (request_id := args.get('request_id')):
        message_user = get_message_user(client, args.get('message_user'))
        result = client.create_mail_assessment_request(args.get('recipient_email'),
                                                       args.get('expected_assessment'),
                                                       args.get('category'),
                                                       message_user,
                                                       args.get('message_id'))
        request_id = result.get('id')

    result = client.get_threat_assessment_request(request_id)
    status = result.get('status')
    demisto.debug(f"status is: {status}")
    if status == 'completed' or result.get('results'):
        outputs = get_result_outputs(result)
        outputs['Message ID'] = args.get('message_id')
        readable_output = tableToMarkdown('Mail assessment request:', outputs, removeNull=True)

        results = CommandResults(readable_output=readable_output,
                                 raw_response=result,
                                 outputs=outputs,
                                 outputs_prefix='MSGraphMail.MailAssessment')
        return PollResult(response=results)
    else:
        return PollResult(continue_to_poll=True, args_for_next_run={"request_id": request_id, **args},
                          response=None,
                          partial_result=CommandResults(readable_output="The status is pending, still waiting to get results..."))


@polling_function('msg-create-email-file-assessment-request',
                  timeout=arg_to_number(demisto.args().get("timeout_in_seconds", 720)),
                  requires_polling_arg=False)
def create_email_file_request_command(args, client: MsGraphClient) -> PollResult | CommandResults:

    if not (request_id := args.get('request_id')):
        content_data = get_content_data(args.get('entry_id'), args.get('content_data'))
        result = client.create_email_file_assessment_request(args.get('recipient_email'),
                                                             args.get('expected_assessment'),
                                                             args.get('category'),
                                                             content_data)
        request_id = result.get('id')
    demisto.debug(f"got request id: {request_id}")
    result = client.get_threat_assessment_request(request_id)
    status = result.get('status')
    demisto.debug(f"status is: {status}")
    if status == 'completed' or result.get('results'):
        outputs = get_result_outputs(result)
        readable_output = tableToMarkdown('Email file assessment request results:', outputs, removeNull=True)

        results = CommandResults(readable_output=readable_output,
                                 raw_response=result,
                                 outputs=outputs,
                                 outputs_prefix='MSGraphMail.EmailAssessment')
        return PollResult(response=results)
    else:
        return PollResult(continue_to_poll=True, args_for_next_run={"request_id": request_id, **args},
                          response=None,
                          partial_result=CommandResults(readable_output="The status is pending, still waiting to get results..."))


@polling_function('msg-create-file-assessment-request', requires_polling_arg=False)
def create_file_assessment_request_command(args, client) -> PollResult | CommandResults:

    if not (request_id := args.get('request_id')):
        content_data = get_content_data(args.get('entry_id'), args.get('content_data'))
        demisto.debug(f"got content data: {content_data}")
        result = client.create_file_assessment_request(args.get('expected_assessment'),
                                                       args.get('category'),
                                                       args.get('file_name'),
                                                       content_data)
        request_id = result.get('id')

    demisto.debug(f"got request id: {request_id}")
    result = client.get_threat_assessment_request_status(request_id)
    status = result.get('status')

    demisto.debug(f"status is: {status}")
    if status == 'completed':
        result = client.get_threat_assessment_request(request_id)
        outputs = get_result_outputs(result)
        readable_output = tableToMarkdown('File assessment request results:', outputs, removeNull=True)

        results = CommandResults(readable_output=readable_output,
                                 raw_response=result,
                                 outputs=outputs,
                                 outputs_prefix='MSGraphMail.FileAssessment')
        return PollResult(response=results)
    else:
        return PollResult(continue_to_poll=True, args_for_next_run={"request_id": request_id, **args},
                          response=None,
                          partial_result=CommandResults(readable_output="The status is pending, still waiting to get results..."))


@polling_function('msg-create-url-assessment-request',
                  timeout=arg_to_number(demisto.args().get("timeout_in_seconds", 720)),
                  requires_polling_arg=False)
def create_url_assessment_request_command(args, client: MsGraphClient) -> PollResult | CommandResults:

    if not (request_id := args.get('request_id')):
        result = client.create_url_assessment_request(args.get('expected_assessment'),
                                                      args.get('category'),
                                                      args.get('url'))
        request_id = result.get('id')

    result = client.get_threat_assessment_request_status(request_id)
    status = result.get('status')
    demisto.debug(f"status is : {status}")
    if status == 'completed':
        result = client.get_threat_assessment_request(request_id)
        outputs = get_result_outputs(result)
        readable_output = tableToMarkdown('URL assessment request results:', outputs, removeNull=True)

        results = CommandResults(readable_output=readable_output,
                                 raw_response=result,
                                 outputs=outputs,
                                 outputs_prefix='MSGraphMail.UrlAssessment')
        return PollResult(response=results)
    else:
        return PollResult(continue_to_poll=True, args_for_next_run={"request_id": request_id, **args},
                          response=None,
                          partial_result=CommandResults(readable_output="The status is pending, still waiting to get results..."))


def list_threat_assessment_requests_command(client: MsGraphClient, args) -> list[CommandResults]:
    command_results = []
    limit = args.get('limit')

    if request_id := args.get('request_id'):
        return get_threat_assessment_request(client, request_id)

    result = client.list_threat_assessment_requests(
        args.get('filter'),
        args.get('order_by'),
        args.get('sort_order'),
        args.get('next_token')
    )
    outputs = []
    requests_list = result.get('value')
    if limit:
        requests_list = requests_list[:limit]
    for req in requests_list:
        outputs.append(get_result_outputs(req))
    readable_outputs = tableToMarkdown('Threat assessment request results:', outputs, removeNull=True)
    command_results.append(CommandResults(readable_output=readable_outputs,
                                          raw_response=result,
                                          outputs=outputs,
                                          outputs_prefix='MSGraphMail.AssessmentRequest'))

    skip_token_field = result.get('@odata.nextLink')
    demisto.debug(f"skip_token_field: {skip_token_field}")
    if skip_token_field:
        next_token_value: List[str] = re.split(r'skip[t|T]oken=', skip_token_field)
        if len(next_token_value) > 1:
            next_token: str = next_token_value[1]

            command_results.append(CommandResults(readable_output=f'Next token is: {next_token}\n' if next_token else None,
                                                  outputs={"next_token": next_token},
                                                  outputs_prefix='MsGraph.AssessmentRequestNextToken'))

    return command_results


def main():
    params: dict = demisto.params()
    args: dict = demisto.args()
    url = params.get('host', '').rstrip('/') + '/v1.0/'
    tenant = params.get('creds_tenant_id', {}).get('password') or params.get('tenant_id')
    auth_and_token_url = params.get('creds_auth_id', {}).get('password') or params.get('auth_id', '')
    enc_key = params.get('creds_enc_key', {}).get('password') or params.get('enc_key')
    use_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    certificate_thumbprint = params.get('creds_certificate', {}).get('identifier') or params.get(
        'certificate_thumbprint')
    private_key = replace_spaces_in_credential(params.get('creds_certificate', {}).get('password')) or params.get(
        'private_key')
    managed_identities_client_id = get_azure_managed_identities_client_id(params)
    self_deployed: bool = params.get('self_deployed', False) or managed_identities_client_id is not None
    api_version: str = params.get('api_version', API_V2)

    if not managed_identities_client_id:
        if not self_deployed and not enc_key:
            raise DemistoException('Key must be provided. For further information see '
                                   'https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication')
        elif not enc_key and not (certificate_thumbprint and private_key):
            raise DemistoException('Key or Certificate Thumbprint and Private Key must be provided.')

    commands = {
        'test-module': test_function,
        'msg-auth-test': test_auth_code_command,
        'msg-search-alerts': search_alerts_command,
        'msg-get-alert-details': get_alert_details_command,
        'msg-update-alert': update_alert_command,
        'msg-get-users': get_users_command,
        'msg-get-user': get_user_command,
        'msg-create-alert-comment': create_alert_comment_command,

        # eDiscovery commands
        'msg-create-ediscovery-case': create_ediscovery_case_command,
        'msg-list-ediscovery-cases': list_ediscovery_case_command,
        'msg-update-ediscovery-case': update_ediscovery_case_command,
        'msg-close-ediscovery-case': close_ediscovery_case_command,
        'msg-reopen-ediscovery-case': reopen_ediscovery_case_command,
        'msg-delete-ediscovery-case': delete_ediscovery_case_command,
        'msg-create-ediscovery-custodian': create_ediscovery_custodian_command,
        'msg-list-ediscovery-custodians': list_ediscovery_custodian_command,
        'msg-release-ediscovery-custodian': release_ediscovery_custodian_command,
        'msg-activate-ediscovery-custodian': activate_ediscovery_custodian_command,
        'msg-create-ediscovery-custodian-user-source': create_ediscovery_custodian_user_source_command,
        'msg-list-ediscovery-custodian-user-sources': list_ediscovery_custodian_user_sources_command,
        'msg-create-ediscovery-custodian-site-source': create_ediscovery_custodian_site_source_command,
        'msg-list-ediscovery-custodian-site-sources': list_ediscovery_custodian_site_sources_command,
        'msg-create-ediscovery-non-custodial-data-source': create_ediscovery_non_custodial_data_source_command,
        'msg-list-ediscovery-non-custodial-data-sources': list_ediscovery_non_custodial_data_source_command,
        'msg-apply-hold-ediscovery-custodian': apply_hold_ediscovery_custodian_command,
        'msg-remove-hold-ediscovery-custodian': remove_hold_ediscovery_custodian_command,
        'msg-create-ediscovery-search': create_ediscovery_search_command,
        'msg-update-ediscovery-search': update_ediscovery_search_command,
        'msg-list-ediscovery-searchs': list_ediscovery_search_command,
        'msg-delete-ediscovery-search': delete_ediscovery_search_command,
        'msg-purge-ediscovery-data': purge_ediscovery_data_command,
        'msg-advanced-hunting': advanced_hunting_command,
        'msg-list-security-incident': get_list_security_incident_command,
        'msg-update-security-incident': update_incident_command,
    }
    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        auth_code = params.get('auth_code', {}).get('password')
        redirect_uri = params.get('redirect_uri')
        grant_type = AUTHORIZATION_CODE if auth_code and redirect_uri else CLIENT_CREDENTIALS

        client: MsGraphClient = MsGraphClient(tenant_id=tenant,
                                              auth_code=auth_code,
                                              auth_id=auth_and_token_url,
                                              enc_key=enc_key,
                                              redirect_uri=redirect_uri,
                                              app_name=APP_NAME,
                                              base_url=url,
                                              verify=use_ssl,
                                              proxy=proxy,
                                              self_deployed=self_deployed,
                                              certificate_thumbprint=certificate_thumbprint,
                                              private_key=private_key,
                                              managed_identities_client_id=managed_identities_client_id,
                                              api_version=api_version,
                                              grant_type=grant_type)
        if command == "fetch-incidents":
            fetch_time = params.get('fetch_time', '1 day')
            fetch_limit = params.get('fetch_limit', 10) or 10
            fetch_providers = params.get('fetch_providers', '')
            fetch_service_sources = params.get('fetch_service_sources', '')
            fetch_filter = params.get('fetch_filter', '')
            incidents = fetch_incidents(client, fetch_time=fetch_time, fetch_limit=int(fetch_limit),
                                        filter=fetch_filter, providers=fetch_providers,
                                        service_sources=fetch_service_sources)
            demisto.incidents(incidents)
        elif command == 'msg-create-mail-assessment-request':
            return_results(create_mail_assessment_request_command(args, client))
        elif command == 'msg-create-email-file-assessment-request':
            return_results(create_email_file_request_command(args, client))
        elif command == 'msg-create-file-assessment-request':
            return_results(create_file_assessment_request_command(args, client))
        elif command == 'msg-create-url-assessment-request':
            return_results(create_url_assessment_request_command(args, client))
        elif command == 'msg-list-threat-assessment-requests':
            return_results(list_threat_assessment_requests_command(client, args))
        elif command == "ms-graph-security-auth-reset":
            return_results(reset_auth())
        elif demisto.command() == 'msg-generate-login-url':
            return_results(generate_login_url(client.ms_client))

        else:
            if command not in commands:
                raise NotImplementedError(f'The provided command {command} was not implemented.')
            command_res = commands[command](client, args)  # type: ignore
            if isinstance(command_res, (CommandResults | list)):
                return_results(command_res)
            else:
                human_readable, entry_context, raw_response = command_res  # pylint: disable=E0633  # type: ignore
                return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=raw_response)

    except Exception as err:
        return_error(f'Failed to execute {command} command.\nError:\n{err}\nTraceback:{traceback.format_exc()}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
