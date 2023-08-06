import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests


import dateparser

from typing import Dict, Any

# Disable insecure warnings
import urllib3
urllib3.disable_warnings()
''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
MAX_PAGE_SIZE = 50
INCIDENT_TYPE_MAPPING = {
    'Network': 'NETWORK',
    'Discover': 'DISCOVER',
    'Endpoint': 'ENDPOINT'
}
INCIDENT_SEVERITY_MAPPING = {
    'Info': 4,
    'Low': 3,
    'Medium': 2,
    'High': 1
}
UPDATE_INCIDENT_SEVERITY_MAPPING = {
    'Info': 'INFO',
    'Low': 'LOW',
    'Medium': 'MEDIUM',
    'High': 'HIGH'
}
INCIDENT_UPDATE_MAPPING = {
    'incident_id': 'incidentIds',
    'data_owner_email': 'dataOwnerEmail',
    'data_owner_name': 'dataOwnerName',
    'note': 'incidentNotes',
    'incident_status_id': 'incidentStatusId',
    'remediation_status_name': 'preventOrProtectStatus',
    'remediation_location': 'remediationLocation',
    'severity': 'severity',
    'custom_attributes': 'incidentCustomAttributes'
}
INCIDENTS_LIST_BODY = [
    {
        "name": "incidentId"
    },
    {
        "name": "incidentStatusId"
    },
    {
        "name": "creationDate"
    },
    {
        "name": "detectionDate"
    },
    {
        "name": "severityId"
    },
    {
        "name": "messageSource"
    },
    {
        "name": "messageTypeId"
    },
    {
        "name": "policyVersion"
    },
    {
        "name": "policyId"
    },
    {
        "name": "matchCount"
    },
    {
        "name": "detectionServerId"
    }
]

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url, verify, proxy, headers, auth):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def get_incidents_request(
        self, creation_date: str = None, status_id: List[str] = None, severity: List[int] = None,
        incident_type: List[str] = None, limit: int = MAX_PAGE_SIZE,
        order_by: bool = None, raw_filter: str = None
    ):
        """Returns incidents list
        in the input (dummy).

        :param creation_date: The creation date to filter. (greater than the creation date)
        :param status_id: The status IDs to filter.
        :param severity: The severities to filter.
        :param incident_type: The incident types to filter.
        :param limit: The limit of the incidents.
        :param order_by: If order by according the creation date or not
        :param raw_filter: Full filter that is used for the body of the request, bypasses all other filters criteria.

        """
        if raw_filter:
            try:
                data = json.loads(raw_filter)
                data["limit"] = limit
            except ValueError as e:
                raise ValueError(f"The provided filter must be in JSON format as detailed"
                                 f" at https://apidocs.securitycloud.symantec.com/#/: "
                                 f"\nError: {e}")
        else:
            data = {"limit": limit, "select": INCIDENTS_LIST_BODY}
            if order_by:

                data["orderBy"] = [{"order": "ASC", "field": {"name": "creationDate"}}]

            if creation_date or status_id or severity or incident_type:

                data['filter'] = {"booleanOperator": "AND", "filterType": "booleanLogic", "filters": []}
                if creation_date:
                    data['filter']['filters'].append(  # type: ignore
                        create_filter_dict(filter_type="localDateTime", filter_by="creationDate",
                                           filter_value=[creation_date], operator="GT"))
                if status_id:
                    data['filter']['filters'].append(  # type: ignore
                        create_filter_dict(filter_type="long", filter_by="incidentStatusId",
                                           filter_value=status_id, operator="IN"))
                if severity:
                    data['filter']['filters'].append(  # type: ignore
                        create_filter_dict(filter_type="long", filter_by="severityId",
                                           filter_value=severity, operator="IN"))
                if incident_type:
                    data['filter']['filters'].append(  # type: ignore
                        create_filter_dict(filter_type="string", filter_by="messageSource",
                                           filter_value=incident_type, operator="IN"))

        headers = self._headers
        response = self._http_request(method='POST', url_suffix='/ProtectManager/webservices/v2/incidents',
                                      json_data=data, headers=headers)
        return response

    def update_incident_request(self, update_body: Dict[str, Any]) -> Dict[str, str]:
        """Update incident
        :param update_body: The details to update in the incident.

        """

        headers = self._headers

        response = self._http_request(method='PATCH', url_suffix='/ProtectManager/webservices/v2/incidents',
                                      headers=headers, json_data=update_body)

        return response

    def get_incident_static_attributes_request(self, incident_id: str) -> Dict[str, str]:
        """Returns incident static attributes.

        :param incident_id: The incident ID.

        """

        headers = self._headers
        response = self._http_request(method='GET', url_suffix=f'/ProtectManager/webservices/'
                                                               f'v2/incidents/{incident_id}/staticAttributes',
                                      headers=headers)

        return response

    def get_incident_editable_attributes_request(self, incident_id: str) -> Dict[str, str]:
        """Returns incident editable attributes.

        :param incident_id: The incident ID.

        """

        headers = self._headers
        response = self._http_request(method='GET', url_suffix=f'/ProtectManager/webservices/'
                                                               f'v2/incidents/{incident_id}/editableAttributes',
                                      headers=headers)

        return response

    def get_incidents_status_request(self) -> List[dict]:
        """Returns incidents status
        """

        headers = self._headers
        response = self._http_request(method='GET', url_suffix='/ProtectManager/webservices/v2/incidents/statuses',
                                      headers=headers)

        return response

    def get_incident_history_request(self, incident_id: Optional[int]) -> List[dict]:
        """Returns incident history

        :param incident_id: The incident ID.

        """

        headers = self._headers
        response = self._http_request(method='GET', url_suffix=f'/ProtectManager/webservices/v2/incidents/'
                                                               f'{incident_id}/history', headers=headers)

        return response

    def get_list_remediation_status_request(self) -> List[dict]:
        """Returns incidents remediation status
        """

        headers = self._headers
        response = self._http_request(method='GET', url_suffix='/ProtectManager/webservices/v2/incidents/'
                                                               'protectOrPreventStatuses', headers=headers)

        return response

    def get_incident_original_message_request(self, incident_id: str) -> requests.Response:
        """Returns incident original message.
        :param incident_id: The incident ID.
        """

        headers = self._headers
        response = self._http_request(method='GET', url_suffix=f'/ProtectManager/webservices/'
                                                               f'v2/incidents/{incident_id}/originalMessage',
                                      headers=headers, resp_type='bytes')
        return response

    def get_report_filters_request(self, report_id: str) -> Dict[str, str]:
        """Returns incident static attributes.

        :param report_id: The report id ID.

        """

        headers = self._headers
        response = self._http_request(method='GET', url_suffix=f'/ProtectManager/webservices/'
                                                               f'v2/savedReport/{report_id}',
                                      headers=headers)

        return response

    def get_sdlp_users_request(self) -> List[dict]:
        """Returns list of SDLP users
        """

        headers = self._headers
        response = self._http_request(method='GET', url_suffix='/ProtectManager/webservices/v2/users',
                                      headers=headers)

        return response

    def get_sender_recipient_pattern_request(self, pattern_id: str) -> Dict[str, str]:
        """Returns incident static attributes.

        :param incident_id: The incident ID.

        """

        headers = self._headers
        response = self._http_request(method='GET', url_suffix=f'/ProtectManager/webservices/'
                                                               f'v2/senderRecipientPattern/{pattern_id}',
                                      headers=headers)

        return response

    def list_sender_recipient_patterns_request(self) -> List[dict]:
        """Returns list of sender/recipient patterns
        """

        headers = self._headers
        response = self._http_request(method='GET',
                                      url_suffix='/ProtectManager/webservices/v2/senderRecipientPattern/list',
                                      headers=headers)

        return response

    def update_sender_pattern_request(
        self,
        pattern_id: str,
        pattern_name: str | None,
        pattern_description: str | None,
        new_ips: List[str] = None,
        new_users: List[str] = None
    ) -> Dict[str, str]:
        """
        Updates the sender pattern

        :param pattern_id: The pattern ID to update
        :param pattern_name: The new name for the sender pattern
        :param pattern_description: The new description for the sender pattern
        :param new_ips: List of new IP address values
        :param new_users: List of new
        """
        headers = self._headers
        data = {
            "name": pattern_name,
            "description": pattern_description,
            "ruleType": 4  # ruleType 4 = Sender pattern
        }

        if new_ips:
            data['ipAddresses'] = new_ips  # type: ignore[assignment]
        if new_users:
            data['userPatterns'] = new_users  # type: ignore[assignment]

        response = self._http_request(method='PUT',
                                      url_suffix=f'/ProtectManager/webservices/v2/senderRecipientPattern/{pattern_id}',
                                      headers=headers, json_data=data)
        return response

    def update_recipient_pattern_request(
        self,
        pattern_id: str,
        pattern_name: str | None,
        pattern_description: str | None,
        new_ips: List[str] = None,
        new_emails: List[str] = None,
        new_domains: List[str] = None
    ) -> Dict[str, str]:
        """
        Updates the sender pattern

        :param pattern_id: The pattern ID to update
        :param pattern_name: The new name for the sender pattern
        :param pattern_description: The new description for the sender pattern
        :param new_ips: List of new IP address values
        :param new_emails: List of new email address values
        :param new_domains: List of new domain values
        """
        headers = self._headers
        data = {
            "name": pattern_name,
            "description": pattern_description,
            "ruleType": 2  # ruleType 2 = Recipient pattern
        }

        if new_ips:
            data['ipAddresses'] = new_ips  # type: ignore[assignment]
        if new_emails:
            data['emailAddresses'] = new_emails  # type: ignore[assignment]
        if new_domains:
            data['urlDomains'] = new_domains  # type: ignore[assignment]

        response = self._http_request(method='PUT',
                                      url_suffix=f'/ProtectManager/webservices/v2/senderRecipientPattern/{pattern_id}',
                                      headers=headers, json_data=data)
        return response

    def get_message_body_request(self, incident_id: str) -> Dict[str, str]:
        """Returns incident message body.
        :param incident_id: The incident ID.
        """

        headers = self._headers
        response = self._http_request(method='GET',
                                      url_suffix=f'/ProtectManager/webservices/v2/incidents/{incident_id}/messageBody',
                                      headers=headers)
        return response


''' HELPER FUNCTIONS '''


def check_status_ids_type(status_ids_list: list):
    if not all(status_id.isdigit() for status_id in status_ids_list):
        raise ValueError("Status IDs must be integers.")
    return status_ids_list


def create_filter_dict(filter_type: str, filter_by: str, filter_value: List[Any], operator: str) -> Dict[str, Any]:
    """Creates a dictionary with the filter for the list-incidents request.

    :param filter_type: The filter type.
    :param filter_by: The field name to filter by.
    :param filter_value: The filter value.
    :param operator: The operator to use for the filter.

    """
    return {"filterType": filter_type, "operandOne": {"name": filter_by},
            "operandTwoValues": filter_value, "operator": operator}


def get_severity_name_by_id(severity: Optional[int]):
    """Returns the name of the severity according to the given severity ID

    :param severity: The severity ID.

    """
    for severity_name, severity_num in INCIDENT_SEVERITY_MAPPING.items():
        if severity_num == severity:
            return severity_name


def parse_creation_date(creation_date: str):
    if creation_date:
        creation_date = dateparser.parse(creation_date).strftime(DATE_FORMAT)  # type: ignore
    return creation_date


def get_readable_output_incidents_list(incidents_list: List[dict]):
    readable_output = []

    for incident in incidents_list:
        readable_output.append(assign_params(**{
            'ID': incident.get('incidentId'),
            'Severity': get_severity_name_by_id(arg_to_number(incident.get('severityId'))),
            'Status': incident.get('incidentStatusId'),
            'Incident Type': incident.get('messageSource'),
            'Creation Date': incident.get('creationDate'),
            'Message Type': incident.get('messageType'),
            'Policy ID': incident.get('policyId'),
            'Match Count': incident.get('matchCount')

        }))

    return readable_output


def get_context_incidents_list(incidents_list: List[dict]):
    for incident in incidents_list:
        incident_id = {'ID': incident.get('incidentId')}
        incident_severity = {"severity": get_severity_name_by_id(arg_to_number(incident.get('severityId')))}
        incident.pop('severityId')
        incident.pop('incidentId')
        incident.update(incident_id)
        incident.update(incident_severity)

    return incidents_list


def get_readable_output_incident_details(incidents_list: List[dict]):
    readable_output = []

    for incident in incidents_list:
        readable_output.append(assign_params(**{
            'ID': incident.get('incidentId'),
            'Severity': get_severity_name_by_id(incident.get('severityId')),
            'Incident Type': incident.get('messageSource'),
            'Creation Date': incident.get('creationDate'),
            'Detection Date': incident.get('detectionDate'),
            'Message Type': incident.get('messageType'),
            'Message Source': incident.get('messageSource'),
            'Detection Server Name': incident.get('detectionServerName'),
            'Data Owner Name': incident.get('dataOwnerName'),
            'Data Owner Email': incident.get('dataOwnerEmail'),
            'Status': incident.get('incidentStatusId'),
            'Policy Name': incident.get('policyName'),
            'Policy Group Name': incident.get('policyGroupName'),
            'Custom Attributes': incident.get('customAttributeGroup')
        }))

    return readable_output


def get_incidents_of_current_page(limit, page, page_size, incidents_list):
    """
    :param limit: The limit of the incidents.
    :param page: The page number
    :param page_size: Maximum number of objects to retrieve per page.
    :param incidents_list: The incidents list

    :return: List of objects from the response according to the limit, page and page_size.

    """
    if page is not None and page_size is not None:
        if page <= 0:
            raise Exception('Chosen page number must be greater than 0')
        start = (page - 1) * page_size
        end = page * page_size
        return incidents_list[start:end]
    limit = limit if limit else MAX_PAGE_SIZE

    return incidents_list[0:limit]


def parse_custom_attribute(custom_attribute_group_list: list, args: dict) -> list:
    """
    Returns a list of all custom attributes chosen by the user.
    There are four options to choose from: all, none, specific attributes, custom attributes group name.
    The choosing flag is given in demisto.args value in the field custom_attributes.
    If the user has chosen "all" then the function will return all custom attributes possible (from all groups).
    If the user has chosen "none" then the function won't return any custom attributes.
    If the user has chosen "specific attributes" then he must also provide a list of all custom attribute names in the
    demisto.args dict under the field "custom_data". If not provided, an error msg will be shown. If provided,
    the function will return only the custom attributes mentioned in the custom_data list.
    If the user has chosen "custom attributes group name" the handling of this option is similar to the "custom" option.
    :param custom_attribute_group_list: the raw list of custom attributes group (as returned from the request)
    :param args: demisto.args
    :return: the parsed custom attributes list
    """
    custom_attributes_flag = args.get('custom_attributes')
    custom_attributes_list: list = []

    # all case
    if custom_attributes_flag == 'all':
        for group in custom_attribute_group_list:
            custom_attributes_list.append(get_all_group_custom_attributes(group))

    # custom attributes group name case
    elif custom_attributes_flag == 'custom attribute group name':
        custom_data = args.get('custom_data')
        if not custom_data:
            raise DemistoException('When choosing the group value for custom_attributes argument - the custom_data'
                                   ' list must be filled with group names. For example: custom_value=g1,g2,g3')
        group_name_list: list = argToList(custom_data, ',')
        for group in custom_attribute_group_list:
            if group.get('name') in group_name_list:
                custom_attributes_list.append(get_all_group_custom_attributes(group))

    # specific attributes case
    elif custom_attributes_flag == 'specific attributes':
        custom_data = args.get('custom_data')
        if not custom_data:
            raise DemistoException('When choosing the custom value for custom_attributes argument - the custom_data'
                                   ' list must be filled with custom attribute names.'
                                   ' For example: custom_value=ca1,ca2,ca3')
        custom_attribute_name_list: list = argToList(custom_data, ',')
        for group in custom_attribute_group_list:
            for raw_custom_attribute in group.get('customAttributes', []):
                custom_attribute_name: str = raw_custom_attribute.get('name')
                if custom_attribute_name in custom_attribute_name_list:
                    custom_attribute: dict = {'name': custom_attribute_name}
                    custom_attribute_value = raw_custom_attribute.get('value')
                    if custom_attribute_value:
                        custom_attribute['value'] = custom_attribute_value
                    custom_attribute['index'] = raw_custom_attribute.get('index')
                    custom_attributes_list.append({'name': group.get('name'), 'customAttribute': custom_attribute})

    # none case - If custom_attributes_flag == 'none' than we return empty list
    return custom_attributes_list


def get_all_group_custom_attributes(group: dict) -> dict:
    """
    Returns a list of all the custom attributes in the group
    :param group: the group
    :return: the list of all custom attributes
    """
    custom_attributes_dict: dict = {'name': group.get('name'), 'customAttribute': []}
    for raw_custom_attribute in group.get('customAttributes', []):
        custom_attribute: dict = {'name': raw_custom_attribute.get('name'), 'index': raw_custom_attribute.get('index')}
        custom_attribute_value = raw_custom_attribute.get('value')
        if custom_attribute_value:
            custom_attribute['value'] = custom_attribute_value
        custom_attributes_dict['customAttribute'].append(custom_attribute)
    return custom_attributes_dict


def get_common_incident_details(static_attributes: dict, editable_attributes: dict, args) -> dict:
    """
    Parses the needed incident details into context paths
    :param static_attributes: The static attributes of the incident
    :param editable_attributes: The editable attributes of the incident
    :param args: demisto.args
    :return: the parsed dict
    """
    incident_info_map_editable = editable_attributes.get('infoMap', {})
    incident_info_map_static = static_attributes.get('infoMap', {})
    incident_custom_attribute_groups = editable_attributes.get('customAttributeGroups', [])
    incident_details: dict = assign_params(**{
        'ID': static_attributes.get('incidentId'),
        'severity': get_severity_name_by_id(arg_to_number(incident_info_map_editable.get('severityId'))),
        'customAttributeGroup': parse_custom_attribute(incident_custom_attribute_groups, args),
    })
    static_attributes.pop('incidentId')
    editable_attributes.pop('incidentId')
    incident_info_map_editable.pop('severityId')
    editable_attributes.pop('customAttributeGroups', [])
    incident_details.update(incident_info_map_static)
    incident_details.update(incident_info_map_editable)

    return assign_params(**incident_details)


def get_details_unauthorized_incident(incident_data):
    incident_details: dict = assign_params(**{
        'ID': incident_data.get('incidentId'),
        'creationDate': incident_data.get('creationDate'),
        'policyId': incident_data.get('policyId'),
        'severity': get_severity_name_by_id(arg_to_number(incident_data.get('severityId'))),
        'incidentStatusId': incident_data.get('incidentStatusId'),
        'detectionDate': incident_data.get('detectionDate'),
        'policyVersion': incident_data.get('policyVersion'),
        'messageSource': incident_data.get('messageSource'),
        'messageType': incident_data.get('messageType'),
        'matchCount': incident_data.get('matchCount'),
        'errorMessage': "Notice: Incident contains partial data only"
    })

    return {key: val for key, val in incident_details.items() if val}


def get_hr_context_incidents_status(status_list: List[dict]):
    status_readable_output = []

    for status in status_list:
        status_readable_output.append(assign_params(**{
            'id': status.get('id'),
            'name': status.get('name'),
        }))

    return status_readable_output


def get_readable_output_incident_history(incident_history_list: List[dict]):
    history_readable_output = []

    for incident_history in incident_history_list:
        history_readable_output.append(assign_params(**{
            'History Date': incident_history.get('incidentHistoryDate'),
            'Incident History Action': incident_history.get('incidentHistoryAction'),
            'DLP User Name': incident_history.get('dlpUserName')
        }))
    return history_readable_output


def get_context_incident_history(incident_history_list: List[dict]):
    history_context = []
    incident_id = arg_to_number(incident_history_list[0].get('incidentId'))
    for incident_history in incident_history_list:
        incident_history.pop('incidentId')
        incident_history.pop('incidentHistoryActionI18nKey')
        incident_history.pop('internationalized')
    history_context.append({"ID": incident_id, "incidentHistory": incident_history_list})

    return history_context


def create_update_body(incident_ids: list, data_owner_email: str = None, data_owner_name: str = None,
                       note: str = None,
                       incident_status_id: str = None, remediation_status_name: str = None,
                       remediation_location: str = None,
                       severity: str = None, custom_attributes: List[str] = None):
    data: Dict[str, Any] = assign_params(**{"incidentIds": incident_ids, 'dataOwnerEmail': data_owner_email,
                                            'dataOwnerName': data_owner_name,
                                            'incidentStatusId': incident_status_id,
                                            'preventOrProtectStatus': remediation_status_name,
                                            'remediationLocation': remediation_location, 'severity': severity})
    custom_attributes_list = build_custom_attributes_update(custom_attributes)  # type: ignore
    if custom_attributes_list:
        data['incidentCustomAttributes'] = custom_attributes_list
    if note:
        data['incidentNotes'] = [{'note': note}]
    return data


def build_custom_attributes_update(custom_attributes: List[str]):
    """
    Builds the custom_attributes_list that the user wants to update. The input should be {columnIndex}:{newValue}.
    :param custom_attributes: The custom attributes the user wants to update
    :return: A list of custom attributes
    """
    custom_attributes_list = []
    for attribute in custom_attributes:
        splitted_att = attribute.split(':')
        if len(splitted_att) != 2:
            raise DemistoException('Error: custom_attributes argument format is {columnIndex}:{newValue}. E.g: 1:test')
        attribute_index = splitted_att[0]
        if not attribute_index.isdigit():
            raise DemistoException('Error: The attribute index must be an integer.')
        attribute_value = splitted_att[1]
        custom_attributes_list.append({"columnIndex": int(attribute_index), "value": attribute_value})
    return custom_attributes_list


def get_incident_details_fetch(client, incident):
    """
    Create incident details dict for each incident pulled from the fetch
    In case of getting 401 error we will return missing data on the incident.
    """
    incident_details = {}
    try:
        incident_id = incident.get('incidentId')
        static_attributes = client.get_incident_static_attributes_request(incident_id)
        editable_attributes = client.get_incident_editable_attributes_request(incident_id)
        incident_details = get_common_incident_details(static_attributes, editable_attributes,
                                                       args={"custom_attributes": "all"})
    # In case of getting 401 (Unauthorized incident) - will get missing data
    except DemistoException as e:
        if '401' in str(e):
            incident_details = get_details_unauthorized_incident(incident)
        else:
            raise e
    return incident_details


''' COMMAND FUNCTIONS '''


def test_module(client: Client, params, fetch_time, fetch_limit, incident_type, incident_status_id,
                incident_severity) -> str:
    message: str = ''

    try:
        if params.get('isFetch'):
            fetch_incidents(client, fetch_time=fetch_time, fetch_limit=fetch_limit, last_run={},
                            incident_types=incident_type, incident_status_id=incident_status_id,
                            incident_severities=incident_severity, is_test=True)
        else:
            client.get_incidents_request()
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Unauthorized' in str(e):
            message = 'Authorization Error: make sure username and password are correctly set'
        else:
            raise e
    return message


def list_incidents_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    creation_date = parse_creation_date(args.get('creation_date', ''))
    status_ids = argToList(args.get('status_id', ''))
    severities = argToList(args.get('severity', ''))
    severities_dlp = [INCIDENT_SEVERITY_MAPPING[severity] for severity in severities]
    incident_types = argToList(args.get('incident_type', ''))
    incident_types_dlp = [INCIDENT_TYPE_MAPPING[incident_type] for incident_type in incident_types]
    limit = arg_to_number(args.get('limit', 50))
    page = arg_to_number(args.get('page', 1))
    page_size = arg_to_number(args.get('page_size'))
    raw_filter = args.get('raw_filter')
    try:
        incidents_result = client.get_incidents_request(
            creation_date,
            status_ids,
            severities_dlp,
            incident_types_dlp,
            limit * page,  # type: ignore[operator]
            raw_filter=raw_filter
        )
    except DemistoException as error:
        if raw_filter:
            raise DemistoException(f'Please make sure the {raw_filter=} is correct, {error=}')
        raise
    incidents_result = get_incidents_of_current_page(limit, page, page_size,
                                                     incidents_list=incidents_result.get('incidents', []))
    if raw_filter:
        list_incidents_hr = incidents_result
        context_incidents_list = incidents_result
        if incidents_result:
            output_headers = list(incidents_result[0].keys())
        else:
            output_headers = None
    else:
        list_incidents_hr = get_readable_output_incidents_list(incidents_result)
        context_incidents_list = get_context_incidents_list(incidents_result)
        output_headers = ['ID', 'Severity', 'Status', 'Creation Date', 'Incident Type', 'Message Type', 'Policy ID',
                          'Match Count']

    return CommandResults(
        readable_output=tableToMarkdown(
            "Symantec DLP incidents results",
            list_incidents_hr,
            removeNull=True,
            headers=output_headers
        ),
        outputs_prefix='SymantecDLP.Incident',
        outputs_key_field='ID',
        outputs=context_incidents_list,
    )


def update_incident_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    incident_ids = argToList(args.get('incident_ids'))
    if not all(incident_id.isdigit() for incident_id in incident_ids):
        raise ValueError("Incident IDs must be integers.")
    data_owner_email = args.get('data_owner_email', '')
    data_owner_name = args.get('data_owner_name', '')
    note = args.get('note', '')
    incident_status_id = args.get('incident_status_id', '')
    remediation_status_name = args.get('remediation_status_name', '')
    remediation_location = args.get('remediation_location', '')
    severity = args.get('severity', '')
    if severity:
        severity = UPDATE_INCIDENT_SEVERITY_MAPPING[severity]
    custom_attributes = argToList(args.get('custom_attributes', ''))

    update_body = create_update_body(incident_ids=incident_ids, data_owner_email=data_owner_email,
                                     data_owner_name=data_owner_name, note=note, incident_status_id=incident_status_id,
                                     remediation_status_name=remediation_status_name,
                                     remediation_location=remediation_location, severity=severity,
                                     custom_attributes=custom_attributes)
    client.update_incident_request(update_body)
    return CommandResults(
        readable_output=f"Symantec DLP incidents: {incident_ids} were updated"
    )


def get_incident_details_command(client: Client, args: Dict[str, Any]):
    """
    static attributes API docs - https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/
    data-loss-prevention/15-8/DLP-Enforce-REST-APIs-overview/definitions/staticincidentinfomap.html
    editable attributes API docs - https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/
    data-loss-prevention/15-8/DLP-Enforce-REST-APIs-overview/definitions/editableincidentinfomap.html
    """
    try:
        incident_id = args.get('incident_id', '')
        custom_attributes = args.get('custom_attributes', '')
        custom_data = args.get('custom_data', '')

        if custom_attributes in ['specific_attributes', 'custom_attribute_group_name'] and not custom_data:
            raise DemistoException('Error: custom_data argument must be provided if you chose specific_attributes or'
                                   ' custom_attribute_group_name.')

        static_attributes = client.get_incident_static_attributes_request(incident_id)
        editable_attributes = client.get_incident_editable_attributes_request(incident_id)

        incident_details = get_common_incident_details(static_attributes, editable_attributes, args=args)
        incident_details_hr = get_readable_output_incident_details([incident_details])

        return CommandResults(
            readable_output=tableToMarkdown(
                f"Symantec DLP incident {incident_id} details",
                incident_details_hr,
                removeNull=True,
                json_transform_mapping={
                    'Custom Attributes': JsonTransformer(keys=('GroupName', 'name', 'value'), is_nested=True)},
                headers=['ID', 'Severity', 'Status', 'Creation Date', 'Detection Date', 'Incident Type', 'Policy Name',
                         'Policy Group Name', 'Detection Server Name', 'Message Type', 'Message Source',
                         'Data Owner Name',
                         'Data Owner Email', 'Custom Attributes']
            ),
            outputs_prefix='SymantecDLP.Incident',
            outputs_key_field='ID',
            outputs=incident_details,
        )
    except DemistoException as e:
        if '401' in str(e):
            raise DemistoException(f"Error 401: Incident access not authorized or the incident does not exist. {e.res}")
        else:
            raise DemistoException(f"Error {e.res}")


def list_incident_status_command(client: Client) -> CommandResults:
    incidents_status_result = client.get_incidents_status_request()

    return CommandResults(
        readable_output=tableToMarkdown(
            "Symantec DLP incidents status",
            camelize(incidents_status_result),
            removeNull=True,
        ),
        outputs_prefix='SymantecDLP.IncidentStatus',
        outputs_key_field='id',
        outputs=incidents_status_result,
    )


def get_incident_history_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    incident_id = arg_to_number(args.get('incident_id'))
    limit = arg_to_number(args.get('limit', 50))
    incident_history_result = client.get_incident_history_request(incident_id)
    incident_history_result = incident_history_result[:limit]
    incidents_history_hr = get_readable_output_incident_history(incident_history_result)

    incidents_history_context = get_context_incident_history(incident_history_result)
    return CommandResults(
        readable_output=tableToMarkdown(
            f"Symantec DLP Incident {incident_id} history results",
            incidents_history_hr,
            removeNull=True
        ),
        outputs_prefix='SymantecDLP.IncidentHistory',
        outputs_key_field='incidentId',
        outputs=remove_empty_elements(incidents_history_context),
    )


def get_list_remediation_status(client: Client) -> CommandResults:
    remediation_status_result = client.get_list_remediation_status_request()
    remediation_status_output = get_hr_context_incidents_status(remediation_status_result)

    return CommandResults(
        readable_output=tableToMarkdown(
            "Incidents remediation status results",
            camelize(remediation_status_output),
            removeNull=True
        ),
        outputs_prefix='SymantecDLP.IncidentRemediationStatus',
        outputs_key_field='id',
        outputs=remediation_status_output,
    )


def get_incident_original_message_command(client: Client, args: Dict[str, Any]):
    """
    Fetch the original message
    """
    try:
        incident_id = args.get('incident_id', '')
        results = client.get_incident_original_message_request(incident_id)
        original_message_file = results.content

        try:
            original_filename = results.headers.get('Content-Disposition').split('=')[1]  # type: ignore[union-attr]
        except (TypeError, IndexError, AttributeError):
            original_filename = 'unknown'
        return fileResult(original_filename, original_message_file)

    except DemistoException as e:
        if '401' in str(e):
            raise DemistoException(f"Error 401: Incident access not authorized or the incident does not exist. {e.res}")
        else:
            raise DemistoException(f"Error {e.res}")


def get_report_filters_command(client: Client, args: Dict[str, Any]):
    """
    Get report filters
    """
    try:
        report_id = args.get('report_id', '')
        report_results = client.get_report_filters_request(report_id)
        report_results['filterString'] = json.dumps(report_results)
        return CommandResults(
            readable_output=f'Returned results for report id {report_id}',
            outputs_prefix='SymantecDLP.ReportFilter',
            outputs=report_results,
            outputs_key_field="id"
        )
    except DemistoException as e:
        if '401' in str(e):
            raise DemistoException(f"Error 401: Report access not authorized or the report does not exist. {e.res}")
        else:
            raise DemistoException(f"Error {e.res}")


def list_users_command(client: Client) -> CommandResults:
    users_results = client.get_sdlp_users_request()

    return CommandResults(
        readable_output=tableToMarkdown(
            "Symantec DLP Users",
            camelize(users_results),
            removeNull=True,
        ),
        outputs_prefix='SymantecDLP.Users',
        outputs_key_field='id',
        outputs=users_results,
    )


def get_sender_recipient_pattern_command(client: Client, args: Dict[str, Any]):
    """
    Fetch the original message
    """
    pattern_id = args.get('pattern_id', '')
    pattern_results = client.get_sender_recipient_pattern_request(pattern_id)

    return CommandResults(
        readable_output=tableToMarkdown(
            name=pattern_results.get('name') or f'Pattern Results for Pattern ID {pattern_id}',
            t=pattern_results,
        ),
        outputs_prefix='SymantecDLP.SenderRecipientPattern',
        outputs=pattern_results,
        outputs_key_field='id'
    )


def list_sender_recipient_patterns_command(client: Client) -> CommandResults:
    patterns_results = client.list_sender_recipient_patterns_request()

    return CommandResults(
        readable_output=tableToMarkdown(
            "Sender/Recipient Patterns",
            patterns_results
        ),
        outputs_prefix='SymantecDLP.Patterns',
        outputs=patterns_results,
        outputs_key_field='id'
    )


def update_sender_pattern_command(client: Client, args: Dict[str, Any]):
    """
    Update the sender pattern
    """
    pattern_id = args.get('pattern_id', '')
    pattern_name = args.get('name')
    pattern_description = args.get('description')
    new_ips = argToList(args.get('ips', []))
    new_users = argToList(args.get('users', []))

    update_results = client.update_sender_pattern_request(
        pattern_id, pattern_name, pattern_description, new_ips, new_users
    )

    return CommandResults(
        readable_output=tableToMarkdown(
            "Sender Pattern Update Results",
            update_results
        ),
        outputs_prefix='SymantecDLP.SenderUpdate',
        outputs=update_results,
        outputs_key_field="id"
    )


def update_recipient_pattern_command(client: Client, args: Dict[str, Any]):
    """
    Update the sender pattern
    """
    pattern_id = args.get('pattern_id', '')
    pattern_name = args.get('name')
    pattern_description = args.get('description')
    new_ips = argToList(args.get('ips', []))
    new_emails = argToList(args.get('emails', []))
    new_domains = argToList(args.get('domains', []))

    update_results = client.update_recipient_pattern_request(
        pattern_id, pattern_name, pattern_description, new_ips, new_emails, new_domains)

    return CommandResults(
        readable_output=tableToMarkdown(
            "Sender Pattern Update Results",
            update_results
        ),
        outputs_prefix='SymantecDLP.RecipientUpdate',
        outputs=update_results,
        outputs_key_field="id"
    )


def get_message_body_command(client: Client, args: Dict[str, Any]):
    """
    Fetch the message body
    """
    try:
        incident_id = args.get('incident_id', '')
        body_results = client.get_message_body_request(incident_id)
        results = {
            "IncidentID": incident_id,
            "MessageBody": body_results
        }
        return CommandResults(
            readable_output=f'Message body for incident {incident_id} written to context data',
            outputs_prefix='SymantecDLP.MessageBody',
            outputs=results,
            outputs_key_field="id"
        )
    except DemistoException as e:
        if '401' in str(e):
            raise DemistoException(f"Error 401: Incident access not authorized or the incident does not exist. {e.res}")
        else:
            raise DemistoException(f"Error {e.res}")


def is_incident_already_fetched_in_previous_fetch(last_update_time, incident_creation_date):
    """
    Checks if the incident was already fetched
    :param last_update_time: last_update_time from last_run
    :param incident_creation_date: The current incident creation date

    """
    return last_update_time and last_update_time >= incident_creation_date


def fetch_incidents(client: Client, fetch_time: str, fetch_limit: int, last_run: dict, incident_types: List[str] = None,
                    incident_status_id: List[str] = None, incident_severities: List[str] = None, is_test=False):
    """
    Performs the fetch incidents functionality, which means that every minute if fetches incidents
    from Symantec DLP and uploads them to Cortex XSOAR server.
    There are multiple incidents created at the same time, that is why we check the lasst update time and incident ID
    to make sure we will not fetch an incident that we already fetched.
    :param client: Cortex XSOAR Client
    :param fetch_time: For the first time the integration is enabled with the fetch incidents functionality, the fetch
    time indicates from what time to start fetching existing incidents in Symantec DLP system.
    :param fetch_limit: Indicates how many incidents to fetch every minute
    :param last_run: Cortex XSOAR last run object
    :param incident_types: The incident type to filter.
    :param incident_status_id: The incident status ID to filter.
    :param incident_severities: The incident severities to filter.
    :param is_test: If we test the fetch for the test module
    :return: A list of Cortex XSOAR incidents
    """
    incidents = []
    if incident_severities:
        incident_severities = [INCIDENT_SEVERITY_MAPPING[severity] for severity in incident_severities]  # type: ignore
    if incident_types:
        incident_types = [INCIDENT_TYPE_MAPPING[incident_type] for incident_type in incident_types]

    if last_run:
        last_update_time = last_run.get('last_incident_creation_time')

    else:
        # In first run
        last_update_time = parse_creation_date(fetch_time)

    incidents_data_res = client.get_incidents_request(status_id=incident_status_id,
                                                      severity=incident_severities,  # type: ignore
                                                      incident_type=incident_types, limit=fetch_limit,
                                                      creation_date=last_update_time, order_by=True)

    incidents_data_list = incidents_data_res.get('incidents', [])

    for incident_data in incidents_data_list:
        incident_id = incident_data.get('incidentId')
        incident_creation_time = incident_data.get('creationDate')

        if is_incident_already_fetched_in_previous_fetch(last_update_time, incident_creation_time):
            # Skipping last incident from last cycle if fetched again
            continue

        incident_details = get_incident_details_fetch(client, incident_data)
        incident: dict = {
            'rawJSON': json.dumps(incident_details),
            'name': f'Symantec DLP Incident ID {incident_id}',
            'occurred': parse_creation_date(incident_creation_time)
        }
        incidents.append(incident)
        if incident_creation_time == incidents_data_list[-1].get('creationDate'):
            last_update_time = incident_creation_time

    if is_test:
        return None

    demisto.setLastRun(
        {
            'last_incident_creation_time': last_update_time
        }
    )
    # Sort the incidents list because the incident's ID and creation date are not synchronize
    sorted_incidents = sorted(incidents, key=lambda d: d['name'])
    return sorted_incidents


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    try:
        params = demisto.params()
        server = params.get('server', '')
        credentials = params.get('credentials', {})
        username = credentials.get('identifier', '')
        password = credentials.get('password', '')
        incident_type = argToList(params.get('fetchIncidentType'), 'Network,Discover,Endpoint')
        incident_status_id = check_status_ids_type(argToList(params.get('incidentStatusId', '')))
        incident_severity = argToList(params.get('incidentSeverity'), 'Medium,High')
        verify_certificate = not params.get('insecure', False)
        proxy = params.get('proxy', False)

        fetch_time = params.get('first_fetch', '3 days').strip()
        try:
            fetch_limit: int = int(params.get('max_fetch', 10))
            fetch_limit = MAX_PAGE_SIZE if fetch_limit > MAX_PAGE_SIZE else fetch_limit

        except ValueError:
            raise DemistoException('Value for fetch limit must be an integer.')

        client = Client(
            base_url=server,
            verify=verify_certificate,
            headers={"Content-type": "application/json"},
            proxy=proxy,
            auth=(username, password)
        )

        args = demisto.args()

        demisto.debug(f'Command being called is {demisto.command()}')

        if demisto.command() == 'test-module':
            result = test_module(client, params, fetch_time, fetch_limit, incident_type, incident_status_id,
                                 incident_severity)
            return_results(result)
        elif demisto.command() == 'fetch-incidents':
            last_run = demisto.getLastRun()
            incidents = fetch_incidents(client, fetch_time, fetch_limit, last_run, incident_type, incident_status_id,
                                        incident_severity)
            demisto.incidents(incidents)
        elif demisto.command() == 'symantec-dlp-list-incidents':
            return_results(list_incidents_command(client, args))
        elif demisto.command() == 'symantec-dlp-get-incident-details':
            return_results(get_incident_details_command(client, args))
        elif demisto.command() == 'symantec-dlp-update-incident':
            return_results(update_incident_command(client, args))
        elif demisto.command() == 'symantec-dlp-list-incident-status':
            return_results(list_incident_status_command(client))
        elif demisto.command() == 'symantec-dlp-get-incident-history':
            return_results(get_incident_history_command(client, args))
        elif demisto.command() == 'symantec-dlp-list-remediation-status':
            return_results(get_list_remediation_status(client))
        elif demisto.command() == 'symantec-dlp-get-incident-original-message':
            return_results(get_incident_original_message_command(client, args))
        elif demisto.command() == 'symantec-dlp-get-report-filters':
            return_results(get_report_filters_command(client, args))
        elif demisto.command() == 'symantec-dlp-list-users':
            return_results(list_users_command(client))
        elif demisto.command() == 'symantec-dlp-get-sender-recipient-pattern':
            return_results(get_sender_recipient_pattern_command(client, args))
        elif demisto.command() == 'symantec-dlp-list-sender-recipient-patterns':
            return_results(list_sender_recipient_patterns_command(client))
        elif demisto.command() == 'symantec-dlp-update-sender-pattern':
            return_results(update_sender_pattern_command(client, args))
        elif demisto.command() == 'symantec-dlp-update-recipient-pattern':
            return_results(update_recipient_pattern_command(client, args))
        elif demisto.command() == 'symantec-dlp-get-message-body':
            return_results(get_message_body_command(client, args))
    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
