import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
from requests import Session
from zeep import Client, Settings
from zeep.transports import Transport
from requests.auth import AuthBase, HTTPBasicAuth
from zeep import helpers
from zeep.cache import SqliteCache
from datetime import datetime
from typing import Dict, Tuple, Any
from dateutil.parser import parse
import urllib3
import uuid
import tempfile
import os
import shutil

# Disable insecure warnings
urllib3.disable_warnings()


def get_cache_path():
    path = tempfile.gettempdir() + "/zeepcache"
    try:
        os.makedirs(path)
    except OSError:
        if os.path.isdir(path):
            pass
        else:
            raise
    db_path = os.path.join(path, "cache.db")
    try:
        if not os.path.isfile(db_path):
            static_init_db = os.getenv('ZEEP_STATIC_CACHE_DB', '/zeep/static/cache.db')
            if os.path.isfile(static_init_db):
                demisto.debug(f'copying static init db: {static_init_db} to: {db_path}')
                shutil.copyfile(static_init_db, db_path)
    except Exception as ex:
        # non fatal
        demisto.error(f'Failed copying static init db to: {db_path}. Error: {ex}')
    return db_path


class SymantecAuth(AuthBase):
    def __init__(self, user, password, host):
        self.basic = HTTPBasicAuth(user, password)
        self.host = host

    def __call__(self, r):
        if r.url.startswith(self.host):
            return self.basic(r)
        else:
            return r


''' HELPER FUNCTIONS '''


def get_data_owner(data_owner: Any) -> dict:
    """
    parses the data owner object
    :param data_owner: the data owner object, can be of any type
    :return: the parsed object
    """
    if data_owner and isinstance(data_owner, dict):
        return {'Name': data_owner.get('name'), 'Email': data_owner.get('email')}
    if data_owner and not isinstance(data_owner, dict):
        LOG(f"A data owner was found in the incident, but did not match the expected format.\n "
            f"Found: {str(data_owner)}")
    return {}


def get_incident_binaries(client: Client, incident_id: str, include_original_message: bool = True,
                          include_all_components: bool = True) -> Tuple[str, dict, list, dict]:
    """
    This function get's the binaries of a specific incident with the id incident_id
    It generates the human readable, entry context & raw response. It also generates the binary files.
    :param client: The client
    :param incident_id: The ID of the incident
    :param include_original_message: Indicates whether the Web Service should include the original message
        in the response document.
    :param include_all_components: Indicates whether the Web Service should include all message components
        (for example, headers and file attachments) in the response document.
    :return: The human readable, entry context, file entries & raw response
    """

    raw_incident_binaries = client.service.incidentBinaries(
        incidentId=incident_id,
        includeOriginalMessage=include_original_message,
        includeAllComponents=include_all_components,
    )

    human_readable: str
    entry_context: dict = {}
    raw_response: dict = {}
    file_entries: list = []

    if raw_incident_binaries:
        serialized_incident_binaries: dict = helpers.serialize_object(raw_incident_binaries)
        raw_response = json.loads(json.dumps(serialized_incident_binaries, default=bytes_to_string))
        raw_components = serialized_incident_binaries.get('Component')
        components: list = parse_component(raw_components)  # type: ignore[arg-type]

        incident_binaries: dict = {
            'ID': serialized_incident_binaries.get('incidentId'),
            'OriginalMessage': serialized_incident_binaries.get('originalMessage'),
            'Component(val.ID && val.ID === obj.ID)': components,
            'LongID': serialized_incident_binaries.get('incidentLongId')
        }

        raw_headers: list = ['ID', 'OriginalMessage', 'LongID']
        headers: list = ['ID', 'Original Message', 'Long ID']
        outputs: dict = {}
        for raw_header in raw_headers:
            outputs[headers[raw_headers.index(raw_header)]] = incident_binaries.get(raw_header)
        human_readable = tableToMarkdown(f'Symantec DLP incident {incident_id} binaries', outputs,
                                         headers=headers, removeNull=True)

        for raw_component in raw_components:  # type: ignore[union-attr]
            filename = raw_component.get('name')
            data = raw_component.get('content')
            if isinstance(data, (str, bytes)):
                file_entries.append(fileResult(filename=filename, data=data))

        entry_context = {'SymantecDLP.Incident(val.ID && val.ID === obj.ID)': incident_binaries}
    else:
        human_readable = 'No incident found.'

    return human_readable, entry_context, file_entries, raw_response


def parse_text(raw_text_list: list) -> list:
    """
    Return the parsed text list
    :param raw_text_list: the raw text list
    :return: the parsed text list
    """
    text_list: list = []
    for raw_text in raw_text_list:
        text: dict = {
            'Data': raw_text.get('_value_1'),
            'Type': raw_text.get('type'),
            'RuleID': raw_text.get('ruleId'),
            'RuleName': raw_text.get('ruleName')
        }
        text_list.append({key: val for key, val in text.items() if val})
    return text_list


def parse_violation_segment(raw_violation_segment_list: list) -> list:
    """
    Return the parsed violation segment list
    :param raw_violation_segment_list: the raw violating segment list
    :return: the parsed violation segment list
    """
    violation_segment_list: list = []
    for raw_violation_segment in raw_violation_segment_list:
        violation_segment: dict = {
            'DocumentViolation': raw_violation_segment.get('documentViolation'),
            'FileSizeViolation': raw_violation_segment.get('fileSizeViolation'),
            'Text': parse_text(raw_violation_segment.get('text', []))
        }
        violation_segment_list.append({key: val for key, val in violation_segment.items() if val})
    return violation_segment_list


def parse_violating_component(raw_violating_component_list: list) -> list:
    """
    Return the parsed violating component list
    :param raw_violating_component_list: the raw violating component list
    :return: the parsed violating component list
    """
    violating_component_list: list = []
    for raw_violating_component in raw_violating_component_list:
        violating_component_type: dict = raw_violating_component.get('violatingComponentType', {})
        violating_component: dict = {
            'Name': raw_violating_component.get('name'),
            'DocumentFormat': raw_violating_component.get('documentFormat'),
            'Type': violating_component_type.get('_value_1'),
            'TypeID': violating_component_type.get('id'),
            'ViolatingCount': raw_violating_component.get('violationCount'),
            'ViolationSegment': parse_violation_segment(raw_violating_component.get('violatingSegment', []))
        }
        violating_component_list.append({key: val for key, val in violating_component.items() if val})
    return violating_component_list


def parse_violated_policy_rule(raw_violated_policy_rule_list: list) -> list:
    """
    Parses a list of rules to context paths
    :param raw_violated_policy_rule_list: the raw rules list
    :return: the parsed rules list
    """
    violated_policy_rule_list: list = []
    for raw_violated_policy_rule in raw_violated_policy_rule_list:
        violated_policy_rule: dict = {
            'Name': raw_violated_policy_rule.get('ruleName'),
            'ID': raw_violated_policy_rule.get('ID')
        }
        violated_policy_rule_list.append({key: val for key, val in violated_policy_rule.items() if val})
    return violated_policy_rule_list


def parse_other_violated_policy(raw_other_violated_policy_list: list) -> list:
    """
    Parses a list of policies to context paths
    :param raw_other_violated_policy_list: the raw policies list
    :return: the parsed policies list
    """
    other_violated_policy_list: list = []
    for raw_other_violated_policy in raw_other_violated_policy_list:
        other_violated_policy: dict = {
            'Name': raw_other_violated_policy.get('name'),
            'Version': raw_other_violated_policy.get('version'),
            'Label': raw_other_violated_policy.get('label'),
            'ID': raw_other_violated_policy.get('policyId')
        }
        other_violated_policy_list.append({key: val for key, val in other_violated_policy.items() if val})
    return other_violated_policy_list


def get_all_group_custom_attributes(group: dict) -> list:
    """
    Returns a list of all the custom attributes in the group
    :param group: the group
    :return: the list of all custom attributes
    """
    custom_attributes_list: list = []
    for raw_custom_attribute in group.get('customAttribute', []):
        custom_attribute: dict = {'Name': raw_custom_attribute.get('name')}
        custom_attribute_value = raw_custom_attribute.get('value')
        if custom_attribute_value:
            custom_attribute['Value'] = custom_attribute_value
        custom_attributes_list.append(custom_attribute)
    return custom_attributes_list


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
            custom_attributes_list.extend(get_all_group_custom_attributes(group))

    # custom attributes group name case
    elif custom_attributes_flag == 'custom attributes group name':
        custom_data = args.get('custom_data')
        if not custom_data:
            raise DemistoException('When choosing the group value for custom_attributes argument - the custom_data'
                                   ' list must be filled with group names. For example: custom_value=g1,g2,g3')
        group_name_list: list = argToList(custom_data, ',')
        for group in custom_attribute_group_list:
            if group.get('name') in group_name_list:
                custom_attributes_list.extend(get_all_group_custom_attributes(group))

    # specific attributes case
    elif custom_attributes_flag == 'specific attributes':
        custom_data = args.get('custom_data')
        if not custom_data:
            raise DemistoException('When choosing the custom value for custom_attributes argument - the custom_data'
                                   ' list must be filled with custom attribute names.'
                                   ' For example: custom_value=ca1,ca2,ca3')
        custom_attribute_name_list: list = argToList(custom_data, ',')
        for group in custom_attribute_group_list:
            for raw_custom_attribute in group.get('customAttribute', []):
                custom_attribute_name: str = raw_custom_attribute.get('name')
                if custom_attribute_name in custom_attribute_name_list:
                    custom_attribute: dict = {'Name': custom_attribute_name}
                    custom_attribute_value = raw_custom_attribute.get('value')
                    if custom_attribute_value:
                        custom_attribute['Value'] = custom_attribute_value
                    custom_attributes_list.append(custom_attribute)

    # none case - If custom_attributes_flag == 'none' than we return empty list
    return custom_attributes_list


def get_incident_details(raw_incident_details: dict, args: dict) -> dict:
    """
    Parses the needed incident details into context paths
    :param raw_incident_details: the raw response of the incident details
    :param args: demisto.args
    :return: the parsed dict
    """
    incident: dict = raw_incident_details.get('incident', {})
    message_source: dict = incident.get('messageSource', {})
    message_type: dict = incident.get('messageType', {})
    policy: dict = incident.get('policy', {})
    incident_details: dict = {
        'ID': raw_incident_details.get('incidentID'),
        'LongID': raw_incident_details.get('incidentLongId'),
        'StatusCode': raw_incident_details.get('statusCode'),
        'CreationDate': incident.get('incidentCreationDate'),
        'DetectionDate': incident.get('detectionDate'),
        'Severity': incident.get('severity'),
        'Status': incident.get('status'),
        'MessageSource': message_source.get('_value_1'),
        'MessageSourceType': message_source.get('sourceType'),
        'MessageType': message_type.get('_value_1'),
        'MessageTypeID': message_type.get('typeId'),
        'Policy(val.ID && val.ID === obj.ID)': {
            'Name': policy.get('name'),
            'Version': policy.get('version'),
            'Label': policy.get('label'),
            'ID': policy.get('policyId')
        },
        'ViolatedPolicyRule(val.ID && val.ID === obj.ID)':
            parse_violated_policy_rule(incident.get('violatedPolicyRule', [])),
        'OtherViolatedPolicy(val.ID && val.ID === obj.ID)':
            parse_other_violated_policy(incident.get('otherViolatedPolicy', [])),
        'BlockedStatus': incident.get('blockedStatus'),
        'MatchCount': incident.get('matchCount'),
        'RuleViolationCount': incident.get('ruleViolationCount'),
        'DetectionServer': incident.get('detectionServer'),
        'CustomAttribute': parse_custom_attribute(incident.get('customAttributeGroup', []), args),
        'DataOwner': get_data_owner(incident.get('dataOwner', {})),
        'EventDate': incident.get('eventDate')
    }
    return {key: val for key, val in incident_details.items() if val}


def get_incident_attributes(attributes: dict) -> dict:
    """
    Transforms the demisto args entered by the user into a dict representing the attributes
    of the updated incidents
    :param attributes: the demisto args dict
    :return: the attributes dict by the API design
    """

    # Verify Custom Attribute
    custom_attribute: dict = {}
    custom_attribute_name: str = attributes.get('custom_attribute_name', '')
    custom_attribute_value: str = attributes.get('custom_attribute_value', '')
    if custom_attribute_name and not custom_attribute_value or custom_attribute_value and not custom_attribute_name:
        raise DemistoException("If updating an incident's custom attribute,"
                               " both custom_attribute_name and custom_attribute_value must be provided.")
    elif custom_attribute_name and custom_attribute_value:
        custom_attribute['value'] = custom_attribute_value
        custom_attribute['name'] = custom_attribute_name

    # Verify Data Owner
    data_owner: dict = {}
    data_owner_name: str = attributes.get('data_owner_name', '')
    data_owner_email: str = attributes.get('data_owner_email', '')
    if data_owner_name and not data_owner_email or data_owner_email and not data_owner_name:
        raise DemistoException("If updating an incident's data owner,"
                               " both data_owner_name and data_owner_email must be provided.")
    elif data_owner_name and data_owner_email:
        data_owner['name'] = data_owner_name
        data_owner['email'] = data_owner_email

    # Verify Note
    note: dict = {}
    note_str: str = attributes.get('note', '')
    note_time_str: str = attributes.get('note_time', '')
    note_time = None
    if note_time_str:
        note_time = parse(note_time_str)
    if note_str and not note_time or note_time and not note_str:
        raise DemistoException("If adding an incident's note, both note and note_time must be provided.")
    elif note_str and note_time:
        note['note'] = note_str
        note['dateAndTime'] = note_time

    attributes: dict = {
        'severity': attributes.get('severity'),
        'status': attributes.get('status'),
        'note': note,
        'customAttribute': custom_attribute,
        'dataOwner': data_owner,
        'remediationStatus': attributes.get('remediation_status'),
        'remediationLocation': attributes.get('remediation_location')
    }

    return {key: val for key, val in attributes.items() if val}


def parse_component(raw_components: list) -> list:
    """
    Parses a list of components into a list of context data
    :param raw_components: the components list before parsing
    :return: the parsed list
    """
    components: list = []
    for raw_component in raw_components:
        unfiltered_component: dict = {
            'ID': raw_component.get('componentId'),
            'Name': raw_component.get('name'),
            'TypeID': raw_component.get('componentTypeId'),
            'Type': raw_component.get('componentType'),
            'Content': bytes_to_string(raw_component.get('content')),
            'LongID': raw_component.get('componentLongId')
        }
        component: dict = {key: val for key, val in unfiltered_component.items() if val}
        if component:
            components.append(component)
    return components


def datetime_to_iso_format(obj: Any):
    """
    Converts a datetime object into an ISO string representation
    :param obj: Any type of object
    :return: If the object is of type datetime the return is it's ISO string representation
    """
    if isinstance(obj, datetime):
        return obj.isoformat()


def bytes_to_string(obj: Any):
    """
    Converts a bytes object into a string
    :param obj: Any type of object
    :return: If the object is of type bytes it returns it's string representation, else returns
    the object itself
    """
    if isinstance(obj, bytes):
        return obj.decode('utf-8')
    else:
        return obj


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client: Client, saved_report_id: int):
    """
    Performs basic get request to get item samples
    """
    helpers.serialize_object(client.service.incidentList(
        savedReportId=saved_report_id,
        incidentCreationDateLaterThan=parse_date_range('1 year')[0]
    ))
    demisto.results('ok')


def get_incident_details_command(client: Client, args: dict) -> Tuple[str, dict, dict]:
    incident_id: str = args.get('incident_id', '')

    raw_incident: list = client.service.incidentDetail(
        incidentId=incident_id,
        includeHistory=True,
        includeViolations=True
    )

    human_readable: str
    entry_context: dict = {}
    raw_response: dict = {}

    if raw_incident and isinstance(raw_incident, list):
        serialized_incident = helpers.serialize_object(raw_incident[0])
        raw_response = json.loads(json.dumps(serialized_incident, default=datetime_to_iso_format))
        incident_details: dict = get_incident_details(raw_response, args)
        raw_headers = ['ID', 'CreationDate', 'DetectionDate', 'Severity', 'Status', 'MessageSourceType',
                       'MessageType', 'Policy Name']
        headers = ['ID', 'Creation Date', 'Detection Date', 'Severity', 'Status', 'DLP Module',
                   'DLP Module subtype', 'Policy Name']
        outputs: dict = {}
        for raw_header in raw_headers:
            if raw_header == 'Policy Name':
                outputs['Policy Name'] = incident_details.get('Policy', {}).get('Name')
            else:
                outputs[headers[raw_headers.index(raw_header)]] = incident_details.get(raw_header)
        human_readable = tableToMarkdown(f'Symantec DLP incident {incident_id} details', outputs, headers=headers,
                                         removeNull=True)
        entry_context = {'SymantecDLP.Incident(val.ID && val.ID === obj.ID)': incident_details}
    else:
        human_readable = 'No incident found.'

    return human_readable, entry_context, raw_response


def list_incidents_command(client: Client, args: dict, saved_report_id: str) -> Tuple[str, dict, dict]:
    if not saved_report_id:
        raise ValueError('Missing saved report ID. Configure it in the integration instance settings.')

    creation_date = parse_date_range(args.get('creation_date', '1 day'))[0]

    raw_incidents = client.service.incidentList(
        savedReportId=saved_report_id,
        incidentCreationDateLaterThan=creation_date
    )

    human_readable: str
    entry_context: dict = {}
    raw_response: dict = {}

    if raw_incidents:
        serialized_incidents: dict = helpers.serialize_object(raw_incidents)
        incidents_ids_list = serialized_incidents.get('incidentId')
        if incidents_ids_list:
            raw_response = serialized_incidents
            incidents = [{'ID': str(incident_id)} for incident_id in incidents_ids_list]
            human_readable = tableToMarkdown('Symantec DLP incidents', incidents, removeNull=True)
            entry_context = {'SymantecDLP.Incident(val.ID && val.ID == obj.ID)': incidents}
        else:
            human_readable = 'No incidents found.'
    else:
        human_readable = 'No incidents found.'

    return human_readable, entry_context, raw_response


def update_incident_command(client: Client, args: dict) -> Tuple[str, dict, dict]:
    incident_id: str = args.get('incident_id', '')
    incident_attributes: dict = get_incident_attributes(args)

    raw_incidents_update_response = client.service.updateIncidents(
        updateBatch={
            'batchId': '_' + str(uuid.uuid1()),
            'incidentId': incident_id,
            'incidentAttributes': incident_attributes
        }
    )

    human_readable: str
    entry_context: dict = {}
    raw_response: dict = {}

    if raw_incidents_update_response and isinstance(raw_incidents_update_response, list):
        incidents_update_response = helpers.serialize_object(raw_incidents_update_response[0])
        headers: list = ['Batch ID', 'Inaccessible Incident Long ID', 'Inaccessible Incident ID', 'Status Code']
        outputs = {
            'Batch ID': incidents_update_response.get('batchId'),
            'Inaccessible Incident Long ID': incidents_update_response.get('InaccessibleIncidentLongId'),
            'Inaccessible Incident ID': incidents_update_response.get('InaccessibleIncidentId'),
            'Status Code': incidents_update_response.get('statusCode')
        }
        if outputs.get('Status Code') == 'VALIDATION_ERROR':
            raise DemistoException('Update was not successful. ADVICE: If status or custom attribute were changed,'
                                   ' check that they are configured in Symantec DLP.')
        human_readable = tableToMarkdown(f'Symantec DLP incidents {incident_id} update', outputs, headers=headers,
                                         removeNull=True)
    else:
        human_readable = 'Update was not successful'

    return human_readable, entry_context, raw_response


def incident_binaries_command(client: Client, args: dict) -> Tuple[str, dict, list, dict]:
    incident_id: str = args.get('incident_id', '')
    include_original_message: bool = bool(args.get('include_original_message', 'True'))
    include_all_components: bool = bool(args.get('include_all_components', 'True'))

    human_readable, entry_context, file_entries, raw_response = get_incident_binaries(client, incident_id,
                                                                                      include_original_message,
                                                                                      include_all_components)

    return human_readable, entry_context, file_entries, raw_response


def list_custom_attributes_command(client: Client) -> Tuple[str, dict, dict]:
    raw_custom_attributes_list = client.service.listCustomAttributes()

    human_readable: str
    entry_context: dict = {}
    raw_response: dict = {}

    if raw_custom_attributes_list:
        custom_attributes_list = helpers.serialize_object(raw_custom_attributes_list)
        raw_response = custom_attributes_list
        outputs: list = [{'Custom Attribute': custom_attribute} for custom_attribute in custom_attributes_list]
        human_readable = tableToMarkdown('Symantec DLP custom attributes', outputs, removeNull=True)
    else:
        human_readable = 'No custom attributes found.'

    return human_readable, entry_context, raw_response


def list_incident_status_command(client: Client) -> Tuple[str, dict, dict]:
    raw_incident_status_list = client.service.listIncidentStatus()

    human_readable: str
    entry_context: dict = {}
    raw_response: dict = {}

    if raw_incident_status_list:
        incident_status_list = helpers.serialize_object(raw_incident_status_list)
        raw_response = incident_status_list
        outputs: list = [{'Incident Status': incident_status} for incident_status in incident_status_list]
        human_readable = tableToMarkdown('Symantec DLP incident status', outputs, removeNull=True)
    else:
        human_readable = 'No incident status found.'

    return human_readable, entry_context, raw_response


def incident_violations_command(client: Client, args: dict) -> Tuple[str, dict, dict]:
    incident_id: str = args.get('incident_id', '')
    include_image_violations: bool = bool(args.get('include_image_violations', 'True'))

    raw_incident_violations = client.service.incidentViolations(
        incidentId=incident_id,
        includeImageViolations=include_image_violations
    )

    human_readable: str
    entry_context: dict = {}
    raw_response: dict = {}

    if raw_incident_violations:
        raw_incident_violations = helpers.serialize_object(raw_incident_violations[0])
        raw_response = raw_incident_violations
        incident_violations: dict = {
            'ID': raw_incident_violations.get('incidentId'),
            'LongID': raw_incident_violations.get('incidentLongId'),
            'StatusCode': raw_incident_violations.get('statusCode'),
            'ViolatingComponent': parse_violating_component(raw_incident_violations.get('violatingComponent', []))
        }
        human_readable = tableToMarkdown(f'Symantec DLP incident {incident_id} violations',
                                         {'ID': incident_violations.get('ID')}, removeNull=True)
        entry_context = {'SymantecDLP.Incident(val.ID && val.ID === obj.ID)': incident_violations}
    else:
        human_readable = 'No incident status found.'

    return human_readable, entry_context, raw_response


def fetch_incidents(client: Client, fetch_time: str, fetch_limit: int, last_run: dict, saved_report_id: str):
    """
    Performs the fetch incidents functionality of Demisto, which means that every minute if fetches incidents
    from Symantec DLP and uploads them to Demisto server.
    :param client: Demisto Client
    :param fetch_time: For the first time the integration is enabled with the fetch incidents functionality, the fetch
    time indicates from what time to start fetching existing incidents in Symantec DLP system.
    :param fetch_limit: Indicates how many incidents to fetch every minute
    :param last_run: Demisto last run object
    :param saved_report_id: The report ID to retrieve the incidents from
    :return: A list of Demisto incidents
    """
    # We use parse to get out time in datetime format and not iso, that's what Symantec DLP is expecting to get
    last_id_fetched = last_run.get('last_incident_id')
    if last_run and last_run.get('last_fetched_event_iso'):
        last_update_time = parse(last_run['last_fetched_event_iso'])
    else:
        last_update_time = parse_date_range(fetch_time)[0]

    incidents = []

    incidents_ids = helpers.serialize_object(client.service.incidentList(
        savedReportId=saved_report_id,
        incidentCreationDateLaterThan=last_update_time
    )).get('incidentId', '')

    if incidents_ids:
        last_incident_time: str = ''
        last_incident_id: str = ''
        for incident_id in incidents_ids:
            if last_id_fetched and last_id_fetched == incident_id:
                # Skipping last incident from last cycle if fetched again
                continue

            if fetch_limit == 0:
                break
            fetch_limit -= 1
            incident_details = json.dumps(helpers.serialize_object(client.service.incidentDetail(
                incidentId=incident_id
            )[0]), default=datetime_to_iso_format)
            incident_creation_time = json.loads(incident_details).get('incident', {}).get('incidentCreationDate')
            incident: dict = {
                'rawJSON': incident_details,
                'name': f'Symantec DLP incident {incident_id}',
                'occurred': incident_creation_time
            }

            _, _, file_entries, _ = get_incident_binaries(client, incident_id, False, False)
            if file_entries:
                attachments: list = []
                for file_entry in file_entries:
                    attachments.append({
                        'path': file_entry['FileID'],
                        'name': file_entry['File']
                    })
                incident['attachment'] = attachments

            incidents.append(incident)
            if incident_id == incidents_ids[-1]:
                last_incident_time = incident_creation_time
                last_incident_id = incident_id

        demisto.setLastRun(
            {
                'last_fetched_event_iso': last_incident_time,
                'last_incident_id': last_incident_id
            }
        )

    demisto.incidents(incidents)


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    handle_proxy()
    params: Dict = demisto.params()
    server: str = params.get('server', '').rstrip('/')
    credentials: Dict = params.get('credentials', {})
    username: str = credentials.get('identifier', '')
    password: str = credentials.get('password', '')
    fetch_time: str = params.get('fetch_time', '3 days').strip()
    try:
        fetch_limit: int = int(params.get('fetch_limit', '10'))
    except ValueError:
        raise DemistoException('Value for fetch_limit must be an integer.')
    saved_report_id: str = demisto.params().get('saved_report_id', '')
    last_run: dict = demisto.getLastRun()
    args: dict = demisto.args()
    verify_ssl = not params.get('insecure', False)
    wsdl: str = f'{server}/ProtectManager/services/v2011/incidents?wsdl'
    session: Session = Session()
    session.auth = SymantecAuth(username, password, server)
    session.verify = verify_ssl
    cache: SqliteCache = SqliteCache(path=get_cache_path(), timeout=None)
    transport: Transport = Transport(session=session, cache=cache)
    settings: Settings = Settings(strict=False, xsd_ignore_sequence_order=True)
    client: Client = Client(wsdl=wsdl, transport=transport, settings=settings)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    commands = {
        'test-module': test_module,
        'fetch-incidents': fetch_incidents,
        'symantec-dlp-get-incident-details': get_incident_details_command,
        'symantec-dlp-list-incidents': list_incidents_command,
        'symantec-dlp-update-incident': update_incident_command,
        'symantec-dlp-incident-binaries': incident_binaries_command,
        'symantec-dlp-list-custom-attributes': list_custom_attributes_command,
        'symantec-dlp-list-incident-status': list_incident_status_command,
        'symantec-dlp-incident-violations': incident_violations_command
    }
    try:
        if command == 'fetch-incidents':
            fetch_incidents(client, fetch_time, fetch_limit, last_run, saved_report_id)  # type: ignore[operator]
        elif command == 'test-module':
            test_module(client, saved_report_id)  # type: ignore[arg-type]
        elif command == 'symantec-dlp-list-incidents':
            human_readable, context, raw_response =\
                commands[command](client, args, saved_report_id)  # type: ignore[operator]
            return_outputs(human_readable, context, raw_response)
        elif command == 'symantec-dlp-list-incident-status' or command == 'symantec-dlp-list-custom-attributes':
            human_readable, context, raw_response = commands[command](client)  # type: ignore[operator]
            return_outputs(human_readable, context, raw_response)
        elif command == 'symantec-dlp-incident-binaries':
            human_readable, context, file_entries, raw_response =\
                commands[command](client, args)  # type: ignore[operator]
            return_outputs(human_readable, context, raw_response)
            for file_entry in file_entries:
                demisto.results(file_entry)
        elif command in commands:
            human_readable, context, raw_response = commands[command](client, args)  # type: ignore[operator]
            return_outputs(human_readable, context, raw_response)
    # Log exceptions
    except Exception as e:
        err_msg = f'Error in Symantec DLP integration: {str(e)}'
        if demisto.command() == 'fetch-incidents':
            LOG(err_msg)
            LOG.print_log()
            raise
        else:
            return_error(err_msg, error=e)


if __name__ == 'builtins':
    main()
