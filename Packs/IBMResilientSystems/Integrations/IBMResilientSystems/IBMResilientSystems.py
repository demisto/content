import os
from typing import Dict, List, Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import logging
import time

import urllib3
import re
import resilient
from resilient.co3 import SimpleClient, SimpleHTTPException
from resilient.co3base import RetryHTTPException

''' IMPORTS '''
logging.basicConfig()

# disable insecure warnings
urllib3.disable_warnings()
try:
    # disable 'warning' logs from 'resilient.co3'
    logging.getLogger('resilient.co3').setLevel(logging.ERROR)
except Exception:
    # client with no co3 instance should pass this exception
    pass

''' GLOBAL VARS '''
DEMISTO_PARAMS = (demisto.params()
                  # TODO delete
                  or {
                      'proxy': False,
                      'server': os.getenv('SERVER'),
                      'org': os.getenv('org'),
                      'api_key_id': os.getenv('API_KEY_ID'),
                      'api_key_secret': os.getenv('API_KEY_SECRET'),
                      'fetch_time': '2020-02-02T19:00:00Z'
                  })

if not DEMISTO_PARAMS['proxy']:
    for var in ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']:
        if os.environ.get(var):
            del os.environ[var]

URL = DEMISTO_PARAMS['server'][:-1] if DEMISTO_PARAMS['server'].endswith('/') else DEMISTO_PARAMS['server']
# Remove the http/s from the url (It's added automatically later)
URL = URL.replace('http://', '').replace('https://', '')
# Split the URL into two parts hostname & port
SERVER, PORT = URL.rsplit(":", 1) if ':' in URL else (URL, '443')
ORG_NAME = DEMISTO_PARAMS['org']
USERNAME = DEMISTO_PARAMS.get('credentials', {}).get('identifier')
PASSWORD = DEMISTO_PARAMS.get('credentials', {}).get('password')
API_KEY_ID = DEMISTO_PARAMS.get('credentials_api_key', {}).get('identifier') or DEMISTO_PARAMS.get('api_key_id')
API_KEY_SECRET = DEMISTO_PARAMS.get('credentials_api_key', {}).get('password') or DEMISTO_PARAMS.get('api_key_secret')
USE_SSL = not DEMISTO_PARAMS.get('insecure', False)

TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

MAX_FETCH = DEMISTO_PARAMS.get('max_fetch', '1000')

INCIDENT_TYPE_DICT = {
    'CommunicationError': 17,
    'DenialOfService': 21,
    'ImproperDisposal:DigitalAsset': 6,
    'ImproperDisposal:documents/files': 7,
    'LostDocuments/files/records': 4,
    'LostPC/laptop/tablet': 3,
    'LostPDA/smartphone': 1,
    'LostStorageDevice/media': 8,
    'Malware': 19,
    'NotAnIssue': 23,
    'Other': 18,
    'Phishing': 22,
    'StolenDocuments/files/records': 11,
    'StolenPC/laptop/tablet': 12,
    'StolenPDA/Smartphone': 13,
    'StolenStorageDevice/media': 14,
    'SystemIntrusion': 20,
    'TBD/Unknown': 16,
    'Vendor/3rdPartyError': 15
}

NIST_DICT = {
    'Attrition': 2,
    'E-mail': 4,
    'External/RemovableMedia': 1,
    'Impersonation': 5,
    'ImproperUsage': 6,
    'Loss/TheftOfEquipment': 7,
    'Other': 8,
    'Web': 3
}

NIST_ID_DICT = {
    2: 'Attrition',
    4: 'E-mail',
    1: 'External/RemovableMedia',
    5: 'Impersonation',
    6: 'ImproperUsage',
    7: 'Loss/TheftOfEquipment',
    8: 'Other',
    3: 'Web'
}

SEVERITY_CODE_DICT = {
    'Low': 4,
    'Medium': 5,
    'High': 6
}

RESOLUTION_DICT = {
    7: 'Unresolved',
    8: 'Duplicate',
    9: 'Not an Issue',
    10: 'Resolved'
}

RESOLUTION_TO_ID_DICT = {
    'Unresolved': 7,
    'Duplicate': 8,
    'NotAnIssue': 9,
    'Resolved': 10
}

MIRROR_STATUS_DICT = {
    'Unresolved': 'Other',
    'Duplicate': 'Duplicate',
    'Not an Issue': 'False Positive',
    'Resolved': 'Resolved',
}

XSOAR_CLOSE_REASON_MAPPING = {
    'Other': 'Unresolved',
    'Duplicate': 'Duplicate',
    'False Positive': 'Not an Issue',
    'Resolved': 'Resolved'
}

EXP_TYPE_ID_DICT = {
    1: 'Unknown',
    2: 'ExternalParty',
    3: 'Individual'
}

IBM_QRADAR_INCIDENT_FIELDS = {
    "description": {
        "xsoar_name": "description",
        "description": "Description of the incident.",
    },
    'incident_type_ids': {
        'xsoar_name': 'alerttypeid',
        'description': 'The IDs of the incident types.'
    },
    'resolution_id': {
        'xsoar_name': 'ibmqradarresolution',
        'description': ''
    },
    'resolution_summary': {
        'xsoar_name': 'ibmqradarresolutionsummary',
        'description': ''
    },
    "owner_id": {
        "xsoar_name": "",
        "description": "The principal ID of the incident owner.",
    },
    "reporter": {
        "xsoar_name": "ibmqradarreportername",
        "description": "Who reported the incident.",
    },
    "severity_code": {
        "xsoar_name": "severity",
        "description": "The severity of the incident. 4 = Low, 5 = Medium, 6 = High.",
    },
    "creator.display_name": {
        "xsoar_name": "displayname",
        "description": "The display name of the incident creator.",
    },
}

""" CONSTANTS """
SCRIPT_ENTITIES = "entities"
DEFAULT_RETURN_LEVEL = "full"
DEFAULT_RETRIES = 1
STATUS_NOT_FOUND = 404
IBM_QRADAR_SOAR_INCIDENT_SCHEMA_NAME = "IBM QRadar SOAR Incident Schema"
DEFAULT_SEVERITY_CODE = 5
""" ENDPOINTS """
SEARCH_INCIDENTS_ENDPOINT = "/incidents/query_paged"

''' HELPER FUNCTIONS '''


def validate_fetch_time(fetch_time: str) -> str:
    """
    Ensures the input timestamp string ends with a 'Z' to denote Zulu time (UTC).

    Args:
    fetch_time (str): The timestamp string to check and modify if needed.

    Returns:
    str: The modified timestamp string with a 'Z' suffix if it wasn't already present.
    """
    if fetch_time:
        return fetch_time if fetch_time.endswith("Z") else fetch_time + "Z"
    else:
        return fetch_time


def normalize_timestamp(timestamp):
    """
    Converts epoch timestamp to human readable timestamp.
    """
    return datetime.fromtimestamp(timestamp / 1000.0).strftime("%Y-%m-%dT%H:%M:%SZ")


def prettify_incidents(client, incidents):
    users = get_users(client)
    phases = get_phases(client).get('entities', [])
    for incident in incidents:
        incident['id'] = str(incident['id'])
        if isinstance(incident['description'], str):
            incident['description'] = remove_html_div_tags(incident['description'])
        incident['discovered_date'] = normalize_timestamp(incident['discovered_date'])
        incident['created_date'] = normalize_timestamp(incident['create_date'])
        incident.pop('create_date', None)
        incident.pop('inc_training', None)

        for user in users:
            if incident['owner_id'] == user['id']:
                incident['owner'] = user['fname'] + ' ' + user['lname']
                incident.pop('owner_id', None)
                break

        for phase in phases:
            if incident['phase_id'] == phase['id']:
                incident['phase'] = phase['name']
                incident.pop('phase_id', None)
                break

        incident['severity'] = incident.get('severity_code', DEFAULT_SEVERITY_CODE)

        if start_date := incident.get('start_date'):
            incident['date_occurred'] = normalize_timestamp(start_date)
            incident.pop('start_date', None)

        if due_date := incident.get('due_date'):
            incident['due_date'] = normalize_timestamp(due_date)

        if negative_pr := incident.get('negative_pr_likely'):
            incident['negative_pr'] = negative_pr
            incident.pop('negative_pr_likely', None)

        if exposure_type_id := incident.get('exposure_type_id'):
            incident['exposure_type'] = EXP_TYPE_ID_DICT.get(exposure_type_id, exposure_type_id)
            incident.pop('exposure_type_id', None)

        if nist_attack_vectors := incident.get('nist_attack_vectors'):
            translated_nist = []
            for vector in nist_attack_vectors:
                translated_nist.append(NIST_ID_DICT[vector])
            incident['nist_attack_vectors'] = translated_nist

        if plan_status := incident.get('plan_status'):
            incident['plan_status'] = 'Active' if plan_status == 'A' else 'Closed'
    return incidents


def prettify_incident_notes(notes: list[dict]) -> list[dict]:
    """
    Reformatting retrieved incident notes to be more readable.
    """
    formatted_notes = []
    notes_copy = notes.copy()
    while notes_copy:
        note = notes_copy.pop()
        new_note_obj = {
            "id": note.get("id", ""),
            "text": remove_html_div_tags(note.get("text", "")),
            "created_by": f"{note.get('user_fname', '')} {note.get('user_lname', '')}",
            "create_date": normalize_timestamp(note.get("create_date")),
        }
        formatted_notes.append(new_note_obj)
    return formatted_notes


def prepare_search_query_data(args: dict) -> dict:
    """
    Preparing the search query filters and pagination parameters for the `search_incidents` request.
    """
    demisto.debug(f'prepare_search_query_data {args=}')

    conditions = []  # type: Any
    if 'severity' in args:
        value = []
        severity = args['severity'].split(',')
        if 'Low' in severity:
            value.append(50)
        if 'Medium' in severity:
            value.append(51)
        if 'High' in severity:
            value.append(52)
        if not value:
            raise Exception('Severity should be given in capital case and comma separated, e.g. Low,Medium,High')
        conditions.append({
            'field_name': 'severity_code',
            'method': 'in',
            'value': value
        })
    if 'date-created-before' in args:
        value = to_timestamp(args['date-created-before'])
        conditions.append({
            'field_name': 'create_date',
            'method': 'lte',
            'value': value
        })
    elif 'date-created-after' in args:
        value = to_timestamp(args['date-created-after'])
        conditions.append({
            'field_name': 'create_date',
            'method': 'gte',
            'value': value
        })
    elif 'date-created-within-the-last' in args:
        if 'timeframe' not in args:
            raise Exception('Timeframe was not given.')
        within_the_last = int(args['date-created-within-the-last'])
        now = int(time.time())
        timeframe = args['timeframe']
        if timeframe == 'days':
            from_time = now - (60 * 60 * 24 * within_the_last)
        elif timeframe == 'hours':
            from_time = now - (60 * 60 * within_the_last)
        elif timeframe == 'minutes':
            from_time = now - (60 * within_the_last)
        conditions.extend((
            {
                'field_name': 'create_date',
                'method': 'lte',
                'value': now * 1000
            },
            {
                'field_name': 'create_date',
                'method': 'gte',
                'value': from_time * 1000
            }))
    if 'date-occurred-before' in args:
        value = to_timestamp(args['date-occurred-before'])
        conditions.append({
            'field_name': 'start_date',
            'method': 'lte',
            'value': value
        })
    elif 'date-occurred-after' in args:
        value = to_timestamp(args['date-occurred-after'])
        conditions.append({
            'field_name': 'start_date',
            'method': 'gte',
            'value': value
        })
    elif 'date-occurred-within-the-last' in args:
        if 'timeframe' not in args:
            raise Exception('Timeframe was not given.')
        within_the_last = int(args['date-occurred-within-the-last'])
        now = int(time.time())
        timeframe = args['timeframe']
        if timeframe == 'days':
            from_time = now - (60 * 60 * 24 * within_the_last)
        elif timeframe == 'hours':
            from_time = now - (60 * 60 * within_the_last)
        elif timeframe == 'minutes':
            from_time = now - (60 * within_the_last)
        conditions.extend((
            {
                'field_name': 'start_date',
                'method': 'lte',
                'value': now * 1000
            },
            {
                'field_name': 'start_date',
                'method': 'gte',
                'value': from_time * 1000
            }))
    if 'incident-type' in args:
        type_id = INCIDENT_TYPE_DICT[args['incident-type']]
        conditions.append({
            'field_name': 'incident_type_ids',
            'method': 'contains',
            'value': [type_id]
        })
    if 'nist' in args:
        nist = NIST_DICT[args['nist']]
        conditions.append({
            'field_name': 'nist_attack_vectors',
            'method': 'contains',
            'value': [nist]
        })
    if 'status' in args:
        status = 'A' if args['status'] == 'Active' else 'C'
        conditions.append({
            'field_name': 'plan_status',
            'method': 'in',
            'value': [status]
        })
    if 'due-in' in args:
        if 'timeframe' not in args:
            raise Exception('Timeframe was not given.')
        within_the_last = int(args['due-in'])
        now = int(time.time())
        timeframe = args['timeframe']
        if timeframe == 'days':
            to_time = now + (60 * 60 * 24 * within_the_last)
        elif timeframe == 'hours':
            to_time = now + (60 * 60 * within_the_last)
        elif timeframe == 'minutes':
            to_time = now + (60 * within_the_last)
        conditions.extend((
            {
                'field_name': 'due_date',
                'method': 'lte',
                'value': to_time * 1000
            },
            {
                'field_name': 'due_date',
                'method': 'gte',
                'value': now * 1000
            }))
    if 'last-modified-after' in args:
        value = to_timestamp(args['last-modified-after'])
        conditions.append({
            'field_name': 'inc_last_modified_date',
            'method': 'gte',
            'value': value
        })

    data = {
        'filters': [{
            'conditions': conditions
        }]
    }

    # Pagination mechanism.
    page = int(args.get('page', 0))
    page_size = int(args.get('page_size', 0))
    limit = int(args.get('limit', MAX_FETCH))
    data['length'] = limit
    # 'limit' parameter is redundant in case proper 'page' and 'page_size' were provided.
    if page_size > 0 and page > 0:
        data['start'] = page_size * (page - 1)
        data['length'] = page_size
    elif page < 0 or page_size < 0:
        raise DemistoException('Invalid page number or page size. Page number and page sizes must be positive integers.')
    demisto.debug(f'prepare_search_query_data {data=}')
    return data


def get_mirroring_data() -> dict:
    """
    Get the integration instance's mirroring configuration parameters.

    Returns:
        dict: A dictionary containing the mirroring configuration parameters.
    """
    params = demisto.params()

    mirror_direction = params.get("mirror_direction")
    demisto.debug(f"get_mirroring_data {mirror_direction=} | {params=} ")
    mirror_tags = []  # TODO - Utilize this
    return {
        "mirror_direction": mirror_direction,
        "mirror_instance": demisto.integrationInstance(),
        "mirror_tags": mirror_tags,
    }


def remove_html_div_tags(raw_value: str) -> str:
    """
    Remove HTML tags from a given string.

    Args:
        raw_value (str): The string to remove HTML tags from.
    Returns:
        str: The string with HTML tags removed.
    """
    # Replace opening div tags with a newline character.
    raw_value = re.sub(r"<div[^>]*>", "\n", raw_value)
    # Remove closing div tags.
    result = re.sub(r"</div>", "", raw_value)
    return result.strip()


def process_raw_incident(client: SimpleClient, incident: dict) -> dict:
    """
    Process a raw incident dictionary by fetching associated artifacts and attachments,
     removing HTML div tags from the description and normalizing timestamps.

     Args:
         client (SimpleClient): The client instance to use for API calls.
         incident (dict): The raw incident dictionary to process.
    Returns:
        dict: The processed incident dictionary.
    """
    incident_id = str(incident.get("id"))
    artifacts = incident_artifacts(client, incident_id)  # TODO Check types
    if artifacts:
        incident["artifacts"] = artifacts

    attachments = incident_attachments(client, incident_id)
    if attachments:
        incident["attachments"] = attachments

    if isinstance(incident.get("description"), str):
        incident["description"] = remove_html_div_tags(incident["description"])

    incident["discovered_date"] = normalize_timestamp(incident.get("discovered_date"))
    incident["create_date"] = normalize_timestamp(incident.get("create_date"))

    notes = get_incident_notes(client, incident_id)
    for note in prettify_incident_notes(notes):
        # TODO - Maintain notes.
        if note:
            pass
            # return_outputs(
            #     {
            #         'ContentsFormat': EntryFormat.MARKDOWN,
            #         'Type': EntryType.NOTE,
            #         'Contents':
            #             f"Added By: {note.get('created_by', '')}\n"
            #             f"Added At: {note.get('created_at', '')}\n"
            #             f"Note Content:{note.get('text', '')}\n"
            #             f"ID:{note.get('id', '')}",
            #         'Note': True
            #     }
            # )
    incident.update(get_mirroring_data())
    return incident


def resolve_field_value(field: str, raw_value: Any) -> dict:
    """
    Resolve an incident's field value for an API PATCH request.
    """
    demisto.debug(f"resolve_field_value {field=} | {type(raw_value)=} | {raw_value=}")

    # Null values & object-formatted values are returned as-is under 'textarea' key.
    if not raw_value or isinstance(raw_value, dict):
        return {"textarea": raw_value or None}

    elif field in ["severity_code", "owner_id", "resolution_id"]:
        return {"id": int(raw_value)}

    elif field in ["reporter", "plan_status", "name"]:
        return {"text": raw_value}

    elif field in ["resolution_summary", "description"]:
        return {"textarea": {"format": "html", "content": raw_value}}

    elif field in ["incident_type_ids", "nist_attack_vectors"]:
        return {"ids": raw_value}

    raise DemistoException('Could no resolve field value for field: {}'.format(field))


def get_field_changes_entry(field: str, old_value: Any, new_value: Any) -> dict:
    """
    Get the field changes entry for an incident update.
    """
    field_changes = {
        "field": field,
        "old_value": resolve_field_value(field, old_value),
        "new_value": resolve_field_value(field, new_value),
    }
    return field_changes


def prepare_incident_update_dto_for_mirror(client: SimpleClient, incident_id: str, delta: dict) -> dict:
    """
    Prepare an incident update DTO for mirroring data.
    Args:
        client (SimpleClient): The client object to interact with the API.
        incident_id (str): The ID of the incident to be updated.
        delta (dict): A dictionary containing the fields and their new values to be updated.
    """
    incident = get_incident(client, incident_id, content_format=True)
    demisto.debug(f"prepare_incident_update_dto_for_mirror {delta=} | {incident=}")

    changes = []
    for field, new_value in delta.items():
        changes.append(
            get_field_changes_entry(
                field=field, old_value=incident[field], new_value=new_value
            )
        )
        # `resolution_id` is updated once the incident is closed or re-opened and requires additional treatment.
        if field == 'resolution_id':
            new_resolution_id = new_value
            remote_status = incident["plan_status"]

            # Handling remote incident reopening.
            if new_resolution_id == '' and remote_status == "C":
                changes.append(get_field_changes_entry("plan_status", remote_status, "A"))

            # Remote incident closure handling.
            else:
                changes.append(get_field_changes_entry("plan_status", remote_status, "C"))

    dto = {"changes": changes}
    demisto.debug(f"prepare_incident_update_dto_for_mirror {dto=}")
    return dto

def to_timestamp(date_str_or_dt, date_format='%Y-%m-%dT%H:%M:%SZ'):
    """
    Parses date_str_or_dt in the given format (default: %Y-%m-%dT%H:%M:%SZ) to milliseconds.
    If the input is already a timestamp, it returns it as is.

    :type date_str_or_dt: ``str``, ``datetime.datetime``, or ``int``
    :param date_str_or_dt: The date to be parsed. (required)

    :type date_format: ``str``
    :param date_format: The date format of the date string (will be ignored if date_str_or_dt is of type
        datetime.datetime or int). (optional)

    :return: The parsed timestamp.
    :rtype: ``int``
    """
    # Check if the input is already an integer, assuming it's a timestamp in milliseconds
    if isinstance(date_str_or_dt, int):
        return date_str_or_dt

    # Check if the input is a string that could be a timestamp
    if isinstance(date_str_or_dt, str):
        try:
            # Try converting the string directly to an integer (e.g., Unix timestamp)
            timestamp = int(date_str_or_dt)
            return timestamp
        except ValueError:
            # If it can't be converted, assume it's a date string and parse it
            parsed_time = time.strptime(date_str_or_dt, date_format)
            return int(time.mktime(parsed_time) * 1000)

    # If the input is a datetime object, convert it to a timestamp
    if isinstance(date_str_or_dt, datetime):
        return int(time.mktime(date_str_or_dt.timetuple()) * 1000)

    raise TypeError("Unsupported type for date_str_or_dt")


def extract_data_form_other_fields_argument(other_fields, incident, changes):
    """Extracts the values from other-field argument and build a json object in ibm format to update an incident.

    Args:
        other_fields (str): Contains the field that should be changed and the new value ({"name": {"text": "The new name"}}).
        incident (dict): Contains the old value of the field that should be changed ({"name": "The old name"}).
        changes (list): Contains the fields that should be changed with the old and new values in IBM format
            ([{'field': {'name': 'confirmed'}, 'old_value': {'boolean': 'false'}, 'new_value': {'boolean': 'true'},
            {'field': {'name': 'name'}, 'old_value': {'text': 'The old name'}, 'new_value': {'text': 'The new name'}}]).

    """

    try:
        other_fields_json = json.loads(other_fields)
    except Exception as e:
        raise Exception('The other_fields argument is not a valid json. ' + str(e))

    for field_path, field_value in other_fields_json.items():
        field_split = field_path.split(".")
        old_value = dict_safe_get(dict_object=incident, keys=field_split, default_return_value="Not found")
        if old_value == "Not found":
            raise Exception('The other_fields argument is invalid. Check the name of the field whether it is the right path')
        changes.append(
            {
                'field': {'name': field_split[-1]},
                # The format should be {type: value}.
                # Because the type is not returned from the API we take the type from the new value.
                'old_value': {list(field_value.keys())[0]: old_value},
                'new_value': field_value
            }
        )


''' COMMAND FUNCTIONS '''


def search_incidents_command(client, args):
    incidents = search_incidents(client, args)
    if incidents:
        pretty_incidents = prettify_incidents(client, incidents)

        result_incidents = createContext(pretty_incidents, id=None, keyTransform=underscoreToCamelCase, removeNull=True)    # pragma: no cover
        ec = {
            'Resilient.Incidents(val.Id && val.Id === obj.Id)': result_incidents
        }
        title = 'QRadar SOAR Incidents'
        entry = {
            'Type': entryTypes['note'],
            'Contents': incidents,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable':
                tableToMarkdown(
                    title,
                    result_incidents,
                    headers=['Id', 'Name', 'PlanStatus', 'CreatedDate', 'DiscoveredDate', 'Owner', 'Phase'],
                    removeNull=True
                ),

            'EntryContext': ec
        }
        return entry
    else:
        return 'No results found.'


def search_incidents(client: SimpleClient, args: dict) -> list | dict:
    """
    Search and get IBM QRadar incidents according to filters and pagination parameters.
    :return: List of IBM QRadar incidents matching the search query.
    """
    search_query_data = prepare_search_query_data(args)

    return_level = args.get('return_level', DEFAULT_RETURN_LEVEL)
    endpoint = f'{SEARCH_INCIDENTS_ENDPOINT}?return_level={return_level}'

    response = client.post(endpoint, search_query_data)
    demisto.debug(f'search_incidents {response}')
    return response['data']


def update_incident_command(client, args):
    if len(args) == 1:
        raise DemistoException("No fields to update were given.")
    incident_id = args['incident-id']
    incident = get_incident(client, incident_id, True)

    changes = []
    if 'severity' in args:
        old_value = incident['severity_code']
        severity = args['severity']
        new_value = SEVERITY_CODE_DICT.get(severity)
        changes.append(get_field_changes_entry('severity_code', old_value, new_value))

    if 'owner' in args:
        users = get_users(client)
        old_value = incident['owner_id']
        full_name = args['owner'].split(' ')
        first_name, last_name = full_name[0], full_name[1]
        new_value = -1
        for user in users:
            if first_name == user['fname'] and last_name == user['lname']:
                new_value = user['id']
                break
        if new_value == -1:
            raise DemistoException('User was not found')
        changes.append(get_field_changes_entry('owner_id', old_value, new_value))

    if 'incident-type' in args:
        old_value = incident['incident_type_ids']
        type_id = INCIDENT_TYPE_DICT[args['incident-type']]
        new_value_list = old_value[:]
        new_value_list.append(type_id)
        changes.append(get_field_changes_entry('incident_type_ids', old_value, new_value_list))

    if 'nist' in args:
        old_value = incident['nist_attack_vectors']
        nist_id = NIST_DICT[args['nist']]
        new_value_list = old_value[:]
        new_value_list.append(nist_id)
        changes.append(get_field_changes_entry('nist_attack_vectors', old_value, new_value_list))

    if 'resolution' in args:
        old_value = incident['resolution_id']
        new_value = RESOLUTION_TO_ID_DICT[args['resolution']]
        changes.append(get_field_changes_entry('resolution_id', old_value, new_value))

    if 'resolution-summary' in args:
        old_summary = incident['resolution_summary']
        new_summary = args['resolution-summary']
        changes.append(get_field_changes_entry('resolution_summary', old_summary, new_summary))

    if 'description' in args:
        old_description = incident['description']
        new_description = args['description']
        changes.append(get_field_changes_entry('description', old_description, new_description))

    if 'name' in args:
        old_name = incident['name']
        new_name = args['name']
        changes.append(get_field_changes_entry('name', old_name, new_name))

    if other_fields := args.get('other-fields'):
        extract_data_form_other_fields_argument(other_fields, incident, changes)

    update_dto = {
        'changes': changes
    }

    demisto.debug(f'update_incident_command: {json.dumps(update_dto, indent=4)}')
    response = update_incident(client, incident_id, update_dto)
    demisto.debug(f'update_incident_command {str(response)=}')
    if response.status_code == 200:
        return f'Incident {incident_id} was updated successfully.'
    else:   # pragma: no cover
        return f'Failed to update incident {incident_id}'


def update_incident(client, incident_id, data):
    response = client.patch('/incidents/' + str(incident_id), data)
    return response


def get_incident_command(client, incident_id):
    incident = get_incident(client, incident_id)
    wanted_keys = ['create_date', 'discovered_date', 'description', 'due_date', 'id', 'name', 'owner_id',
                   'phase_id', 'severity_code', 'confirmed', 'employee_involved', 'negative_pr_likely',
                   'confirmed', 'start_date', 'due_date', 'negative_pr_likely', 'reporter', 'exposure_type_id',
                   'nist_attack_vectors']
    pretty_incident = dict((k, incident[k]) for k in wanted_keys if k in incident)
    if incident['resolution_id']:
        pretty_incident['resolution'] = RESOLUTION_DICT.get(incident['resolution_id'], incident['resolution_id'])
    if incident['resolution_summary']:
        pretty_incident['resolution_summary'] = incident['resolution_summary'].replace('<div>', '').replace('</div>',
                                                                                                            '')
    pretty_incident = prettify_incidents(client, [pretty_incident])
    result_incident = createContext(pretty_incident, id=None, keyTransform=underscoreToCamelCase, removeNull=True)
    ec = {
        'Resilient.Incidents(val.Id && val.Id === obj.Id)': result_incident
    }
    hr_incident = result_incident[:]
    if hr_incident[0].get('NistAttackVectors'):
        nist_vectors_str = ''
        for vector in hr_incident[0].get('NistAttackVectors', []):
            nist_vectors_str += vector + '\n'
        hr_incident[0]['NistAttackVectors'] = nist_vectors_str
    title = 'IBM QRadar SOAR incident ID ' + str(incident_id)
    entry = {
        'Type': entryTypes['note'],
        'Contents': incident,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, hr_incident,
                                         headers=['Id', 'Name', 'Description', 'NistAttackVectors', 'Phase',
                                                  'Resolution', 'ResolutionSummary', 'Owner',
                                                  'CreatedDate', 'DateOccurred', 'DiscoveredDate', 'DueDate',
                                                  'NegativePr', 'Confirmed', 'ExposureType',
                                                  'Severity', 'Reporter']),
        'EntryContext': ec
    }
    return entry


def get_incident(client: SimpleClient, incident_id, content_format=False):
    url = '/incidents/' + str(incident_id)
    if content_format:
        url += '?text_content_output_format=objects_convert_html'
    response = client.get(url)
    return response


def list_open_incidents(client):
    response = client.get('/incidents/open')
    return response


def get_members_command(client, incident_id):
    response = get_members(client, incident_id)['members']
    incident = get_incident(client, incident_id)
    response.append(incident['owner_id'])
    users = get_users(client)
    members = []
    for user in users:
        if user['id'] in response:
            members.append({
                'FirstName': user['fname'],
                'LastName': user['lname'],
                'ID': user['id'],
                'Email': user['email']
            })

    ec = {
        'Resilient.Incidents(val.Id && val.Id === obj.Id)': {
            'Id': incident_id,
            'Members': members
        }
    }
    title = 'Members of incident ' + incident_id
    entry = {
        'Type': entryTypes['note'],
        'Contents': members,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, members, ['ID', 'LastName', 'FirstName', 'Email']),
        'EntryContext': ec
    }
    return entry


def get_members(client, incident_id):
    response = client.get('/incidents/' + incident_id + '/members')
    return response


def get_users_command(client):
    response = get_users(client)
    users = []
    for user in response:
        users.append({
            'FirstName': user['fname'],
            'LastName': user['lname'],
            'ID': user['id'],
            'Email': user['email']
        })

    title = 'IBM QRadar SOAR Users'
    entry = {
        'Type': entryTypes['note'],
        'Contents': users,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, users, ['ID', 'LastName', 'FirstName', 'Email'])
    }
    return entry


def get_users(client):
    response = client.get('/users')
    return response


def get_phases(client):
    response = client.get('/phases')
    return response


def get_tasks_command(client, incident_id):
    response = get_tasks(client, incident_id)
    if response:
        tasks = []
        for task in response:
            task_object = {}
            incident_name = task['inc_name']
            task_object['ID'] = task['id']
            task_object['Name'] = task['name']
            if task['due_date']:
                task_object['DueDate'] = normalize_timestamp(task['due_date'])
            task_object['Status'] = 'Open' if task['status'] == 'O' else 'Closed'
            task_object['Required'] = task['required']
            if task['form']:
                task_object['Form'] = task['form']
            if task['user_notes']:
                task_object['UserNotes'] = task['user_notes']
            task_object['Creator'] = task.get('creator_principal', {}).get('display_name')
            task_object['Category'] = task['cat_name']
            if task['instr_text']:
                task_object['Instructions'] = task['instr_text']
            tasks.append(task_object)
        ec = {
            'Resilient.Incidents(val.Id && val.Id === obj.Id)': {
                'Id': incident_id,
                'Name': incident_name,
                'Tasks': tasks
            }
        }
        title = 'Incident ' + incident_id + ' tasks'
        entry = {
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, tasks,
                                             ['ID', 'Name', 'Category', 'Form', 'Status', 'DueDate', 'Instructions',
                                              'UserNotes', 'Required', 'Creator']),
            'EntryContext': ec
        }
        return entry
    else:
        return 'No tasks found for this incident.'


def get_tasks(client, incident_id):
    response = client.get('/incidents/' + incident_id + '/tasks')
    return response


def set_member_command(client, incident_id, members):
    members = [int(x) for x in members.split(',')]
    incident = get_incident(client, incident_id)
    incident_version = incident['vers']
    data = {
        'vers': incident_version,
        'members': members
    }
    response = set_member(client, incident_id, data)
    users = get_users(client)
    entry = {}
    if response:
        for user in users:
            if user['id'] in members:
                if isinstance(response, dict):
                    response.update({
                        'FirstName': user['fname'],
                        'LastName': user['lname'],
                        'ID': user['id'],
                        'Email': user['email']
                    })
                else:
                    response.append({
                        'FirstName': user['fname'],
                        'LastName': user['lname'],
                        'ID': user['id'],
                        'Email': user['email']
                    })
        ec = {
            'Resilient.Incidents(val.Id && val.Id === obj.Id)': {
                'Id': incident_id,
                'Members': response
            }
        }
        title = 'Members of incident ' + incident_id
        entry = {
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, response),
            'EntryContext': ec
        }
    return entry


def set_member(client, incident_id, data):
    response = client.put(f'/incidents/{incident_id}/members', payload=data)
    return response


def close_incident_command(client, incident_id):
    incident = get_incident(client, incident_id)
    if not incident['resolution_id'] or not incident['resolution_summary']:
        return 'Resolution and resolution summary of the incident should be updated before closing an incident.'
    response = close_incident(client, incident_id, incident)
    if response.status_code == 200:
        return 'Incident ' + incident_id + ' was closed.'


def close_incident(client, incident_id, incident):
    old_status = incident['plan_status']
    data = {
        'changes': [get_field_changes_entry('plan_status', old_status, 'C')]
    }
    return update_incident(client, incident_id, data)


def create_incident_command(client, args):
    incident_name = args['name']
    data = {
        "name": incident_name,
        "discovered_date": 0
    }
    response = create_incident(client, data)
    hr = {
        'ID': response['id'],
        'Name': incident_name
    }
    ec = {
        'Resilient.Incidents(val.Id && val.Id === obj.Id)': {
            'Id': str(response['id']),
            'Name': incident_name
        }
    }
    title = 'Incident ' + incident_name + ' was created'
    entry = {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, hr),
        'EntryContext': ec
    }
    return entry


def create_incident(client, data):
    response = client.post('/incidents', data)
    return response


def incident_artifacts_command(client, incident_id):
    response = incident_artifacts(client, incident_id)
    if response:
        users = get_users(client)
        ec_artifacts = []
        hr_artifacts = []
        for artifact in response:
            incident_name = artifact['inc_name']
            artifact_object = {
            }
            if artifact['description']:
                artifact_object['Description'] = artifact['description']
            hr_artifact = dict(artifact_object)
            if artifact['attachment']:
                artifact_object['Attachments'] = {}
                attachment_string = ''
                artifact_object['Attachments']['ID'] = artifact['attachment']['id']
                attachment_string += 'ID: ' + str(artifact_object['Attachments']['ID']) + '\n'
                artifact_object['Attachments']['Name'] = artifact['attachment']['name']
                attachment_string += 'Name: ' + artifact_object['Attachments']['Name'] + '\n'
                artifact_object['Attachments']['CreatedDate'] = normalize_timestamp(artifact['attachment']['created'])
                attachment_string += 'Created Date: ' + artifact_object['Attachments']['CreatedDate'] + '\n'
                artifact_object['Attachments']['ContentType'] = artifact['attachment']['content_type']
                attachment_string += 'Content Type : ' + artifact_object['Attachments']['ContentType'] + '\n'
                artifact_object['Attachments']['Size'] = artifact['attachment']['size']
                attachment_string += 'Size: ' + str(artifact_object['Attachments']['Size']) + '\n'
                creator_id = artifact['attachment']['creator_id']
                for user in users:
                    if creator_id == user['id']:
                        artifact_object['Attachments']['Creator'] = user['fname'] + ' ' + user['lname']
                        attachment_string += 'Creator: ' + artifact_object['Attachments']['Creator']
                        break
                hr_artifact['Attachments'] = attachment_string
            hr_artifacts.append(hr_artifact)
            ec_artifacts.append(artifact_object)
        ec = {
            'Resilient.Incidents(val.Id && val.Id === obj.Id)': {
                'Id': incident_id,
                'Name': incident_name,
                'Artifacts': ec_artifacts
            }
        }
        title = 'Incident ' + incident_id + ' artifacts'
        entry = {
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, hr_artifacts,
                                             headers=['ID', 'Value', 'Description', 'CreatedDate', 'Creator']),
            'EntryContext': ec
        }
        return entry
    else:
        return 'No artifacts found.'


def incident_artifacts(client, incident_id):
    response = client.get('/incidents/' + incident_id + '/artifacts')
    return response


def get_artifact_type(client, artifact_id):
    response = client.get('/artifact_types/' + str(artifact_id))
    return response['name']


def incident_attachments_command(client, incident_id):
    response = incident_attachments(client, incident_id)
    if response:
        attachments = []
        users = get_users(client)
        for attachment in response:
            incident_name = attachment['inc_name']
            attachment_object = {}
            attachment_object['ID'] = attachment['id']
            attachment_object['Name'] = attachment['name']
            attachment_object['CreatedDate'] = normalize_timestamp(attachment['created'])
            attachment_object['Size'] = attachment['size']
            attachment_object['ContentType'] = attachment['content_type']
            attachment_object['Name'] = attachment['name']
            for user in users:
                if attachment['creator_id'] == user['id']:
                    attachment_object['Creator'] = user['fname'] + ' ' + user['lname']
                if attachment['inc_owner'] == user['id']:
                    incident_owner = user['fname'] + ' ' + user['lname']
            attachments.append(attachment_object)
        ec = {
            'Resilient.Incidents(val.Id && val.Id === obj.Id)': {
                'Id': incident_id,
                'Name': incident_name,
                'Owner': incident_owner,
                'Attachments': attachments
            }
        }
        title = 'Incident ' + incident_id + ' attachments'
        entry = {
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, attachments),
            'EntryContext': ec
        }
        return entry
    else:
        return 'No attachments found.'


def incident_attachments(client, incident_id):
    response = client.get('/incidents/' + incident_id + '/attachments')
    return response


def get_incident_notes(client: SimpleClient, incident_id: str) -> list:
    response = client.get(f'/incidents/{incident_id}/comments')
    return response


def related_incidents_command(client, incident_id):
    response = related_incidents(client, incident_id)['incidents']
    if response:
        ec_incidents = []
        hr_incidents = []
        for incident in response:
            incident_object = {
                'ID': incident['id'],
                'Name': incident['name'],
                'Status': 'Active' if incident['plan_status'] == 'A' else 'Closed',
                'CreatedDate': normalize_timestamp(incident['create_date']),
            }
            hr_incident = dict(incident_object)
            if incident['artifacts']:
                hr_incident['Artifacts'] = ''
                artifacts = []
                for artifact in incident['artifacts']:
                    artifact_object = {}
                    artifact_string = ''
                    artifact_object['ID'] = artifact['id']
                    artifact_string += 'ID: ' + str(artifact_object['ID']) + '\n'
                    artifact_object['CreatedDate'] = normalize_timestamp(artifact['created'])
                    artifact_string += 'Created Date: ' + artifact_object['CreatedDate'] + '\n'
                    if artifact['description']:
                        artifact_object['Description'] = artifact['description']
                        artifact_string += 'Description: ' + artifact_object['Description'] + '\n'
                    artifact_object['Creator'] = artifact['creator']['fname'] + ' ' + artifact['creator']['lname']
                    artifact_string += 'Creator: ' + artifact_object['Creator'] + '\n'
                    hr_incident['Artifacts'] += artifact_string
                    artifacts.append(artifact_object)
                incident_object['Artifacts'] = artifacts
            hr_incidents.append(hr_incident)
            ec_incidents.append(incident_object)
        ec = {
            'Resilient.Incidents(val.Id && val.Id === obj.Id)': {
                'Id': incident_id,
                'Related': ec_incidents
            }
        }
        title = 'Incident ' + incident_id + ' related incidents'
        entry = {
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, hr_incidents),
            'EntryContext': ec
        }
        return entry
    else:
        return 'No related incidents found.'


def related_incidents(client, incident_id):
    response = client.get('/incidents/' + incident_id + '/related_ex?want_artifacts=true')
    return response


def add_note_command(client, incident_id, note):
    body = {
        'text': {
            'format': 'text',
            'content': note
        }
    }

    response = client.post('/incidents/' + str(incident_id) + '/comments', body)

    ec = {
        'Resilient.incidentNote(val.Id && val.Id === obj.Id)': response
    }
    entry = {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'EntryContext': ec,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'The note was added successfully to incident {0}'.format(incident_id)
    }
    return entry


def add_artifact_command(client, incident_id, artifact_type, artifact_value, artifact_description):
    body = {
        'type': artifact_type,
        'value': artifact_value,
        'description': {
            'format': 'text',
            'content': artifact_description
        }
    }
    response = client.post('/incidents/' + str(incident_id) + '/artifacts', body)

    ec = {
        'Resilient.incidentArtifact(val.Id && val.Id === obj.Id)': response
    }
    entry = {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'EntryContext': ec,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'The artifact was added successfully to incident {0}'.format(incident_id)
    }

    return entry


def fetch_incidents(client, first_fetch_time: str):
    last_fetched_timestamp = demisto.getLastRun() and demisto.getLastRun().get('time')
    demisto.debug(f'fetch_incidents {last_fetched_timestamp=}')

    if not last_fetched_timestamp:
        last_fetched_timestamp = to_timestamp(first_fetch_time)
    args = {'date-created-after': last_fetched_timestamp}    # Fetch incident from the last fetched timestamp.
    resilient_incidents = search_incidents(client, args)

    demisto_incidents = []
    last_incident_creation_time = last_fetched_timestamp
    if resilient_incidents:
        #  Update last_run_time to the latest incident creation time (maximum in milliseconds).
        last_incident_creation_time = max(
            [_incident.get("create_date") for _incident in resilient_incidents]
        )
        for incident in resilient_incidents:
            # Only fetching non-resolved incidents.
            if not incident.get('end_date') and incident.get('plan_status') == 'A':  # 'A' stands for 'Active'
                demisto.debug(f'fetch_incidents {incident=}')
                incident = process_raw_incident(client, incident)
                demisto_incident = dict()
                demisto_incident['name'] = f'IBM QRadar SOAR incident ID {str(incident["id"])}'
                demisto_incident['occurred'] = incident['create_date']
                demisto_incident['rawJSON'] = json.dumps(incident)
                demisto_incidents.append(demisto_incident)

    # Increasing by one millisecond in order not to fetch the same incident in the next run.
    demisto.setLastRun({'time': last_incident_creation_time + 1})
    demisto.incidents(demisto_incidents)


def list_scripts_command(client: SimpleClient, args: dict) -> CommandResults:
    """
    Getting the list of scripts belonging to the IBM QRadar SOAR organization (client instance is org specific),
    or a specific script if `script_id` argument was provided.
    """
    human_readable = ""
    script_id = args.get("script_id", "")

    response = client.get(f"/scripts/{script_id}")
    demisto.debug(f"list_scripts_command {response=}")

    script_ids = []
    scripts_to_process = (
        [response] if script_id else response.get(SCRIPT_ENTITIES, [])
    )
    human_readable += "Received script IDs: {received_ids}"
    for script in scripts_to_process:
        script_id = script.get("id", "")
        script_ids.append(script_id)
        # Padding blank lines inorder to format the outputs in a block.
        human_readable += f"""
        
Script ID: {script_id}
Script Name: {script.get('name, ''')}
Description: {script.get('description', '')}
Language: {script.get('language', '')}
        
        """
    demisto.info(f"list_scripts_command received script ids: {str(script_ids)}")
    return CommandResults(
        outputs_prefix="Resilient.Script",
        outputs=response,
        readable_output=human_readable.format(received_ids=str(script_ids)),
    )



def upload_incident_attachment_command(
    client: SimpleClient, args: dict
) -> CommandResults:
    """
    Uploads a file from XSOAR to an IBM SOAR incident.
    """
    incident_id = args.get("incident_id")
    entry_id = args.get("entry_id")
    try:
        file_path_obj = demisto.getFilePath(entry_id)
    except ValueError:
        return CommandResults(
            entry_type=EntryType.ERROR,
            readable_output=f"Could not find a file with entry ID: {entry_id}",
        )

    file_path, file_name = file_path_obj.get("path"), file_path_obj.get("name")

    try:
        response = client.post_attachment(
            uri=f"/incidents/{incident_id}/attachments",
            filepath=file_path,
            filename=file_name,
        )
        demisto.debug(f"upload_incident_attachment_command {response=}")
    except SimpleHTTPException as e:
        return CommandResults(
            entry_type=EntryType.ERROR,
            readable_output=f"Could not upload a file with entry ID: {entry_id} to incident: {incident_id}."
            f"\nGot error: {e.response.text}",
        )
    return CommandResults(
        readable_output=f"File was uploaded successfully to {incident_id}."
    )


def delete_incidents_command(client: SimpleClient, args: dict) -> CommandResults:
    """
    Deletes multiple incidents.
    """
    incident_ids: list = argToList(args.get("incident_ids", ""))
    demisto.info(f"delete_incidents_command {incident_ids=}")
    try:
        response: dict = client.put("/incidents/delete", payload=incident_ids)
        human_readable: str = (
            f"{incident_ids} were deleted successfully."
            if response["success"]
            else f"{response['message']}"
        )
    except SimpleHTTPException as e:
        return CommandResults(
            entry_type=EntryType.ERROR,
            readable_output=f"Could not delete incidents {incident_ids}. Got error: {e.response.text} ",
        )
    return CommandResults(readable_output=human_readable)


def list_incident_notes_command(client: SimpleClient, args: dict) -> CommandResults:
    """
    Lists an array of open tasks to which the current user is assigned.
    """
    incident_id = args.get("incident_id")
    demisto.debug(f"list_incident_notes_command {incident_id=}")
    try:
        response = client.get(f"/incidents/{incident_id}/comments")
        human_readable: str = tableToMarkdown(
            f"Incident {incident_id} Notes", t=prettify_incident_notes(response)
        )
        demisto.debug(f"{response=}")
        return CommandResults(
            outputs_prefix="Resilient.IncidentNotes",
            outputs=response,
            readable_output=human_readable,
        )
    except SimpleHTTPException as e:
        return CommandResults(
            entry_type=EntryType.ERROR,
            readable_output=f"Could not retrieve incident nots for incident ID: {incident_id}. Got error {e.response.text}",
        )


def update_incident_note_command(client: SimpleClient, args: dict) -> CommandResults:
    """
    Updates an incident's comment.
    """
    incident_id, note_id, note_text = (
        args.get("incident_id"),
        args.get("note_id"),
        args.get("note"),
    )
    demisto.debug(
        f"update_incident_note_command {incident_id=}, {note_id=}, {note_text=}"
    )
    body = {"text": {"format": "text", "content": note_text}}
    try:
        response = client.put(
            f"/incidents/{incident_id}/comments/{note_id}", payload=body
        )
        demisto.debug(f"{response=}")
        return CommandResults(
            readable_output=f"Successfully updated note ID {note_id} for incident ID {incident_id}"
        )
    except SimpleHTTPException as e:
        return CommandResults(
            entry_type=EntryType.ERROR,
            readable_output=f"Could not update note ID {note_id} for incident ID: {incident_id}. Got error {e.response.text}",
        )


def add_custom_incident_task_command(client: SimpleClient, args: dict):
    """
    Creates a new task for the given incident.
    """
    incident_id, task_instructions = args.get("incident_id"), args.get("instructions")
    demisto.debug(f"add_custom_incident_task_command {incident_id=}")
    body = {"text": {"format": "text", "content": task_instructions}}
    try:
        response = client.post(f"/incidents/{incident_id}/tasks", payload=body)
        demisto.debug(f"{response=}")
        return CommandResults(
            readable_output=f"Successfully created task for incident ID {incident_id}"
        )
    except SimpleHTTPException as e:
        return CommandResults(
            entry_type=EntryType.ERROR,
            readable_output=f"Could not create a task for incident ID: {incident_id}. Got error {e.response.text}",
        )


def list_tasks_command(client: SimpleClient) -> CommandResults:
    """
    Lists an array of open tasks to which the current user is assigned.
    """
    try:
        response: list = client.get("/tasks")
        demisto.debug(f"{response=}")
        tasks_list = []
        for incident_tasks_obj in response:
            tasks_list.extend(incident_tasks_obj.get("tasks"))
        # TODO - Figure out what human readable table to produce here
        human_readable: str = tableToMarkdown(name="Open Tasks", t=tasks_list)
        return CommandResults(
            outputs_prefix="Resilient.Tasks",
            outputs=response,
            readable_output=human_readable,
        )
    except SimpleHTTPException as e:
        return CommandResults(
            entry_type=EntryType.ERROR,
            readable_output=f"Could not retrieve tasks. Got error {e.response.text}",
        )


def get_task_members_command(client: SimpleClient, args: dict) -> CommandResults:
    """
    Gets the members of a given task by its ID.
    """
    task_id = args.get("task_id")
    try:
        response = client.get(f'/tasks/{task_id}/members')
        demisto.debug(f'{response=}')
        response = client.get(f"/tasks/{task_id}/members")
        demisto.debug(f"{response=}")
    except SimpleHTTPException as e:
        return CommandResults(
            entry_type=EntryType.ERROR,
            readable_output=f"Could not retrieve members of task ID: {task_id}. Got error {e.response.text}",
        )
    return CommandResults(
        outputs_prefix="Resilient.Task",
        outputs=response,
        readable_output=response.get("content", ""),
    )


def delete_tasks_command(client: SimpleClient, args: dict) -> CommandResults:
    """
    Deletes a single or multiple tasks.
    """
    task_ids: list = argToList(args.get("task_id"))
    try:
        response: dict = client.put("/tasks/delete", payload=task_ids)
        demisto.debug(f"delete_tasks_command {response=}")
        human_readable = (
            f"Tasks with IDs {task_ids} were deleted successfully."
            if response["success"]
            else f"{response['message']}"
        )
    except SimpleHTTPException as e:
        return CommandResults(
            entry_type=EntryType.ERROR,
            readable_output=f"Could not delete tasks with IDs: {task_ids}. Got error {e.response.text}",
        )
    demisto.debug(f"{response=}")
    return CommandResults(readable_output=human_readable)


def delete_task_members_command(client: SimpleClient, args: dict) -> CommandResults:
    """
    Deletes the members for a given task.
    """
    task_id = args.get("task_id")
    try:
        response = client.delete(f"/tasks/{task_id}/members")
    except SimpleHTTPException as e:
        return CommandResults(
            entry_type=EntryType.ERROR,
            readable_output=f"Could not retrieve instructions for task ID: {task_id}. Got error {e.response.text}",
        )
    demisto.debug(f"{response=}")
    return CommandResults(readable_output=response.get("content", ""))


def list_task_instructions_command(client: SimpleClient, args: dict) -> CommandResults:
    """
    Gets the instructions for a specific task.
    """
    task_id = args.get("task_id")
    try:
        response = client.get(
            f"/tasks/{task_id}/instructions_ex?text_content_output_format=objects_convert_text"
        )
    except SimpleHTTPException as e:
        return CommandResults(
            entry_type=EntryType.ERROR,
            readable_output=f"Could not retrieve instructions for task ID: {task_id}. Got error {e.response.text}",
        )
    demisto.debug(f"{response=}")
    return CommandResults(
        outputs_prefix="Resilient.Task",
        outputs=response,
        readable_output=response.get("content", ""),
    )


def get_modified_remote_data_command(
    client: SimpleClient, args: dict
) -> GetModifiedRemoteDataResponse:
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update = (
        remote_args.last_update
    )  # In the first run, this value will be set to 1 minute earlier
    last_update = (
        last_update.split(".")[0] + "Z"
    )  # Truncate milliseconds to match the format expected by the API.
    demisto.debug(f"get-modified-remote-data command {last_update=}")

    incidents = search_incidents(client, args={"last-modified-after": last_update})
    # Casting the incident ID to match the format expected by the server.
    modified_incident_ids = [str(incident.get("id")) for incident in incidents]
    demisto.debug(f"get-modified-remote-data command {modified_incident_ids=}")
    return GetModifiedRemoteDataResponse(modified_incident_ids)


def handle_incoming_incident_resolution(incident_id: str, resolution_id: int, resolution_summary: str) -> dict:
    """
    Resolves XSOAR close reason and creates a closing entry to be posted in the incident's War Room.
    """
    resolution_status = RESOLUTION_DICT.get(resolution_id, "Resolved")
    demisto.debug(
        f"handle_incoming_incident_resolution {incident_id=} | {resolution_status=} | {resolution_summary=}"
    )
    closing_entry = {
        "Type": EntryType.NOTE,
        "Contents": {
            "dbotIncidentClose": True,
            "closeReason": MIRROR_STATUS_DICT.get(resolution_status, "Resolved"),
            "closeNotes": f"{resolution_summary}\nClosed on IBM QRadar SOAR".strip(),
        },
        "ContentsFormat": EntryFormat.JSON,
    }
    return closing_entry


def handle_incoming_incident_reopening(incident_id: str) -> dict:
    """
    Post a reopening entry to the incident's War Room.
    """
    demisto.debug(f"handle_incident_reopening {incident_id=}")
    reopening_entry = {
        "Type": EntryType.NOTE,
        "Contents": {"dbotIncidentReopen": True},
        "ContentsFormat": EntryFormat.JSON,
    }
    return reopening_entry


def get_remote_data_command(client: SimpleClient, args: dict) -> GetRemoteDataResponse:
    """
    Args:
        client (SimpleClient): The IBM Resillient client.
        # TODO - Complete
        attachments_tag (str): The attachment tag, to tag the mirrored attachments.
        notes_tag (str): The comment tag, to tag the mirrored comments.
        fetch_attachments (bool): Whether to fetch the attachments or not.
        fetch_notes (bool): Whether to fetch the comments or not.
        mirror_resolved_issue (bool): Whether to mirror Jira issues that have been resolved, or have the status `Done`.
        args:
            id: Remote incident id.
            lastUpdate: Server last sync time with remote server.

    Returns:
        GetRemoteDataResponse: Structured incident response.
    """
    remote_args = GetRemoteDataArgs(args)
    incident_id = remote_args.remote_incident_id
    demisto.debug(f"get-remote-data {incident_id=}")

    incident = get_incident(client, incident_id)
    incident = process_raw_incident(client, incident)
    demisto.debug(f"get-remote-data {incident=}")
    entries = []

    # Handling remote incident resolution.
    if incident.get("end_date") and incident.get("plan_status") == "C":  # 'C' stands for 'Closed'
        if DEMISTO_PARAMS.get('close_xsoar_incident', True):
            resolution_id = incident.get("resolution_id")
            closing_entry = handle_incoming_incident_resolution(
                incident_id=incident_id,
                resolution_id=resolution_id,
                resolution_summary=remove_html_div_tags(
                    incident.get("resolution_summary", "")
                )
            )
            entries.append(closing_entry)

    # Handling open and remote incident re-opening.
    elif not incident.get("end_date") and incident.get("plan_status") == "A":
        reopening_entry = handle_incoming_incident_reopening(incident_id=incident_id)
        entries.append(reopening_entry)

    mirrored_data = dict()
    mirrored_data["rawJSON"] = json.dumps(incident)

    # TODO - Handle tags for attachments, tasks, notes
    return GetRemoteDataResponse(mirrored_object=incident, entries=entries)


def update_remote_system_command(client: SimpleClient, args: dict) -> str:
    remote_args = UpdateRemoteSystemArgs(args)
    incident_id = remote_args.remote_incident_id
    demisto.debug(
        f"update_remote_system_command {incident_id=} | {remote_args.incident_changed=}"
        f" {remote_args.entries=} | {remote_args.delta=} | {remote_args.data=} | {remote_args.inc_status}"
    )
    if remote_args.incident_changed and remote_args.delta:
        update_dto = prepare_incident_update_dto_for_mirror(client, incident_id, remote_args.delta)
        update_incident(client, incident_id, update_dto)
    else:
        demisto.debug(
            f"Skipping updating remote incident fields [{remote_args.remote_incident_id}] as it is not new nor changed"
        )
    return incident_id


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    ibm_qradar_incident_type_scheme = SchemeTypeMapping(
        type_name=IBM_QRADAR_SOAR_INCIDENT_SCHEMA_NAME,
        fields=IBM_QRADAR_INCIDENT_FIELDS,
    )

    for field in IBM_QRADAR_INCIDENT_FIELDS:
        ibm_qradar_incident_type_scheme.add_field(
            name=field,
            description=IBM_QRADAR_INCIDENT_FIELDS[field].get("description"),
        )
    return GetMappingFieldsResponse([ibm_qradar_incident_type_scheme])


def test_module(client: SimpleClient, fetch_time: str):
    """
    Verify client connectivity and the fetch_time parameter are according to the standards, if exists.

    Returns:
        'ok' if all tests passed, anything else will fail the test.
    """
    # Making a request to the client's base URL to retrieve information about the organization.
    client.get(uri="")

    # Testing fetch_time parameter's value.
    if fetch_time:
        try:
            datetime.strptime(fetch_time, TIME_FORMAT)
        except ValueError:
            raise DemistoException(
                "Invalid first fetch timestamp format, should be (YYYY-MM-DDTHH:MM:SSZ)."
                " For example: 2020-02-02T19:00:00Z"
            )
    return "ok"


''' EXECUTION CODE '''


def get_client():
    opts_dict = {
        "host": SERVER,
        "port": PORT,
        "cafile": os.environ.get("SSL_CERT_FILE") if USE_SSL else "false",
        "org": ORG_NAME,
    }
    if API_KEY_ID and API_KEY_SECRET:
        opts_dict.update({"api_key_id": API_KEY_ID, "api_key_secret": API_KEY_SECRET})
    elif USERNAME and PASSWORD:
        opts_dict.update({"email": USERNAME, "password": PASSWORD})
    else:
        return_error(
            "Credentials were not provided. Please configure API key ID and API key secret"
        )
    resilient_client = resilient.get_client(opts=opts_dict)
    resilient_client.request_max_retries = DEFAULT_RETRIES
    return resilient_client


def main():
    params = demisto.params()
    fetch_time = validate_fetch_time(params.get("fetch_time", ""))
    client = get_client()

    # Disable SDK logging warning messages
    integration_logger = logging.getLogger("resilient")  # type: logging.Logger
    integration_logger.propagate = False

    LOG(f"command is {demisto.command()}")

    try:
        command = demisto.command()
        args = demisto.args()
        if command == "test-module":
            # Checks if there is an authenticated session
            return_results(test_module(client, fetch_time))
        elif command == "fetch-incidents":
            fetch_incidents(client, fetch_time)
        elif command == "rs-search-incidents":
            demisto.results(search_incidents_command(client, args))
        elif command == "rs-update-incident":
            demisto.results(update_incident_command(client, args))
        elif command == "rs-incidents-get-members":
            demisto.results(get_members_command(client, args["incident-id"]))
        elif command == "rs-get-incident":
            demisto.results(get_incident_command(client, args["incident-id"]))
        elif command == "rs-incidents-update-member":
            demisto.results(
                set_member_command(client, args["incident-id"], args["members"])
            )
        elif command == "rs-incidents-get-tasks":
            demisto.results(get_tasks_command(client, args["incident-id"]))
        elif command == "rs-get-users":
            demisto.results(get_users_command(client))
        elif command == "rs-close-incident":
            demisto.results(close_incident_command(client, args["incident-id"]))
        elif command == "rs-create-incident":
            demisto.results(create_incident_command(client, args))
        elif command == "rs-incident-artifacts":
            demisto.results(incident_artifacts_command(client, args["incident-id"]))
        elif command == "rs-incident-attachments":
            demisto.results(incident_attachments_command(client, args["incident-id"]))
        elif command == "rs-related-incidents":
            demisto.results(related_incidents_command(client, args["incident-id"]))
        elif command == "rs-add-note":
            demisto.results(add_note_command(client, args["incident-id"], args["note"]))
        elif command == "rs-add-artifact":
            demisto.results(
                add_artifact_command(
                    client,
                    args["incident-id"],
                    args["artifact-type"],
                    args["artifact-value"],
                    args.get("artifact-description"),
                )
            )
        elif command == "rs-list-scripts":
            return_results(list_scripts_command(client, args))
        elif command == "rs-upload-incident-attachment":
            return_results(upload_incident_attachment_command(client, args))
        elif command == "rs-delete-incidents":
            return_results(delete_incidents_command(client, args))
        elif command == "rs-list-incident-notes":
            return_results(list_incident_notes_command(client, args))
        elif command == "rs-update-incident-note":
            return_results(update_incident_note_command(client, args))
        elif command == "rs-add-custom-incident-task":
            return_results(add_custom_incident_task_command(client, args))
        elif command == "rs-list-tasks":
            return_results(list_tasks_command(client))
        elif command == "rs-get-task-members":
            return_results(get_task_members_command(client, args))
        elif command == "rs-delete-tasks":
            return_results(delete_tasks_command(client, args))
        elif command == "rs-delete-task-members":
            return_results(delete_task_members_command(client, args))
        elif command == "rs-list-task-instructions":
            return_results(list_task_instructions_command(client, args))
        elif command == "get-modified-remote-data":
            return_results(get_modified_remote_data_command(client, args))
        elif command == "get-remote-data":
            return_results(get_remote_data_command(client, args))
        elif command == "update-remote-system":
            return_results(update_remote_system_command(client, args))
        elif command == "get-mapping-fields":
            return_results(get_mapping_fields_command())
    except Exception as e:
        LOG(str(e))
        LOG.print_log()
        raise


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
