
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import logging
import time
import urllib3
import resilient
from resilient.co3 import SimpleClient
from datetime import timezone

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
DEMISTO_PARAMS = demisto.params()
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
MAX_FETCH = DEMISTO_PARAMS.get('max_fetch', '1000')
TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
UTC = timezone.utc  # noqa: UP017
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
    'Other': 7,
    'Duplicate': 8,
    'False Positive': 9,
    'Resolved': 10
}

EXP_TYPE_ID_DICT = {
    1: 'Unknown',
    2: 'ExternalParty',
    3: 'Individual'
}

OBJECT_ACTION_TYPE_TO_ID = {
    'Incident': 0,
    'Task': 1,
    'Note': 2,
    'Milestone': 3,
    'Artifact': 4,
    'Attachment': 5,
    'Email Message': 13
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
        'xsoar_name': 'ibmsecurityqradarsoarresolution',
        'description': ''
    },
    'resolution_summary': {
        'xsoar_name': 'ibmsecurityqradarsoarresolutionsummary',
        'description': ''
    },
    "owner_id": {
        "xsoar_name": "",
        "description": "The principal ID of the incident owner.",
    },
    "reporter": {
        "xsoar_name": "ibmsecurityqradarsoarreportername",
        "description": "Who reported the incident.",
    },
    "severity_code": {
        "xsoar_name": "severity",
        "description": "The severity of the incident. 4 = Low, 5 = Medium, 6 = High.",
    },
    "creator.display_name": {
        "xsoar_name": "displayname",
        "description": "The display name of the incident creator.",
    }
}

""" CONSTANTS """
FILE_DOWNLOAD_ERROR_MESSAGE = "<html><head><title>Download error</title></head><body>Download error</body></html>"
SCRIPT_ENTITIES = "entities"
DEFAULT_RETURN_LEVEL = "full"
DEFAULT_RETRIES = 1
IBM_QRADAR_SOAR_INCIDENT_SCHEMA_NAME = "IBM QRadar SOAR Incident Schema"
DEFAULT_SEVERITY_CODE = 5
DEFAULT_TAG_FROM_IBM = 'FROM IBM'
DEFAULT_TAG_TO_IBM = 'FROM XSOAR'
""" ENDPOINTS """
SEARCH_INCIDENTS_ENDPOINT = "/incidents/query_paged"
''' HELPER FUNCTIONS '''


def validate_iso_time_format(iso_time: str) -> str:
    """
    Ensures the input time string does not contain the milliseconds part and the time string
    ends with a 'Z' to denote Zulu time (UTC).

    Args:
    iso_time (str): Time in ISO format to check and modify if needed.

    Returns:
    str: The modified iso_time string with a 'Z' suffix if it wasn't already present.
    """
    if not iso_time:
        return iso_time

    # Remove milliseconds from the time string.
    iso_time = iso_time.split('.')[0]

    if not iso_time.endswith('Z'):
        iso_time += 'Z'
    return iso_time


def normalize_timestamp(timestamp_ms: int | None):
    """
    Converts a timestamp in milliseconds to an ISO 8601 formatted date string in UTC.

    Parameters:
    - timestamp_ms (int or float): The timestamp in milliseconds since the Unix epoch.

    Returns:
    - str: The ISO 8601 formatted date string (e.g., "2020-08-09T10:00:00Z").
    """
    if not timestamp_ms:
        return ""
    try:
        # Convert milliseconds to seconds
        timestamp_s = timestamp_ms / 1000.0

        # Create a datetime object in UTC
        dt = datetime.fromtimestamp(timestamp_s, tz=UTC)

        # Format the datetime without microseconds and append 'Z'
        iso_str = dt.strftime('%Y-%m-%dT%H:%M:%SZ')

        return iso_str
    except (OverflowError, OSError) as e:
        raise ValueError("The timestamp is out of the valid range.") from e


def prettify_incidents(client, incidents):
    users = get_users(client)
    phases = get_phases(client)
    for incident in incidents:
        incident['id'] = str(incident['id'])
        if isinstance(incident['description'], str):
            incident['description'] = incident['description']
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
        demisto.debug(f"prettify_incident_notes {note=}")
        if note.get('text'):
            create_date: int | None = note.get("create_date")
            new_note_obj = {
                "id": note.get("id", ""),
                "text": note.get("text"),
                "created_by": f"{note.get('user_fname', '')} {note.get('user_lname', '')}",
                "create_date": normalize_timestamp(create_date),
                "modify_date": note.get("modify_date")
            }
            formatted_notes.append(new_note_obj)
    return formatted_notes


def prettify_incident_tasks(client: SimpleClient, tasks: list[dict]) -> list[dict]:
    """
    Formats and enriches tasks to a more readable data.
    """

    def format_task(task):

        task.update({
            'Phase': get_phase_name(client, task['phase_id']),
            'ID': task['id'],
            'Name': task['name'],
            'Description': task['description'],
            'DueDate': normalize_timestamp(task['due_date']) if task['due_date'] else 'No due date',
            'Status': 'Open' if task['status'] == 'O' else 'Closed',
            'Required': task['required'],
            'Owner': f"{task.get('owner_fname', '')} {task.get('owner_lname', '')}",
            'Creator': '',
            'Instructions': ''
        })

        if creator := task.get('creator_principal'):
            task['Creator'] = creator.get('display_name', '')
        if instructions := task.get('instructions'):
            task['Instructions'] = instructions.get('content', '')

        return task

    formatted_tasks = [format_task(task) for task in tasks]
    demisto.debug(f'prettify_incident_tasks {formatted_tasks=}')
    return formatted_tasks


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
        else:  # timeframe == 'minutes':
            demisto.debug(f"{timeframe=} should be minutes.")
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
        else:  # timeframe == 'minutes':
            demisto.debug(f"{timeframe=} should be minutes.")
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
        else:  # timeframe == 'minutes':
            demisto.debug(f"{timeframe=} should be minutes.")
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

    data: Dict[str, Any] = {
        'filters': [{
            'conditions': conditions
        }],
        'sorts': [{
            'field_name': 'create_date',
            'type': "asc"
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
    mirror_tags = [
        params.get('tag_from_ibm'),
        params.get('tag_to_ibm')
    ]
    return {
        "mirror_direction": mirror_direction,
        "mirror_instance": demisto.integrationInstance(),
        "mirror_tags": mirror_tags,
    }


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
    demisto.debug(f'process_raw_incident {incident_id=}')

    if isinstance(incident.get("description"), str):
        incident["description"] = incident["description"]
    elif isinstance(incident.get("description"), dict):
        incident["description"] = incident["description"]["content"]

    incident["discovered_date"] = normalize_timestamp(incident.get("discovered_date"))
    incident["create_date"] = normalize_timestamp(incident.get("create_date"))

    if DEMISTO_PARAMS.get('fetch_notes'):
        notes = get_incident_notes(client, incident_id)
        incident["notes"] = prettify_incident_notes(notes)
        demisto.debug(f"process_raw_incident {[note['text'] for note in incident['notes']]=}")

    if DEMISTO_PARAMS.get('fetch_tasks'):
        tasks = get_tasks(client, incident_id)
        incident["tasks"] = prettify_incident_tasks(client, tasks)

    attachments_metadata = incident_attachments(client, incident_id)
    incident['attachments'] = [
        {
            'ID': attachment.get('id'),
            'Name': attachment.get('name'),
            'Create Time': attachment.get('created'),    # Timestamp in milliseconds.
            'Size': attachment.get('size')
        }
        for attachment in attachments_metadata
    ]
    demisto.debug(f'process_raw_incident {incident["attachments"]=}')

    artifacts = incident_artifacts(client, incident_id)
    incident['artifacts'] = [
        {
            'ID': artifact.get('id'),
            'Type': get_artifact_type(client, artifact.get('type')),
            'Value': artifact.get('value'),    # Timestamp in milliseconds.
        }
        for artifact in artifacts
    ]
    incident["phase"] = get_phase_name(client, incident['phase_id'])
    incident.update(get_mirroring_data())
    demisto.debug(f'process_raw_incident processed_incident={incident}')
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

    raise DemistoException(f'Could no resolve field value for field: {field}')


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
    incident = get_incident(client, incident_id)
    demisto.debug(f"prepare_incident_update_dto_for_mirror {delta=} | {incident=}")

    changes = []
    for field, new_value in delta.items():
        # `resolution_id` is updated once the incident is closed or re-opened and requires additional treatment.
        if field == 'resolution_id' and DEMISTO_PARAMS.get('close_ibm_incident'):
            remote_status = incident["plan_status"]

            # Handling remote incident reopening.
            if new_value == '' and remote_status == "C":
                changes.append(get_field_changes_entry("plan_status", remote_status, "A"))

            # Remote incident closure handling.
            else:
                changes.append(get_field_changes_entry("plan_status", remote_status, "C"))

        elif field == 'ibmsecurityqradarsoarname':  # Excluding this field as the 'name' field is also used and read by XSOAR.
            field = 'name'

        changes.append(
            get_field_changes_entry(
                field=field, old_value=incident[field], new_value=new_value
            )
        )

    dto = {"changes": changes}
    demisto.debug(f"prepare_incident_update_dto_for_mirror {dto=}")
    return dto


def to_timestamp(time_input):
    if isinstance(time_input, int):
        # Input is already a timestamp in milliseconds
        return time_input
    elif isinstance(time_input, str):
        # Try to parse the string as an integer timestamp
        try:
            timestamp_ms = int(time_input)
            return timestamp_ms
        except ValueError:
            # Not an integer, try to parse as ISO time string
            try:
                dt = datetime.strptime(time_input, '%Y-%m-%dT%H:%M:%SZ')
                dt = dt.replace(tzinfo=UTC)
                timestamp_ms = int(dt.timestamp() * 1000)
                return timestamp_ms
            except ValueError:
                raise ValueError(
                    f"Invalid time input: '{time_input}' is neither a valid integer timestamp nor a valid ISO time string.")
    else:
        raise TypeError(f"Invalid type for time_input: expected str or int, got {type(time_input).__name__}.")


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


def get_attachment(client: SimpleClient, incident_id: str, attachment_id: str) -> tuple[str, str]:
    """
    Retrieves the name and the contents of an incident's attachment with ID `attachment_id`.
    """
    response = client.get(f'/incidents/{incident_id}/attachments/{attachment_id}')
    demisto.debug(f"get_attachment {response}")
    if isinstance(response, dict) and 'name' in response:
        attachment_name = response['name']
    else:
        raise DemistoException(f'Could not retrieve a file with ID {attachment_id}')

    response: requests.Response = client.get(f'/incidents/{incident_id}/attachments/{attachment_id}/contents',
                                             get_response_object=True)
    contents = str(response.content)
    demisto.debug(f"get_attachment {contents}")
    if FILE_DOWNLOAD_ERROR_MESSAGE in contents:
        raise DemistoException(f'Could not retrieve a file with ID {attachment_id}')

    return attachment_name, contents


def get_users(client):
    response = client.get('/users')
    return response


def get_phase_name(client: SimpleClient, phase_id: str) -> str:
    response = client.get(f'/phases/{phase_id}')
    return response.get('name')


def get_phases(client: SimpleClient):
    response = client.get('/phases')
    return response.get('entities', [])


def get_tasks(client: SimpleClient, incident_id: str):
    response = client.get(f'/incidents/{incident_id}/tasks?text_content_output_format=objects_convert_text')
    return response


def update_task(client: SimpleClient, task_id: str, task_dto: dict):
    """
    Updating a remote task with ID `task_id` according to the updated values in `task_dto`.
    """
    response = client.put(f'/tasks/{task_id}', payload=task_dto)
    return response


def search_incidents(client: SimpleClient, args: dict) -> list | dict:
    """
    Search and get IBM QRadar incidents according to filters and pagination parameters.
    :return: List of IBM QRadar incidents matching the search query.
    """
    search_query_data = prepare_search_query_data(args)

    return_level = args.get('return_level', DEFAULT_RETURN_LEVEL)
    endpoint = f'{SEARCH_INCIDENTS_ENDPOINT}?text_content_output_format=objects_convert_text&return_level={return_level}'

    response = client.post(endpoint, search_query_data)
    demisto.debug(f'search_incidents {response}')
    return response['data']


def update_incident(client, incident_id, data):
    response = client.patch('/incidents/' + str(incident_id), data)
    return response


def get_incident(client: SimpleClient, incident_id, content_format=False):
    url = '/incidents/' + str(incident_id)
    if content_format:
        url += '?text_content_output_format=objects_convert_text'
    response = client.get(url)
    return response


def list_open_incidents(client):
    response = client.get('/incidents/open')
    return response


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


''' COMMAND FUNCTIONS '''


def get_incident_command(client, incident_id):
    incident = get_incident(client, incident_id)
    wanted_keys = ['create_date', 'discovered_date', 'description', 'due_date', 'id', 'name', 'owner_id',
                   'phase_id', 'severity_code', 'confirmed', 'employee_involved', 'negative_pr_likely',
                   'confirmed', 'start_date', 'due_date', 'negative_pr_likely', 'reporter', 'exposure_type_id',
                   'nist_attack_vectors']
    pretty_incident = {k: incident[k] for k in wanted_keys if k in incident}
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


def search_incidents_command(client, args):
    incidents = search_incidents(client, args)
    if incidents:
        pretty_incidents = prettify_incidents(client, incidents)

        result_incidents = createContext(pretty_incidents, id=None,
                                         keyTransform=underscoreToCamelCase, removeNull=True)  # pragma: no cover
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
    else:  # pragma: no cover
        return f'Failed to update incident {incident_id}'


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


def get_tasks_command(client, incident_id):
    tasks = get_tasks(client, incident_id)
    tasks = prettify_incident_tasks(client, tasks)
    for task in tasks:
        incident_name = task.get('IncidentName', '')
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
            'Contents': tasks,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, tasks,
                                             ['ID', 'Name', 'Category', 'Form', 'Status', 'DueDate', 'Instructions',
                                              'UserNotes', 'Required', 'Creator']),
            'EntryContext': ec
        }
        return entry
    return 'No tasks found for this incident.'


def update_task_command(client: SimpleClient, args: dict) -> CommandResults:
    task_id = args.get('task_id')
    if not task_id:
        raise DemistoException('task_id is required')

    task_dto = {}
    if task_name := args.get('name'):
        task_dto['name'] = task_name

    if owner_id := args.get('owner_id'):
        task_dto['inc_owner_id'] = int(owner_id)

    if due_date := args.get('due_date'):
        task_dto['due_date'] = to_timestamp(due_date)

    if phase := args.get('phase'):
        task_dto['phase_id'] = phase

    if instructions := args.get('instructions'):
        task_dto['instructions'] = instructions

    if args.get('status') == "Open":
        task_dto['status'] = 'O'
    elif args.get('status') == "Completed":
        task_dto['status'] = 'C'
    demisto.debug(f'update_task_command {task_dto=}')
    update_task(client, task_id, task_dto)
    return CommandResults(readable_output=f'Task {task_id} updated successfully.')


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
    return None


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
    incident_owner = ""
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


def upload_incident_attachment(client: SimpleClient, incident_id: str, entry_id: str, tag_to_ibm: str):
    """
        Uploads a file from XSOAR to the IBM QRadar SOAR incident with ID `incident_id`.
    """
    try:
        file_path_obj = demisto.getFilePath(entry_id)
    except ValueError:
        raise DemistoException(f"Could not find a file with entry ID: {entry_id}")

    file_path, file_name = file_path_obj.get("path"), file_path_obj.get("name")

    # Split the file name into root and extension
    root, extension = os.path.splitext(file_name)
    tagged_file_name = f'{root}_{tag_to_ibm}'
    if extension:
        tagged_file_name = tagged_file_name + extension

    response = client.post_attachment(
        uri=f"/incidents/{incident_id}/attachments",
        filepath=file_path,
        filename=tagged_file_name,
    )
    demisto.debug(f"upload_incident_attachment_command {response=}")


def get_incident_notes(client: SimpleClient, incident_id: str) -> list:
    response = client.get(f"/incidents/{incident_id}/comments?text_content_output_format=objects_convert_text")
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


def get_scripts(client: SimpleClient, script_id: str) -> dict[str, Any]:
    """
    Retrieves a single script's enriched data if `script_id` is provided,
    and retrieves the list of scripts belonging to the IBM QRadar SOAR organization if `script_id` is not provided.
    """
    response = client.get(f"/scripts/{script_id}")
    demisto.debug(f"get_scripts | {type(response)=} | {response=}")
    return response


def fetch_incidents(client, first_fetch_time: str, fetch_closed: bool):
    last_fetched_timestamp = demisto.getLastRun() and demisto.getLastRun().get('time')
    demisto.info(f'fetch_incidents {last_fetched_timestamp=} | {first_fetch_time=}')

    if not last_fetched_timestamp:
        if not first_fetch_time:
            raise DemistoException('First fetch time not provided.')

        last_fetched_timestamp = to_timestamp(first_fetch_time)
    args = {'date-created-after': last_fetched_timestamp}  # Fetch incident from the last fetched timestamp.
    resilient_incidents = search_incidents(client, args)

    demisto_incidents = []
    if resilient_incidents:
        demisto.info(f'fetch_incidents retrieved {len(resilient_incidents)=} | '
                     f'with IDs: {[incident.get("id") for incident in resilient_incidents]}')
        #  Update last_run_time to the latest incident creation time (maximum in milliseconds).
        last_fetched_timestamp = last_incident_creation_time = max(
            [_incident.get("create_date") for _incident in resilient_incidents]
        )
        demisto.debug(f'fetch_incidents {last_incident_creation_time=}')
        for incident in resilient_incidents:

            # Only fetching non-resolved incidents if `fetch_closed` is disabled.
            if fetch_closed or (not incident.get('end_date') and incident.get('plan_status') == 'A'):  # 'A' stands for 'Active'
                demisto.debug(f'fetch_incidents {incident=}')
                incident = process_raw_incident(client, incident)
                demisto_incident = {}
                demisto_incident['name'] = f'IBM QRadar SOAR incident ID {str(incident["id"])}'
                demisto_incident['occurred'] = incident.get('discovered_date', None) or incident['create_date']
                demisto_incident['rawJSON'] = json.dumps(incident)
                demisto_incidents.append(demisto_incident)

    # Increasing by one millisecond in order not to fetch the same incident in the next run.
    demisto.setLastRun({'time': last_fetched_timestamp + 1})
    demisto.incidents(demisto_incidents)


def add_note(client: SimpleClient, incident_id: str, note_content: str) -> dict:
    """
    Adds a note to the specified incident.
    """
    body = {
        'text': {
            'format': 'text',
            'content': note_content
        }
    }
    return client.post(f'/incidents/{str(incident_id)}/comments', body)


def add_custom_task(client: SimpleClient,
                    incident_id: str,
                    task_name: str,
                    phase: str,
                    due_date: int | None,
                    description: str,
                    instructions: str,
                    owner_id: str) -> dict:
    """
    Adds a custom task to the incident.
    If task creation was successful, task ID is returned.
    """
    # Initiating with required fields.
    task_dto: Dict[str, Any] = {
        "name": task_name,
        "phase_id": {"name": phase},
        "description": description,
    }
    # Optional fields.
    if due_date:
        task_dto["due_date"] = due_date     # Due date in milliseconds timestamp.
    if instructions:
        task_dto["instructions"] = instructions
    if owner_id and owner_id.isdigit():
        task_dto["owner_id"] = int(owner_id)
    elif owner_id:
        raise DemistoException("Owner ID must be an integer number.")
    demisto.debug(f"{task_dto=}")
    return client.post(uri=f"/incidents/{incident_id}/tasks", payload=task_dto)


def add_note_command(client, incident_id, note: str, tag_to_ibm: str):
    response = add_note(client, str(incident_id), '\n'.join((note, tag_to_ibm)))
    demisto.debug(f'add_note_command {response=}')
    return CommandResults(
        mark_as_note=True,
        entry_type=EntryType.NOTE,
        tags=[tag_to_ibm],
        outputs_prefix="Resilient.incidentNote",
        outputs=response,
        readable_output=f'The note was added successfully to incident {incident_id}\n\n{note} '
    )


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
        'HumanReadable': f'The artifact was added successfully to incident {incident_id}'
    }

    return entry


def list_scripts_command(client: SimpleClient, args: dict) -> CommandResults:
    """
    Getting the list of scripts belonging to the IBM QRadar SOAR organization (client instance is org specific),
    or a specific script if `script_id` argument was provided.
    """
    script_id = args.get("script_id", "")
    response = get_scripts(client, script_id)

    script_ids = []
    scripts_to_process = [response] if script_id else response.get(SCRIPT_ENTITIES, [])

    if not script_id and len(scripts_to_process) > 1:  # Multiple script to retrieve info for.
        for script in scripts_to_process:
            _script_id = script.get('id')
            if not _script_id:
                raise DemistoException("Script with ID not found.")

            script = get_scripts(client, _script_id)  # Enriching script's data.
            script_ids.append(_script_id)

    demisto.info(f"list_scripts_command received script ids: {str(script_ids)}")
    return CommandResults(
        outputs_prefix="Resilient.Scripts",
        outputs=scripts_to_process,  # Already processed and enriched with additional data.
        readable_output=tableToMarkdown(f'{DEMISTO_PARAMS.get("org")} Scripts',
                                        scripts_to_process,
                                        headers=["id", "name", "description", "language"])
    )


def get_attachment_command(client: SimpleClient, args: dict) -> dict:
    """
    Retrieves an attachment with ID: `args['attachment_id']` from IBM QRadar SOAR.
    """
    name, contents = get_attachment(client, str(args.get('incident_id', '')), str(args.get('attachment_id', '')))
    demisto.debug(f"get_attachments_command {name=}")
    return fileResult(name, contents)


def upload_incident_attachment_command(
    client: SimpleClient, args: dict, tag_to_ibm: str
) -> CommandResults:
    """
    Uploads a file from XSOAR to an IBM QRadar SOAR incident.
    """
    incident_id = args.get("incident_id")
    if not incident_id:
        raise DemistoException("Incident ID is required.")

    entry_id = args.get("entry_id")
    if not entry_id:
        raise DemistoException("Entry ID is required.")

    upload_incident_attachment(client, str(incident_id), str(entry_id), tag_to_ibm)
    return CommandResults(
        readable_output=f"File was uploaded successfully to {incident_id}."
    )


def delete_incidents_command(client: SimpleClient, args: dict) -> CommandResults:
    """
    Deletes multiple incidents.
    """
    incident_ids: list = argToList(args.get("incident_ids", ""))
    demisto.info(f"delete_incidents_command {incident_ids=}")

    response: dict = client.put("/incidents/delete", payload=incident_ids)
    human_readable: str = (
        f"Incidents {incident_ids} were deleted successfully."
        if response["success"]
        else f"{response['message']}"
    )

    return CommandResults(readable_output=human_readable)


def list_incident_notes_command(client: SimpleClient, args: dict) -> CommandResults:
    """
    Lists an array of open tasks to which the current user is assigned.
    """
    incident_id = str(args.get("incident_id"))
    demisto.debug(f"list_incident_notes_command {incident_id=}")

    response = get_incident_notes(client, incident_id)
    human_readable: str = tableToMarkdown(
        f"Incident {incident_id} Notes", t=prettify_incident_notes(response)
    )
    demisto.debug(f"{response=}")
    return CommandResults(
        outputs_prefix="Resilient.IncidentNote",
        outputs=response,
        readable_output=human_readable,
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
    body = {
        "text": {
            "format": "text",
            "content": note_text
        }
    }
    response = client.put(
        f"/incidents/{incident_id}/comments/{note_id}", payload=body
    )
    demisto.debug(f"{response=}")
    return CommandResults(
        readable_output=f"Successfully updated note ID {note_id} for incident ID {incident_id}"
    )


def list_tasks_command(client: SimpleClient) -> CommandResults:
    """
    Lists an array of open tasks to which the current user is assigned.
    """
    response: list = client.get("/tasks")
    demisto.debug(f"{response=}")
    tasks_list = []
    for incident_tasks_obj in response:
        tasks_list.extend(incident_tasks_obj.get("tasks"))
    human_readable: str = tableToMarkdown(name="Open Tasks", t=tasks_list)
    return CommandResults(
        outputs_prefix="Resilient.Tasks",
        outputs=response,
        readable_output=human_readable,
    )


def get_task_members_command(client: SimpleClient, args: dict) -> CommandResults:
    """
    Gets the members of a given task by its ID.
    """
    task_id: str = str(args.get('task_id', ''))
    response = client.get(f'/tasks/{task_id}/members')
    demisto.debug(f'{response=}')

    return CommandResults(
        outputs_prefix="Resilient.Task",
        outputs=response,
        readable_output=response.get("content", ""),
    )


def delete_tasks_command(client: SimpleClient, args: dict) -> CommandResults:
    """
    Deletes a single or multiple tasks.
    """
    task_ids: list = argToList(args.get("task_ids"))
    if not task_ids:
        raise DemistoException('No task IDs provided.')
    response: dict = client.put("/tasks/delete", payload=task_ids)
    demisto.debug(f"delete_tasks_command {response=}")
    human_readable = (
        f"Tasks with IDs {task_ids} were deleted successfully."
        if response["success"]
        else f"{response['message']}"
    )
    demisto.debug(f"{response=}")
    return CommandResults(readable_output=human_readable)


def delete_task_members_command(client: SimpleClient, args: dict) -> CommandResults:
    """
    Deletes the members for a given task.
    """
    task_id = args.get("task_id")
    response = client.delete(f"/tasks/{task_id}/members")
    demisto.debug(f"{response=}")
    return CommandResults(readable_output=response.get("content", ""))


def list_task_instructions_command(client: SimpleClient, args: dict) -> CommandResults:
    """
    Gets the instructions for a specific task.
    """
    task_id = args.get("task_id")
    response = client.get(f"/tasks/{task_id}/instructions_ex?text_content_output_format=objects_convert_text")

    return CommandResults(
        outputs_prefix="Resilient.Task",
        outputs=response,
        readable_output=response.get("content", ""),
    )


def add_custom_task_command(client: SimpleClient, args: dict) -> CommandResults:
    """
    Adds a custom task to the specified incident.
    """
    demisto.debug(f"add_custom_task_command {args=}")
    incident_id: str = str(args.get("incident_id", ''))
    name: str = str(args.get("name", ''))
    owner_id: str = str(args.get("owner_id", ''))
    description: str = str(args.get("description", ''))
    instructions: str = str(args.get("instructions", ''))
    phase: str = str(args.get("phase", ''))

    if due_date := args.get("due_date"):
        due_date = validate_iso_time_format(str(due_date))
        due_date = to_timestamp(due_date)
    else:
        due_date = None
    response = add_custom_task(client, incident_id, name, phase, due_date, description, instructions, owner_id)
    demisto.debug(f"add_custom_task_command {response=}")
    if task_id := response.get('id'):
        return CommandResults(
            outputs_prefix="Resilient.TaskId",
            outputs=task_id,
            readable_output=f"Successfully created new task for incident with ID {incident_id}. Task ID: {task_id}")
    return CommandResults(readable_output=f"Could not create a new task: {response.get('message')}")


def get_modified_remote_data_command(client: SimpleClient, args: dict) -> GetModifiedRemoteDataResponse:
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update = validate_iso_time_format(remote_args.last_update)  # In the first run, this value will be set to 1 minute
    # earlier
    demisto.debug(f"get-modified-remote-data command {last_update=}")

    incidents = search_incidents(client, args={"last-modified-after": last_update})
    # Casting the incident ID to match the format expected by the server.
    modified_incident_ids = [str(incident.get("id")) for incident in incidents]
    demisto.debug(f"get-modified-remote-data command {modified_incident_ids=}")
    return GetModifiedRemoteDataResponse(modified_incident_ids)


def get_remote_data_command(client: SimpleClient,
                            args: dict,
                            tag_to_ibm: str,
                            tag_from_ibm: str
                            ) -> GetRemoteDataResponse:
    """
    Args:
        client (SimpleClient): The IBM Resilient client.
        args (dict): The command arguments.
        tag_to_ibm (str): Mirror in tag.
        tag_from_ibm (str): Mirror out tag.
    Returns:
        GetRemoteDataResponse: Structured incident response.
    """
    remote_args = GetRemoteDataArgs(args)
    # In the first run, this value will be set to 1 minute earlier.
    last_update_iso = validate_iso_time_format(remote_args.last_update)
    last_update_timestamp = to_timestamp(last_update_iso)

    incident_id = remote_args.remote_incident_id
    demisto.debug(f"get_remote_data_command {incident_id=}")

    incident = get_incident(client, incident_id, content_format=True)
    incident = process_raw_incident(client, incident)
    demisto.debug(f"get_remote_data_command {incident=}")
    entries = []

    # Create note entries.
    note_entries = incident.get('notes', [])
    for note_entry in note_entries:
        demisto.debug(f'get_remote_data_command {note_entry=}')
        note_modify_date_timestamp = note_entry.get('modify_date')
        if (tag_to_ibm not in str(note_entry['text'])
                and note_modify_date_timestamp
                and note_modify_date_timestamp >= last_update_timestamp):
            entries.append({
                'ContentsFormat': EntryFormat.TEXT,
                'Type': EntryType.NOTE,
                'Contents':
                    f"{note_entry.get('text').get('content')}\n"
                    f"Added By: {note_entry.get('created_by', '')}\n",
                'Tags': [tag_from_ibm],
                'Note': True
            })

    # Create file entries
    attachment_entries = incident.get('attachments', [])
    for attachment_entry in attachment_entries:
        demisto.debug(f'get_remote_data_command {attachment_entry=}')
        attachment_create_time = attachment_entry.get('Create Time')

        if (tag_to_ibm not in attachment_entry.get('Name', '')
                and attachment_create_time
                and attachment_create_time >= last_update_timestamp):
            file_name, content = get_attachment(client, incident_id, attachment_entry.get('ID'))
            file_entry = fileResult(filename=file_name, data=content, file_type=EntryType.ENTRY_INFO_FILE)
            entries.append(file_entry)

    # Handling remote incident resolution. 'C' stands for 'Closed'
    if DEMISTO_PARAMS.get('close_xsoar_incident', False) and incident.get("end_date") and incident.get("plan_status") == "C":
        resolution_id = incident.get("resolution_id")
        if resolution_id is not None:
            closing_entry = handle_incoming_incident_resolution(
                incident_id=incident_id,
                resolution_id=int(resolution_id),
                resolution_summary=incident.get("resolution_summary", "")
            )
            entries.append(closing_entry)

    # Handling open and remote incident re-opening.
    elif not incident.get("end_date") and incident.get("plan_status") == "A":
        reopening_entry = handle_incoming_incident_reopening(incident_id=incident_id)
        entries.append(reopening_entry)

    mirrored_data = {}
    mirrored_data["rawJSON"] = json.dumps(incident)

    demisto.debug(f"get_remote_data_command mirrored_object={incident}")
    return GetRemoteDataResponse(mirrored_object=incident, entries=entries)


def update_remote_system_command(client: SimpleClient, args: dict, tag_to_ibm: str) -> str:
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
    entries = remote_args.entries
    if entries:
        for entry in entries:
            demisto.debug(f'update_remote_system_command {entry=}')
            entry_id = entry.get('id', '')
            entry_type = entry.get('type', '')
            entry_tags = entry.get('tags', [])
            demisto.debug(f'update_remote_system {entry_id=} | {entry_type=} | {entry_tags=}')
            if entry_type == EntryType.NOTE and tag_to_ibm in entry_tags:
                add_note(client, incident_id, entry.get('Contents'))
            elif entry_type == EntryType.FILE and tag_to_ibm in entry_tags:
                upload_incident_attachment(client, incident_id, entry_id, tag_to_ibm)
    return incident_id


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    ibm_qradar_incident_type_scheme = SchemeTypeMapping(
        type_name=IBM_QRADAR_SOAR_INCIDENT_SCHEMA_NAME,
        fields=IBM_QRADAR_INCIDENT_FIELDS,
    )

    fields_copy = []
    for field in IBM_QRADAR_INCIDENT_FIELDS:
        fields_copy.append(field)
    for field in fields_copy:
        ibm_qradar_incident_type_scheme.add_field(
            name=field,
            description=IBM_QRADAR_INCIDENT_FIELDS[field].get("description")
        )
    return GetMappingFieldsResponse([ibm_qradar_incident_type_scheme])


def test_module(client: SimpleClient, fetch_time: str, tag_to_ibm=DEFAULT_TAG_TO_IBM, tag_from_ibm=DEFAULT_TAG_FROM_IBM) -> str:
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

    # Testing tags
    if tag_from_ibm == tag_to_ibm:
        raise DemistoException(
            f'Tag *to* IBM (`{tag_to_ibm}`) and Tag *from* IBM (`{tag_from_ibm}`) cannot have the same value.')

    return "ok"


''' EXECUTION CODE '''


def get_client():  # pragma: no cover
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


def main():  # pragma: no cover
    params = demisto.params()
    fetch_time = validate_iso_time_format(params.get("fetch_time", ""))
    client = get_client()

    # Disable SDK logging warning messages
    integration_logger = logging.getLogger("resilient")  # type: logging.Logger
    integration_logger.propagate = False

    tag_to_ibm = params.get('tag_to_ibm', DEFAULT_TAG_TO_IBM)
    tag_from_ibm = params.get('tag_from_ibm', DEFAULT_TAG_FROM_IBM)
    demisto.debug(f"main {tag_from_ibm=} | {tag_to_ibm=}")

    try:
        command = demisto.command()
        args = demisto.args()
        demisto.info(f"main {command=} | {args=}")

        if command == "test-module":
            # Checks if there is an authenticated session
            return_results(test_module(client, fetch_time, tag_to_ibm, tag_from_ibm))
        elif command == "fetch-incidents":
            fetch_incidents(client, fetch_time, params.get('fetch_closed', False))
        elif command == "rs-search-incidents":
            return_results(search_incidents_command(client, args))
        elif command == "rs-update-incident":
            return_results(update_incident_command(client, args))
        elif command == "rs-incidents-get-members":
            return_results(get_members_command(client, args["incident-id"]))
        elif command == "rs-get-incident":
            return_results(get_incident_command(client, args["incident-id"]))
        elif command == "rs-incidents-update-member":
            return_results(
                set_member_command(client, args["incident-id"], args["members"])
            )
        elif command == "rs-incidents-get-tasks":
            return_results(get_tasks_command(client, args["incident-id"]))
        elif command == "rs-get-users":
            return_results(get_users_command(client))
        elif command == "rs-close-incident":
            return_results(close_incident_command(client, args["incident-id"]))
        elif command == "rs-create-incident":
            return_results(create_incident_command(client, args))
        elif command == "rs-incident-artifacts":
            return_results(incident_artifacts_command(client, args["incident-id"]))
        elif command == "rs-incident-attachments":
            return_results(incident_attachments_command(client, args["incident-id"]))
        elif command == "rs-get-attachment":
            return_results(get_attachment_command(client, args))
        elif command == "rs-upload-incident-attachment":
            return_results(upload_incident_attachment_command(client, args, tag_to_ibm))
        elif command == "rs-related-incidents":
            return_results(related_incidents_command(client, args["incident-id"]))
        elif command == "rs-add-note":
            return_results(add_note_command(client, args["incident-id"], args["note"], tag_to_ibm))
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
        elif command == "rs-delete-incidents":
            return_results(delete_incidents_command(client, args))
        elif command == "rs-list-incident-notes":
            return_results(list_incident_notes_command(client, args))
        elif command == "rs-update-incident-note":
            return_results(update_incident_note_command(client, args))
        elif command == "rs-list-tasks":
            return_results(list_tasks_command(client))
        elif command == "rs-update-task":
            return_results(update_task_command(client, args))
        elif command == "rs-get-task-members":
            return_results(get_task_members_command(client, args))
        elif command == "rs-delete-tasks":
            return_results(delete_tasks_command(client, args))
        elif command == "rs-delete-task-members":
            return_results(delete_task_members_command(client, args))
        elif command == "rs-list-task-instructions":
            return_results(list_task_instructions_command(client, args))
        elif command == "rs-add-custom-task":
            return_results(add_custom_task_command(client, args))
        elif command == "get-modified-remote-data":
            return_results(get_modified_remote_data_command(client, args))
        elif command == "get-remote-data":
            return_results(get_remote_data_command(client, args, tag_to_ibm, tag_from_ibm))
        elif command == "update-remote-system":
            return_results(update_remote_system_command(client, args, tag_to_ibm))
        elif command == "get-mapping-fields":
            return_results(get_mapping_fields_command())
    except Exception as e:
        LOG(str(e))
        LOG.print_log()
        raise


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
