import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests
import traceback
from datetime import datetime, timedelta
import os

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
PARAMS = demisto.params()
FETCHES_INCIDENTS = PARAMS.get('isFetch')
FETCH_TIME = PARAMS.get('fetch_time')
FETCH_ATTACHMENTS = PARAMS.get('fetch_attachments')
OBJECTS_TO_FETCH = PARAMS.get('objects_to_fetch').split(',')
MAX_RESULT = PARAMS.get('max_results')
USERNAME = PARAMS.get('credentials').get('identifier')
PASSWORD = PARAMS.get('credentials').get('password')
# Remove trailing slash to prevent wrong URL path to service
SERVER = PARAMS['url'][:-1] if (PARAMS['url'] and PARAMS['url'].endswith('/')) else PARAMS['url']
CLIENT_ID = PARAMS.get('client_id')
QUERY_STRING = PARAMS.get('query_string')
DATE_FORMAT = '%m/%d/%Y %I:%M:%S %p'
# Service base URL
BASE_URL = SERVER + '/CherwellAPI/'

HTTP_CODES = {
    'unauthorized': 401,
    'internal_server_error': 500,
    'success': 200
}

HEADERS = {
    'Content-Type': "application/json",
    'Accept': "application/json"
}

QUERY_OPERATORS = ['eq', 'gt', 'lt', 'contains', 'startwith']

BUSINESS_OBJECT_IDS = {
    "incident": "6dd53665c0c24cab86870a21cf6434ae",
    "task": "9355d5ed41e384ff345b014b6cb1c6e748594aea5b",
}

INCIDENT_FIELD_DICT = {
    "service": {
        "displayName": "Service",
        "name": "Service",
        "field_id": "936725cd10c735d1dd8c5b4cd4969cb0bd833655f4"
    },
    "category": {
        "displayName": "Category",
        "name": "Category",
        "field_id": "9e0b434034e94781ab29598150f388aa"
    },
    "subcategory": {
        "displayName": "Subcategory",
        "name": "Subcategory",
        "field_id": "1163fda7e6a44f40bb94d2b47cc58f46"
    },
    "description": {
        "displayName": "Description",
        "name": "Description",
        "field_id": "252b836fc72c4149915053ca1131d138"
    },
    "priority": {
        "displayName": "Priority",
        "name": "Priority",
        "field_id": "83c36313e97b4e6b9028aff3b401b71c"
    },
    "customer_display_name": {
        "displayName": "Customer Display Name",
        "name": "CustomerDisplayName",
        "field_id": "93734aaff77b19d1fcfd1d4b4aba1b0af895f25788"
    },
    "owned_by": {
        "displayName": "Owned By",
        "name": "OwnedBy",
        "field_id": "9339fc404e4c93350bf5be446fb13d693b0bb7f219"
    },
    "owned_by_team": {
        "displayName": "Owned By Team",
        "name": "OwnedByTeam",
        "field_id": "9339fc404e8d5299b7a7c64de79ab81a1c1ff4306c"
    },
    'source': {
        "displayName": "Source",
        "field_id": "93670bdf8abe2cd1f92b1f490a90c7b7d684222e13",
        "name": "Source"
    },
    'form_view': {
        "displayName": "Form View",
        "field_id": "9416983037b2b2cded624d4168964b5f0fce05d285",
        "name": "FormView"
    },
    'short_description': {
        "displayName": "Short Description",
        "field_id": "93e8ea93ff67fd95118255419690a50ef2d56f910c",
        "name": "ShortDescription"
    },
    'status': {
        "displayName": "Status",
        "field_id": "5eb3234ae1344c64a19819eda437f18d",
        "name": "Status"
    },
    'restaurant_number': {
        "displayName": "Restaurant Number",
        "field_id": "9413aa138a4d8ec546418249499b66c9aa948eb522",
        "name": "RestaurantNumber"
    }
}

TASK_FIELD_DICT = {
    'title': {
        "displayName": "Title",
        "field_id": "93ad98a2d68a61778eda3d4d9cbb30acbfd458aea4",
        "name": "Title"
    },
    'owned_by': {
        "displayName": "Owned By",
        "field_id": "93cfd5a4e13f7d4a4de1914f638abebee3a982bb50",
        "name": "OwnedBy"
    },
    'status': {
        "displayName": "Status",
        "field_id": "9368f0fb7b744108a666984c21afc932562eb7dc16",
        "name": "Status"
    },
    "description": {
        "displayName": "Description",
        "name": "Description",
        "field_id": "9355d5ef648edf7a8ed5604d56af11170cce5dc25e"
    },
    'owned_by_team': {
        "displayName": "Owned By Team",
        "field_id": "93cfd5a4e10af4933a573444d08cbc412da491b42e",
        "name": "OwnedByTeam"
    },
    'type': {
        "field_id": "9355d5ed6ca15a8308c5e24389b2138b3aa9b6c7fa",
        "name": "Type",
        "displayName": "Type"
    },
    'vendor_record': {
        "field_id": "942c29e6afe42dcbceaf024539b61a843e6d9d3599",
        "name": "VendorRecord",
        "displayName": "Vendor Record"
    }
}

INCIDENT_HEADERS_NAMES = [
    "IncidentPublicID",
    "IncidentRecordID",
    "Status",
    "CustomerDisplayName",
    "Description",
    "OwnedBy",
    "OwnedByTeam",
    "TotalTasks",
    "CreatedDateTime",
    "SLAResolveByDeadline"
]

TASK_HEADERS_NAMES = [
    "TaskPublicID",
    "TaskRecordID",
    "ParentPublicID",
    "ParentTypeName",
    "Status",
    "CustomerDisplayName",
    "Description",
    "OwnedBy",
    "OwnedByTeam",
    "TotalTasks",
    "CreatedDateTime",
    "SLAResolveByDeadline",
    "VendorRecord"
]
# disable-secrets-detection-start
HEADERS_IDS = {
    'incident': [
        "6ae282c55e8e4266ae66ffc070c17fa3",  # Incident ID
        "936725cd10c735d1dd8c5b4cd4969cb0bd833655f4",  # Service
        "9e0b434034e94781ab29598150f388aa",  # Category
        "1163fda7e6a44f40bb94d2b47cc58f46",  # Subcategory
        "252b836fc72c4149915053ca1131d138",  # Description[
        "83c36313e97b4e6b9028aff3b401b71c",  # Priority
        "93734aaff77b19d1fcfd1d4b4aba1b0af895f25788",  # Customer Display Name
        "9339fc404e4c93350bf5be446fb13d693b0bb7f219",  # OwnedBy
        "9339fc404e8d5299b7a7c64de79ab81a1c1ff4306c",  # Owned By Team
        "93670bdf8abe2cd1f92b1f490a90c7b7d684222e13",  # Source
        "9416983037b2b2cded624d4168964b5f0fce05d285",  # FormView
        "93e8ea93ff67fd95118255419690a50ef2d56f910c",  # Short Description
        "c1e86f31eb2c4c5f8e8615a5189e9b19",  # Created Date Time
        "5eb3234ae1344c64a19819eda437f18d"  # Status
    ],
    'task': [
        "BO:9355d5ed41e384ff345b014b6cb1c6e748594aea5b,FI:93ad98a2d68a61778eda3d4d9cbb30acbfd458aea4",
        # Title  disable-secrets-detection
        "BO:9355d5ed41e384ff345b014b6cb1c6e748594aea5b,FI:93cfd5a4e13f7d4a4de1914f638abebee3a982bb50",
        # Owned  disable-secrets-detection
        "BO:9355d5ed41e384ff345b014b6cb1c6e748594aea5b,FI:9368f0fb7b744108a666984c21afc932562eb7dc16",
        # Status  disable-secrets-detection
        "BO:9355d5ed41e384ff345b014b6cb1c6e748594aea5b,FI:9355d5ef648edf7a8ed5604d56af11170cce5dc25e",
        # Description  disable-secrets-detection
        "BO:9355d5ed41e384ff345b014b6cb1c6e748594aea5b,FI:93cfd5a4e10af4933a573444d08cbc412da491b42e",
        # Owned  disable-secrets-detection
        "BO:9355d5ed41e384ff345b014b6cb1c6e748594aea5b,FI:9355d5ed6ca15a8308c5e24389b2138b3aa9b6c7fa",
        # Type  disable-secrets-detection
        "BO:9355d5ed41e384ff345b014b6cb1c6e748594aea5b,FI:942c29e6afe42dcbceaf024539b61a843e6d9d3599"
        # Vendor  disable-secrets-detection
    ]
}

# disable-secrets-detection-end

RELATIONSHIP_IDS = {
    "incident_owns_task": "9369187528b417b4a17aaa4646b7f7a78b3c821be9"
}

#######################################################################################################################


''' HELPER FUNCTIONS '''


def parse_response(response, error_operation):
    try:
        response.raise_for_status()
        if not response.content:
            return
        return response.json()
    except requests.exceptions.HTTPError:
        try:
            res_json = response.json()
            err_msg = res_json.get('errorMessage') or res_json.get('error_description') or res_json.get('Message')
        except Exception:
            err_msg = response.content.decode('utf-8')
        return_error(error_operation + ": " + err_msg)
    except Exception:
        try:
            return response.content  # check if needed
        except Exception as error:
            LOG.print_log()
            return_error(f'Could not parse response {error}')


def cherwell_dict_parser(key, value, item_list):
    new_dict = {}
    for item in item_list:
        field_key = item.get(key)
        new_dict[field_key] = item.get(value)

    return new_dict


def parse_fields_from_business_object(field_list):
    new_business_obj = cherwell_dict_parser('name', 'value', field_list)

    return new_business_obj


def parse_fields_from_business_object_list(response):
    object_list = []
    if not response.get('businessObjects'):
        return []
    for business_obj in response.get('businessObjects'):
        new_business_obj = parse_fields_from_business_object(business_obj.get('fields'))
        new_business_obj['BusinessObjectID'] = business_obj.get('busObId')
        new_business_obj['PublicID'] = business_obj.get('busObPublicId')
        new_business_obj['RecordID'] = business_obj.get('busObRecId')
        object_list.append(new_business_obj)

    return object_list


def build_fields_for_business_object(data_dict, ids_dict):
    fields = []
    for key, value in data_dict.items():
        new_field = {
            "dirty": "true",
            "fieldId": ids_dict.get(key),
            "name": key,
            "value": value
        }
        fields.append(new_field)
    return fields


def http_request(method, url, payload, token=None, custom_headers=None):
    headers = build_headers(token, custom_headers)
    response = requests.request(method, url, data=payload, headers=headers)
    return response


def request_new_access_token(using_refresh):
    url = BASE_URL + "token"
    refresh_token = demisto.getIntegrationContext().get('refresh_token')

    payload = f'client_id={CLIENT_ID}'
    payload = payload + f'&grant_type=refresh_token&refresh_token={refresh_token}' if using_refresh \
        else payload + f'&grant_type=password&username={USERNAME}&password={PASSWORD}'

    headers = {
        'Accept': "application/json",
        'Content-Type': "application/x-www-form-urlencoded",
    }

    response = http_request('POST', url, payload, custom_headers=headers)
    return response


def get_new_access_token():
    response = request_new_access_token(True)
    if not response.status_code == HTTP_CODES['success']:
        response = request_new_access_token(False)
    res_json = parse_response(response, "Could not get token")
    demisto.setIntegrationContext({
        'refresh_token': res_json.get('refresh_token'),
        'token_expiration_time': int(date_to_timestamp(res_json.get('.expires'), '%a, %d %b %Y %H:%M:%S GMT')),
        'access_token': res_json.get('access_token')
    })
    return res_json.get('access_token')


def get_access_token(new_token):
    integration_context = demisto.getIntegrationContext()
    token_expiration_time = integration_context.get('token_expiration_time')
    current_time = date_to_timestamp(datetime.utcnow())
    if new_token or not token_expiration_time or token_expiration_time < current_time:
        token = get_new_access_token()
        return token
    else:
        return integration_context.get('access_token')


def build_headers(token, headers=None):
    headers = headers if headers else HEADERS
    headers['Authorization'] = f'Bearer {token}'
    return headers


def make_request(method, url, payload=None, headers=None):
    token = get_access_token(False)
    response = http_request(method, url, payload, token, custom_headers=headers)
    if response.status_code == HTTP_CODES['unauthorized']:
        token = get_access_token(True)
        response = http_request(method, url, payload, token, custom_headers=headers)
    return response


def get_business_object_summary_by_name(name):
    url = BASE_URL + f'api/V1/getbusinessobjectsummary/busobname/{name}'
    response = make_request('GET', url)
    res_json = parse_response(response, "Could not get business object summary")
    return res_json


def resolve_business_object_id_by_name(name):
    res = get_business_object_summary_by_name(name)
    if not res:
        return_error(f'Could not retrieve "{name}" business object id. '
                     f'Make sure "{name}" is a valid business object.')
    return res[0].get('busObId')


def save_business_object(payload):
    url = BASE_URL + "api/V1/savebusinessobject"
    response = make_request("POST", url, json.dumps(payload))
    res_json = parse_response(response, "Could not save business object")
    return res_json


def get_business_object_record(business_object_id, object_id, id_type):
    id_type_str = 'publicid' if id_type == 'public_id' else 'busobrecid'
    url = BASE_URL + f'api/V1/getbusinessobject/busobid/{business_object_id}/{id_type_str}/{object_id}'
    response = make_request("GET", url)
    res_json = parse_response(response, "Could not get business objects")
    return res_json


def delete_business_object_record(business_object_id, object_id, id_type):
    id_type_str = 'publicid' if id_type == 'public_id' else 'busobrecid'
    url = BASE_URL + f'api/V1/deletebusinessobject/busobid/{business_object_id}/{id_type_str}/{object_id}'
    response = make_request("DELETE", url)
    res_json = parse_response(response, "Could not delete business object")
    return res_json


def get_search_results(payload):
    url = BASE_URL + "api/V1/getsearchresults"
    response = make_request("POST", url, json.dumps(payload))
    res_json = parse_response(response, "Could not search for business objects")
    return res_json


def get_business_object_template(business_object_id, include_all=True, field_names=None, fields_ids=None):
    url = BASE_URL + "api/V1/getbusinessobjecttemplate"
    payload = {
        "busObId": business_object_id,
        "includeAll": include_all
    }

    if field_names:
        payload['fieldNames'] = field_names
    if fields_ids:
        payload['fieldIds'] = fields_ids
    response = make_request("POST", url, json.dumps(payload))
    res_json = parse_response(response, "Could not get business object template")
    return res_json


def build_business_object_json(simple_json, business_object_id, object_id=None, id_type=None):
    business_object_ids_dict = get_key_value_dict_from_template('name', 'fieldId', business_object_id)
    fields_for_business_object = build_fields_for_business_object(simple_json, business_object_ids_dict)
    business_object_json = {
        'busObId': business_object_id,
        "fields": fields_for_business_object
    }
    if object_id:
        id_key = 'busObPublicId' if id_type == 'public_id' else 'busObRecId'
        business_object_json[id_key] = object_id
    return business_object_json


def create_business_object(name, data_json):
    business_object_id = resolve_business_object_id_by_name(name)
    business_object_json = build_business_object_json(data_json, business_object_id)
    result = save_business_object(business_object_json)
    return result


def update_business_object(name, data_json, object_id, id_type):
    business_object_id = resolve_business_object_id_by_name(name)
    business_object_json = build_business_object_json(data_json, business_object_id, object_id, id_type)
    result = save_business_object(business_object_json)
    return result


def get_business_object(name, object_id, id_type):
    business_object_id = resolve_business_object_id_by_name(name)
    results = get_business_object_record(business_object_id, object_id, id_type)
    parsed_business_object = parse_fields_from_business_object(results.get('fields'))
    parsed_business_object['PublicID'] = results.get('busObPublicId')
    parsed_business_object['RecordID'] = results.get('busObRecId')
    return parsed_business_object, results


def delete_business_object(name, object_id, id_type):
    business_object_id = resolve_business_object_id_by_name(name)
    results = delete_business_object_record(business_object_id, object_id, id_type)
    return results


def download_attachment_from_business_object(attachment):
    attachment_id = attachment.get('attachmentId')
    business_object_id = attachment.get('busObId')
    business_record_id = attachment.get('busObRecId')
    url = BASE_URL + f'api/V1/getbusinessobjectattachment' \
        f'/attachmentid/{attachment_id}/busobid/{business_object_id}/busobrecid/{business_record_id}'
    response = make_request('GET', url)
    attachment_content = parse_response(response, f'Unable to get content of attachment {attachment_id}')
    return attachment_content


def get_attachments_content(attachments_to_download):
    attachments = []
    for attachment in attachments_to_download:
        new_attachment = {
            'FileName': attachment.get('displayText'),
            'CreatedAt': attachment.get('created'),
            'Content': download_attachment_from_business_object(attachment)
        }
        attachments.append(new_attachment)
    return attachments


def get_attachments_details(id_type, object_id, object_type_name, object_type_id, type, attachment_type):
    id_type_str = 'publicid' if id_type == 'public_id' else 'busobrecid'
    businees_object_type_str = 'busobid' if object_type_id else 'busobname'
    object_type = object_type_id if object_type_id else object_type_name
    url = BASE_URL + f'api/V1/getbusinessobjectattachments/' \
        f'{businees_object_type_str}/{object_type}/' \
        f'{id_type_str}/{object_id}' \
        f'/type/{type}' \
        f'/attachmenttype/{attachment_type}'
    response = make_request('GET', url)
    parsed_response = parse_response(response, f'Unable to get attachments for {object_type} {object_id}')
    return parsed_response


def download_attachments(id_type, object_id, business_object_type_name=None, business_object_type_id=None):
    type = 'File'
    attachment_type = 'Imported'
    result = get_attachments_details(id_type, object_id, business_object_type_name, business_object_type_id, type,
                                     attachment_type)
    attachments_to_download = result.get('attachments')
    if not attachments_to_download:
        return
    attachments_to_return = get_attachments_content(attachments_to_download)
    return attachments_to_return


def get_attachments_info(id_type, object_id, business_object_type_name=None, business_object_type_id=None):
    type = 'File'
    attachment_type = 'Imported'
    result = get_attachments_details(id_type, object_id, business_object_type_name, business_object_type_id, type,
                                     attachment_type)
    attachments = result.get('attachments')
    attachments_info = [{
        'AttachmentFieldID': attachment.get('attachmentFileId'),
        'FileName': attachment.get('displayText'),
        'AttachmentID': attachment.get('attachmentId'),
    } for attachment in attachments]
    return attachments_info, result


def attachment_results(attachments):
    for attachment in attachments:
        attachment_content = attachment.get('Content')
        attachment_name = attachment.get('FileName')
        demisto.results(fileResult(attachment_name, attachment_content))
    return


def run_query_on_business_objects(bus_id, filter_query, max_results):
    payload = {
        'busObId': bus_id,
        'includeAllFields': True,
        'filters': filter_query
    }
    if max_results:
        payload['pageSize']: max_results
    return get_search_results(payload)


def get_key_value_dict_from_template(key, val, business_object_id):
    template_dict = get_business_object_template(business_object_id)
    business_object_ids_dict = cherwell_dict_parser(key, val, template_dict.get('fields'))
    return business_object_ids_dict


def get_all_incidents(objects_names, last_created_time, max_result, query_string):
    all_incidents = []
    for business_object_name in objects_names:
        business_object_id = resolve_business_object_id_by_name(business_object_name)
        query_list = [['CreatedDateTime', 'gt', last_created_time]]
        if query_string:
            additional_query_list = validate_query_for_fetch_incidents(objects_names, query_string)
            query_list += additional_query_list
        incidents, _ = query_business_object(query_list, business_object_id, max_result)
        all_incidents += incidents
    sorted_incidents = sorted(all_incidents, key=lambda incident: incident.get('CreatedDateTime'))
    return sorted_incidents[:max_result]


def object_to_incident(obj):
    attachments_list = []
    attachments = obj.get('Attachments')
    obj.pop('Attachments')
    if attachments:
        for attachment in attachments:
            file_name = attachment.get('FileName')
            attachment_file = fileResult(file_name, attachment.get('Content'))
            attachments_list.append({
                'path': attachment_file.get('FileID'),
                'name': file_name
            })
    item = {
        'name': f'Record ID:{obj.get("RecID")}',
        'attachment': attachments_list,
        'rawJSON': json.dumps(obj)
    }

    return createContext(item, removeNull=True)


def save_incidents(objects_to_save):
    final_incidents = []
    for obj in objects_to_save:
        final_incidents.append(object_to_incident(obj))
    demisto.incidents(final_incidents)
    return


def fetch_incidents_attachments(incidents):
    for incident in incidents:
        rec_id = incident.get('RecID')
        business_object_id = incident.get('BusinessObjectID')
        incident['Attachments'] = []
        attachments = download_attachments('record_id', rec_id, business_object_type_id=business_object_id)
        if attachments:
            for attachment in attachments:
                new_attachment_obj = {
                    'Content': attachment.get('Content'),
                    'FileName': attachment.get('FileName')
                }
                incident['Attachments'].append(new_attachment_obj)
    return incidents


def fetch_incidents(objects_names, last_created_time, max_result, query_string, fetch_attachments):
    incidents = get_all_incidents(objects_names, last_created_time, max_result, query_string)
    if fetch_attachments:
        incidents = fetch_incidents_attachments(incidents)
    save_incidents(incidents)
    return incidents


def upload_business_object_attachment(file_name, file_size, file_content, object_type_name, id_type, object_id, ):
    id_type_str = 'publicid' if id_type == 'public_id' else 'busobrecid'
    url = BASE_URL + f'/api/V1/uploadbusinessobjectattachment/' \
        f'filename/{file_name}/busobname/{object_type_name}/{id_type_str}/{object_id}/offset/0/totalsize/{file_size}'
    payload = file_content
    headers = HEADERS
    headers['Content-Type'] = "application/octet-stream"
    response = make_request('POST', url, payload, headers)
    parsed_response = parse_response(response, f'Could not upload attachment {file_name}')
    return parsed_response


def upload_attachment(id_type, object_id, type_name, file_entry_id):
    file_data = demisto.getFilePath(file_entry_id)
    file_path = file_data.get('path')
    file_name = file_data.get('name')
    try:
        file_size = os.path.getsize(file_path)
        with open(file_path) as f:
            file_content = f.read()
        attachment_id = upload_business_object_attachment(file_name, file_size, file_content, type_name, id_type,
                                                          object_id)
        return attachment_id
    except Exception as err:
        return_error(f'unable to open file: {err}')


def remove_attachment(id_type, object_id, type_name, attachment_id):
    id_type_str = 'publicid' if id_type == 'public_id' else 'busobrecid'
    url = BASE_URL + f'/api/V1/removebusinessobjectattachment/' \
        f'attachmentid/{attachment_id}/busobname/{type_name}/{id_type_str}/{object_id}'
    response = make_request('DELETE', url)
    parse_response(response, f'Could not remove attachment {attachment_id} from {type_name} {object_id}')
    return


def link_related_business_objects(action, parent_business_object_id, parent_business_object_record_id, relationship_id,
                                  business_object_id, business_object_record_id):
    url_action_str = 'linkrelatedbusinessobject' if action == 'link' else 'unlinkrelatedbusinessobject'
    url = BASE_URL + f"api/V1/{url_action_str}/parentbusobid/{parent_business_object_id}" \
        f"/parentbusobrecid/{parent_business_object_record_id}" \
        f"/relationshipid/{relationship_id}" \
        f"/busobid/{business_object_id}" \
        f"/busobrecid/{business_object_record_id}"
    http_method = 'GET' if action == 'link' else 'DELETE'
    response = make_request(http_method, url)
    parse_response(response, "Could not link business objects")
    return


def business_objects_relation_action(action, parent_type_name, parent_record_id, child_type_name, child_record_id,
                                     relationship_id):
    parent_business_object_id = resolve_business_object_id_by_name(parent_type_name)
    child_business_object_id = resolve_business_object_id_by_name(child_type_name)
    link_related_business_objects(action, parent_business_object_id, parent_record_id, relationship_id,
                                  child_business_object_id, child_record_id)
    return


def validate_query_list(query_list):
    for query in query_list:
        if not len(query) == 3:
            return_error('Cannot parse query, should be of the form: `field:operator:value`')
        if query[1] not in QUERY_OPERATORS:
            return_error(
                f'Operator should be one of the following: {", ".join(QUERY_OPERATORS)}. Received: {query[1]}')
    return


def validate_query_for_fetch_incidents(objects_names, query_string):
    if not objects_names:
        return_error(f'No business object name was given. \n'
                     f'In order to run advanced query, fill the integration'
                     f' parameter-`Objects to fetch` with exactly one business object name.')
    if len(objects_names) > 1:
        return_error(f'Advanced query operation is supported for a single business object. '
                     f'{len(objects_names)} objects were given: {",".join(objects_names)}')
    query_list = parse_string_query_to_list(query_string)
    return query_list


def build_query_dict(query, filed_ids_dict):
    field_name = query[0]
    operator = query[1]
    value = query[2]
    field_id = filed_ids_dict.get(field_name)
    if not field_id:
        demisto.results(f'Field name: {field_name} does not exit in the given business objects')
    return {
        'fieldId': filed_ids_dict.get(field_name),
        'operator': operator,
        'value': value
    }


def build_query_dict_list(query_list, filed_ids_dict):
    query_dict_list = []
    for query in query_list:
        query_dict = build_query_dict(query, filed_ids_dict)
        query_dict_list.append(query_dict)
    return query_dict_list


def query_business_object(query_list, business_object_id, max_results):
    filed_ids_dict = get_key_value_dict_from_template('name', 'fieldId', business_object_id)
    filters = build_query_dict_list(query_list, filed_ids_dict)
    query_result = run_query_on_business_objects(business_object_id, filters, max_results)
    business_objects = parse_fields_from_business_object_list(query_result)
    return business_objects, query_result


def parse_string_query_to_list(query_string):
    query_list = query_string.split(',')
    query_filters_list = [query_filter.split('::') for query_filter in query_list]
    validate_query_list(query_filters_list)
    return query_filters_list


def query_business_object_string(business_object_name, query_string, max_results):
    if max_results:
        try:
            int(max_results)
        except Exception:
            return return_error(f'`max_results` argument received is not a number')
    business_object_id = resolve_business_object_id_by_name(business_object_name)
    query_filters_list = parse_string_query_to_list(query_string)
    return query_business_object(query_filters_list, business_object_id, max_results)


def get_field_info(type, field_property):
    business_object_id = resolve_business_object_id_by_name(type)
    template = get_business_object_template(business_object_id)
    business_object_fields = template.get('fields')
    field_to_return = None
    for field in business_object_fields:
        if field.get('displayName') == field_property or \
                field.get('fieldId') == field_property or \
                field.get('name') == field_property:
            field_to_return = field
    if field_to_return:
        field_to_return = {
            'DisplayName': field_to_return.get('displayName'),
            'Name': field_to_return.get('name'),
            'FieldID': field_to_return.get('fieldId')
        }
    else:
        return_error(f'Field with the value {field_property} was not found')
    return field_to_return


########################################################################################################################
def test_command():
    if FETCHES_INCIDENTS:
        if not OBJECTS_TO_FETCH[0]:
            return_error('No objects to fetch were given')
        for object_name in OBJECTS_TO_FETCH:
            resolve_business_object_id_by_name(object_name)
        if QUERY_STRING:
            validate_query_for_fetch_incidents(OBJECTS_TO_FETCH, QUERY_STRING)
    else:
        get_access_token(True)
    return


def create_business_object_command():
    args = demisto.args()
    type_name = args.get('type')
    data_json = json.loads(args.get('json'))
    result = create_business_object(type_name, data_json)
    ids = {
        'PublicID': result.get('busObPublicId'),
        'RecordID': result.get('busObRecId')
    }
    md = tableToMarkdown(f'New {type_name.capitalize()} was created', ids, headerTransform=pascalToSpace)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'HumanReadable': md,
        'EntryContext': {
            'Cherwell.BusinessObjects(val.RecordID == obj.RecordID)': ids
        }
    })


def update_business_object_command():
    args = demisto.args()
    type_name = args.get('type')
    data_json = json.loads(args.get('json'))
    object_id = args.get('id_value')
    id_type = args.get('id_type')
    result = update_business_object(type_name, data_json, object_id, id_type)
    ids = {
        'PublicID': result.get('busObPublicId'),
        'RecordID': result.get('busObRecId')
    }
    md = tableToMarkdown(f'{type_name.capitalize()} {object_id} was updated', ids, headerTransform=pascalToSpace)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'HumanReadable': md,
        'EntryContext': {
            'Cherwell.BusinessObjects(val.RecordID == obj.RecordID)': ids
        }
    })


def get_business_object_command():
    args = demisto.args()
    type_name = args.get('type')
    id_type = args.get('id_type')
    object_id = args.get('id_value')
    business_object, results = get_business_object(type_name, object_id, id_type)
    md = tableToMarkdown(f'{type_name.capitalize()}: {object_id}', business_object,
                         headerTransform=pascalToSpace)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': results,
        'HumanReadable': md,
        'EntryContext': {
            'Cherwell.BusinessObjects(val.RecordID == obj.RecordID)': createContext(business_object)
        }
    })


def delete_business_object_command():
    args = demisto.args()
    type_name = args.get('type')
    id_type = args.get('id_type')
    object_id = args.get('id_value')
    results = delete_business_object(type_name, object_id, id_type)
    md = f'### Record {object_id} of type {type_name} was deleted.'

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': results,
        'HumanReadable': md
    })


def fetch_incidents_command():
    last_run = demisto.getLastRun()
    objects_names_to_fetch = OBJECTS_TO_FETCH if OBJECTS_TO_FETCH[0] else ['incidents']
    fetch_attachments = FETCH_ATTACHMENTS
    max_result = int(MAX_RESULT) if MAX_RESULT else 30
    fetch_time = FETCH_TIME if FETCH_TIME else '3 days'
    query_string = QUERY_STRING
    if 'last_created_time' in last_run:
        last_created_time = last_run.get('last_created_time')
    else:
        last_created_time, _ = parse_date_range(fetch_time, date_format=DATE_FORMAT, to_timestamp=False)
    incidents = fetch_incidents(objects_names_to_fetch, last_created_time, max_result, query_string, fetch_attachments)
    if incidents:
        last_incident_created_time = incidents[-1].get('CreatedDateTime')
        next_created_time_to_fetch = \
            (datetime.strptime(last_incident_created_time, DATE_FORMAT) + timedelta(seconds=1)).strftime(DATE_FORMAT)
        demisto.setLastRun({'last_created_time': next_created_time_to_fetch})
    return


def download_attachments_command():
    args = demisto.args()
    id_type = args.get('id_type')
    object_id = args.get('id_value')
    type_name = args.get('type')
    attachments = download_attachments(id_type, object_id, business_object_type_name=type_name)
    if not attachments:
        return_error(f'No attachments were found for {type_name}:{object_id}')
    attachment_results(attachments)
    return


def upload_attachment_command():
    args = demisto.args()
    id_type = args.get('id_type')
    object_id = args.get('id_value')
    type_name = args.get('type')
    file_entry_id = args.get('file_entry_id')
    attachment_id = upload_attachment(id_type, object_id, type_name, file_entry_id)
    entry_context = {
        'AttachmentFileID': attachment_id,
        'BusinessObjectType': type_name,
        string_to_context_key(id_type): object_id
    }
    md = f'### Attachment: {attachment_id}, was successfully attached to {type_name} {object_id}'
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': {'attachment_id': attachment_id},
        'EntryContext': {'Cherwell.UploadedAttachments(val.AttachmentID == obj.AttachmentID)': entry_context},
        'HumanReadable': md,
    })


def remove_attachment_command():
    args = demisto.args()
    id_type = args.get('id_type')
    object_id = args.get('id_value')
    type_name = args.get('type')
    attachment_id = args.get('attachment_id')
    remove_attachment(id_type, object_id, type_name, attachment_id)
    md = f'### Attachment: {attachment_id}, was successfully removed from {type_name} {object_id}'
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': md,
        'HumanReadable': md,
    })


def get_attachments_info_command():
    args = demisto.args()
    id_type = args.get('id_type')
    object_id = args.get('id_value')
    type_name = args.get('type')
    attachments_info, raw_result = get_attachments_info(id_type, object_id, type_name)
    md = tableToMarkdown(f'{type_name.capitalize()} {object_id} attachments:', attachments_info,
                         headerTransform=pascalToSpace) if attachments_info \
        else f'### {type_name.capitalize()} {object_id} has no attachments'

    entry = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': raw_result,
        'HumanReadable': md
    }
    if attachments_info:
        entry['EntryContext'] = {
            f'Cherwell.AttachmentsInfo.{string_to_context_key(type_name)}{object_id}': attachments_info}
    demisto.results(entry)


def link_business_objects_command():
    args = demisto.args()
    parent_type = args.get('parent_type')
    parent_record_id = args.get('parent_record_id')
    child_type = args.get('child_type')
    child_record_id = args.get('child_record_id')
    relationship_id = args.get('relationship_id')
    business_objects_relation_action('link', parent_type, parent_record_id, child_type, child_record_id,
                                     relationship_id)
    message = \
        f'{parent_type.capitalize()} {parent_record_id} and {child_type.capitalize()} {child_record_id} were linked'
    md = f'### {message}'
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': message,
        'HumanReadable': md,
    })


def unlink_business_objects_command():
    args = demisto.args()
    parent_type = args.get('parent_type')
    parent_record_id = args.get('parent_record_id')
    child_type = args.get('child_type')
    child_record_id = args.get('child_record_id')
    relationship_id = args.get('relationship_id')
    business_objects_relation_action('unlink', parent_type, parent_record_id, child_type, child_record_id,
                                     relationship_id)
    message = \
        f'{parent_type.capitalize()} {parent_record_id} and {child_type.capitalize()} {child_record_id} were unlinked'
    md = f'### {message}'
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': message,
        'HumanReadable': md,
    })


def query_business_object_command():
    args = demisto.args()
    type_name = args.get('type')
    query_string = args.get('query')
    max_results = args.get('max_results')
    results, raw_response = query_business_object_string(type_name, query_string, max_results)
    md = tableToMarkdown('Query Results', results, headerTransform=pascalToSpace)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': raw_response,
        'EntryContext': {'Cherwell.QueryResults': results},
        'HumanReadable': md,
    })


def get_field_info_command():
    args = demisto.args()
    type_name = args.get('type')
    field_property = args.get('field_property')
    results = get_field_info(type_name, field_property)
    md = tableToMarkdown('Field info:', results, headerTransform=pascalToSpace)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': results,
        'EntryContext': {'Cherwell.FieldInfo(val.FieldID == obj.FieldID)': results},
        'HumanReadable': md,
    })


# def update_incident_status():
#     args = demisto.args()
#     incident_public_id = args.get('incident_public_id')
#     status = args.get('status')
#     args.pop('incident_public_id')
#
#     payload = {
#         "busObId": BUSINESS_OBJECT_IDS['incident'],
#         "busObPublicId": incident_public_id,
#         "fields": build_fields_for_business_object(args, INCIDENT_FIELD_DICT)
#     }
#
#     results = save_business_object(payload)
#
#     md = "### Incident: {0} new status is: {1}".format(incident_public_id, status)
#     demisto.results({
#         'Type': entryTypes['note'],
#         'ContentsFormat': formats['json'],
#         'Contents': results,
#         'HumanReadable': md,
#         'EntryContext': {
#             'Cherwell.Incidents(val.IncidentID == {0}).Status'.format(incident_public_id): status
#         }
#     })


# def list_incidents():
#     payload = {
#         "busObId": BUSINESS_OBJECT_IDS['incident'],
#         "pageNumber": 0,
#         "pageSize": 300,
#         "fields": HEADERS_IDS['incident']
#     }
#
#     results = get_search_results(payload)
#     incidents = parse_fields_from_business_object_list(results)
#     md = tableToMarkdown('Incidents List', incidents, headers=INCIDENT_HEADERS_NAMES, removeNull=True,
#                          headerTransform=pascalToSpace)
#
#     demisto.results({
#         'Type': entryTypes['note'],
#         'ContentsFormat': formats['json'],
#         'Contents': results,
#         'HumanReadable': md,
#         'EntryContext': {
#             'Cherwell.Incidents': incidents
#         }
#     })


# def get_task_command():
#     args = demisto.args()
#     task_id = args.get('task_id')
#     id_type = args.get('id_type')
#     results = get_business_object(BUSINESS_OBJECT_IDS["task"], task_id, id_type)
#     task = parse_fields_from_business_object(results.get('fields'))
#     task['TaskPublicID'] = results.get('busObPublicId')
#     task['TaskRecordID'] = results.get('busObRecId')
#     md = tableToMarkdown('Task Number: {}'.format(task_id), task, headers=TASK_HEADERS_NAMES, removeNull=True,
#                          headerTransform=pascalToSpace)
#
#     demisto.results({
#         'Type': entryTypes['note'],
#         'ContentsFormat': formats['json'],
#         'Contents': results,
#         'HumanReadable': md,
#         'EntryContext': {
#             'Cherwell.Tasks(val.TaskPublicID == obj.TaskPublicID)': createContext(task, removeNull=True)
#         }
#     })


# def create_task():
#     args = demisto.args()
#     payload = {
#         "busObId": BUSINESS_OBJECT_IDS['task'],
#         "fields": build_fields_for_business_object(args, TASK_FIELD_DICT)
#     }
#     response = save_business_object(payload)
#     return response


# def create_task_command():
#     args = demisto.args()
#     parent_business_object_record_id = args.get('incident_record_id')
#     args.pop('incident_record_id')
#     result = create_task()
#     link_related_business_objects(BUSINESS_OBJECT_IDS['incident'], parent_business_object_record_id,
#                                   RELATIONSHIP_IDS['incident_owns_task'], BUSINESS_OBJECT_IDS['task'],
#                                   result.get('busObRecId'))
#
#     ids = {
#         'TaskPublicID': result.get('busObPublicId'),
#         'TaskRecordID': result.get('busObRecId'),
#         'IncidentRecordID': parent_business_object_record_id
#     }
#     md = tableToMarkdown('New Task was created', ids, headerTransform=pascalToSpace)
#
#     demisto.results({
#         'Type': entryTypes['note'],
#         'ContentsFormat': formats['json'],
#         'Contents': result,
#         'HumanReadable': md,
#         'EntryContext': {
#             'Cherwell.Tasks(val.TaskPublicID == obj.TaskPublicID)': ids
#         }
#     })


# def update_task_command():
#     demisto.results(update_task())


# def update_task():
#     args = demisto.args()
#     task_public_id = args.get('task_public_id')
#     args.pop('task_public_id')
#
#     payload = {
#         "busObId": BUSINESS_OBJECT_IDS['task'],
#         "busObPublicId": task_public_id,
#         "fields": build_fields_for_business_object(args, TASK_FIELD_DICT)
#     }
#
#     results = save_business_object(payload)
#     md = "### Task: {} was updated".format(task_public_id)
#     return ({
#         'Type': entryTypes['note'],
#         'ContentsFormat': formats['json'],
#         'Contents': results,
#         'HumanReadable': md
#     })
#
#
# def search_in_business_object_command():
#     results = search_in_business_object()
#     parsed_results = parse_fields_from_business_object_list(results)
#     md = tableToMarkdown('Search Results', parsed_results, removeNull=True, headerTransform=pascalToSpace)
#
#     demisto.results({
#         'Type': entryTypes['note'],
#         'ContentsFormat': formats['json'],
#         'Contents': results,
#         'HumanReadable': md,
#         'EntryContext': {
#             'Cherwell.Search': createContext(parsed_results, removeNull=True)
#         }
#     })
#

#######################################################################################################################


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    handle_proxy()
    if demisto.command() == 'test-module':
        test_command()
        demisto.results('ok')

    elif demisto.command() == 'fetch-incidents':
        fetch_incidents_command()

    elif demisto.command() == 'cherwell-create-business-object':
        create_business_object_command()

    elif demisto.command() == 'cherwell-update-business-object':
        update_business_object_command()

    elif demisto.command() == 'cherwell-get-business-object':
        get_business_object_command()

    elif demisto.command() == 'cherwell-delete-business-object':
        delete_business_object_command()

    elif demisto.command() == 'cherwell-download-attachments':
        download_attachments_command()

    elif demisto.command() == 'cherwell-get-attachments-info':
        get_attachments_info_command()

    elif demisto.command() == 'cherwell-upload-attachment':
        upload_attachment_command()

    elif demisto.command() == 'cherwell-remove-attachment':
        remove_attachment_command()

    elif demisto.command() == 'cherwell-link-business-objects':
        link_business_objects_command()

    elif demisto.command() == 'cherwell-unlink-business-objects':
        unlink_business_objects_command()

    elif demisto.command() == 'cherwell-query-business-object':
        query_business_object_command()

    elif demisto.command() == 'cherwell-get-field-info':
        get_field_info_command()


# Log exceptions
except Exception as e:
    LOG(str(e))
    LOG.print_log()
    return_error(f"Unexpected error: {e}, traceback: {traceback.print_exc()}")
