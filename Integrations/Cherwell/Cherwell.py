import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

USERNAME = demisto.params().get('credentials').get('identifier')
PASSWORD = demisto.params().get('credentials').get('password')
SERVER = demisto.params()['url'][:-1] if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else \
    demisto.params()['url']  # Remove trailing slash to prevent wrong URL path to service
CLIENT_ID = demisto.params().get('client_id')
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
    except Exception as error:
        LOG.print_log()
        return_error("Could not parse response ".format(error))


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
    for business_obj in response.get('businessObjects'):
        new_business_obj = parse_fields_from_business_object(business_obj.get('fields'))
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


def http_request(method, url, payload, token):
    headers = build_headers(token)
    response = requests.request(method, url, data=payload, headers=headers)
    return response


def request_new_access_token(using_refresh):
    url = BASE_URL + "token"
    refresh_token = demisto.getIntegrationContext().get('refresh_token')

    payload = "client_id={0}".format(CLIENT_ID)
    payload = payload + "&grant_type=refresh_token&refresh_token={0}".format(refresh_token) if using_refresh \
        else payload + "&grant_type=password&username={0}&password={1}".format(USERNAME, PASSWORD)

    headers = {
        'Accept': "application/json",
        'Content-Type': "application/x-www-form-urlencoded",
    }

    response = http_request('POST', url, payload, headers)
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


def build_headers(token):
    headers = HEADERS
    headers['Authorization'] = "Bearer {}".format(token)
    return headers


def make_request(method, url, payload=None):
    token = get_access_token(False)
    response = http_request(method, url, payload, token)
    if response.status_code == HTTP_CODES['unauthorized']:
        token = get_access_token(True)
        response = http_request(method, url, payload, token)
    return response


def get_business_object_summary_by_name(name):
    url = BASE_URL + 'api/V1/getbusinessobjectsummary/busobname/{0}'.format(name)
    response = make_request('GET', url)
    res_json = parse_response(response, "Could not get business object summary")
    return res_json


def resolve_business_object_id_by_name(name):
    res = get_business_object_summary_by_name(name)
    if len(res) == 0:
        return_error('Could not retrieve business object id. Please make sure the business object type is correct.')
    return res[0].get('busObId')


def save_business_object(payload):
    url = BASE_URL + "api/V1/savebusinessobject"
    response = make_request("POST", url, json.dumps(payload))
    res_json = parse_response(response, "Could not save business object")
    return res_json


def get_business_object_record(business_object_id, object_id, id_type):
    id_type_str = 'publicid' if id_type == 'public_id' else 'busobrecid'
    url = BASE_URL + "api/V1/getbusinessobject/busobid/{0}/{1}/{2}".format(business_object_id, id_type_str, object_id)
    response = make_request("GET", url)
    res_json = parse_response(response, "Could not get incident")
    return res_json


def delete_business_object_record(business_object_id, object_id, id_type):
    id_type_str = 'publicid' if id_type == 'public_id' else 'busobrecid'
    url = BASE_URL + "api/V1/deletebusinessobject/busobid/{0}/{1}/{2}".format(business_object_id, id_type_str,
                                                                              object_id)
    response = make_request("DELETE", url)
    res_json = parse_response(response, "Could not delete incident")
    return res_json


def get_search_results(payload):
    url = BASE_URL + "api/V1/getsearchresults"
    response = make_request("POST", url, json.dumps(payload))
    res_json = parse_response(response, "Could not get incidents")
    return res_json


def get_business_object_template(business_object_id):
    url = BASE_URL + "api/V1/getbusinessobjecttemplate"
    payload = {
        "busObId": business_object_id,
        "includeAll": True,
    }
    response = make_request("POST", url, json.dumps(payload))
    res_json = parse_response(response, "Could not get incidents")
    return res_json


def build_business_object_json(simple_json, business_object_id, object_id=None, id_type=None):
    template_dict = get_business_object_template(business_object_id)
    business_object_ids_dict = cherwell_dict_parser('name', 'fieldId', template_dict.get('fields'))
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
    incident = parse_fields_from_business_object(results.get('fields'))
    incident['IncidentPublicID'] = results.get('busObPublicId')
    incident['IncidentRecordID'] = results.get('busObRecId')
    return results, incident


def delete_business_object(name, object_id, id_type):
    business_object_id = resolve_business_object_id_by_name(name)
    results = delete_business_object_record(business_object_id, object_id, id_type)
    return results


#######################################################################################################################


def create_business_object_command():
    args = demisto.args()
    type_name = args.get('type')
    data_json = json.loads(args.get('json'))
    result = create_business_object(type_name, data_json)
    ids = {
        'IncidentPublicID': result.get('busObPublicId'),
        'IncidentRecordID': result.get('busObRecId')
    }
    md = tableToMarkdown('New Incident was created', ids, headerTransform=pascalToSpace)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'HumanReadable': md,
        'EntryContext': {
            'Cherwell.BusinessObjects(val.IncidentPublicID == obj.IncidentPublicID)': ids
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
        'IncidentPublicID': result.get('busObPublicId'),
        'IncidentRecordID': result.get('busObRecId')
    }
    md = tableToMarkdown('New Incident was created', ids, headerTransform=pascalToSpace)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'HumanReadable': md,
        'EntryContext': {
            'Cherwell.BusinessObjects(val.IncidentPublicID == obj.IncidentPublicID)': ids
        }
    })


def get_business_object_command():
    args = demisto.args()
    type_name = args.get('type')
    id_type = args.get('id_type')
    object_id = args.get('id_value')
    results, incident = get_business_object(type_name, object_id, id_type)
    md = tableToMarkdown('Incidents Number: {}'.format(object_id), incident, headers=INCIDENT_HEADERS_NAMES,
                         removeNull=True, headerTransform=pascalToSpace)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': results,
        'HumanReadable': md,
        'EntryContext': {
            'Cherwell.Incidents(val.IncidentPublicID == obj.IncidentPublicID)': createContext(incident, removeNull=True)
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


def link_related_business_objects(parent_business_object_id, parent_business_object_record_id, relationship_id,
                                  business_object_id, business_object_record_id):
    url = BASE_URL + f"api/V1/linkrelatedbusinessobject/parentbusobid/{parent_business_object_id}" \
        f"/parentbusobrecid/{parent_business_object_record_id}" \
        f"/relationshipid/{relationship_id}" \
        f"/busobid/{business_object_id}" \
        f"/busobrecid/{business_object_record_id}"
    response = make_request("GET", url)
    parse_response(response, "Could not link business objects")
    return


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


def search_in_business_object_command():
    results = search_in_business_object()
    parsed_results = parse_fields_from_business_object_list(results)
    md = tableToMarkdown('Search Results', parsed_results, removeNull=True, headerTransform=pascalToSpace)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': results,
        'HumanReadable': md,
        'EntryContext': {
            'Cherwell.Search': createContext(parsed_results, removeNull=True)
        }
    })


def search_in_business_object():
    args = demisto.args()
    business_obj_name = args.get('business_obj_name')
    business_obj_id = args.get('business_obj_id')
    if business_obj_name or business_obj_id:
        try:
            bus_id = business_obj_id if business_obj_id else BUSINESS_OBJECT_IDS[business_obj_name.lower()]
            bus_name = business_obj_name if business_obj_name else BUSINESS_OBJECT_IDS.keys()[
                BUSINESS_OBJECT_IDS.values().index(bus_id)]
            fields_list = HEADERS_IDS[bus_name]
            payload = {
                "busObId": bus_id,
                "pageNumber": 0,
                "pageSize": 300,
                "searchText": args.get('search_text'),
                "fields": fields_list
            }
        except KeyError:
            return_error('Error: ID for {} not found'.format(args.get('business_obj_name')))
    else:
        return_error('Error: Please provide either a business object ID or Name')
    return get_search_results(payload)


#######################################################################################################################


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    # handle_proxy()

    if demisto.command() == 'test-module':
        token = get_access_token(True)
        demisto.results('ok')
    elif demisto.command() == 'cherwell-create-business-object':
        create_business_object_command()

    elif demisto.command() == 'cherwell-update-business-object':
        update_business_object_command()

    elif demisto.command() == 'cherwell-get-business-object':
        get_business_object_command()

    elif demisto.command() == 'cherwell-delete-business-object':
        delete_business_object_command()

    # elif demisto.command() == 'cherwell-list-incidents':
    #     list_incidents()
    #
    # elif demisto.command() == 'cherwell-create-task':
    #     create_task_command()
    #
    # elif demisto.command() == 'cherwell-update-incident-status':
    #     update_incident_status()
    #
    # elif demisto.command() == 'cherwell-update-task':
    #     update_task_command()
    #
    # elif demisto.command() == 'cherwell-search-in-business-object':
    #     search_in_business_object_command()
    #
    # elif demisto.command() == 'cherwell-get-task':
    #     get_task_command()

# Log exceptions
except Exception as e:
    LOG(str(e))
    LOG.print_log()
    return_error("Unexpected error: {}".format(e))
