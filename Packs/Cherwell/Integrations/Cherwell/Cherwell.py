import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" IMPORTS """

import json
import requests
import traceback
from datetime import datetime, timedelta
import os
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" GLOBALS/PARAMS """
FETCHES_INCIDENTS = ""
FETCH_TIME = ""
FETCH_ATTACHMENTS = ""
OBJECTS_TO_FETCH = ""
MAX_RESULT = ""
USERNAME = ""
PASSWORD = ""
SERVER = ""
SECURED = False
CLIENT_ID = ""
QUERY_STRING = ""
DATE_FORMAT = ""
BASE_URL = ""

HTTP_CODES = {"unauthorized": 401, "internal_server_error": 500, "success": 200}

HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}

QUERY_OPERATORS = ["eq", "gt", "lt", "contains", "startswith"]

ONE_STEP_ACTION_HEADERS = ["name", "displayName", "description", "id", "association", "standInKey"]

#######################################################################################################################


""" HELPER FUNCTIONS """


def parse_response(response, error_operation, file_content=False, is_fetch=False):
    try:
        response.raise_for_status()
        if not response.content:
            return
        if file_content:
            return response.content
        else:
            return response.json()
    except requests.exceptions.HTTPError:
        try:
            res_json = response.json()
            err_msg = res_json.get("errorMessage") or res_json.get("error_description") or res_json.get("Message")
        except Exception:
            err_msg = response.content.decode("utf-8")
        raise_or_return_error(error_operation + ": " + str(err_msg), is_fetch)
    except Exception as error:
        raise_or_return_error(f"Could not parse response {error}", is_fetch)


def cherwell_dict_parser(key, value, item_list):
    new_dict = {}
    for item in item_list:
        field_key = item.get(key)
        new_dict[field_key] = item.get(value)

    return new_dict


def parse_fields_from_business_object(field_list):
    new_business_obj = cherwell_dict_parser("name", "value", field_list)

    return new_business_obj


def parse_fields_from_business_object_list(response):
    object_list = []
    if not response.get("businessObjects"):
        return []
    for business_obj in response.get("businessObjects"):
        new_business_obj = parse_fields_from_business_object(business_obj.get("fields"))
        new_business_obj["BusinessObjectId"] = business_obj.get("busObId")
        new_business_obj["PublicId"] = business_obj.get("busObPublicId")
        new_business_obj["RecordId"] = business_obj.get("busObRecId")
        object_list.append(new_business_obj)

    return object_list


def build_fields_for_business_object(data_dict, ids_dict):
    fields = []
    for key, value in data_dict.items():
        new_field = {"dirty": "true", "fieldId": ids_dict.get(key), "name": key, "value": value}
        fields.append(new_field)
    return fields


def http_request(method, url, payload, token=None, custom_headers=None, is_fetch=False):
    headers = build_headers(token, custom_headers)
    try:
        response = requests.request(method, url, data=payload, headers=headers, verify=SECURED)
    except requests.exceptions.ConnectionError as e:
        err_message = f"Error connecting to server. Check your URL/Proxy/Certificate settings: {e}"
        raise_or_return_error(err_message, is_fetch)
    return response


def request_new_access_token(using_refresh):
    url = BASE_URL + "token"
    refresh_token = demisto.getIntegrationContext().get("refresh_token")

    if using_refresh:
        payload = f"client_id={CLIENT_ID}&grant_type=refresh_token&refresh_token={refresh_token}"
    else:
        payload = f"client_id={CLIENT_ID}&grant_type=password&username={USERNAME}&password={PASSWORD}"

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    response = http_request("POST", url, payload, custom_headers=headers)
    return response


def get_new_access_token(is_fetch=False):
    response = request_new_access_token(True)
    if not response.status_code == HTTP_CODES["success"]:
        response = request_new_access_token(False)
    res_json = parse_response(
        response, "Could not get token. Check your credentials (user/password/client id) and try again", is_fetch=is_fetch
    )
    token_expiration_time = int(date_to_timestamp(res_json.get(".expires"), "%a, %d %b %Y %H:%M:%S GMT"))
    demisto.setIntegrationContext(
        {
            "refresh_token": res_json.get("refresh_token"),
            "token_expiration_time": token_expiration_time,
            "access_token": res_json.get("access_token"),
        }
    )
    return res_json.get("access_token")


def get_access_token(new_token, is_fetch=False):
    integration_context = demisto.getIntegrationContext()
    token_expiration_time = integration_context.get("token_expiration_time")
    current_time = date_to_timestamp(datetime.utcnow())
    if new_token or not token_expiration_time or token_expiration_time < current_time:
        token = get_new_access_token(is_fetch=is_fetch)
        return token
    else:
        return integration_context.get("access_token")


def build_headers(token, headers=None):
    headers = headers if headers else HEADERS
    headers["Authorization"] = f"Bearer {token}"
    return headers


def make_request(method, url, payload=None, headers=None, is_fetch=False):
    token = get_access_token(False, is_fetch=is_fetch)
    response = http_request(method, url, payload, token, custom_headers=headers, is_fetch=is_fetch)
    if response.status_code == HTTP_CODES["unauthorized"]:
        token = get_access_token(True, is_fetch=is_fetch)
        response = http_request(method, url, payload, token, custom_headers=headers, is_fetch=is_fetch)
    return response


def get_business_object_summary_by_name(name, is_fetch=False):
    url = BASE_URL + f"api/V1/getbusinessobjectsummary/busobname/{name}"
    response = make_request("GET", url, is_fetch=is_fetch)
    return parse_response(response, "Could not get business object summary", is_fetch=is_fetch)


def get_business_object_summary_by_id(_id, is_fetch=False):
    url = BASE_URL + f"api/V1/getbusinessobjectsummary/busobid/{_id}"
    response = make_request("GET", url, is_fetch=is_fetch)
    return parse_response(response, "Could not get business object summary", is_fetch=is_fetch)


def resolve_business_object_id_by_name(name, is_fetch=False):
    res = get_business_object_summary_by_name(name, is_fetch)
    if not res:
        err_message = f'Could not retrieve "{name}" business object id. Make sure "{name}" is a valid business object.'
        raise_or_return_error(err_message, is_fetch)
    return res[0].get("busObId")


def save_business_object(payload):
    url = BASE_URL + "api/V1/savebusinessobject"
    response = make_request("POST", url, json.dumps(payload))
    return parse_response(response, "Could not save business object")


def get_business_object_record(business_object_id, object_id, id_type):
    id_type_str = "publicid" if id_type == "public_id" else "busobrecid"
    url = BASE_URL + f"api/V1/getbusinessobject/busobid/{business_object_id}/{id_type_str}/{object_id}"
    response = make_request("GET", url)
    return parse_response(response, "Could not get business objects")


def delete_business_object_record(business_object_id, object_id, id_type):
    id_type_str = "publicid" if id_type == "public_id" else "busobrecid"
    url = BASE_URL + f"api/V1/deletebusinessobject/busobid/{business_object_id}/{id_type_str}/{object_id}"
    response = make_request("DELETE", url)
    return parse_response(response, "Could not delete business object")


def get_search_results(payload, is_fetch=False):
    url = BASE_URL + "api/V1/getsearchresults"
    response = make_request("POST", url, json.dumps(payload))
    return parse_response(response, "Could not search for business objects", is_fetch=is_fetch)


def get_business_object_template(business_object_id, include_all=True, field_names=None, fields_ids=None, is_fetch=False):
    url = BASE_URL + "api/V1/getbusinessobjecttemplate"
    payload = {"busObId": business_object_id, "includeAll": include_all}

    if field_names:
        payload["fieldNames"] = field_names
    if fields_ids:
        payload["fieldIds"] = fields_ids
    response = make_request("POST", url, json.dumps(payload), is_fetch=is_fetch)
    return parse_response(response, "Could not get business object template", is_fetch=is_fetch)


def build_business_object_json(simple_json, business_object_id, object_id=None, id_type=None):
    business_object_ids_dict = get_key_value_dict_from_template("name", "fieldId", business_object_id)
    fields_for_business_object = build_fields_for_business_object(simple_json, business_object_ids_dict)
    business_object_json = {"busObId": business_object_id, "fields": fields_for_business_object}
    if object_id:
        id_key = "busObPublicId" if id_type == "public_id" else "busObRecId"
        business_object_json[id_key] = object_id
    return business_object_json


def create_business_object(name, data_json):
    business_object_id = resolve_business_object_id_by_name(name)
    business_object_json = build_business_object_json(data_json, business_object_id)
    return save_business_object(business_object_json)


def update_business_object(name, data_json, object_id, id_type):
    business_object_id = resolve_business_object_id_by_name(name)
    business_object_json = build_business_object_json(data_json, business_object_id, object_id, id_type)
    return save_business_object(business_object_json)


def get_business_object(name, object_id, id_type):
    business_object_id = resolve_business_object_id_by_name(name)
    results = get_business_object_record(business_object_id, object_id, id_type)
    parsed_business_object = parse_fields_from_business_object(results.get("fields"))
    parsed_business_object["PublicId"] = results.get("busObPublicId")
    parsed_business_object["RecordId"] = results.get("busObRecId")
    return parsed_business_object, results


def delete_business_object(name, object_id, id_type):
    business_object_id = resolve_business_object_id_by_name(name)
    return delete_business_object_record(business_object_id, object_id, id_type)


def download_attachment_from_business_object(attachment, is_fetch):
    attachment_id = attachment.get("attachmentId")
    business_object_id = attachment.get("busObId")
    business_record_id = attachment.get("busObRecId")
    url = (
        BASE_URL + f"api/V1/getbusinessobjectattachment"
        f"/attachmentid/{attachment_id}/busobid/{business_object_id}/busobrecid/{business_record_id}"
    )
    response = make_request("GET", url, is_fetch=is_fetch)
    return parse_response(response, f"Unable to get content of attachment {attachment_id}", file_content=True, is_fetch=is_fetch)


def get_attachments_content(attachments_to_download, is_fetch):
    attachments = []
    for attachment in attachments_to_download:
        new_attachment = {
            "FileName": attachment.get("displayText"),
            "CreatedAt": attachment.get("created"),
            "Content": download_attachment_from_business_object(attachment, is_fetch=is_fetch),
        }
        attachments.append(new_attachment)
    return attachments


def get_attachments_details(id_type, object_id, object_type_name, object_type_id, type, attachment_type, is_fetch=False):
    id_type_str = "publicid" if id_type == "public_id" else "busobrecid"
    business_object_type_str = "busobid" if object_type_id else "busobname"
    object_type = object_type_id if object_type_id else object_type_name
    url = (
        BASE_URL + f"api/V1/getbusinessobjectattachments/"
        f"{business_object_type_str}/{object_type}/"
        f"{id_type_str}/{object_id}"
        f"/type/{type}"
        f"/attachmenttype/{attachment_type}"
    )
    response = make_request("GET", url, is_fetch=is_fetch)
    return parse_response(response, f"Unable to get attachments for {object_type} {object_id}", is_fetch=is_fetch)


def download_attachments(id_type, object_id, business_object_type_name=None, business_object_type_id=None, is_fetch=False):
    type = "File"
    attachment_type = "Imported"
    result = get_attachments_details(
        id_type, object_id, business_object_type_name, business_object_type_id, type, attachment_type, is_fetch=is_fetch
    )
    attachments_to_download = result.get("attachments")
    if not attachments_to_download:
        return
    return get_attachments_content(attachments_to_download, is_fetch=is_fetch)


def get_attachments_info(id_type, object_id, attachment_type, business_object_type_name=None, business_object_type_id=None):
    type = "File"
    result = get_attachments_details(
        id_type, object_id, business_object_type_name, business_object_type_id, type, attachment_type
    )
    attachments = result.get("attachments")
    attachments_info = [
        {
            "AttachmentFiledId": attachment.get("attachmentFileId"),
            "FileName": attachment.get("displayText"),
            "AttachmentId": attachment.get("attachmentId"),
            "BusinessObjectType": business_object_type_name,
            f"BusinessObject{string_to_context_key(id_type)}": object_id,
        }
        for attachment in attachments
    ]
    return attachments_info, result


def attachment_results(attachments):
    attachments_file_results = []
    for attachment in attachments:
        attachment_content = attachment.get("Content")
        attachment_name = attachment.get("FileName")
        attachments_file_results.append(fileResult(attachment_name, attachment_content))
    return attachments_file_results


def run_query_on_business_objects(bus_id, filter_query, max_results, is_fetch):
    payload = {"busObId": bus_id, "includeAllFields": True, "filters": filter_query}
    if max_results:
        payload["pageSize"] = max_results
    return get_search_results(payload, is_fetch=is_fetch)


def get_key_value_dict_from_template(key, val, business_object_id, is_fetch=False):
    template_dict = get_business_object_template(business_object_id, is_fetch=is_fetch)
    return cherwell_dict_parser(key, val, template_dict.get("fields"))


def get_all_incidents(objects_names, last_created_time, max_results, query_string, real_fetch):
    all_incidents: list = []
    for business_object_name in objects_names:
        business_object_id = resolve_business_object_id_by_name(business_object_name, is_fetch=real_fetch)
        query_list = [["CreatedDateTime", "gt", last_created_time]]
        if query_string:
            additional_query_list = validate_query_for_fetch_incidents(objects_names, query_string, real_fetch)
            query_list += additional_query_list
        incidents, _ = query_business_object(query_list, business_object_id, max_results, is_fetch=real_fetch)
        all_incidents += incidents
    sorted_incidents = sorted(all_incidents, key=lambda incident: incident.get("CreatedDateTime"))
    return sorted_incidents[:max_results]


def object_to_incident(obj):
    attachments_list = []
    attachments = obj.get("Attachments")
    if attachments:
        obj.pop("Attachments")
        for attachment in attachments:
            file_name = attachment.get("FileName")
            attachment_file = fileResult(file_name, attachment.get("Content"))
            attachments_list.append({"path": attachment_file.get("FileID"), "name": file_name})
    item = {"name": f'Record ID:{obj.get("RecID")}', "attachment": attachments_list, "rawJSON": json.dumps(obj)}

    return createContext(item, removeNull=True)


def save_incidents(objects_to_save):
    final_incidents = []
    for obj in objects_to_save:
        final_incidents.append(object_to_incident(obj))
    demisto.incidents(final_incidents)
    return


def fetch_incidents_attachments(incidents, is_fetch):
    for incident in incidents:
        rec_id = incident.get("RecID")
        business_object_id = incident.get("BusinessObjectId")
        incident["Attachments"] = []
        attachments = download_attachments("record_id", rec_id, business_object_type_id=business_object_id, is_fetch=is_fetch)
        if attachments:
            for attachment in attachments:
                new_attachment_obj = {"Content": attachment.get("Content"), "FileName": attachment.get("FileName")}
                incident["Attachments"].append(new_attachment_obj)
    return incidents


def validate_params_for_fetch(max_result, objects_to_fetch, real_fetch):
    # Check that max result is positive integer
    try:
        max_result = int(max_result)
        if max_result < 0:
            raise ValueError
    except ValueError:
        max_result_err_message = "Max results to fetch must be a number grater than 0"
        raise_or_return_error(max_result_err_message, real_fetch)
    # Make sure that there are objects to fetch
    if len(objects_to_fetch) == 0:
        objects_to_fetch_err_message = "No objects to fetch were given"
        raise_or_return_error(objects_to_fetch_err_message, real_fetch)
    return


def fetch_incidents(objects_names, fetch_time, max_results, query_string, fetch_attachments, real_fetch=False):
    validate_params_for_fetch(max_results, objects_names, real_fetch)
    max_results = int(max_results)
    last_run = demisto.getLastRun()
    last_objects_fetched = last_run.get("objects_names_to_fetch")
    if "last_created_time" in last_run and last_objects_fetched == objects_names:
        last_created_time = last_run.get("last_created_time")
    else:
        try:
            last_created_time, _ = parse_date_range(fetch_time, date_format=DATE_FORMAT, to_timestamp=False)
        except ValueError:
            error_message = (
                f"First fetch time stamp should be of the form: <number> <time unit>, e.g., 12 hours, "
                f'7 days. Received: "{fetch_time}"'
            )
            raise_or_return_error(error_message, real_fetch)
    incidents = get_all_incidents(objects_names, last_created_time, max_results, query_string, real_fetch)
    if fetch_attachments:
        incidents = fetch_incidents_attachments(incidents, real_fetch)
    if real_fetch:
        save_incidents(incidents)
    return incidents


def upload_business_object_attachment(
    file_name,
    file_size,
    file_content,
    object_type_name,
    id_type,
    object_id,
):
    id_type_str = "publicid" if id_type == "public_id" else "busobrecid"
    url = (
        BASE_URL + f"/api/V1/uploadbusinessobjectattachment/"
        f"filename/{file_name}/busobname/{object_type_name}/{id_type_str}/{object_id}/offset/0/totalsize/{file_size}"
    )
    payload = file_content
    headers = HEADERS
    headers["Content-Type"] = "application/octet-stream"
    response = make_request("POST", url, payload, headers)
    return parse_response(response, f"Could not upload attachment {file_name}")


def upload_attachment(id_type, object_id, type_name, file_entry_id):
    file_data = demisto.getFilePath(file_entry_id)
    file_path = file_data.get("path")
    file_name = file_data.get("name")
    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            file_content = f.read()
        attachment_id = upload_business_object_attachment(file_name, file_size, file_content, type_name, id_type, object_id)
        return attachment_id
    except Exception as err:
        return_error(f"unable to open file: {err}")


def remove_attachment(id_type, object_id, type_name, attachment_id):
    id_type_str = "publicid" if id_type == "public_id" else "busobrecid"
    url = (
        BASE_URL + f"/api/V1/removebusinessobjectattachment/"
        f"attachmentid/{attachment_id}/busobname/{type_name}/{id_type_str}/{object_id}"
    )
    response = make_request("DELETE", url)
    parse_response(response, f"Could not remove attachment {attachment_id} from {type_name} {object_id}")
    return


def link_related_business_objects(
    action,
    parent_business_object_id,
    parent_business_object_record_id,
    relationship_id,
    business_object_id,
    business_object_record_id,
):
    url_action_str = "linkrelatedbusinessobject" if action == "link" else "unlinkrelatedbusinessobject"
    url = (
        BASE_URL + f"api/V1/{url_action_str}/parentbusobid/{parent_business_object_id}"
        f"/parentbusobrecid/{parent_business_object_record_id}"
        f"/relationshipid/{relationship_id}"
        f"/busobid/{business_object_id}"
        f"/busobrecid/{business_object_record_id}"
    )
    http_method = "GET" if action == "link" else "DELETE"
    response = make_request(http_method, url)
    parse_response(response, "Could not link business objects")
    return


def business_objects_relation_action(
    action, parent_type_name, parent_record_id, child_type_name, child_record_id, relationship_id
):
    parent_business_object_id = resolve_business_object_id_by_name(parent_type_name)
    child_business_object_id = resolve_business_object_id_by_name(child_type_name)
    link_related_business_objects(
        action, parent_business_object_id, parent_record_id, relationship_id, child_business_object_id, child_record_id
    )
    return


def validate_query_list(query_list, is_fetch):
    for index, query in enumerate(query_list):
        if not len(query) == 3:
            length_err_message = (
                f'Cannot parse query, should be of the form: `[["FieldName","Operator","Value"],'
                f'["FieldName","Operator","Value"],...]`. Filter in index {index} is malformed: {query}'
            )
            raise_or_return_error(length_err_message, is_fetch)
        if query[1] not in QUERY_OPERATORS:
            operator_err_message = (
                f'Operator should be one of the following: {", ".join(QUERY_OPERATORS)}. Filter in'
                f' index {index}, was: {query[1]}'
            )
            raise_or_return_error(operator_err_message, is_fetch)
    return


def validate_query_for_fetch_incidents(objects_names, query_string, real_fetch):
    if not objects_names:
        no_objects_err_message = (
            "No business object name was given. \n In order to run advanced query, "
            "fill the integration parameter-`Objects to fetch` with exactly one business object name."
        )
        raise_or_return_error(no_objects_err_message, real_fetch)
    if len(objects_names) > 1:
        multiple_objects_error_message = (
            f'Advanced query operation is supported for a single business object. '
            f'{len(objects_names)} objects were given: {",".join(objects_names)}'
        )
        raise_or_return_error(multiple_objects_error_message, real_fetch)
    return parse_string_query_to_list(query_string, real_fetch)


def build_query_dict(query, filed_ids_dict, is_fetch):
    field_name = query[0]
    operator = query[1]
    value = query[2]
    field_id = filed_ids_dict.get(field_name)
    if not field_id:
        err_message = f"Field name: {field_name} does not exit in the given business objects"
        raise_or_return_error(err_message, is_fetch)
    return {"fieldId": filed_ids_dict.get(field_name), "operator": operator, "value": value}


def build_query_dict_list(query_list, filed_ids_dict, is_fetch):
    query_dict_list = []
    for query in query_list:
        query_dict = build_query_dict(query, filed_ids_dict, is_fetch)
        query_dict_list.append(query_dict)
    return query_dict_list


def query_business_object(query_list, business_object_id, max_results, is_fetch=False):
    filed_ids_dict = get_key_value_dict_from_template("name", "fieldId", business_object_id, is_fetch=is_fetch)
    filters = build_query_dict_list(query_list, filed_ids_dict, is_fetch=is_fetch)
    query_result = run_query_on_business_objects(business_object_id, filters, max_results, is_fetch=is_fetch)
    business_objects = parse_fields_from_business_object_list(query_result)
    return business_objects, query_result


def parse_string_query_to_list(query_string, is_fetch=False):
    try:
        query_list = json.loads(query_string)
    except (ValueError, TypeError):
        err_message = (
            'Cannot parse query, should be of the form: `[["FieldName","Operator","Value"],' '["FieldName","Operator","Value"]]`.'
        )
        raise_or_return_error(err_message, is_fetch)
    validate_query_list(query_list, is_fetch)
    return query_list


def query_business_object_string(business_object_name, query_string, max_results):
    if max_results:
        try:
            int(max_results)
        except ValueError:
            return return_error("`max_results` argument received is not a number")
    business_object_id = resolve_business_object_id_by_name(business_object_name)
    query_filters_list = parse_string_query_to_list(query_string)
    return query_business_object(query_filters_list, business_object_id, max_results)


def get_field_info(type, field_property):
    business_object_id = resolve_business_object_id_by_name(type)
    template = get_business_object_template(business_object_id)
    business_object_fields = template.get("fields")
    field_to_return = None
    for field in business_object_fields:
        if (
            field.get("displayName") == field_property
            or field.get("fieldId") == field_property
            or field.get("name") == field_property
        ):
            field_to_return = field
    if field_to_return:
        field_to_return = {
            "DisplayName": field_to_return.get("displayName"),
            "Name": field_to_return.get("name"),
            "FieldId": field_to_return.get("fieldId"),
        }
    else:
        return_error(f"Field with the value {field_property} was not found")
    return field_to_return


def cherwell_run_saved_search(association_id, scope, scope_owner, search_name):
    search_payload = {
        "Association": association_id,
        "scope": scope,
        "scopeOwner": scope_owner,
        "searchName": search_name,
        "includeAllFields": True,
    }

    results = get_search_results(search_payload)
    return parse_fields_from_business_object_list(results)


def cherwell_get_business_object_id(business_object_name):
    business_object_id = resolve_business_object_id_by_name(business_object_name)
    business_object_info = {"BusinessObjectId": business_object_id, "BusinessObjectName": business_object_name}
    return business_object_info


def raise_or_return_error(msg, raise_flag):
    """
    This function handles errors occurred in functions that are within the fetch incidents flow.
    If the error occurred as part of a fetch-incidents flow then an exception will be thrown otherwise a regular error
    entry will be returned.
    This is needed when running fetch-incidents process since regular error entries are not handled correctly by the
    server
    :param msg: error msg to raise/return
    :param raise_flag: if true should raise, otherwise throw
    """
    if raise_flag:
        raise Exception(msg)
    else:
        return_error(msg)


def get_one_step_actions(bus_id, is_fetch=False):
    url = BASE_URL + f"api/V1/getonestepactions/association/{bus_id}"
    response = make_request("GET", url, is_fetch=is_fetch)
    return parse_response(response, "Could not get one step actions", is_fetch=is_fetch)


def get_one_step_actions_recursive(root, actions):
    if root.get("childItems"):
        actions_list = []
        for item in root.get("childItems"):
            actions_list.append(item)
        actions[root.get("name")] = actions_list

    for folder in root.get("childFolders", []):
        get_one_step_actions_recursive(folder, actions)
    return actions


def run_one_step_action(payload):
    url = BASE_URL + "api/V1/runonestepaction"
    response = make_request("POST", url, json.dumps(payload))
    return parse_response(response, "Could not run one step action")


########################################################################################################################


"""
Commands
"""


def test_command():
    if FETCHES_INCIDENTS:
        fetch_incidents(OBJECTS_TO_FETCH, FETCH_TIME, MAX_RESULT, QUERY_STRING, FETCH_ATTACHMENTS)
    else:
        get_access_token(True)
    return


def create_business_object_command():
    args = demisto.args()
    type_name = args.get("type")
    data_json = json.loads(args.get("json"))
    result = create_business_object(type_name, data_json)
    ids = {"PublicId": result.get("busObPublicId"), "RecordId": result.get("busObRecId")}
    md = tableToMarkdown(f"New {type_name.capitalize()} was created", ids, headerTransform=pascalToSpace)

    return {
        "Type": entryTypes["note"],
        "ContentsFormat": formats["json"],
        "Contents": result,
        "HumanReadable": md,
        "EntryContext": {"Cherwell.BusinessObjects(val.RecordId == obj.RecordId)": ids},
    }


def update_business_object_command():
    args = demisto.args()
    type_name = args.get("type")
    data_json = json.loads(args.get("json"))
    object_id = args.get("id_value")
    id_type = args.get("id_type")
    result = update_business_object(type_name, data_json, object_id, id_type)
    ids = {"PublicId": result.get("busObPublicId"), "RecordId": result.get("busObRecId")}
    md = tableToMarkdown(f"{type_name.capitalize()} {object_id} was updated", ids, headerTransform=pascalToSpace)

    return {
        "Type": entryTypes["note"],
        "ContentsFormat": formats["json"],
        "Contents": result,
        "HumanReadable": md,
        "EntryContext": {"Cherwell.BusinessObjects(val.RecordId == obj.RecordId)": ids},
    }


def get_business_object_command():
    args = demisto.args()
    type_name = args.get("type")
    id_type = args.get("id_type")
    object_id = args.get("id_value")
    business_object, results = get_business_object(type_name, object_id, id_type)
    md = tableToMarkdown(f"{type_name.capitalize()}: {object_id}", business_object, headerTransform=pascalToSpace)

    return {
        "Type": entryTypes["note"],
        "ContentsFormat": formats["json"],
        "Contents": results,
        "HumanReadable": md,
        "EntryContext": {"Cherwell.BusinessObjects(val.RecordId == obj.RecordId)": createContext(business_object)},
    }


def delete_business_object_command():
    args = demisto.args()
    type_name = args.get("type")
    id_type = args.get("id_type")
    object_id = args.get("id_value")
    results = delete_business_object(type_name, object_id, id_type)
    md = f"### Record {object_id} of type {type_name} was deleted."

    return {"Type": entryTypes["note"], "ContentsFormat": formats["json"], "Contents": results, "HumanReadable": md}


def fetch_incidents_command():
    objects_names_to_fetch = OBJECTS_TO_FETCH
    fetch_attachments = FETCH_ATTACHMENTS
    max_result = MAX_RESULT
    fetch_time = FETCH_TIME
    query_string = QUERY_STRING
    incidents = fetch_incidents(objects_names_to_fetch, fetch_time, max_result, query_string, fetch_attachments, real_fetch=True)
    if incidents:
        last_incident_created_time = incidents[-1].get("CreatedDateTime")
        next_created_time_to_fetch = (datetime.strptime(last_incident_created_time, DATE_FORMAT) + timedelta(seconds=1)).strftime(
            DATE_FORMAT
        )
        demisto.setLastRun({"last_created_time": next_created_time_to_fetch, "objects_names_to_fetch": objects_names_to_fetch})
    return


def download_attachments_command():
    args = demisto.args()
    id_type = args.get("id_type")
    object_id = args.get("id_value")
    type_name = args.get("type")
    attachments = download_attachments(id_type, object_id, business_object_type_name=type_name)
    if not attachments:
        return_error(f"No attachments were found for {type_name}:{object_id}")
    return attachment_results(attachments)


def upload_attachment_command():
    args = demisto.args()
    id_type = args.get("id_type")
    object_id = args.get("id_value")
    type_name = args.get("type")
    file_entry_id = args.get("file_entry_id")
    attachment_id = upload_attachment(id_type, object_id, type_name, file_entry_id)
    entry_context = {
        "AttachmentFileId": attachment_id,
        "BusinessObjectType": type_name,
        string_to_context_key(id_type): object_id,
    }
    md = f"### Attachment: {attachment_id}, was successfully attached to {type_name} {object_id}"
    return {
        "Type": entryTypes["note"],
        "ContentsFormat": formats["text"],
        "Contents": {"attachment_id": attachment_id},
        "EntryContext": {"Cherwell.UploadedAttachments(val.AttachmentId == obj.AttachmentId)": entry_context},
        "HumanReadable": md,
    }


def remove_attachment_command():
    args = demisto.args()
    id_type = args.get("id_type")
    object_id = args.get("id_value")
    type_name = args.get("type")
    attachment_id = args.get("attachment_id")
    remove_attachment(id_type, object_id, type_name, attachment_id)
    md = f"### Attachment: {attachment_id}, was successfully removed from {type_name} {object_id}"
    return {
        "Type": entryTypes["note"],
        "ContentsFormat": formats["text"],
        "Contents": md,
        "HumanReadable": md,
    }


def get_attachments_info_command():
    args = demisto.args()
    id_type = args.get("id_type")
    object_id = args.get("id_value")
    type_name = args.get("type")
    attachment_type = args.get("attachment_type")
    attachments_info, raw_result = get_attachments_info(id_type, object_id, attachment_type, business_object_type_name=type_name)
    md = (
        tableToMarkdown(f"{type_name.capitalize()} {object_id} attachments:", attachments_info, headerTransform=pascalToSpace)
        if attachments_info
        else f"### {type_name.capitalize()} {object_id} has no attachments"
    )

    entry = {"Type": entryTypes["note"], "ContentsFormat": formats["text"], "Contents": raw_result, "HumanReadable": md}
    if attachments_info:
        entry["EntryContext"] = {"Cherwell.AttachmentsInfo": attachments_info}
    return entry


def link_business_objects_command():
    args = demisto.args()
    parent_type = args.get("parent_type")
    parent_record_id = args.get("parent_record_id")
    child_type = args.get("child_type")
    child_record_id = args.get("child_record_id")
    relationship_id = args.get("relationship_id")
    business_objects_relation_action("link", parent_type, parent_record_id, child_type, child_record_id, relationship_id)
    message = f"{parent_type.capitalize()} {parent_record_id} and {child_type.capitalize()} {child_record_id} were linked"
    md = f"### {message}"
    return {
        "Type": entryTypes["note"],
        "ContentsFormat": formats["text"],
        "Contents": message,
        "HumanReadable": md,
    }


def unlink_business_objects_command():
    args = demisto.args()
    parent_type = args.get("parent_type")
    parent_record_id = args.get("parent_record_id")
    child_type = args.get("child_type")
    child_record_id = args.get("child_record_id")
    relationship_id = args.get("relationship_id")
    business_objects_relation_action("unlink", parent_type, parent_record_id, child_type, child_record_id, relationship_id)
    message = f"{parent_type.capitalize()} {parent_record_id} and {child_type.capitalize()} {child_record_id} were unlinked"
    md = f"### {message}"
    return {
        "Type": entryTypes["note"],
        "ContentsFormat": formats["text"],
        "Contents": message,
        "HumanReadable": md,
    }


def query_business_object_command():
    args = demisto.args()
    type_name = args.get("type")
    query_string = args.get("query")
    max_results = args.get("max_results")
    results, raw_response = query_business_object_string(type_name, query_string, max_results)
    md = tableToMarkdown("Query Results", results, headerTransform=pascalToSpace)
    return {
        "Type": entryTypes["note"],
        "ContentsFormat": formats["text"],
        "Contents": raw_response,
        "EntryContext": {"Cherwell.QueryResults": results},
        "HumanReadable": md,
    }


def get_field_info_command():
    args = demisto.args()
    type_name = args.get("type")
    field_property = args.get("field_property")
    results = get_field_info(type_name, field_property)
    md = tableToMarkdown("Field info:", results, headerTransform=pascalToSpace)
    return {
        "Type": entryTypes["note"],
        "ContentsFormat": formats["text"],
        "Contents": results,
        "EntryContext": {"Cherwell.FieldInfo(val.FieldId == obj.FieldId)": results},
        "HumanReadable": md,
    }


def cherwell_run_saved_search_command():
    args = demisto.args()
    association_id = args.get("association_id")
    scope = args.get("scope")
    scope_owner = args.get("scope_owner")
    search_name = args.get("search_name")
    results = cherwell_run_saved_search(association_id, scope, scope_owner, search_name)
    md = tableToMarkdown(f"{search_name} results:", results, headerTransform=pascalToSpace)
    return {
        "Type": entryTypes["note"],
        "ContentsFormat": formats["text"],
        "Contents": results,
        "EntryContext": {"Cherwell.SearchOperation(val.RecordId == obj.RecordId)": results},
        "HumanReadable": md,
    }


def cherwell_get_business_object_id_command():
    args = demisto.args()
    business_object_name = args.get("business_object_name")
    result = cherwell_get_business_object_id(business_object_name)
    md = tableToMarkdown("Business Object Info:", result, headerTransform=pascalToSpace)
    return {
        "Type": entryTypes["note"],
        "ContentsFormat": formats["text"],
        "Contents": result,
        "EntryContext": {"Cherwell.BusinessObjectInfo(val.BusinessObjectId == obj.BusinessObjectId)": result},
        "HumanReadable": md,
    }


def cherwell_get_business_object_summary_command():
    args = demisto.args()
    business_object_name = args.get("name")
    business_object_id = args.get("id")

    if not business_object_id and not business_object_name:
        raise DemistoException("No name or ID were specified. Please specify at least one of them.")
    elif business_object_id:
        result = get_business_object_summary_by_id(business_object_id)
    else:
        result = get_business_object_summary_by_name(business_object_name)

    md = tableToMarkdown("Business Object Summary:", result, headerTransform=pascalToSpace)

    return CommandResults(
        outputs=result,
        readable_output=md,
        outputs_key_field="busObId",
        outputs_prefix="Cherwell.BusinessObjectSummary",
        raw_response=result,
    )


def cherwell_get_one_step_actions_command():
    args = demisto.args()
    business_object_id = args.get("busobjectid")
    result = get_one_step_actions(business_object_id)

    actions: dict = {}
    ec = {}
    md = ""

    get_one_step_actions_recursive(result.get("root"), actions)

    if actions:
        for key, action in actions.items():
            md += tableToMarkdown(
                f"{key} one-step actions:", action, headerTransform=pascalToSpace, headers=ONE_STEP_ACTION_HEADERS
            )
        ec = {"BusinessObjectId": business_object_id, "Actions": actions}
    else:
        md = f"No one-step actions found for business object ID {business_object_id}"

    return CommandResults(
        outputs=ec,
        readable_output=md,
        outputs_key_field="BusinessObjectId",
        outputs_prefix="Cherwell.OneStepActions",
        raw_response=result,
    )


def cherwell_run_one_step_action_command():
    prompt_values = {}
    args = demisto.args()
    business_object_id = args.get("busobjectid")
    rec_id = args.get("busobrecid")
    stand_in_key = args.get("oneStepAction_StandInKey")
    prompt_values_arg = args.get("prompt_values")

    if prompt_values_arg:
        prompt_values = json.loads(prompt_values_arg)

    payload = {
        "acquireLicense": True,
        "busObId": business_object_id,
        "busObRecId": rec_id,
        "oneStepActionStandInKey": stand_in_key,
        "promptValues": prompt_values,
    }

    result = run_one_step_action(payload)

    return CommandResults(readable_output="One-Step action has been executed successfully.", raw_response=result)


#######################################################################################################################


def main():
    global \
        FETCHES_INCIDENTS, \
        FETCH_TIME, \
        FETCH_ATTACHMENTS, \
        OBJECTS_TO_FETCH, \
        MAX_RESULT, \
        USERNAME, \
        PASSWORD, \
        SERVER, \
        SECURED, \
        CLIENT_ID, \
        QUERY_STRING, \
        DATE_FORMAT, \
        BASE_URL

    params = demisto.params()

    FETCHES_INCIDENTS = params.get("isFetch")
    FETCH_TIME = params.get("fetch_time")
    FETCH_ATTACHMENTS = params.get("fetch_attachments")
    OBJECTS_TO_FETCH = params.get("objects_to_fetch").split(",")
    MAX_RESULT = params.get("max_results")
    USERNAME = params.get("credentials").get("identifier")
    PASSWORD = params.get("credentials").get("password")
    # Remove trailing slash to prevent wrong URL path to service
    SERVER = params["url"][:-1] if (params["url"] and params["url"].endswith("/")) else params["url"]
    SECURED = not params.get("insecure")
    CLIENT_ID = params.get("client_id")
    QUERY_STRING = params.get("query_string")
    DATE_FORMAT = "%m/%d/%Y %I:%M:%S %p"
    # Service base URL
    BASE_URL = SERVER + "/CherwellAPI/"

    try:
        handle_proxy()

        command = demisto.command()
        demisto.debug(f"Command being called is {command}")

        commands = {
            "cherwell-create-business-object": create_business_object_command,
            "cherwell-update-business-object": update_business_object_command,
            "cherwell-get-business-object": get_business_object_command,
            "cherwell-delete-business-object": delete_business_object_command,
            "cherwell-download-attachments": download_attachments_command,
            "cherwell-get-attachments-info": get_attachments_info_command,
            "cherwell-upload-attachment": upload_attachment_command,
            "cherwell-remove-attachment": remove_attachment_command,
            "cherwell-link-business-objects": link_business_objects_command,
            "cherwell-unlink-business-objects": unlink_business_objects_command,
            "cherwell-query-business-object": query_business_object_command,
            "cherwell-get-field-info": get_field_info_command,
            "cherwell-run-saved-search": cherwell_run_saved_search_command,
            "cherwell-get-business-object-id": cherwell_get_business_object_id_command,
            "cherwell-get-business-object-summary": cherwell_get_business_object_summary_command,
            "cherwell-get-one-step-actions-for-business-object": cherwell_get_one_step_actions_command,
            "cherwell-run-one-step-action-on-business-object": cherwell_run_one_step_action_command,
        }
        if command == "test-module":
            test_command()
            demisto.results("ok")
        elif command == "fetch-incidents":
            fetch_incidents_command()
        elif command in commands:
            return_results(commands[command]())
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    # Log exceptions
    except Exception as e:
        message = f"Unexpected error: {e}."
        return_error(message, error=traceback.format_exc())


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
