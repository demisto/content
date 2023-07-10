import json

import demistomock as demisto
from Packs.Base.Scripts.CommonServerPython.CommonServerPython import (
    LOG, CommandResults, argToList, handle_proxy, parse_date_range,
    return_error, return_outputs, return_results, tableToMarkdown,
    GetModifiedRemoteDataArgs, GetModifiedRemoteDataResponse,
    GetRemoteDataArgs, GetRemoteDataResponse,
    SchemeTypeMapping, GetMappingFieldsResponse,
)

""" IMPORTS """
from datetime import datetime, timedelta
from typing import Any, Dict, List, Union, cast

import requests
from urllib3 import disable_warnings

# Disable insecure warnings
disable_warnings()

""" GLOBALS/PARAMS """

USERNAME: str = demisto.params().get("credentials", {}).get("identifier")
PASSWORD: str = demisto.params().get("credentials", {}).get("password")
USE_SSL: bool = not demisto.params().get("insecure", False)
BASE_URL: str = (
    demisto.params()["url"][:-1]
    if demisto.params()["url"].endswith("/")
    else demisto.params()["url"]
)
FETCH_TIME_DEFAULT = "3 days"
FETCH_TIME: str = demisto.params().get("fetch_time", FETCH_TIME_DEFAULT).strip()

CLOSED_ALERT_STATUS = ["Closed", "Deleted"]

""" HELPER FUNCTIONS """


def dict_value_to_integer(params: Dict, key: str):
    """
    :param params: A dictionary which has the key param
    :param key: The key that we need to convert it's value to integer
    :return: The integer representation of the key's value in the dict params
    """
    try:
        if params:
            value: str = params.get(key, "")
            if value:
                params[key] = int(value)
                return params[key]
    except ValueError:
        raise Exception(f"This value for {key} must be an integer.")


def severity_num_to_string(severity_num: int) -> str:
    """
    transforms severity number to string representation
    :param severity_num: Severity score as Integer
    :return: Returns the String representation of the severity score
    """
    if severity_num == 1:
        return "Info"
    elif severity_num == 2:
        return "Low"
    elif severity_num == 3:
        return "Medium"
    elif severity_num == 4:
        return "High"
    elif severity_num == 5:
        return "Critical"
    return ""


def severity_string_to_num(severity_str: str) -> int:
    """
    :param severity_str: Severity score as String
    :return: Returns the Integer representation of the severity score
    """
    if severity_str == "Info":
        return 1
    elif severity_str == "Low":
        return 2
    elif severity_str == "Medium":
        return 3
    elif severity_str == "High":
        return 4
    elif severity_str == "Critical":
        return 5
    return -1


def alert_to_incident(alert: Dict) -> Dict:
    """
    transforms an alert to incident convention
    :param alert: alert is a dictionary
    :return: Incident - dictionary
    """
    alert_id: str = str(alert.get("id", ""))
    incident: Dict = {
        "rawJSON": json.dumps(alert),
        "name": f"ZeroFox Alert {alert_id}",
        "occurred": alert.get("timestamp", ""),
    }
    return incident


def alert_contents_request(alert_id: int) -> Dict:
    """
    returns updated contents of an alert
    :param alert_id: The ID of the alert - Integer
    :return: Dict of the contents of the alert
    """
    response_content: Dict = get_alert(alert_id)
    alert: Dict = response_content.get("alert", {})
    if not alert or not isinstance(alert, Dict):
        return {}
    contents: Dict = get_alert_contents(alert)
    return contents


def remove_none_dict(input_dict: Dict) -> Dict:
    """
    removes all none values from a dict
    :param input_dict: any dictionary in the world is OK
    :return: same dictionary but without None values
    """
    return {key: value for key, value in input_dict.items() if value is not None}


def get_alert_contents(alert: Dict) -> Dict:
    """
    :param alert: Alert is a dictionary
    :return: A dict representing the alert contents
    """
    return {
        "AlertType": alert.get("alert_type"),
        "OffendingContentURL": alert.get("offending_content_url"),
        "Assignee": alert.get("assignee"),
        "EntityID": alert.get("entity", {}).get("id") if alert.get("entity") else None,
        "EntityName": alert.get("entity", {}).get("name")
        if alert.get("entity")
        else None,
        "EntityImage": alert.get("entity", {}).get("image")
        if alert.get("entity")
        else None,
        "EntityTermID": alert.get("entity_term", {}).get("id")
        if alert.get("entity_term")
        else None,
        "EntityTermName": alert.get("entity_term", {}).get("name")
        if alert.get("entity_term")
        else None,
        "EntityTermDeleted": alert.get("entity_term", {}).get("deleted")
        if alert.get("entity_term")
        else None,
        "ContentCreatedAt": alert.get("content_created_at"),
        "ID": alert.get("id"),
        "ProtectedAccount": alert.get("protected_account"),
        "RiskRating": severity_num_to_string(int(alert["severity"])) if alert.get("severity") else None,  # type: ignore
        "PerpetratorName": alert.get("perpetrator", {}).get("name")
        if alert.get("perpetrator")
        else None,
        "PerpetratorURL": alert.get("perpetrator", {}).get("url")
        if alert.get("perpetrator")
        else None,
        "PerpetratorTimeStamp": alert.get("perpetrator", {}).get("timestamp")
        if alert.get("perpetrator")
        else None,
        "PerpetratorType": alert.get("perpetrator", {}).get("type")
        if alert.get("perpetrator")
        else None,
        "PerpetratorID": alert.get("perpetrator", {}).get("id")
        if alert.get("perpetrator")
        else None,
        "PerpetratorNetwork": alert.get("perpetrator", {}).get("network")
        if alert.get("perpetrator")
        else None,
        "RuleGroupID": alert.get("rule_group_id"),
        "Status": alert.get("status"),
        "Timestamp": alert.get("timestamp"),
        "RuleName": alert.get("rule_name"),
        "LastModified": alert.get("last_modified"),
        "ProtectedLocations": alert.get("protected_locations"),
        "DarkwebTerm": alert.get("darkweb_term"),
        "Reviewed": alert.get("reviewed"),
        "Escalated": alert.get("escalated"),
        "Network": alert.get("network"),
        "ProtectedSocialObject": alert.get("protected_social_object"),
        "Notes": alert.get("notes"),
        "RuleID": alert.get("rule_id"),
        "EntityAccount": alert.get("entity_account"),
        "Tags": alert.get("tags"),
    }


def get_alert_human_readable_outputs(contents: Dict) -> Dict:
    """
    returns the convention for the war room
    :param contents: Contents is a dictionary
    :return: A dict representation of the war room contents displayed to the user
    """
    return {
        "ID": contents.get("ID"),
        "Protected Entity": contents.get("EntityName", "").title(),
        "Content Type": contents.get("AlertType", "").title(),
        "Alert Date": contents.get("Timestamp", ""),
        "Status": contents.get("Status", "").title(),
        "Source": contents.get("Network", "").title(),
        "Rule": contents.get("RuleName"),
        "Risk Rating": contents.get("RiskRating"),
        "Notes": contents.get("Notes") if contents.get("Notes") else None,
        "Tags": contents.get("Tags"),
    }


def get_entity_contents(entity: Dict) -> Dict:
    """
    :param entity: Entity is a dictionary
    :return: A dict representation of the contents of entity
    """
    return {
        "ID": entity.get("id"),
        "Name": entity.get("name"),
        "EmailAddress": entity.get("email_address"),
        "Organization": entity.get("organization"),
        "Tags": entity.get("labels"),
        "StrictNameMatching": entity.get("strict_name_matching"),
        "PolicyID": entity.get("policy_id"),
        "Profile": entity.get("profile"),
        "EntityGroupID": entity.get("entity_group", {}).get("id")
        if entity.get("entity_group")
        else None,
        "EntityGroupName": entity.get("entity_group", {}).get("name")
        if entity.get("entity_group")
        else None,
        "TypeID": entity.get("type", {}).get("id") if entity.get("type") else None,
        "TypeName": entity.get("type", {}).get("name") if entity.get("type") else None,
    }


def get_entity_human_readable_outputs(contents: Dict) -> Dict:
    """
    returns the convention for the war room
    :param contents: Contents is a dictionary
    :return: A dict representation of the war room contents displayed to the user
    """
    return {
        "Name": contents.get("Name"),
        "Type": contents.get("TypeName"),
        "Policy": contents.get("PolicyID"),
        "Email": contents.get("EmailAddress"),
        "Tags": contents.get("Tags"),
        "ID": contents.get("ID"),
    }


def get_authorization_token() -> str:
    """
    :return: Returns the authorization token
    """
    integration_context: Dict = demisto.getIntegrationContext()
    token: str = integration_context.get("token", "")
    if token:
        return token
    url_suffix: str = "/1.0/api-token-auth/"
    data_for_request: Dict = {"username": USERNAME, "password": PASSWORD}
    response_content: Dict = _http_request(
        "POST", url_suffix, data=data_for_request, continue_err=True, header={}
    )
    token = response_content.get("token", "")
    if not token:
        if "res_content" in response_content:
            raise Exception("Failure resolving URL.")
        error_msg_list: List = response_content.get("non_field_errors", [])
        if not error_msg_list:
            raise Exception("Unable to log in with provided credentials.")
        else:
            raise Exception(error_msg_list[0])
    demisto.setIntegrationContext({"token": token})
    return token


def _is_cti_token_valid(token):
    url_suffix: str = "/auth/token/verify/"
    data_for_request: Dict = {"token": token}
    response: Dict = _http_request(
        "POST", url_suffix, data=data_for_request, continue_err=True, header={}
    )
    return bool(response)


def _get_new_access_token():
    url_suffix: str = "/auth/token/"
    data_for_request: Dict = {"username": USERNAME, "password": PASSWORD}
    response_content: Dict = _http_request(
        "POST", url_suffix, data=data_for_request, continue_err=True, header={}
    )
    return response_content.get("access", "")


def get_cti_authorization_token() -> str:
    """
    :return: returns the authorization token for the CTI feed
    """
    integration_context: Dict = demisto.getIntegrationContext()
    token: str = integration_context.get("cti_token", "")
    if token and _is_cti_token_valid(token):
        return token
    token = _get_new_access_token()
    if not token:
        raise Exception("Unable to retrieve token.")
    demisto.setIntegrationContext({"cti_token": token})
    return token


def get_api_request_header():
    token: str = get_authorization_token()
    return {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def get_cti_request_header():
    token: str = get_cti_authorization_token()
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _http_request(
    method: str,
    url_suffix: str,
    params: Dict = None,
    data: Union[Dict, str] = "",
    continue_err: bool = False,
    header: dict = {},
) -> Dict:
    """
    :param method: HTTP request type
    :param url_suffix: The suffix of the URL
    :param params: The request's query parameters
    :param data: The request's body parameters
    :param continue_err: A boolean flag to help us know if we want to show the error like we got it from
    the API, or if we want to parse the error message. If continue_err is False (default) we handle the error as
    we received it from the API, otherwise if continue_err is True we parse it.
    :param api_request: A boolean flag to help us know if the request is a regular API call or a token call.
    If api_request is False the call is to get Authorization Token, otherwise if api_request is True then it's a
    regular API call.
    :param version : api prefix to consider, default is to use version 1.0
    :return: Returns the content of the response received from the API.
    """
    try:
        err_msg: str
        res = requests.request(
            method,
            BASE_URL + url_suffix,
            verify=USE_SSL,
            params=params,
            data=data,
            headers=header,
        )
        # Handle error responses gracefully
        if res.status_code not in {200, 201} and not continue_err:
            err_msg = f"Error calling ZeroFox integration API [{res.status_code}] - {res.reason}\n"
            try:
                res_json = res.json()
                if "error" in res_json:
                    err_msg += res_json.get("error", "")
            except ValueError:
                err_msg += str(res.content)
            finally:
                raise ValueError(err_msg)
        else:
            try:
                if res.status_code not in {200, 201}:
                    try:
                        res_data = json.loads(res.text)
                    except ValueError:
                        raise Exception("Failure resolving URL.")
                    if isinstance(res_data, dict) and "non_field_errors" in res_data:
                        # case of wrong credentials
                        err_msg_list = res_data.get("non_field_errors")
                        if isinstance(err_msg_list, list) and err_msg_list:
                            raise Exception(err_msg_list[0])
                    else:
                        raise Exception("Failure resolving URL.")
                return res.json()
            except ValueError:
                return {"res_content": res.content}
    except requests.exceptions.ConnectTimeout:
        err_msg = (
            "Connection Timeout Error - incorrect server URL parameter"
            " or the Server cannot be accessed from your host."
        )
        raise Exception(err_msg)
    except requests.exceptions.SSLError:
        err_msg = (
            "Failure verying SSL certificate. Try selecting 'Trust any certificate' in"
            " the integration configuration."
        )
        raise Exception(err_msg)
    except requests.exceptions.ProxyError:
        err_msg = (
            "Proxy Error - try clearing 'Use system proxy' in the integration configuration if it has been"
            " selected."
        )
        raise Exception(err_msg)
    except requests.exceptions.ConnectionError as e:
        # Get originating Exception in Exception chain
        while "__context__" in dir(e) and e.__context__:
            e = cast(Any, e.__context__)
        err_msg = (
            f"\nMESSAGE: {e.strerror}\n"
            f"ADVICE: Check that the Server URL parameter is correct and that you"
            f" have access to the Server from your host."
        )
        raise Exception(err_msg)


def transform_alert_human_readable_header(header: str):
    transformations = {
        "EntityName": "Protected Entity",
        "AlertType": "Content Type",
        "Timestamp": "Alert Date",
        "Network": "Source",
        "RuleName": "Rule",
        "RiskRating": "Risk Rating",
        "OffendingContentURL": "Offending Content",
    }
    return transformations.get(header, header)


def transform_alert_human_readable_values(alert: Dict, title_keys: List[str] = []):
    transformed_alert = alert.copy()
    for key in title_keys:
        transformed_alert[key] = transformed_alert.get(key, "").title()
    return transformed_alert


def transform_alerts_human_readable_values(
    alerts: Union[Dict, List], title_keys: List[str] = []
):
    if isinstance(alerts, list):
        return [
            transform_alert_human_readable_values(alert, title_keys=title_keys)
            for alert in alerts
        ]
    elif isinstance(alerts, dict):
        return transform_alert_human_readable_values(alerts, title_keys=title_keys)


def get_human_readable_alerts(alerts: Union[Dict, List]):
    visible_keys: List = [
        "ID",
        "EntityName",
        "AlertType",
        "Timestamp",
        "Status",
        "OffendingContentURL",
        "Network",
        "RuleName",
        "RiskRating",
        "Notes",
        "Tags",
    ]
    title_keys = ["AlertType", "RuleName", "Network", "EntityName"]
    transformed_alerts = transform_alerts_human_readable_values(
        alerts, title_keys=title_keys
    )
    readable_output: str = tableToMarkdown(
        "ZeroFox Alerts",
        transformed_alerts,
        headers=visible_keys,
        date_fields=["Timestamp"],
        headerTransform=transform_alert_human_readable_header,
        removeNull=True,
    )
    return readable_output


def api_request(
    method: str,
    url_suffix: str,
    params: Dict = None,
    data: Union[Dict, str] = "",
    continue_err: bool = False,
    header: dict = get_api_request_header(),
    prefix="1.0",
) -> Dict:
    """
    :param method: HTTP request type
    :param url_suffix: The suffix of the URL
    :param params: The request's query parameters
    :param data: The request's body parameters
    :param continue_err: A boolean flag to help us know if we want to show the error like we got it from
    the API, or if we want to parse the error message. If continue_err is False (default) we handle the error as
    we received it from the API, otherwise if continue_err is True we parse it.
    :param api_request: A boolean flag to help us know if the request is a regular API call or a token call.
    If api_request is False the call is to get Authorization Token, otherwise if api_request is True then it's a
    regular API call.
    :param version : api prefix to consider, default is to use version 1.0
    :return: Returns the content of the response received from the API.
    """
    # A wrapper for requests lib to send our requests and handle requests and responses better
    pref_string = f"/{prefix}" if prefix else ""
    return _http_request(
        method=method,
        url_suffix=pref_string + url_suffix,
        params=params,
        data=data,
        continue_err=continue_err,
        header=header,
    )


def _retrieve_endpoint_results(keys: Dict, endpoint, request_body):
    request_body = remove_none_dict(request_body)
    response: Dict = api_request(
        "GET",
        f"/{endpoint}/",
        data=json.dumps(request_body),
        header=get_cti_request_header(),
        prefix="cti",
    )
    outputs = []
    for result in response.get("results", []):
        output = {k: v(result) for k, v in keys.items()}
        output["ZF source"] = endpoint
        outputs.append(output)
    return outputs


""" COMMANDS + REQUESTS FUNCTIONS """


def close_alert(alert_id: int) -> Dict:
    """
    :param alert_id: The ID of the alert.
    :return: HTTP request content.
    """
    url_suffix: str = f"/alerts/{alert_id}/close/"
    response_content: Dict = api_request("POST", url_suffix)
    return response_content


def close_alert_command():
    alert_id: int = dict_value_to_integer(demisto.args(), "alert_id")
    close_alert(alert_id)
    contents: Dict = alert_contents_request(alert_id)
    context: Dict = {
        "ZeroFox.Alert(val.ID && val.ID === obj.ID)": {
            "ID": alert_id,
            "Status": "Closed",
        }
    }
    return_outputs(
        f"Successfully closed Alert {alert_id}.", context, raw_response=contents
    )


def open_alert(alert_id: int) -> Dict:
    """
    :param alert_id: The ID of the alert.
    :return: HTTP request content.
    """
    url_suffix: str = f"/alerts/{alert_id}/open/"
    response_content: Dict = api_request("POST", url_suffix)
    return response_content


def open_alert_command():
    alert_id: int = dict_value_to_integer(demisto.args(), "alert_id")
    open_alert(alert_id)
    contents: Dict = alert_contents_request(alert_id)
    context: Dict = {
        "ZeroFox.Alert(val.ID && val.ID === obj.ID)": {"ID": alert_id, "Status": "Open"}
    }
    return_outputs(
        f"Successfully opened Alert {alert_id}.", context, raw_response=contents
    )


def alert_request_takedown(alert_id: int) -> Dict:
    """
    :param alert_id: The ID of the alert.
    :return: HTTP request content.
    """
    url_suffix: str = f"/alerts/{alert_id}/request_takedown/"
    response_content: Dict = api_request("POST", url_suffix)
    return response_content


def alert_request_takedown_command():
    alert_id: int = dict_value_to_integer(demisto.args(), "alert_id")
    alert_request_takedown(alert_id)
    contents: Dict = alert_contents_request(alert_id)
    context: Dict = {
        "ZeroFox.Alert(val.ID && val.ID === obj.ID)": {
            "ID": alert_id,
            "Status": "Takedown:Requested",
        }
    }
    return_outputs(
        f"Request to successfully take down Alert {alert_id}.",
        context,
        raw_response=contents,
    )


def alert_cancel_takedown(alert_id: int) -> Dict:
    """
    :param alert_id: The ID of the alert.
    :return: HTTP request content.
    """
    url_suffix: str = f"/alerts/{alert_id}/cancel_takedown/"
    response_content: Dict = api_request("POST", url_suffix)
    return response_content


def alert_cancel_takedown_command():
    alert_id: int = dict_value_to_integer(demisto.args(), "alert_id")
    alert_cancel_takedown(alert_id)
    contents: Dict = alert_contents_request(alert_id)
    context: Dict = {
        "ZeroFox.Alert(val.ID && val.ID === obj.ID)": {"ID": alert_id, "Status": "Open"}
    }
    return_outputs(
        f"Successful cancelled takedown of Alert {alert_id}.",
        context,
        raw_response=contents,
    )


def alert_user_assignment(alert_id: int, username: str) -> Dict:
    """
    :param alert_id: The ID of the alert.
    :param username: The username we want to assign to the alert.
    :return: HTTP request content.
    """
    url_suffix: str = f"/alerts/{alert_id}/assign/"
    request_body: str = json.dumps({"subject": username})
    response_content: Dict = api_request("POST", url_suffix, data=request_body)
    return response_content


def alert_user_assignment_command():
    alert_id: int = dict_value_to_integer(demisto.args(), "alert_id")
    username: str = demisto.args().get("username", "")
    alert_user_assignment(alert_id, username)
    contents: Dict = alert_contents_request(alert_id)
    context: Dict = {
        "ZeroFox.Alert(val.ID && val.ID === obj.ID)": {
            "ID": alert_id,
            "Assignee": username,
        }
    }
    return_outputs(
        f"Successful assignment of {username} to alert {alert_id}.",
        context,
        raw_response=contents,
    )


def modify_alert_tags(alert_id: int, action: str, tags_list_string: str) -> Dict:
    """
    :param alert_id: The ID of the alert.
    :param action: action can be 'added' or 'removed'. It indicates what action we want to do i.e add/remove tags/
    :param tags_list_string: A string representation of the tags, separated by a comma ','
    :return: HTTP request content.
    """
    url_suffix: str = "/alerttagchangeset/"
    tags_list: list = argToList(tags_list_string, separator=",")
    request_body: Dict = {"changes": [{f"{action}": tags_list, "alert": alert_id}]}
    response_content: Dict = api_request(
        "POST", url_suffix, data=json.dumps(request_body)
    )
    return response_content


def modify_alert_tags_command():
    alert_id: int = dict_value_to_integer(demisto.args(), "alert_id")
    action_string: str = demisto.args().get("action", "")
    action: str = "added" if action_string == "add" else "removed"
    tags_list_string: str = demisto.args().get("tags", "")
    response_content: Dict = modify_alert_tags(alert_id, action, tags_list_string)
    if not response_content.get("changes"):
        raise Exception(f"Alert with ID {alert_id} does not exist")
    contents: Dict = alert_contents_request(alert_id)
    context: Dict = {"ZeroFox.Alert(val.ID && val.ID === obj.ID)": contents}
    return_outputs("Successful modification of tags.", context)


def modify_alert_notes(alert_id: int, notes: str) -> Dict:
    """
    :param alert_id: The ID of the alert.
    :param notes: The notes for the alert.
    :return: HTTP request content.
    """
    url_suffix: str = f"/alerts/{alert_id}/"
    request_body: Dict = {"notes": notes}
    data: str = json.dumps(request_body)
    response_content: Dict = api_request("POST", url_suffix, data=data)
    return response_content


def modify_alert_notes_command():
    args = demisto.args()
    alert_id: int = dict_value_to_integer(args, "alert_id")
    alert_notes: str = args.get("notes", "")
    response_content: Dict = modify_alert_notes(alert_id, alert_notes)
    alert: Dict = response_content.get("alert", {})
    contents: Dict = get_alert_contents(alert)
    results = CommandResults(
        readable_output=f"Successful note modification of alert with ID: {alert_id}",
        outputs=contents,
        outputs_prefix="ZeroFox.Alert",
    )
    return_results(results)


def get_alert(alert_id: int) -> Dict:
    """
    :param alert_id: The ID of the alert.
    :return: HTTP request content.
    """
    url_suffix: str = f"/alerts/{alert_id}/"
    response_content: Dict = api_request("GET", url_suffix, continue_err=True)
    return response_content


def get_alert_command():
    alert_id: int = dict_value_to_integer(demisto.args(), "alert_id")
    response_content: Dict = get_alert(alert_id)
    alert: Dict = response_content.get("alert", {})
    if not alert or not isinstance(alert, Dict):
        raise Exception(f"Alert with ID {alert_id} does not exist")
    output: Dict = get_alert_contents(alert)
    readable_output: str = get_human_readable_alerts(output)
    return_results(
        CommandResults(
            outputs=output,
            outputs_prefix="ZeroFox.Alert",
            readable_output=readable_output,
        )
    )


def create_entity(
    name: str,
    strict_name_matching: bool = None,
    tags: list = None,
    policy: int = None,
    organization: str = None,
) -> Dict:
    """
    :param name: Name of the entity (may be non-unique).
    :param strict_name_matching: Indicating type of string matching for comparing name to impersonators.
    :param tags: List of string tags for tagging the entity. Seperated by a comma ','.
    :param policy: The ID of the policy to assign to the new entity.
    :param organization: Organization name associated with entity.
    :return: HTTP request content.
    """
    url_suffix: str = "/entities/"
    request_body: Dict = {
        "name": name,
        "strict_name_matching": strict_name_matching,
        "labels": tags,
        "policy": policy,
        "policy_id": policy,
        "organization": organization,
    }
    request_body = remove_none_dict(request_body)
    response_content: Dict = api_request(
        "POST", url_suffix, data=json.dumps(request_body)
    )
    return response_content


def create_entity_command():
    name: str = demisto.args().get("name", "")
    strict_name_matching: bool = bool(demisto.args().get("strict_name_matching", ""))
    tags: str = demisto.args().get("tags", "")
    tags: List = argToList(tags, ",")
    policy_id: int = dict_value_to_integer(demisto.args(), "policy_id")
    organization: str = demisto.args().get("organization", "")
    response_content: Dict = create_entity(
        name, strict_name_matching, tags, policy_id, organization
    )
    entity_id: int = response_content.get("id", "")
    return_outputs(
        f"Successful creation of entity. ID: {entity_id}.",
        {
            "ZeroFox.Entity(val.ID && val.ID === obj.ID)": {
                "ID": entity_id,
                "StrictNameMatching": strict_name_matching,
                "Name": name,
                "Tags": tags,
                "PolicyID": policy_id,
                "Organization": organization,
            }
        },
        response_content,
    )


def get_entity_types() -> Dict:
    """
    :return: HTTP request content.
    """
    url_suffix: str = "/entities/types/"
    response_content: Dict = api_request("GET", url_suffix)
    return response_content


def get_entity_types_command():
    response_content: Dict = get_entity_types()
    entity_types: List = response_content.get("results", [])
    human_readable = []
    for entity_type in entity_types:
        type_name: str = entity_type.get("name", "")
        type_id: int = entity_type.get("id", "")
        human_readable.append({"Name": type_name, "ID": type_id})
    headers = ["Name", "ID"]
    return_outputs(
        readable_output=tableToMarkdown(
            "ZeroFox Entity Types", human_readable, headers=headers, removeNull=True
        ),
        outputs={},
        raw_response=response_content,
    )


def get_policy_types() -> Dict:
    """
    :return: HTTP request content.
    """
    url_suffix: str = "/policies/"
    response_content: Dict = api_request("GET", url_suffix)
    return response_content


def get_policy_types_command():
    response_content: Dict = get_policy_types()
    policy_types: List = response_content.get("policies", [])
    human_readable = []
    for policy_type in policy_types:
        type_name: str = policy_type.get("name", "")
        type_id: int = policy_type.get("id", "")
        human_readable.append({"Name": type_name, "ID": type_id})
    headers = ["Name", "ID"]
    return_outputs(
        readable_output=tableToMarkdown(
            "ZeroFox Policy Types", human_readable, headers=headers, removeNull=True
        ),
        outputs={},
        raw_response=response_content,
    )


def list_alerts(params: Dict) -> Dict:
    """
    :param params: The request's body parameters.
    :return: HTTP request content.
    """
    url_suffix: str = "/alerts/"
    response_content: Dict = api_request("GET", url_suffix, params=params)
    return response_content


def list_alerts_command():
    params: Dict = remove_none_dict(demisto.args())
    # handle all integer query params
    for key in [
        "entity",
        "entity_term",
        "last_modified",
        "offset",
        "page_id",
        "rule_id",
    ]:
        dict_value_to_integer(params, key)
    # handle severity/risk_rating parameter - special case
    risk_rating_string: str = params.get("risk_rating", "")
    if risk_rating_string:
        del params["risk_rating"]
        params["severity"] = severity_string_to_num(risk_rating_string)
    # handle limit parameter - special case
    limit_str = params.get("limit")
    if limit_str:
        limit: int = dict_value_to_integer(params, "limit")
        if limit < 0 or limit > 100:
            raise Exception("Incorrect limit. Limit should be 0 <= x <= 100.")
    response_content: Dict = list_alerts(params)
    if not response_content:
        return_results(CommandResults(readable_output="No alerts found.", outputs=[]))
    elif isinstance(response_content, Dict):
        alerts: List = response_content.get("alerts", [])
        if not alerts:
            return_results(
                CommandResults(readable_output="No alerts found.", outputs=[])
            )
        else:
            output: List = [get_alert_contents(alert) for alert in alerts]
            readble_output: str = get_human_readable_alerts(output)
            return_results(
                CommandResults(
                    outputs=output,
                    readable_output=readble_output,
                    outputs_prefix="ZeroFox.Alert",
                )
            )
    else:
        return_results(CommandResults(readable_output="No alerts found.", outputs=[]))


def list_entities(params: Dict) -> Dict:
    """
    :param params: The request's body parameters.
    :return: HTTP request content.
    """
    url_suffix: str = "/entities/"
    response_content: Dict = api_request("GET", url_suffix, params=params)
    return response_content


def list_entities_command():
    params: Dict = remove_none_dict(demisto.args())
    # handle all integer query params
    for key in ["group", "label", "network", "page", "policy", "type"]:
        dict_value_to_integer(params, key)
    response_content: Dict = list_entities(params)
    if not response_content:
        return_outputs("No entities found.", outputs={})
    elif isinstance(response_content, Dict):
        entities: List = response_content.get("entities", [])
        if not entities:
            return_outputs("No entities found.", outputs={})
        else:
            contents: List = [get_entity_contents(entity) for entity in entities]
            human_readable: List = [
                get_entity_human_readable_outputs(content) for content in contents
            ]
            context: Dict = {"ZeroFox.Entity(val.ID && val.ID === obj.ID)": contents}
            headers: List = ["Name", "Type", "Policy", "Email", "Tags", "ID"]
            return_outputs(
                tableToMarkdown(
                    "ZeroFox Entities", human_readable, headers=headers, removeNull=True
                ),
                context,
                response_content,
            )
    else:
        return_outputs("No entities found.", outputs={})


def fetch_incidents():
    date_format = "%Y-%m-%dT%H:%M:%S"
    last_run = demisto.getLastRun()
    if last_run and last_run.get("last_fetched_event_timestamp"):
        last_update_time = last_run["last_fetched_event_timestamp"]
    else:
        last_update_time = parse_date_range(FETCH_TIME, date_format=date_format)[0]
    incidents = []
    limit: int = int(demisto.params().get("fetch_limit", ""))
    response_content = list_alerts(
        {"sort_direction": "asc", "limit": limit, "min_timestamp": last_update_time}
    )
    alerts: List = response_content.get("alerts", [])

    mirror_direction = 'In'
    integration_instance = demisto.integrationInstance()
    last_mirrored_in = int(datetime.now().timestamp() * 1000)
    if alerts:
        for alert in alerts:
            # Fields for mirroring alert
            alert['mirror_direction'] = mirror_direction
            alert['mirror_instance'] = integration_instance
            alert['last_mirrored_in'] = last_mirrored_in
            incident = alert_to_incident(alert)
            incidents.append(incident)
        # max_update_time is the timestamp of the last alert in alerts (alerts is a sorted list)
        last_alert_timestamp: str = str(alerts[-1].get("timestamp", ""))
        # ZeroFox is using full timestamp ISO 8061 format which includes the GMT field i.e (+00:00/-00:00)
        # The option to refine the search of alerts in the API is by the ISO 8061 format without the GMT field.
        if "+" in last_alert_timestamp:
            max_update_time = last_alert_timestamp.split("+")[0]
        else:
            max_update_time = last_alert_timestamp.split("-")[0]
        # add 1 second to last alert timestamp, in order to prevent duplicated alerts
        max_update_time = (
            datetime.strptime(max_update_time, date_format) + timedelta(seconds=1)
        ).isoformat()
        demisto.setLastRun({"last_fetched_event_timestamp": max_update_time})
    demisto.incidents(incidents)


def submit_threat_command():
    args = demisto.args()
    source: str = args.get("source", "")
    alert_type: str = args.get("alert_type", "")
    violation: str = args.get("violation", "")
    entity_id: str = args.get("entity_id", "")
    url_suffix: str = "/threat_submit/"
    request_body: Dict = {
        "source": source,
        "alert_type": alert_type,
        "violation": violation,
        "entity_id": entity_id,
    }
    request_body = remove_none_dict(request_body)
    response_content: Dict = api_request(
        "POST", url_suffix, data=json.dumps(request_body), prefix="2.0"
    )
    alert_id = response_content.get("alert_id")
    output = f"Successful submission of threat. ID: {alert_id}."
    return return_results(
        CommandResults(
            readable_output=output,
            raw_response=response_content,
            output={"ID": alert_id},
            outputs_prefix="ZeroFox.Alert",
        )
    )


def test_module():
    """
    Performs basic get request to get item samples
    """
    get_policy_types()
    demisto.results("ok")


def compromised_domain_command():
    domain: str = demisto.args().get("domain", "")
    outputs = []
    request_body: Dict = {
        "domain": domain,
    }
    c2_keys = {
        "Domain": lambda r: r["domain"],
        "Last_modified": lambda r: r["created_at"],
        "IPs": lambda r: ", ".join(r["ip_addresses"]),
    }
    outputs += _retrieve_endpoint_results(
        keys=c2_keys, endpoint="c2-domains", request_body=request_body
    )

    phishing_keys = {
        "Domain": lambda r: r["domain"],
        "Last_modified": lambda r: r["scanned"],
        "IPs": lambda r: r["host"]["ip"],
    }
    outputs += _retrieve_endpoint_results(
        keys=phishing_keys, endpoint="phishing", request_body=request_body
    )
    if len(outputs) == 0:
        return return_results(
            CommandResults(
                outputs="No compromised domains were found",
                outputs_prefix="ZeroFox.Alert",
            )
        )
    return return_results(
        CommandResults(
            outputs=outputs,
            readable_output=tableToMarkdown("Compromised domain Summary", outputs),
            outputs_prefix="ZeroFox.Alert",
        )
    )


def compromised_email_command():
    email: str = demisto.args().get("email", "")
    outputs = []
    request_body: Dict = {
        "email": email,
    }
    keys = {
        "domain": lambda r: r["domain"],
        "email": lambda r: r["email"],
        "Created at": lambda r: r["created_at"],
    }
    outputs += _retrieve_endpoint_results(keys=keys, endpoint="email-addresses", request_body=request_body)
    outputs += _retrieve_endpoint_results(keys, endpoint="compromised-credentials", request_body=request_body)
    outputs += _retrieve_endpoint_results(keys, endpoint="botnet-compromised-credentials", request_body=request_body)

    if len(outputs) == 0:
        return return_results(
            CommandResults(
                outputs="No compromised emails were found",
                outputs_prefix="ZeroFox.Alert",
            )
        )
    return return_results(
        CommandResults(
            outputs=outputs,
            readable_output=tableToMarkdown("Compromised email Summary", outputs),
            outputs_prefix="ZeroFox.Alert",
        )
    )


def malicious_ip_command():
    ip: str = demisto.args().get("ip", "")
    outputs = []
    botnet_body: Dict = {
        "ip": ip,
    }
    botnet_keys = {
        "Created at": lambda r: r["acquired_at"],
        "ip address": lambda r: r["ip_address"],
        "Domain": lambda r: r["c2_domain"],
    }
    outputs += _retrieve_endpoint_results(
        keys=botnet_keys, endpoint="botnet", request_body=botnet_body
    )

    phishing_body: Dict = {
        "host_ip": ip,
    }
    phishing_keys = {
        "Created at": lambda r: r["scanned"],
        "ip address": lambda r: r["host"]["ip"],
        "Domain": lambda r: r["domain"],
    }
    outputs += _retrieve_endpoint_results(
        keys=phishing_keys, endpoint="phishing", request_body=phishing_body
    )

    if len(outputs) == 0:
        return return_results(
            CommandResults(
                outputs="No malicious ips were found", outputs_prefix="ZeroFox.Alert"
            )
        )
    return return_results(
        CommandResults(
            outputs=outputs,
            readable_output=tableToMarkdown("Malicious ip Summary", outputs),
            outputs_prefix="ZeroFox.Alert",
        )
    )


def malicious_hash_command():
    hash: str = demisto.args().get("hash", "")
    outputs = []
    hash_keys = {
        "Created at": lambda r: r["created_at"],
        "Family": lambda r: ", ".join(r["family"]) if r["family"] else "",
        "md5": lambda r: r["md5"],
        "sha1": lambda r: r["sha1"],
        "sha256": lambda r: r["sha256"],
        "sha512": lambda r: r["sha512"],
    }

    for hash_type in ["md5", "sha1", "sha256", "sha512"]:
        hash_keys["Found hash"] = lambda r: hash_type
        hash_body: Dict = {hash_type: hash}
        outputs += _retrieve_endpoint_results(
            keys=hash_keys, endpoint="malware", request_body=hash_body
        )

    if len(outputs) == 0:
        return return_results(
            CommandResults(
                outputs="No malicious hashes were found", outputs_prefix="ZeroFox.Alert"
            )
        )
    return return_results(
        CommandResults(
            outputs=outputs,
            readable_output=tableToMarkdown("Malicious hash Summary", outputs),
            outputs_prefix="ZeroFox.Alert",
        )
    )


def search_exploit_command():
    since: str = demisto.args().get("since", "")
    outputs = []
    request_body: Dict = {
        "created_after": since,
    }
    exploit_keys = {
        "Created at": lambda r: r["created_at"],
        "CVE code": lambda r: r["cve"],
        "urls": lambda r: ", ".join(r["urls"]),
    }
    outputs += _retrieve_endpoint_results(
        keys=exploit_keys, endpoint="exploits", request_body=request_body
    )

    if len(outputs) == 0:
        return return_results(
            CommandResults(
                outputs="No exploits were found", outputs_prefix="ZeroFox.Alert"
            )
        )
    return return_results(
        CommandResults(
            outputs=outputs,
            readable_output=tableToMarkdown("Exploit Search Summary", outputs),
            outputs_prefix="ZeroFox.Alert",
        )
    )


def get_modified_remote_data_command():
    raw_args = demisto.args()
    if not raw_args.get('lastUpdate'):
        raw_args = {'lastUpdate': datetime.now() - timedelta(days=1)}
    args = GetModifiedRemoteDataArgs(raw_args)
    last_update = args.last_update

    # Get alerts created before `last_update` and modified after `last_update`
    list_alert_params = {
        "last_modified_min_date": str(last_update),
        "max_timestamp": str(last_update),
    }
    response_content = list_alerts(list_alert_params)
    modified_alerts = response_content.get("alerts", [])
    modified_alert_ids = [alert.get("id") for alert in modified_alerts]

    return return_results(GetModifiedRemoteDataResponse(modified_alert_ids))


def get_remote_data_command():
    args = demisto.args()
    remote_args = GetRemoteDataArgs(args)
    alert_id = remote_args.remote_incident_id

    response_content = get_alert(alert_id)
    alert = response_content.get("alert", {})

    entries = []
    if alert.get("status") in CLOSED_ALERT_STATUS:
        entries.append({"Contents": {"dbotIncidentClose": True}})

    return return_results(GetRemoteDataResponse(mirrored_object=alert, entries=entries))


def get_mapping_fields_command():
    incident_type_scheme = SchemeTypeMapping(type_name='ZeroFox Mapping')
    return GetMappingFieldsResponse(incident_type_scheme)


""" COMMANDS MANAGER / SWITCH PANEL """


def main():
    commands = {
        "test-module": test_module,
        "fetch-incidents": fetch_incidents,
        "get-modified-remote-data": get_modified_remote_data_command,
        "get-remote-data": get_remote_data_command,
        "get-mapping-fields": get_mapping_fields_command,
        "zerofox-get-alert": get_alert_command,
        "zerofox-alert-user-assignment": alert_user_assignment_command,
        "zerofox-close-alert": close_alert_command,
        "zerofox-open-alert": open_alert_command,
        "zerofox-alert-request-takedown": alert_request_takedown_command,
        "zerofox-alert-cancel-takedown": alert_cancel_takedown_command,
        "zerofox-modify-alert-tags": modify_alert_tags_command,
        "zerofox-create-entity": create_entity_command,
        "zerofox-list-alerts": list_alerts_command,
        "zerofox-list-entities": list_entities_command,
        "zerofox-get-entity-types": get_entity_types_command,
        "zerofox-get-policy-types": get_policy_types_command,
        "zerofox-modify-alert-notes": modify_alert_notes_command,
        "zerofox-submit-threat": submit_threat_command,
        "zerofox-search-compromised-domain": compromised_domain_command,
        "zerofox-search-compromised-email": compromised_email_command,
        "zerofox-search-malicious-ip": malicious_ip_command,
        "zerofox-search-malicious-hash": malicious_hash_command,
        "zerofox-search-exploit": search_exploit_command,
    }
    try:
        handle_proxy()
        commands[demisto.command()]()

    # Log exceptions
    except Exception as e:
        error_msg: str = str(e)
        if demisto.command() == "fetch-incidents":
            LOG(error_msg)
            LOG.print_log()
            raise
        else:
            return_error(error_msg)


if __name__ == "builtins":
    main()
