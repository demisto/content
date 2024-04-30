import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests


def get_assets(api_token):
    url = "https://api.brandefense.io/api/v1/assets"
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": "Bearer " + api_token,
    }
    response = requests.get(url, headers=headers)
    allassets = {"assets": response.json()}
    result = CommandResults(outputs=allassets, outputs_prefix="branddefense_assets")
    return_results(result)


def get_specific_asset(api_token, args):
    asset_id = args.get("assetid")
    url = "https://api.brandefense.io/api/v1/assets/" + str(asset_id)
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": "Bearer " + api_token,
    }
    response = requests.get(url, headers=headers)
    requestedasset = {"assets": response.json()}
    result = CommandResults(
        outputs=requestedasset, outputs_prefix="branddefense_requested_asset"
    )
    return_results(result)
    return result


def get_audit_logs(api_token):
    url = "https://api.brandefense.io/api/v1/audit-logs"
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": "Bearer " + api_token,
    }
    response = requests.get(url, headers=headers)
    auditlogs = {"auditlogs": response.json()}
    result = CommandResults(outputs=auditlogs, outputs_prefix="branddefense_audit_logs")
    return_results(result)
    return result


def get_specific_audit_log(api_token, args):
    audit_log_id = args.get("audit_log_id")
    url = "https://api.brandefense.io/api/v1/audit-logs/" + str(audit_log_id)
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": "Bearer " + api_token,
    }
    response = requests.get(url, headers=headers)
    requestedauditlog = {"requestedauditlog": response.json()}
    result = CommandResults(
        outputs=requestedauditlog, outputs_prefix="branddefense_requested_audit_log"
    )
    return_results(result)
    return result


def get_threat_search(api_token, args):
    uuid = args.get("search_uuid")
    uuid = str(uuid)
    url = "https://api.brandefense.io/api/v1/cti/threat-search/" + uuid
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": "Bearer " + api_token,
    }
    response = requests.get(url, headers=headers)
    search_result = {"sarch_result": response.json()}
    result = CommandResults(outputs=search_result, outputs_prefix="search_result")
    return_results(result)
    return result


def get_specific_incident(api_token, args):
    incident_code = args.get("incident_code")
    incident_code = str(incident_code)
    url = "https://api.brandefense.io/api/v1/incidents/" + incident_code
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": "Bearer " + api_token,
    }
    response = requests.get(url, headers=headers)
    branddefense_requested_incident = {
        "branddefense_requested_incident": response.json()
    }
    result = CommandResults(
        outputs=branddefense_requested_incident,
        outputs_prefix="branddefense_requested_incident",
    )
    return_results(result)
    return result


def change_incident_status(api_token, args):
    incident_code = args.get("incident_code")
    incident_code = str(incident_code)
    incident_status = args.get("incident_status")
    incident_status = str(incident_status)
    url = (
        "https://api.brandefense.io/api/v1/incidents/"
        + incident_code
        + "/change-status"
    )
    payload = {"status": incident_status}
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": "Bearer " + api_token,
    }
    response = requests.patch(url, json=payload, headers=headers)
    incident_status_to_changed = {"incident_status_to_changed": response.json()}
    result = CommandResults(
        outputs=incident_status_to_changed, outputs_prefix="incident_status_to_changed"
    )
    return_results(result)
    return result


def get_incident_indicators(api_token, args):
    incident_code = args.get("incident_code")
    incident_code = str(incident_code)
    url = "https://api.brandefense.io/api/v1/incidents/" + incident_code + "/indicators"
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": "Bearer " + api_token,
    }
    response = requests.get(url, headers=headers)
    branddefense_requested_incident_indicators = {
        "branddefense_requested_incident_indicators": response.json()
    }
    result = CommandResults(
        outputs=branddefense_requested_incident_indicators,
        outputs_prefix="branddefense_requested_incident_indicators",
    )
    return_results(result)
    return result


def get_indicator(api_token, args):
    indicator_type = args.get("indicator_type")
    indicator_type = str(indicator_type)
    url = "https://api.brandefense.io/api/v1/indicators"
    querystring = {"indicator_type": indicator_type}
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": "Bearer " + api_token,
    }
    response = requests.get(url, headers=headers, params=querystring)
    branddefense_requested_indicator = {
        "branddefense_requested_indicator": response.json()
    }
    result = CommandResults(
        outputs=branddefense_requested_indicator,
        outputs_prefix="branddefense_requested_indicator",
    )
    return_results(result)
    return result


def get_ioc(api_token, args):
    ioc_type = args.get("ioc_type")
    url = "https://api.brandefense.io/api/v1/threat-intelligence/iocs"
    querystring = {"ioc_type": ioc_type}
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": "Bearer " + api_token,
    }
    response = requests.get(url, headers=headers, params=querystring)
    branddefense_ioc = {"branddefense_ioc": response.json()}
    result = CommandResults(outputs=branddefense_ioc, outputs_prefix="branddefense_ioc")
    return_results(result)
    return result


def get_cti_rules(api_token, args):
    url = "https://api.brandefense.io/api/v1/threat-intelligence/rules"
    search = args.get("search")
    tag = args.get("tag")
    source = args.get("source__ilike")
    querystring = {"tag": tag, "search": search, "source__ilike": source}
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": "Bearer " + api_token,
    }
    try:
        response = requests.get(url, headers=headers, params=querystring)
    except Exception:
        response = requests.get(url, headers=headers)
    branddefense_cti_rules = {"branddefense_cti_rules": response.json()}
    result = CommandResults(
        outputs=branddefense_cti_rules, outputs_prefix="branddefense_cti_rules"
    )
    return_results(result)
    return result


def create_threat_search(api_token, args):
    value = args.get("value")
    value = str(value)
    url = "https://api.brandefense.io/api/v1/cti/threat-search"
    payload = {"value": value}
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": "Bearer " + api_token,
    }
    response = requests.post(url, json=payload, headers=headers)
    search_start = {"sarch_created": response.json()}
    result = CommandResults(outputs=search_start, outputs_prefix="search_start")
    return_results(result)
    return result


def get_incidents(api_token, args):
    created_at = args.get("created_at")
    url = "https://api.brandefense.io/api/v1/incidents"
    querystring = {"created_at__range": str(created_at)}
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": "Bearer " + api_token,
    }
    response = requests.get(url, headers=headers, params=querystring)
    branddefense_all_incidents = {"branddefense_incidents": response.json()}
    result = CommandResults(
        outputs=branddefense_all_incidents, outputs_prefix="branddefense_all_incidents"
    )
    return_results(result)
    return result


def test_module(api_token, args, params):
    url = params.get("url", "https://api.brandefense.io/api/v1/incidents")
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": "Bearer " + api_token,
    }
    try:
        test = requests.get(url, headers=headers)
        if test.status_code == 200:
            return_results("ok")
        elif test.status_code == 401 or test.status_code == 403:
            return_results("Authorization Error: make sure API Key is correctly set")
        else:
            return_results(f"Unexpected error status code: {test.status_code}")
    except Exception as e:
        if "Forbidden" in str(e):
            return_results("Authorization Error: make sure API Key is correctly set")
        else:
            raise e


def main():
    args = demisto.args()
    command = demisto.command()
    params = demisto.params()
    api_token = params.get("credentials", {}).get("password")
    try:
        if command == "branddefense-get-assets":
            get_assets(api_token)
        elif command == "branddefense-get-specific-asset":
            get_specific_asset(api_token, args)
        elif command == "branddefense-get-audit-logs":
            get_audit_logs(api_token)
        elif command == "branddefense-get-specific-audit-log":
            get_specific_audit_log(api_token, args)
        elif command == "branddefense-get-threat-search":
            get_threat_search(api_token, args)
        elif command == "branddefense-get-specific-incident":
            get_specific_incident(api_token, args)
        elif command == "branddefense-change-incident-status":
            change_incident_status(api_token, args)
        elif command == "branddefense-get-incident-indicators":
            get_incident_indicators(api_token, args)
        elif command == "branddefense-get-indicators":
            get_indicator(api_token, args)
        elif command == "branddefense-get-ioc":
            get_ioc(api_token, args)
        elif command == "branddefense-get-cti-rules":
            get_cti_rules(api_token, args)
        elif command == "branddefense-create-threat-search":
            create_threat_search(api_token, args)
        elif command == "branddefense-get-incidents":
            get_incidents(api_token, args)
        elif command == "test-module":
            test_module(api_token, args, params)
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
