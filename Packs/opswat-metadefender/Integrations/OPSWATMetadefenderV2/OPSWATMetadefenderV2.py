import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import shutil

""" GLOBAL VARS """
PARAMS = demisto.params()
BASE_URL = PARAMS["url"] + "/" if PARAMS["url"][-1] != "/" else PARAMS["url"]
USE_SSL = not PARAMS.get("insecure", False)
API_KEY = PARAMS.get("api_key_creds", {}).get("password") or PARAMS.get("api_key", "")
USE_CLOUD = PARAMS.get("cloud", False)
HIGH_THRESHOLD = int(PARAMS.get("highPercnt", 66))
LOW_THRESHOLD = int(PARAMS.get("lowPercnt", 34))

DEFAULT_HEADERS = {"Accept": "application/json"}

HTTP_ERROR_CODES = {
    "400": "Request failed, got status 400: bad request. Check command parameters",
    "401": "Request failed, got status 401: unauthorized. Check your API Key",
    "404": "Request failed, got status 404: not found. Check integration URL Address",
}

""" HELPER FUNCTIONS """


def http_req(method="GET", url_suffix="", file_name=None, parse_json=True, scan_rule=None):
    data = None
    url = BASE_URL + url_suffix
    headers = DEFAULT_HEADERS
    if USE_CLOUD:
        headers["apikey"] = API_KEY
    if scan_rule:
        demisto.debug(f"Using explicit rule: {scan_rule}")
        headers["rule"] = scan_rule.encode("utf-8")
    if file_name:
        headers["filename"] = file_name.encode("utf-8")  # type: ignore
        with open(file_name, "rb") as file_:
            res = requests.post(url, verify=USE_SSL, files={"file": file_}, headers=headers)
    elif method.upper() == "GET":
        res = requests.get(url, verify=USE_SSL, headers=headers)
    elif method.upper() == "POST":
        res = requests.post(url, verify=USE_SSL, data=data, headers=headers)
    else:
        return_error(f"Got unsupporthed http method: {method}")
        return ""
    status = res.status_code
    if status != 200:
        if str(status) in HTTP_ERROR_CODES:
            return_error(HTTP_ERROR_CODES[str(status)])
        else:
            return_error(f"Request failed got status {status}")
    if parse_json:
        return res.json()
    else:
        return res.content


def scan_file(file_entry_id, scan_rule=None):
    try:
        file_entry = demisto.getFilePath(file_entry_id)
    except ValueError as e:
        return_error(f'Failed to find file entry with id:"{file_entry_id}". got error: {e}')
    file_name = file_entry["name"]
    shutil.copy(file_entry["path"], file_name)
    try:
        res = http_req(method="POST", url_suffix="file", file_name=file_name, scan_rule=scan_rule)
    finally:
        shutil.rmtree(file_name, ignore_errors=True)
    return res, file_name


def get_hash_info(file_hash):
    res = http_req(method="GET", url_suffix=f"hash/{file_hash}")
    return res


def get_scan_result(scan_id):
    res = http_req(method="GET", url_suffix=f"file/{scan_id}")
    return res


def get_dbot_file_context(file_hash, dbotscore):
    return {"Indicator": file_hash, "Type": "file", "Vendor": "OPSWAT", "Score": dbotscore}


def get_sanitized_file(scan_id):
    return http_req(method="GET", url_suffix=f"file/converted/{scan_id}", parse_json=False)


def get_hash_info_command():
    file_hash = demisto.args()["hash"]
    res = get_hash_info(file_hash)
    ec = {}
    md = "# OPSWAT-Metadefender\n"
    dbotScore = 0

    if "file_info" in res:
        file_info = res["file_info"]
        display_name = file_info["display_name"]
        scan_results = res["scan_results"]
        file_type_description = file_info["file_type_description"]
        scan_all_result_a = scan_results["scan_all_result_a"]
        total_avs = scan_results["total_avs"]
        scan_details = scan_results["scan_details"]
        total_detected_avs = 0
        if "total_detected_avs" in scan_results:
            total_detected_avs = scan_results["total_detected_avs"]
        else:
            for key in scan_details:
                if scan_details[key]["threat_found"] != "":
                    total_detected_avs = total_detected_avs + 1

        md += f"File name: {display_name}\n"
        md += f"File description: {file_type_description}\n"
        md += f"Scan result: {scan_all_result_a}\n"
        md += f"Detected AV: {total_detected_avs}/{total_avs}\n"
        md += "AV Name|Def Time|Threat Name Found\n"
        md += "---|---|---\n"

        for key, scan in scan_details.items():
            def_time = scan["def_time"]
            threat_found = scan["threat_found"]
            md += f"{key}|{def_time}|{threat_found}\n"
        percntBad = (total_detected_avs / total_avs) * 100
        if percntBad >= HIGH_THRESHOLD:
            dbotScore = 3
            ec[outputPaths["file"]] = {
                "Hash": file_hash,
                "Malicious": {"Vendor": "OPSWAT", "Description": "Result from OPSWAT-Metadefender"},
            }
        elif percntBad >= LOW_THRESHOLD:
            dbotScore = 2
        else:
            dbotScore = 1

        if is_demisto_version_ge("5.5.0"):
            ec[
                "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type"
                " == obj.Type)"
            ] = get_dbot_file_context(file_hash, dbotScore)

        else:
            ec["DBotScore"] = get_dbot_file_context(file_hash, dbotScore)

    else:
        md += f"No results for hash {file_hash}\n"
    entry = {
        "ContentsFormat": formats["json"],
        "Type": entryTypes["note"],
        "Contents": res,
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": md,
        "EntryContext": ec,
    }
    demisto.results(entry)


def scan_file_command():
    file_entry_id = demisto.args()["fileId"]
    scan_rule_name = demisto.args().get("scanRule")
    res, file_name = scan_file(file_entry_id, scan_rule_name)
    scan_id = res["data_id"]
    md = "# OPSWAT-Metadefender\n"
    ec = {"OPSWAT": {"FileName": file_name, "ScanId": scan_id}}

    md += "The file has been successfully submitted to scan.\n"
    md += f"Scan id: {scan_id}\n"
    entry = {
        "ContentsFormat": formats["json"],
        "Type": entryTypes["note"],
        "Contents": res,
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": md,
        "EntryContext": ec,
    }
    demisto.results(entry)


def get_scan_result_command():
    scan_id = demisto.args()["id"]
    res = get_scan_result(scan_id)
    md = "# OPSWAT-Metadefender\n"
    md += f"### Results for scan id {scan_id}\n"
    ec = {}
    dbotScore = 0

    if "file_info" in res and "file_type_description" in res["file_info"]:
        file_info = res["file_info"]
        process_info = res["process_info"]
        display_name = file_info["display_name"]
        progress_percentage = process_info["progress_percentage"]
        if progress_percentage < 100:
            md += f"### The scan proccess is in progrees (done: {progress_percentage}%) \n"
        md += f"File name: {display_name}\n"
        if "scan_results" in res:
            scan_results = res["scan_results"]
            total_avs = scan_results["total_avs"]
            scan_all_result_a = scan_results["scan_all_result_a"]
            scan_all_result_i = scan_results["scan_all_result_i"]
            md += f"Scan result:{scan_all_result_a}\n"
            md += f"Detected AV: {scan_all_result_i}/{total_avs}\n"
            md += "AV Name|Def Time|Threat Name Found\n"
            md += "---|---|---\n"
            avRes = scan_results["scan_details"]
            for key, scan in avRes.items():
                def_time = scan["def_time"]
                threat_found = scan["threat_found"]
                md += f"{key}|{def_time}|{threat_found}\n"
            percntBad = (scan_all_result_i / total_avs) * 100

            ec[f"OPSWAT(val.ScanId == {scan_id}).ScanProgress"] = progress_percentage
            ec[f"OPSWAT(val.ScanId == {scan_id}).PercentageBad"] = percntBad
            ec[f"OPSWAT(val.ScanId == {scan_id}).Result"] = scan_all_result_a

            if percntBad >= percntBad >= HIGH_THRESHOLD:
                dbotScore = 3
                ec[outputPaths["file"]] = {
                    "Hash": file_info["md5"],
                    "MD5": file_info["md5"],
                    "Malicious": {"Vendor": "OPSWAT", "Description": "Result from OPSWAT-Metadefender"},
                }
            elif percntBad >= LOW_THRESHOLD:
                dbotScore = 2
            else:
                dbotScore = 1

            file_md5_hash = file_info["md5"]
            if is_demisto_version_ge("5.5.0"):
                ec[
                    "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type"
                    " == obj.Type)"
                ] = get_dbot_file_context(file_md5_hash, dbotScore)

            else:
                ec["DBotScore"] = get_dbot_file_context(file_md5_hash, dbotScore)

    else:
        md += "No results for this id\n"
    entry = {
        "ContentsFormat": formats["json"],
        "Type": entryTypes["note"],
        "Contents": res,
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": md,
        "EntryContext": ec,
    }
    demisto.results(entry)


def get_sanitized_file_command():
    """
    Get OPSWAT sanitization result (Requires CDR feature).
    Args:
        scan_id(int): The scan id.

    Returns:
        (demisto.Results).
    """
    scan_id = demisto.args()["id"]
    res = get_scan_result(scan_id)
    # Check the scan report whether there is a sanitized file.
    if res.get("process_info", {}).get("post_processing", {}).get("actions_ran") == "Sanitized":
        sanitized_file_name = res["process_info"]["post_processing"].get("converted_destination", "sanitized.file")
        res = get_sanitized_file(scan_id)
        demisto.results(fileResult(filename=sanitized_file_name, data=res, file_type=EntryType.ENTRY_INFO_FILE))
    else:
        demisto.results({"Type": entryTypes["warning"], "ContentsFormat": formats["text"], "Contents": "No sanitized file."})


""" COMMANDS MANAGER / SWITCH PANEL """


def main():  # pragma: no cover
    command = demisto.command()
    demisto.info(f"Command being called is: {command}")

    try:
        # Remove proxy if not set to true in params
        handle_proxy()

        if command == "test-module":
            # This is the call made when pressing the integration test button.
            get_hash_info("66DA1A91E1ED5D59BECFAD85F53C05F9")
            demisto.results("ok")
        if command == "opswat-scan-file":
            scan_file_command()
        if command == "opswat-hash":
            get_hash_info_command()
        if command == "opswat-scan-result":
            get_scan_result_command()
        if command == "opswat-sanitization-result":
            get_sanitized_file_command()
    except Exception as e:
        message = f"Unexpected error: {e}"
        demisto.error(str(e))
        return_error(message)


if __name__ in ["__builtin__", "builtins", "__main__"]:  # pragma: no cover
    main()
