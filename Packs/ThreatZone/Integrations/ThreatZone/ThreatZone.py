import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import urllib3
import requests
from typing import Any, Dict

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def threatzone_add(self, param: dict) -> Dict[str, Any]:
        """Sends the sample to ThreatZone url using the '/public-api/scan/' API endpoint

        :return: dict containing the sample uuid as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        payload = []
        if param["scan_type"] == "sandbox":
            payload = [
                {"metafieldId": "environment", "value": param["environment"]},
                {"metafieldId": "private", "value": param["private"]},
                {"metafieldId": "timeout", "value": param["timeout"]},
                {"metafieldId": "work_path", "value": param["work_path"]},
                {"metafieldId": "mouse_simulation", "value": param["mouse_simulation"]},
                {"metafieldId": "https_inspection", "value": param["https_inspection"]},
                {"metafieldId": "internet_connection", "value": param["internet_connection"]},
                {"metafieldId": "raw_logs", "value": param["raw_logs"]},
                {"metafieldId": "snapshot", "value": param["snapshot"]},
            ]
        suffix = "/public-api/scan/" + param["scan_type"]
        return self._http_request(method="POST", url_suffix=suffix, data=payload, files=param["files"])

    def threatzone_get(self, param: dict) -> Dict[str, Any]:
        """Gets the sample scan result from ThreatZone using the '/public-api/get/submission/' API endpoint

        :return: dict containing the sample scan results as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        return self._http_request(method="GET", url_suffix="/public-api/get/submission/" + param["uuid"])

    def threatzone_get_sanitized(self, uuid):
        # next patch
        return ""

    def threatzone_me(self):
        """
        :return: dict containing limit data returned from the API
        :rtype: ``Dict[str, Any]``
        """
        return self._http_request(method="GET", url_suffix="/public-api/me")

    def threatzone_check_limits(self, type):
        """Checks limits using the '/public-api/me' API endpoint
        :return: dict containing limit data returned from the API
        :rtype: ``Dict[str, Any]``
        """
        api_me = self.threatzone_me()
        acc_email = api_me["userInfo"]["email"]
        limits_count = api_me["userInfo"]["limitsCount"]
        submission_limits = api_me["plan"]["submissionLimits"]
        available_api = submission_limits["apiLimit"] - limits_count["apiRequestCount"]
        available_submission = submission_limits["dailyLimit"] - limits_count["dailySubmissionCount"]
        available_concurrent = submission_limits["concurrentLimit"] - limits_count["concurrentSubmissionCount"]
        limits = {
            "E_Mail": f"{acc_email}",
            "Daily_Submission_Limit": f"{limits_count['dailySubmissionCount']}/{submission_limits['dailyLimit']}",
            "Concurrent_Limit": f"{limits_count['concurrentSubmissionCount']}/{submission_limits['concurrentLimit']}",
            "API_Limit": f"{limits_count['apiRequestCount']}/{submission_limits['apiLimit']}",
        }
        if available_api < 1:
            return {
                "available": False,
                "Limits": limits,
                "Reason": f"API request limit ({submission_limits['apiLimit']}) exceeded",
                "Suggestion": "Upgrade your plan or contact us.",
            }
        elif available_submission < 1:
            return {
                "available": False,
                "Limits": limits,
                "Reason": f"Daily submission limit({submission_limits['dailyLimit']})  exceeded",
                "Suggestion": "Upgrade your plan or contact us.",
            }
        elif available_concurrent < 1 and type == "sandbox":
            return {
                "available": False,
                "Limits": limits,
                "Reason": f"Concurrent analysis limit ({submission_limits['concurrentLimit']}) exceeded.",
                "Suggestion": "Upgrade your plan or wait for previous sandbox analyzes to finish.",
            }
        else:
            return {
                "available": True,
                "Limits": limits,
            }


def test_module(params) -> str:
    """Tests API connectivity and authentication'"
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.
    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    try:
        url = params.get("url")[:-1] if str(params.get("url")).endswith("/") else params.get("url")
        credentials = params.get("apikey")
        creds = "Bearer " + credentials
        headers = {"Authorization": creds}
        url = urljoin(url, "/public-api/get/submission/41704f61-6f3f-4241-9e81-f13f9e532e37")
        response = requests.request("GET", url, headers=headers)
        status = response.status_code
        if status != 200:
            if "UnauthorizedError" in str(response.content):
                return "Authorization Error: make sure API Key is correctly set"
            else:
                return str(status)
    except Exception as e:
        raise e
    return "ok"


def encode_file_name(file_name):
    """
    encodes the file name - i.e ignoring non ASCII chars and removing backslashes
    Args:
        file_name (str): name of the file
    Returns: encoded file name
    """
    return file_name.encode("ascii", "ignore")


def translate_score(
    score: int,
) -> int:
    """Translate ThreatZone threat level to DBot score enum."""
    if score == 0:
        return Common.DBotScore.NONE
    elif score == 1:
        return Common.DBotScore.GOOD
    elif score == 2:
        return Common.DBotScore.SUSPICIOUS
    else:
        return Common.DBotScore.BAD


def get_reputation_reliability(reliability):
    if reliability == "A+ - 3rd party enrichment":
        return DBotScoreReliability.A_PLUS
    if reliability == "A - Completely reliable":
        return DBotScoreReliability.A
    if reliability == "B - Usually reliable":
        return DBotScoreReliability.B
    if reliability == "C - Fairly reliable":
        return DBotScoreReliability.C
    if reliability == "D - Not usually reliable":
        return DBotScoreReliability.D
    if reliability == "E - Unreliable":
        return DBotScoreReliability.E
    if reliability == "F - Reliability cannot be judged":
        return DBotScoreReliability.F
    return None


def generate_dbotscore(indicator, report, score, type_of_indicator=None):
    """Creates DBotScore object based on the content of 'indicator' argument
    :type indicator: ``str``
    :param indicator: The value of the indicator

    :type report: ``dict``
    :param report: The readable report dict

    :return: A DBotScore object.
    :rtype: dict
    """

    def _type_selector(_type):
        types = {
            "ip": DBotScoreType.IP,
            "file": DBotScoreType.FILE,
            "domain": DBotScoreType.DOMAIN,
            "url": DBotScoreType.URL,
            "email": DBotScoreType.EMAIL,
            "custom": DBotScoreType.CUSTOM,
        }
        if not _type:
            return types["custom"]
        return types[_type]

    return Common.DBotScore(
        indicator=indicator,
        indicator_type=_type_selector(type_of_indicator),
        integration_name="ThreatZone",
        score=translate_score(score),
        reliability=get_reputation_reliability(demisto.params().get("integrationReliability")),
    )


def generate_indicator(indicator, report, type_of_indicator, score=None):
    """Creates Indicator object based on the content of 'indicator' argument

    :type indicator: ``str``
    :param indicator: The value of the indicator

    :type report: ``dict``
    :param report: The readable report dict

    :return: A Indicator object.
    :rtype: dict
    """
    if score is not None:
        dbot_score = generate_dbotscore(indicator, report, score, type_of_indicator)
    else:
        dbot_score = generate_dbotscore(indicator, report, report.get("LEVEL"), type_of_indicator)
    if type_of_indicator == "file":
        return Common.File(dbot_score=dbot_score, sha256=indicator)
    elif type_of_indicator == "ip":
        return Common.IP(ip=indicator, dbot_score=dbot_score)
    elif type_of_indicator == "url":
        return Common.URL(url=indicator, dbot_score=dbot_score)
    elif type_of_indicator == "domain":
        return Common.Domain(domain=indicator, dbot_score=dbot_score)
    elif type_of_indicator == "email":
        return Common.EMAIL(address=indicator, dbot_score=dbot_score)
    return None


def threatzone_get_result(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get the sample scan result from ThreatZone.
    :param - uuid: For filtering with status
    :type uuid: ``str``
    :return: list containing result returned from ThreatZone API and human readable output
    :rtype: ``list``
    """
    uuid = args.get("uuid")
    param = {"uuid": uuid}

    result = client.threatzone_get(param=param)
    stats = {1: "File received", 2: "Submission is accepted", 3: "Submission is running", 4: "Submission VM is ready", 5: "Submission is finished"}

    levels = {0: "Not Measured", 1: "Informative", 2: "Suspicious", 3: "Malicious"}

    def create_res(readable_dict, output, exception=None):
        if not exception:
            base_readable_output = tableToMarkdown("Submission Result", readable_dict)
        else:
            raise exception

        def indicator_creator(output: dict) -> list:
            indicators = []
            if output["REPORT"].get("ioc", {}).get("url", []):
                for url in output["REPORT"].get("ioc", {}).get("url", []):
                    indicators.append(["url", url, generate_indicator(url, output, "url", score=0)])
                for domain in output["REPORT"].get("ioc", {}).get("domain", []):
                    indicators.append(["domain", domain, generate_indicator(domain, output, "domain", score=0)])
                for email in output["REPORT"].get("ioc", {}).get("email", []):
                    indicators.append(["email", email, generate_indicator(email, output, "email", score=0)])
                for ip in output["REPORT"].get("ioc", {}).get("ip", []):
                    indicators.append(["ip", ip, generate_indicator(ip, output, "ip", score=0)])
            return indicators

        command_result_list = [
            CommandResults(
                outputs_prefix="ThreatZone.Analysis",
                readable_output=base_readable_output,
                outputs_key_field="UUID",
                outputs=output,
                indicator=generate_indicator(output["SHA256"], output, "file"),
            )
        ]
        for ind in indicator_creator(output):
            command_result_list.append(
                CommandResults(
                    outputs_prefix="ThreatZone.Indicators",
                    readable_output=tableToMarkdown(f"{ind[0].upper()} Indicator created: {ind[1]}", t={}),
                    indicator=ind[2],
                    outputs=output,
                    outputs_key_field="UUID",
                )
            )
        return command_result_list

    try:

        report_type = ""
        if result.get("reports", {}).get("dynamic", {}).get("enabled"):
            report_type = "dynamic"
        elif result.get("reports", {}).get("static", {}).get("enabled"):
            report_type = "static"
        elif result.get("reports", {}).get("cdr", {}).get("enabled"):
            report_type = "cdr"

        status = result["reports"][report_type]["status"]
        if status == 0:
            raise Exception(
                "Submission is declined by the scanner." + " " + "The reason behind this could be about your file is broken or the analyzer has crashed."
            )
        md5 = result["fileInfo"]["hashes"]["md5"]
        sha1 = result["fileInfo"]["hashes"]["sha1"]
        sha256 = result["fileInfo"]["hashes"]["sha256"]
        submission_info = {"file_name": result["fileInfo"]["name"], "private": result["private"]}
        submission_info = {"file_name": result["fileInfo"]["name"], "private": result["private"]}

        submission_uuid = result["uuid"]
        if status == 0:
            raise DemistoException(f"Reason: {stats[status]}\nUUID: {submission_uuid}\nSuggestion: Re-analyze submission or contact us.")

        result_url = f"https://app.threat.zone/submission/{submission_uuid}"
        level = result["level"]
        readable_dict = {
            "ANALYSIS TYPE": report_type,
            "STATUS": stats[status],
            "MD5": md5,
            "SHA1": sha1,
            "SHA256": sha256,
            "THREAT_LEVEL": levels[level],
            "FILE_NAME": result["fileInfo"]["name"],
            "PRIVATE": result["private"],
            "SCAN_URL": result_url,
            "UUID": submission_uuid,
            "SANITIZED": None,
        }

        output = {
            "TYPE": report_type,
            "STATUS": status,
            "MD5": md5,
            "SHA1": sha1,
            "SHA256": sha256,
            "LEVEL": level,
            "INFO": submission_info,
            "URL": result_url,
            "UUID": submission_uuid,
            "REPORT": result["reports"][report_type],
            "SANITIZED": None,
        }

        res = create_res(readable_dict, output)
        if report_type == "cdr" and status == 5:
            sanitized_file_url = f"https://app.threat.zone/download/v1/download/cdr/{submission_uuid}"
            output["SANITIZED"] = sanitized_file_url
            readable_dict["SANITIZED"] = sanitized_file_url
            res = create_res(readable_dict, output)

    except Exception as e:
        output = {"REPORT": result}
        res = create_res(result, output, exception=e)
    return res


def threatzone_check_limits(client: Client) -> CommandResults:
    """Checks and prints remaining limits and current quota"""
    availability = client.threatzone_check_limits(None)
    readable_output = tableToMarkdown("LIMITS", availability["Limits"])
    return CommandResults(outputs_prefix="ThreatZone.Limits", outputs_key_field="E_Mail", readable_output=readable_output, outputs=availability["Limits"])


def threatzone_return_results(scan_type, uuid, url, readable_output, availability) -> List[CommandResults]:
    """Helper function for returning results with limits."""
    scan_prefix = ""
    if scan_type == "static-scan":
        scan_prefix = "Static"
    elif scan_type == "cdr":
        scan_prefix = "CDR"
    else:
        scan_prefix = "Sandbox"
    return [
        CommandResults(
            outputs_prefix=f"ThreatZone.Submission.{scan_prefix}", readable_output=readable_output, outputs_key_field="UUID", outputs={"UUID": uuid, "URL": url}
        ),
        CommandResults(outputs_prefix="ThreatZone.Limits", outputs_key_field="E_Mail", outputs=availability["Limits"]),
    ]


def threatzone_get_sanitized_file(client: Client, args: Dict[str, Any]) -> None:
    """Downloads and uploads sanitized file to WarRoom & Context Data."""
    submission_uuid = args.get("uuid")
    data = client.threatzone_get_sanitized(submission_uuid)
    return_results(fileResult(f"sanitized-{submission_uuid}.zip", data))


def threatzone_sandbox_upload_sample(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """Uploads the sample to the ThreatZone sandbox to analyse with required or optional selections."""
    availability = client.threatzone_check_limits("sandbox")
    if not availability["available"]:
        raise DemistoException(f"Reason: {availability['Reason']}\nSuggestion: {availability['Suggestion']}\nLimits: {availability['Limits']}")

    ispublic = args.get("private")
    environment = args.get("environment")
    work_path = args.get("work_path")
    timeout = args.get("timeout")
    mouse_simulation = args.get("mouse_simulation")
    https_inspection = args.get("https_inspection")
    internet_connection = args.get("internet_connection")
    raw_logs = args.get("raw_logs")
    snapshot = args.get("snapshot")
    file_id = args.get("entry_id")
    file_obj = demisto.getFilePath(file_id)
    file_name = encode_file_name(file_obj["name"])
    file_path = file_obj["path"]

    files = [("file", (file_name, open(file_path, "rb"), "application/octet-stream"))]

    param = {
        "scan_type": "sandbox",
        "environment": environment,
        "private": ispublic,
        "timeout": timeout,
        "work_path": work_path,
        "mouse_simulation": mouse_simulation,
        "https_inspection": https_inspection,
        "internet_connection": internet_connection,
        "raw_logs": raw_logs,
        "file_path": file_path,
        "snapshot": snapshot,
        "files": files,
    }

    result = client.threatzone_add(param=param)
    readable_output = tableToMarkdown("SAMPLE UPLOADED", result)
    uuid = result["uuid"]
    url = f"https://app.threat.zone/submission/{uuid}"
    availability = client.threatzone_check_limits("sandbox")
    return threatzone_return_results("sandbox", uuid, url, readable_output, availability)


def threatzone_static_cdr_upload_sample(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """Uploads the sample to the ThreatZone to analyse with required or optional selections."""
    scan_type = args.get("scan_type")
    availability = client.threatzone_check_limits(scan_type)
    if not availability["available"]:
        raise DemistoException(f"Reason: {availability['Reason']}\nSuggestion: {availability['Suggestion']}")

    file_id = args.get("entry_id")
    file_obj = demisto.getFilePath(file_id)
    file_name = encode_file_name(file_obj["name"])
    file_path = file_obj["path"]
    files = [("file", (file_name, open(file_path, "rb"), "application/octet-stream"))]
    param = {"scan_type": scan_type, "files": files}

    result = client.threatzone_add(param=param)
    uuid = result["uuid"]
    url = f"https://app.threat.zone/submission/{uuid}"
    readable = {"Message": result["message"], "UUID": result["uuid"], "URL": url}
    readable_output = tableToMarkdown("SAMPLE UPLOADED", readable)
    availability = client.threatzone_check_limits(scan_type)
    return threatzone_return_results(scan_type, uuid, url, readable_output, availability)


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    base_url = params["url"]
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    """ EXECUTION """
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    args = demisto.args()
    try:
        credentials = params.get("apikey")
        creds = "Bearer " + credentials
        headers = {"Authorization": creds}

        client = Client(base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy)

        if command == "test-module":
            return_results(test_module(params))
        elif command == "tz-check-limits":
            return_results(threatzone_check_limits(client))
        elif command == "tz-sandbox-upload-sample":
            return_results(threatzone_sandbox_upload_sample(client, args))
        elif command == "tz-static-upload-sample":
            args["scan_type"] = "static-scan"
            return_results(threatzone_static_cdr_upload_sample(client, args))
        elif command == "tz-cdr-upload-sample":
            args["scan_type"] = "cdr"
            return_results(threatzone_static_cdr_upload_sample(client, args))
        elif command == "tz-get-result":
            return_results(threatzone_get_result(client, args))
        elif command == "tz-get-sanitized":
            raise DemistoException("Sanitized file download will be available at next patch, use tz-get-result instead.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
