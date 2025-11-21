import json
import shutil
from contextlib import closing
from typing import Any, Callable, Dict, List, Optional, Union

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

ARCHIVE_SUFFIXES = (
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".tgz",
    ".tar.gz",
    ".tar.bz2",
    ".tar.xz",
)

SECTION_METADATA: Dict[str, Dict[str, Any]] = {
    "include_indicators": {
        "endpoint": "indicators",
        "prefix": "ThreatZone.Submission.Indicators",
        "title": "Dynamic Indicators",
        "response_key": "indicators",
    },
    "include_iocs": {
        "endpoint": "iocs",
        "prefix": "ThreatZone.Submission.IOCs",
        "title": "Indicators of Compromise",
        "response_key": "iocs",
    },
    "include_yara": {
        "endpoint": "matched-yara-rules",
        "prefix": "ThreatZone.Submission.YaraMatches",
        "title": "Matched YARA Rules",
        "response_key": "yaraRules",
    },
    "include_artifacts": {
        "endpoint": "analysis-artifacts",
        "prefix": "ThreatZone.Submission.Artifacts",
        "title": "Analysis Artifacts",
        "response_key": "artifacts",
    },
    "include_config": {
        "endpoint": "config-extractor-results",
        "prefix": "ThreatZone.Submission.Config",
        "title": "Configuration Extractor Results",
        "response_key": "configExtractorResults",
    },
}

DETAIL_SECTIONS = (
    ("Indicators", "indicators", "indicators"),
    ("Indicators of Compromise", "iocs", "ioc"),
    ("Matched YARA Rules", "matchedYARARules", "matched_yara_rules"),
    ("Analysis Artifacts", "artifacts", "additionalFiles"),
    ("Extracted Configurations", "extractedConfigs", "extractedConfigs"),
)

DETAIL_TABLE_LABELS = {
    "Indicators": "INDICATORS",
    "Indicators of Compromise": "INDICATORS OF COMPROMISE",
    "Matched YARA Rules": "MATCHED YARA RULES",
    "Analysis Artifacts": "ANALYSIS ARTIFACTS",
    "Extracted Configurations": "EXTRACTED CONFIGURATIONS",
}


def _sanitize_text(value: Any) -> str:
    """Normalize values rendered inside War Room tables."""
    text = str(value)
    for token in ("\r\n", "\n", "\r"):
        text = text.replace(token, " ")
    for token in ("<br />", "<br/>", "<br>"):
        text = text.replace(token, " ")
    return text


def _is_empty_value(value: Any) -> bool:
    """Return True when a ThreatZone field is effectively empty."""
    return value in (None, "", []) or value == {} or value == ()


def _format_bullet_section(values: List[Any], formatter: Callable[[Any], str]) -> str:
    """Render a list of values as a compact, single-line string."""
    if not values:
        return "No data returned."

    lines = [_sanitize_text(formatter(item)) for item in values]
    return "; ".join(lines)


def _format_comma_separated(values: List[Any], formatter: Callable[[Any], str]) -> str:
    """Render a list of values as a comma separated string."""
    if not values:
        return ""

    items = [_sanitize_text(formatter(item)) for item in values]
    return ", ".join(items)


def _summarize_indicator_item(item: Any) -> str:
    """Return a concise string for a dynamic indicator entry."""
    if isinstance(item, dict):
        name = item.get("name") or item.get("indicator") or item.get("description") or "Indicator"
        details: List[str] = []
        category = item.get("category")
        if not _is_empty_value(category):
            details.append(str(category))
        score = item.get("score")
        if score is not None:
            details.append(f"score {score}")
        level = item.get("level")
        if not _is_empty_value(level):
            details.append(str(level))
        suffix = f" ({', '.join(details)})" if details else ""
        return _sanitize_text(f"{name}{suffix}")
    return _sanitize_text(item)


def _summarize_ioc_item(item: Any) -> str:
    """Return a concise string for an IOC entry."""
    if isinstance(item, dict):
        indicator_value = (
            item.get("value") or item.get("indicator") or item.get("indicator_value") or item.get("name") or "IOC"
        )
        indicator_type = item.get("type") or item.get("indicatorType")
        suffix = f" ({indicator_type})" if indicator_type else ""
        return _sanitize_text(f"{indicator_value}{suffix}")
    return _sanitize_text(item)


def _summarize_yara_item(item: Any) -> str:
    """Return a concise string for a matched YARA rule."""
    if isinstance(item, dict):
        rule_name = item.get("rule") or item.get("name") or item.get("id") or "Rule"
        rule_type = item.get("type") or item.get("classification")
        suffix = f" ({rule_type})" if rule_type else ""
        return _sanitize_text(f"{rule_name}{suffix}")
    return _sanitize_text(item)


def _summarize_artifact_item(item: Any) -> str:
    """Return a concise string for an artifact entry."""
    if isinstance(item, dict):
        for key in ("path", "name", "filename", "id"):
            value = item.get(key)
            if not _is_empty_value(value):
                return _sanitize_text(value)
        for value in item.values():
            if isinstance(value, str) and not _is_empty_value(value):
                return _sanitize_text(value)
        return "Artifact"
    return _sanitize_text(item)


def _summarize_config_item(item: Any) -> str:
    """Return a concise string for a configuration extractor entry."""
    if isinstance(item, dict):
        key = item.get("key") or item.get("name")
        value = item.get("value")
        if not _is_empty_value(key) and not _is_empty_value(value):
            return _sanitize_text(f"{key}: {value}")
        if not _is_empty_value(key):
            return _sanitize_text(key)
        if not _is_empty_value(value):
            return _sanitize_text(value)
        # Fall back to the first string value for readability.
        for entry_value in item.values():
            if isinstance(entry_value, str) and not _is_empty_value(entry_value):
                return _sanitize_text(entry_value)
        return "Configuration result"
    return _sanitize_text(item)


def summarize_indicators_section(section_data: Any) -> str:
    """Summarize indicators into a markdown-friendly preview."""
    indicators: List[Any] = []
    if isinstance(section_data, list):
        indicators = section_data
    elif isinstance(section_data, dict):
        possible_list = section_data.get("indicators")
        if isinstance(possible_list, list):
            indicators = possible_list

    if not indicators:
        return "No data returned."
    return _format_bullet_section(indicators, _summarize_indicator_item)


def summarize_iocs_section(section_data: Any) -> str:
    """Summarize IOCs into a markdown-friendly preview."""
    if isinstance(section_data, dict):
        lines: List[str] = []
        for key, values in section_data.items():
            if isinstance(values, list) and values:
                formatted_values = _format_comma_separated(values, _summarize_ioc_item)
                if formatted_values:
                    lines.append(f"{_sanitize_text(key)}: {formatted_values}")
            elif not _is_empty_value(values):
                lines.append(f"{_sanitize_text(key)}: {_sanitize_text(values)}")
        return "; ".join(lines) or "No data returned."

    if isinstance(section_data, list):
        return _format_bullet_section(section_data, _summarize_ioc_item)

    return "No data returned."


def summarize_yara_section(section_data: Any) -> str:
    """Summarize matched YARA rules into a markdown-friendly preview."""
    if isinstance(section_data, dict):
        lines: List[str] = []
        for key, value in section_data.items():
            if isinstance(value, list) and value:
                formatted_values = _format_comma_separated(value, _summarize_yara_item)
                if formatted_values:
                    lines.append(f"{_sanitize_text(key)}: {formatted_values}")
            elif not _is_empty_value(value):
                lines.append(f"{_sanitize_text(key)}: {_sanitize_text(value)}")
        return "; ".join(lines) or "No data returned."

    if isinstance(section_data, list):
        return _format_bullet_section(section_data, _summarize_yara_item)

    return "No data returned."


def summarize_artifacts_section(section_data: Any) -> str:
    """Summarize analysis artifacts into a markdown-friendly preview."""
    if isinstance(section_data, dict):
        possible_list = section_data.get("artifacts")
        if isinstance(possible_list, list):
            section_data = possible_list
        else:
            return "No data returned."

    if isinstance(section_data, list):
        return _format_bullet_section(section_data, _summarize_artifact_item)

    return "No data returned."


def summarize_configs_section(section_data: Any) -> str:
    """Summarize configuration extractor results into a markdown-friendly preview."""
    if isinstance(section_data, dict):
        lines: List[str] = []
        for key, value in section_data.items():
            if isinstance(value, list) and value:
                formatted_values = _format_comma_separated(value, _summarize_config_item)
                if formatted_values:
                    lines.append(f"{_sanitize_text(key)}: {formatted_values}")
            elif not _is_empty_value(value):
                lines.append(f"{_sanitize_text(key)}: {_sanitize_text(value)}")
        return "; ".join(lines) or "No data returned."

    if isinstance(section_data, list):
        return _format_bullet_section(section_data, _summarize_config_item)

    return "No data returned."


DETAIL_SUMMARIZERS: Dict[str, Callable[[Any], str]] = {
    "Indicators": summarize_indicators_section,
    "Indicators of Compromise": summarize_iocs_section,
    "Matched YARA Rules": summarize_yara_section,
    "Analysis Artifacts": summarize_artifacts_section,
    "Extracted Configurations": summarize_configs_section,
}


def is_archive_filename(filename: str) -> bool:
    """Returns True when filename extension suggests an archive."""
    lower_name = filename.lower()
    return any(lower_name.endswith(suffix) for suffix in ARCHIVE_SUFFIXES)


def as_api_bool(value: bool) -> str:
    """Return lowercase string that ThreatZone API accepts for boolean fields."""
    return "true" if value else "false"


def parse_modules_argument(modules_arg: Optional[str]) -> Optional[List[str]]:
    """Parse modules argument supporting JSON array or comma-separated string."""
    if not modules_arg:
        return None

    try:
        parsed = json.loads(modules_arg)
    except ValueError:
        parsed = None

    modules: List[str] = []
    if isinstance(parsed, list):
        modules = [str(module).strip() for module in parsed if str(module).strip()]
    elif isinstance(parsed, str):
        modules = [parsed.strip()]
    elif parsed is None:
        modules = [mod.strip() for mod in modules_arg.split(",") if mod.strip()]
    else:
        raise DemistoException("modules argument must be a JSON array or comma-separated string.")

    return modules or None


def parse_analyze_config_argument(analyze_arg: Optional[str]) -> List[Dict[str, Any]]:
    """Parse analyze_config argument and validate schema."""
    if not analyze_arg:
        return []

    try:
        parsed = json.loads(analyze_arg)
    except ValueError as exc:
        raise DemistoException("Invalid JSON provided for analyze_config argument.") from exc

    if isinstance(parsed, dict):
        parsed = [parsed]

    if not isinstance(parsed, list):
        raise DemistoException("analyze_config argument must be a JSON object or array of objects.")

    validated: List[Dict[str, Any]] = []
    for entry in parsed:
        if not isinstance(entry, dict):
            raise DemistoException("analyze_config entries must be JSON objects.")
        metafield_id = entry.get("metafieldId")
        if not metafield_id:
            raise DemistoException("analyze_config entries must include 'metafieldId'.")
        if "value" not in entry:
            raise DemistoException("analyze_config entries must include 'value'.")
        validated.append({"metafieldId": metafield_id, "value": entry.get("value")})

    return validated


def parse_int_argument(arg_value: Optional[str], argument_name: str) -> Optional[int]:
    """Convert CLI argument to int with validation."""
    if arg_value in (None, ""):
        return None
    try:
        return int(arg_value)
    except (TypeError, ValueError) as exc:
        raise DemistoException(f"{argument_name} argument must be an integer.") from exc


""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def threatzone_add(
        self,
        *,
        scan_type: str,
        data: Dict[str, Any],
        files: List[tuple],
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Submit a scan request to ThreatZone via the /public-api/scan/ endpoints."""
        request_kwargs: Dict[str, Any] = {
            "method": "POST",
            "url_suffix": f"/public-api/scan/{scan_type}",
            "data": data,
            "files": files,
        }
        if params:
            request_kwargs["params"] = params
        return self._http_request(**request_kwargs)

    def threatzone_submit_url(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Submit a URL analysis request to ThreatZone."""
        return self._http_request(
            method="POST",
            url_suffix="/public-api/scan/url-analysis",
            json_data=payload,
        )

    def threatzone_get_section(self, submission_uuid: str, section: str) -> Any:
        """Fetch a nested submission resource (e.g. indicators, artifacts)."""
        return self._http_request(
            method="GET",
            url_suffix=f"/public-api/get/submission/{submission_uuid}/{section}",
        )

    def _download_submission_asset(self, url_suffix: str, filename: str) -> dict:
        """Download a submission-related asset (HTML report, sanitized archive) and upload to War Room."""
        with closing(
            self._http_request(
                method="GET",
                url_suffix=url_suffix,
                resp_type="response",
                stream=True,
            )
        ) as response:
            if not response.ok:
                raise DemistoException(f"Bad HTTP response [{response.status_code}] - {response.text}")

            with open(filename, "wb") as file_handle:
                response.raw.decode_content = True
                shutil.copyfileobj(response.raw, file_handle)
        return file_result_existing_file(filename)

    def threatzone_get(self, param: dict) -> dict[str, Any]:
        """Gets the sample scan result from ThreatZone using the '/public-api/get/submission/' API endpoint

        :return: dict containing the sample scan results as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        return self._http_request(method="GET", url_suffix="/public-api/get/submission/" + param["uuid"])

    def threatzone_get_sanitized(self, submission_uuid) -> dict:
        filename = f"sanitized-{submission_uuid}.zip"
        return self._download_submission_asset(f"/public-api/download/cdr/{submission_uuid}", filename)

    def threatzone_get_html_report(self, submission_uuid: str) -> dict:
        filename = f"threatzone-report-{submission_uuid}.html"
        return self._download_submission_asset(f"/public-api/download/html-report/{submission_uuid}", filename)

    def threatzone_me(self):
        """
        :return: dict containing limit data returned from the API
        :rtype: ``Dict[str, Any]``
        """
        return self._http_request(method="GET", url_suffix="/public-api/me")

    def threatzone_check_limits(self, scan_category):
        """Checks limits using the '/public-api/me' API endpoint
        :return: dict containing limit data returned from the API
        :rtype: ``Dict[str, Any]``
        """
        api_me = self.threatzone_me()
        user_info = api_me.get("userInfo", {})
        plan_info = api_me.get("plan", {})
        acc_email = user_info.get("email")
        limits_count = user_info.get("limitsCount", {})
        submission_limits = plan_info.get("submissionLimits", {}) or {}

        def _remaining(total: Optional[int], used: Optional[int]) -> Optional[int]:
            if total is None or used is None:
                return None
            return total - used

        available_api = _remaining(submission_limits.get("apiLimit"), limits_count.get("apiRequestCount"))
        available_submission = _remaining(submission_limits.get("dailyLimit"), limits_count.get("dailySubmissionCount"))
        available_concurrent = _remaining(
            submission_limits.get("concurrentLimit"), limits_count.get("concurrentSubmissionCount")
        )
        limits = {
            "E_Mail": f"{acc_email}",
            "Daily_Submission_Limit": f"{limits_count.get('dailySubmissionCount', '?')}/{submission_limits.get('dailyLimit', '?')}",
            "Concurrent_Limit": f"{limits_count.get('concurrentSubmissionCount', '?')}/{submission_limits.get('concurrentLimit', '?')}",
            "API_Limit": f"{limits_count.get('apiRequestCount', '?')}/{submission_limits.get('apiLimit', '?')}",
        }
        file_limits = plan_info.get("fileLimits", {})
        plan_details = {
            "File_Size_Limit_MiB": file_limits.get("fileSize"),
            "Allowed_Extensions": file_limits.get("extensions"),
            "Modules": [module.get("name") for module in api_me.get("modules", []) if module.get("name")],
        }
        metadata = {
            "Full_Name": user_info.get("fullName"),
            "Workspace": user_info.get("workspaceName"),
            "Plan_Name": plan_info.get("name"),
            "Plan_Status": plan_info.get("status"),
        }
        if available_api is not None and available_api < 1:
            return {
                "available": False,
                "Limits": limits,
                "PlanDetails": plan_details,
                "Metadata": metadata,
                "Reason": f"API request limit ({submission_limits.get('apiLimit', '?')}) exceeded",
                "Suggestion": "Upgrade your plan or contact us.",
            }
        elif available_submission is not None and available_submission < 1:
            return {
                "available": False,
                "Limits": limits,
                "PlanDetails": plan_details,
                "Metadata": metadata,
                "Reason": f"Daily submission limit ({submission_limits.get('dailyLimit', '?')}) exceeded",
                "Suggestion": "Upgrade your plan or contact us.",
            }
        elif (
            available_concurrent is not None
            and available_concurrent < 1
            and scan_category in ("sandbox", "static-scan", "cdr")
        ):
            return {
                "available": False,
                "Limits": limits,
                "PlanDetails": plan_details,
                "Metadata": metadata,
                "Reason": f"Concurrent analysis limit ({submission_limits.get('concurrentLimit', '?')}) exceeded.",
                "Suggestion": "Upgrade your plan or wait for previous sandbox analyzes to finish.",
            }
        else:
            return {
                "available": True,
                "Limits": limits,
                "PlanDetails": plan_details,
                "Metadata": metadata,
            }


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'"
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.
    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    try:
        client.threatzone_me()
    except DemistoException as e:
        message = str(e)
        if any(err in message for err in ("Unauthorized", "401", "403")):
            return "Authorization Error: make sure API Key is correctly set"
        raise
    except Exception as e:
        raise e
    return "ok"


def encode_file_name(file_name: str) -> str:
    """
    encodes the file name - i.e ignoring non ASCII chars and removing backslashes
    Args:
        file_name (str): name of the file
    Returns: encoded file name
    """
    return file_name.encode("ascii", "ignore").decode("ascii", "ignore")


def translate_score(
    score: Optional[int],
) -> int:
    """Translate ThreatZone threat level to DBot score enum."""
    if score is None:
        return Common.DBotScore.NONE
    if score == 0:
        return Common.DBotScore.NONE
    if score == 1:
        return Common.DBotScore.GOOD
    if score == 2:
        return Common.DBotScore.SUSPICIOUS
    if score >= 3:
        return Common.DBotScore.BAD
    return Common.DBotScore.NONE


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


def generate_dbotscore(indicator, score, type_of_indicator=None):
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
        dbot_score = generate_dbotscore(indicator, score, type_of_indicator=type_of_indicator)
    else:
        dbot_score = generate_dbotscore(indicator, report.get("LEVEL"), type_of_indicator=type_of_indicator)
    if type_of_indicator == "file":
        return Common.File(
            dbot_score,
            md5=report.get("MD5"),
            sha1=report.get("SHA1"),
            sha256=report.get("SHA256"),
        )
    elif type_of_indicator == "ip":
        return Common.IP(ip=indicator, dbot_score=dbot_score)
    elif type_of_indicator == "url":
        return Common.URL(url=indicator, dbot_score=dbot_score)
    elif type_of_indicator == "domain":
        return Common.Domain(domain=indicator, dbot_score=dbot_score)
    elif type_of_indicator == "email":
        return Common.EMAIL(address=indicator, dbot_score=dbot_score)
    raise DemistoException(f"{type_of_indicator} does not supported")


def render_section_markdown(title: str, data: Any) -> str:
    """Safely render integration data as markdown, falling back to JSON when needed."""
    if data in (None, [], {}):
        return f"{title}\nNo data returned."

    try:
        return tableToMarkdown(title, data, removeNull=True)
    except Exception as exc:  # pragma: no cover - defensive, tableToMarkdown rarely fails
        demisto.debug(f"tableToMarkdown failed for section '{title}': {exc}")
        serialized = json.dumps(data, indent=2, default=str)
        return f"{title}\n```json\n{serialized}\n```"


def build_section_command_results(uuid: str, prefix: str, title: str, data: Any) -> CommandResults:
    """Build a CommandResults object for a submission section."""
    readable_output = render_section_markdown(title, data)
    outputs: Optional[Dict[str, Any]] = None
    outputs_key_field: Optional[str] = None
    if data not in (None, [], {}):
        outputs = {"UUID": uuid, "Data": data}
        outputs_key_field = "UUID"
    return CommandResults(
        outputs_prefix=prefix,
        outputs_key_field=outputs_key_field,
        outputs=outputs,
        readable_output=readable_output,
    )


def fetch_section_data(client: "Client", uuid: str, endpoint: str, response_key: Optional[str]) -> Any:
    """Fetch a submission section, returning the nested payload when possible."""
    raw_section = client.threatzone_get_section(uuid, endpoint)
    if response_key and isinstance(raw_section, dict) and response_key in raw_section:
        return raw_section.get(response_key)
    return raw_section


def threatzone_get_result(client: Client, args: dict[str, Any]) -> List[Union[CommandResults, dict]]:
    """Get the sample scan result from ThreatZone with optional detailed sections."""
    uuid = args.get("uuid")
    if not uuid:
        raise DemistoException("uuid argument is required.")

    result = client.threatzone_get({"uuid": uuid})
    stats = {
        1: "File received",
        2: "Submission is accepted",
        3: "Submission is running",
        4: "Submission VM is ready",
        5: "Submission is finished",
    }
    levels = {0: "Not Measured", 1: "Informative", 2: "Suspicious", 3: "Malicious"}

    reports = result.get("reports") or {}
    report_type = next(
        (name for name in ("dynamic", "static", "cdr", "urlAnalysis") if reports.get(name, {}).get("enabled")), None
    )
    if report_type is None:
        raise DemistoException("No enabled report found for the submission.")

    report_section = reports.get(report_type) or {}
    status = report_section.get("status")
    if status == 0:
        raise DemistoException(
            "Submission is declined by the scanner. "
            "The file may be corrupted or the analyzer encountered an unrecoverable error."
        )

    submission_uuid = result.get("uuid", uuid)
    download_sanitized = argToBoolean(args.get("download_sanitized", "false"))

    file_info = result.get("fileInfo") or {}
    file_hashes = file_info.get("hashes") or {}
    md5 = file_hashes.get("md5")
    sha1 = file_hashes.get("sha1")
    sha256 = file_hashes.get("sha256")
    file_name = file_info.get("name")
    analyzed_url = result.get("url")
    if not analyzed_url and report_type == "urlAnalysis":
        general_info = report_section.get("generalInfo") or {}
        analyzed_url = general_info.get("url") or general_info.get("URL")
    level = result.get("level")
    private_flag = result.get("private")

    threat_level_readable = levels.get(level, str(level) if level is not None else "Unknown")
    status_readable = stats.get(status, f"Status {status}" if status is not None else "Unknown")
    analysis_type_label = "URL Analysis" if report_type == "urlAnalysis" else report_type
    readable_summary: Dict[str, Any] = {
        "ANALYSIS TYPE": analysis_type_label,
        "STATUS": status_readable,
        "THREAT_LEVEL": threat_level_readable,
        "PRIVATE": private_flag,
        "UUID": submission_uuid,
    }
    if file_name:
        readable_summary["FILE_NAME"] = file_name
    if analyzed_url:
        readable_summary["URL"] = analyzed_url
    if md5:
        readable_summary["MD5"] = md5
    if sha1:
        readable_summary["SHA1"] = sha1
    if sha256:
        readable_summary["SHA256"] = sha256

    submission_info: Dict[str, Any] = {"private": private_flag}
    if file_name:
        submission_info["file_name"] = file_name
    if analyzed_url:
        submission_info["url"] = analyzed_url
    if report_type == "urlAnalysis":
        general_info = report_section.get("generalInfo") or {}
        if general_info.get("domain"):
            submission_info["domain"] = general_info.get("domain")
        if general_info.get("websiteTitle"):
            submission_info["website_title"] = general_info.get("websiteTitle")

    summary_output: Dict[str, Any] = {
        "TYPE": analysis_type_label,
        "STATUS": status_readable,
        "MD5": md5,
        "SHA1": sha1,
        "SHA256": sha256,
        "LEVEL": threat_level_readable,
        "INFO": submission_info,
        "UUID": submission_uuid,
        "REPORT": report_section,
    }
    result["Summary"] = summary_output

    include_details = argToBoolean(args.get("details", "false"))

    warnings: List[str] = []
    if status and status != 5:
        warnings.append(
            f"Submission status is '{stats.get(status, status)}'; some sections may not yet be available."
        )

    indicator_value = sha256 or analyzed_url
    indicator_level = level if isinstance(level, int) else None
    indicator_type = "file" if sha256 else "url"
    indicator_obj = None
    if indicator_value:
        try:
            indicator_obj = generate_indicator(
                indicator_value,
                summary_output,
                indicator_type,
                score=indicator_level,
            )
        except DemistoException as exc:
            warnings.append(f"indicator-generation: {exc}")
            demisto.debug(f"ThreatZone indicator generation failed: {exc}")

    sanitized_file: Optional[dict] = None
    if report_type == "cdr" and status == 5 and download_sanitized:
        try:
            sanitized_file = threatzone_get_sanitized_file(client, {"uuid": submission_uuid})
        except DemistoException as exc:
            warnings.append(f"sanitized-download: {exc}")
            demisto.debug(f"ThreatZone sanitized download failed: {exc}")

    readable_rows = {
        key: _sanitize_text(value) if isinstance(value, str) else value for key, value in readable_summary.items()
    }
    if include_details:
        for title, top_level_key, report_key in DETAIL_SECTIONS:
            section_data = result.get(top_level_key)
            if _is_empty_value(section_data) and isinstance(report_section, dict):
                section_data = report_section.get(report_key)

            summarizer = DETAIL_SUMMARIZERS.get(title)
            detail_value = (
                summarizer(section_data)
                if summarizer
                else ("No data returned." if _is_empty_value(section_data) else str(section_data))
            )
            label = DETAIL_TABLE_LABELS.get(title, title.upper())
            readable_rows[label] = _sanitize_text(detail_value)

    summary_table = tableToMarkdown("Submission Result", readable_rows, removeNull=True)
    if warnings:
        warning_lines = "\n".join(f"- {warning}" for warning in warnings)
        summary_table = f"{summary_table}\n\n### Additional Data Notes\n{warning_lines}"

    command_results: List[Union[CommandResults, dict]] = [
        CommandResults(
            outputs_prefix="ThreatZone.Submission",
            readable_output=summary_table,
            outputs_key_field="uuid",
            outputs=result,
            raw_response=result,
            indicator=indicator_obj,
        )
    ]

    if sanitized_file:
        command_results.append(sanitized_file)

    return command_results


def threatzone_get_section_result(client: Client, args: dict[str, Any], flag_name: str) -> List[CommandResults]:
    """Generic handler to retrieve a submission section using its dedicated endpoint."""
    metadata = SECTION_METADATA[flag_name]
    uuid = args.get("uuid")
    if not uuid:
        raise DemistoException("uuid argument is required.")

    endpoint = metadata.get("endpoint")
    if not endpoint:
        raise DemistoException("This section cannot be retrieved via a dedicated endpoint.")

    section_data = fetch_section_data(client, uuid, endpoint, metadata.get("response_key"))
    return [
        build_section_command_results(
            uuid,
            metadata["prefix"],
            metadata["title"],
            section_data,
        )
    ]


def threatzone_get_indicator_result(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    """Fetch dynamic behaviour indicators using the dedicated endpoint."""
    return threatzone_get_section_result(client, args, "include_indicators")


def threatzone_get_ioc_result(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    """Fetch Indicators of Compromise using the dedicated endpoint."""
    return threatzone_get_section_result(client, args, "include_iocs")


def threatzone_get_yara_result(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    """Fetch matched YARA rules using the dedicated endpoint."""
    return threatzone_get_section_result(client, args, "include_yara")


def threatzone_get_artifact_result(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    """Fetch analysis artifacts using the dedicated endpoint."""
    return threatzone_get_section_result(client, args, "include_artifacts")


def threatzone_get_config_result(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    """Fetch configuration extractor results using the dedicated endpoint."""
    return threatzone_get_section_result(client, args, "include_config")


def threatzone_check_limits(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    """Checks and prints remaining limits and current quota"""
    availability = client.threatzone_check_limits(None)
    readable_output = tableToMarkdown("LIMITS", availability["Limits"], removeNull=True)
    results: List[CommandResults] = [
        CommandResults(
            outputs_prefix="ThreatZone.Limits",
            outputs_key_field="E_Mail",
            readable_output=readable_output,
            outputs=availability["Limits"],
        )
    ]

    include_details = argToBoolean(args.get("detailed", "false"))

    plan_details = availability.get("PlanDetails")
    if include_details and plan_details:
        plan_readable = tableToMarkdown("PLAN DETAILS", plan_details, removeNull=True)
        results.append(
            CommandResults(
                outputs_prefix="ThreatZone.Plan",
                readable_output=plan_readable,
                outputs=plan_details,
            )
        )

    metadata = availability.get("Metadata")
    if include_details and metadata:
        filtered_metadata = {k: v for k, v in metadata.items() if v not in (None, "", [])}
        if filtered_metadata:
            metadata_readable = tableToMarkdown("ACCOUNT METADATA", filtered_metadata, removeNull=True)
            results.append(
                CommandResults(
                    outputs_prefix="ThreatZone.Metadata",
                    readable_output=metadata_readable,
                    outputs=filtered_metadata,
                )
            )

    return results


def threatzone_return_results(
    scan_type: str, submission_data: Union[str, Dict[str, Any]], readable_output: str, availability: Dict[str, Any]
) -> List[CommandResults]:
    """Helper function for returning results with limits."""
    scan_prefix = ""
    if scan_type == "static-scan":
        scan_prefix = "Static"
    elif scan_type == "cdr":
        scan_prefix = "CDR"
    elif scan_type == "url-analysis":
        scan_prefix = "URL"
    else:
        scan_prefix = "Sandbox"

    if isinstance(submission_data, str):
        submission_data = {"UUID": submission_data}
    filtered_submission = {k: v for k, v in submission_data.items() if v not in (None, "", [])}
    uuid = filtered_submission.get("UUID")
    if not uuid:
        raise DemistoException("Submission UUID is missing from the response.")
    return [
        CommandResults(
            outputs_prefix=f"ThreatZone.Submission.{scan_prefix}",
            readable_output=readable_output,
            outputs_key_field="UUID",
            outputs=filtered_submission,
        ),
        CommandResults(outputs_prefix="ThreatZone.Limits", outputs_key_field="E_Mail", outputs=availability["Limits"]),
    ]


def threatzone_get_sanitized_file(client: Client, args: dict[str, Any]) -> dict:
    """Downloads and uploads sanitized file to WarRoom & Context Data."""
    submission_uuid = args.get("uuid")
    if not submission_uuid:
        raise DemistoException("uuid argument is required.")
    return client.threatzone_get_sanitized(submission_uuid)


def threatzone_get_html_report_file(client: Client, args: dict[str, Any]) -> dict:
    """Downloads the HTML report for a submission and uploads it to the War Room."""
    submission_uuid = args.get("uuid")
    if not submission_uuid:
        raise DemistoException("uuid argument is required.")
    return client.threatzone_get_html_report(submission_uuid)


def threatzone_sandbox_upload_sample(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    """Uploads the sample to the ThreatZone sandbox to analyse with required or optional selections."""
    availability = client.threatzone_check_limits("sandbox")
    if not availability["available"]:
        raise DemistoException(
            f"Reason: {availability['Reason']}\nSuggestion: {availability['Suggestion']}\nLimits: {availability['Limits']}"
        )

    file_id = args.get("entry_id")
    if not file_id:
        raise DemistoException("entry_id argument is required.")
    try:
        file_obj = demisto.getFilePath(file_id)
    except Exception as exc:
        raise DemistoException(f"Failed to retrieve file for entry ID {file_id}.") from exc
    original_file_name = file_obj["name"]
    file_name = encode_file_name(original_file_name)
    file_path = file_obj["path"]

    timeout_value = parse_int_argument(args.get("timeout"), "timeout")
    environment = args.get("environment")
    work_path = args.get("work_path")
    private_value = argToBoolean(args.get("private", "true"))

    default_analyze_config: List[Dict[str, Any]] = []
    if environment:
        default_analyze_config.append({"metafieldId": "environment", "value": environment})
    default_analyze_config.append({"metafieldId": "private", "value": private_value})
    if timeout_value is not None:
        default_analyze_config.append({"metafieldId": "timeout", "value": timeout_value})
    if work_path:
        default_analyze_config.append({"metafieldId": "work_path", "value": work_path})

    bool_metafields = (
        ("mouse_simulation", "mouse_simulation"),
        ("https_inspection", "https_inspection"),
        ("internet_connection", "internet_connection"),
        ("raw_logs", "raw_logs"),
        ("snapshot", "snapshot"),
    )
    for arg_name, metafield_id in bool_metafields:
        bool_value = argToBoolean(args.get(arg_name, "false"))
        default_analyze_config.append({"metafieldId": metafield_id, "value": bool_value})

    user_analyze_config = parse_analyze_config_argument(args.get("analyze_config"))
    merged_config: Dict[str, Dict[str, Any]] = {entry["metafieldId"]: entry for entry in default_analyze_config}
    for entry in user_analyze_config:
        merged_config[entry["metafieldId"]] = entry

    analyze_config_payload = list(merged_config.values())
    payload: Dict[str, Any] = {}
    if analyze_config_payload:
        payload["analyzeConfig"] = json.dumps(analyze_config_payload)

    modules_list = parse_modules_argument(args.get("modules"))
    if modules_list:
        payload["modules"] = json.dumps(modules_list)

    extension_check = argToBoolean(args.get("extension_check", "true"))
    payload["extensionCheck"] = as_api_bool(extension_check)

    if entrypoint := args.get("entrypoint"):
        payload["entrypoint"] = entrypoint
    if password := args.get("password"):
        payload["password"] = password

    auto_param = args.get("auto")
    url_params = None
    if auto_param is not None:
        auto_bool = argToBoolean(auto_param)
        url_params = {"auto": as_api_bool(auto_bool)}

    with open(file_path, "rb") as file_handle:
        files = [("file", (file_name, file_handle, "application/octet-stream"))]
        result = client.threatzone_add(
            scan_type="sandbox",
            data=payload,
            files=files,
            params=url_params,
        )

    custom_result = {
        "Message": result.get("message"),
        "UUID": result.get("uuid"),
        "FileName": original_file_name,
    }
    readable_output = tableToMarkdown("SAMPLE UPLOADED", custom_result)
    updated_availability = client.threatzone_check_limits("sandbox")
    return threatzone_return_results("sandbox", custom_result, readable_output, updated_availability)


def threatzone_static_cdr_upload_sample(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    """Uploads the sample to the ThreatZone to analyse with required or optional selections."""
    scan_type = args.get("scan_type")
    availability = client.threatzone_check_limits(scan_type)
    if not availability["available"]:
        raise DemistoException(f"Reason: {availability['Reason']}\nSuggestion: {availability['Suggestion']}")

    file_id = args.get("entry_id")
    if not file_id:
        raise DemistoException("entry_id argument is required.")
    try:
        file_obj = demisto.getFilePath(file_id)
    except Exception as exc:
        raise DemistoException(f"Failed to retrieve file for entry ID {file_id}.") from exc
    original_file_name = file_obj["name"]
    file_name = encode_file_name(original_file_name)
    file_path = file_obj["path"]

    private_flag = argToBoolean(args.get("private", "false"))
    is_public = not private_flag
    payload: Dict[str, Any] = {"isPublic": as_api_bool(is_public)}

    extension_check_arg = args.get("extension_check")
    if extension_check_arg is not None:
        extension_check = argToBoolean(extension_check_arg)
        payload["extensionCheck"] = as_api_bool(extension_check)

    if entrypoint := args.get("entrypoint"):
        payload["entrypoint"] = entrypoint
    if password := args.get("password"):
        payload["password"] = password

    with open(file_path, "rb") as file_handle:
        files = [("file", (file_name, file_handle, "application/octet-stream"))]
        result = client.threatzone_add(scan_type=scan_type, data=payload, files=files)

    readable = {"Message": result.get("message"), "UUID": result.get("uuid"), "FileName": original_file_name}
    readable_output = tableToMarkdown("SAMPLE UPLOADED", readable)
    updated_availability = client.threatzone_check_limits(scan_type)
    return threatzone_return_results(scan_type, readable, readable_output, updated_availability)


def threatzone_submit_url_analysis(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    """Submit a URL for analysis via the ThreatZone public API."""
    availability = client.threatzone_check_limits("url-analysis")
    if not availability["available"]:
        raise DemistoException(
            f"Reason: {availability['Reason']}\nSuggestion: {availability['Suggestion']}\nLimits: {availability['Limits']}"
        )

    analyzed_url = args.get("url")
    if not analyzed_url:
        raise DemistoException("url argument is required.")

    payload: Dict[str, Any] = {"url": analyzed_url}
    if args.get("private") is not None:
        payload["private"] = as_api_bool(argToBoolean(args.get("private", "false")))

    result = client.threatzone_submit_url(payload)
    readable = {"Message": result.get("message"), "UUID": result.get("uuid"), "URL": analyzed_url}
    readable_output = tableToMarkdown("URL SUBMITTED", readable)
    updated_availability = client.threatzone_check_limits("url-analysis")
    return threatzone_return_results("url-analysis", readable, readable_output, updated_availability)


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    base_url = params["url"].rstrip("/")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    """ EXECUTION """
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    args = demisto.args()
    try:
        credentials: str = str(params.get("apikey"))
        creds = "Bearer " + credentials
        headers = {"Authorization": creds}
        client = Client(base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client))
        elif command == "tz-check-limits":
            return_results(threatzone_check_limits(client, args))
        elif command == "tz-sandbox-upload-sample":
            return_results(threatzone_sandbox_upload_sample(client, args))
        elif command == "tz-static-upload-sample":
            args["scan_type"] = "static-scan"
            return_results(threatzone_static_cdr_upload_sample(client, args))
        elif command == "tz-cdr-upload-sample":
            args["scan_type"] = "cdr"
            return_results(threatzone_static_cdr_upload_sample(client, args))
        elif command == "tz-url-analysis":
            return_results(threatzone_submit_url_analysis(client, args))
        elif command == "tz-download-html-report":
            return_results(threatzone_get_html_report_file(client, args))
        elif command == "tz-get-result":
            return_results(threatzone_get_result(client, args))
        elif command == "tz-get-indicator-result":
            return_results(threatzone_get_indicator_result(client, args))
        elif command == "tz-get-ioc-result":
            return_results(threatzone_get_ioc_result(client, args))
        elif command == "tz-get-yara-result":
            return_results(threatzone_get_yara_result(client, args))
        elif command == "tz-get-artifact-result":
            return_results(threatzone_get_artifact_result(client, args))
        elif command == "tz-get-config-result":
            return_results(threatzone_get_config_result(client, args))
        elif command == "tz-get-sanitized":
            return_results(threatzone_get_sanitized_file(client, args))
        else:
            return_error(f"Command '{command}' is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
