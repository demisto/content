"""ThreatZone integration for Cortex XSOAR / XSIAM.

API interaction is delegated to the official `threatzone` Python SDK.
"""

import json
import re
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO, cast

import demistomock as demisto  # noqa: F401
import httpx
from CommonServerPython import *  # noqa: F401,F403
from threatzone import (
    AnalysisTimeoutError,
    APIError,
    AuthenticationError,
    BadRequestError,
    DownloadResponse,
    NotFoundError,
    PaymentRequiredError,
    PermissionDeniedError,
    RateLimitError,
    ReportUnavailableError,
    ThreatZoneError,
    YaraRulePendingError,
)
from threatzone import ThreatZone as ThreatZoneSDK
from threatzone.types.config import MetafieldOption

INTEGRATION_NAME = "ThreatZone"
PUBLIC_API_SUFFIX = "/public-api"
SDK_REQUEST_TIMEOUT_SECONDS = 60.0
REPORT_FINDINGS_PAGE_SIZE = 100
YARA_POLL_INTERVAL_SECONDS = 5.0

# Old integration used integer codes for level/status. Preserved for backward
# compatibility with playbooks that branch on these numbers.
LEVEL_LABEL_TO_INT = {"unknown": 0, "benign": 1, "suspicious": 2, "malicious": 3}
LEVEL_INT_TO_LABEL = {
    0: "Not Measured",
    1: "Informative",
    2: "Suspicious",
    3: "Malicious",
}
STATUS_LABEL_TO_INT = {
    "not_started": 1,
    "accepted": 2,
    "in_progress": 3,
    "clean_up": 4,
    "completed": 5,
    "error": 0,
}
STATUS_INT_TO_READABLE = {
    0: "Declined",
    1: "File received",
    2: "Submission is accepted",
    3: "Submission is running",
    4: "Submission VM is ready",
    5: "Submission is finished",
}
REPORT_TYPE_LABEL = {
    "dynamic": "dynamic",
    "static": "static",
    "cdr": "cdr",
    "url_analysis": "urlAnalysis",
    "open_in_browser": "openInBrowser",
}


def normalize_sdk_base_url(base_url: str) -> str:
    normalized_base_url = base_url.strip().rstrip("/")
    if not normalized_base_url:
        raise DemistoException("Server URL is required.")  # noqa: F405
    if normalized_base_url.endswith(PUBLIC_API_SUFFIX):
        return normalized_base_url
    return normalized_base_url + PUBLIC_API_SUFFIX


class Client(BaseClient):  # noqa: F405 - BaseClient from CommonServerPython
    """Thin wrapper over the ThreatZone SDK."""

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool) -> None:
        sdk_base_url = normalize_sdk_base_url(base_url)
        super().__init__(  # noqa: F405
            base_url=sdk_base_url,
            verify=verify,
            proxy=proxy,
            headers={"Authorization": f"Bearer {api_key}"},
        )
        http_client = httpx.Client(
            verify=verify,
            trust_env=bool(proxy),
            timeout=httpx.Timeout(SDK_REQUEST_TIMEOUT_SECONDS),
            follow_redirects=True,
        )
        self.sdk = ThreatZoneSDK(
            api_key=api_key,
            base_url=sdk_base_url,
            verify_ssl=verify,
            http_client=http_client,
        )
        self._http_client = http_client

    def close(self) -> None:
        try:
            self.sdk.close()
        finally:
            self._http_client.close()


class _OriginalNameFile:
    """Proxy a file handle while exposing its original War Room filename."""

    def __init__(self, file_handle: BinaryIO, original_name: str) -> None:
        self._file_handle = file_handle
        self.name = original_name

    def __getattr__(self, attribute: str) -> Any:
        return getattr(self._file_handle, attribute)


@contextmanager
def open_file_for_upload(file_path: Path, original_name: str) -> Iterator[BinaryIO]:
    """Open a local War Room file for streaming upload under its original name."""
    with file_path.open("rb") as file_handle:
        yield cast(BinaryIO, _OriginalNameFile(file_handle, original_name))


def translate_score(score: int | None) -> int:
    if score is None or isinstance(score, bool):
        return Common.DBotScore.NONE  # noqa: F405
    try:
        score_int = int(score)
    except (TypeError, ValueError):
        return Common.DBotScore.NONE  # noqa: F405
    if score_int <= 0:
        return Common.DBotScore.NONE  # noqa: F405
    if score_int == 1:
        return Common.DBotScore.GOOD  # noqa: F405
    if score_int == 2:
        return Common.DBotScore.SUSPICIOUS  # noqa: F405
    return Common.DBotScore.BAD  # noqa: F405


def get_reputation_reliability(reliability: str | None) -> str | None:
    mapping = {
        "A+ - 3rd party enrichment": DBotScoreReliability.A_PLUS,  # noqa: F405
        "A - Completely reliable": DBotScoreReliability.A,  # noqa: F405
        "B - Usually reliable": DBotScoreReliability.B,  # noqa: F405
        "C - Fairly reliable": DBotScoreReliability.C,  # noqa: F405
        "D - Not usually reliable": DBotScoreReliability.D,  # noqa: F405
        "E - Unreliable": DBotScoreReliability.E,  # noqa: F405
        "F - Reliability cannot be judged": DBotScoreReliability.F,  # noqa: F405
    }
    return mapping.get(reliability or "")


def build_dbot_score(
    indicator: str,
    level_int: int | None,
    indicator_type: str,
    reliability: str | None,
) -> Common.DBotScore:  # noqa: F405
    type_map = {
        "file": DBotScoreType.FILE,  # noqa: F405
        "ip": DBotScoreType.IP,  # noqa: F405
        "domain": DBotScoreType.DOMAIN,  # noqa: F405
        "url": DBotScoreType.URL,  # noqa: F405
        "email": DBotScoreType.EMAIL,  # noqa: F405
    }
    return Common.DBotScore(  # noqa: F405
        indicator=indicator,
        indicator_type=type_map.get(indicator_type, DBotScoreType.CUSTOM),  # noqa: F405
        integration_name=INTEGRATION_NAME,
        score=translate_score(level_int),
        reliability=get_reputation_reliability(reliability),
    )


def parse_int_argument(arg_value: str | None, argument_name: str) -> int | None:
    if arg_value is None or arg_value == "":
        return None
    try:
        return int(arg_value)
    except (TypeError, ValueError) as exc:
        raise DemistoException(f"{argument_name} argument must be an integer.") from exc  # noqa: F405


def parse_bounded_int_argument(
    arg_value: str | None,
    argument_name: str,
    *,
    minimum: int,
    maximum: int,
    default: int | None = None,
) -> int | None:
    """Parse an optional integer and enforce the API-supported range."""
    value = default if arg_value in (None, "") else parse_int_argument(arg_value, argument_name)
    if value is None:
        return None
    if not minimum <= value <= maximum:
        raise DemistoException(  # noqa: F405
            f"{argument_name} argument must be between {minimum} and {maximum}."
        )
    return value


def parse_json_object_argument(arg_value: str | None, argument_name: str) -> dict[str, Any] | None:
    """Parse a JSON-object command argument."""
    if not arg_value:
        return None
    try:
        parsed = json.loads(arg_value)
    except (TypeError, ValueError) as exc:
        raise DemistoException(f"{argument_name} argument must be a valid JSON object.") from exc  # noqa: F405
    if not isinstance(parsed, dict):
        raise DemistoException(f"{argument_name} argument must be a JSON object.")  # noqa: F405
    return parsed


def parse_csv_list_argument(arg_value: str | None) -> list[str] | None:
    """Parse a comma-separated command argument, omitting empty values."""
    if not arg_value:
        return None
    values = [value.strip() for value in arg_value.split(",") if value.strip()]
    return values or None


def resolve_private_flag(private_arg: str | None, default: bool = True) -> bool:
    if private_arg is None:
        return default
    return argToBoolean(private_arg)  # noqa: F405


def parse_modules_argument(modules_arg: str | None) -> list[str] | None:
    if not modules_arg:
        return None
    try:
        parsed = json.loads(modules_arg)
    except ValueError:
        parsed = None
    if isinstance(parsed, list):
        modules = [str(m).strip() for m in parsed if str(m).strip()]
    elif isinstance(parsed, str):
        modules = [parsed.strip()]
    elif parsed is None:
        modules = [m.strip() for m in modules_arg.split(",") if m.strip()]
    else:
        raise DemistoException("modules argument must be a JSON array or comma-separated string.")  # noqa: F405
    return modules or None


def parse_analyze_config_argument(analyze_arg: str | None) -> list[dict[str, Any]]:
    if not analyze_arg:
        return []
    try:
        parsed = json.loads(analyze_arg)
    except ValueError as exc:
        raise DemistoException("Invalid JSON provided for analyze_config argument.") from exc  # noqa: F405
    if isinstance(parsed, dict):
        parsed = [parsed]
    if not isinstance(parsed, list):
        raise DemistoException("analyze_config argument must be a JSON object or array of objects.")  # noqa: F405
    validated: list[dict[str, Any]] = []
    for entry in parsed:
        if not isinstance(entry, dict):
            raise DemistoException("analyze_config entries must be JSON objects.")  # noqa: F405
        metafield_id = entry.get("metafieldId")
        if not metafield_id:
            raise DemistoException("analyze_config entries must include 'metafieldId'.")  # noqa: F405
        if "value" not in entry:
            raise DemistoException("analyze_config entries must include 'value'.")  # noqa: F405
        validated.append({"metafieldId": metafield_id, "value": entry["value"]})
    return validated


def sandbox_api_defaults(client: Client) -> dict[str, Any]:
    """Return active, accessible sandbox defaults advertised by ThreatZone."""
    try:
        definitions = cast(list[MetafieldOption], client.sdk.get_metafields("sandbox"))
    except ThreatZoneError as exc:
        demisto.debug(f"Could not retrieve ThreatZone sandbox metafield defaults: {exc}")
        return {}

    defaults: dict[str, Any] = {}
    for definition in definitions:
        if not definition.active or not definition.accessible:
            continue
        if definition.options:
            default_option = next(
                (option for option in definition.options if option.value == definition.default),
                None,
            )
            if default_option is not None and not default_option.accessible:
                continue
        defaults[definition.key] = definition.default
    return defaults


def metafields_from_legacy_args(args: dict[str, Any], api_defaults: dict[str, Any] | None = None) -> dict[str, Any]:
    """Map historical sandbox arguments to SDK `metafields` dict.

    The legacy v2 integration accepted dedicated YAML arguments (timeout,
    work_path, mouse_simulation, etc.) and serialized them into an
    `analyzeConfig` envelope. The SDK now accepts a flat dict.
    """
    fields = {key: value for key, value in (api_defaults or {}).items() if key not in {"private", "raw_logs"}}
    if (timeout := parse_int_argument(args.get("timeout"), "timeout")) is not None:
        fields["timeout"] = timeout
    if work_path := args.get("work_path"):
        fields["work_path"] = work_path
    # Threat.Zone v3.2 rejects the legacy `raw_logs` metafield for dynamic
    # reports even when its value is false. Keep accepting the XSOAR argument
    # for command compatibility, but do not forward the unsupported key.
    for arg_name in (
        "mouse_simulation",
        "https_inspection",
        "internet_connection",
        "snapshot",
    ):
        if args.get(arg_name) is not None:
            fields[arg_name] = argToBoolean(args[arg_name])  # noqa: F405
    if args.get("extension_check") is not None:
        fields["dynamic_mimetype_check"] = argToBoolean(args["extension_check"])  # noqa: F405
    if parse_modules_argument(args.get("modules")) is not None:
        demisto.debug(
            "The legacy modules argument is ignored because ThreatZone v3.2 "
            "does not expose a supported submission field for module selection."
        )
    user_overrides = parse_analyze_config_argument(args.get("analyze_config"))
    for entry in user_overrides:
        fields[str(entry["metafieldId"])] = entry["value"]
    return fields


def submission_to_dict(submission: Any) -> dict[str, Any]:
    """Render any SDK pydantic model into a JSON-compatible dict (camelCase keys)."""
    if submission is None:
        return {}
    if hasattr(submission, "model_dump"):
        return submission.model_dump(by_alias=True, exclude_none=True, mode="json")
    if isinstance(submission, dict):
        return submission
    if isinstance(submission, list):
        return {"items": [submission_to_dict(item) for item in submission]}
    return {"value": submission}


def serialize_sdk_data(value: Any) -> Any:
    """Render SDK models and collections into JSON-compatible values."""
    if hasattr(value, "model_dump"):
        return value.model_dump(by_alias=True, exclude_none=True, mode="json")
    if isinstance(value, dict):
        return {key: serialize_sdk_data(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [serialize_sdk_data(item) for item in value]
    return value


def models_to_dicts(items: Any) -> list[dict[str, Any]]:
    if items is None:
        return []
    if hasattr(items, "items") and not isinstance(items, dict):
        # `IndicatorsResponse`, `IoCsResponse`, etc.
        return [submission_to_dict(item) for item in items.items]
    if isinstance(items, list):
        return [submission_to_dict(item) for item in items]
    return [submission_to_dict(items)]


def get_all_report_items(fetch_page: Callable[..., Any], uuid: str, **filters: Any) -> list[Any]:
    """Fetch every page from an SDK report endpoint that exposes an item total."""
    items: list[Any] = []
    page = 1
    while True:
        response = fetch_page(uuid, page=page, limit=REPORT_FINDINGS_PAGE_SIZE, **filters)
        page_items = list(response.items)
        items.extend(page_items)
        if not page_items or len(items) >= response.total:
            return items
        page += 1


def parse_file_size_mib(file_size: Any) -> int | float | None:
    if isinstance(file_size, bool) or file_size is None:
        return None
    if isinstance(file_size, int | float):
        numeric_size = float(file_size)
    else:
        match = re.search(r"\d+(?:\.\d+)?", str(file_size))
        if not match:
            return None
        numeric_size = float(match.group(0))
    return int(numeric_size) if numeric_size.is_integer() else numeric_size


def submission_level_int(level: str | None) -> int | None:
    if level is None:
        return None
    return LEVEL_LABEL_TO_INT.get(level)


def report_status_int(status: str | None) -> int | None:
    if status is None:
        return None
    return STATUS_LABEL_TO_INT.get(status)


def legacy_report_to_dict(report: Any) -> dict[str, Any]:
    report_dict = submission_to_dict(report)
    status_int = report_status_int(getattr(report, "status", None))
    if status_int is not None:
        report_dict["status"] = status_int
    return report_dict


def select_primary_report(submission: Any) -> Any:
    """Pick the most relevant report for legacy summary output.

    Preference order matches the legacy code: dynamic, static, cdr,
    url_analysis, open_in_browser.
    """
    if not submission or not getattr(submission, "reports", None):
        return None
    by_type = {report.type: report for report in submission.reports}
    for preferred in ("dynamic", "static", "cdr", "url_analysis", "open_in_browser"):
        if preferred in by_type:
            return by_type[preferred]
    return submission.reports[0]


def test_module(client: Client) -> str:
    try:
        client.sdk.get_user_info()
    except AuthenticationError:
        return "Authorization Error: make sure API Key is correctly set"
    except PermissionDeniedError as exc:
        return f"Authorization Error: {exc}"
    return "ok"


def threatzone_check_limits(client: Client, args: dict[str, Any]) -> list[CommandResults]:  # noqa: F405
    user_info = client.sdk.get_user_info()
    details = user_info.user_info
    limits_count = details.limits_count
    plan = user_info.plan
    submission_limits = plan.submission_limits

    limits = {
        "E_Mail": details.email,
        "Daily_Submission_Limit": f"{limits_count.daily_submission_count}/{submission_limits.daily_limit}",
        "Concurrent_Limit": f"{limits_count.concurrent_submission_count}/{submission_limits.concurrent_limit}",
        "API_Limit": f"{limits_count.api_request_count}/{submission_limits.api_limit}",
    }
    results: list[CommandResults] = [  # noqa: F405
        CommandResults(  # noqa: F405
            outputs_prefix="ThreatZone.Limits",
            outputs_key_field="E_Mail",
            outputs=limits,
            readable_output=tableToMarkdown("LIMITS", limits, removeNull=True),  # noqa: F405
        )
    ]
    if argToBoolean(args.get("detailed", "false")):  # noqa: F405
        plan_details = {
            "File_Size_Limit_MiB": parse_file_size_mib(plan.file_limits.file_size),
            "Allowed_Extensions": plan.file_limits.extensions,
            "Modules": [module.module_name for module in user_info.modules],
        }
        results.append(
            CommandResults(  # noqa: F405
                outputs_prefix="ThreatZone.Plan",
                outputs=plan_details,
                readable_output=tableToMarkdown("PLAN DETAILS", plan_details, removeNull=True),  # noqa: F405
            )
        )
        metadata = {
            "Full_Name": details.full_name,
            "Workspace": details.workspace.name,
            "Plan_Name": plan.plan_name,
        }
        filtered_metadata = {k: v for k, v in metadata.items() if v not in (None, "", [])}
        if filtered_metadata:
            results.append(
                CommandResults(  # noqa: F405
                    outputs_prefix="ThreatZone.Metadata",
                    outputs=filtered_metadata,
                    readable_output=tableToMarkdown("ACCOUNT METADATA", filtered_metadata, removeNull=True),  # noqa: F405
                )
            )
    return results


def _verify_plan_capacity(client: Client, *, requires_concurrent: bool) -> None:
    """Raise DemistoException when the plan has no remaining quota for an upload."""
    info = client.sdk.get_user_info()
    counts = info.user_info.limits_count
    limits = info.plan.submission_limits
    if counts.api_request_count >= limits.api_limit > 0:
        raise DemistoException(  # noqa: F405
            f"API request limit ({limits.api_limit}) exceeded. Upgrade your plan or contact us."
        )
    if counts.daily_submission_count >= limits.daily_limit > 0:
        raise DemistoException(  # noqa: F405
            f"Daily submission limit ({limits.daily_limit}) exceeded. Upgrade your plan or contact us."
        )
    if requires_concurrent and counts.concurrent_submission_count >= limits.concurrent_limit > 0:
        raise DemistoException(  # noqa: F405
            f"Concurrent analysis limit ({limits.concurrent_limit}) exceeded. Wait for in-flight analyses to finish."
        )


def _file_from_entry(args: dict[str, Any]) -> tuple[Path, str]:
    entry_id = args.get("entry_id")
    if not entry_id:
        raise DemistoException("entry_id argument is required.")  # noqa: F405
    try:
        file_info = demisto.getFilePath(entry_id)
    except Exception as exc:
        raise DemistoException(f"Failed to retrieve file for entry ID {entry_id}.") from exc  # noqa: F405
    return Path(file_info["path"]), file_info["name"]


def _build_limits_payload(client: Client) -> dict[str, Any]:
    """Build the current plan limits payload returned with upload results."""
    info = client.sdk.get_user_info()
    counts = info.user_info.limits_count
    limits = info.plan.submission_limits
    return {
        "E_Mail": info.user_info.email,
        "Daily_Submission_Limit": f"{counts.daily_submission_count}/{limits.daily_limit}",
        "Concurrent_Limit": f"{counts.concurrent_submission_count}/{limits.concurrent_limit}",
        "API_Limit": f"{counts.api_request_count}/{limits.api_limit}",
    }


def _submission_result(scan_prefix: str, payload: dict[str, Any], readable: str, limits: dict[str, Any]) -> list[CommandResults]:  # noqa: F405
    filtered = {k: v for k, v in payload.items() if v not in (None, "", [])}
    return [
        CommandResults(  # noqa: F405
            outputs_prefix=f"ThreatZone.Submission.{scan_prefix}",
            outputs_key_field="UUID",
            outputs=filtered,
            readable_output=readable,
        ),
        CommandResults(  # noqa: F405
            outputs_prefix="ThreatZone.Limits",
            outputs_key_field="E_Mail",
            outputs=limits,
        ),
    ]


def threatzone_sandbox_upload_sample(client: Client, args: dict[str, Any]) -> list[CommandResults]:  # noqa: F405
    _verify_plan_capacity(client, requires_concurrent=True)
    file_path, original_name = _file_from_entry(args)

    auto_select_environment = argToBoolean(args.get("auto", "false"))  # noqa: F405
    environment = None if auto_select_environment else args.get("environment")
    api_defaults = sandbox_api_defaults(client)
    private = resolve_private_flag(args.get("private"), bool(api_defaults.get("private", True)))
    entrypoint = args.get("entrypoint")
    password = args.get("password")
    metafields = metafields_from_legacy_args(args, api_defaults)
    configurations = parse_json_object_argument(args.get("configurations"), "configurations")

    with open_file_for_upload(file_path, original_name) as upload_file:
        submission = client.sdk.create_sandbox_submission(
            upload_file,
            environment=environment,
            auto_select_environment=auto_select_environment,
            metafields=metafields or None,
            private=private,
            entrypoint=entrypoint,
            password=password,
            configurations=configurations,
        )
    message = submission.message
    submission_uuid = submission.uuid
    payload = {
        "Message": message,
        "UUID": submission_uuid,
        "FileName": original_name,
    }
    readable = tableToMarkdown("SAMPLE UPLOADED", payload)  # noqa: F405
    return _submission_result("Sandbox", payload, readable, _build_limits_payload(client))


def threatzone_static_or_cdr_upload(client: Client, args: dict[str, Any], scan_type: str) -> list[CommandResults]:  # noqa: F405
    if scan_type not in ("static", "cdr"):
        raise DemistoException(f"Unsupported scan_type '{scan_type}'.")  # noqa: F405
    _verify_plan_capacity(client, requires_concurrent=True)
    file_path, original_name = _file_from_entry(args)
    private = resolve_private_flag(args.get("private"))
    entrypoint = args.get("entrypoint")
    password = args.get("password")
    extension_check = args.get("extension_check")
    dynamic_mimetype_check = argToBoolean(extension_check) if extension_check is not None else None  # noqa: F405

    with open_file_for_upload(file_path, original_name) as upload_file:
        if scan_type == "static":
            submission = client.sdk.create_static_submission(
                upload_file,
                private=private,
                entrypoint=entrypoint,
                password=password,
                dynamic_mimetype_check=dynamic_mimetype_check,
            )
            prefix = "Static"
        else:
            submission = client.sdk.create_cdr_submission(
                upload_file,
                private=private,
                entrypoint=entrypoint,
                password=password,
                dynamic_mimetype_check=dynamic_mimetype_check,
            )
            prefix = "CDR"
    payload = {
        "Message": submission.message,
        "UUID": submission.uuid,
        "FileName": original_name,
    }
    readable = tableToMarkdown("SAMPLE UPLOADED", payload)  # noqa: F405
    return _submission_result(prefix, payload, readable, _build_limits_payload(client))


def threatzone_submit_url_analysis(client: Client, args: dict[str, Any]) -> list[CommandResults]:  # noqa: F405
    _verify_plan_capacity(client, requires_concurrent=False)
    url_value = args.get("url")
    if not url_value:
        raise DemistoException("url argument is required.")  # noqa: F405
    private = resolve_private_flag(args.get("private"))
    safe_browsing = argToBoolean(args.get("safe_browsing", "false"))  # noqa: F405
    submission = client.sdk.create_url_submission(url_value, private=private, safe_browsing=safe_browsing)
    payload = {
        "Message": submission.message,
        "UUID": submission.uuid,
        "URL": url_value,
    }
    readable = tableToMarkdown("URL SUBMITTED", payload)  # noqa: F405
    return _submission_result("URL", payload, readable, _build_limits_payload(client))


def _build_indicator_object(submission: Any, level_int: int | None) -> Any:
    hashes = getattr(submission, "hashes", None)
    sha256 = getattr(hashes, "sha256", None) if hashes else None
    md5 = getattr(hashes, "md5", None) if hashes else None
    sha1 = getattr(hashes, "sha1", None) if hashes else None
    url_value = getattr(submission, "url", None)
    reliability = demisto.params().get("integrationReliability")

    if sha256:
        dbot = build_dbot_score(sha256, level_int, "file", reliability)
        return Common.File(dbot, md5=md5, sha1=sha1, sha256=sha256)  # noqa: F405
    if url_value:
        dbot = build_dbot_score(url_value, level_int, "url", reliability)
        return Common.URL(url=url_value, dbot_score=dbot)  # noqa: F405
    return None


def threatzone_get_result(client: Client, args: dict[str, Any]) -> list[CommandResults | dict]:  # noqa: F405
    uuid = args.get("uuid")
    if not uuid:
        raise DemistoException("uuid argument is required.")  # noqa: F405

    submission = client.sdk.get_submission(uuid)
    submission_dict = submission_to_dict(submission)
    primary_report = select_primary_report(submission)

    level_int = submission_level_int(submission.level)
    level_label = LEVEL_INT_TO_LABEL.get(level_int) if level_int is not None else "Unknown"

    status_label = primary_report.status if primary_report else None
    status_int = report_status_int(status_label)
    if status_int == 0:
        raise DemistoException(  # noqa: F405
            "Submission is declined by the scanner. The file may be corrupted or the analyzer encountered an unrecoverable error."
        )
    status_readable = STATUS_INT_TO_READABLE.get(status_int, status_label or "Unknown") if status_int is not None else "Unknown"
    legacy_report = legacy_report_to_dict(primary_report)

    report_type_label = REPORT_TYPE_LABEL.get(primary_report.type, primary_report.type) if primary_report else None
    analysis_type_label = "URL Analysis" if report_type_label == "urlAnalysis" else (report_type_label or "")

    hashes = submission.hashes
    md5 = hashes.md5 if hashes else None
    sha1 = hashes.sha1 if hashes else None
    sha256 = hashes.sha256 if hashes else None
    analyzed_url = submission.url
    file_name = submission.filename or (submission.file.name if submission.file else None)
    private_flag = submission.private

    summary_info: dict[str, Any] = {"private": private_flag}
    if file_name:
        summary_info["file_name"] = file_name
    if analyzed_url:
        summary_info["url"] = analyzed_url

    summary_output: dict[str, Any] = {
        "TYPE": analysis_type_label,
        "STATUS": status_readable,
        "MD5": md5,
        "SHA1": sha1,
        "SHA256": sha256,
        "LEVEL": level_int,
        "LEVEL_LABEL": level_label,
        "INFO": summary_info,
        "UUID": submission.uuid,
        "REPORT": dict(legacy_report),
    }
    submission_dict["Summary"] = summary_output

    download_sanitized = argToBoolean(args.get("download_sanitized", "false"))  # noqa: F405
    include_details = argToBoolean(args.get("details", "false"))  # noqa: F405

    warnings: list[str] = []
    if status_int is not None and status_int != 5:
        warnings.append(f"Submission status is '{status_readable}'; some sections may not yet be available.")

    indicator_obj = _build_indicator_object(submission, level_int)

    sanitized_file: dict | None = None
    if primary_report and primary_report.type == "cdr" and status_int == 5 and download_sanitized:
        try:
            sanitized_file = threatzone_get_sanitized_file(client, {"uuid": submission.uuid})
        except (ThreatZoneError, DemistoException) as exc:  # noqa: F405
            warnings.append(f"sanitized-download: {exc}")

    readable_summary: dict[str, Any] = {
        "ANALYSIS TYPE": analysis_type_label,
        "STATUS": status_readable,
        "THREAT_LEVEL": level_label,
        "PRIVATE": private_flag,
        "UUID": submission.uuid,
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

    readable_output = tableToMarkdown("Submission Result", readable_summary, removeNull=True)  # noqa: F405

    detail_extras: list[CommandResults] = []  # noqa: F405
    ioc_items: list[Any] = []
    ioc_fetch_attempted = False
    if include_details:
        try:
            indicators_data = models_to_dicts(get_all_report_items(client.sdk.get_indicators, submission.uuid))
            detail_extras.append(
                _section_result(
                    submission.uuid,
                    "ThreatZone.Submission.Indicators",
                    "Dynamic Indicators",
                    indicators_data,
                )
            )
        except ReportUnavailableError as exc:
            warnings.append(f"indicators-unavailable: {exc}")
        ioc_fetch_attempted = True
        try:
            ioc_items = get_all_report_items(client.sdk.get_iocs, submission.uuid)
            iocs_data = models_to_dicts(ioc_items)
            detail_extras.append(
                _section_result(
                    submission.uuid,
                    "ThreatZone.Submission.IOCs",
                    "Indicators of Compromise",
                    iocs_data,
                )
            )
        except ReportUnavailableError as exc:
            warnings.append(f"iocs-unavailable: {exc}")
        try:
            yara_data = models_to_dicts(get_all_report_items(client.sdk.get_yara_rules, submission.uuid))
            detail_extras.append(
                _section_result(
                    submission.uuid,
                    "ThreatZone.Submission.YaraMatches",
                    "Matched YARA Rules",
                    yara_data,
                )
            )
        except ReportUnavailableError as exc:
            warnings.append(f"yara-unavailable: {exc}")
        try:
            artifacts_data = models_to_dicts(client.sdk.get_artifacts(submission.uuid))
            detail_extras.append(
                _section_result(
                    submission.uuid,
                    "ThreatZone.Submission.Artifacts",
                    "Analysis Artifacts",
                    artifacts_data,
                )
            )
        except ReportUnavailableError as exc:
            warnings.append(f"artifacts-unavailable: {exc}")
        try:
            configs_data = models_to_dicts(client.sdk.get_extracted_configs(submission.uuid))
            detail_extras.append(
                _section_result(
                    submission.uuid,
                    "ThreatZone.Submission.Config",
                    "Configuration Extractor Results",
                    configs_data,
                )
            )
        except ReportUnavailableError as exc:
            warnings.append(f"config-unavailable: {exc}")

    if warnings:
        warning_lines = "\n".join(f"- {warning}" for warning in warnings)
        readable_output = f"{readable_output}\n\n### Additional Data Notes\n{warning_lines}"

    legacy_analysis: dict[str, Any] = {
        "TYPE": report_type_label,
        "STATUS": status_int if status_int is not None else -1,
        "MD5": md5,
        "SHA1": sha1,
        "SHA256": sha256,
        "LEVEL": level_int,
        "INFO": dict(summary_info),
        "UUID": submission.uuid,
        "REPORT": dict(legacy_report),
        "URL": analyzed_url,
        "SANITIZED": sanitized_file.get("EntryID") if isinstance(sanitized_file, dict) else None,
    }

    legacy_iocs: dict[str, list[Any]] = {"URL": [], "DOMAIN": [], "EMAIL": [], "IP": []}
    if not ioc_fetch_attempted:
        try:
            ioc_items = get_all_report_items(client.sdk.get_iocs, submission.uuid)
        except (ReportUnavailableError, APIError) as exc:
            demisto.debug(f"Could not retrieve ThreatZone IOCs for legacy output: {exc}")
    for item in ioc_items:
        bucket = item.type.upper()
        if bucket in legacy_iocs:
            legacy_iocs[bucket].append(item.value)

    command_results: list[CommandResults | dict] = [  # noqa: F405
        CommandResults(  # noqa: F405
            outputs_prefix="ThreatZone.Submission",
            outputs_key_field="uuid",
            outputs=submission_dict,
            raw_response=submission_dict,
            readable_output=readable_output,
            indicator=indicator_obj,
        ),
        CommandResults(  # noqa: F405
            outputs_prefix="ThreatZone.Analysis",
            outputs_key_field="UUID",
            outputs=legacy_analysis,
        ),
        CommandResults(  # noqa: F405
            outputs_prefix="ThreatZone.IOC",
            outputs=legacy_iocs,
        ),
    ]
    command_results.extend(detail_extras)
    if sanitized_file:
        command_results.append(sanitized_file)
    return command_results


def _section_result(uuid: str, prefix: str, title: str, data: list[dict[str, Any]]) -> CommandResults:  # noqa: F405
    readable = tableToMarkdown(title, data, removeNull=True) if data else f"{title}\nNo data returned."  # noqa: F405
    outputs: dict[str, Any] | None = {"UUID": uuid, "Data": data} if data else None
    return CommandResults(  # noqa: F405
        outputs_prefix=prefix,
        outputs_key_field="UUID" if outputs else None,
        outputs=outputs,
        readable_output=readable,
    )


def _require_uuid(args: dict[str, Any]) -> str:
    uuid = args.get("uuid")
    if not uuid:
        raise DemistoException("uuid argument is required.")  # noqa: F405
    return uuid


def threatzone_get_indicator_result(client: Client, args: dict[str, Any]) -> list[CommandResults]:  # noqa: F405
    uuid = _require_uuid(args)
    filters = {
        "level": args.get("level"),
        "category": args.get("category"),
        "pid": parse_int_argument(args.get("pid"), "pid"),
        "attack_code": args.get("attack_code"),
    }
    data = models_to_dicts(
        get_all_report_items(
            client.sdk.get_indicators,
            uuid,
            **{key: value for key, value in filters.items() if value is not None},
        )
    )
    return [_section_result(uuid, "ThreatZone.Submission.Indicators", "Dynamic Indicators", data)]


def threatzone_get_ioc_result(client: Client, args: dict[str, Any]) -> list[CommandResults]:  # noqa: F405
    uuid = _require_uuid(args)
    filters = {"type": args.get("type")} if args.get("type") else {}
    data = models_to_dicts(get_all_report_items(client.sdk.get_iocs, uuid, **filters))
    return [_section_result(uuid, "ThreatZone.Submission.IOCs", "Indicators of Compromise", data)]


def threatzone_get_yara_result(client: Client, args: dict[str, Any]) -> list[CommandResults]:  # noqa: F405
    uuid = _require_uuid(args)
    filters = {"category": args.get("category")} if args.get("category") else {}
    data = models_to_dicts(get_all_report_items(client.sdk.get_yara_rules, uuid, **filters))
    return [_section_result(uuid, "ThreatZone.Submission.YaraMatches", "Matched YARA Rules", data)]


def threatzone_get_artifact_result(client: Client, args: dict[str, Any]) -> list[CommandResults]:  # noqa: F405
    uuid = _require_uuid(args)
    data = models_to_dicts(client.sdk.get_artifacts(uuid))
    return [_section_result(uuid, "ThreatZone.Submission.Artifacts", "Analysis Artifacts", data)]


def threatzone_get_config_result(client: Client, args: dict[str, Any]) -> list[CommandResults]:  # noqa: F405
    uuid = _require_uuid(args)
    data = models_to_dicts(client.sdk.get_extracted_configs(uuid))
    return [
        _section_result(
            uuid,
            "ThreatZone.Submission.Config",
            "Configuration Extractor Results",
            data,
        )
    ]


def _structured_result(
    prefix: str,
    title: str,
    data: Any,
    *,
    uuid: str | None = None,
    scan_type: str | None = None,
) -> CommandResults:  # noqa: F405
    """Build a predictable Data envelope for SDK-native command results."""
    serialized_data = serialize_sdk_data(data)
    outputs: dict[str, Any] = {"Data": serialized_data}
    if uuid is not None:
        outputs["UUID"] = uuid
    if scan_type is not None:
        outputs["ScanType"] = scan_type
    readable = (
        tableToMarkdown(title, serialized_data, removeNull=True)  # noqa: F405
        if serialized_data
        else f"{title}\nNo data returned."
    )
    return CommandResults(  # noqa: F405
        outputs_prefix=prefix,
        outputs_key_field="UUID" if uuid is not None else None,
        outputs=outputs,
        readable_output=readable,
    )


def threatzone_get_metafields(client: Client, args: dict[str, Any]) -> list[CommandResults]:  # noqa: F405
    scan_type = args.get("scan_type")
    allowed_scan_types = {"sandbox", "static", "cdr", "url", "open_in_browser"}
    if scan_type and scan_type not in allowed_scan_types:
        raise DemistoException(  # noqa: F405
            "scan_type must be one of sandbox, static, cdr, url, or open_in_browser."
        )
    data = client.sdk.get_metafields(scan_type) if scan_type else client.sdk.get_metafields()
    return [
        _structured_result(
            "ThreatZone.Configuration.Metafields",
            "ThreatZone Metafields",
            data,
            scan_type=scan_type,
        )
    ]


def threatzone_get_environments(client: Client, args: dict[str, Any]) -> list[CommandResults]:  # noqa: F405
    return [
        _structured_result(
            "ThreatZone.Configuration.Environments",
            "ThreatZone Environments",
            client.sdk.get_environments(),
        )
    ]


def threatzone_list_network_configs(client: Client, args: dict[str, Any]) -> list[CommandResults]:  # noqa: F405
    return [
        _structured_result(
            "ThreatZone.Configuration.NetworkConfigurations",
            "ThreatZone Network Configurations",
            client.sdk.list_network_configs(),
        )
    ]


def threatzone_open_in_browser(client: Client, args: dict[str, Any]) -> list[CommandResults]:  # noqa: F405
    _verify_plan_capacity(client, requires_concurrent=True)
    url_value = args.get("url")
    if not url_value:
        raise DemistoException("url argument is required.")  # noqa: F405
    auto_select_environment = argToBoolean(args.get("auto", "false"))  # noqa: F405
    environment = None if auto_select_environment else args.get("environment")
    submission = client.sdk.create_open_in_browser_submission(
        url_value,
        environment=environment,
        auto_select_environment=auto_select_environment,
        metafields=parse_json_object_argument(args.get("metafields"), "metafields"),
        private=resolve_private_flag(args.get("private")),
        configurations=parse_json_object_argument(args.get("configurations"), "configurations"),
    )
    payload = {"Message": submission.message, "UUID": submission.uuid, "URL": url_value}
    readable = tableToMarkdown("OPEN IN BROWSER SUBMITTED", payload)  # noqa: F405
    return _submission_result("OpenInBrowser", payload, readable, _build_limits_payload(client))


def threatzone_list_submissions(client: Client, args: dict[str, Any]) -> list[CommandResults]:  # noqa: F405
    page = cast(
        int,
        parse_bounded_int_argument(args.get("page"), "page", minimum=1, maximum=2_147_483_647, default=1),
    )
    limit = cast(
        int,
        parse_bounded_int_argument(args.get("limit"), "limit", minimum=1, maximum=100, default=20),
    )
    private = argToBoolean(args["private"]) if args.get("private") is not None else None  # noqa: F405
    response = client.sdk.list_submissions(
        page=page,
        limit=limit,
        level=parse_csv_list_argument(args.get("level")),
        type=args.get("type"),
        sha256=args.get("sha256"),
        filename=args.get("filename"),
        start_date=args.get("start_date"),
        end_date=args.get("end_date"),
        private=private,
        tags=parse_csv_list_argument(args.get("tags")),
        sort=args.get("sort"),
        order=args.get("order"),
    )
    serialized = serialize_sdk_data(response)
    return [
        CommandResults(  # noqa: F405
            outputs_prefix="ThreatZone.SubmissionList",
            outputs=serialized,
            readable_output=tableToMarkdown("ThreatZone Submissions", serialized.get("items", []), removeNull=True),  # noqa: F405
        )
    ]


def threatzone_search_submissions(client: Client, args: dict[str, Any]) -> list[CommandResults]:  # noqa: F405
    sha256 = args.get("sha256")
    if not sha256:
        raise DemistoException("sha256 argument is required.")  # noqa: F405
    return [
        _structured_result(
            "ThreatZone.SubmissionSearch",
            "ThreatZone Submission Search",
            client.sdk.search_by_sha256(sha256),
        )
    ]


def threatzone_get_uuid_section(
    client: Client,
    args: dict[str, Any],
    sdk_method: str,
    section: str,
    title: str,
) -> list[CommandResults]:  # noqa: F405
    uuid = _require_uuid(args)
    data = getattr(client.sdk, sdk_method)(uuid)
    return [_structured_result(f"ThreatZone.Submission.{section}", title, data, uuid=uuid)]


def threatzone_get_behaviours(client: Client, args: dict[str, Any]) -> list[CommandResults]:  # noqa: F405
    uuid = _require_uuid(args)
    page = cast(
        int,
        parse_bounded_int_argument(args.get("page"), "page", minimum=1, maximum=2_147_483_647, default=1),
    )
    limit = cast(
        int,
        parse_bounded_int_argument(args.get("limit"), "limit", minimum=1, maximum=500, default=100),
    )
    data = client.sdk.get_behaviours(
        uuid,
        type=args.get("type"),
        pid=parse_int_argument(args.get("pid"), "pid"),
        operation=args.get("operation"),
        process_name=args.get("process_name"),
        page=page,
        limit=limit,
    )
    return [_structured_result("ThreatZone.Submission.Behaviours", "ThreatZone Behaviours", data, uuid=uuid)]


def threatzone_get_syscalls(client: Client, args: dict[str, Any]) -> list[CommandResults]:  # noqa: F405
    uuid = _require_uuid(args)
    page = cast(
        int,
        parse_bounded_int_argument(args.get("page"), "page", minimum=1, maximum=2_147_483_647, default=1),
    )
    limit = cast(
        int,
        parse_bounded_int_argument(args.get("limit"), "limit", minimum=1, maximum=2000, default=500),
    )
    data = client.sdk.get_syscalls(uuid, page=page, limit=limit)
    return [_structured_result("ThreatZone.Submission.Syscalls", "ThreatZone Syscalls", data, uuid=uuid)]


def threatzone_get_network_data(
    client: Client,
    args: dict[str, Any],
    sdk_method: str,
    section: str,
    title: str,
) -> list[CommandResults]:  # noqa: F405
    uuid = _require_uuid(args)
    limit = parse_bounded_int_argument(args.get("limit"), "limit", minimum=0, maximum=1000)
    skip = parse_bounded_int_argument(args.get("skip"), "skip", minimum=0, maximum=1000)
    window = {"limit": limit, "skip": skip}
    data = getattr(client.sdk, sdk_method)(uuid, **{key: value for key, value in window.items() if value is not None})
    return [_structured_result(f"ThreatZone.Submission.{section}", title, data, uuid=uuid)]


def _save_download(download: DownloadResponse, fallback_filename: str) -> dict[str, Any]:
    try:
        download_filename = Path(download.filename.replace("\\", "/")).name if download.filename else ""
        filename = fallback_filename if download_filename in ("", "download") else download_filename
        saved_path = download.save(filename)
    finally:
        download.close()
    return file_result_existing_file(str(saved_path), filename)  # noqa: F405


def _safe_media_filename(filename: str, fallback_filename: str) -> str:
    """Reject unsafe API-provided media names instead of writing outside the War Room."""
    if not filename:
        return fallback_filename
    if filename in {".", ".."} or "\x00" in filename or "/" in filename or "\\" in filename:
        raise DemistoException("ThreatZone returned an unsafe media filename.")  # noqa: F405
    return filename


def threatzone_download_sdk_file(
    client: Client,
    args: dict[str, Any],
    sdk_method: str,
    fallback_pattern: str,
    *,
    id_argument: str | None = None,
) -> dict[str, Any]:
    uuid = _require_uuid(args)
    if id_argument:
        resource_id = args.get(id_argument)
        if not resource_id:
            raise DemistoException(f"{id_argument} argument is required.")  # noqa: F405
        download = getattr(client.sdk, sdk_method)(uuid, resource_id)
    else:
        download = getattr(client.sdk, sdk_method)(uuid)
    return _save_download(download, fallback_pattern.format(uuid=uuid))


def threatzone_download_yara_rule(client: Client, args: dict[str, Any]) -> dict[str, Any]:
    uuid = _require_uuid(args)
    timeout = cast(
        int,
        parse_bounded_int_argument(args.get("timeout"), "timeout", minimum=1, maximum=3600, default=120),
    )
    started_at = time.monotonic()
    while True:
        try:
            download = client.sdk.download_yara_rule(uuid)
            return _save_download(download, f"{uuid}.yar")
        except YaraRulePendingError as exc:
            elapsed = time.monotonic() - started_at
            retry_after = max(0.0, exc.retry_after) if exc.retry_after is not None else YARA_POLL_INTERVAL_SECONDS
            if elapsed >= timeout or retry_after > timeout - elapsed:
                raise DemistoException(  # noqa: F405
                    f"Timed out after {timeout} seconds waiting for the generated YARA rule."
                ) from exc
            demisto.executeCommand("Sleep", {"seconds": str(retry_after)})


def threatzone_download_url_screenshot(client: Client, args: dict[str, Any]) -> dict[str, Any]:
    uuid = _require_uuid(args)
    return fileResult(f"threatzone-url-screenshot-{uuid}.png", client.sdk.get_screenshot(uuid))  # noqa: F405


def threatzone_list_media_files(client: Client, args: dict[str, Any]) -> list[CommandResults]:  # noqa: F405
    uuid = _require_uuid(args)
    return [
        _structured_result(
            "ThreatZone.Submission.MediaFiles",
            "ThreatZone Media Files",
            client.sdk.list_media_files(uuid),
            uuid=uuid,
        )
    ]


def threatzone_download_media_file(client: Client, args: dict[str, Any]) -> dict[str, Any]:
    uuid = _require_uuid(args)
    file_id = args.get("file_id")
    if not file_id:
        raise DemistoException("file_id argument is required.")  # noqa: F405
    media_files = client.sdk.list_media_files(uuid)
    media_file = next((item for item in media_files if item.id == file_id), None)
    if media_file is None:
        raise DemistoException(f"Media file '{file_id}' was not found for submission '{uuid}'.")  # noqa: F405
    filename = _safe_media_filename(media_file.name, f"threatzone-media-{uuid}-{file_id}")
    return fileResult(filename, client.sdk.get_media_file(uuid, file_id))  # noqa: F405


def threatzone_get_sanitized_file(client: Client, args: dict[str, Any]) -> dict[str, Any]:
    uuid = _require_uuid(args)
    download = client.sdk.download_cdr_result(uuid)
    return _save_download(download, f"sanitized-{uuid}.zip")


def threatzone_get_html_report_file(client: Client, args: dict[str, Any]) -> dict[str, Any]:
    uuid = _require_uuid(args)
    download = client.sdk.download_html_report(uuid)
    return _save_download(download, f"threatzone-report-{uuid}.html")


def _format_sdk_exception(exc: Exception) -> str:
    if isinstance(exc, AuthenticationError):
        return f"Authorization error: {exc}. Verify the API key is correct and active."
    if isinstance(exc, PermissionDeniedError):
        return f"Permission denied: {exc}"
    if isinstance(exc, PaymentRequiredError):
        return f"Plan limit reached: {exc}"
    if isinstance(exc, NotFoundError):
        return f"Resource not found: {exc}"
    if isinstance(exc, BadRequestError):
        return f"Bad request: {exc}"
    if isinstance(exc, RateLimitError):
        return f"Rate limited: {exc}"
    if isinstance(exc, ReportUnavailableError):
        return f"Report not yet available: {exc}"
    if isinstance(exc, YaraRulePendingError):
        return f"YARA rule still being generated: {exc}"
    if isinstance(exc, AnalysisTimeoutError):
        return f"Analysis timed out: {exc}"
    if isinstance(exc, APIError):
        return f"ThreatZone API error: {exc}"
    return str(exc)


CommandHandler = Callable[[Client, dict[str, Any]], Any]


def _uuid_section_handler(sdk_method: str, section: str, title: str) -> CommandHandler:
    return lambda client, args: threatzone_get_uuid_section(client, args, sdk_method, section, title)


def _network_handler(sdk_method: str, section: str, title: str) -> CommandHandler:
    return lambda client, args: threatzone_get_network_data(client, args, sdk_method, section, title)


COMMAND_HANDLERS: dict[str, CommandHandler] = {
    "test-module": lambda client, args: test_module(client),
    "tz-check-limits": threatzone_check_limits,
    "tz-sandbox-upload-sample": threatzone_sandbox_upload_sample,
    "tz-static-upload-sample": lambda client, args: threatzone_static_or_cdr_upload(client, args, "static"),
    "tz-cdr-upload-sample": lambda client, args: threatzone_static_or_cdr_upload(client, args, "cdr"),
    "tz-url-analysis": threatzone_submit_url_analysis,
    "tz-open-in-browser": threatzone_open_in_browser,
    "tz-list-submissions": threatzone_list_submissions,
    "tz-search-submissions-by-sha256": threatzone_search_submissions,
    "tz-get-metafields": threatzone_get_metafields,
    "tz-get-environments": threatzone_get_environments,
    "tz-list-network-configs": threatzone_list_network_configs,
    "tz-get-result": threatzone_get_result,
    "tz-get-indicator-result": threatzone_get_indicator_result,
    "tz-get-ioc-result": threatzone_get_ioc_result,
    "tz-get-yara-result": threatzone_get_yara_result,
    "tz-get-artifact-result": threatzone_get_artifact_result,
    "tz-get-config-result": threatzone_get_config_result,
    "tz-get-overview-summary": _uuid_section_handler("get_overview_summary", "OverviewSummary", "ThreatZone Overview Summary"),
    "tz-get-eml-analysis": _uuid_section_handler("get_eml_analysis", "EMLAnalysis", "ThreatZone EML Analysis"),
    "tz-get-mitre-techniques": _uuid_section_handler("get_mitre_techniques", "MITRE", "ThreatZone MITRE ATT&CK Techniques"),
    "tz-get-static-scan-result": _uuid_section_handler("get_static_scan_results", "StaticScan", "ThreatZone Static Scan"),
    "tz-get-cdr-result": _uuid_section_handler("get_cdr_results", "CDRResult", "ThreatZone CDR Result"),
    "tz-get-signature-check-result": _uuid_section_handler(
        "get_signature_check_results", "SignatureCheck", "ThreatZone Signature Check"
    ),
    "tz-get-processes": _uuid_section_handler("get_processes", "Processes", "ThreatZone Processes"),
    "tz-get-process-tree": _uuid_section_handler("get_process_tree", "ProcessTree", "ThreatZone Process Tree"),
    "tz-get-behaviours": threatzone_get_behaviours,
    "tz-get-syscalls": threatzone_get_syscalls,
    "tz-get-url-analysis-result": _uuid_section_handler("get_url_analysis", "URLAnalysis", "ThreatZone URL Analysis"),
    "tz-get-network-summary": _uuid_section_handler("get_network_summary", "NetworkSummary", "ThreatZone Network Summary"),
    "tz-get-dns-queries": _network_handler("get_dns_queries", "DNSQueries", "ThreatZone DNS Queries"),
    "tz-get-http-requests": _network_handler("get_http_requests", "HTTPRequests", "ThreatZone HTTP Requests"),
    "tz-get-tcp-connections": _network_handler("get_tcp_connections", "TCPConnections", "ThreatZone TCP Connections"),
    "tz-get-udp-connections": _network_handler("get_udp_connections", "UDPConnections", "ThreatZone UDP Connections"),
    "tz-get-network-threats": _network_handler("get_network_threats", "NetworkThreats", "ThreatZone Network Threats"),
    "tz-get-sanitized": threatzone_get_sanitized_file,
    "tz-download-html-report": threatzone_get_html_report_file,
    "tz-download-static-scan-strings": lambda client, args: (
        threatzone_download_sdk_file(client, args, "get_static_scan_strings", "{uuid}_strings.json")
    ),
    "tz-download-sample": lambda client, args: threatzone_download_sdk_file(client, args, "download_sample", "sample-{uuid}"),
    "tz-download-artifact": lambda client, args: threatzone_download_sdk_file(
        client, args, "download_artifact", "artifact-{uuid}", id_argument="artifact_id"
    ),
    "tz-download-pcap": lambda client, args: threatzone_download_sdk_file(
        client, args, "download_pcap", "threatzone-{uuid}.pcap"
    ),
    "tz-download-yara-rule": threatzone_download_yara_rule,
    "tz-download-url-screenshot": threatzone_download_url_screenshot,
    "tz-list-media-files": threatzone_list_media_files,
    "tz-download-media-file": threatzone_download_media_file,
}


def main() -> None:
    params = demisto.params()
    base_url = str(params.get("url") or "")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    api_key = str(params.get("apikey") or "")
    handle_proxy()  # noqa: F405 - propagates HTTPS_PROXY env vars when proxy enabled

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    args = demisto.args()

    client: Client | None = None
    try:
        client = Client(base_url=base_url, api_key=api_key, verify=verify, proxy=proxy)
        handler = COMMAND_HANDLERS.get(command)
        if handler is None:
            raise DemistoException(f"Command '{command}' is not implemented.")  # noqa: F405
        return_results(handler(client, args))  # noqa: F405
    except Exception as exc:
        error_message = _format_sdk_exception(exc) if isinstance(exc, ThreatZoneError) else str(exc)
        return_error(f"Failed to execute {command} command.\nError:\n{error_message}")  # noqa: F405
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:  # pragma: no cover - cleanup best-effort
                pass


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
