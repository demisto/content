"""
IPQualityScore integration for XSOAR.

Supports:
- IP reputation
- URL/domain reputation
- Email reputation
- Phone reputation
- Leak checks (username, password, email)
- Malware scan / lookup for files and URLs
"""

from collections.abc import Callable
from ipaddress import ip_address
from re import compile as re_compile
from typing import Any
from urllib.parse import quote, urlparse

import demistomock as demisto  # pylint: disable=import-error
import urllib3
from CommonServerPython import *  # pylint: disable=import-error,unused-wildcard-import,wildcard-import
from CommonServerUserPython import *  # pylint: disable=import-error

INTEGRATION_NAME = "IPQualityScore"
BASE_URL = "https://ipqualityscore.com/api/json"
MALWARE_SCAN_URL = f"{BASE_URL}/malware/scan/"
MALWARE_LOOKUP_URL = f"{BASE_URL}/malware/lookup/"

DEFAULT_THRESHOLD_VALUES = {"suspicious": 75, "malicious": 90}
DEFAULT_FILE_THRESHOLD_VALUES = {"suspicious": 1, "malicious": 4}

DEFAULT_MAX_RETRIES = 9
DEFAULT_POLLING_INTERVAL = 10

REPUTATION_RELIABILITY_MAP = {
    "A+ - 3rd party enrichment": DBotScoreReliability.A_PLUS,
    "A - Completely reliable": DBotScoreReliability.A,
    "B - Usually reliable": DBotScoreReliability.B,
    "C - Fairly reliable": DBotScoreReliability.C,
    "D - Not usually reliable": DBotScoreReliability.D,
    "E - Unreliable": DBotScoreReliability.E,
    "F - Reliability cannot be judged": DBotScoreReliability.F,
}

EMAIL_REGEX = re_compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DOMAIN_REGEX = re_compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$",
)
PHONE_REGEX = re_compile(r"^\+?[0-9().\-\s]{6,25}$")


class Client(BaseClient):
    """Client for IPQualityScore API."""

    def reputation_request(
        self,
        endpoint: str,
        query_name: str,
        value: str,
    ) -> dict[str, Any]:
        """Send reputation request to IPQS."""
        encoded_value = quote(value, safe="")
        return ensure_dict_response(
            self._http_request(
                method="GET",
                url_suffix=f"/{endpoint}/?{query_name}={encoded_value}",
                resp_type="json",
            ),
            f"{endpoint} reputation request",
        )

    def leaked_request(
        self,
        leaked_type: str,
        query_name: str,
        value: str,
    ) -> dict[str, Any]:
        """Send leaked-data request to IPQS."""
        encoded_value = quote(value, safe="")
        return ensure_dict_response(
            self._http_request(
                method="GET",
                url_suffix=f"/leaked/{leaked_type}?{query_name}={encoded_value}",
                resp_type="json",
            ),
            f"{leaked_type} leaked request",
        )

    def malware_url_request(self, *, is_lookup: bool, url: str) -> dict[str, Any]:
        """Submit URL malware lookup or scan request."""
        return ensure_dict_response(
            self._http_request(
                method="POST",
                full_url=MALWARE_LOOKUP_URL if is_lookup else MALWARE_SCAN_URL,
                data={"url": url},
                resp_type="json",
                timeout=60,
            ),
            "malware url lookup" if is_lookup else "malware url scan",
        )

    def malware_file_request(
        self,
        *,
        is_lookup: bool,
        file_path: str,
    ) -> dict[str, Any]:
        """Submit file malware lookup or scan request."""
        with open(file_path, "rb") as file_handle:
            return ensure_dict_response(
                self._http_request(
                    method="POST",
                    full_url=MALWARE_LOOKUP_URL if is_lookup else MALWARE_SCAN_URL,
                    files={"file": file_handle},
                    resp_type="json",
                    timeout=60,
                ),
                "malware file lookup" if is_lookup else "malware file scan",
            )

    def poll_result(self, request_id: str) -> dict[str, Any]:
        """Fetch IPQS postback result once."""
        return ensure_dict_response(
            self._http_request(
                method="POST",
                url_suffix="/postback",
                data={"request_id": request_id},
                resp_type="json",
                timeout=30,
            ),
            "polling scan result",
        )


def ensure_dict_response(response: Any, operation: str) -> dict[str, Any]:
    """Validate that the response is a dictionary."""
    if not isinstance(response, dict):
        raise DemistoException(
            f"Invalid response from {operation}: expected dict, got {type(response).__name__}",
        )
    return response


def get_reputation_reliability(reliability: str | None) -> str:
    """Map configured feed reliability to DBotScore reliability."""
    return REPUTATION_RELIABILITY_MAP.get(reliability or "", DBotScoreReliability.F)


def calculate_score(
    value: int,
    suspicious_threshold: int,
    malicious_threshold: int,
) -> int:
    """Convert a numeric value into a DBot score."""
    if value >= malicious_threshold:
        return Common.DBotScore.BAD
    if value >= suspicious_threshold:
        return Common.DBotScore.SUSPICIOUS
    return Common.DBotScore.NONE


def was_leaked(result: dict[str, Any]) -> bool:
    """Support both possible leaked indicators from API schema."""
    return bool(result.get("leaked") or result.get("exposed"))


def get_thresholds(params: dict[str, Any], prefix: str) -> tuple[int, int]:
    """Get suspicious and malicious score thresholds from integration params."""
    suspicious = arg_to_number(params.get(f"{prefix}_suspicious_score_threshold"))
    malicious = arg_to_number(params.get(f"{prefix}_malicious_score_threshold"))

    return (
        suspicious if suspicious is not None else DEFAULT_THRESHOLD_VALUES["suspicious"],
        malicious if malicious is not None else DEFAULT_THRESHOLD_VALUES["malicious"],
    )


def get_file_thresholds(params: dict[str, Any]) -> tuple[int, int]:
    """Get suspicious and malicious thresholds for malware scan results."""
    suspicious = arg_to_number(params.get("file_suspicious_score_threshold"))
    malicious = arg_to_number(params.get("file_malicious_score_threshold"))

    return (
        suspicious if suspicious is not None else DEFAULT_FILE_THRESHOLD_VALUES["suspicious"],
        malicious if malicious is not None else DEFAULT_FILE_THRESHOLD_VALUES["malicious"],
    )


def get_retry_context_key(request_id: str) -> str:
    """Build retry counter key for integration context."""
    return f"ipqs_retry_count_{request_id}"


def get_retry_count(request_id: str) -> int:
    """Get retry count from integration context."""
    context = demisto.getIntegrationContext() or {}
    retry_count = context.get(get_retry_context_key(request_id), 0)

    if isinstance(retry_count, int):
        return retry_count

    if isinstance(retry_count, str):
        try:
            return int(retry_count)
        except ValueError as exc:
            raise DemistoException(
                f"Invalid retry count for request_id: {request_id}",
            ) from exc

    raise DemistoException(
        f"Invalid retry count type for request_id {request_id}: {type(retry_count).__name__}",
    )


def set_retry_count(request_id: str, retry_count: int) -> None:
    """Set retry count in integration context."""
    context = demisto.getIntegrationContext() or {}
    context[get_retry_context_key(request_id)] = retry_count
    demisto.setIntegrationContext(context)


def clear_retry_count(request_id: str) -> None:
    """Clear retry count after scan completes or fails."""
    context = demisto.getIntegrationContext() or {}
    context.pop(get_retry_context_key(request_id), None)
    demisto.setIntegrationContext(context)


def get_dbot_type(type_name: str, fallback: str = DBotScoreType.URL) -> str:
    """Safely get DBotScoreType value if available."""
    return getattr(DBotScoreType, type_name, fallback)


def create_dbot_score(
    indicator: str,
    indicator_type: str,
    score: int,
    reliability: str,
) -> Common.DBotScore:
    """Create a DBotScore object."""
    return Common.DBotScore(
        indicator=indicator,
        indicator_type=indicator_type,
        score=score,
        integration_name=INTEGRATION_NAME,
        reliability=reliability,
    )


def create_command_result(
    title: str,
    result: dict[str, Any],
    indicator: Any,
    outputs_prefix: str,
    outputs_key_field: str,
) -> CommandResults:
    """Create a standard CommandResults object."""
    return CommandResults(
        readable_output=tableToMarkdown(title, result, headers=list(result.keys())),
        indicator=indicator,
        outputs_prefix=outputs_prefix,
        outputs_key_field=outputs_key_field,
        outputs=result,
        raw_response=result,
    )


def build_pending_result(
    args: dict[str, Any],
    result: dict[str, Any],
    request_id: str,
    outputs_prefix: str,
) -> CommandResults:
    """Return scheduled command for pending IPQS malware scan."""
    current_retry = get_retry_count(request_id)

    if current_retry >= DEFAULT_MAX_RETRIES:
        clear_retry_count(request_id)
        raise DemistoException(
            f"Maximum retries reached while waiting for IPQS malware scan result. " f"Request ID: {request_id}",
        )

    set_retry_count(request_id, current_retry + 1)

    scheduled_args = {
        **args,
        "request_id": request_id,
    }

    return CommandResults(
        readable_output=(
            f"IPQS malware scan is still processing. "
            f"The result will be checked again in {DEFAULT_POLLING_INTERVAL} seconds. "
            f"Polling is limited to {DEFAULT_MAX_RETRIES} attempts. "
            f"Request ID: {request_id}"
        ),
        outputs_prefix=outputs_prefix,
        outputs=result,
        raw_response=result,
        scheduled_command=ScheduledCommand(
            command=demisto.command(),
            next_run_in_seconds=DEFAULT_POLLING_INTERVAL,
            args=scheduled_args,
        ),
    )


def flatten_engine_results(scan_result: dict[str, Any]) -> dict[str, Any]:
    """Flatten engine results into top-level keys for readable output."""
    flattened = dict(scan_result)
    engines = flattened.pop("result", [])

    if not isinstance(engines, list):
        return flattened

    for engine in engines:
        if not isinstance(engine, dict):
            continue

        engine_name = engine.get("name", "Unknown")
        flattened[engine_name] = {
            "detected": engine.get("detected", False),
            "error": engine.get("error", False),
        }

    return flattened


def extract_detected_scans(scan_result: dict[str, Any]) -> int:
    """Extract detected scan count from engine list, or fallback to API field."""
    engines = scan_result.get("result")

    if isinstance(engines, list) and engines:
        return sum(1 for engine in engines if isinstance(engine, dict) and engine.get("detected") is True)

    detected_scans = arg_to_number(scan_result.get("detected_scans"))
    return detected_scans if detected_scans is not None else 0


def normalize_scan_result(scan_result: dict[str, Any]) -> dict[str, Any]:
    """Normalize scan result fields used by XSOAR."""
    normalized = dict(scan_result)
    normalized.pop("update_url", None)
    normalized["file_size"] = arg_to_number(normalized.get("file_size")) or 0
    normalized["detected_scans"] = extract_detected_scans(normalized)
    return normalized


def validate_ip(ip_value: str) -> str:
    """Validate IP value."""
    try:
        stripped_ip = ip_value.strip()
        ip_address(stripped_ip)
        return stripped_ip
    except ValueError as exc:
        raise DemistoException(f"Invalid IP address provided: {ip_value}") from exc


def validate_email(email: str) -> str:
    """Validate email value."""
    email = email.strip()
    if not EMAIL_REGEX.match(email):
        raise DemistoException(f"Invalid email address provided: {email}")
    return email


def validate_phone(phone: str) -> str:
    """Validate phone value."""
    phone = phone.strip()
    if not PHONE_REGEX.match(phone):
        raise DemistoException(f"Invalid phone number provided: {phone}")
    return phone


def validate_url_or_domain(value: str) -> str:
    """Validate URL or domain. Both use the same IPQS endpoint."""
    value = value.strip()
    parsed = urlparse(value)

    if parsed.scheme and parsed.netloc:
        return value

    if DOMAIN_REGEX.match(value):
        return value

    raise DemistoException(f"Invalid URL or domain provided: {value}")


def validate_non_empty(value: str, field_name: str) -> str:
    """Validate non-empty string."""
    value = value.strip()
    if not value:
        raise DemistoException(f"{field_name} cannot be empty")
    return value


def build_reputation_results(
    indicators: list[str],
    fetch_result: Callable[[str], dict[str, Any]],
    validator: Callable[[str], str],
    score_field: str,
    suspicious_threshold: int,
    malicious_threshold: int,
    reliability: str | None,
    indicator_type: str,
    outputs_prefix: str,
    outputs_key_field: str,
    title_template: str,
    indicator_builder: Callable[[str, dict[str, Any], Common.DBotScore], Any],
    result_key_name: str,
) -> list[CommandResults]:
    """Generic builder for reputation-based commands."""
    results: list[CommandResults] = []
    parsed_reliability = get_reputation_reliability(reliability)

    for raw_indicator in indicators:
        indicator_value = validator(raw_indicator)
        result = fetch_result(indicator_value)
        result[result_key_name] = indicator_value

        score_value = arg_to_number(result.get(score_field)) or 0
        score = calculate_score(
            score_value,
            suspicious_threshold,
            malicious_threshold,
        )

        dbot_score = create_dbot_score(
            indicator_value,
            indicator_type,
            score,
            parsed_reliability,
        )

        results.append(
            create_command_result(
                title_template.format(indicator=indicator_value),
                result,
                indicator_builder(indicator_value, result, dbot_score),
                outputs_prefix,
                outputs_key_field,
            ),
        )

    return results


def build_leaked_results(
    indicators: list[str],
    fetch_result: Callable[[str], dict[str, Any]],
    validator: Callable[[str], str],
    reliability: str | None,
    indicator_type: str,
    outputs_prefix: str,
    outputs_key_field: str,
    title_template: str,
    result_key_name: str,
    indicator_builder: Callable[[str, dict[str, Any], Common.DBotScore], Any],
) -> list[CommandResults]:
    """Generic builder for leaked-data commands."""
    results: list[CommandResults] = []
    parsed_reliability = get_reputation_reliability(reliability)

    for raw_indicator in indicators:
        indicator_value = validator(raw_indicator)
        result = fetch_result(indicator_value)
        result[result_key_name] = indicator_value

        dbot_score = create_dbot_score(
            indicator_value,
            indicator_type,
            Common.DBotScore.BAD if was_leaked(result) else Common.DBotScore.NONE,
            parsed_reliability,
        )

        results.append(
            create_command_result(
                title_template.format(indicator=indicator_value),
                result,
                indicator_builder(indicator_value, result, dbot_score),
                outputs_prefix,
                outputs_key_field,
            ),
        )

    return results


def ip_command(
    client: Client,
    args: dict[str, Any],
    suspicious_threshold: int,
    malicious_threshold: int,
    reliability: str | None,
) -> list[CommandResults]:
    """Run reputation check on IP addresses."""
    return build_reputation_results(
        indicators=argToList(args.get("ip"), ","),
        fetch_result=lambda value: client.reputation_request("ip", "ip", value),
        validator=validate_ip,
        score_field="fraud_score",
        suspicious_threshold=suspicious_threshold,
        malicious_threshold=malicious_threshold,
        reliability=reliability,
        indicator_type=DBotScoreType.IP,
        outputs_prefix="IPQualityScore.IP",
        outputs_key_field="address",
        title_template="IPQS Fraud and Risk Scoring Results for IP Address {indicator}",
        result_key_name="address",
        indicator_builder=lambda ip_value, result, dbot_score: Common.IP(
            ip=ip_value,
            dbot_score=dbot_score,
            asn=result.get("ASN"),
            hostname=result.get("host"),
            geo_country=result.get("country_code"),
            geo_longitude=result.get("longitude"),
            geo_latitude=result.get("latitude"),
        ),
    )


def email_command(
    client: Client,
    args: dict[str, Any],
    suspicious_threshold: int,
    malicious_threshold: int,
    reliability: str | None,
) -> list[CommandResults]:
    """Run reputation check on email addresses."""
    return build_reputation_results(
        indicators=argToList(args.get("email"), ","),
        fetch_result=lambda value: client.reputation_request("email", "email", value),
        validator=validate_email,
        score_field="fraud_score",
        suspicious_threshold=suspicious_threshold,
        malicious_threshold=malicious_threshold,
        reliability=reliability,
        indicator_type=DBotScoreType.EMAIL,
        outputs_prefix="IPQualityScore.Email",
        outputs_key_field="address",
        title_template="IPQS Fraud and Risk Scoring Results for Email Address {indicator}",
        result_key_name="address",
        indicator_builder=lambda email_value, result, dbot_score: Common.EMAIL(
            address=email_value,
            dbot_score=dbot_score,
            domain=result.get("sanitized_email", email_value).split("@")[-1],
        ),
    )


def url_command(
    client: Client,
    args: dict[str, Any],
    suspicious_threshold: int,
    malicious_threshold: int,
    reliability: str | None,
) -> list[CommandResults]:
    """Run reputation check on URLs/domains."""
    return build_reputation_results(
        indicators=argToList(args.get("url"), ","),
        fetch_result=lambda value: client.reputation_request("url", "url", value),
        validator=validate_url_or_domain,
        score_field="risk_score",
        suspicious_threshold=suspicious_threshold,
        malicious_threshold=malicious_threshold,
        reliability=reliability,
        indicator_type=DBotScoreType.URL,
        outputs_prefix="IPQualityScore.Url",
        outputs_key_field="url",
        title_template="IPQS Fraud and Risk Scoring Results for URL {indicator}",
        result_key_name="url",
        indicator_builder=lambda url_value, _result, dbot_score: Common.URL(
            url=url_value,
            dbot_score=dbot_score,
        ),
    )


def phone_command(
    client: Client,
    args: dict[str, Any],
    suspicious_threshold: int,
    malicious_threshold: int,
    reliability: str | None,
) -> list[CommandResults]:
    """Run reputation check on phone numbers."""
    phone_dbot_type = get_dbot_type("PHONE", DBotScoreType.URL)

    return build_reputation_results(
        indicators=argToList(args.get("phone"), ","),
        fetch_result=lambda value: client.reputation_request("phone", "phone", value),
        validator=validate_phone,
        score_field="fraud_score",
        suspicious_threshold=suspicious_threshold,
        malicious_threshold=malicious_threshold,
        reliability=reliability,
        indicator_type=phone_dbot_type,
        outputs_prefix="IPQualityScore.Phone",
        outputs_key_field="phone",
        title_template="IPQS Fraud and Risk Scoring Results for Phone Number {indicator}",
        result_key_name="phone",
        indicator_builder=lambda _phone, _result, dbot_score: dbot_score,
    )


def leaked_username_command(
    client: Client,
    args: dict[str, Any],
    reliability: str | None,
) -> list[CommandResults]:
    """Check if usernames were leaked."""
    account_dbot_type = get_dbot_type("ACCOUNT", DBotScoreType.URL)

    return build_leaked_results(
        indicators=argToList(args.get("username"), ","),
        fetch_result=lambda value: client.leaked_request("username", "username", value),
        validator=lambda value: validate_non_empty(value, "Username"),
        reliability=reliability,
        indicator_type=account_dbot_type,
        outputs_prefix="IPQualityScore.Username",
        outputs_key_field="username",
        title_template="IPQS Dark Web Leak Results for Username {indicator}",
        result_key_name="username",
        indicator_builder=lambda _username, _result, dbot_score: dbot_score,
    )


def leaked_password_command(
    client: Client,
    args: dict[str, Any],
    reliability: str | None,
) -> list[CommandResults]:
    """Check if passwords were leaked."""
    generic_dbot_type = get_dbot_type("GENERIC", DBotScoreType.URL)

    return build_leaked_results(
        indicators=argToList(args.get("password"), ","),
        fetch_result=lambda value: client.leaked_request("password", "password", value),
        validator=lambda value: validate_non_empty(value, "Password"),
        reliability=reliability,
        indicator_type=generic_dbot_type,
        outputs_prefix="IPQualityScore.Password",
        outputs_key_field="password",
        title_template="IPQS Dark Web Leak Results for Password {indicator}",
        result_key_name="password",
        indicator_builder=lambda _password, _result, dbot_score: dbot_score,
    )


def leaked_email_command(
    client: Client,
    args: dict[str, Any],
    reliability: str | None,
) -> list[CommandResults]:
    """Check if emails were leaked."""
    return build_leaked_results(
        indicators=argToList(args.get("email"), ","),
        fetch_result=lambda value: client.leaked_request("email", "email", value),
        validator=validate_email,
        reliability=reliability,
        indicator_type=DBotScoreType.EMAIL,
        outputs_prefix="IPQualityScore.LeakedEmail",
        outputs_key_field="email",
        title_template="IPQS Dark Web Leak Results for Email Address {indicator}",
        result_key_name="email",
        indicator_builder=lambda email_value, _result, dbot_score: Common.EMAIL(
            address=email_value,
            dbot_score=dbot_score,
        ),
    )


def build_file_scan_command_result(
    scan_result: dict[str, Any],
    file_name: str,
    suspicious_threshold: int,
    malicious_threshold: int,
    parsed_reliability: str,
) -> CommandResults:
    """Build file scan CommandResults."""
    detected_scans = arg_to_number(scan_result.get("detected_scans")) or 0
    score = calculate_score(
        detected_scans,
        suspicious_threshold,
        malicious_threshold,
    )

    indicator_value = scan_result.get("file_hash") or scan_result.get("sha256") or scan_result.get("md5") or file_name

    dbot_score = create_dbot_score(
        indicator_value,
        DBotScoreType.FILE,
        score,
        parsed_reliability,
    )

    file_context = Common.File(
        sha256=scan_result.get("file_hash") or scan_result.get("sha256"),
        md5=scan_result.get("md5"),
        sha1=scan_result.get("sha1"),
        size=scan_result.get("file_size"),
        name=file_name,
        dbot_score=dbot_score,
    )

    flattened_result = flatten_engine_results(scan_result)
    flattened_result["file_name"] = file_name

    return create_command_result(
        f"IPQS Malware File Scan Results for File {file_name}",
        flattened_result,
        file_context,
        "IPQualityScore.FileScan",
        "file_name",
    )


def build_url_file_scan_command_result(
    scan_result: dict[str, Any],
    url_value: str,
    suspicious_threshold: int,
    malicious_threshold: int,
    parsed_reliability: str,
) -> CommandResults:
    """Build URL malware scan CommandResults."""
    detected_scans = arg_to_number(scan_result.get("detected_scans")) or 0
    score = calculate_score(
        detected_scans,
        suspicious_threshold,
        malicious_threshold,
    )

    dbot_score = create_dbot_score(
        url_value,
        DBotScoreType.URL,
        score,
        parsed_reliability,
    )

    url_context = Common.URL(url=url_value, dbot_score=dbot_score)
    flattened_result = flatten_engine_results(scan_result)

    return create_command_result(
        f"IPQS Malware File Scan Results for URL {url_value}",
        flattened_result,
        url_context,
        "IPQualityScore.URLFileScan",
        "url",
    )


def file_command(
    client: Client,
    args: dict[str, Any],
    suspicious_threshold: int,
    malicious_threshold: int,
    reliability: str | None,
) -> CommandResults | list[CommandResults]:
    """Run malware scan on uploaded files."""
    request_id = args.get("request_id")
    parsed_reliability = get_reputation_reliability(reliability)

    if request_id:
        scan_result = client.poll_result(request_id)

        if scan_result.get("status") == "pending":
            return build_pending_result(
                args=args,
                result=scan_result,
                request_id=request_id,
                outputs_prefix="IPQualityScore.FileScan",
            )

        clear_retry_count(request_id)
        scan_result = normalize_scan_result(scan_result)
        file_name = scan_result.get("file_name") or args.get("entry_id") or request_id

        return build_file_scan_command_result(
            scan_result=scan_result,
            file_name=file_name,
            suspicious_threshold=suspicious_threshold,
            malicious_threshold=malicious_threshold,
            parsed_reliability=parsed_reliability,
        )

    entry_ids = argToList(args.get("entry_id"))
    if not entry_ids:
        raise DemistoException("entry_id is required for file scan.")

    results: list[CommandResults] = []

    for entry_id in entry_ids:
        file_info = demisto.getFilePath(entry_id)
        file_path = file_info.get("path")
        file_name = file_info.get("name") or entry_id

        if not file_path:
            raise DemistoException(
                f"Could not resolve file path for entry ID: {entry_id}",
            )

        lookup_response = client.malware_file_request(
            is_lookup=True,
            file_path=file_path,
        )

        if lookup_response.get("status") == "cached":
            scan_result = normalize_scan_result(lookup_response)
            results.append(
                build_file_scan_command_result(
                    scan_result=scan_result,
                    file_name=file_name,
                    suspicious_threshold=suspicious_threshold,
                    malicious_threshold=malicious_threshold,
                    parsed_reliability=parsed_reliability,
                ),
            )
            continue

        scan_result = client.malware_file_request(
            is_lookup=False,
            file_path=file_path,
        )
        request_id = scan_result.get("request_id")

        if scan_result.get("status") == "pending":
            if not request_id:
                raise DemistoException("File scan is pending but request_id is missing.")

            pending_args = dict(args)
            pending_args["entry_id"] = entry_id

            return build_pending_result(
                args=pending_args,
                result=scan_result,
                request_id=request_id,
                outputs_prefix="IPQualityScore.FileScan",
            )

        scan_result = normalize_scan_result(scan_result)
        results.append(
            build_file_scan_command_result(
                scan_result=scan_result,
                file_name=file_name,
                suspicious_threshold=suspicious_threshold,
                malicious_threshold=malicious_threshold,
                parsed_reliability=parsed_reliability,
            ),
        )

    return results


def url_file_command(
    client: Client,
    args: dict[str, Any],
    suspicious_threshold: int,
    malicious_threshold: int,
    reliability: str | None,
) -> CommandResults | list[CommandResults]:
    """Run malware scan on URLs/domains."""
    request_id = args.get("request_id")
    parsed_reliability = get_reputation_reliability(reliability)

    if request_id:
        scan_result = client.poll_result(request_id)

        if scan_result.get("status") == "pending":
            return build_pending_result(
                args=args,
                result=scan_result,
                request_id=request_id,
                outputs_prefix="IPQualityScore.URLFileScan",
            )

        clear_retry_count(request_id)
        url_value = args.get("url") or scan_result.get("url") or request_id
        scan_result["url"] = url_value
        scan_result = normalize_scan_result(scan_result)

        return build_url_file_scan_command_result(
            scan_result=scan_result,
            url_value=url_value,
            suspicious_threshold=suspicious_threshold,
            malicious_threshold=malicious_threshold,
            parsed_reliability=parsed_reliability,
        )

    urls = argToList(args.get("url"), ",")
    if not urls:
        raise DemistoException("url is required for URL malware scan.")

    results: list[CommandResults] = []

    for raw_url in urls:
        url_value = validate_url_or_domain(raw_url)

        lookup_response = client.malware_url_request(
            is_lookup=True,
            url=url_value,
        )

        if lookup_response.get("status") == "cached":
            lookup_response["url"] = url_value
            scan_result = normalize_scan_result(lookup_response)
            results.append(
                build_url_file_scan_command_result(
                    scan_result=scan_result,
                    url_value=url_value,
                    suspicious_threshold=suspicious_threshold,
                    malicious_threshold=malicious_threshold,
                    parsed_reliability=parsed_reliability,
                ),
            )
            continue

        scan_result = client.malware_url_request(
            is_lookup=False,
            url=url_value,
        )
        request_id = scan_result.get("request_id")

        if scan_result.get("status") == "pending":
            if not request_id:
                raise DemistoException("URL scan is pending but request_id is missing.")

            pending_args = dict(args)
            pending_args["url"] = url_value

            return build_pending_result(
                args=pending_args,
                result=scan_result,
                request_id=request_id,
                outputs_prefix="IPQualityScore.URLFileScan",
            )

        scan_result["url"] = url_value
        scan_result = normalize_scan_result(scan_result)
        results.append(
            build_url_file_scan_command_result(
                scan_result=scan_result,
                url_value=url_value,
                suspicious_threshold=suspicious_threshold,
                malicious_threshold=malicious_threshold,
                parsed_reliability=parsed_reliability,
            ),
        )

    return results


def test_module(client: Client) -> str:
    """Test integration connectivity."""
    result = client.reputation_request("ip", "ip", "8.8.8.8")
    if result.get("success") is True:
        return "ok"

    raise DemistoException(result.get("message", "Test failed"))


def main() -> None:
    """Main execution entry point."""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get("apikey")
    if not api_key:
        return_error("API Key is required.")

    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    reliability = params.get("feedReliability")

    if not verify_certificate:
        demisto.debug("SSL verification is disabled.")
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    client = Client(
        base_url=BASE_URL,
        headers={"IPQS-KEY": api_key},
        verify=verify_certificate,
        proxy=proxy,
    )

    demisto.debug(f"Command being called is {command}")

    def run_ip_command() -> list[CommandResults]:
        suspicious, malicious = get_thresholds(params, "ip")
        return ip_command(client, args, suspicious, malicious, reliability)

    def run_email_command() -> list[CommandResults]:
        suspicious, malicious = get_thresholds(params, "email")
        return email_command(client, args, suspicious, malicious, reliability)

    def run_phone_command() -> list[CommandResults]:
        suspicious, malicious = get_thresholds(params, "phone")
        return phone_command(client, args, suspicious, malicious, reliability)

    def run_url_command() -> list[CommandResults]:
        suspicious, malicious = get_thresholds(params, "url")
        return url_command(client, args, suspicious, malicious, reliability)

    def run_file_scan_command() -> CommandResults | list[CommandResults]:
        suspicious, malicious = get_file_thresholds(params)
        return file_command(client, args, suspicious, malicious, reliability)

    def run_url_file_scan_command() -> CommandResults | list[CommandResults]:
        suspicious, malicious = get_file_thresholds(params)
        return url_file_command(client, args, suspicious, malicious, reliability)

    commands: dict[str, Callable[[], Any]] = {
        "test-module": lambda: test_module(client),
        "ipqs-ip-reputation": run_ip_command,
        "ipqs-email-reputation": run_email_command,
        "ipqs-phone-reputation": run_phone_command,
        "ipqs-url-reputation": run_url_command,
        "ipqs-username-leaked": lambda: leaked_username_command(
            client,
            args,
            reliability,
        ),
        "ipqs-password-leaked": lambda: leaked_password_command(
            client,
            args,
            reliability,
        ),
        "ipqs-email-leaked": lambda: leaked_email_command(client, args, reliability),
        "ipqs-file-scan": run_file_scan_command,
        "ipqs-url-file-scan": run_url_file_scan_command,
    }

    try:
        command_func = commands.get(command)
        if command_func is None:
            raise NotImplementedError(f"Command '{command}' is not implemented.")

        return_results(command_func())

    except Exception as exc:  # pylint: disable=broad-exception-caught
        return_error(f"Failed to execute {command} command. Error: {exc!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
