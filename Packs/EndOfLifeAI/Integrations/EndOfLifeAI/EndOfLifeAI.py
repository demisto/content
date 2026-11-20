import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import urllib.parse
from typing import Any

import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DEFAULT_BASE_URL = "https://api.endoflife.ai"
FREE_KEY_URL = "https://endoflife.ai/api#free-key"
API_DOCS_URL = "https://endoflife.ai/api"
USER_AGENT = "endoflife.ai-cortex-xsoar/1.0.0"
REQUEST_TIMEOUT = 30
DEFAULT_LIMIT = 50
DEFAULT_CHUNK_SIZE = 5

PRODUCT_PREFIX = "EndOfLifeAI.Product"
VERSION_PREFIX = "EndOfLifeAI.Version"
BATCH_ERROR_PREFIX = "EndOfLifeAI.BatchError"

MONTHS = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
]

STATUS_LABELS = {
    "active": "Supported",
    "warn": "Supported, end of life within 180 days",
    "eol": "End of life",
    "unknown": "Unknown",
}

# The fields of the API's Score object that are written to the context, in display order.
VERSION_FIELDS = [
    "product",
    "version",
    "alias_of",
    "requested_version",
    "version_matched_by",
    "latest_release",
    "release_date",
    "status",
    "is_supported",
    "eol_date",
    "eol_boolean",
    "eol_date_precision",
    "date_precision_note",
    "days_until_eol",
    "days_past_eol",
    "support_date",
    "support_date_precision",
    "extended_support_available",
    "extended_support_date",
    "extended_support_date_precision",
    "extended_support_ships_fixes",
    "score",
    "grade",
    "grade_label",
    "band",
    "factors",
    "cpe",
    "cpe_scope",
    "cpe_note",
    "purl",
    "eol_date_source",
    "eol_date_source_url",
    "eol_date_verified_at",
    "eol_date_status",
    "eol_date_agreement",
    "eol_date_confidence",
    "data_source",
    "score_card_url",
    "product_url",
    "methodology_url",
    "generated_at",
]

# Fields that the API sends only in some answers; they are left out of the context when absent.
OPTIONAL_VERSION_FIELDS = {
    "alias_of",
    "requested_version",
    "version_matched_by",
    "date_precision_note",
    "cpe_scope",
    "cpe_note",
}

VERSION_TABLE_HEADERS = [
    "Product",
    "Version",
    "Status",
    "EOL Date",
    "Days Until EOL",
    "Days Past EOL",
    "Risk Score",
    "Grade",
    "Band",
    "KEV Exposed",
    "Extended Support Until",
    "EOL Date Source",
    "Source URL",
]

BATCH_ERROR_TABLE_HEADERS = ["Product", "Version", "Error", "Reason", "Candidates"]

AUTH_ERROR_PREFIX = "Authorization Error"
TIMEOUT_MESSAGE = (
    f"The endoflife.ai API did not answer within {REQUEST_TIMEOUT} seconds. "
    "Check the Server URL, the proxy settings and the network connection, then try again."
)

""" EXCEPTIONS """


class NotFoundError(DemistoException):
    """Raised when the API answers 404. Keeps the parsed error body for the command to explain."""

    def __init__(self, message: str, body: dict[str, Any] | None = None, res: requests.Response | None = None):
        super().__init__(message, res=res)
        self.body: dict[str, Any] = body or {}


""" CLIENT CLASS """


class Client(BaseClient):
    """Client for the endoflife.ai API. Every data request carries the API key in the X-API-Key header."""

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool):
        headers = {
            "X-API-Key": api_key,
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def _request(self, method: str, url_suffix: str, json_data: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            response = self._http_request(
                method=method,
                url_suffix=url_suffix,
                json_data=json_data,
                timeout=REQUEST_TIMEOUT,
                error_handler=self._error_handler,
            )
        except requests.exceptions.Timeout as e:
            raise DemistoException(TIMEOUT_MESSAGE, exception=e)
        except DemistoException as e:
            if isinstance(getattr(e, "exception", None), requests.exceptions.Timeout):
                raise DemistoException(TIMEOUT_MESSAGE, exception=e.exception)
            raise
        if not isinstance(response, dict):
            raise DemistoException("The endoflife.ai API returned an answer that is not a JSON object.")
        return response

    @staticmethod
    def _error_handler(res: requests.Response) -> None:
        """Turns an error answer of the API into an exception with a message the user can act on."""
        try:
            body = res.json()
        except ValueError:
            body = {}
        if not isinstance(body, dict):
            body = {}
        api_message = str(body.get("error") or res.reason or "").strip()
        status = res.status_code

        if status == 401:
            key_status = body.get("key_status") or res.headers.get("X-EOL-Key-Status")
            if key_status == "inactive":
                reason = "The API key has been deactivated."
            elif key_status == "unknown":
                reason = "The API key was not recognised."
            else:
                reason = "No valid API key was sent."
            raise DemistoException(
                f"{AUTH_ERROR_PREFIX}: {reason} Every data request to the endoflife.ai API needs an API key. "
                f"A free API key is available at {FREE_KEY_URL}. "
                "Enter the key in the API Key field of the integration instance.",
                res=res,
            )
        if status == 404:
            raise NotFoundError(api_message or "Not found", body=body, res=res)
        if status == 429:
            raise DemistoException(
                "Rate limit reached: the daily request allowance of this API key is used up. "
                f"The counter resets at 00:00 UTC{retry_after_text(res.headers.get('Retry-After'))}. "
                f"See {API_DOCS_URL} for the limits.",
                res=res,
            )
        if status == 403:
            raise DemistoException(
                "The endoflife.ai API refused the request: it holds more items than this API key accepts in one request. "
                "Lower the chunk_size argument (a free API key accepts 5 items per request).",
                res=res,
            )
        raise DemistoException(f"endoflife.ai API error [{status}]: {api_message or 'no details returned'}", res=res)

    def list_products(self) -> dict[str, Any]:
        """GET /v1/products - the slugs of all tracked products. Used by the connectivity test."""
        return self._request("GET", "/v1/products")

    def get_product(self, product: str) -> dict[str, Any]:
        """GET /v1/product/{slug} - all release cycles of a product."""
        return self._request("GET", f"/v1/product/{quote_segment(product)}")

    def get_version(self, product: str, version: str) -> dict[str, Any]:
        """GET /v1/score/{slug}/{version} - lifecycle facts and EOL risk score of one version."""
        return self._request("GET", f"/v1/score/{quote_segment(product)}/{quote_segment(version)}")

    def batch(self, items: list[dict[str, str]]) -> dict[str, Any]:
        """POST /v1/batch - lifecycle facts and EOL risk score of several product versions."""
        return self._request("POST", "/v1/batch", json_data={"products": items})


""" HELPER FUNCTIONS """


def quote_segment(value: str) -> str:
    """Encodes a value so that it is sent as exactly one URL path segment."""
    return urllib.parse.quote(str(value).strip(), safe="")


def retry_after_text(retry_after: str | None) -> str:
    """Turns the Retry-After header (seconds) into a short phrase, or an empty string when it is absent."""
    try:
        seconds = int(str(retry_after))
    except ValueError:
        return ""
    if seconds <= 0:
        return ""
    if seconds < 3600:
        minutes = max(1, round(seconds / 60))
        return f", in about {minutes} minute{'s' if minutes != 1 else ''}"
    hours = round(seconds / 3600)
    return f", in about {hours} hour{'s' if hours != 1 else ''}"


def format_date(date_value: str | None, precision: str | None) -> str | None:
    """Formats an ISO date for display with the precision the API reports.

    The API stores a date that the vendor publishes to the month or quarter only as the last day of that
    period, and asks clients to show the period rather than the day.
    """
    if not date_value:
        return None
    if precision in ("month", "quarter"):
        try:
            year, month = int(date_value[0:4]), int(date_value[5:7])
        except ValueError:
            return date_value
        if not 1 <= month <= 12:
            return date_value
        if precision == "quarter":
            return f"Q{(month - 1) // 3 + 1} {year}"
        return f"{MONTHS[month - 1]} {year}"
    return date_value


def kev_exposed(raw: dict[str, Any]) -> bool | None:
    """True when the cisa_kev_exposure factor of the risk score is above zero. None when the factor is absent."""
    factors = raw.get("factors")
    if not isinstance(factors, dict) or factors.get("cisa_kev_exposure") is None:
        return None
    try:
        return float(factors["cisa_kev_exposure"]) > 0
    except (TypeError, ValueError):
        return None


def build_version(raw: dict[str, Any]) -> dict[str, Any]:
    """Builds the context object of one version from the API's Score object."""
    version: dict[str, Any] = {}
    for field in VERSION_FIELDS:
        if field in raw:
            version[field] = raw[field]
        elif field not in OPTIONAL_VERSION_FIELDS:
            version[field] = None
    version["kev_exposed"] = kev_exposed(raw)
    return version


def eol_date_text(version: dict[str, Any]) -> str | None:
    """The end-of-life date as shown in the table, or what the API says when no date is published."""
    text = format_date(version.get("eol_date"), version.get("eol_date_precision"))
    if text:
        return text
    if version.get("eol_boolean") is True:
        return "End of life, no date published"
    if version.get("eol_boolean") is False:
        return "No end-of-life date published"
    return None


def version_row(version: dict[str, Any]) -> dict[str, Any]:
    """Builds the human-readable table row of one version."""
    exact_day = version.get("eol_date_precision") in (None, "day")
    exposed = version.get("kev_exposed")
    status = version.get("status")
    return {
        "Product": version.get("product"),
        "Version": version.get("version"),
        "Status": STATUS_LABELS.get(str(status), status),
        "EOL Date": eol_date_text(version),
        "Days Until EOL": version.get("days_until_eol") if exact_day else None,
        "Days Past EOL": version.get("days_past_eol") if exact_day else None,
        "Risk Score": version.get("score"),
        "Grade": version.get("grade"),
        "Band": version.get("band"),
        "KEV Exposed": None if exposed is None else ("Yes" if exposed else "No"),
        "Extended Support Until": format_date(
            version.get("extended_support_date"), version.get("extended_support_date_precision")
        ),
        "EOL Date Source": version.get("eol_date_source"),
        "Source URL": version.get("eol_date_source_url") or version.get("data_source"),
    }


def resolution_notes(version: dict[str, Any]) -> list[str]:
    """Sentences that say how the API resolved the request, where it did not match exactly."""
    notes = []
    if version.get("alias_of"):
        notes.append(f"The slug {version['alias_of']} is an alias of the tracked product {version.get('product')}.")
    if version.get("requested_version"):
        matched_by = version.get("version_matched_by") or "release-line"
        notes.append(
            f"The version {version['requested_version']} was resolved to {version.get('version')} ({matched_by} match)."
        )
    if version.get("date_precision_note"):
        notes.append(str(version["date_precision_note"]))
    return notes


def not_found_result(error: NotFoundError, product: str, version: str | None = None) -> CommandResults:
    """Explains a 404 answer of the API: the closest tracked slugs, or why a version did not resolve."""
    body = error.body
    subject = f"{product} {version}" if version else product
    lines = [f"### endoflife.ai: {subject} was not found", str(body.get("error") or error.message)]
    suggestions = [str(item) for item in argToList(body.get("did_you_mean"))]
    if suggestions:
        lines.append(f"Did you mean: {', '.join(suggestions)}?")
    if body.get("reason"):
        lines.append(f"Reason: {body['reason']}")
    candidates = [str(item) for item in argToList(body.get("candidates"))]
    if candidates:
        lines.append(f"Candidates: {', '.join(candidates)}")
    if body.get("cycle") and body.get("last_published"):
        lines.append(f"The last published release of the {body['cycle']} line is {body['last_published']}.")
    if body.get("not_tracked") and not suggestions and not body.get("reason"):
        lines.append("endoflife.ai does not track a product with this slug.")
    return CommandResults(readable_output="\n\n".join(lines), raw_response=body)


def parse_pairs(entries: list[Any]) -> list[dict[str, str]]:
    """Turns product:version entries into the items of a batch request. The version is optional."""
    items: list[dict[str, str]] = []
    for entry in entries:
        text = str(entry).strip()
        if not text:
            continue
        slug, _, version = text.partition(":")
        slug, version = slug.strip(), version.strip()
        if not slug:
            raise ValueError(f'"{text}" is not a valid entry. Use product:version, for example nodejs:18.')
        item = {"slug": slug}
        if version:
            item["version"] = version
        items.append(item)
    if not items:
        raise ValueError("The products argument is empty. Use product:version pairs, for example nodejs:18,python:3.8.")
    return items


def positive_int(value: Any, name: str, default: int) -> int:
    """Reads a positive whole number from a command argument."""
    number = arg_to_number(value, arg_name=name)
    if number is None:
        return default
    if number < 1:
        raise ValueError(f"The {name} argument must be 1 or higher.")
    return number


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests the connection and the API key with one request to a route that needs a key."""
    try:
        client.list_products()
    except DemistoException as e:
        if str(e).startswith(AUTH_ERROR_PREFIX):
            return str(e)
        raise
    return "ok"


def product_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """endoflife-ai-product-get: the lifecycle of a product, one row per tracked version."""
    product = str(args.get("product") or "").strip()
    if not product:
        raise ValueError("The product argument is required.")
    limit = positive_int(args.get("limit"), "limit", DEFAULT_LIMIT)

    try:
        raw = client.get_product(product)
    except NotFoundError as e:
        return not_found_result(e, product)

    all_versions = [build_version(item) for item in raw.get("versions") or [] if isinstance(item, dict)]
    versions = all_versions[:limit]
    slug = raw.get("product") or product
    outputs: dict[str, Any] = {
        "product": slug,
        "version_count": raw.get("version_count"),
        "product_url": raw.get("product_url"),
        "versions": versions,
    }
    if raw.get("alias_of"):
        outputs["alias_of"] = raw["alias_of"]

    title = f"endoflife.ai lifecycle of {slug}"
    readable = tableToMarkdown(
        title,
        [version_row({**item, "product": None}) for item in versions],
        headers=[header for header in VERSION_TABLE_HEADERS if header != "Product"],
        removeNull=True,
    )
    notes = []
    if raw.get("alias_of"):
        notes.append(f"The slug {raw['alias_of']} is an alias of the tracked product {slug}.")
    if len(versions) < len(all_versions):
        notes.append(f"Showing {len(versions)} of {len(all_versions)} versions. Raise the limit argument to see more.")
    if raw.get("product_url"):
        notes.append(f"Product page: {raw['product_url']}")
    if notes:
        readable += "\n" + "\n\n".join(notes) + "\n"

    return CommandResults(
        outputs_prefix=PRODUCT_PREFIX,
        outputs_key_field="product",
        outputs=outputs,
        readable_output=readable,
        raw_response=raw,
    )


def version_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """endoflife-ai-version-get: lifecycle status and EOL risk score of one product version."""
    product = str(args.get("product") or "").strip()
    version = str(args.get("version") or "").strip()
    if not product or not version:
        raise ValueError("The product and version arguments are required.")

    try:
        raw = client.get_version(product, version)
    except NotFoundError as e:
        return not_found_result(e, product, version)

    result = build_version(raw)
    readable = tableToMarkdown(
        f"endoflife.ai status of {result.get('product')} {result.get('version')}",
        version_row(result),
        headers=VERSION_TABLE_HEADERS,
        removeNull=True,
    )
    notes = resolution_notes(result)
    if result.get("score_card_url"):
        notes.append(f"Score card: {result['score_card_url']}")
    if notes:
        readable += "\n" + "\n\n".join(notes) + "\n"

    return CommandResults(
        outputs_prefix=VERSION_PREFIX,
        outputs_key_field=["product", "version"],
        outputs=result,
        readable_output=readable,
        raw_response=raw,
    )


def version_batch_get_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """endoflife-ai-version-batch-get: lifecycle status and EOL risk score of a list of product versions."""
    items = parse_pairs(argToList(args.get("products")))
    chunk_size = positive_int(args.get("chunk_size"), "chunk_size", DEFAULT_CHUNK_SIZE)

    resolved: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    raw_responses: list[dict[str, Any]] = []
    for start in range(0, len(items), chunk_size):
        chunk = items[start: start + chunk_size]
        raw = client.batch(chunk)
        raw_responses.append(raw)
        answers = raw.get("results") or []
        for index, sent in enumerate(chunk):
            answer = answers[index] if index < len(answers) and isinstance(answers[index], dict) else {}
            if not answer or answer.get("error"):
                failure = {
                    "product": sent["slug"],
                    "version": sent.get("version"),
                    "error": answer.get("error") or "No answer was returned for this item.",
                    "reason": answer.get("reason"),
                    "candidates": answer.get("candidates"),
                    "cycle": answer.get("cycle"),
                    "last_published": answer.get("last_published"),
                }
                unresolved.append({key: value for key, value in failure.items() if value is not None})
            else:
                resolved.append(build_version(answer))

    results: list[CommandResults] = []
    if resolved:
        readable = tableToMarkdown(
            "endoflife.ai batch check",
            [version_row(item) for item in resolved],
            headers=VERSION_TABLE_HEADERS,
            removeNull=True,
        )
        notes = [note for item in resolved for note in resolution_notes(item)]
        if notes:
            readable += "\n" + "\n\n".join(notes) + "\n"
        results.append(
            CommandResults(
                outputs_prefix=VERSION_PREFIX,
                outputs_key_field=["product", "version"],
                outputs=resolved,
                readable_output=readable,
                raw_response=raw_responses,
            )
        )
    if unresolved:
        rows = [
            {
                "Product": item.get("product"),
                "Version": item.get("version"),
                "Error": item.get("error"),
                "Reason": item.get("reason"),
                "Candidates": ", ".join(str(candidate) for candidate in argToList(item.get("candidates"))) or None,
            }
            for item in unresolved
        ]
        results.append(
            CommandResults(
                outputs_prefix=BATCH_ERROR_PREFIX,
                outputs_key_field=["product", "version"],
                outputs=unresolved,
                readable_output=tableToMarkdown(
                    "endoflife.ai batch check: items that were not resolved",
                    rows,
                    headers=BATCH_ERROR_TABLE_HEADERS,
                    removeNull=True,
                ),
                raw_response=None if resolved else raw_responses,
            )
        )
    return results


""" MAIN FUNCTION """


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = str((params.get("credentials") or {}).get("password") or "").strip()
    base_url = str(params.get("url") or DEFAULT_BASE_URL).strip().rstrip("/")
    verify_certificate = not argToBoolean(params.get("insecure") or False)
    proxy = argToBoolean(params.get("proxy") or False)

    demisto.debug(f"Command being called is {command}")
    try:
        if not api_key:
            raise DemistoException(
                f"{AUTH_ERROR_PREFIX}: The API Key field is empty. A free API key is available at {FREE_KEY_URL}."
            )
        client = Client(base_url=base_url, api_key=api_key, verify=verify_certificate, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client))
        elif command == "endoflife-ai-product-get":
            return_results(product_get_command(client, args))
        elif command == "endoflife-ai-version-get":
            return_results(version_get_command(client, args))
        elif command == "endoflife-ai-version-batch-get":
            return_results(version_batch_get_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
