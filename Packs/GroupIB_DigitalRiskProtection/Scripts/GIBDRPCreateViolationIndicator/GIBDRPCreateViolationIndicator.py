"""
GIBDRPCreateViolationIndicator
==============================

Creates the indicator of a Group-IB DRP violation from its incident.

The postprocessing playbook runs it on a new incident whose **GIB DRP Indicator Wanted** field is
set, which the fetch sets for the violation types selected in **Create indicators from
Violations**. Creating the indicator here, with ``createNewIndicator``, rather than in the fetch
gives it what a fetch-created indicator lacked: a link to the incident (``relatedIncidents``), a
source, first and last seen dates, and a verdict; and it ties the indicator's life to the
incident's, so that the pre-processing rule or the Reject button can expire it when the violation
is over.

Only an ``http`` or ``https`` URL, a domain or an IPv4 address becomes an indicator. A violation
URI that is none of those -- a marketplace seller id, a messenger handle, a ``mail://`` address --
is reported and skipped rather than published as junk.
"""

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

SOURCE = "Group-IB Digital Risk Protection"

# `createNewIndicator` reputation names per violation type. Group-IB analysts confirm a
# violation before it is published, so the types that describe an active attack on the
# customer are Malicious; the types that describe a rights dispute are Suspicious; a
# violation explicitly closed as "No violation" must not poison the customer's threat
# intel and is Benign. An unknown type never claims more than Suspicious.
REPUTATION_BY_TYPE: dict[str, str] = {
    "counterfeit": "Bad",
    "scam": "Bad",
    "malware": "Bad",
    "phishing": "Bad",
    "partner policy compliance": "Suspicious",
    "piracy": "Suspicious",
    "trademark": "Suspicious",
    "no violation": "Good",
}
DEFAULT_REPUTATION = "Suspicious"
VERDICT_BY_REPUTATION = {"Bad": "Malicious", "Suspicious": "Suspicious", "Good": "Benign"}

# Labels per RFC 1123, and a top-level label that is alphabetic (or punycode), so that a
# malformed dotted number such as `999.1.1.1` is neither an IP nor a domain.
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOSTNAME = re.compile(rf"^(?=.{{1,253}}$)(?:{_LABEL}\.)+(?:xn--[A-Za-z0-9-]{{1,59}}|[A-Za-z]{{2,63}})\.?$")


def classify(value: str) -> tuple[str, str] | None:
    """(indicator type, normalized value) for a violation URI, or None when it is none of the three.

    DRP writes many URIs without a scheme (`//bad.example/login`, `bad.example`); a bare
    `//host/path` is read as an https URL, a bare host as a domain. Anything with a scheme
    other than http or https (`mail://`, `tg://`, `android-app://`) is not an indicator.
    """
    candidate = value.strip()
    if not candidate:
        return None
    if candidate.startswith("//"):
        candidate = "https:" + candidate
    if "://" in candidate:
        parts = urlsplit(candidate)
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            return None
        return "URL", candidate
    if "/" in candidate or "?" in candidate:
        parts = urlsplit("https://" + candidate)
        if not parts.hostname:
            return None
        return "URL", "https://" + candidate
    try:
        ipaddress.IPv4Address(candidate)
        return "IP", candidate
    except ValueError:
        pass
    if _HOSTNAME.match(candidate):
        return "Domain", candidate.rstrip(".").lower()
    return None


def reputation_for(violation_type: str | None) -> str:
    if not isinstance(violation_type, str):
        return DEFAULT_REPUTATION
    return REPUTATION_BY_TYPE.get(violation_type.strip().lower(), DEFAULT_REPUTATION)


def indicator_arguments(incident: dict[str, Any], value: str, indicator_type: str) -> dict[str, Any]:
    fields = incident.get("CustomFields") or {}
    violation_type = fields.get("gibdrptype")
    brand = fields.get("gibdrpbrand")
    tags = [tag for tag in ("Group-IB DRP", violation_type, brand) if isinstance(tag, str) and tag.strip()]
    description = fields.get("gibdrptitle") or fields.get("gibdrpdescription")
    first_seen = fields.get("gibdrpfirstdetected") or fields.get("gibdrpdetected")
    last_seen = fields.get("gibdrpcurrentstatusdate")
    return assign_params(
        value=value,
        type=indicator_type,
        source=SOURCE,
        reputation=reputation_for(violation_type),
        relatedIncidents=str(incident.get("id") or "") or None,
        tags=",".join(tags) if tags else None,
        description=description,
        firstseenbysource=first_seen,
        lastseenbysource=last_seen,
    )


def create_indicator(arguments: dict[str, Any]) -> None:
    responses = demisto.executeCommand("createNewIndicator", arguments)
    for response in responses or []:
        if is_error(response):
            raise DemistoException(f"createNewIndicator failed: {get_error(response)}")


def main() -> None:
    try:
        args = demisto.args()
        incident = demisto.incident() or {}
        fields = incident.get("CustomFields") or {}
        uri = str(args.get("value") or fields.get("gibdrpviolationuri") or "").strip()
        if not uri:
            raise DemistoException(
                "No violation URI: pass `value`, or run this on an incident that has GIB DRP Violation URI set."
            )

        classified = classify(uri)
        outputs: dict[str, Any] = {"uri": uri, "created": False}
        if classified is None:
            readable_output = (
                f"No indicator was created from `{uri}`: only an http or https URL, a domain or an IPv4 address "
                "becomes an indicator."
            )
        else:
            indicator_type, value = classified
            arguments = indicator_arguments(incident, value, indicator_type)
            create_indicator(arguments)
            outputs.update(
                {
                    "value": value,
                    "type": indicator_type,
                    "verdict": VERDICT_BY_REPUTATION[arguments["reputation"]],
                    "created": True,
                }
            )
            readable_output = (
                f"Created the **{indicator_type}** indicator `{value}` ({outputs['verdict']}) from the violation and "
                "linked it to this incident."
            )

        return_results(
            CommandResults(
                readable_output=readable_output,
                outputs_prefix="GIBDRP.ViolationIndicator",
                outputs_key_field="uri",
                outputs=outputs,
                # The indicator is created deliberately above; the entry itself must not be extracted.
                ignore_auto_extract=True,
            )
        )
    except Exception as exc:  # noqa: BLE001 - the automation boundary
        return_error(f"GIBDRPCreateViolationIndicator failed: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
