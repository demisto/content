"""
GIBDRPResolveViolation
======================

Layout-button automation: approves or rejects a Group-IB DRP violation.

The decision goes to the instance that fetched the incident. Without ``using`` Cortex XSOAR runs
``gibdrp-change-violation-status`` on every enabled instance of the integration, and with several
instances (one per brand, section or severity, which the setup guide recommends) the instances
that do not own the violation answer with an error and the button fails. The ``using`` argument
wins; then the incident's ``sourceInstance``, when that instance is still active; then the only
active instance.

Approving does **not** close the incident by default. It settles the customer's half of the
decision -- the takedown itself continues in DRP afterwards, and the incident is closed later, when
DRP reports the violation as resolved (``resolved``, or ``solved`` on older API versions) or handed
to legal (``legal``). That close is owned by ``GIBDRPIncidentUpdate``. With **Close the incident
when a violation is approved** enabled on the instance, ``gibdrp-change-violation-status`` answers
with ``closeIncident: true`` and this automation closes the incident as *Resolved* at once.

Rejecting always closes the incident as *False Positive*: DRP does nothing more with a rejected
violation, so nothing later would close the incident. When the incident asks for it (**GIB DRP
Expire Indicator On Close**), the indicator created from the violation is expired as well.

Either way the automation records the decision on the incident, so that the **Approve Violation**
and **Reject Violation** buttons stop offering a decision that has already been made: both are
displayed only while ``gibdrpapprovestate`` is ``under_review``.
"""

from typing import Any
from urllib.parse import urlsplit

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

CHANGE_COMMAND = "gibdrp-change-violation-status"
INTEGRATION_BRAND = "Group-IB Digital Risk Protection"

# `violation.approveState` after DRP accepts the customer's decision, per the
# `ClientViolationPageBrandInfo` enum of the DRP API. Writing it back locally rather than
# re-reading the violation keeps the button press to a single API call; the next fetch
# overwrites the field with whatever DRP actually holds.
RESOLVED_APPROVE_STATE = {"approve": "approved", "reject": "rejected"}

# Close reasons: an approval closes only when the instance asks for it, a rejection always.
CLOSE_REASON = {"approve": "Resolved", "reject": "False Positive"}


def violation_id(args: dict[str, Any], incident: dict[str, Any]) -> str:
    explicit = (args.get("id") or "").strip()
    if explicit:
        return explicit
    fields = incident.get("CustomFields") or {}
    found = fields.get("gibdrpid") or incident.get("gibdrpid")
    if not found:
        raise DemistoException("No Group-IB DRP violation id: pass `id`, or run this on an incident that has GIB DRP ID set.")
    return str(found)


def resolve_instance(args: dict[str, Any], incident: dict[str, Any]) -> str | None:
    """The integration instance the decision is sent through.

    ``using`` wins; then the instance that fetched the incident, when it is still active; then
    the only active instance. ``None`` (every instance, the platform default) only when several
    are active and none of them fetched the incident.
    """
    explicit = str(args.get("using") or "").strip()
    if explicit:
        return explicit
    modules = demisto.getModules() or {}
    active = {
        name
        for name, module in modules.items()
        if isinstance(module, dict) and module.get("brand") == INTEGRATION_BRAND and module.get("state") == "active"
    }
    source = str(incident.get("sourceInstance") or "").strip()
    if source and source in active:
        return source
    if len(active) == 1:
        return next(iter(active))
    return None


def wants_indicator_expired(incident: dict[str, Any]) -> bool:
    fields = incident.get("CustomFields") or {}
    return argToBoolean(fields.get("gibdrpexpireindicatoronclose") or False)


def change_status(feed_id: str, status: str, instance: str | None) -> dict[str, Any]:
    """Send the decision to DRP; return the command's answer (`closeIncident` among it)."""
    command_args: dict[str, Any] = {"id": feed_id, "status": status}
    if instance:
        command_args["using"] = instance

    responses = demisto.executeCommand(CHANGE_COMMAND, command_args)
    answer: dict[str, Any] = {}
    for response in responses or []:
        if is_error(response):
            raise DemistoException(f"{CHANGE_COMMAND} failed: {get_error(response)}")
        contents = response.get("Contents") if isinstance(response, dict) else None
        if isinstance(contents, dict) and not answer:
            answer = contents
    return answer


def record_decision(status: str) -> bool:
    """Write the new approve state onto the current incident; return False if it did not stick.

    A failure here is not fatal: the decision already reached DRP and cannot be taken back, so
    the automation reports a stale field rather than an error that would suggest nothing happened.
    """
    responses = demisto.executeCommand("setIncident", {"gibdrpapprovestate": RESOLVED_APPROVE_STATE[status]})
    for response in responses or []:
        if is_error(response):
            demisto.debug(f"GIBDRPResolveViolation: setIncident failed: {get_error(response)}")
            return False
    return True


def close_incident(status: str) -> bool:
    """Close the current incident with the decision; return False if XSOAR refused."""
    if status == "reject":
        notes = "The violation was rejected in Group-IB DRP from the incident. DRP does nothing more with a rejected violation."
    else:
        notes = (
            "The violation was approved in Group-IB DRP from the incident, and the instance is configured "
            "to close the incident with the approval."
        )
    # No violation id in the notes: a 64-hex string in a note is auto-extracted as a SHA256 File
    # indicator. The id stays in the GIB DRP ID field.
    responses = demisto.executeCommand("closeInvestigation", {"closeReason": CLOSE_REASON[status], "closeNotes": notes})
    for response in responses or []:
        if is_error(response):
            demisto.debug(f"GIBDRPResolveViolation: closeInvestigation failed: {get_error(response)}")
            return False
    return True


def indicator_value(uri: str) -> str | None:
    """The value GIBDRPCreateViolationIndicator gave the indicator made from this violation URI.

    Mirrors that automation's `classify`: a bare `//host/path` became an https URL, a bare
    `host/path` got an https scheme, a bare host was lower-cased; anything with a scheme other
    than http or https (`mail://`, `tg://`) never became an indicator, so there is nothing to expire.
    """
    candidate = uri.strip()
    if not candidate:
        return None
    if candidate.startswith("//"):
        candidate = "https:" + candidate
    if "://" in candidate:
        parts = urlsplit(candidate)
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            return None
        return candidate
    if "/" in candidate or "?" in candidate:
        return "https://" + candidate if urlsplit("https://" + candidate).hostname else None
    return candidate.rstrip(".").lower()


def expire_indicator(incident: dict[str, Any]) -> bool | None:
    """Expire the indicator created from the violation URI.

    Returns None when the URI never became an indicator, True when it was expired and False when
    the expireIndicators builtin refused (the reason goes to the server log).
    """
    fields = incident.get("CustomFields") or {}
    value = indicator_value(str(fields.get("gibdrpviolationuri") or ""))
    if not value:
        return None
    # Cortex XSOAR 8 reads the builtin's list from `indicatorsValues` ("Provide indicator(s) value(s)"
    # otherwise); `value` is the name older builtin documentation uses, so both are passed.
    responses = demisto.executeCommand("expireIndicators", {"indicatorsValues": value, "value": value})
    for response in responses or []:
        if is_error(response):
            demisto.info(f"GIBDRPResolveViolation: expireIndicators failed for {value!r}: {get_error(response)}")
            return False
    return True


def main() -> None:
    try:
        args = demisto.args()
        status = str(args.get("status") or "").strip().lower()
        if status not in RESOLVED_APPROVE_STATE:
            raise DemistoException(f"Invalid status {status!r}: expected one of {', '.join(sorted(RESOLVED_APPROVE_STATE))}.")

        incident = demisto.incident() or {}
        feed_id = violation_id(args, incident)
        answer = change_status(feed_id, status, resolve_instance(args, incident))
        approve_state = RESOLVED_APPROVE_STATE[status]
        recorded = record_decision(status)
        should_close = status == "reject" or bool(answer.get("closeIncident"))
        # The indicator is expired BEFORE the investigation is closed: Cortex XSOAR refuses to run
        # a command inside a closed investigation (HTTP 412), so the old order silently never expired anything.
        expired: bool | None = None
        if should_close and status == "reject" and wants_indicator_expired(incident):
            expired = expire_indicator(incident)
        closed = should_close and close_incident(status)

        readable_output = f"Group-IB DRP violation **{feed_id}** was set to **{status}**."
        if closed and status == "reject":
            readable_output += (
                " The incident was closed as **False Positive**: Group-IB DRP does nothing more with a rejected violation."
            )
            if expired:
                readable_output += " The indicator created from the violation was expired."
            elif expired is False:
                readable_output += " The indicator created from the violation could not be expired; see the server log."
        elif closed:
            readable_output += f" The incident was closed as **{CLOSE_REASON[status]}**, as the instance is configured."
        elif recorded:
            readable_output += (
                f" The incident stays open until Group-IB DRP resolves the violation; "
                f"its approve state is now **{approve_state}**."
            )
        else:
            readable_output += (
                " The incident stays open until Group-IB DRP resolves the violation."
                " GIB DRP Approve State could not be updated on the incident and will catch up on the next fetch."
            )

        return_results(
            CommandResults(
                readable_output=readable_output,
                outputs_prefix="GIBDRP.ViolationResolution",
                outputs={
                    "id": feed_id,
                    "status": status,
                    "approveState": approve_state,
                    "incidentUpdated": recorded,
                    "incidentClosed": closed,
                    "indicatorExpired": bool(expired),
                },
                # The violation id is a 64-hex string; without this XSOAR extracts it from the
                # entry as a SHA256 File indicator on every button press.
                ignore_auto_extract=True,
            )
        )
    except Exception as exc:  # noqa: BLE001 - the automation boundary
        return_error(f"GIBDRPResolveViolation failed: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
