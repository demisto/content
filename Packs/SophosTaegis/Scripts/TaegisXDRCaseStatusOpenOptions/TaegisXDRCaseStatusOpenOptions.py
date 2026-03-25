"""
Field display script for Taegis XDR Case Status (taegisxdrcasestatus).

Returns only status values that do NOT start with "CLOSED_", for use in sections
such as Taegis XDR Case Details where you want to show only open/active statuses
(ACTIVE, AWAITING_ACTION, OPEN, SUSPENDED). Attach this script to the incident
field as the field display script.

Note: When this script is attached, the field will show only these options
wherever it is displayed. To allow selecting closed statuses (e.g. in a Close
section), use a second single-select field with full values there, or do not
attach this script and use layout visibility to show the field in different places.
"""

# All Taegis XDR investigation statuses (must match incident field selectValues)
TAEGIS_STATUSES_ALL = [
    "ACTIVE",
    "AWAITING_ACTION",
    "CLOSED_AUTHORIZED_ACTIVITY",
    "CLOSED_CONFIRMED_SECURITY_INCIDENT",
    "CLOSED_FALSE_POSITIVE_ALERT",
    "CLOSED_INCONCLUSIVE",
    "CLOSED_INFORMATIONAL",
    "CLOSED_NOT_VULNERABLE",
    "CLOSED_THREAT_MITIGATED",
    "OPEN",
    "SUSPENDED",
]

# Only statuses that do not start with "CLOSED_" (for Case Details / open-status display)
OPEN_STATUSES = [s for s in TAEGIS_STATUSES_ALL if not s.startswith("CLOSED_")]


def main():
    # Field display scripts must return a dict: {"hidden": bool, "options": list}
    # A plain list is ignored and the field falls back to selectValues (all options).
    # Prepend placeholder for "Update in Taegis" requested field so user can reset after push
    PLACEHOLDER = "Select Status"
    options = [PLACEHOLDER] + OPEN_STATUSES
    demisto.results({"hidden": False, "options": options})


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
