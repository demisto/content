"""
Domain Tools Iris Detect Status Update
"""
from CommonServerPython import *  # noqa: F401


def main():
    """
    This script updates the state of DomainTools Iris Detect New Domains incident and takes appropriate action based on
    the new and old values.

    Returns:
        None

    Raises:
        ValueError: If the new and old values are not valid JSON.

    """
    commands = {
        "watched": "domaintools-iris-detect-watch-domains",
        "ignored": "domaintools-iris-detect-ignore-domains",
        "blocked": "domaintools-iris-detect-blocklist-domains",
        "escalated": "domaintools-iris-detect-escalate-domains",
    }
    error_message = "The changed, blocked, escalated, or ignored domain state cannot be updated to a new domain state."
    try:
        args = demisto.args()
        domain_list: Dict = {
            "watched": [],
            "ignored": [],
            "new": [],
            "blocked": [],
            "escalated": [],
        }
        command_args = {}
        old_value = demisto.get(args, "old")
        new_value = demisto.get(args, "new")
        if not all(map(json.loads, [old_value, new_value])):
            raise DemistoException("Invalid JSON value")
        old_value, new_value = map(json.loads, [old_value, new_value])
        update_list: Dict = {
            "watched": [],
            "ignored": [],
            "new": [],
            "blocked": [],
            "escalated": [],
        }
        for idx, obj in enumerate(new_value):
            if obj.get("state") != old_value[idx].get("state"):
                update_list[obj["state"]].append(obj["id"])
                domain_list[obj["state"]].append(obj["domain"])

        for state, ids in update_list.items():
            if ids:
                command_args["watchlist_domain_ids"] = ids
                if state == "new":
                    demisto.error(error_message)
                    raise DemistoException(error_message)

                demisto.executeCommand(commands.get(state), command_args)
        for state, domains in domain_list.items():
            if domains:
                if state == "new":
                    demisto.error(error_message)
                    raise DemistoException(error_message)
                for domain in domains:
                    args = {'value': domain, 'irisdetectdomainstate': state}
                    demisto.executeCommand('setIndicator', args)
    except Exception as err:
        return_error(f"Failed to update state. {err}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
