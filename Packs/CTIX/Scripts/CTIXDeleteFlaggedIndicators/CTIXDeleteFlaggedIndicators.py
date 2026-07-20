import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

BRAND = "CTIX v3"

# Script argument name -> TIM indicator field (cliName) populated by the CTIX v3 feed.
FLAG_ARG_TO_FIELD = {
    "delete_deprecated": "ctixisdeprecated",
    "delete_revoked": "ctixisrevoked",
    "delete_false_positive": "ctixisfalsepositive",
    "delete_whitelisted": "ctixiswhitelisted",
    "delete_reviewed": "ctixisreviewed",
}


def build_query(args: dict) -> str:
    """Build the deleteIndicators search query from the enabled delete_* flags.

    Returns an empty string when no flag is enabled so callers never issue an
    unscoped delete.
    """
    enabled_fields = [field for arg, field in FLAG_ARG_TO_FIELD.items() if argToBoolean(args.get(arg, False))]
    if not enabled_fields:
        return ""
    flag_conditions = " or ".join(f"{field}:T" for field in enabled_fields)
    return f'sourceBrands:"{BRAND}" and ({flag_conditions})'


def main():
    try:
        args = demisto.args()
        query = build_query(args)
        if not query:
            return_results("No delete flags enabled; nothing to do.")
            return

        do_not_whitelist = not argToBoolean(args.get("exclude", False))
        reason = args.get("reason") or "Deleted by CTIXDeleteFlaggedIndicators job"

        # execute_command raises DemistoException on an error entry, caught below.
        res = execute_command("deleteIndicators", {"query": query, "doNotWhitelist": do_not_whitelist, "reason": reason})
        return_results(res)

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute CTIXDeleteFlaggedIndicators. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
