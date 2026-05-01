import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():  # pragma: no cover
    """Entry point for the GetSupportTicketTaxonomyWrapper script."""
    try:
        result = demisto.executeCommand("GetSupportTicketTaxonomy", {})
        return_results(result)
    except Exception as e:
        return_error(f"GetSupportTicketTaxonomyWrapper failed: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
