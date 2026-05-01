import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():  # pragma: no cover
    """Entry point for the VerifySupportTicketPermissionWrapper script."""
    try:
        result = demisto.executeCommand("VerifySupportTicketPermission", {})
        return_results(result)
    except Exception as e:
        return_error(f"VerifySupportTicketPermissionWrapper failed: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
