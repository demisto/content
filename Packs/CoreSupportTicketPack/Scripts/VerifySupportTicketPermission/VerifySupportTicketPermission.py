import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def verify_support_ticket_permission() -> CommandResults:
    """Command wrapper for verify_support_ticket_permission.
    Checks whether the current user has the required permissions to manage support tickets.

    Args:
        client (Client): The client instance used to send the request.

    Returns:
        CommandResults: Object containing the permission check results with
            user_csp_permission and tenant_entitlement_check fields.

    """
    response = demisto._apiCall(
        method="POST",
        path="/api/webapp/sfdc_support/check_permission",
    )
    demisto.debug(f"Support ticket permission check: {response}")
    reply = json.loads(response.get("data", "")).get("reply", {})
    user_csp_permission = reply.get("user_csp_permission", False)
    tenant_entitlement_check = reply.get("tenant_entitlement_check", False)

    has_permission = bool(user_csp_permission and tenant_entitlement_check)

    output = {
        "user_csp_permission": user_csp_permission,
        "tenant_entitlement_check": tenant_entitlement_check,
        "has_permission": has_permission,
    }

    if not has_permission:
        readable_output = ""
        if not tenant_entitlement_check:
            readable_output += "Support for this tenant has expired."
        if not user_csp_permission:
            readable_output += "You do not have the required CSP permissions to manage support tickets."

        output["Error"] = readable_output

    else:
        readable_output = tableToMarkdown(
            "Support Ticket Permission",
            output,
            headerTransform=string_to_table_header,
        )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Core.SupportTicketPermission",
        outputs=output,
        raw_response=response,
    )


def main():  # pragma: no cover
    """Entry point for the VerifySupportTicketPermission script."""
    try:
        results = verify_support_ticket_permission()
        return_results(results)
    except Exception as e:
        return_error(f"Failed to verify support ticket permission: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
