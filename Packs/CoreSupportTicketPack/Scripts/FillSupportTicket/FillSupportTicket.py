import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# ---------------------------------------------------------------------------
# Step 1 & 2: Verify permission
# ---------------------------------------------------------------------------


def verify_permission() -> tuple[bool, str]:
    """Call _apiCall to check support ticket permission.

    Returns:
        (has_permission, error_message)

    """
    response = demisto._apiCall(
        method="POST",
        path="/api/webapp/sfdc_support/check_permission",
    )
    demisto.debug(f"FillSupportTicket: permission response: {response}")

    raw_data = response.get("data", "")
    if not raw_data:
        raise DemistoException(f"Permission check returned an empty response body. Full response: {response}")
    try:
        parsed = json.loads(raw_data)
    except json.JSONDecodeError as exc:
        raise DemistoException(f"Permission check returned non-JSON data: {raw_data!r}") from exc

    reply = parsed.get("reply", {})
    user_csp_permission = reply.get("user_csp_permission", False)
    tenant_entitlement_check = reply.get("tenant_entitlement_check", False)
    has_permission = bool(user_csp_permission and tenant_entitlement_check)

    error_msg = ""
    if not has_permission:
        if not tenant_entitlement_check:
            error_msg += "Support for this tenant has expired. "
        if not user_csp_permission:
            error_msg += "You do not have the required CSP permissions to manage support tickets."

    return has_permission, error_msg.strip()


# ---------------------------------------------------------------------------
# Step 3: Get taxonomy
# ---------------------------------------------------------------------------


def get_taxonomy() -> str:
    """Call _apiCall to retrieve the support ticket taxonomy.

    Returns:
        Taxonomy as a string (list of dicts) for passing to the LLM classifier.

    """
    response = demisto._apiCall(
        method="GET",
        path="/api/webapp/sfdc_support/get_sme_areas_and_sub_groups",
    )
    demisto.debug(f"FillSupportTicket: taxonomy response status: {response.get('status')}")

    raw_data = response.get("data", "")
    if not raw_data:
        raise DemistoException(f"Taxonomy request returned an empty response body. Full response: {response}")
    try:
        parsed = json.loads(raw_data)
    except json.JSONDecodeError as exc:
        raise DemistoException(f"Taxonomy request returned non-JSON data: {raw_data!r}") from exc

    reply = parsed.get("reply", {})

    taxonomy: list[dict] = []
    for area in reply:
        area_value = area.get("value", "")
        suggested_values = area.get("suggestedValues", [])
        problem_concentrations = [sg.get("value") for sg in suggested_values if sg.get("value")]
        taxonomy.append({area_value: problem_concentrations})

    return str(taxonomy)


# ---------------------------------------------------------------------------
# Step 4: Classify via LLM
# ---------------------------------------------------------------------------


def classify_ticket(description: str, taxonomy: str) -> str:
    """Run the SupportTicketClassification LLM script via executeCommand.

    Args:
        description: The user-provided ticket description.
        taxonomy: The taxonomy string from get_taxonomy().

    Returns:
        The raw classification result string (e.g. "Agent|||Communication").

    """
    result = demisto.executeCommand(
        "SupportTicketClassification",
        {"description": description, "taxonomy": taxonomy},
    )
    demisto.debug(f"FillSupportTicket: classification result: {result}")

    if is_error(result):
        raise DemistoException(f"SupportTicketClassification failed: {get_error(result)}")

    classification_result = ""
    if result:
        entry = result[0]
        ctx = entry.get("EntryContext") or {}
        # LLM scripts store result as flat key in EntryContext
        classification_result = ctx.get("Core.SupportTicketClassification.result", "")
        if not classification_result:
            # Fallback: extract answer from Contents (LLM preamble format: "AI Task Name:...\n\nAnswer:\n\t<result>")
            raw_contents = str(entry.get("Contents", "")).strip()
            if "Answer:" in raw_contents:
                classification_result = raw_contents.split("Answer:")[-1].strip()
            else:
                classification_result = raw_contents

    demisto.debug(f"FillSupportTicket: classification_result: {classification_result!r}")
    return classification_result


# ---------------------------------------------------------------------------
# Step 5: Parse classification
# ---------------------------------------------------------------------------


def parse_classification(classification_result: str, taxonomy: str) -> tuple[str | None, str | None]:
    """Run SupportTicketCategoryParser via executeCommand.

    Args:
        classification_result: The raw delimited string from classify_ticket().
        taxonomy: The taxonomy string.

    Returns:
        (issue_category, problem_concentration) — either may be None if invalid.

    """
    result = demisto.executeCommand(
        "SupportTicketCategoryParser",
        {"classification_result": classification_result, "taxonomy": taxonomy},
    )
    demisto.debug(f"FillSupportTicket: parser result: {result}")

    if is_error(result):
        raise DemistoException(f"SupportTicketCategoryParser failed: {get_error(result)}")

    issue_category = None
    problem_concentration = None
    if result:
        entry = result[0]
        ctx = entry.get("EntryContext") or {}
        parser_output = ctx.get("Core.SupportTicketCategoryParser", {})
        issue_category = parser_output.get("IssueCategory")
        problem_concentration = parser_output.get("ProblemConcentration")

    demisto.debug(f"FillSupportTicket: issue_category={issue_category!r} problem_concentration={problem_concentration!r}")
    return issue_category, problem_concentration


# ---------------------------------------------------------------------------
# Step 6: Map fields (original FillSupportTicket logic)
# ---------------------------------------------------------------------------


def core_fill_support_ticket(
    args: dict,
    issue_category: str | None,
    problem_concentration: str | None,
) -> CommandResults:
    """Validates arguments and maps them to the support ticket context.

    Args:
        args: Script arguments.
        issue_category: Classified issue category from LLM.
        problem_concentration: Classified problem concentration from LLM.

    Returns:
        CommandResults with Core.SupportTicket.* outputs.

    """
    demisto.debug(f"FillSupportTicket: core_fill_support_ticket args={args}")
    start_time = args.get("most_recent_issue_start_time")
    start_time_dt = arg_to_datetime(start_time) if start_time else None

    data = {
        "description": args.get("description"),
        "contactNumber": args.get("contact_number"),
        "OngoingIssue": args.get("issue_frequency"),
        "DateTimeOfIssue": start_time_dt.timestamp() if start_time_dt else None,
        "IssueImpact": args.get("issue_impact"),
        "smeArea": issue_category,
        "subGroupName": problem_concentration,
    }

    return CommandResults(
        outputs_prefix="Core.SupportTicket",
        outputs=data,
        raw_response=data,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():  # pragma: no cover
    """Entry point for the FillSupportTicket script."""
    try:
        args = demisto.args()
        description: str = args["description"]

        # Step 1 & 2: Permission check
        has_permission, error_msg = verify_permission()
        if not has_permission:
            return_error(error_msg)
            return

        # Step 3: Get taxonomy
        taxonomy = get_taxonomy()

        # Step 4: Classify
        classification_result = classify_ticket(description, taxonomy)

        # Step 5: Parse
        issue_category, problem_concentration = parse_classification(classification_result, taxonomy)

        # Step 6: Build ticket
        result = core_fill_support_ticket(args, issue_category, problem_concentration)
        return_results(result)

    except Exception as e:
        return_error(f"Failed to fill support ticket: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
