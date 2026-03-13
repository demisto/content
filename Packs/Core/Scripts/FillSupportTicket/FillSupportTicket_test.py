from Packs.Core.Scripts.FillSupportTicket.FillSupportTicket import core_fill_support_ticket


def test_core_fill_support_ticket_command_success():
    """
    GIVEN:
        Valid arguments including the new product_type.
    WHEN:
        The core_fill_support_ticket_command function is called.
    THEN:
        The response contains the productType and other fields correctly mapped.
    """

    args = {
        "product_type": "Cortex XSIAM",
        "description": "This is a detailed description that is at least 25 characters long.",
        "contact_number": "123456789",
        "issue_impact": "P4",
        "issue_category": "Agent",
        "problem_concentration": "Communication",
        "issue_frequency": "Yes - Consistent",
        "most_recent_issue_start_time": "2023-01-01T00:00:00Z",
    }

    result = core_fill_support_ticket(args)

    assert result.outputs["description"] == args["description"]
    assert result.outputs["contactNumber"] == "123456789"
    assert result.outputs["IssueImpact"] == "P4"
    assert result.outputs["smeArea"] == "Agent"
    assert result.outputs["subGroupName"] == "Communication"
    assert result.outputs["OngoingIssue"] == "Yes - Consistent"
    assert result.outputs["DateTimeOfIssue"] is not None
    assert result.outputs_prefix == "Core.SupportTicket"
