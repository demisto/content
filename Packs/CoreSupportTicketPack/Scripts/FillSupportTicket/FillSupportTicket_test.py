import demistomock as demisto  # noqa: F401
from FillSupportTicket import core_fill_support_ticket


def test_core_fill_support_ticket_all_fields():
    """GIVEN:
        Valid arguments for all supported fields.
    WHEN:
        core_fill_support_ticket is called.
    THEN:
        All fields are correctly mapped to the output dict.
    """
    args = {
        "description": "This is a detailed description that is at least 25 characters long.",
        "contact_number": "123456789",
        "issue_impact": "P4",
        "issue_frequency": "Yes - Consistent",
        "most_recent_issue_start_time": "2023-01-01T00:00:00Z",
    }

    result = core_fill_support_ticket(args, issue_category="Agent", problem_concentration="Communication")

    assert result.outputs["description"] == args["description"]
    assert result.outputs["contactNumber"] == "123456789"
    assert result.outputs["IssueImpact"] == "P4"
    assert result.outputs["smeArea"] == "Agent"
    assert result.outputs["subGroupName"] == "Communication"
    assert result.outputs["OngoingIssue"] == "Yes - Consistent"
    assert result.outputs["DateTimeOfIssue"] is not None
    assert result.outputs_prefix == "Core.SupportTicket"


def test_core_fill_support_ticket_no_start_time():
    """GIVEN:
        Arguments without most_recent_issue_start_time.
    WHEN:
        core_fill_support_ticket is called.
    THEN:
        DateTimeOfIssue is None.
    """
    args = {
        "description": "Test description",
    }

    result = core_fill_support_ticket(args, issue_category="Agent", problem_concentration="Communication")

    assert result.outputs["DateTimeOfIssue"] is None
    assert result.outputs["smeArea"] == "Agent"
    assert result.outputs_prefix == "Core.SupportTicket"
