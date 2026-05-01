import json

import demistomock as demisto  # noqa: F401
from GetSupportTicketTaxonomy import get_support_ticket_taxonomy

MOCK_REPLY = [
    {
        "value": "Agent",
        "suggestedValues": [
            {"value": "Communication"},
            {"value": "Device Control"},
        ],
    },
    {
        "value": "XDR Agent",
        "suggestedValues": [
            {"value": "XDR Agent for Enterprise - Linux"},
            {"value": "XDR Agent for Enterprise - Windows"},
        ],
    },
]


def test_get_support_ticket_taxonomy_success(mocker):
    """GIVEN:
        The API returns a valid list of SME areas with suggested values.
    WHEN:
        get_support_ticket_taxonomy is called.
    THEN:
        The taxonomy is built as a list of single-key dicts and returned
        with the correct outputs_prefix.
    """
    mocker.patch.object(
        demisto,
        "_apiCall",
        return_value={"data": json.dumps({"reply": MOCK_REPLY})},
    )

    result = get_support_ticket_taxonomy()

    assert result.outputs_prefix == "Core.SupportTicketTaxonomy"
    assert result.raw_response == [
        {"Agent": ["Communication", "Device Control"]},
        {"XDR Agent": ["XDR Agent for Enterprise - Linux", "XDR Agent for Enterprise - Windows"]},
    ]
    assert result.outputs == str(result.raw_response)


def test_get_support_ticket_taxonomy_empty_reply(mocker):
    """GIVEN:
        The API returns an empty reply list.
    WHEN:
        get_support_ticket_taxonomy is called.
    THEN:
        The taxonomy is empty.
    """
    mocker.patch.object(
        demisto,
        "_apiCall",
        return_value={"data": json.dumps({"reply": []})},
    )

    result = get_support_ticket_taxonomy()

    assert result.raw_response == []


def test_get_support_ticket_taxonomy_filters_empty_suggested_values(mocker):
    """GIVEN:
        Some suggestedValues entries have empty or missing 'value' fields.
    WHEN:
        get_support_ticket_taxonomy is called.
    THEN:
        Only non-empty values are included in the concentration list.
    """
    mock_reply = [
        {
            "value": "Agent",
            "suggestedValues": [
                {"value": "Communication"},
                {"value": ""},
                {},
            ],
        }
    ]
    mocker.patch.object(
        demisto,
        "_apiCall",
        return_value={"data": json.dumps({"reply": mock_reply})},
    )

    result = get_support_ticket_taxonomy()

    assert result.raw_response == [{"Agent": ["Communication"]}]


def test_get_support_ticket_taxonomy_area_with_no_suggested_values(mocker):
    """GIVEN:
        An SME area has no suggestedValues.
    WHEN:
        get_support_ticket_taxonomy is called.
    THEN:
        The area is included with an empty concentration list.
    """
    mock_reply = [{"value": "Agent", "suggestedValues": []}]
    mocker.patch.object(
        demisto,
        "_apiCall",
        return_value={"data": json.dumps({"reply": mock_reply})},
    )

    result = get_support_ticket_taxonomy()

    assert result.raw_response == [{"Agent": []}]
