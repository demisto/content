import pytest
import demistomock as demisto

CONTEXT_WITH_CAMPAIGN = {
    "EmailCampaign": {
        "field_example": "field_example",
        "field_example_2": "field_example"
    },
    'NotCampaign': 'field_example'
}
EMPTY_CONTEXT = {}
CONTEXT_WITHOUT_CAMPAIGN = {'NotCampaign': 'field_example'}
CONTEXT_MOCK_CASES = [
    (CONTEXT_WITH_CAMPAIGN, CONTEXT_WITH_CAMPAIGN.get("EmailCampaign")),
    (EMPTY_CONTEXT, None),
    (CONTEXT_WITHOUT_CAMPAIGN, None),
]

@pytest.mark.parametrize('context_mock, expected_results', CONTEXT_MOCK_CASES)
def test_get_campaign_context(mocker, context_mock, expected_results):
    from SetPhishingCampaignDetails import get_campaign_context
    mocker.patch.object(demisto, 'context', return_value=context_mock)
    res = get_campaign_context()
    assert res == expected_results