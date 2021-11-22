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
    """
    Given:  context with campaign data (has EmailCampaign key) and other data
            empty context
            context without campaign data
    When:   Getting context from the original incident in order to put it in other incident
    Then:   Validate we take only the campaign data part.
    """
    from SetPhishingCampaignDetails import get_campaign_context
    mocker.patch.object(demisto, 'context', return_value=context_mock)
    res = get_campaign_context()
    assert res == expected_results


CONTEXT_COPY_CASES = [
    (CONTEXT_WITH_CAMPAIGN.get("EmailCampaign"), {'incidents': 1, 'command': 'Set', 'arguments':
        {'key': 'EmailCampaign', 'value': {'field_example': 'field_example', 'field_example_2': 'field_example'},
         'append': False}}),
]


@pytest.mark.parametrize('context_mock, expected_results', CONTEXT_COPY_CASES)
def test_copy_campaign_data_to_incident(mocker, context_mock, expected_results):
    """
    Given:  context with only campaign data
    When:   adding context from the original incident to other incident
    Then:   Validate we call the set command with the correct arguments.
    """
    from SetPhishingCampaignDetails import copy_campaign_data_to_incident
    execute_mock = mocker.patch.object(demisto, 'executeCommand')
    copy_campaign_data_to_incident(1, context_mock, False)
    execute_mock.assert_called_once_with('executeCommandAt', expected_results)


CONTEXT_COPY_CASES_FAILS = [
    (EMPTY_CONTEXT),
    (None)
]


@pytest.mark.parametrize('context_mock', CONTEXT_COPY_CASES_FAILS)
def test_copy_campaign_data_to_incident_fails(mocker, context_mock):
    """
        Given:  empty context
                context without campaign data
        When:   adding context from the original incident to other incident
        Then:   Validate we ignore the incident if no campaign data is found with correct error logged.
    """
    from SetPhishingCampaignDetails import copy_campaign_data_to_incident, EMAIL_CAMPAIGN_KEY
    debugging_mock = mocker.patch.object(demisto, 'debug')
    execute_mock = mocker.patch.object(demisto, 'executeCommand')
    copy_campaign_data_to_incident(1, context_mock, False)
    debugging_mock.assert_called_once_with(f'Error - {EMAIL_CAMPAIGN_KEY} was not found. Ignoring incident id: 1')
    execute_mock.assert_not_called()
