from unittest.mock import patch
from freezegun import freeze_time

from GetCampaignDuration import get_duration_html

import pytest

import demistomock as demisto

CAMPAIGN_WITH_DURATION_RESULT = """
                    <div class="demisto-duration vertical-strech">
                        <div class="duration-widget">
                            <div class="grid-container">
                                <div class="duration-icon"><i class="wait icon home"></i></div>
                                <div class="days-number">30</div>
                                <div class="colon center aligned">:</div>
                                <div class="hours-number">22</div>
                                <div class="colon-2 center aligned">:</div>
                                <div class="one column wide minutes-number">39</div>
                                <div class="days-label time-unit title-h5 opacity-description">DAYS</div>
                                <div class="hours-label time-unit title-h5 opacity-description">HOURS</div>
                                <div class="minutes-label time-unit title-h5 opacity-description">MIN</div>
                            </div>
                        </div>
                    </div>
    """

CURRENT_TIME_MOCK = "05-08-2021 14:40:22"


@pytest.mark.parametrize('EmailCampaign_context, result',
                         [({"firstIncidentDate": "2021-04-07T16:00:52.602353+00:00"}, CAMPAIGN_WITH_DURATION_RESULT)])
@freeze_time(CURRENT_TIME_MOCK)
def test_campaign_with_duration(mocker, EmailCampaign_context, result):
    """
    Given:
        - Email campaign context with first incident time

    When:
        - Get the campaign duration

    Then:
        - Calculate the duration and return valid html output

    """
    # prepare
    mocker.patch.object(demisto, "incident", return_value={'id': "100"})
    mocker.patch.object(demisto, "executeCommand",
                        return_value=[
                            {'Contents': {
                                'context': {"EmailCampaign": EmailCampaign_context}}}])

    # run
    res = get_duration_html()
    assert "".join(res.split()) == "".join(result.split())


@patch('GetCampaignDuration.return_error')
@freeze_time(CURRENT_TIME_MOCK)
def test_campaign_without_duration(mock_return_error, mocker):
    """
    Given:
        - Email campaign context without first incident time

    When:
        - Get the campaign duration

    Then:
        - Return error, invalid Cant find firstIncidentDat

    """
    # prepare
    mocker.patch.object(demisto, "incident", return_value={'id': "100"})
    mocker.patch.object(demisto, "executeCommand",
                        return_value=[
                            {'Contents': {
                                'context': {"EmailCampaign": {}}}}])

    # run
    res = get_duration_html()
    assert res == '<div style="text-align: center;">Duration is not available.</div>'
