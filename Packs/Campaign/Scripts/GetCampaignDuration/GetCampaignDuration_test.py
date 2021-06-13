import re
from unittest.mock import patch

from GetCampaignDuration import get_duration_html

import pytest

import demistomock as demisto
from datetime import datetime

CAMPAIGN_WITH_DURATION_RESULT = """
                    <div class="demisto-duration vertical-strech">
                        <div class="duration-widget">
                            <div class="grid-container">
                                <div class="duration-icon"><i class="wait icon home"></i></div>
                                <div class="days-number">5</div>
                                <div class="colon center aligned">:</div>
                                <div class="hours-number">22</div>
                                <div class="colon-2 center aligned">:</div>
                                <div class="one column wide minutes-number">49</div>
                                <div class="days-label time-unit title-h5 opacity-description">DAYS</div>
                                <div class="hours-label time-unit title-h5 opacity-description">HOURS</div>
                                <div class="minutes-label time-unit title-h5 opacity-description">MIN</div>
                            </div>
                        </div>
                    </div>

    """

CAMPAIGN_WITHout_DURATION_RESULT = """
                    <div class="demisto-duration vertical-strech">
                        <div class="duration-widget">
                            <div class="grid-container">
                                <div class="duration-icon"><i class="wait icon home"></i></div>
                                <div class="days-number">5</div>
                                <div class="colon center aligned">:</div>
                                <div class="hours-number">22</div>
                                <div class="colon-2 center aligned">:</div>
                                <div class="one column wide minutes-number">50</div>
                                <div class="days-label time-unit title-h5 opacity-description">DAYS</div>
                                <div class="hours-label time-unit title-h5 opacity-description">HOURS</div>
                                <div class="minutes-label time-unit title-h5 opacity-description">MIN</div>
                            </div>
                        </div>
                    </div>

    """


def compare_html_strings(a_string, b_string):
    a_list = re.findall("<div.*>.*</div>", a_string)
    b_list = re.findall("<div.*>.*</div>", b_string)
    return a_list == b_list


@pytest.mark.parametrize('EmailCampaign_context, result',
                         [({"firstIncidentDate": "04/07/2021, 16:00:52"}, CAMPAIGN_WITH_DURATION_RESULT)])
def test_campaign_with_duration(mocker, EmailCampaign_context, result):
    # prepare
    mocker.patch.object(demisto, "incident", return_value={'id': "100"})
    mocker.patch.object(demisto, "executeCommand",
                        return_value=[
                            {'Contents': {
                                'context': {"EmailCampaign": EmailCampaign_context}}}])
    mocker.patch("GetCampaignDuration.datetime", datetime(2021, 8, 5, 17, 30, 22))

    # run
    res = get_duration_html()
    assert compare_html_strings(res, result)


@patch('GetCampaignDuration.return_error')
def test_campaign_without_duration(mock_return_error, mocker):
    # prepare
    mocker.patch.object(demisto, "incident", return_value={'id': "100"})
    mocker.patch.object(demisto, "executeCommand",
                        return_value=[
                            {'Contents': {
                                'context': {"EmailCampaign": {}}}}])
    mocker.patch("GetCampaignDuration.datetime", datetime(2021, 8, 5, 17, 30, 22))

    # run
    get_duration_html()
    mock_return_error.assert_called_once_with('Cant find firstIncidentDate in context, please run FindEmailCampaign')
