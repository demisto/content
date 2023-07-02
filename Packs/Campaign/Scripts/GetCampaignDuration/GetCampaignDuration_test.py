from unittest.mock import patch
from freezegun import freeze_time

from GetCampaignDuration import get_duration_html

import pytest

import demistomock as demisto

CAMPAIGN_WITH_DURATION_RESULT = """
                <table style="margin-left:auto;margin-right:auto;">
                <tr>
                <th style="font-size: 25px;">&#128345;</th>
                <th style="font-size: 30px;">30</th>
                <th style="font-size: 30px;">:</th>
                <th style="font-size: 30px;">22</th>
                <th style="font-size: 30px;">:</th>
                <th style="font-size: 30px;">39</th>
                </tr>
                <tr>
                <td style="font-size: 15px; text-align: center"></td>
                <td style="font-size: 15px; text-align: center">Days</td>
                <td style="font-size: 15px; text-align: center"></td>
                <td style="font-size: 15px; text-align: center">Hours</td>
                <td style="font-size: 15px; text-align: center"></td>
                <td style="font-size: 15px; text-align: center">Minutes</td>
                </tr>
                </table>
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
