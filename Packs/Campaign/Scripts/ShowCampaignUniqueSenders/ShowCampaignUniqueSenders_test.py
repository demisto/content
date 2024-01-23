import pytest
from ShowCampaignUniqueSenders import *
import demistomock as demisto


@pytest.fixture()
def mock_demisto(mocker):
    mocker.patch.object(demisto, 'incidents', return_value=[{'id': '1'}])
    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Contents': {'context': {'EmailCampaign': {'incidents': [
        {'emailfrom': 'test@example.com'},
        {'emailfrom': 'test2@example.com'}]}}}}])
    mocker.patch.object(demisto, 'results')
    return demisto


def test_happy_path(mock_demisto):
    """
    Given the executeCommand and incidents commands return valid data
    When ShowCampaignUniqueSenders is executed
    Then demisto.results is called with the correct unique senders count
    """
    main()

    demisto.results.assert_called_with({
        'ContentsFormat': EntryFormat.HTML,
        'Type': EntryType.NOTE,
        'Contents': "<div style='font-size:17px; text-align:center; "
        "padding-top: 20px;'> Unique Senders <div style='font-size:32px;'> <div> 2 </div></div>"
    })


def test_no_campaign_data(mock_demisto):
    """
    Given the executeCommand returns empty campaign incidents
    When ShowCampaignUniqueSenders is executed
    Then demisto.results is called with 0 senders message
    """
    mock_demisto.executeCommand.return_value = [{'Contents': {'context': {'EmailCampaign': {'incidents': []}}}}]

    main()

    demisto.results.assert_called_with({
        'ContentsFormat': EntryFormat.HTML,
        'Type': EntryType.NOTE,
        'Contents': "<div style='font-size:17px; text-align:center; "
        "padding-top: 20px;'> Unique Senders <div style='font-size:32px;'> <div> 0 </div></div>"
    })
