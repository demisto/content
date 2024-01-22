import ShowNumberOfCampaignIncidents
import demistomock as demisto
from CommonServerPython import EntryType
import pytest


@pytest.fixture()
def mock_demisto(mocker):
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(demisto, 'incidents', return_value=[{'id': '1'}])


def test_main_with_campaign(mock_demisto, mocker):
    """
    Given the incident contains an email campaign 
    When main is called
    Then the number of campaign incidents is displayed
    """
    demisto.executeCommand.return_value = [{'Contents': {'context': {'EmailCampaign': {'incidents': [1, 2, 3]}}}}]

    ShowNumberOfCampaignIncidents.main()

    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert results['Type'] == EntryType.NOTE
    assert '3' in results['Contents']
