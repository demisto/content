import json
from CommonServerPython import *
import DBotGroupXDRIncidents


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_DBotGroupXDRIncidents_scatter(mocker):
    """
    Given:
        - returnWidgetType - scatter and the rest of the arguments.
    When:
     - calling DBotGroupXDRIncidents
    Then:
     - Verify that in case 0 incidents fetched, the returned data object was set correctly to [].
    """
    mocker.patch.object(demisto, 'args', return_value={'returnWidgetType': 'scatter'})
    args = {
        'returnWidgetType': 'scatter',
        'incidentType': 'XDR incident',
        'limit': '500',
        'fromDate': '1 months ago',
        'searchQuery': 'searchQuery',
        'forceRetrain': 'False'
    }
    response = [{'ModuleName': 'CustomScripts',
                 'Brand': 'Scripts',
                 'Category': 'automation',
                 'ID': '',
                 'Version': 0,
                 'Type': 1,
                 'Contents': '- 0 incidents fetched with these exact match for the given dates. \n \n',
                 'HumanReadable': None,
                 'ImportantEntryContext': None,
                 'EntryContext': None,
                 'IgnoreAutoExtract': False,
                 'ReadableContentsFormat': '',
                 'ContentsFormat': 'text',
                 'File': '', 'FileID': '',
                 'FileMetadata': None,
                 'System': '',
                 'Note': False,
                 'Evidence': False,
                 'EvidenceID': '',
                 'Tags': None,
                 'Metadata': {},
                 'IndicatorTimeline': None,
                 'NextRun': '',
                 'Timeout': '',
                 'PollingCommand': '',
                 'PollingArgs': None,
                 'PollingItemsRemaining': 0,
                 'Relationships': None,
                 'APIExecutionMetrics': None}]
    mocker.patch.object(demisto, 'executeCommand', return_value=response)
    result = DBotGroupXDRIncidents.get_group_incidents(args)
    assert result.get('Contents', {}) == {'data': []}
    assert not result.get('EntryContext')


def test_DBotGroupXDRIncidents_incidents(mocker):
    """
    Given:
        - returnWidgetType - incidents and the rest of the arguments.
    When:
     - calling DBotGroupXDRIncidents
    Then:
     - Verify that Contents and EntryContext aren't empty and of type dict.
    """
    mocker.patch.object(demisto, 'args', return_value={'returnWidgetType': 'scatter'})
    args = {
        'returnWidgetType': 'incidents',
        'incidentType': 'XDR incident',
        'limit': '500',
        'fromDate': '1 months ago',
        'searchQuery': 'searchQuery',
        'forceRetrain': 'False'
    }
    response = [{'ModuleName': 'CustomScripts', 'Brand': 'Scripts', 'Category': 'automation', 'ID': '', 'Version': 0, 'Type': 1,
                 'Contents': {'data': [{'color': '0048BA', 'data': [7], 'dataType': 'incident',
                                        'incidents': '[{"incident1data", "incident2data"}]'}]},
                 'EntryContext': {'DBotTrainClustering': '{info}'}}]
    mocker.patch.object(demisto, 'executeCommand', return_value=response)
    result = DBotGroupXDRIncidents.get_group_incidents(args)
    assert isinstance(result[0]['Contents'], dict)
    assert isinstance(result[0]['EntryContext'], dict)
