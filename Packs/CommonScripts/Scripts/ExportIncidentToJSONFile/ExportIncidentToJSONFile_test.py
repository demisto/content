import demistomock as demisto
from ExportIncidentToJSONFile import main


def test_main(mocker):

    args = {'filename': 'incident', 'type': 'Incident'}
    mocker.patch.object(demisto, 'executeCommand')
    res = main(args)
    assert res.get('File') == 'incident.json'
    assert res.get('Type') == 3
