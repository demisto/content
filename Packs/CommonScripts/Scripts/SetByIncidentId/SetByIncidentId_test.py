import demistomock as demisto
from SetByIncidentId import main


def test_set_by_incident_id(mocker):
    """
    Given:
        - ID (1) of incident to update
        - Key (Key) to update
        - Value (Value) to update
        - Argument append set to false
        - Argument errorUnfinished set to false

    When:
        - Running SetByIncidentId

    Then:
        - Ensure executeCommand is called with expected args
    """
    mocker.patch.object(demisto, 'args', return_value={
        'id': '1',
        'key': 'Key',
        'value': 'Value',
        'append': 'false',
        'errorUnfinished': 'false',
    })
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'executeCommand')
    main()
    demisto.executeCommand.assert_called_with(
        'executeCommandAt',
        {
            'arguments': {'append': 'false', 'key': 'Key', 'value': 'Value'},
            'command': 'Set',
            'incidents': '1',
        }
    )
