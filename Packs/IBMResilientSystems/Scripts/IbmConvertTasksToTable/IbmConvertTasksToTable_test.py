from IbmConvertTasksToTable import convert_to_table
import demistomock as demisto
import pytest


def test_empty_incident(mocker):
    import re
    mocker.patch.object(demisto, 'incident', return_value={})
    with pytest.raises(ValueError, match=re.escape("Error - demisto.incident() expected to return current incident from context "
                                                   "but returned None")):
        convert_to_table()


def test_no_custom_fields(mocker):
    mocker.patch.object(demisto, 'incident', return_value={'id': '1'})
    result = convert_to_table()
    assert result.readable_output == 'No tasks were found for this incident'


def test_empty_tasks(mocker):
    mocker.patch.object(demisto, 'incident', return_value={'CustomFields': {'ibmsecurityqradarsoartasks': []}})
    result = convert_to_table()
    assert result.readable_output == 'No tasks were found for this incident'


def test_multiple_tasks(mocker):
    import json
    task_data1 = json.dumps({
        'Phase': 'Initial',
        'ID': '1',
        'Name': 'Analyze Log',
        'Status': 'Open',
        'Instructions': 'Review logs',
        'DueDate': '2023-05-01',
        'Owner': 'No Body',
        'Required': 'Yes'
    })
    task_data2 = json.dumps({
        'Phase': 'Custom',
        'ID': '2',
        'Name': 'Isolate System',
        'Status': 'Completed',
        'Instructions': 'Isolate affected system',
        'DueDate': '2023-05-02',
        'Owner': 'No Body',
        'Required': 'No'
    })
    mocker.patch.object(demisto, 'incident', return_value={
        'CustomFields': {
            'ibmsecurityqradarsoartasks': [task_data1, task_data2]
        }
    })
    result = convert_to_table()
    assert '| Initial | 1 | Analyze Log | Open | Review logs | 2023-05-01 | No Body | Yes |' in result.readable_output
    assert ('| Custom | 2 | Isolate System | Completed | Isolate affected system | 2023-05-02 | No Body | No |'
            in result.readable_output)
