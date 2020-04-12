import demistomock as demisto
import CommonServerPython as csp
import json
import importlib


def test_capitalize_context_list_inplace(mocker):
    context = {'key1': 1,
               'high': {
                   'middle': [
                       {'key': 'val',
                        'key2': 'val2'},
                       {'list2key1': 1,
                        'list2key2': 2}
                   ]
               }
               }
    mocker.patch.object(demisto, 'context', return_value=context)
    mocker.patch.object(demisto, 'args', return_value={'key': 'high.middle', 'capitalize': 'True', 'inplace': 'True'})
    xcommand_tracker = mocker.patch.object(demisto, 'executeCommand')
    import ChangeContext
    importlib.reload(ChangeContext)  # Making sure that the script is ran with the above mock
    assert xcommand_tracker.call_args[0][1] == {'key': 'high.middle',
                                                'value': [{'Key': 'val', 'Key2': 'val2'},
                                                          {'List2Key1': 1, 'List2Key2': 2}]
                                                }


def test_capitalize_context_list_not_inplace(mocker):
    context = {'key1': 1,
               'high': {
                   'middle': [
                       {'key': 'val',
                        'key2': 'val2'},
                       {'list2key1': 1,
                        'list2key2': 2}
                   ]
               }
               }
    mocker.patch.object(demisto, 'context', return_value=context)
    mocker.patch.object(demisto, 'args', return_value={'key': 'high.middle', 'capitalize': 'True', 'inplace': 'False'})
    return_outputs_tracker = mocker.patch.object(csp, 'return_outputs')
    import ChangeContext
    importlib.reload(ChangeContext)  # Making sure that the script is ran with the above mock
    assert return_outputs_tracker.call_args[0][1] == {'high.middle': [{'Key': 'val', 'Key2': 'val2'},
                                                                      {'List2Key1': 1, 'List2Key2': 2}]
                                                      }


def test_change_context_path_inplace(mocker):
    context = {'key1': 1,
               'high': {
                   'middle': [
                       {'key': 'val',
                        'key2': 'val2'},
                       {'list2key1': 1,
                        'list2key2': 2}
                   ]
               }
               }
    mocker.patch.object(demisto, 'context', return_value=context)
    mocker.patch.object(demisto, 'args', return_value={'key': 'high.middle', 'capitalize': 'True', 'inplace': 'True',
                                                       'replace_dict': json.dumps({'key': 'newKey',
                                                                                   'list2key2': 'newListKey'})})
    mocker.patch.object(demisto, 'executeCommand')
    import ChangeContext
    importlib.reload(ChangeContext)
    assert demisto.executeCommand.call_args[0][1] == {'key': 'high.middle',
                                                      'value': [{'newKey': 'val', 'Key2': 'val2'},
                                                                {'List2Key1': 1, 'newListKey': 2}]
                                                      }
