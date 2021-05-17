import demistomock as demisto
from ChangeContext import replace_context
from CommonServerPython import *


def test_capitalize_context_list_inplace(mocker):
    context = [{'key': 'val', 'key2': 'val2'},
               {'list2key1': 1, 'list2key2': 2}]
    args = {'input': context, 'capitalize': 'True', 'inplace': 'True', 'output_key': 'Demisto.Test'}
    xcommand_tracker = mocker.patch.object(demisto, 'executeCommand')
    replace_context(args)
    assert xcommand_tracker.call_args[0][1] == {'key': 'Demisto.Test',
                                                'value': [{'Key': 'val', 'Key2': 'val2'},
                                                          {'List2Key1': 1, 'List2Key2': 2}]
                                                }


def test_capitalize_context_list_not_inplace(mocker):
    context = [{'key': 'val', 'key2': 'val2'},
               {'list2key1': 1, 'list2key2': 2}]
    args = {'input': context, 'output_key': 'Demisto.Test', 'capitalize': 'True', 'inplace': 'False'}
    _, ec, _ = replace_context(args)

    assert ec == {'Demisto.Test': [{'Key': 'val', 'Key2': 'val2'}, {'List2Key1': 1, 'List2Key2': 2}]}


def test_change_context_path_inplace(mocker):
    context = [{'key': 'val', 'key2': 'val2'},
               {'list2key1': 1, 'list2key2': 2}]
    args = {'input': context, 'output_key': 'Demisto.Test', 'capitalize': 'True', 'inplace': 'True',
            'replace_dict': json.dumps({'key': 'newKey', 'list2key2': 'newListKey'})}
    mocker.patch.object(demisto, 'executeCommand')
    replace_context(args)
    assert demisto.executeCommand.call_args[0][1] == {'key': 'Demisto.Test',
                                                      'value': [{'newKey': 'val', 'Key2': 'val2'},
                                                                {'List2Key1': 1, 'newListKey': 2}]
                                                      }


def test_replace_dict_not_inplace(mocker):
    context = [{'key': 'val', 'key2': 'val2'},
               {'list2key1': 1, 'list2key2': 2}]
    args = {'input': context, 'output_key': 'Demisto.Test', 'capitalize': 'False', 'inplace': 'False',
            'replace_dict': json.dumps({'key': 'newKey', 'list2key2': 'newListKey'})}
    _, ec, _ = replace_context(args)

    assert ec == {'Demisto.Test': [{'newKey': 'val', 'key2': 'val2'}, {'list2key1': 1, 'newListKey': 2}]}
