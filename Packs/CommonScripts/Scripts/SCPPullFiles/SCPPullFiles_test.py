
from SCPPullFiles import *


def test_scp_pull_files(mocker):
    with open('./test_data/json_file.json', 'r') as file:
        json_file = file.read()
        mocker.patch.object(demisto, 'get', return_value=json_file)
        mocker.patch.object(demisto, 'executeCommand', return_value=['copy-from response'])
        assert scp_pull_files({}) == ['copy-from response', 'copy-from response']


def test_scp_pull_files_error_in_file(mocker):
    with open('./test_data/not_dict_json_file.json', 'r') as file:
        txt_file = file.read()
        mocker.patch.object(demisto, 'get', return_value=txt_file)
        assert scp_pull_files({}) == {'Type': 4, 'ContentsFormat': 'text',
                                      'Contents': 'Wrong argument provided. Not a dict. Dump of args: {}'}
