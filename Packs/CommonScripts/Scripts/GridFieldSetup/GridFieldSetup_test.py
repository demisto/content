from GridFieldSetup import *


def test_strings(mocker):
    # mocker.patch.object(demisto, 'executeCommand',
    #                     return_value=[{'path': './test_data/text_file.txt', 'name': 'text_file.txt', 'Type': ''}])
    # mocker.patch.object(demisto, 'get', return_value='./test_data/text_file.txt')
    IPs = ['1.1.1.1','2.2.2.2']
    entry = GridFieldSetup({'val1': IPs, 'keys': 'IP,SRC', 'val2': 'AWS', 'context_path': 'temp'})
    assert entry == [{'IP': '1.1.1.1','SRC': 'AWS'},{'IP': '2.2.2.2','SRC': 'AWS'}]