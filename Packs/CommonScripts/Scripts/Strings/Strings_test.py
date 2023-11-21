from Strings import *


def test_strings(mocker):
    mocker.patch.object(demisto, 'executeCommand',
                        return_value=[{'path': './test_data/text_file.txt', 'name': 'text_file.txt', 'Type': ''}])
    mocker.patch.object(demisto, 'get', return_value='./test_data/text_file.txt')
    entry = strings({'chars': 4, 'size': 1024, 'entry': '123'})
    assert entry == 'abcabc'


def test_strings_no_string(mocker):
    mocker.patch.object(demisto, 'executeCommand',
                        return_value=[{'path': './test_data/no_text_file.txt', 'name': 'text_file.txt', 'Type': ''}])
    mocker.patch.object(demisto, 'get', return_value='./test_data/no_text_file.txt')
    entry = strings({'chars': 4, 'size': 1024, 'entry': '123'})
    assert entry == 'No strings were found.'


def test_strings_small_buff(mocker):
    mocker.patch.object(demisto, 'executeCommand',
                        return_value=[{'path': './test_data/text_file.txt', 'name': 'text_file.txt', 'Type': ''}])
    mocker.patch.object(demisto, 'get', return_value='./test_data/text_file.txt')
    entry = strings({'chars': 1, 'size': 1024, 'entry': '123'})
    assert entry == 'abcabc'


def test_strings_regex(mocker):
    mocker.patch.object(demisto, 'executeCommand',
                        return_value=[{'path': './test_data/text_file.txt', 'name': 'text_file.txt', 'Type': ''}])
    mocker.patch.object(demisto, 'get', return_value='./test_data/text_file.txt')
    entry = strings({'chars': 1, 'size': 1024, 'entry': '123', 'filter': '.*'})
    assert entry == 'abcabc'


def test_pdf_file(mocker):
    mocker.patch.object(demisto, 'executeCommand',
                        return_value=[{'path': './test_data/pdf_file.pdf', 'name': 'pdf_file.pdf', 'Type': ''}])
    mocker.patch.object(demisto, 'get', return_value='./test_data/pdf_file.pdf')
    entry = strings({'chars': 1, 'size': 1024, 'entry': '123', 'filter': '.*'})
    assert entry != ''
