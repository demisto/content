from ImageOCR import list_languages, extract_text, main
import pytest
import demistomock as demisto
from CommonServerPython import entryTypes


RETURN_ERROR_TARGET = 'ImageOCR.return_error'


def test_list_languages():
    res = list_languages()
    assert len(res) >= 16
    assert "eng" in res


@pytest.mark.parametrize('image,expected_text,langs', [
                         ('irs.png', 'Internal Revenue Service', None),
                         ('bomb.jpg', 'You must transfer bitcoins', None),
                         ('noisy1.jpg', 'Tesseract OCR', None),
                         ('noisy.png', 'Tesseract Will', None),
                         ('cnbc.gif', 'Goldman Sachs', None),
                         ('hebrew.tiff', 'ביטקוין', ['eng', 'heb'])
                        ])  # noqa: E124
def test_extract_text(image, expected_text, langs):
    res = extract_text('test_data/' + image, langs)
    assert expected_text in res


def test_extract_text_command(mocker):
    mocker.patch.object(demisto, 'args', return_value={'entryid': 'test'})
    mocker.patch.object(demisto, 'getFilePath', return_value={"path": "test_data/irs.png"})
    mocker.patch.object(demisto, 'command', return_value='image-ocr-extract-text')
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['entryid'] == 'test'
    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert 'Internal Revenue Service' in results[0]['HumanReadable']
    assert 'Internal Revenue Service' in results[0]["EntryContext"]["File(val.EntryID == obj.EntryID)"]['Text']


# test with bad langs params
def test_extract_text_command_bad(mocker):
    mocker.patch.object(demisto, 'args', return_value={'entryid': 'test', 'langs': 'thisis,bad'})
    mocker.patch.object(demisto, 'getFilePath', return_value={"path": "test_data/irs.png"})
    mocker.patch.object(demisto, 'command', return_value='image-ocr-extract-text')
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    # validate our mocks are good
    assert demisto.args()['entryid'] == 'test'
    main()
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert 'Error:' in err_msg
    assert 'bad' in err_msg
