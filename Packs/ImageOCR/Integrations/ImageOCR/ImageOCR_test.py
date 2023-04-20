import pytest

import demistomock as demisto
from CommonServerPython import entryTypes
from ImageOCR import list_languages, extract_text, run_test_module, main

RETURN_ERROR_TARGET = 'ImageOCR.return_error'


def test_list_languages():
    """
    When:
     - Running the list_languages function

    Then:
     - Ensure the supported languages in the Docker image are present.
    """
    res = list_languages()
    assert len(res) >= 16
    assert "eng" in res  # english
    assert "pol" in res  # polish


@pytest.mark.parametrize('image,expected_text,langs', [
    ('irs.png', 'Internal Revenue Service', None),
    ('bomb.jpg', 'You must transfer bitcoins', None),
    ('noisy1.jpg', 'Tesseract OCR', None),
    ('noisy.png', 'Tesseract Will', None),
    ('cnbc.gif', 'MARKETS', None),
    ('hebrew.tiff', 'ביטקוין', ['eng', 'heb'])
])  # noqa: E124
def test_extract_text(image, expected_text, langs):
    """
    Given:
     - An image with text

    When:
     - Running the extract_text command

    Then:
     - The expected text is extracted
    """
    res = extract_text('test_data/' + image, langs)
    assert expected_text in res


def test_extract_text_command(mocker):
    """
    Given:
     - An image with text

    When:
     - Running the image-ocr-extract-text command

    Then:
     - The expected text is extracted
     - The Human Readable and context are stored with the proper values
    """
    mocker.patch.object(demisto, 'args', return_value={'entryid': 'test'})
    mocker.patch.object(demisto, 'getFilePath', return_value={"path": "test_data/irs.png"})
    mocker.patch.object(demisto, 'command', return_value='image-ocr-extract-text')
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['entryid'] == 'test'
    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0][0]
    assert results['Type'] == entryTypes['note']
    assert 'Internal Revenue Service' in results['HumanReadable']
    assert 'Internal Revenue Service' in \
           results['EntryContext']['File(val.EntryID && val.EntryID == obj.EntryID)']['Text']


def test_extract_text_command_bad(mocker):
    """
    Given:
     - An image with text
     - a non supported language

    When:
     - Running the image-ocr-extract-text command

    Then:
     - A proper error is raised
    """
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


def test_run_test_module():
    """
    Given:
     - A param with the supported swedish language

    When:
     - Running the test-module command

    Then:
     - An ok is returned
    """
    res = run_test_module(['swe'])
    assert res == 'ok'


def test_run_test_module_bad(mocker):
    """
    Given:
     - A param with the non supported valyrian language

    When:
     - Running the test-module command

    Then:
     - A proper error is presented
    """
    mocker.patch.object(demisto, 'params', return_value={'langs': 'valyrian'})
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results')
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    # validate our mocks are good
    assert demisto.command() == 'test-module'
    main()
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert 'Unsupported language configured: valyrian' in err_msg
