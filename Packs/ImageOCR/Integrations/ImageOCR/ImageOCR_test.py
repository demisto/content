import pytest

import demistomock as demisto
from CommonServerPython import CommandResults, EntryType
from ImageOCR import (
    CORRUPTED_ERR,
    list_languages_command,
    extract_text,
    extract_text_command,
    run_test_module,
    main,
)

RETURN_ERROR_TARGET = 'ImageOCR.return_error'


def test_list_languages_command():
    """
    When:
     - Running the list_languages function

    Then:
     - Ensure the supported languages in the Docker image are present.
    """
    cmd_res = list_languages_command()
    res = cmd_res.raw_response
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


def test_extract_text_verbose_params():
    """
    Given:
     - An image with text

    When:
     - Running the extract_text command

    Then:
     - Validate the result with and without the verbose parameter.
    """
    path = 'test_data/bomb.jpg'
    res_verbose = extract_text(path, verbose=True)
    # Some of the verbose data.
    assert "tesseract" in res_verbose
    # Without verbose.
    res_without_verbose = extract_text(path, verbose=False)
    assert "tesseract" not in res_without_verbose


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
    assert results['Type'] == EntryType.NOTE
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


@pytest.mark.parametrize('skip_corrupted', [True, False])
def test_extract_text_command_corrupted_image(mocker, skip_corrupted: bool):
    """
    Note: if this unittests fails after a docker update, it means tesseract improved corrupted images handling
    Given:
     - A corrupted image
     - The skip_corrupted boolean indicating whether or not to raise an error
    When:
     - Running the image-ocr-extract-text command
    Then:
     - Ensure an error message is returned if skip_corrupted is false, or a warning otherwise.
    """
    mocker.patch.object(demisto, 'getFilePath', return_value={"path": "test_data/corrupted.png"})
    results, errors = extract_text_command(
        args={'entryid': 'test'},
        instance_languages=['eng'],
        skip_corrupted=skip_corrupted,
    )
    assert len(results + errors) == 1
    if skip_corrupted:
        assert isinstance(results[0], CommandResults)
        assert results[0].entry_type == EntryType.WARNING
    else:
        assert CORRUPTED_ERR in errors[0]


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
