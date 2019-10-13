from ConvertFile import main
import demistomock as demisto
from CommonServerPython import entryTypes
import logging
import pytest
import glob
import os


# set logging to DEBUG for better understanding when the tests fails
@pytest.fixture(autouse=True)
def set_logging(caplog):
    caplog.set_level(logging.DEBUG)  # easier to debug if the test fails


# these tests use soffice. they will probably fail if running within an editor.
@pytest.mark.parametrize('file', ['MS-DOCX-190319.docx', 'financial-sample.xslx'])
def test_conver_to_pdf(mocker, file):
    mocker.patch.object(demisto, 'args', return_value={'entry_id': 'test'})
    ext = os.path.splitext(file)[1]
    mocker.patch.object(demisto, 'getFilePath', return_value={"path": "test_data/" + file, 'name': 'test' + ext})
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['entry_id'] == 'test'
    main()
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert demisto.results.call_count == 1
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['file']
    assert results[0]['File'] == 'test.pdf'
    assert glob.glob('./*' + results[0]['FileID'])


def test_conver_to_html(mocker):
    file = 'MS-DOCX-190319.docx'
    mocker.patch.object(demisto, 'args', return_value={'entry_id': 'test', 'format': 'html', 'all_files': 'yes'})
    ext = os.path.splitext(file)[1]
    mocker.patch.object(demisto, 'getFilePath', return_value={"path": "test_data/" + file, 'name': 'test' + ext})
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['entry_id'] == 'test'
    main()
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert demisto.results.call_count > 10  # we have also a bunch of images
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['file']
    assert results[0]['File'] == 'test.html'
    res_file = glob.glob('./*' + results[0]['FileID'])
    assert res_file
    with open(res_file[0], "r") as f:
        contents = f.read()
        assert 'Extensions to the Office Open XML' in contents
    # assert the next result is an image
    results = demisto.results.call_args_list[1][0]
    assert results[0]['Type'] == entryTypes['file']
    assert results[0]['File'].endswith('.png')
    assert glob.glob('./*' + results[0]['FileID'])
