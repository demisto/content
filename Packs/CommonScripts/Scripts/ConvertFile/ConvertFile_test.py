import subprocess
from ConvertFile import main, find_zombie_processes
import demistomock as demisto
from CommonServerPython import entryTypes
import logging
import pytest
import glob
import os

RETURN_ERROR_TARGET = 'ConvertFile.return_error'


@pytest.fixture(autouse=True)
def set_logging(caplog):
    """set logging to DEBUG for better understanding when the tests fails
    """
    caplog.set_level(logging.DEBUG)  # easier to debug if the test fails


# these tests use soffice. they will probably fail if running within an editor.
@pytest.mark.parametrize('file', ['MS-DOCX-190319.docx', 'financial-sample.xslx'])  # disable-secrets-detection
def test_convert_to_pdf(mocker, file):
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


def test_convert_to_html(mocker):
    file = 'MS-DOCX-190319.docx'  # disable-secrets-detection
    mocker.patch.object(demisto, 'args', return_value={'entry_id': 'test', 'format': 'html', 'all_files': 'yes'})
    ext = os.path.splitext(file)[1]
    mocker.patch.object(demisto, 'getFilePath', return_value={"path": "test_data/" + file, 'name': 'test' + ext})
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['entry_id'] == 'test'
    main()
    assert demisto.results.call_count > 10  # we have also a bunch of images
    # call_args_list holds all calls as a tuple (args list, kwargs). we only need the first one
    # we check if we have an html file
    results = [x[0] for x in demisto.results.call_args_list if x[0][0]['File'].endswith('.html')][0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['file']
    assert results[0]['File'] == 'test.html'
    glob_list = glob.glob('./*' + results[0]['FileID'])
    logging.getLogger().info(f'glob list for results: {results[0]}. list: {glob_list}')
    assert glob_list
    with open(glob_list[0]) as f:
        contents = f.read()
        assert 'Extensions to the Office Open XML' in contents
    # assert the next result is an image
    results = [x[0] for x in demisto.results.call_args_list if x[0][0]['File'].endswith('.png')][0]
    assert results[0]['Type'] == entryTypes['file']
    assert results[0]['File'].startswith('test_html_')
    assert glob.glob('./*' + results[0]['FileID'])


def test_convert_pdf_to_html(mocker):
    file = 'text-only.pdf'
    mocker.patch.object(demisto, 'args', return_value={'entry_id': 'test', 'format': 'html', 'all_files': 'yes'})
    ext = os.path.splitext(file)[1]
    mocker.patch.object(demisto, 'getFilePath', return_value={"path": "test_data/" + file, 'name': 'test' + ext})
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['entry_id'] == 'test'
    main()
    assert demisto.results.call_count == 1
    results = [x[0] for x in demisto.results.call_args_list if x[0][0]['File'].endswith('.html')][0]
    assert results[0]['Type'] == entryTypes['file']
    assert results[0]['File'] == 'test.html'
    glob_list = glob.glob('./*' + results[0]['FileID'])
    logging.getLogger().info(f'glob list for results: {results[0]}. list: {glob_list}')
    assert glob_list
    # check no defunct processed
    zombies, output = find_zombie_processes()
    assert not zombies


def test_convert_failure(mocker):
    # test with BAD format to see that we fail
    file = 'MS-DOCX-190319.docx'  # disable-secrets-detection
    mocker.patch.object(demisto, 'args', return_value={'entry_id': 'test', 'format': 'BAD', 'all_files': 'yes'})
    ext = os.path.splitext(file)[1]
    mocker.patch.object(demisto, 'getFilePath', return_value={"path": "test_data/" + file, 'name': 'test' + ext})
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    # validate our mocks are good
    assert demisto.args()['entry_id'] == 'test'
    main()
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert 'BAD' in err_msg
    assert 'Error: no export filter' in err_msg


def test_zombie_prcesses(mocker):
    ps_output = '''   PID  PPID S CMD
    1     0 S python /tmp/pyrunner/_script_docker_python_loop.py
   39     1 Z [soffice.bin] <defunct>
   55     1 Z [gpgconf] <defunct>
   57     1 Z [gpgconf] <defunct>
   59     1 Z [gpg] <defunct>
   61     1 Z [gpgsm] <defunct>
   63     1 Z [gpgconf] <defunct>
   98     1 Z [gpgconf] <defunct>
  100     1 Z [gpgconf] <defunct>
  102     1 Z [gpg] <defunct>
'''
    mocker.patch.object(subprocess, 'check_output', return_value=ps_output)
    mocker.patch.object(os, 'getpid', return_value=1)
    zombies, output = find_zombie_processes()
    assert len(zombies) == 9
    assert output == ps_output
