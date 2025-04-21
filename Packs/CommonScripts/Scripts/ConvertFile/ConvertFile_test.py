import glob
import logging
import os
import subprocess

import demistomock as demisto
import pytest
from CommonServerPython import entryTypes
from ConvertFile import find_zombie_processes, main, make_sha, CommandResults

RETURN_ERROR_TARGET = "ConvertFile.return_error"


@pytest.fixture(autouse=True)
def set_logging(caplog):
    """set logging to DEBUG for better understanding when the tests fails"""
    caplog.set_level(logging.DEBUG)  # easier to debug if the test fails


@pytest.mark.parametrize("file", ["test1"])
def test_convert_to_pdf(mocker,file):
    mocker.patch.object(demisto, "args", return_value={"entry_id": "test"})
    ext = os.path.splitext(file)[1]
    mocker.patch.object(demisto, "getFilePath", return_value={"path": "test_data/" + file, "name": "test" + ext})
    mocker.patch.object(demisto, "results")
    mocker.patch("ConvertFile.make_sha", return_value='mocked_sha')
    mocker.patch.object(subprocess, "check_output", return_value=b'mocked_output')
    mocker.patch.object(glob, "glob", return_value=['file1'])
    mocker.patch('ConvertFile.shutil.copy')
    mocker.patch('ConvertFile.os.path.basename', return_value='test1_name')
    main()
    results1 = demisto.results.call_args_list[0][0]
    results2 = demisto.results.call_args_list[1][0]
    assert demisto.results.call_count == 2
    assert results1[0]["Type"] == entryTypes["file"]
    assert results1[0]["File"] == "test"
    assert 'ERROR' not in str(results1)
    assert results2[0]["Type"] == entryTypes["note"]
    assert results2[0]["EntryContext"]['ConvertedFile']['FileSHA1'] == 'mocked_sha'
    assert results2[0]["EntryContext"]['ConvertedFile']['Convertable'] == 'yes'


def test_convert_failure(mocker):
    # test with BAD format to see that we do not fail and that outputs contain the ERROR field
    file = "MS-DOCX-190319.docx"  # disable-secrets-detection
    mocker.patch.object(demisto, "args", return_value={"entry_id": "test", "format": "BAD", "all_files": "yes"})
    ext = os.path.splitext(file)[1]
    mocker.patch.object(demisto, "getFilePath", return_value={"path": "test_data/" + file, "name": "test" + ext})
    mocker.patch.object(demisto, "results")
    # validate our mocks are good
    assert demisto.args()["entry_id"] == "test"
    main()
    result = [x[0] for x in demisto.results.call_args_list][0]
    assert 'ERROR' in str(result)


def test_zombie_prcesses(mocker):
    ps_output = """   PID  PPID S CMD
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
"""
    mocker.patch.object(subprocess, "check_output", return_value=ps_output)
    mocker.patch.object(os, "getpid", return_value=1)
    zombies, output = find_zombie_processes()
    assert len(zombies) == 9
    assert output == ps_output
