import shutil

from UnzipFile import *
import os
import pytest


data_test_extract = [
    ('testZip.yml', None),
    ('ScanSummary.txt', None),
    ('item.png', None),
    ('fix_unzip.png', 'demisto'),
]


@pytest.mark.parametrize('file_name, password', data_test_extract)
def test_extract(file_name, password):
    """
    :param file_name: file name in dir Scripts/UnzipFile/data_test/
    :param password: if the is encrypted
    """
    # crate the full path to Scripts/UnzipFile/data_test/
    main_dir = '/'.join(__file__.split('/')[0:-1])
    path = os.path.join(main_dir + '/data_test', file_name)

    error_message = 'Failed extracting ' + path
    if password:
        error_message += ' with password: ' + password

    # crate a temp directory for extracting the files
    # extracting file
    _dir = mkdtemp()
    extract(path + '.zip', _dir, password)

    # get the extracted file content from temp dir
    with open(_dir + '/' + file_name, 'rb') as f:
        extract_file = f.read()

    # get the original file content from Scripts/UnzipFile/data_test/
    with open(path, 'rb') as f:
        _file = f.read()

    shutil.rmtree(_dir)
    assert _file == extract_file, error_message
