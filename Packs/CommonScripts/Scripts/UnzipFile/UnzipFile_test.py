from tempfile import mkdtemp
from UnzipFile import *
import os
import pytest


data_test_unzip_no_password = ['testZip.yml', 'ScanSummary.txt', 'item.png']


@pytest.mark.parametrize('file_name', data_test_unzip_no_password)
def test_unzip_no_password(file_name):
    """
    Given
    - valid zip file - no password required
    - empty folder _dir
    When
    - run extract on that zip file and export the internal files to _dir
    Then
    - ensure zip file content have be saved at _dir directory with the original filename
    - ensure that the saved file has expected content
    """
    # Given
    # - valid zip file - no password required
    main_dir = '/'.join(__file__.split('/')[0:-1])
    expected_file_unzipped = os.path.join(main_dir + '/data_test', file_name)
    zipped_file_path = expected_file_unzipped + '.zip'
    # - empty folder _dir
    _dir = mkdtemp()
    # When
    # - run extract on that zip file and export the internal files to _dir
    extract(zipped_file_path, _dir)
    # Then
    # - ensure zip file content have been saved at _dir directory with the original filename
    with open(_dir + '/' + file_name, 'rb') as f:
        actual_file_data = f.read()
    with open(expected_file_unzipped, 'rb') as f:
        expected_data = f.read()
    shutil.rmtree(_dir)
    # - ensure that the saved file has expected content data
    assert expected_data == actual_file_data, 'failed extracting ' + zipped_file_path


data_test_unzip_with_password = [
    ('fix_unzip.png', 'demisto'),
]


@pytest.mark.parametrize('file_name, password', data_test_unzip_with_password)
def test_unzip_with_password(file_name, password):
    """
    Given
    - valid zip file - with password required
    - empty folder _dir
    When
    - run extract on that zip file and export the internal files to _dir
    Then
    - ensure zip file content have be saved at _dir directory with the original filename
    - ensure that the saved file has expected content
    """
    # Given
    # - valid zip file - no password required
    main_dir = '/'.join(__file__.split('/')[0:-1])
    expected_file_unzipped = os.path.join(main_dir + '/data_test', file_name)
    zipped_file_path = expected_file_unzipped + '.zip'
    # - empty folder _dir
    _dir = mkdtemp()
    # When
    # - run extract on that zip file and export the internal files to _dir
    extract(zipped_file_path, _dir, password)
    # Then
    # - ensure zip file content have been saved at _dir directory with the original filename
    with open(_dir + '/' + file_name, 'rb') as f:
        actual_file_data = f.read()
    with open(expected_file_unzipped, 'rb') as f:
        expected_data = f.read()
    shutil.rmtree(_dir)
    # - ensure that the saved file has expected content data
    assert expected_data == actual_file_data,\
        'failed unzipping file: ' + zipped_file_path + ' with password: ' + password
