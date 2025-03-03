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
    # Creation of file object
    zipped_file_object = {
        'name': 'testFile',
        'path': zipped_file_path
    }
    # - empty folder _di
    _dir = mkdtemp()
    # When
    # - run extract on that zip file and export the internal files to _dir
    extract(zipped_file_object, _dir)
    # Then
    # - ensure zip file content have been saved at _dir directory with the original filename
    with open(_dir + '/' + file_name, 'rb') as f:
        actual_file_data = f.read()
    with open(expected_file_unzipped, 'rb') as f:
        expected_data = f.read()
    shutil.rmtree(_dir)
    # - ensure that the saved file has expected content data
    assert expected_data == actual_file_data, 'failed extracting ' + zipped_file_path


@pytest.mark.parametrize('zip_tool', ('7z', 'zipfile'))
def test_unzip_with_password(zip_tool: str):
    """
    Given
    - valid zip file - with password required
    - empty folder _dir
    - the tool to extract files
    When
    - run extract on that zip file and export the internal files to _dir
    Then
    - ensure zip file content have be saved at _dir directory with the original filename
    - ensure that the saved file has expected content
    """
    # Given
    # - valid zip file - no password required
    file_name = 'fix_unzip.png'
    password = 'demisto'
    main_dir = '/'.join(__file__.split('/')[0:-1])
    expected_file_unzipped = os.path.join(main_dir + '/data_test', file_name)
    zipped_file_path = expected_file_unzipped + '.zip'
    # Creation of file object
    zipped_file_object = {
        'name': 'testFile',
        'path': zipped_file_path
    }
    # - empty folder _dir
    _dir = mkdtemp()
    # When
    # - run extract on that zip file and export the internal files to _dir
    extract(zipped_file_object, _dir, password=password, zip_tool=zip_tool)
    # Then
    # - ensure zip file content have been saved at _dir directory with the original filename
    with open(_dir + '/' + file_name, 'rb') as f:
        actual_file_data = f.read()
    with open(expected_file_unzipped, 'rb') as f:
        expected_data = f.read()
    shutil.rmtree(_dir)
    # - ensure that the saved file has expected content data
    assert expected_data == actual_file_data, \
        'failed unzipping file: ' + zipped_file_path + ' with password: ' + password


long_file_name = os.urandom(256)
data_test_unzip_long_file_name = ['long_filename_zip.zip']


@pytest.mark.parametrize('file_name', data_test_unzip_long_file_name)
def test_unzip_long_filename(file_name, mocker):
    """
    Given
    - valid zip file - includes a file with long filename
    - empty folder _dir
    When
    - run extract on that zip file and export the internal files to _dir
    Then
    - ensure zip file content have be saved at _dir directory with the new filename
    """
    import UnzipFile as unzip
    # Given
    # - valid zip file - includes a file with long filename
    main_dir = '/'.join(__file__.split('/')[0:-1])
    zip_file_path = os.path.join(main_dir + '/data_test', file_name)
    # Creation of file object
    zipped_file_object = {
        'name': 'testFile',
        'path': zip_file_path
    }
    # - empty folder _dir
    _dir = mkdtemp()
    # When
    # - run extract on that zip file and export the internal files to _dir
    mocker.patch.object(unzip, 'SLICE_FILENAME_SIZE_BYTES', return_value=100)
    extract(zipped_file_object, _dir, zip_tool='zipfile')
    # Then
    # - ensure zip file content have been saved at _dir directory with the new filename
    files_list = os.listdir(_dir)

    shutil.rmtree(_dir)
    assert files_list[0].endswith('_shortened_.rtf') is True


def test_unrar_no_password():
    """
    Given
    - valid rar file - no password required
    - empty folder _dir
    When
    - run extract on the rar file and export the internal files to _dir
    Then
    - ensure rar file content has been saved at _dir directory with the original filename
    - ensure that the saved file has expected content
    """
    file_name = 'Untitled_document.pdf'
    main_dir = '/'.join(__file__.split('/')[0:-1])
    expected_file_unzipped = os.path.join(main_dir + '/data_test', file_name)
    zipped_file_path = expected_file_unzipped + '.rar'
    # Creation of file object
    zipped_file_object = {
        'name': 'Untitled_document.pdf.rar',
        'path': zipped_file_path
    }
    # - empty folder _di
    _dir = mkdtemp()
    # When
    # - run extract on that zip file and export the internal files to _dir
    extract(zipped_file_object, _dir)
    # Then
    # - ensure rar file content have been saved at _dir directory with the original filename
    with open(_dir + '/' + file_name, 'rb') as f:
        actual_file_data = f.read()
    with open(expected_file_unzipped, 'rb') as f:
        expected_data = f.read()
    shutil.rmtree(_dir)
    # - ensure that the saved file has expected content data
    assert expected_data == actual_file_data, 'failed extracting ' + zipped_file_path


def test_extract_tarfile():
    """
    Given
    - valid tar.gz file
    - empty folder _dir
    When
    - run extract on the tar file and export the internal files to _dir
    Then
    - ensure tar file content has been saved at _dir directory with the original filename
    - ensure that the saved file has expected content
    """
    file_name = 'test_file.txt'
    main_dir = '/'.join(__file__.split('/')[0:-1])
    expected_file_unzipped = os.path.join(main_dir + '/data_test', file_name)
    zipped_file_path = expected_file_unzipped + '.tar.gz'
    # Creation of file object
    zipped_file_object = {
        'name': 'test_file.tar.gz',
        'path': zipped_file_path
    }
    # - empty folder _di
    _dir = mkdtemp()
    # When
    # - run extract on that zip file and export the internal files to _dir
    extract(zipped_file_object, _dir)
    # Then
    # - ensure tar file content have been saved at _dir directory with the original filename
    with open(_dir + '/' + file_name, 'rb') as f:
        actual_file_data = f.read()
    with open(expected_file_unzipped, 'rb') as f:
        expected_data = f.read()
    shutil.rmtree(_dir)
    # - ensure that the saved file has expected content data
    assert expected_data == actual_file_data, 'failed extracting ' + zipped_file_path


ARGS_BOTH_PASSWORDS_IDENTICAL = {'password': 'aa', 'nonsensitive_password': 'aa'}
ARGS_BOTH_PASSWORDS_NOT_IDENTICAL = {'password': 'aa', 'nonsensitive_password': 'bb'}
ARGS_ONLY_PASSWORD = {'password': 'aa'}
ARGS_ONLY_NONSENSITIVE_PASSWORD = {'nonsensitive_password': 'aa'}


@pytest.mark.parametrize('args', [ARGS_BOTH_PASSWORDS_IDENTICAL, ARGS_ONLY_NONSENSITIVE_PASSWORD, ARGS_ONLY_PASSWORD])
def test_get_password_valid(args):
    """
    Given
    - arguments for the script
    When
    - running the script on a password locked file
    Then
    - ensure that only one of the arguments 'password' or 'nonsensitive_password' is given or if they are identical.
    """
    assert get_password(args) == 'aa'


def test_get_password_invalid():
    """
    Given
    - arguments for the script
    When
    - running the script on a password locked file
    Then
    - ensure that only one of the arguments 'password' or 'nonsensitive_password' is given or if they are identical.
    """
    with pytest.raises(ValueError) as e:
        get_password(ARGS_BOTH_PASSWORDS_NOT_IDENTICAL)
        if not e:
            raise AssertionError


def test_archive_with_slash_in_path():
    """
    Given
    - valid tar.gz file with slash in path
    - empty folder _dir
    When
    - run extract on the tar file and export the internal files to _dir
    Then
    - ensure no error was returned
    """
    zipped_file_object = {
        'name': 'Archive_with_slash_in_path.tar.gz',
        'path': 'data_test/Archive_with_slash_in_path.tar.gz'
    }
    # - empty folder _dir
    _dir = mkdtemp()
    # When
    # - run extract on that zip file and export the internal files to _dir
    excluded_dirs, excluded_files = extract(zipped_file_object, _dir)
    # Then
    assert excluded_dirs
