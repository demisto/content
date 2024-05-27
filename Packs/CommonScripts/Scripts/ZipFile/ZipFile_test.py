import os
import pytest
import pyzipper
from ZipFile import escape_illegal_characters_in_file_name, compress_multiple
import tempfile

ESCAPE_CHARACTERS_PACK = [
    ('/Users/user/Downloads/b/a/testingfile.txt', '-Users-user-Downloads-b-a-testingfile.txt'),
    ('/Users/user/Downloads/?///testingfile.txt', '-Users-user-Downloads-testingfile.txt'),
    ('/Users/user/Downloads/b/a/testingfile*.txt', '-Users-user-Downloads-b-a-testingfile-.txt'),
    ('abcde', 'abcde')
]


def unzip(zip_file_path: str, password: str = None):
    with tempfile.TemporaryDirectory() as unzip_dir, pyzipper.AESZipFile(zip_file_path) as zf:
        zf.pwd = bytes(password, 'utf-8') if password else None
        zf.extractall(path=unzip_dir)


@pytest.mark.parametrize(('input_name', 'output_name'), ESCAPE_CHARACTERS_PACK)
def test_escape_characters_in_file_name(input_name, output_name):
    assert escape_illegal_characters_in_file_name(input_name) == output_name


def test_compress_multiple_with_password():
    """
    Given:
        - A directory with files to zip.
    When:
        - Calling the function compress_multiple.
    Then:
        - The function should not raise an exception.
    """
    test_data_dir = './test_data'
    file_names = [os.path.join(test_data_dir, f) for f in os.listdir(test_data_dir) if
                  os.path.isfile(os.path.join(test_data_dir, f))]
    with tempfile.NamedTemporaryFile(suffix='.zip') as tmp_zip:
        zip_name = tmp_zip.name
        compress_multiple(
            file_names=file_names,
            zip_name=zip_name,
            password='123'
        )


def test_zip_and_unzip_with_password():
    """
    Given:
        - A directory with files to zip.
    When:
        - Calling the function compress_multiple with a password.
    Then:
        - We can unzip the file with the correct password.
    """
    test_data_dir = './test_data'
    file_names = [os.path.join(test_data_dir, f) for f in os.listdir(test_data_dir) if
                  os.path.isfile(os.path.join(test_data_dir, f))]
    with tempfile.NamedTemporaryFile(suffix='.zip') as tmp_zip:
        zip_name = tmp_zip.name
        compress_multiple(
            file_names=file_names,
            zip_name=zip_name,
            password='123'
        )
        unzip(zip_name, '123')


def test_unzip_wrong_password():
    """
    Given:
        - A directory with files to zip.
    When:
        - Calling the function compress_multiple with a password.
    Then:
        - We can not unzip the file with the wrong password.
    """
    test_data_dir = './test_data'
    file_names = [os.path.join(test_data_dir, f) for f in os.listdir(test_data_dir) if
                  os.path.isfile(os.path.join(test_data_dir, f))]
    with tempfile.NamedTemporaryFile(suffix='.zip') as tmp_zip:
        zip_name = tmp_zip.name
        compress_multiple(
            file_names=file_names,
            zip_name=zip_name,
            password='123'
        )
        with pytest.raises(Exception) as e:
            unzip(zip_name, '1234')

        assert 'Bad password' in e.value.args[0]
