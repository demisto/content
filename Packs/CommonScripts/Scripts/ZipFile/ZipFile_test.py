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
    unzip_file_path = f'{os.getcwd()}/unzipped_test_data'
    with pyzipper.AESZipFile(zip_file_path) as zf:
        zf.pwd = bytes(password, 'utf-8') if password else None
        zf.extractall(path=unzip_file_path)


@pytest.mark.parametrize(('input_name', 'output_name'), ESCAPE_CHARACTERS_PACK)
def test_escape_characters_in_file_name(input_name, output_name):
    assert escape_illegal_characters_in_file_name(input_name) == output_name


def test_compress_multiple_with_password():
    with tempfile.NamedTemporaryFile(suffix='.zip') as tmp_zip:
        zip_name = tmp_zip.name
        compress_multiple(
            file_names=['./test_data/test_txt.txt', './test_data/test_image.png', './test_data/test_image.svg'],
            zip_name=zip_name,
            password='123'
        )


def test_unzip():
    with tempfile.NamedTemporaryFile(suffix='.zip') as tmp_zip:
        zip_name = tmp_zip.name
        compress_multiple(
            file_names=['./test_data/test_txt.txt', './test_data/test_image.png', './test_data/test_image.svg'],
            zip_name=zip_name,
            password='123'
        )
        unzip(zip_name, '123')


def test_unzip_wrong_password():
    with tempfile.NamedTemporaryFile(suffix='.zip') as tmp_zip:
        zip_name = tmp_zip.name
        compress_multiple(
            file_names=['./test_data/test_txt.txt', './test_data/test_image.png', './test_data/test_image.svg'],
            zip_name=zip_name,
            password='123'
        )
        with pytest.raises(Exception) as e:
            unzip(zip_name, '1234')

        assert 'Bad password' in e.value.args[0]

