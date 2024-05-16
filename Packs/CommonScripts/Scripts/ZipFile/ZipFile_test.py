import pytest
from ZipFile import escape_illegal_characters_in_file_name, compress_multiple_with_password

ESCAPE_CHARACTERS_PACK = [
    ('/Users/user/Downloads/b/a/testingfile.txt', '-Users-user-Downloads-b-a-testingfile.txt'),
    ('/Users/user/Downloads/?///testingfile.txt', '-Users-user-Downloads-testingfile.txt'),
    ('/Users/user/Downloads/b/a/testingfile*.txt', '-Users-user-Downloads-b-a-testingfile-.txt'),
    ('abcde', 'abcde')
]


@pytest.mark.parametrize(('input_name', 'output_name'), ESCAPE_CHARACTERS_PACK)
def test_escape_characters_in_file_name(input_name, output_name):
    assert escape_illegal_characters_in_file_name(input_name) == output_name


def test_compress_multiple_with_password():
    compress_multiple_with_password(
        file_names=['./test_data/test_txt.txt', './test_data/test_image.png', './test_data/test_image.svg'],
        zip_name='compressed_data.zip',
        password='123'
    )
