import pytest
from ZipFile import escape_illegal_characters_in_file_name

ESCAPE_CHARACTERS_PACK = [
    ('/Users/user/Downloads/b/a/testingfile.txt', '-Users-user-Downloads-b-a-testingfile.txt'),
    ('/Users/user/Downloads/?///testingfile.txt', '-Users-user-Downloads-testingfile.txt'),
    ('/Users/user/Downloads/b/a/testingfile*.txt', '-Users-user-Downloads-b-a-testingfile-.txt'),
    ('abcde', 'abcde')
]


@pytest.mark.parametrize(('input_name', 'output_name'), ESCAPE_CHARACTERS_PACK)
def test_escape_characters_in_file_name(input_name, output_name):
    assert escape_illegal_characters_in_file_name(input_name) == output_name
