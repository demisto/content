import pytest
from ExtractIndicatorsFromWordFile import WordParser
import os
import shutil

expected_partial_all_data = 'Lorem ipsum dolor sit amet, an quas nostro posidonium mei, pro choro vocent pericula et'


@pytest.mark.parametrize('file_name,file_path', [
    ('docwithindicators.doc', 'test_data/docwithindicators'),
    ('docxwithindicators.docx', 'test_data/docxwithindicators')
])
def test_parse_word(file_name, file_path, request):
    basename = os.path.basename(file_path)
    shutil.copy(file_path, os.getcwd())

    def cleanup():
        try:
            os.remove(basename + ".docx")
            os.remove(basename)
        except OSError:
            pass

    request.addfinalizer(cleanup)
    if os.getcwd().endswith('test_data'):
        os.chdir('..')
    parser = WordParser()
    parser.get_file_details = lambda: None
    parser.file_name = file_name
    parser.file_path = basename
    parser.parse_word()
    assert(expected_partial_all_data in parser.all_data)
