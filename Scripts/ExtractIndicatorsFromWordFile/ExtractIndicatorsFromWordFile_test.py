import pytest
from ExtractIndicatorsFromWordFile import WordParser
import os

expected_partial_all_data = 'Lorem ipsum dolor sit amet, an quas nostro posidonium mei, pro choro vocent pericula et'


@pytest.mark.parametrize('file_name,file_path', [
    ('docwithindicators.doc', 'test_data/docwithindicators'),
    ('docxwithindicators.docx', 'test_data/docxwithindicators')
])
def test_parse_word(file_name, file_path):
    if os.getcwd().endswith('test_data'):
        os.chdir('..')
    parser = WordParser()
    parser.get_file_details = lambda: None
    parser.file_name = file_name
    parser.file_path = file_path
    parser.parse_word()
    assert(expected_partial_all_data in parser.all_data)
