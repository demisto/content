import pytest
import os
import shutil
from ExtractIndicatorsFromWordFile import WordParser
import demistomock as demisto
from unittest.mock import MagicMock

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

    if os.getcwd().endswith('test_data'):
        os.chdir('..')
    parser = WordParser()
    parser.get_file_details = lambda: None
    parser.file_name = file_name
    parser.file_path = basename
    parser.parse_word()
    assert (expected_partial_all_data in parser.paragraphs)
    # request.addfinalizer(cleanup)


def test_getting_file_from_context(mocker):
    """
    Given:
        -

    When:
        - Call to get_file_details

    Then:
        - Validate the context comes from incident by calling execute_command('getContext')
        instead of demisto.context witch is missed in context of sub-playbook

    """

    # prepare
    parser = WordParser()
    mocker.patch.object(demisto, 'dt')
    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, 'incident', return_value={'id': 1})
    mocked_method = mocker.patch('ExtractIndicatorsFromWordFile.execute_command', return_value={'context': {}})

    # run
    parser.get_file_details()

    # validate
    assert mocked_method.call_args[0][0] == 'getContext'


def test_get_hyperlinks():
    """
    Given:
        - Document with 3 hyperlinks.
    When:
        - Call to get_hyperlinks
    Then:
        - Validate the result contains the 3 links.
    """
    from docx.opc.constants import RELATIONSHIP_TYPE as RT
    parser = WordParser()

    doc = MagicMock()
    doc.part.rels = {}

    doc.part.rels = {
        "r1": MagicMock(reltype=RT.HYPERLINK, _target="http://example1.com"),
        "r2": MagicMock(reltype=RT.HYPERLINK, _target="http://example2.com"),
        "r3": MagicMock(reltype=RT.HYPERLINK, _target="http://example3.com")
    }

    result = parser.get_hyperlinks(doc)
    assert result == "http://example1.com http://example2.com http://example3.com "
