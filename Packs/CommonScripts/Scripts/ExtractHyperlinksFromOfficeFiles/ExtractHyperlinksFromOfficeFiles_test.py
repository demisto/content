import pytest
from ExtractHyperlinksFromOfficeFiles import extract_hyperlink_by_file_type


@pytest.mark.parametrize('file_path, expected_output', [
    ('test_data/d1.docx',
     {'https://xsoar.pan.dev/', 'https://www.paloaltonetworks.com/', 'https://jobs.paloaltonetworks.com/en/'}),
    ('test_data/d2.docx', set()),
    ('test_data/e1.xlsx', {'http://www.google.com', 'http://www.yahoo.de/'}),
    ('test_data/e2.xlsx', set()),
    ('test_data/e3.xlsx', {'https://www.paloaltonetworks.com/'}),
    ('test_data/p1.pptx', {'https://xsoar.pan.dev/', 'https://www.paloaltonetworks.com/'}),
    ('test_data/p2.pptx', set()),
])
def test_basescript_dummy(file_path, expected_output):
    """
    Given:
        1. docx file with hyperlinks on a picture and text.
        2. docx file without hyperlinks
        3. excel file with hyperlinks on a picture and inside text cell.
        4. excel file with no hyperlinks.
        5. excel file with hyperlinks inside text cell.
        6. power point file with hyperlinks on a picture and text.
        7. power point file without hyperlinks.
    When:
        Extracting hyperlinks from file using ExtractHyperlinksFromOfficeFiles script.
    Then:
        Validate that:
        1. hyperlinks extracted from docx file
        2. no hyperlinks extracted from docx file
        3. hyperlinks extracted from excel file
        4. no hyperlinks extracted from excel file
        5. hyperlinks extracted from excel file
        6. hyperlinks extracted from power point file
        7. no hyperlinks extracted from power point file
    """
    response = extract_hyperlink_by_file_type(file_name=file_path, file_path=file_path)
    assert set(response.raw_response) == expected_output
