import pytest
from ExtractHyperlinksFromOfficeFiles import extract_hyperlink_by_file_type


@pytest.mark.parametrize('file_path, expected_output', [
    ('test_data/d1.docx',
     {'https://xsoar.pan.dev/', 'https://www.paloaltonetworks.com/', 'https://jobs.paloaltonetworks.com/en/'}),
    ('test_data/d2.docx', set()),
    ('test_data/d3.docx', {'https://www.paloaltonetworks.com/', 'http://www.google.com'}),
    ('test_data/e1.Xlsx', {'http://www.google.com', 'http://www.yahoo.de/'}),
    ('test_data/e2.xlsx', set()),
    ('test_data/e3.xlsx', {'https://www.paloaltonetworks.com/'}),
    ('test_data/p1.pptx', {'https://xsoar.pan.dev/', 'https://www.paloaltonetworks.com/'}),
    ('test_data/p2.pptx', set()),
    ('test_data/p3.pptx', {'http://www.google.com'})
])
def test_basescript_dummy(file_path, expected_output):
    """
    Given:
        1. docx file with hyperlinks on a picture and text.
        2. docx file without hyperlinks
        3. docx file with hyperlinks on a picture and in the document.
        4. excel file with hyperlinks on a picture and inside text cell.
        5. excel file with no hyperlinks.
        6. excel file with hyperlinks inside text cell.
        7. power point file with hyperlinks on a picture and text.
        8. power point file without hyperlinks.
        9. power point file with hyperlinks inside grourped shapes.
    When:
        Extracting hyperlinks from file using ExtractHyperlinksFromOfficeFiles script.
    Then:
        Validate that:
        1. hyperlinks extracted from docx file
        2. no hyperlinks extracted from docx file
        3. hyperlinks extracted from the docx file.
        4. hyperlinks extracted from excel file
        5. no hyperlinks extracted from excel file
        6. hyperlinks extracted from excel file
        7. hyperlinks extracted from power point file
        8. no hyperlinks extracted from power point file
        9. The grouped shapes are parsed correctly and the hyperlink is extracted.
    """
    response = extract_hyperlink_by_file_type(file_name=file_path, file_path=file_path)
    assert set(response.raw_response) == expected_output


def test_invalid_file_type():
    """
    Given:
        An unsupported file type.
    When:
        Extracting hyperlinks from the unsupported file type using `extract_hyperlink_by_file_type` function.
    Then:
        Validate that a ValueError is raised with the appropriate message.
    """
    file_path = 'test_data/unsupported_file.txt'
    with pytest.raises(ValueError, match="Unsupported file type. Supported types are: 'xlsx, docx, pptx'"):
        extract_hyperlink_by_file_type(file_name=file_path, file_path=file_path)
