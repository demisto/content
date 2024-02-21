import pytest


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
    When:
    Then:
    """
    from ExtractHyperlinksFromOfficeFiles import extract_hyperlink_by_file_type

    response = extract_hyperlink_by_file_type(file_path)
    assert response.outputs == expected_output
