from AnsibleApiModule import dict2md
from TestsInput.markdown import MOCK_SINGLE_LEVEL_LIST, EXPECTED_MD_LIST, MOCK_SINGLE_LEVEL_DICT, EXPECTED_MD_DICT
from TestsInput.markdown import MOCK_MULTI_LEVEL_DICT, EXPECTED_MD_MULTI_DICT, MOCK_MULTI_LEVEL_LIST
from TestsInput.markdown import EXPECTED_MD_MULTI_LIST, MOCK_MULTI_LEVEL_LIST_ID_NAMES, EXPECTED_MD_MULTI_LIST_ID_NAMES


def test_dict2md_simple_lists():
    """
    Scenario: Given a simple single level dict or list, dict2md should output a dot point list equivalent

    Given:
    - List of strings
    - Single level dict

    When:
    - Convert to markdown

    Then:
    - Validate that the returned text is converted to a markdown list correctly

    """
    markdown_list = dict2md(MOCK_SINGLE_LEVEL_LIST)
    markdown_dict = dict2md(MOCK_SINGLE_LEVEL_DICT)

    assert markdown_list == EXPECTED_MD_LIST
    assert markdown_dict == EXPECTED_MD_DICT


def test_dict2md_complex_lists():
    """
    Scenario: Given a complex multi level dict dict2md should output the markdown equivalent with appropriate level headings

    Given:
    - Multi-level dict
    - List of dicts
    - List of dicts including id and name keys

    When:
    - Convert to markdown

    Then:
    - Validate that the returned text is converted to a markdown correctly

    """
    markdown_multi_dict = dict2md(MOCK_MULTI_LEVEL_DICT)
    markdown_multi_list = dict2md(MOCK_MULTI_LEVEL_LIST)
    markdown_multi_list_id_name = dict2md(MOCK_MULTI_LEVEL_LIST_ID_NAMES)

    assert markdown_multi_dict == EXPECTED_MD_MULTI_DICT
    assert markdown_multi_list == EXPECTED_MD_MULTI_LIST
    assert markdown_multi_list_id_name == EXPECTED_MD_MULTI_LIST_ID_NAMES
