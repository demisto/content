from AnsibleApiModule import dict2md, rec_ansible_key_strip
from TestsInput.markdown import MOCK_SINGLE_LEVEL_LIST, EXPECTED_MD_LIST, MOCK_SINGLE_LEVEL_DICT, EXPECTED_MD_DICT
from TestsInput.markdown import MOCK_MULTI_LEVEL_DICT, EXPECTED_MD_MULTI_DICT, MOCK_MULTI_LEVEL_LIST
from TestsInput.markdown import EXPECTED_MD_MULTI_LIST, MOCK_MULTI_LEVEL_LIST_ID_NAMES, EXPECTED_MD_MULTI_LIST_ID_NAMES
from TestsInput.ansible_keys import MOCK_ANSIBLE_DICT, EXPECTED_ANSIBLE_DICT, MOCK_ANSIBLELESS_DICT, EXPECTED_ANSIBLELESS_DICT

def test_dict2md_simple_lists():
    """
    Scenario: Given a simple single level dict or list, dict2md should output a dot point list equivalent

    Given:
    - List of strings
    - Single level dict

    When:
    - Convert to markdownMOCK_ANSIBLE_DICT
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


def test_rec_ansible_key_strip():
    """
    Scenario: Given a multi level dict rec_ansible_key_strip should recursively remove the string 'ansible_' from any keys

    Given:
    - Multi-level dict with some keys starting with ansible_
    - Multi-level dict with no keys starting with ansible_

    When:
    - rec_ansible_key_strip is used to santise the value

    Then:
    - Return de-branded result

    """
    ansible_dict = rec_ansible_key_strip(MOCK_ANSIBLE_DICT)
    ansibleless_dict = rec_ansible_key_strip(MOCK_ANSIBLELESS_DICT)

    assert ansible_dict == EXPECTED_ANSIBLE_DICT
    assert ansibleless_dict == EXPECTED_ANSIBLELESS_DICT
