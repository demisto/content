from pytest_mock import MockerFixture
from ConvertRequestParametersToTable import *
CONTEXT_RESULTS = (
    '{"key_1": "val_1", "key_2": "val_2", "key_3": "val_3", "key_4": "val_4"}'
)


def test_convert_to_table(mocker: MockerFixture):
    """
    Given:
        - A string that contains data of the incident field.
    When:
        - Calling convert_to_table function.
    Then:
        - Validate that the function tableToMarkdown is called with the correct arguments.
    """
    tableToMarkdown_mocker = mocker.patch('ConvertRequestParametersToTable.tableToMarkdown', side_effect=tableToMarkdown)
    convert_to_table(CONTEXT_RESULTS)
    call_args_list = tableToMarkdown_mocker.call_args_list[0][1]
    assert call_args_list.get('t') == json.loads(CONTEXT_RESULTS)
    assert call_args_list.get('headers') == ['key_1', 'key_2', 'key_3', 'key_4']
    assert call_args_list.get('is_auto_json_transform') is True
    assert call_args_list.get('headerTransform') == pascalToSpace
