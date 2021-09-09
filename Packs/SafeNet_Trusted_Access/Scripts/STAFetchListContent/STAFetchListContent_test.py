import demistomock as demisto
from STAFetchListContent import get_unusual_activity_group_sta

# Defining output of the getList command for mocker.
xsoar_list_contents = [
    {'Contents': 'TestUnusualActivityGroup'}
]


# Tests get_unusual_activity_group_sta function.
def test_get_unusual_activity_group_sta(mocker):

    execute_mocker = mocker.patch.object(demisto, 'executeCommand', return_value=xsoar_list_contents)
    expected_method_arg = {
        'list_name': 'sta_unusual_activity_group',
    }
    response = get_unusual_activity_group_sta(expected_method_arg)

    expected_command = 'getList'
    expected_command_args = {
        'listName': expected_method_arg['list_name'],
    }
    execute_mocker.assert_called_with(expected_command, expected_command_args)
    assert response.outputs == 'TestUnusualActivityGroup'
