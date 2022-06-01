from IsListExist import main

import pytest

import demistomock as demisto


@pytest.mark.parametrize('list_name,get_list_res,expected', [
    (
        'list1',
        [
            {
                'Type': 1,
                'Contents': 'list content',
            }
        ],
        'yes',
    ),
    (
        'list2',
        [
            {
                'Type': 4,
                'Contents': 'Item not found',
            }
        ],
        'no',
    ),
])
def test_is_list_exist(mocker, list_name, get_list_res, expected):
    """
    Given:
        - Case A: List named list1 and getList response which include the list
        - Case A: List named list2 and getList response which contains an error that list was not found

    When:
        - Running IsListExist

    Then:
        - Case A: Ensure yes is returned
        - Case B: Ensure no is returned
    """
    mocker.patch.object(demisto, 'args', return_value={
        'listName': list_name,
    })
    mocker.patch.object(demisto, 'executeCommand', return_value=get_list_res)
    mocker.patch.object(demisto, 'results')
    main()
    demisto.results.assert_called_with(expected)
