import demistomock as demisto  # noqa: F401
import DarkmonFilterUnseen


def test_main_no_items(mocker):
    """
    Given:
        - No items passed to the script

    When:
        - main() is called with an empty items list

    Then:
        - return_results is called with an empty NewAccounts list
    """
    mocker.patch.object(demisto, "args", return_value={"items": [], "id_field": "id", "seen_list": "test-list"})
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Contents": "", "Type": 1}])
    mock_return = mocker.patch.object(DarkmonFilterUnseen, "return_results")

    DarkmonFilterUnseen.main()

    mock_return.assert_called_once()
    result = mock_return.call_args[0][0]
    assert result.get("NewAccounts") == []


def test_main_filters_seen_items(mocker):
    """
    Given:
        - Two items where one ID is already in the seen list

    When:
        - main() is called

    Then:
        - Only the unseen item is returned in NewAccounts
    """
    items = [{"id": "abc123"}, {"id": "xyz789"}]
    mocker.patch.object(demisto, "args", return_value={"items": items, "id_field": "id", "seen_list": "test-list"})
    mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=[
            [{"Contents": "abc123", "Type": 1}],  # getList returns abc123 as already seen
            [{"Contents": "", "Type": 1}],  # setList call
        ],
    )
    mock_return = mocker.patch.object(DarkmonFilterUnseen, "return_results")

    DarkmonFilterUnseen.main()

    mock_return.assert_called_once()
    result = mock_return.call_args[0][0]
    assert len(result.get("NewAccounts", [])) == 1
    assert result["NewAccounts"][0]["id"] == "xyz789"
