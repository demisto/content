from CompareIndicators import collect_unique_indicators_from_lists, extract_list_from_args, demisto


def test_collect_unique_indicators_from_lists__empty():
    """
    Given:
        - Empty lists
    When:
        - Calling collect_unique_indicators_from_lists
    Then:
        - Return 2 empty lists
    """
    list1 = []
    list2 = []
    actual = collect_unique_indicators_from_lists(list1, list2)
    assert actual == ([], [])


def test_collect_unique_indicators_from_lists__partial_empty1():
    """
    Given:
        - Base list is empty
        - Compare to list is populated
    When:
        - Calling collect_unique_indicators_from_lists
    Then:
        - First result is empty
        - Second result is same as compare to list
    """
    expected = ['1.1.1.1', '2.2.0.0-2.2.15.255', 'abcd']
    list1 = []
    list2 = ['1.1.1.1', '2.2.2.2/20', 'abcd']
    actual = collect_unique_indicators_from_lists(list1, list2)
    assert actual[0] == []
    for e in expected:
        assert e in actual[1]


def test_collect_unique_indicators_from_lists__partial_empty2():
    """
    Given:
        - Base list is populated
        - Compare to list is empty
    When:
        - Calling collect_unique_indicators_from_lists
    Then:
        - First result is same as base list
        - Second result is empty
    """
    expected = ['1.1.1.1', '2.2.0.0-2.2.15.255', 'abcd']
    list1 = ['1.1.1.1', '2.2.2.2/20', 'abcd']
    list2 = []
    actual = collect_unique_indicators_from_lists(list1, list2)
    assert actual[1] == []
    for e in expected:
        assert e in actual[0]


def test_collect_unique_indicators_from_lists__populated_lists():
    """
    Given:
        - Both lists are populated
        - list1 and list2 have 1) unique iocs, 2) fully matching iocs, 3) partially matching iocs
    When:
        - Calling collect_unique_indicators_from_lists
    Then:
        - Partial results and unique results are returned back
    """
    #             partial    partial     partial          unique
    expected1 = ['1.1.1.3', '3.3.3.6', '1.1.1.0-1.1.1.1', 'abcd']
    #            partial   unique
    expected2 = ['3.3.3.2', 'bcde']
    list1 = ['abcd', '1.1.1.0/30', '2.2.2.2', '3.3.3.3-3.3.3.6']
    list2 = ['bcde', '1.1.1.2', '2.2.2.2', '3.3.3.2-3.3.3.5']
    actual = collect_unique_indicators_from_lists(list1, list2)
    for e in expected1:
        assert e in actual[0]
    for e in expected2:
        assert e in actual[1]


def test_extract_list_from_args__file_doesnt_exist(mocker):
    """
    Given:
        - A list of 1 is provided
    When:
        - Calling extract_lists_from_args
    Then:
        - Return a list with the ioc
    """
    mocker.patch.object(demisto, 'getFilePath', side_effect=ValueError)
    actual = extract_list_from_args({'test': '1.1.1.1'}, 'test')
    assert actual == ['1.1.1.1']


def test_extract_list_from_args__file_exists(mocker):
    """
    Given:
        - A list is provided via entry id
        - The file exists
    When:
        - Calling extract_lists_from_args
    Then:
        - Return a list with the iocs in the file
    """
    mocker.patch.object(demisto, 'getFilePath',
                        return_value={'path': 'test_files/ips.txt'})
    actual = extract_list_from_args({'test': '12@1'}, 'test')
    assert actual == ['1.1.1.1', '2.2.2.2']
