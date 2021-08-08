from CompareIndicators import collect_unique_indicators_from_lists


def test_collect_unique_indicators_from_lists():
    # empty lists
    list1 = []
    list2 = []
    actual = collect_unique_indicators_from_lists(list1, list2)
    assert actual == (set(), set())

    # list1 only is empty
    list2 = ['1.1.1.1', '2.2.2.2/20', 'abcd']
    actual = collect_unique_indicators_from_lists(list1, list2)
    assert actual == (set(), {'1.1.1.1', 'abcd', '2.2.0.0-2.2.15.255'})

    # list2 only  is empty
    list1 = list2
    list2 = []
    actual = collect_unique_indicators_from_lists(list1, list2)
    assert actual == ({'1.1.1.1', 'abcd', '2.2.0.0-2.2.15.255'}, set())

    # list1 and list2 have 1) unique iocs, 2) fully matching iocs, 3) partially matching iocs
    list1 = ['abcd', '1.1.1.0/30', '2.2.2.2', '3.3.3.3-3.3.3.6']
    list2 = ['bcde', '1.1.1.2', '2.2.2.2', '3.3.3.2-3.3.3.5']
    actual = collect_unique_indicators_from_lists(list1, list2)
    #                   partial    partial     partial          unique     partial   unique
    assert actual == ({'1.1.1.3', '3.3.3.6', '1.1.1.0-1.1.1.1', 'abcd'}, {'3.3.3.2', 'bcde'})
