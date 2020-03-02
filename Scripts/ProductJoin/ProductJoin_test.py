from ProductJoin import product_join


def test_when_list1_is_csv_and_list2_is_list():
    list1 = 'a,b,c'
    list2 = ['1', '2']
    result = product_join({'value': list1, 'list2': list2, 'join': '='})
    expectedOutput = ['a=1', 'a=2', 'b=1', 'b=2', 'c=1', 'c=2']

    assert expectedOutput == result


def test_when_list1_is_list_and_list2_is_csv():
    list1 = ['a', 'b', 'c']
    list2 = '1,2'
    result = product_join({'value': list1, 'list2': list2, 'join': '='})
    expectedOutput = ['a=1', 'a=2', 'b=1', 'b=2', 'c=1', 'c=2']

    assert expectedOutput == result


def test_when_list1_is_list_and_list2_is_list():
    list1 = ['a', 'b', 'c']
    list2 = ['1', '2']
    result = product_join({'value': list1, 'list2': list2, 'join': '='})
    expectedOutput = ['a=1', 'a=2', 'b=1', 'b=2', 'c=1', 'c=2']

    assert expectedOutput == result


def test_when_list1_is_csv_and_list2_is_csv():
    list1 = 'a,b,c'
    list2 = '1,2'
    result = product_join({'value': list1, 'list2': list2, 'join': '='})
    expectedOutput = ['a=1', 'a=2', 'b=1', 'b=2', 'c=1', 'c=2']

    assert expectedOutput == result


def test_when_list1_is_csv_and_list2_is_csv_with_spaces():
    list1 = 'a,b,c'
    list2 = '1, 2'
    result = product_join({'value': list1, 'list2': list2, 'join': '='})
    expectedOutput = ['a=1', 'a=2', 'b=1', 'b=2', 'c=1', 'c=2']

    assert expectedOutput == result


def test_when_list1_is_csv_and_list2_is_numbers():
    list1 = 'a, b, c'
    list2 = [1, 2]
    result = product_join({'value': list1, 'list2': list2, 'join': '='})
    expectedOutput = ['a=1', 'a=2', 'b=1', 'b=2', 'c=1', 'c=2']

    assert expectedOutput == result


def test_when_list1_is_csv_and_list2_is_number():
    list1 = 'a, b, c'
    list2 = 1
    result = product_join({'value': list1, 'list2': list2, 'join': '='})
    expectedOutput = ['a=1', 'b=1', 'c=1']

    assert expectedOutput == result


def test_when_list1_is_csv_and_list2_is_single_item():
    list1 = 'a, b, c'
    list2 = [1]
    result = product_join({'value': list1, 'list2': list2, 'join': '='})
    expectedOutput = ['a=1', 'b=1', 'c=1']

    assert expectedOutput == result
