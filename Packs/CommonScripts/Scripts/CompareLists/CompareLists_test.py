from CompareLists import compare


def test_compare():
    leftArg = [1, 2, 3]
    rightArg = [2, 3, 4]
    result = compare(leftArg, rightArg)
    assert result == {
        'ListCompare':
            {
                'LeftOnly': [1],
                'RightOnly': [4],
                'Both': [2, 3]
            }
    }
