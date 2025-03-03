from MapRangeValues import Replace, RangeReplace, get_replace_list, replace_values
import pytest

data_test_replace_class = [
    (1, 1, True),
    (1, 4, False),
    ('a', 'a', True),
    ('a', 'c', False),
]


@pytest.mark.parametrize('_from, value, should_replace', data_test_replace_class)
def test_replace_class(_from, value, should_replace):
    replace_obg = Replace(_from, 1)
    assert replace_obg.should_replace(value) is should_replace


data_test_range_replace_class = [
    (1, 4, 1, True),
    (1, 3, 4, False),
    ('a', 'b', 'a', True),
    ('a', 'b', 'c', False),
]


@pytest.mark.parametrize('start, end, value, should_replace', data_test_range_replace_class)
def test_rage_replace_class(start, end, value, should_replace):
    replace_obg = RangeReplace(start, end, 1)
    assert replace_obg.should_replace(value) is should_replace


data_test_get_typed_value = [
    ('a', str),
    ('1', int),
    (1, int),
    ('1.5', float),
    (1.5, float),
    ('10.0', int)
]


@pytest.mark.parametrize('str_value, output_type', data_test_get_typed_value)
def test_get_typed_value(str_value, output_type):
    assert isinstance(Replace.get_typed_value(str_value), output_type)


data_test_get_replace_list = [
    (
        ['1', '2'],
        ['2', '3'], '-',
        [
            Replace('1', '2'),
            Replace('2', '3'),
        ]
    ),
    (
        ['1', '2', '3-5'],
        ['2', '3', '4'], '-',
        [
            Replace('1', '2'),
            Replace('2', '3'),
            RangeReplace('3', '5', '4'),
        ]
    ),
    (
        ['a', 'b-c'],
        ['b', 'd'], '-',
        [
            Replace('a', 'b'),
            RangeReplace('b', 'c', 'd')
        ]
    ),
    (
        ['1', '2', '3-5', 'a', 'b-c'],
        ['2', '3', '4', 'b', 'd'], '-',
        [
            Replace('1', '2'),
            Replace('2', '3'),
            RangeReplace('3', '5', '4'),
            Replace('a', 'b'),
            RangeReplace('b', 'c', 'd')
        ]
    ),
    (
        ['1', '2', '3§5', 'a', 'b§c'],
        ['2', '3', '4', 'b', 'd'], '§',
        [
            Replace('1', '2'),
            Replace('2', '3'),
            RangeReplace('3', '5', '4'),
            Replace('a', 'b'),
            RangeReplace('b', 'c', 'd')
        ]
    ),
]


@pytest.mark.parametrize('map_from, map_to, sep, expected_replace_list', data_test_get_replace_list)
def test_get_replace_list(map_from, map_to, sep, expected_replace_list):
    for expected_replace, replace in zip(expected_replace_list, get_replace_list(map_from, map_to, sep)):
        assert expected_replace.__dict__ == replace.__dict__


data_test_replace_values = [
    (['1'], [Replace('1', '2')], [2]),
    (['3', '4', '5'], [RangeReplace('3', '5', '4')], [4] * 3),
    (['0.5', '2'], [RangeReplace('0.3', '0.6', 'test'), Replace('2', 'test2')], ['test', 'test2']),
    ([str(i) for i in range(1, 6)], [Replace('1', '2'), RangeReplace('3', '5', '4')], [2, 2, 4, 4, 4]),
]


@pytest.mark.parametrize('values_list, replace_list, expected_values', data_test_replace_values)
def test_replace_values(values_list, replace_list, expected_values):
    assert expected_values == replace_values(values_list, replace_list)
