import demistomock as demisto
import SortBy
import json
import random
import math
import itertools
import unittest
from typing import Any


def run_test(mocker: unittest.mock,
             value: list[Any] | None,
             keys: str | list[str] | None,
             descending_keys: str | list[str] | None,
             result: list[Any]):

    mocker.patch.object(demisto, 'args', return_value={
        'value': value,
        'keys': keys,
        'descending_keys': descending_keys
    })
    mocker.patch.object(SortBy, 'return_results')
    SortBy.main()
    assert SortBy.return_results.call_count == 1
    ret = SortBy.return_results.call_args[0][0]
    assert json.dumps(ret) == json.dumps(result)


def test_shuffleable(mocker):
    with open('./test_data/test-shuffleable.json') as f:
        test_list = json.load(f)

    for case in test_list:
        value = case['value']
        result = case['result']
        for args in case.get('args') or [{}]:
            keys = args.get('keys')
            descending_keys = args.get('descending_keys')
            if not value:
                run_test(mocker, value, keys, descending_keys, result)
            elif math.factorial(len(value)) > 1000:
                for _ in range(1000):
                    random.shuffle(value)
                    run_test(mocker, value.copy(), keys, descending_keys, result)
            else:
                for v in itertools.permutations(value):
                    run_test(mocker, list(v), keys, descending_keys, result)


def test_special_descending_symbol_is_not_for_keys(mocker):
    sorted_value_in_descending = [
        {
            'key': 3
        },
        {
            'key': 2,
        },
        {
            'key': 1
        }
    ]
    sorted_count = 0
    combination_count = 0
    for value in itertools.permutations(sorted_value_in_descending):
        mocker.patch.object(demisto, 'args', return_value={
            'value': list(value),
            'keys': 'key',
            'descending_keys': '*'
        })
        mocker.patch.object(SortBy, 'return_results')
        SortBy.main()
        assert SortBy.return_results.call_count == 1
        ret = SortBy.return_results.call_args[0][0]
        if json.dumps(ret) == json.dumps(sorted_value_in_descending):
            sorted_count += 1
        combination_count += 1

    assert sorted_count != combination_count
