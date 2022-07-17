import demistomock as demisto  # noqa: F401
import pytest


@pytest.mark.parametrize("args,expected", [
    # Matching tables
    (
            {
                "left": [{"key1": "value1"}],
                "right": [{"key1": "value1"}],
            },
            {
                "Result": []
            }
    ),
    # Changed Value
    (
            {
                "left": [{"id": 1, "key1": "value1"}, {"id": 2, "key2": "value1"}],
                "right": [{"id": 1, "key1": "value2"}, {"id": 2, "key2": "value1"}],
            },
            {'Result': [{'description': 'key1 - value1 different to value2',
                         'key': 'id',
                         'table_id': 'compare',
                         'value': 1}]
             }
    ),
    # Missing key
    (
            {
                "left": [{"id": 1, "key1": "value1"}, {"id": 2, "key2": "value1"}],
                "right": [{"id": 2, "key2": "value1"}],
            },
            {'Result': [{'description': '1 missing.',
                         'key': 'id',
                         'table_id': 'compare',
                         'value': 1}]
             }
    ),
])
def test_main(mocker, args, expected):
    mocker.patch.object(demisto, 'args', return_value=args)
    from CompareTables import main
    result = main()
    assert result.outputs == expected
