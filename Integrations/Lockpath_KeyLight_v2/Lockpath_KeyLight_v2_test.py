import pytest

def test_filter_creator():
    from Lockpath_KeyLight_v2 import create_filter
    filt = create_filter('Starts With', 'Blue', '3881')
    check = {
        "FieldPath": [
            3881
        ],
        "FilterType": "3",
        "Value": "Blue"
    }

    assert filt == check

    with pytest.raises(ValueError, match='Filter Type is invalid.'):
        create_filter('>=', '5', '3881')


