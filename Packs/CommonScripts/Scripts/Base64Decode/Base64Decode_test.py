import pytest


@pytest.mark.parametrize('value,expected_result', [
    ('aGVsbG8=', 'hello'),
    ('dGhpcw==', 'this')
])
def test_decoding(value, expected_result):
    from Base64Decode import decode
    actual_result, output = decode(value)

    assert actual_result == expected_result
    assert output == {
        "Base64":
            {
                "originalValue": value,
                "decoded": expected_result
            }
    }
