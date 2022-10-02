import pytest


@pytest.mark.parametrize('value, expected_result', [
    ('aGVsbG8=', 'hello'),
    ('dGhpcw==', 'this'),
    ('VGhpcyBpcyBhIHRlc3Q', 'This is a test')
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

@pytest.mark.parametrize('value, expected_result', [
    ('aGVsbG80l', 'aGVsbG80l==='),
    ('dGhpcw', 'dGhpcw=='),
    ('VGhpcyBpcyBhIHRlc3Q', 'VGhpcyBpcyBhIHRlc3Q='),
    ('ERVKHBEK0ejbce8IUBninli0', 'ERVKHBEK0ejbce8IUBninli0')
])
def test_padding(value, expected_result):
    from Base64Decode import add_padding
    padded_result = add_padding(value=value)

    assert padded_result == expected_result
