import pytest

@pytest.mark.parametrize('input,expected_result', [
    ('e', 'ZQ=='),
    ('日本語', '5pel5pys6Kqe')
])
def test_encoding(input, expected_result):
    from Base64Encode import encode
    actual_result, output = encode(input)

    assert actual_result == expected_result
    assert output == {
        'Base64':
            {
                'encoded': expected_result
            }
    }
