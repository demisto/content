from CalculateEntropy import calculate_shannon_entropy


def test_calculate_shannon_entropy():
    result = calculate_shannon_entropy('1234', 1)
    assert result == ('', {'EntropyResult': {'checked_value': '1234', 'entropy': 2.0}}, {})

    result = calculate_shannon_entropy('1234', 3)
    assert result == ('', {}, {})
