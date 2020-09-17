from CalculateEntropy import calculate_shannon_entropy


def test_calculate_shannon_entropy():
    _, context_result, _ = calculate_shannon_entropy('1234', 1)
    assert context_result == {'EntropyResult': {'checked_value': '1234', 'entropy': 2.0}}

    _, context_result, _ = calculate_shannon_entropy('1234', 3)
    assert context_result == {}
