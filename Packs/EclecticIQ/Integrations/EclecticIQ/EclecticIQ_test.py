import pytest
from EclecticIQ import maliciousness_to_dbotscore

test_data = [
    ('unknown', 'unknown', 3),
    ('unknown', 'safe', 0),
    ('unknown', 'low', 0),
    ('unknown', 'medium', 0),
    ('unknown', 'high', 0),
    ('safe', 'unknown', 3),
    ('safe', 'safe', 3),
    ('safe', 'low', 1),
    ('safe', 'medium', 1),
    ('safe', 'high', 1),
    ('low', 'unknown', 3),
    ('low', 'safe', 3),
    ('low', 'low', 3),
    ('low', 'medium', 3),
    ('low', 'high', 2),
    ('medium', 'unknown', 3),
    ('medium', 'safe', 3),
    ('medium', 'low', 3),
    ('medium', 'medium', 3),
    ('medium', 'high', 2),
    ('high', 'unknown', 3),
    ('high', 'safe', 3),
    ('high', 'low', 3),
    ('high', 'medium', 3),
    ('high', 'high', 3)
]


@pytest.mark.parametrize('maliciousness,threshold,expected_result', test_data)
def test_maliciousness_to_dbotscore(maliciousness, threshold, expected_result):
    assert maliciousness_to_dbotscore(maliciousness, threshold) == expected_result


def test_maliciousness_to_dbotscore_with_bad_args():
    with pytest.raises(ValueError, match=r'maliciousness=.*$'):
        maliciousness_to_dbotscore('tutuloo', 'unknown')

    with pytest.raises(ValueError, match=r'threshold=.*$'):
        maliciousness_to_dbotscore('safe', 'YUP')
