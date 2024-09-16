import pytest
from AnalyzeTimestampIntervals import analyze_intervals

# UT contains sample timestamp lists (100+ timestamps each) for different test cases

# Consistent intervals (1000 ms apart)
consistent_timestamps = [1609459200000 + i * 1000 for i in range(100)]

# High frequency detection (100 ms apart within a small window)
high_freq_timestamps = [1609459200000 + i * 100 for i in range(100)]

# Inconsistent intervals (varied intervals)
inconsistent_timestamps = [
    1609459200000, 1609459205000, 1609459210000, 1609459215000, 1609459220000,
    1609459227000, 1609459234000, 1609459241000, 1609459248000, 1609459255000
] + [1609459255000 + i * 3000 for i in range(90)]


def test_consistent_intervals():
    """
    Given:
    - A list of consistent timestamps
    - `max_intervals_per_window` = 30 and `interval_consistency_threshold` = 0.15
    When:
    - Calling analyze_intervals()
    Then:
    - Ensure the ConsistentIntervalsDetected output is True
    - Ensure the HighFrequencyDetected output is False
    - Ensure the outputs are returned with the expected values
    """
    max_intervals_per_window = 30
    interval_consistency_threshold = 0.15

    result = analyze_intervals(
        consistent_timestamps, verbose=True, max_intervals_per_window=max_intervals_per_window,
        interval_consistency_threshold=interval_consistency_threshold)

    # Adjust expected value to seconds (1000 ms = 1 second)
    assert result["MeanIntervalInSeconds"] == pytest.approx(1.0, rel=1e-2)
    assert result["MedianIntervalInSeconds"] == pytest.approx(1.0, rel=1e-2)
    assert result["StandardDeviationInSeconds"] == pytest.approx(0.0, rel=1e-2)
    assert result["HighFrequencyDetected"] is False
    assert result["ConsistentIntervalsDetected"] is True
    assert result["IsPatternLikelyAutomated"] is True


def test_high_frequency_detection():
    """
    Given:
    - A list of timestamps with high frequency (100 ms apart)
    - `max_intervals_per_window` = 30 and `interval_consistency_threshold` = 0.15
    When:
    - Calling analyze_intervals()
    Then:
    - Ensure the HighFrequencyDetected output is True
    - Ensure the ConsistentIntervalsDetected output is True
    - Ensure the outputs are returned with the expected values
    """
    max_intervals_per_window = 30
    interval_consistency_threshold = 0.15

    result = analyze_intervals(
        high_freq_timestamps, verbose=True, max_intervals_per_window=max_intervals_per_window,
        interval_consistency_threshold=interval_consistency_threshold)

    # Adjust expected value to seconds (100 ms = 0.1 second)
    assert result["MeanIntervalInSeconds"] == pytest.approx(0.1, rel=1e-2)
    assert result["MedianIntervalInSeconds"] == pytest.approx(0.1, rel=1e-2)
    assert result["StandardDeviationInSeconds"] == pytest.approx(0.0, rel=1e-2)
    assert result["HighFrequencyDetected"] is True
    assert result["ConsistentIntervalsDetected"] is True
    assert result["IsPatternLikelyAutomated"] is True


def test_inconsistent_intervals():
    """
    Given:
    - A list of inconsistent timestamps with varied intervals
    - `max_intervals_per_window` = 30 and `interval_consistency_threshold` = 0.15
    When:
    - Calling analyze_intervals()
    Then:
    - Ensure the ConsistentIntervalsDetected output is False
    - Ensure the HighFrequencyDetected output is False
    - Ensure the outputs are returned with the expected values
    """
    max_intervals_per_window = 30
    interval_consistency_threshold = 0.15

    result = analyze_intervals(
        inconsistent_timestamps, verbose=True, max_intervals_per_window=max_intervals_per_window,
        interval_consistency_threshold=interval_consistency_threshold)

    assert result["MeanIntervalInSeconds"] == pytest.approx(3.0, rel=1e-2)
    assert result["MedianIntervalInSeconds"] == pytest.approx(3.0, rel=1e-2)
    assert result["StandardDeviationInSeconds"] == pytest.approx(2.0, rel=1e-2)
    assert result["HighFrequencyDetected"] is False
    assert result["ConsistentIntervalsDetected"] is False
    assert result["IsPatternLikelyAutomated"] is False
