import pytest
from AnalyzeTimestampIntervals import analyze_intervals
import random


# Consistent intervals (10,000 ms apart, i.e., 1 event every 10 seconds)
consistent_timestamps = [1609459200000 + i * 10000 for i in range(100)]

# High frequency detection (100 ms apart, i.e., 10 events per second)
high_freq_timestamps = [1609459200000 + i * 100 for i in range(100)]

# Random intervals with +-1500 ms variation
random.seed(42)  # Ensures reproducibility for tests
random_intervals = [3000 + random.randint(-1500, 1500) for _ in range(90)]

inconsistent_timestamps = [
    1609459200000, 1609459205000, 1609459210000, 1609459215000, 1609459220000,
    1609459227000, 1609459234000, 1609459241000, 1609459248000, 1609459255000
] + [1609459255000 + sum(random_intervals[:i + 1]) for i in range(90)]


def test_consistent_intervals():
    """
    Given:
    - A list of consistent timestamps (2000 ms apart, 1 event per 2 seconds)
    - `max_intervals_per_window` = 30 (1 event per 2 seconds for 60 seconds = 30 events max)
    - `interval_consistency_threshold` = 0.15
    When:
    - Calling analyze_intervals()
    Then:
    - Ensure the ConsistentIntervalsDetected output is True (events are consistently spaced)
    - Ensure the HighFrequencyDetected output is False (frequency is within human limits)
    - Ensure the outputs are returned with the expected values
    """
    max_intervals_per_window = 30  # 1 event per 2 seconds allowed within a 60-second window
    interval_consistency_threshold = 0.15

    result = analyze_intervals(
        consistent_timestamps, verbose=True, max_intervals_per_window=max_intervals_per_window,
        interval_consistency_threshold=interval_consistency_threshold)

    assert result["MeanIntervalInSeconds"] == pytest.approx(10.0, rel=1e-1)
    assert result["MedianIntervalInSeconds"] == pytest.approx(10.0, rel=1e-1)
    assert result["StandardDeviationInSeconds"] == pytest.approx(0.0, rel=1e-1)
    assert result["HighFrequencyDetected"] is False  # 1 event per 2 seconds is allowed
    assert result["ConsistentIntervalsDetected"] is True  # Intervals are consistent
    assert result["IsPatternLikelyAutomated"] is True  # Consistent intervals suggest automation


def test_high_frequency_detection():
    """
    Given:
    - A list of timestamps with high frequency (100 ms apart, 10 events per second)
    - `max_intervals_per_window` = 30 (1 event per 2 seconds for 60 seconds = 30 events max)
    - `interval_consistency_threshold` = 0.15
    When:
    - Calling analyze_intervals()
    Then:
    - Ensure the HighFrequencyDetected output is True (frequency exceeds human capability)
    - Ensure the ConsistentIntervalsDetected output is True (since intervals are consistent)
    - Ensure the outputs are returned with the expected values
    """
    max_intervals_per_window = 30  # 1 event per 2 seconds allowed within a 60-second window
    interval_consistency_threshold = 0.15

    result = analyze_intervals(
        high_freq_timestamps, verbose=True, max_intervals_per_window=max_intervals_per_window,
        interval_consistency_threshold=interval_consistency_threshold)

    assert result["MeanIntervalInSeconds"] == pytest.approx(0.1, rel=1e-1)
    assert result["MedianIntervalInSeconds"] == pytest.approx(0.1, rel=1e-1)
    assert result["StandardDeviationInSeconds"] == pytest.approx(0.0, rel=1e-1)
    assert result["HighFrequencyDetected"] is True  # More than 1 event per 2 seconds, flagged as high frequency
    assert result["ConsistentIntervalsDetected"] is True  # Even though fast, the intervals are consistent
    assert result["IsPatternLikelyAutomated"] is True  # High frequency and consistency suggest automation


def test_inconsistent_intervals():
    """
    Given:
    - A list of inconsistent timestamps with varied intervals
    - `max_intervals_per_window` = 30 (1 event per 2 seconds for 60 seconds = 30 events max)
    - `interval_consistency_threshold` = 0.15
    When:
    - Calling analyze_intervals()
    Then:
    - Ensure the ConsistentIntervalsDetected output is False (since intervals are varied)
    - Ensure the HighFrequencyDetected output is False (frequency does not exceed human limits)
    - Ensure the outputs are returned with the expected values
    """
    max_intervals_per_window = 30  # 1 event per 2 seconds allowed within a 60-second window
    interval_consistency_threshold = 0.15

    result = analyze_intervals(
        inconsistent_timestamps, verbose=True, max_intervals_per_window=max_intervals_per_window,
        interval_consistency_threshold=interval_consistency_threshold)

    # Adjusted for the inconsistency of intervals
    assert result["MeanIntervalInSeconds"] == pytest.approx(3.5, rel=1e-1)
    assert result["MedianIntervalInSeconds"] == pytest.approx(3.085, rel=1e-1)
    assert result["StandardDeviationInSeconds"] == pytest.approx(1.4, rel=2e-1)
    assert result["HighFrequencyDetected"] is False  # No high frequency detected
    assert result["ConsistentIntervalsDetected"] is False  # Intervals are too varied
    assert result["IsPatternLikelyAutomated"] is False  # Not enough evidence for automation
