import pytest
from statistics import stdev, median
from AnalyzeTimestampIntervals import analyze_intervals, calculate_statistics

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

@pytest.mark.parametrize("timestamps, expected_mean, expected_median, expected_std, expected_high_freq, expected_consistent", [
    (consistent_timestamps, 1000.0, 1000.0, 0.0, False, True), # Consistent intervals
    (high_freq_timestamps, 100.0, 100.0, 0.0, True, True), # High frequency
    (inconsistent_timestamps, 3000.0, 3000.0, 2000.0, False, False) # Inconsistent intervals
])
def test_analyze_intervals(timestamps, expected_mean, expected_median, expected_std, expected_high_freq, expected_consistent):
    # Default thresholds
    max_intervals_per_window = 30
    interval_consistency_threshold = 0.15

    # Run analysis
    result = analyze_intervals(timestamps, verbose=True, max_intervals_per_window=max_intervals_per_window, interval_consistency_threshold=interval_consistency_threshold)

    # Verify results
    assert result["MeanIntervalInSeconds"] == pytest.approx(expected_mean, rel=1e-2)
    assert result["MedianIntervalInSeconds"] == pytest.approx(expected_median, rel=1e-2)
    assert result["StandardDeviationInSeconds"] == pytest.approx(expected_std, rel=1e-2)
    assert result["HighFrequencyDetected"] == expected_high_freq
    assert result["ConsistentIntervalsDetected"] == expected_consistent
    assert result["IsPatternLikelyAutomated"] == (expected_high_freq or expected_consistent)

def test_high_frequency_detection():
    # High frequency detection should trigger at default settings
    timestamps = high_freq_timestamps
    max_intervals_per_window = 30
    interval_consistency_threshold = 0.15

    result = analyze_intervals(timestamps, verbose=True, max_intervals_per_window=max_intervals_per_window, interval_consistency_threshold=interval_consistency_threshold)

    assert result["HighFrequencyDetected"] == True
    assert result["IsPatternLikelyAutomated"] == True

def test_consistent_intervals():
    # Consistent intervals should be detected as automated with low std deviation
    timestamps = consistent_timestamps
    max_intervals_per_window = 30
    interval_consistency_threshold = 0.15

    result = analyze_intervals(timestamps, verbose=True, max_intervals_per_window=max_intervals_per_window, interval_consistency_threshold=interval_consistency_threshold)

    assert result["ConsistentIntervalsDetected"] == True
    assert result["IsPatternLikelyAutomated"] == True

def test_inconsistent_intervals():
    # Inconsistent intervals should not be flagged as consistent
    timestamps = inconsistent_timestamps
    max_intervals_per_window = 30
    interval_consistency_threshold = 0.15

    result = analyze_intervals(timestamps, verbose=True, max_intervals_per_window=max_intervals_per_window, interval_consistency_threshold=interval_consistency_threshold)

    assert result["ConsistentIntervalsDetected"] == False
    assert result["IsPatternLikelyAutomated"] == False
