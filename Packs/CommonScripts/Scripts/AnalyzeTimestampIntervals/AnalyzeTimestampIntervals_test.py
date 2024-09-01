import pytest
from AnalyzeTimestampIntervals import calculate_interval_differences, calculate_statistics, analyze_intervals

def test_calculate_interval_differences():
    # Test with 10 timestamps and regular intervals (simulating an automated brute force attack)
    timestamps = [
        1724933689406, 1724933690406, 1724933691406, 1724933692406,
        1724933693406, 1724933694406, 1724933695406, 1724933696406,
        1724933697406, 1724933698406
    ]
    intervals, interval_differences = calculate_interval_differences(timestamps)
    assert intervals == [1.0] * 9  # 1 second intervals
    assert interval_differences == [0.0] * 8  # No difference between intervals

    # Test with 15 timestamps and irregular intervals
    timestamps = [
        1724933689406, 1724933700000, 1724933701000, 1724933705000,
        1724933710000, 1724933715000, 1724933720000, 1724933730000,
        1724933740000, 1724933750000, 1724933760000, 1724933770000,
        1724933780000, 1724933790000, 1724933800000
    ]
    intervals, interval_differences = calculate_interval_differences(timestamps)
    assert intervals == [10594, 1000, 4000, 5000, 5000, 5000, 10000, 10000, 10000, 10000, 10000, 10000, 10000, 10000]
    assert interval_differences == [9594, 3000, 1000, 0, 0, 5000, 0, 0, 0, 0, 0, 0, 0]

    # Test with 50 timestamps, random irregular intervals
    timestamps = [
        1724933689406 + i * 1054 for i in range(50)
    ]
    intervals, interval_differences = calculate_interval_differences(timestamps)
    assert len(intervals) == 49  # 49 intervals for 50 timestamps
    assert len(interval_differences) == 48  # 48 differences for 49 intervals

    # Test with 200 timestamps, increasing regular intervals
    timestamps = [
        1724933689406 + i * 1000 for i in range(200)
    ]
    intervals, interval_differences = calculate_interval_differences(timestamps)
    assert len(intervals) == 199  # 199 intervals for 200 timestamps
    assert len(interval_differences) == 198  # 198 differences for 199 intervals

def test_calculate_statistics():
    # Test with 50 regular intervals
    intervals = [1.0] * 50
    mean_interval, median_interval, std_deviation = calculate_statistics(intervals)
    assert mean_interval == 1.0
    assert median_interval == 1.0
    assert std_deviation == 0.0

    # Test with 15 irregular intervals
    intervals = [10594, 1000, 4000, 5000, 5000, 5000, 10000, 10000, 10000, 10000, 10000, 10000, 10000, 10000]
    mean_interval, median_interval, std_deviation = calculate_statistics(intervals)
    assert round(mean_interval, 2) == 7295.57
    assert median_interval == 10000
    assert round(std_deviation, 2) == 3095.23

    # Test with 100 random intervals
    intervals = [i * 100 for i in range(10, 110)]
    mean_interval, median_interval, std_deviation = calculate_statistics(intervals)
    assert round(mean_interval, 2) == 6000.0
    assert median_interval == 6000
    assert round(std_deviation, 2) == 2886.75

def test_analyze_intervals():
    # Test with 10 timestamps and regular intervals (likely automated pattern)
    timestamps = [
        1724933689406 + i * 1000 for i in range(10)
    ]
    result = analyze_intervals(timestamps, verbose=False, threshold=1.0)
    assert result["IsPatternLikelyAutomated"] is True
    assert result["IsPatternConsistent"] is True

    # Test with 15 timestamps and irregular intervals (non-automated, inconsistent pattern)
    timestamps = [
        1724933689406, 1724933700000, 1724933701000, 1724933705000,
        1724933710000, 1724933715000, 1724933720000, 1724933730000,
        1724933740000, 1724933750000, 1724933760000, 1724933770000,
        1724933780000, 1724933790000, 1724933800000
    ]
    result = analyze_intervals(timestamps, verbose=False, threshold=5000)
    assert result["IsPatternLikelyAutomated"] is False
    assert result["IsPatternConsistent"] is False

    # Test with 100 timestamps and increasing intervals
    timestamps = [
        1724933689406 + i * 1500 for i in range(100)
    ]
    result = analyze_intervals(timestamps, verbose=False, threshold=1500)
    assert result["IsPatternLikelyAutomated"] is True
    assert result["IsPatternConsistent"] is True

    # Test with 200 timestamps and regular intervals
    timestamps = [
        1724933689406 + i * 1000 for i in range(200)
    ]
    result = analyze_intervals(timestamps, verbose=False, threshold=1000)
    assert result["IsPatternLikelyAutomated"] is True
    assert result["IsPatternConsistent"] is True

    # Test with verbose output enabled for a mid-size set
    timestamps = [
        1724933689406 + i * 1054 for i in range(50)
    ]
    result = analyze_intervals(timestamps, verbose=True, threshold=2000)
    assert "IntervalsInSeconds" in result
    assert "IntervalDifferencesInSeconds" in result

if __name__ == "__main__":
    pytest.main()
