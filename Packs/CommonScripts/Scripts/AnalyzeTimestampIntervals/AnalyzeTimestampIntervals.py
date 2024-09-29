import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import statistics


def calculate_interval_differences(timestamps):
    # Sort the timestamps
    timestamps.sort()

    # Calculate the time differences between each consecutive pair (in seconds)
    intervals = [(timestamps[i + 1] - timestamps[i]) / 1000 for i in range(len(timestamps) - 1)]  # Convert to seconds

    demisto.debug(f"Calculated intervals: {intervals}")
    return intervals


def check_high_frequency(timestamps, max_intervals_per_window, time_window=60):
    """ Check if there is a high number of intervals within a short time window (in seconds). """
    timestamps.sort()
    count_exceeds_threshold = False

    # Use a sliding window approach, ensuring no overlap
    for i in range(len(timestamps)):
        window_start = timestamps[i]
        window_end = window_start + (time_window * 1000)  # time_window in milliseconds

        count = sum(1 for t in timestamps[i:] if t <= window_end)  # Count events only in the current window

        if count > max_intervals_per_window:
            count_exceeds_threshold = True
            break

    return count_exceeds_threshold


def calculate_statistics(intervals):
    mean_interval = sum(intervals) / len(intervals)
    median_interval = statistics.median(intervals)
    std_deviation = statistics.stdev(intervals) if len(intervals) > 1 else 0

    return mean_interval, median_interval, std_deviation


def analyze_intervals(timestamps, verbose, max_intervals_per_window=30, interval_consistency_threshold=0.15):
    intervals = calculate_interval_differences(timestamps)

    result = {
        "TimestampCount": len(timestamps),
        "IsPatternLikelyAutomated": False
    }

    # Check for high frequency of intervals
    high_frequency = check_high_frequency(timestamps, max_intervals_per_window)

    # Calculate statistics
    mean_interval, median_interval, std_deviation = calculate_statistics(intervals)

    # Check for consistent intervals
    consistent_intervals = std_deviation < interval_consistency_threshold

    result.update({
        "MeanIntervalInSeconds": mean_interval,
        "MedianIntervalInSeconds": median_interval,
        "StandardDeviationInSeconds": std_deviation,
        "HighFrequencyDetected": high_frequency,
        "ConsistentIntervalsDetected": consistent_intervals
    })

    if verbose:
        result["IntervalsInSeconds"] = intervals

    # Determine if pattern is likely automated in a unified result. High frequency or intervals that are more or less the same
    # can suggest automation.
    if high_frequency or consistent_intervals:
        result["IsPatternLikelyAutomated"] = True

    return result


def create_human_readable(result, verbose):
    headers = [
        "TimestampCount",
        "MeanIntervalInSeconds",
        "MedianIntervalInSeconds",
        "StandardDeviationInSeconds",
        "HighFrequencyDetected",
        "ConsistentIntervalsDetected",
        "IsPatternLikelyAutomated",
    ]
    if verbose:
        headers.append("IntervalsInSeconds")
    return tableToMarkdown(
        "Interval Analysis Results",
        result,
        headers=headers,
        headerTransform=pascalToSpace,
    )


def main():  # pragma: no cover
    try:
        timestamps = argToList(demisto.args()['timestamps'], transform=int)
        verbose = argToBoolean(demisto.args().get('verbose') or False)

        if len(timestamps) < 2:
            raise ValueError(f"The number of timestamps should exceed 2. The number of timestamps given was {len(timestamps)}.")

        # Get thresholds from arguments
        max_intervals_per_window = int(demisto.args().get('max_intervals_per_window', 30))
        interval_consistency_threshold = float(demisto.args().get('interval_consistency_threshold', 0.1))

        result = analyze_intervals(timestamps, verbose, max_intervals_per_window, interval_consistency_threshold)

        # Create human-readable output
        human_readable = create_human_readable(result, verbose)

        # Prepare the CommandResults object
        command_results = CommandResults(
            outputs_prefix='IntervalAnalysis',
            outputs_key_field='TimestampCount',
            outputs=result,
            readable_output=human_readable,
            raw_response=result
        )

        # Return results
        return_results(command_results)

    except Exception as e:
        return_error(f"An error occurred: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
