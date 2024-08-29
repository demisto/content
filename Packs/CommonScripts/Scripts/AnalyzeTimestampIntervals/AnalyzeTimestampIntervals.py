import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import statistics

def calculate_interval_differences(timestamps):
    if len(timestamps) < 2:
        return [], []

    # Sort the timestamps
    timestamps.sort()

    # Calculate the time differences between each consecutive pair
    intervals = [(timestamps[i + 1] - timestamps[i]) / 1000 for i in range(len(timestamps) - 1)]  # Convert to seconds

    # Calculate the differences between consecutive intervals
    interval_differences = [abs(intervals[i + 1] - intervals[i]) for i in range(len(intervals) - 1)]

    return intervals, interval_differences

def calculate_statistics(intervals):
    if not intervals:
        return None, None, None

    mean_interval = sum(intervals) / len(intervals)
    median_interval = statistics.median(intervals)  # Use statistics.median for accurate median calculation
    variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
    std_deviation = variance ** 0.5

    return mean_interval, median_interval, std_deviation

def analyze_intervals(timestamps, verbose, threshold=1.0):
    intervals, interval_differences = calculate_interval_differences(timestamps)

    if intervals:
        mean_interval, median_interval, std_deviation = calculate_statistics(intervals)

        result = {
            "TimestampCount": len(timestamps),
            "MeanIntervalInSeconds": mean_interval,
            "MedianIntervalInSeconds": median_interval,
            "StandardDeviationInSeconds": std_deviation,
            "IsPatternLikelyAutomated": False,
            "IsPatternConsistent": False
        }

        # Add verbose data if requested
        if verbose:
            result["IntervalsInSeconds"] = intervals
            result["IntervalDifferencesInSeconds"] = interval_differences

        # Use the user-defined or default threshold to determine conclusions
        if std_deviation < threshold:
            result["IsPatternLikelyAutomated"] = True  # Consistent intervals (likely automated)
        if abs(mean_interval - median_interval) < threshold:
            result["IsPatternConsistent"] = True  # Mean and median close (consistent pattern)

        return result
    else:
        return {"IsPatternLikelyAutomated": False, "IsPatternConsistent": False}

def create_human_readable(result, verbose):
    human_readable = "### Interval Analysis Results\n"
    human_readable += f"- **Number of Timestamps:** {result.get('TimestampCount')}\n"
    human_readable += f"- **Mean Interval (seconds):** {result.get('MeanIntervalInSeconds')}\n"
    human_readable += f"- **Median Interval (seconds):** {result.get('MedianIntervalInSeconds')}\n"
    human_readable += f"- **Standard Deviation (seconds):** {result.get('StandardDeviationInSeconds')}\n"
    human_readable += f"- **Is Pattern Likely Automated:** {result.get('IsPatternLikelyAutomated')}\n"
    human_readable += f"- **Is Pattern Consistent:** {result.get('IsPatternConsistent')}\n"

    if verbose:
        human_readable += "\n### Extra Data\n"
        human_readable += f"- **Intervals (seconds):** {result.get('IntervalsInSeconds')}\n"
        human_readable += f"- **Interval Differences (seconds):** {result.get('IntervalDifferencesInSeconds')}\n"

    return human_readable

def main():
    try:
        timestamps = demisto.args().get('timestamps')
        verbose = demisto.args().get('verbose', 'false').lower() == 'true'  # Get verbose argument, default is false
        threshold = float(demisto.args().get('threshold', 1.0))  # Get threshold argument, default is 1.0

        # Ensure timestamps are provided and are in a valid format
        if not timestamps:
            return_error("No timestamps provided.")

        if isinstance(timestamps, str):
            try:
                timestamps = [int(x.strip()) for x in timestamps.split(',')]  # Convert comma-separated string to list of integers
            except ValueError:
                return_error("Invalid timestamp format. Ensure all timestamps are integers.")

        result = analyze_intervals(timestamps, verbose, threshold)

        # Create human-readable output
        human_readable = create_human_readable(result, verbose)

        # Output the results to the war room and context
        demisto.results({
            "Type": 1,  # Human-readable entry
            "ContentsFormat": "markdown",
            "Contents": human_readable
        })
        demisto.setContext('IntervalAnalysis', result)

    except Exception as e:
        return_error(f"An error occurred: {str(e)}")

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
