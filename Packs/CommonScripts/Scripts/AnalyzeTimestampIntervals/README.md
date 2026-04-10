Analyze a list of Unix timestamps in milliseconds, to detect simple patterns of consistency or high frequency. The script can aid in the investigation of multi-event alerts that contain a list of timestamps.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| timestamps | List of Unix timestamps \(in milliseconds\) representing time intervals. |
| max_intervals_per_window | The maximum number of intervals allowed within a specific time window. |
| interval_consistency_threshold | The threshold for determining how consistent the intervals are \(in seconds\). |
| verbose | If true, includes detailed interval information in the output. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IntervalAnalysis.TimestampCount | The total number of timestamps analyzed. | number |
| IntervalAnalysis.MeanIntervalInSeconds | The average time interval \(in seconds\) between consecutive timestamps. | number |
| IntervalAnalysis.MedianIntervalInSeconds | The median time interval \(in seconds\) between consecutive timestamps. | number |
| IntervalAnalysis.StandardDeviationInSeconds | The standard deviation of the time intervals \(in seconds\) between consecutive timestamps. | number |
| IntervalAnalysis.HighFrequencyDetected | Indicates whether a high frequency of intervals within a short time window was detected. | boolean |
| IntervalAnalysis.ConsistentIntervalsDetected | Indicates whether the intervals between timestamps were consistent based on the standard deviation threshold. | boolean |
| IntervalAnalysis.IsPatternLikelyAutomated | Indicates whether the pattern of intervals is likely automated based on analysis. Intervals with high frequency or consistency can suggest the use of an automation. | boolean |
