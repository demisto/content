Collects metrics for a time window and the top 20 incident types in that period. Creates a small CSV with four tables 1) All Incidents 2) Closed Incidents 3) Open Duration 4) SLA timer durations.  The time window is expected to be a complete month specified by the "firstday" and "lastday" arguments. If partial months are used, the  open durations and SLA metrics is the average of the last set of incidents found, while incident counts are incremented.

The "slatimers" argument is a CSV list of  custom SLA timer fields to include in the metrics. 

       Example:  slatimers="customsla1,customsla2,customsla3"

The "filters" argument is a CSV list thats support the following field names to filter incidents on:  status, notstatus, type, severity, owner:

        "severity" values are: unknown, information, low, medium, high, critical
         "status or notstatus" values are: pending, active, done, archive
        "type" is the name of a single incident type
         "owner" is the name of a single incident owner

          Example: filters ="type=typea,status=done,severity=high"

If the "query" parameter is passed, the "filters" argument is ignored. The "query" parameter is a Lucene/Bleve search string in the incidents search box.  The "query" string is used to select which incidents - do not specify any dates. These are controlled by the "firstday" and  "lastday" parameters.

If the "windowstart" and "windowend" parameters are passed with the name of timer fields, the duration is calculated from windowend.endDate - windowstart.startDate for the "UserWindow" SLA metric.

The "mode" argument controls saving monthly statistics in this year's XSOAR list (a JSON object) as specified in the "thisyearlist" argument.  The default mode is "increment" and expects the time windows for each query to be contiguous with no gaps or overlaps in the time window specified by the "firstday" and "lastday" arguments. If the time windows overlap, then incidents will be double counted. If there are gaps between time windows, then incidents may be missed.  If the query needs to run and not update the saved statistics,  use "mode=noupdate".  In the event a month in the saved statistics becomes corrupted, this is corrected by using "mode=initialize" with the first day and the last day of the month to reset the values.

The "computeduration" argument allows the overall incident open duration to be computed from the created and closed dates versus using the openDuration field. Set to "yes" to use computed duration.  This is helpful when incidents do not have valid data in the openDuration field.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| firstday | First day to find incident occurrences. Example: "2023-03-01".  "2023-01" defaults to "2023-01-01". |
| lastday | Last day to find incident occurrences. Does not support a different year than the first day.Example: "2023-06-30".  "2023-01" defaults to "2023-01-31". |
| esflag | If using Elasticsearch, set this to "true".  Elasticsearch has a 10000 incident search limit and this flag reduces the search windows from 2 days to to 4 hours. |
| slatimers | CSV list of additional SLA timer fields to include in the metrics. Example: slatimers="customsla1,customsla2,customsla3". |
| filters | CSV list of incident filters. Example:   filters ="type=typea,status=done". |
| thisyearlist | List name to store this year's monthly result. |
| lastyearlist | List name to store last year's results. |
| mode | Controls the how statistics are saved to this years data list. |
| query | Query string for incidents using Lucene/Bleve. Do not include any date related fields - those are controlled by the "firstday" and "lastday" arguments.  Ignores the "filter" argument. |
| windowstart | Timer field name to use as the start time for a user defined duration. |
| windowend | Timer field name to use as the end time for a user defined duration. |
| computeduration | Compute the incident open duration from the created and closed dates. |

## Outputs

---
There are no outputs for this script.
