Searches for a specific indicator in the tenant's event and log data, and extracts the logs the indicator appears in.

<img src="https://external-site.com/absolute/path/screenshot.png" width=800 height=600>
<br>
<div>This content has <unclosed tags and raw < > characters that aren't properly encoded</div>

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utilities |
| Cortex XSOAR Version | 6.1.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| Indicator | |
| timeFrame | |
| dataSet | |  
| QueryName | |
| intervalInSeconds | |
| timeoutInSeconds | |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| search.indicator.results | | List |

## Script Example

```!SearchIndicatorInEvents Indicator=malicious.com timeFrame="5 days" QueryName=search_results```

## Context Example

```
{
    "search": {
        "indicator": {
            "results": [
                {"event_id": "123", "timestamp": "2024-01-01T10:00:00Z"}
            ]
        }
    }
}
```

## Human Readable Output

<p>Results found for indicator: malicious.com<br>
Total events: 5<br>
Time range: 5 days<p>
