This is a thin wrapper around the `dateutil.parser.parse` function. It will parse a string containing a date/time stamp and return it in ISO 8601 format.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, date |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | Date value to convert. |
| dayfirst | Whether to interpret the first value in an ambiguous 3-integer date \(e.g. 01/05/09\) as the day \(\`\`True\`\`\) or month \(\`\`False\`\`\). If \`\`yearfirst\`\` is set to \`\`True\`\`, this distinguishes between YDM and YMD. |
| yearfirst | Whether to interpret the first value in an ambiguous 3-integer date \(e.g. 01/05/09\) as the year. If \`\`True\`\`, the first number is taken to be the year, otherwise the last number is taken to be the year. |
| fuzzy | Whether to allow fuzzy parsing, allowing for string like "Today is January 1, 2047 at 8:21:00AM". |
| add_utc_timezone | Whether to add UTC timezone to the date string returned in case offset-naive date was provided as input. |

## Outputs
---
There are no outputs for this script.


## Script Examples
### Example command
```!DateStringToISOFormat value="'05-11-2929'" dayfirst="true" yearfirst="true" fuzzy="true" add_utc_timezone="false"```
### Context Example
```json
{}
```

### Human Readable Output

>2929-11-05T00:00:00