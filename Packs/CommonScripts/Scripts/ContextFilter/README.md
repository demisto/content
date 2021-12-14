Filters context keys by applying one of the various available manipulations and stores a new context key. The resulting context key will not be available automatically but you can still specify it as an option.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Utility |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| data | The data to apply the filter on. |
| filterType | The type of filter to apply. Can be, "upper", "lower", "join", "split", "index", "substr", "trim", "regex", or "replace". |
| filter | The data for the filter. Can be, "join" - the join string between elements (this is optional. The default is ','), "split" - the string on which to split (This is optional. The default is ','), "index" - the index of the array to return (This is optional. The default 0), "substr" - the from (inclusive) and length (This is optional. The default is to end of string), "regex" - the regular expression to match, "replace" - a regular expression to replace and with what. |
| out | The name of the context output parameter that should be written to. |
| additional | The additional arguments to add to filter. For example, flags for regex. Flags, replace string for replace. Length for substr. |

## Outputs
---
There are no outputs for this script.
