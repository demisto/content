Extraction of all matches from a specified regular expression pattern from a provided string.  Returns an array of results.  This differs from RegexGroups in several ways:

* It returns all matches of the specified pattern, not just specific groups.  This is useful for extracting things using a pattern where the content of the source string is indeterminate, such as extracting all email addresses.
* Some "convenience" arguments have been added to enhance usability: multi-line, ignore_case, period_matches_newline
* Added a new argument, "error_if_no_match".  The script will not ordinarily throw an error if a match is not found but if not using as a transformer within a playbook, it may, in certain limited circumstances, be desirable to throw an error if the expression doesn't match.
* It uses the 'regex'  library, which supports more some more advanced regex functionality than the standard 're' library.  For more info, see https://pypi.org/project/regex/.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, string |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | Text to match against, e.g., The quick brown fox. |
| regex | Regex pattern to search \(in Python\), e.g., \(The\)\\s\(quick\).\*\(fox\). |
| multi_line | Process value in multiline mode.  See more information on re.MULTILINE, see https://docs.python.org/3/library/re.html. |
| ignore_case | Whether character matching will be case-insensitive. Default is "false". |
| period_matches_newline | Whether to make the '.' character also match a new line. Default is "false". |
| error_if_no_match | Only set to 'true' if used in a playbook task and you want that failure will return an error. |
| unpack_matches | Whether to unpack the tuple values of results. Default is "false". |

## Outputs
---
There are no outputs for this script.
