## [Unreleased]


## [19.12.1] - 2019-12-25
#### New Script
Extraction of all matches from a specified regular expression pattern from a provided string.  Returns an array of results.  This differs from RegexGroups in several ways:

* It returns all matches of the specified pattern, not just specific groups.  This is useful for extracting things using a pattern where the content of the source string is indeterminate, such as extracting all email addresses.
* Some "convenience" arguments have been added to enhance usability: multi-line, ignore_case, period_matches_newline
* Added a new argument, "error_if_no_match".  The script will not ordinarily throw an error if a match is not found but if not using as a transformer within a playbook, it may, in certain limited circumstances, be desirable to throw an error if the expression doesn't match.
* It uses the 'regex'  library, which supports more some more advanced regex functionality than the standard 're' library.  For more info, see https://pypi.org/project/regex/.