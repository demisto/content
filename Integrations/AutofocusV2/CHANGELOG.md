## [Unreleased]


## [19.11.0] - 2019-11-12
Added descriptions to the ***autofocus-tag-details*** command.

## [19.10.0] - 2019-10-03
  - Improved handling of empty responses for the  ***autofocus-samples-search*** and ***autofocus-sessions-search*** commands.


## [19.9.1] - 2019-09-18
Added several arguments to the ***autofocus-samples-search*** and ***autofocus-sessions-search*** commands.
  - *file_hash*
  - *domain*
  - *ip*
  - *url*
  - *wildfire_verdict*
  - *first_seen*
  - *last_updated*

## [19.9.0] - 2019-09-04
  - Updated Palo Alto Networks AutoFocus V2 Indicators context outputs to support version 5.0.

## [19.8.2] - 2019-08-22
  - Added *tagGroups* output to ***autofocus-samples-search-results*** command.
  - Improved handling of cases in which unknown tags are retrieved from the ***autofocus-tag-details*** command.


## [19.8.0] - 2019-08-06
  - Added to context the status of commands with the following prefixes: ***autofocus-samples-search***, ***autofocus-sessions-search***, and ***autofocus-top-tags***.
  - Improved error handling for cases of no report in the ***autofocus-sample-analysis*** command.
  - Improved error handling for retrieving a pending query in the ***autofocus-samples-search-results*** command.
