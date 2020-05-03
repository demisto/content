## [Unreleased]


## [20.4.1] - 2020-04-29
Fixed an issue where ***!file*** only accepted a lower case hash.
Added the *artifact* argument to the ***autofocus-search-samples*** command, which by default is set to "true" and retrieves the artifacts of the sample.


## [20.4.0] - 2020-04-14
-

## [20.3.4] - 2020-03-30
  - Fixed an issue where *get_search_results* mistakenly returns "no results".
  - Added the *SessionStart* context output to the following commands.
    - ***autofocus-search-samples***
    - ***autofocus-search-Sessions***
    - ***autofocus-top-tags-search***

## [20.3.3] - 2020-03-18
-

## [20.2.0] - 2020-02-04
Added the ***autofocus-get-export-list-indicators*** command.

## [20.1.0] - 2020-01-07
Fixed an issue where errors for the reputation commands: ***ip***, ***domain***, ***file***, ***url*** were not handled.

## [19.12.1] - 2019-12-25
Added four reputation commands.
  - ***ip***
  - ***domain***
  - ***file***
  - ***url***

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
