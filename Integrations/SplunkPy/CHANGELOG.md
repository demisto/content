## [Unreleased]


## [20.1.2] - 2020-01-22
Added the ***splunk-submit-event-hec*** command.

## [20.1.0] - 2020-01-07
Fixed an issue with the access to a non-existing key when fetching non-ES events.

## [19.12.1] - 2019-12-25
Enhanced the execution speed of the ***splunk-search*** command.

## [19.11.0] - 2019-11-12
Increased the maximum fetch limit for Splunk.

## [19.10.2] - 2019-10-29
  - Improved handling of the *app context* parameter.
  - Fixed handling of arrays when converting notable events to incidents.

## [19.10.1] - 2019-10-15
- Added the *app* parameter, which is the app context of the namespace.
- Prettified the human readable of the search command.


## [19.10.0] - 2019-10-03
Added the *Earliest time to fetch* and *Latest time to fetch* parameters, which are the name of the Splunk fields whose value defines the query's earliest and latest time to fetch.


## [19.9.1] - 2019-09-18
-

## [19.9.0] - 2019-09-04
- Added the *Fetch limit* parameter to the instance configuration, which specified the maximum number of results to fetch.
