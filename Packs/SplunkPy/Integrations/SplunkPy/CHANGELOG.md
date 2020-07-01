## [Unreleased]
- Added the ***splunk-kv-store-collection-create*** command, which creates a new KV store.
- Added the ***splunk-kv-store-collection-config*** command, which used to configure the KV store fields.
- Added the ***splunk-kv-store-collection-add-entries*** command, which creates a new KV store entry.
- Added the ***splunk-kv-store-collections-list*** command, which print all KV stores.
- Added the ***splunk-kv-store-collection-data-list*** command, which returns the KV store data.
- Added the ***splunk-kv-store-collection-data-delete*** command, which deletes the data in a KV store.
- Added the ***splunk-kv-store-collection-delete*** command, which deleted a KV store.
- Added the ***splunk-kv-store-collection-search-entry*** command, which returns the KV store data for specific query.
- Added the ***splunk-kv-store-collection-delete-entry*** command, which deletes the KV store data with specific query.

## [20.5.2] - 2020-05-26
Added support for HTTPS handler, which uses tbhe Python **requests** library. 

## [20.4.0] - 2020-04-14
-
- Added the ***splunk-job-status*** command, which checks the status of a job.

## [20.3.4] - 2020-03-30
- Added the **Replace with Underscore in Incident Fields** parameter key, which replaces problematic characters (e.g., ".") with underscores ("\_") in context keys.
- Added ***First fetch timestamp*** parameter which indicates from which date and time should incidents be fetched.
- Fixed an issue where ***splunk-search*** presented the table headers in alphabetical order instead of the query order.

## [20.3.3] - 2020-03-18
Fixed an issue in the test command, which caused an out of memory error. 

## [20.3.1] - 2020-03-04
- Fixed an issue where ***fetch-incidents*** did not work as intended.
- Fixed an issue where ***splunk-parse-raw*** cut the last character of parsed fields.

## [20.2.4] - 2020-02-25
Added support for comma-separated values in the ***splunk-parse-raw*** command.

## [20.2.3] - 2020-02-18
Added the *app* argument to the ***splunk-job-create*** and ***splunk-search*** commands.

## [20.2.0] - 2020-02-04
- The Test button now tests the fetch incidents function when the *Fetch incidents* option is selected.
- Fixed an issue in the *Splunk notable events ES query* parameter where the time parameter was not passed to the table in Splunk.

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
