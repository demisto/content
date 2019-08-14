## [Unreleased]
  - Fixed an issue encountered by users who used API token without username/password, where they would sometimes encounter an error about missing SEC header.

## [19.8.0] - 2019-08-06
  - Fixed an issue in which the fetch incidents function would fail when there were non-ASCII characters in the data.
  - Fixed an issue in which the fetch incidents function would ignore the filter if the maximum number of offenses set in the instance configuration were fetched in a single fetch.
  - Improved error messages for fetch-incidents.
  - Added the *Required Permissions* information in the detailed description section.
