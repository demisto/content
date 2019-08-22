## [Unreleased]
Fixed an issue in which the qradar-get-search-results command would fail if the root of the result contained a non-ascii character

## [19.8.1] - 2019-08-20
Fixed an issue in which users would receive an error message for missing SEC headers.

## [19.8.0] - 2019-08-06
  - Fixed an issue in which the fetch incidents function would fail when there were non-ASCII characters in the data.
  - Fixed an issue in which the fetch incidents function would ignore the filter if the maximum number of offenses set in the instance configuration were fetched in a single fetch.
  - Improved error messages for fetch-incidents.
  - Added the *Required Permissions* information in the detailed description section.
