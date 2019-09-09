## [Unreleased]


## [19.9.0] - 2019-09-04
  - Fixed an issue in which the ***qradar-get-search-results*** command failed when the root of the result contained a non-ascii character.
  - Fixed an issue in which the ***qradar-offense-by-id*** command failed if an SEC header was missing when trying to get an offense type.

## [19.8.2] - 2019-08-22
  - Fixed an issue in which users would receive an error message for missing SEC headers.
Fixed an issue in which the qradar-get-search-results command would fail if the root of the result contained a non-ascii character

## [19.8.0] - 2019-08-06
  - Fixed an issue in which the fetch incidents function would fail when there were non-ASCII characters in the data.
  - Fixed an issue in which the fetch incidents function would ignore the filter if the maximum number of offenses set in the instance configuration were fetched in a single fetch.
  - Improved error messages for fetch-incidents.
  - Added the *Required Permissions* information in the detailed description section.
