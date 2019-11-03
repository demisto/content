## [Unreleased]


## [19.10.2] - 2019-10-29
  - Fixed an issue in which ***fetch-incidents*** failed while enriching fetched offenses with source and destination IP addresses.
  - Fixed an issue in which ***qradar-delete-reference-set-value*** failed to delete reference sets with the "\\" character in their names.

## [19.9.1] - 2019-09-18
  - The *note_id* argument is now optional in the ***qradar-get-note*** command. If the *note_id* argument is not specified, the command will return all notes for the the offense.
  - Fixed an issue when closing an offense with the ***qradar-update-offense*** command, in which a user would specify a close reason, but an error was returned specifying that there was no close reason.  

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
