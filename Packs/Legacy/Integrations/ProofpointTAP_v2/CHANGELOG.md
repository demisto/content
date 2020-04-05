## [Unreleased]


## [19.11.1] - 2019-11-26
Fixed the **fetch-incidents** function, which did not fetch duplicate values.
  - Added the **proofpoint-get-forensics** command. 
  - Added context outputs for the **proofpoint-get-events** command.

## [19.10.2] - 2019-10-29
Fixed the **fetch-incidents** function when the last_fetch time range is greater than 1 hour.

## [19.8.0] - 2019-08-06
  - Modified the fetch range for the first fetch to 1 hour (the Proofpoint TAP API maximum).
