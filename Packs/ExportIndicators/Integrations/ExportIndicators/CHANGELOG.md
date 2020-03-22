## [Unreleased]
  - Added support for IP ranges and CIDR collapse
  - Added URL param *tr* - Indicates whether to collapse IPs to ranges or CIDRs.

## [20.3.3] - 2020-03-18
  - Added the *offset* parameter to the ***eis-update*** command.
  - Added support for the following inline URL parameters.
    - n - The number of indicators to fetch.
    - s - The first index from which to fetch indicators.
    - v - The output format for indicators.
    - q - The query that defines which indicators to fetch.
  - Improved test module functionality.


## [20.2.4] - 2020-02-25
Use the Export Indicators Service integration to export system indicators to a list (file) and supports enforcing basic authentication.
