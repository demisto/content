## [Unreleased]
  - Added the *offset* parameter to the ***eis-update*** command.
  - Added support for the following inline URL parameters.
    - n - The number of indicators to fetch.
    - s - The first index from which to fetch indicators.
    - v - The output format for indicators.
    - q - The query that defines which indicators to fetch.
    - t - The type indicated in the mwg format.
    - sp - Whether to strip ports of urls in the panosurl format.
    - di - Whether to drop invalid urls in the panosurl format.
    - cd - The default category in the proxysg format.
    - ca - The categories to show in the proxysg format.
  - Added support for "McAfee Web Gateway", "panosurl" and "Symantec ProxySG" output formats.

## [20.2.4] - 2020-02-25
Use the Export Indicators Service integration to export system indicators to a list (file) and supports enforcing basic authentication.
