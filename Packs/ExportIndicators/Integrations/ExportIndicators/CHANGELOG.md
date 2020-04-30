## [Unreleased]


## [20.4.1] - 2020-04-29
Removed the default initial value for the **Listen Port** parameter.

## [20.4.0] - 2020-04-14
  - Fixed an issue where running **On-Demand** mode an error appeared if export was not initialized.
  - Now when the *query* argument in the ***eis-update*** command is not supplied, the query from the integration parameters is used.
  - Added a feature to output *csv* and *XSOAR-csv* formats as textual web pages. This can be done by:
    - The integration configuration.
    - The URL parameter *tx*.
    - The *csv_text* argument for the ***eis-update*** command. 

## [20.3.4] - 2020-03-30
  - Added support for the following inline URL parameters.
    - t - The type indicated in the mwg format.
    - sp - Whether to strip ports of URLs in the panosurl format.
    - di - Whether to drop invalid URLs in the panosurl format.
    - cd - The default category in the proxysg format.
    - ca - The categories to show in the proxysg format.
    - tr - Whether to collapse IPs to ranges or CIDRs.
  - Added support for "McAfee Web Gateway", "PAN-OS URL" and "Symantec ProxySG" output formats.
  - Fixed and issue where "json", "json-seq" and "csv" formats did not match the original Minemeld formats.
  - Added support for "XSOAR json", "XSOAR json-seq" and "XSOAR csv" output formats.
  - Added a feature where "csv" and "XSOAR csv" formats now download a .csv file with the indicator information.
  - The "json-seq" and "XSOAR json-seq" functions now download a file with indicator information as a JSON sequence.
  - Added support for IP ranges and CIDR collapse.

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
