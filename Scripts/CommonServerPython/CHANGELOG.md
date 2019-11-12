## [Unreleased]


## [19.11.0] - 2019-11-12
Fixed the IntegrationLogger auto-replace of sensitive strings.

## [19.10.1] - 2019-10-15
 - Added ***is_debug_mode*** wrapper function for checking if **debug-mode** is enabled. 
 - The ***return_outputs*** function can now return readable_output.

## [19.10.0] - 2019-10-03
  - Added requests debugging logger when `debug-mode=true`.
  - Added the ***BaseClient*** and ***DemistoException*** objects.
  - Added the ***build_dbot_entry*** and ***build_malicious_dbot_entry*** functions.
  - Added spaces between cells for ***tableToMarkdown*** function output, to prevent auto-extract over multiple cells.

## [19.9.1] - 2019-09-18
  - Added the ***parse_date_string*** function, which parses the date string to a datetime object.


## [19.9.0] - 2019-09-04
  - IntegrationLogger improvements.
  - Added support for IPv6 in the ***is_ip_valid*** command.
  - Added function ***get_demisto_version*** which return the Demisto server version and build number.


## [19.8.2] - 2019-08-22
  - Added return_warning command


## [19.8.0] - 2019-08-06
  - Added is_mac command

