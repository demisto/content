## [Unreleased]
  - Added **Endpoint** Common class.
  - Added a new function **auto_detect_indicator_type** which detects indicators. 
  - Fixed an issue where the **argToList** function did not behave as expected. This fix is breaking backward compatibility.

## [20.5.2] - 2020-05-26
  - Fixed IPv4 regex to only catch IPv4 addresses, not CIDR ranges.
  - Added a retry mechanism to the BaseClient.
  - Fixed an issue where the **appendContext** function did not behave as expected.


## [20.5.0] - 2020-05-12
  - Added retry mechanism to the BaseClient

## [20.4.1] - 2020-04-29
  - Deprecated the following enums: 
    - **entryTypes**
    - **formats**
    - **dbotscores**
  - Added new enums: 
    - **DBotScoreType** (replaces *dbotscores*)
    - **EntryFormat** (replaces *formats*)
    - **EntryType** (replaces *entryTypes*)
  - Added new classes to represent reputation outputs:
    - **DBotScore**
    - **IP**
    - **URL**
    - **CVE**
    - **File**
    - **Domain**
    - **WHOIS**
    - **CommandResults** (returns results to the War Room)
  - Added support for traceback in debug-log mode.

## [20.4.0] - 2020-04-14
  - Added the argument *ignore_auto_extract* to the ***return_outputs*** command.
  - Added a default value to the indicator timeline field **Category** when a value is not provided in an entry's timeline data.
  - Improved error message parsing of HTTP response in BaseClient.


## [20.3.4] - 2020-03-30
- Added support for successful empty responses (status code 204) in the base client.

## [20.3.3] - 2020-03-18
Added ***remove_empty_elements*** command.
Added ***datetime_to_string*** command.
Added ***safe_load_json*** command.
Added encoding from UTF-8 for Python 2.

## [20.3.1] - 2020-03-04
Added **DomainGlob** to the **FeedIndicatorType** class.
Added the *timeline* argument to the ***return_outputs*** convenience function.

## [20.2.3] - 2020-02-18
Added cveRegex to validate cve_id format.

## [20.2.0] - 2020-02-04
Added ***ip_to_indicator_type*** command.


## [20.1.2] - 2020-01-22
Added encode string results - safe handle unicode strings to demisto results

## [20.1.0] - 2020-01-07
 - Added the ***argToBoolean*** command, which takes a input value of type string or boolean and converts it to boolean.
 - Added the **batch** command, which takes an iterable and how many items to return and yields batches of that size.

## [19.12.0] - 2019-12-10
-

## [19.11.1] - 2019-11-26
BaseClient now uses the session function to maintain an open session with the server.

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

