## [Unreleased]
- Respect configured page limit when fetching new incidents.
- Added support for the ***expanse-get-domains-for-certificate*** command.
- Support Cloud Exposure types for incident fetching.

## [20.5.2] - 2020-05-26
- Added support for filtering incident creation by Expanse Exposure severity level.

## [20.5.0] - 2020-05-12
- Added support for the ***expanse-get-exposures*** command.

## [20.4.1] - 2020-04-29
Fixed an issue where incident polling did not behave as expected in some situations.

## [20.4.0] - 2020-04-14
  - Added support for pulling behavior data to create new incidents.
  - Added support for the ***expanse-get-behavior*** command.
  - Added support for the ***expanse-get-certificate*** command.

## [20.3.4] - 2020-03-30
  - Shortened the period of time that tokens are considered valid, to avoid authorization errors.
  - Fixed an issue related to the ***ip*** command where an error is generated if the API returns a partial response.
  - Added friendly values for various empty fields returned by the ***domain*** command.

## [20.3.3] - 2020-03-18
  - Updated the Authorization header for the Events API to use the correct token.
  - Added a User-Agent header to assist with diagnostics/debugging.

## [20.2.4] - 2020-02-25
-

## [19.11.1] - 2019-11-26
These notes will be published in the next release notes
