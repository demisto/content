## [Unreleased]
- Fixed an issue with ***fetch-incidents*** when setting a *Fetch Limit*, it would drop older incidents if the fetched incidents number was greater than the limit.

## [19.12.1] - 2019-12-25
  - Fixed an issue where environment proxy effects the integration when even though no proxy should be used.


## [19.11.0] - 2019-11-12
  - Added the *Fetch Limit* parameter.
  - Fixed an issue where an unsupported timestamp format caused the integration to fail.

## [19.8.2] - 2019-08-22
  - Added the *fetch time* parameter
  - Improved error reporting for fetch incidents.
  - Fixed an issue in fetch incidents for cases in which an unsupported timestamp format was received.
