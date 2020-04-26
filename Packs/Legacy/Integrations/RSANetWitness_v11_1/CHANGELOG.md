## [Unreleased]
-


## [20.4.0] - 2020-04-14
-


## [20.3.3] - 2020-03-18
Fixed an issue with the ***get-incident*** command when the returned sources attribute is set to "[null]". Applicable to NetWitness 11.4.

## [20.2.3] - 2020-02-18
- Fixed an issue with ***fetch-incidents*** where setting a *Fetch Limit* would drop older incidents if the number of the fetched incidents was greater than the limit.
- Added the new argument *pageNumber* to  the ***netwitness-get-incidents*** command. The new argument allows the user to get incidents from a specific page and is intended to be used with limit argument.

## [19.12.1] - 2019-12-25
  - Fixed an issue where environment proxy effects the integration when even though no proxy should be used.


## [19.11.0] - 2019-11-12
  - Added the *Fetch Limit* parameter.
  - Fixed an issue where an unsupported timestamp format caused the integration to fail.

## [19.8.2] - 2019-08-22
  - Added the *fetch time* parameter
  - Improved error reporting for fetch incidents.
  - Fixed an issue in fetch incidents for cases in which an unsupported timestamp format was received.
