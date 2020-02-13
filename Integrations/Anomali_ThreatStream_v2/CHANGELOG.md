## [Unreleased]
  - Added command ***threatstream-approve-import***
  - The ***threatstream-import-indicator-with-approval*** command now receives two new arguments ***tags*** ***trustedcircles***
  - The ***threatstream-create-model*** command now receives two new arguments ***import_sessions*** ***circles***
  - The ***threatstream-update-model*** command now receives two new arguments ***import_sessions*** ***circles***

## [19.12.0] - 2019-12-10
  - The ***threatstream-import-indicator-with-approval*** command now works as expected.
  - Added support for CSV values in reputation commands (***!ip***, ***!file***, ***!domain***, and ***!url***).

## [19.11.1] - 2019-11-26
Fixed an issue with DBotScore context data.

## [19.8.0] - 2019-08-06
  - Fixed an issue with the *description* argument in the ***threatstream-create-model*** command.
