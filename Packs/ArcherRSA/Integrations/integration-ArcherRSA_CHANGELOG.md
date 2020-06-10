## [Unreleased]


## [20.5.2] - 2020-05-26
- Fixed an issue where several commands would not work as expected in case they were performed on app ID 411.
- Fixed an issue where type 4 fields were not displayed in ***archer-search-records*** command results.


## [20.3.3] - 2020-03-18
Fixed an issue where the following commands failed on numeric incident IDs.
  - ***archer-update-record***
  - ***archer-delete-record*** 
  - ***archer-upload-file***
  - ***archer-add-to-detailed-analysis***
  - ***archer-get-record***

## [19.12.1] - 2019-12-25
Fixed an issue where reports generated from the **GenerateInvestigationReport** script failed to upload to RSA Archer.

## [19.12.0] - 2019-12-10
- Fixed an issue with the retrieval of app IDs for applications with reverse field mapping.
- Added support for multiselect fields on the ***archer-create-record*** and ***archer-update-record*** commands.
- Added support for specifying users in type 8 fields on the ***archer-create-record*** and ***archer-update-record*** commands.

## [19.11.1] - 2019-11-26
Fixed an issue with the presentation of users display names.

## [19.11.0] - 2019-11-12
- Fixed an issue in the Archer fetch incidents offset.
- Fixed an issue in the fetched incidents details.
- Improved errors and added debug logs.

## [19.10.2] - 2019-10-29
Fixed the default field on which the search is performed.

## [19.10.1] - 2019-10-15
Added support for European timestamps.
