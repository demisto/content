## [Unreleased]
  - Fixed an issue encountered by users who used API token without username/password, where they would sometimes encounter an error about missing SEC header.

## [19.8.0]
* Fixed a bug where sometimes fetch-incidents would fail due to a non-ASCII character in the data.
* Fixed a bug where fetch-incident would ignore filter if the max amount of offenses set in the instance configuration were fetched in a single fetch.
* Made fetch-incidents error messages more informative.
* Added *Required Permissions* section in detailed description
