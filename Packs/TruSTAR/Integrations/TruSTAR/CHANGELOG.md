## [Unreleased]
- Breaking changes:
  - `normalized_triage_score` argument replaced by `priority_event_score` in `trustar-get-phishing-submissions` and `trustar-get-phishing-indicators` command.
  - `normalized_source_score` argument replaced by `normalized_indicator_score` in `trustar-get-phishing-indicators` command.
  - Updated context outputs on `trustar-get-phishing-submissions` and `trustar-get-phishing-indicators`.

- Non Breaking changes:
  - Fixed `from_time` description on `trustar-get-phishing-indicators` and `trustar-get-phishing-submissions` to '24 hours ago'
  - Added -1 to list of default values in `priority_event_score` on `trustar-get-phishing-submissions`
  - Added -1 to list of default values in `priority_event_score` and `normalized_indicator_score` on `trustar-get-phishing-indicators`



## [20.5.0] - 2020-05-12
-

## [20.4.1] - 2020-04-29
- Added 3 new commands:
  - ***trustar-get-phishing-submissions***
  - ***trustar-get-phishing-indicators***
  - ***trustar-set-triage-status***
- Deprecated the following commands:
  - ***file***
  - ***url***
  - ***ip***
  - ***domain***

## [20.4.0] - 2020-04-14
-


## [20.3.3] - 2020-03-18
-

## [19.10.1] - 2019-10-15
Fixed an issue where the ***trustar-search-indicator*** command returned an incorrect context output.
