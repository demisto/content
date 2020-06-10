## [Unreleased]
- Fixed an issue where URL screenshots did not show in the layout.
- Merged 2 conditions into 1 to clean up playbook.

## [20.5.2] - 2020-05-26
-


## [19.11.1] - 2019-11-26
Fixed an issue where Rasterize would attempt to run even if inactive.

## [19.10.2] - 2019-10-29
#### New Playbook
Provides a basic response to phishing incidents. Playbook features:
- Calculates reputation for all indicators
- Extracts indicators from email attachments
- Calculates severity for the incident based on indicator reputation
- Updates reporting user about investigation status
- Allows manual remediation of the incident