## [Unreleased]


## [19.10.1] - 2019-10-15
Fixed an issue where current incident severity was not always taken into account.

## [19.9.1] - 2019-09-18
#### New Playbook
Calculate and assign the incident severity based on the highest returned severity level from the following calculations:

- DBotScores of indicators
- Critical assets
- Email authenticity
- Current incident severity
