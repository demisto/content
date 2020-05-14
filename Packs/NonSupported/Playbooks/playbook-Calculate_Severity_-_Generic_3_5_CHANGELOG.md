## [Unreleased]


## [20.5.0] - 2020-05-12
#### New Playbook
Calculate incident severity by indicators reputation and user/endpoint membership in critical groups.

Note - current severity will be overwritten and new severity may be lower than the current one.

Playbook inputs:
* CriticalUsers - Comma separated array with usernames of critical users
* CriticalEndpoints - Comma separated array with hostnames of critical endpoints
* CriticalGroups - Comma separated array with DN of critical Active Directory groups
* QualysSeverity - A Qualys severity score (1-5) to calculate severity from