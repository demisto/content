## [Unreleased]


## [20.5.2] - 2020-05-26
-


## [20.3.4] - 2020-03-30
Fixed an issue that caused the playbook to fail when certain inputs were missing.

## [20.3.3] - 2020-03-18
Fixed an issue that caused the **Critical Assets** field to be populated partially or not at all.

## [19.10.1] - 2019-10-15
Added a task that sets all found critical assets to a new incident field.

## [19.9.1] - 2019-09-18
#### New Playbook
Determines if a critical assest is associated with the invesigation. The playbook returns a severity level of "Critical" if at least one critical asset is associated with the investigation.
Critical assets refer to: users, user groups, endpoints and endpoint groups.
