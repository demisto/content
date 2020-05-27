## [Unreleased]


## [20.5.2] - 2020-05-26
-

## [20.5.0] - 2020-05-12
  - Simplified the process that gets details of the user's manager.
  - Fixed a potential error with running Active Directory commands when the integration is disabled.

## [20.3.4] - 2020-03-30
Fixed an issue with sending an email to the manager of the user.

## [20.3.3] - 2020-03-18
-

## [19.11.1] - 2019-11-26
The countries from which the user logged in are now saved in incident fields and are displayed in the layout.

## [19.11.0] - 2019-11-12
#### New Playbook
This playbook investigates an event whereby a user has multiple application login attempts from various locations in a short time period (impossible traveler). The playbook gathers user, timestamp and IP information
associated with the multiple application login attempts.

The playbook then measures the time difference between the multiple login attempts and computes the distance between the two locations to verify whether it is possible the user could traverse the distance
in the amount of time determined. Also, it takes steps to remediate the incident by blocking the offending IPs and disabling the user account, if chosen to do so.
