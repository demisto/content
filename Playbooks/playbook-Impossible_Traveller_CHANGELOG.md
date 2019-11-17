## [Unreleased]
The countries from which the user logged in, are now saved in incident fields and are displayed in the layout.

## [19.11.0] - 2019-11-12
#### New Playbook
This playbook investigates an event whereby a user has multiple application login attempts from various locations in a short time period (impossible traveler). The playbook gathers user, timestamp and IP information
associated with the multiple application login attempts.

The playbook then measures the time difference between the multiple login attempts and computes the distance between the two locations to verify whether it is possible the user could traverse the distance
in the amount of time determined. Also, it takes steps to remediate the incident by blocking the offending IPs and disabling the user account, if chosen to do so.