## [Unreleased]
-


## [20.3.4] - 2020-03-30
#### New Playbook
This playbook investigates a "Brute Force" incident by gathering user and IP information, calculating the incident severity based on the gathered information and information received from the user, and performs remediation.

The playbook handles the following use-cases:

* Brute Force IP Detected - A detection of source IPs that are exceeding a high threshold of rejected and/or invalid logins. 
* Brute Force Increase Percentage - A detection of large increase percentages in various brute force statistics over different periods of time.
* Brute Force Potentially Compromised Accounts - A detection of accounts that have shown high amount of failed logins with one successful login.

Used Sub-playbooks:
- IP Enrichment - Generic v2
- Account Enrichment - Generic v2.1
- Calculate Severity - Critical Assets v2
- Isolate Endpoint - Generic
- Block Indicators - Generic v2
