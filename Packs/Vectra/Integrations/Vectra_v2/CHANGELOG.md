## [Unreleased]


## [20.5.0] - 2020-05-12
Fixed an issue where the ***fetch-incidents*** command failed due to incorrect date format.

## [20.4.1] - 2020-04-29
-


## [20.4.0] - 2020-04-14
-


## [19.11.0] - 2019-11-12
  - New version to support the new API version (tested on 2.1).
  - Added support for API token authentication. 
  - Added Proxy support.
  - Improved error handling and Context outputs.
  - Improved fetch incidents methodology and added Threshold parameters (Threat score, Certainty score, State).
  - Added the following commands:
    - ***vectra-search***: allows users to perform advanced search for Hosts and Detections
    - ***vectra-get-proxies***: retrieves the current list of proxy IP addresses
    - ***vectra-get-users***: lists all users
    - ***vectra-get-threatfeed***: lists all ThreatFeeds
