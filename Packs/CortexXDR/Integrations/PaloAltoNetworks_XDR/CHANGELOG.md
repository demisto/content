## [Unreleased]
- Added 6 commands.
  - ***xdr-blacklist-files***
  - ***xdr-whitelist-files***
  - ***xdr-quarantine-files***
  - ***xdr-get-quarantine-status***
  - ***xdr-restore-file***
  - ***xdr-endpoint-scan***
- Added get-quarantine-file-status playbook.
- Fixed a bug in the ***xdr-get-endpoint*** command where only the last endpoint was displayed in context.

## [20.4.1] - 2020-04-29
- Fixed an issue where the ***xdr-get-endpoints*** command failed when returning all the endpoints if no filters were given. 

## [20.4.0] - 2020-04-14
  - Fixed the issue where the ***xdr-isolate-endpoint*** command was failing when:  
    - The endpoint was disconnected. 
    - The isolation was still pending.  
    - The isolation cancellation was still pending.
  - Fixed the issue where ***xdr-unisolate-endpoint*** was failing when: 
    - The endpoint was disconnected.
    - The isolation was still pending.
    - The isolation cancellation was still pending.

## [20.2.0] - 2020-02-04
  - Fixed issue where trailing whitespaces would effect outputs. 
  - Implemented the Cortex XDR API v2. 
  -  Added 11 Traps commands.
    - ***xdr-isolate-endpoint***
    - ***xdr-unisolate-endpoint***
    - ***xdr-get-endpoints***
    - ***xdr-insert-parsed-alert***
    - ***xdr-insert-cef-alerts***
    - ***xdr-get-audit-management-logs***
    - ***xdr-get-audit-agent-reports***
    - ***xdr-get-distribution-versions***
    - ***xdr-get-distribution-url***
    - ***xdr-get-create-distribution-status***
    - ***xdr-create-distribution***
    

## [19.9.0] - 2019-09-04
Return a meaningful error when no query args are given for the !xdr-get-incidents command 


## [19.8.0] - 2019-08-06
Added instructions in the integration instance Detailed Description section how to generate an API Key, API Key ID, and how to copy the integration URL.
