## [Unreleased]
  - Added the following real-time response API commands:
    - ***cs-falcon-run-get-command***
    - ***cs-falcon-status-get-command***
    - ***cs-falcon-status-command***
    - ***cs-falcon-get-extracted-file***
    - ***cs-falcon-list-host-files***
    - ***cs-falcon-refresh-session***
    
  - Added the *target* argument to the ***cs-falcon-run-command*** command to support single and batch operations.
  - Fixed entry context keys.
  - Fixed an issue in the ***cs-falcon-get-script*** command where returned script entries replaced the entry identifying with *ID* in the *CrowdStrike.Script* path. This breaks backward compatibility.
  - Fixed an issue in the ***cs-falcon-list-scripts*** command where returned script entries replaced the entry identifying with *ID*s in the *CrowdStrike.Script* path. This breaks backward compatibility.

## [20.5.0] - 2020-05-12
-


## [20.4.0] - 2020-04-14
-


## [20.1.0] - 2020-01-07
-

## [19.12.1] - 2019-12-25
  - Added the following real-time response API commands:
    - ***cs-falcon-run-command***
    - ***cs-falcon-upload-script***
    - ***cs-falcon-get-script***
    - ***cs-falcon-delete-script***
    - ***cs-falcon-list-scripts***
    - ***cs-falcon-upload-file***
    - ***cs-falcon-delete-file***
    - ***cs-falcon-get-file***
    - ***cs-falcon-list-files***
    - ***cs-falcon-run-script***
  - Added the *email* argument to the ***cs-falcon-resolve-detection*** command, which can be used instead of the *ids* argument.
  - Fixed an issue where ***fetch incidents*** would not take milliseconds into consideration when updating last fetch time.

## [19.12.0] - 2019-12-10
Fixed an issue with ***fetch incidents*** which caused incident duplication.
