## [Unreleased]
-

## [19.9.0] - 2019-09-04
 - New command `!sep-identify-old-clients` which identifies endpoints with a running
  version that is inconsistant with the target version or the desired version (as optional argument).
 - New argument added to `!sep-endpoints-info`. Now it's possible to specify a group to search.
 - New context outputs for `!sep-endpoints-info`:
    * Group
    * RunningVersion
    * TargetVersion
    * PatterIdx
    * OnlineStatus
    * UpdateTime