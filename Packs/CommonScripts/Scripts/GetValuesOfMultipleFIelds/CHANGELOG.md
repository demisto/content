## [Unreleased]


## [20.5.2] - 2020-05-26
-


## [20.4.0] - 2020-04-14
-


## [20.1.2] - 2020-01-22
#### New Script
The script receives a list of fields and a context key base path. For example, Key=demisto.result List=username,user and will get all of the values from demisto.result.username and demisto.result.user.
The Get field of the task must have the value ${.=[]}.