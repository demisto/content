## [Unreleased]

#### New Script
The script receives a list of fields and a context key base path. for example Key=demisto.result List=username,user and will get all the values from demisto.result.username and demisto.result.user.
  The Get of the task will have to be ${.=[]}

