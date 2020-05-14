## [Unreleased]


## [20.5.0] - 2020-05-12
#### New Playbook
Run on a QRadar offense to get more information:

* Get all correlations relevant to the offense
* Get all logs relevant to the correlations (not done by default - set "GetCorrelationLogs" to "True")

Inputs:
* GetCorrelationLogs (default: False)
* MaxLogsCount (default: 20)