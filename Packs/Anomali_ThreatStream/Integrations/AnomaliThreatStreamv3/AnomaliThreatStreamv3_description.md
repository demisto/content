## Anomali Threat Stream v3
To access ThreatStream using the API, you need a user ID and API key. To get these credentials, register at [http://ui.threatstream.com](http://ui.threatstream.com).


#### Configure the Threshold Parameters
Each indicator have its threshold parameter.
This threshold will impact the calculation of an indicator's DBotScore.
The DBotScore of an indicator will be calculated based on this threshold as below:
if `confidence` value of the indicator will be above this threshold - the Score will be 3 (Malicious)
otherwise the DBotScore will 1 (Good).
if this threshold will not be specified - the DBotScore will calculate as following:
`confidence` > 65 - DBotScore value will be 3 (Malicious).
`confidence` between 25 and 65 - DBotScore value will be 2 (Suspicious).
`confidence` < 25 - DBotScore value will be 1 (Good).