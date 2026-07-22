# Anomali Threat Stream v3
To access ThreatStream using the API, you need a user ID and API key. To get these credentials, register at [http://ui.threatstream.com](http://ui.threatstream.com).


#### Configure Indicator Threshold Parameters
Each indicator has a threshold parameter that impacts the indicator's DBotScore calculation.
The indicator DBotScore is calculated based on the threshold parameter as follows:
If the indicator `confidence` value is above the threshold parameter value, the Score is set to 3 (Malicious)
Otherwise the DBotScore is set to 1 (Good).
If the threshold parameter value is not specified, the DBotScore is calculated as follows:
If the indicator `confidence` > 65, the DBotScore value is set to 3 (Malicious).
If the indicator `confidence` is between 25 and 65, the DBotScore value is set to 2 (Suspicious).
If the indicator `confidence` < 25, the DBotScore value is set to 1 (Good).
