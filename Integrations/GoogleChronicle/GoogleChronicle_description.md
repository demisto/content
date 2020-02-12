## Configure an API account on Google Chronicle
---
Your Customer Experience Engineer (CEE) will provide you with a [Google Developer Service Account Credential](https://developers.google.com/identity/protocols/OAuth2#serviceaccount) to enable the Google API client to communicate with the Backstory API
## Configure Google Chronicle Backstory on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Google Chronicle Backstory.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __User's Service Account JSON__
    * __First fetch time interval. The time range to consider for initial data fetch.(<number> <unit>, e.g., 1 day, 7 days, 3 months, 1 year)__
    * __How many incidents to fetch each time__
    * __Select the severity of asset alerts to be filtered for Fetch Incidents. Available options are 'High', 'Medium', 'Low' and 'Unspecified' (Default-No Selection)__
    * __Provide comma(',') separated categories (e.g. APT-Activity, Phishing). Indicators belonging to these "categories" would be considered as "malicious" when executing reputation commands.__
    * __Provide comma(',') separated categories (e.g. Unwanted, VirusTotal YARA Rule Match). Indicators belonging to these "categories" would be considered as "suspicious" when executing reputation commands.__
    * __Specify the "severity" of indicator that should be considered as "malicious" irrespective of the category.  If you wish to consider all indicators with High severity as Malicious, set this parameter to 'High'. Allowed values are 'High', 'Medium' and 'Low'. This configuration is applicable for reputation commands only.__
    * __Specify the "severity" of indicator that should be considered as "suspicious" irrespective of the category. If you wish to consider all indicators with Medium severity as Suspicious, set this parameter to 'Medium'. Allowed values are 'High', 'Medium' and 'Low'. This configuration is applicable for reputation commands only.__
    * __Specify the numeric value of "confidence score". If the indicator's confidence score is equal or above the configured threshold, it would be considered as "malicious". The value provided should be greater than the suspicious threshold. This configuration is applicable for reputation commands only.__
    * __Specify the numeric value of "confidence score". If the indicator's confidence score is equal or above the configured threshold, it would be considered as "suspicious". The value provided should be smaller than the malicious threshold. This configuration is applicable for reputation commands only.__
    * __Select the the confidence score level. If the indicator's confidence score level is equal or above the configured level, it would be considered as "malicious". This configuration is applicable for reputation commands only. Refer the "confidence score" level precedence UNKNOWN_SEVERITY < INFORMATIONAL < LOW < MEDIUM < HIGH__
    * __Select the confidence score level. If the indicator's confidence score level is equal or above the configured level, it would be considered as "suspicious". This configuration is applicable for reputation commands only. Refer the confidence score level precedence UNKNOWN_SEVERITY < INFORMATIONAL < LOW < MEDIUM < HIGH__
    * __Fetches incidents__: Enable this option to create Incidents in Demisto based on Backstory IOC Domain matches or Asset Alerts.
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
    * __Backstory Alert Type (Select the type of data to consider for fetch incidents)__: Select one of the type of data to be considered for Incidents creation. Available options are 'IOC Domain matches' and 'Assets with Alerts'. To fetch both type of data, make sure to create 2 separate instances with each option selected.
4. Click __Test__ to validate the URLs, token, and connection.

### Reputation Calculation Algorithm
Chronicle provides the intelligence context to the indicators as provided by the configured threat intelligence sources. The IOC context properties provided by Chronicle are Severity, Category and Confidence Score. To provide the user with control over the reputation calculation, the integration configuration provides fine control over these properties. 

* User can specify a list of categories, IoCs belonging to which should be considered as Malicious or Suspicious irrespective of its severity and confidence score. For example, if you wish to consider all the IoCs of Category 'Blocked' as Malicious, configure the category within instance configuration. 
* User can specify the Severity levels, indicators belonging to such severity would be considered as Malicious/Suspicious irrespective of the category and confidence score. 
* The confidence score provided by the Threat Intel sources can be numeric or a string representation(Low, High, Medium). The configuration allows separate options to control reputation calculation based on the confidence score returned. The user can configure the raw confidence score threshold values(separate configuration for numeric score and string representation) to control the reputation calculation.

Note: While evaluating the reputation of an indicator at multiple stages, if an indicator is found Malicious, the overall reputation remains 'Malicious'. For example, if a category is configured with both Malicious and Suspicious categories, the IoCs belonging to such category would be considered Malicious.