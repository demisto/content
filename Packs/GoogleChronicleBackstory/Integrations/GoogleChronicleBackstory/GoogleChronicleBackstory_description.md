## Configure an API account on Google Chronicle
---
Your Customer Experience Engineer (CEE) will provide you with a [Google Developer Service Account Credential](https://developers.google.com/identity/protocols/OAuth2#serviceaccount) to enable the Google API client to communicate with the Backstory API.

Starting from "First fetch time", XSOAR will retrieve "How many incidents to fetch each time" at every "Incident Fetch Interval" period.

### Reputation Calculation Algorithm
Chronicle provides the intelligence context to the indicators as provided by the configured threat intelligence sources. The IOC context properties provided by Chronicle are Severity, Category and Confidence Score. To provide the user with control over the reputation calculation, the integration configuration enables granular control over these properties. 

* Users can specify a list of categories, IoCs belonging to which should be considered as Malicious or Suspicious irrespective of its severity and confidence score. For example, if you want to consider all the IoCs of Category 'Blocked' as Malicious, configure the category within instance configuration. 
* Users can specify the Severity levels, indicators belonging to such severity would be considered as Malicious/Suspicious irrespective of the category and confidence score. 
* The confidence score provided by the Threat Intel sources can be numeric or a string representation (Low, Medium, or High). The configuration allows separate options to control reputation calculation based on the returned confidence score. The user can configure the raw confidence score threshold values(separate configuration for numeric score and string representation) to control the reputation calculation.

Note: While evaluating the reputation of an indicator at multiple stages, if an indicator is found to be Malicious, the overall reputation remains 'Malicious'. For example, if a category is configured with both Malicious and Suspicious categories, the IoCs belonging to such category would be considered Malicious.