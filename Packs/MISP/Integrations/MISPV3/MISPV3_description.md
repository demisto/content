## MISP V3

## Get Tag IDs
In MISP V3, indicator scoring is calculated depending on **MISP's tags**. In case no tags were found, the score
is calculated by the event's threat level ID.
* Indicators of attributes and events that have tags that are configured as malicious will be scored 3 (i.e., malicious).
* Indicators of attributes and events that have tags that are configured as suspicious will be scored 2 (i.e., suspicious).
* Indicators of attributes and events that have tags that are configured as benign will be scored 1 (i.e., benign).
* Indicators of attributes and events that don't have any tags that are configured as suspicious nor malicious will be scored by their events' threat level ID.
* Threat level ID with a value of 1, 2, or 3 will be scored 3 (i.e., malicious).
* Threat level ID with a value of 4 will be scored 0 (i.e., unknown).

When configuring an instance, you should set: 
- Malicious tag IDs with tag IDs that would be calculated as malicious.
- Suspicious tag IDs with tag IDs that would be calculated as suspicious.
- Benign tag IDs with tag IDs that would be calculated as benign.


Note:
* You can find tag IDs in: **<MISP_URL_SERVER>/tags/index**.
* In case the same tag appears in both Malicious tag IDs and Suspicious tag IDs lists, the indicator will be scored as **malicious**.
* Attribute tags (both malicious and suspicious) are stronger than event tags. 
 For example:

  Attribute 'A' from type file with value '123' has a suspicious tag. This 'A' attribute is part of event 'B' which has a malicious tag. Running the reputation command: ***!file file='123'*** will create a new indicator scored as **suspicious**.


### Configuration parameters
**NOTE**: If using version 6.0.2 or lower, put your API Key in the **Password** field, leave the **User** field empty.

Notice: Submitting indicators using the following commands of this integration might make the indicator data publicly available.
- ***url***
- ***domain***
See the vendor’s documentation for more details.