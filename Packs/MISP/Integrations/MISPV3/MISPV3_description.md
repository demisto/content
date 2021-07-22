## MISP V3

## Get Tag IDs
In MISP V3, indicator scoring calculated depending on **MISP's tags**. In case no tags were found, the score
is calculated by the event's threat level id.
* Indicators of attributes and Events that have tags which configured as malicious will be scored 3 (i.e malicious).
* Indicators of attributes and Events that have tags which configured as suspicious will be scored 2 (i.e suspicious).
* Indicators of attributes and Events that don't have any tags configured as suspicious nor malicious will be scored by their events' threat level id.
* Threat level id with value 1, 2 or 3 will be scored 3 (i.e malicious).
* Threat level id with value 4 will be scored 0 (i.e unknown).

When configure an instance you should set: 
1. Malicious tag IDs with tag IDs that would be calculated as malicious.
2. Suspicious tag IDs with tag IDs that would be calculated as suspicious.

Note:
* You can find tag's ID in: **<MISP_URL_SERVER>/tags/index**.
* In case the same tag appears in both Malicious tag IDs and Suspicious tag IDs lists the indicator will be scored as **malicious**.
* Attributes tags (both malicious and suspicious) are stronger than events' tags. 
 For example:
a. Attribute 'A' from type file with value '123' has a suspicious tag
b. This 'A' attribute is part of the event 'B' which has a malicious tag.
c. Running the reputation command: !file file='123' will create a new indicator scored as **suspicious**.


### Configuration params
**NOTE**: If using 6.0.2 or lower version, put your API Key in the **Password** field, leave the **User** field empty.