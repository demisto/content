The integration uses the Panorama XML API
To obtain an API Key, run the following REST command and copy the key:
https://[PanoramaIP]/api/?type=keygen&user=[user]&password=[password]

For more information, visit the [Palo Alto Networks documentation](https://www.paloaltonetworks.com/documentation).

---
You need to create a separate integration instance for Palo Alto Networks Firewall and Palo Alto Networks. Unless specified otherwise, all commands are valid for both Firewall and Panorama.

---
### Firewall: Configure the vsys
- The vsys is located in the Firewall URL; e.g, https://<server>#device::<vsys>::device/setup

### Panorama: Configure a device group
- Access the Panorama UI.
- Go to Panorama --> Device Groups.
- Choose a device group name.

---
### Fetch Incidents
Panorama integration now supports fetch incidents.
The incidents are fetched according to a number of deferent optional log type queries. The log types are: **Traffic, Threat, URL, Data, Correlation, System, Wildfire, Decryption**.


##### Max incidents per fetch
The max incidents per fetch parameter specifies the maximum number of incidents to fetch **per** Log Type Query.

##### Log Type 
The queries that will be included during the fetch are decided according to "Log Type" parameter (Multiple select dropdown).
- Selecting "All" will use all the log type queries in the fetch.
- To choose a specific set of queries, select their log types from the dropdown (make sure "All" option is unselected).

##### Log Type Query
- Each log type has its own query field in the instance configuration. 
- Note that the default query values has some example text in it, make sure to enter a valid query.

##### Classifiers and Mappers

This integration supports a default Classifier (Panorama Classifier) and Mapper (Panorama Mapper) That handles incidents returned from the API.

---



[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/panorama)