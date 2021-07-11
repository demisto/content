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

### Fetch incidents
To start fetching incidents, enable the *Long running instance* parameter. This will start a long-running process that will fetch incidents periodically.
Depending on the system load, the initial fetch might take a long time.

#### Query to fetch logs
You can apply additional (optional) filters for the fetch-incident query using the *Query to fetch offenses* integration parameter. For more information on how to use the filter syntax: 
- Visit [QRadar Filter Syntax Documentation](https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.3/com.ibm.qradar.doc/c_rest_api_filtering.html) for explanation about filter syntax.
- Visit [QRadar Offense Documentation](https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--siem-offenses-GET.html) for a list of all possible fields to be used in the filter.

#### Reset the "last run" timestamp
To reset fetch incidents, run the ***panorama-reset-last-run*** command - This will reset the fetch to its initial state. (Will try to fetch the first available offense).


#### Mapping limitations for Cortex XSOAR users below 6.0.0
* For Cortex XSOAR users below 6.0.0 version, using 'Pull from instance' option when creating a new mapper is not supported.