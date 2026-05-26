The integration uses the Panorama XML API.
To obtain an API key, run the following CURL command and copy the key:
shell:
curl -H "Content-Type: application/x-www-form-urlencoded" -X POST https://[PanoramaIP]/api/\?type\=keygen -d 'user=[user]&password=[password]'


This integration enables you to manage the Palo Alto Networks Firewall and Panorama. For more information see the [PAN-OS documentation](https://docs.paloaltonetworks.com/pan-os.html).
This integration was integrated and tested with versions 8.xx, 9.xx, 10.xx and 11.xx of Palo Alto Firewall and Palo Alto Panorama.

## Use Cases

* Create custom security rules in Palo Alto Networks PAN-OS.
* Create and update address objects, address-groups, custom URL categories, and URL filtering objects.
* Use the URL Filtering category information from Palo Alto Networks to enrich URLs by checking the *use_url_filtering* parameter. A valid license for the Firewall is required.
* Get URL Filtering category information from Palo Alto. Request Change is a known Palo Alto limitation.
* Add URL filtering objects including overrides to Palo Alto Panorama and Firewall.
* Commit a configuration to Palo Alto Firewall and to Panorama, and push a configuration from Panorama to Pre-Defined Device-Groups of Firewalls.
* Block IP addresses using registered IP tags from PAN-OS without committing the PAN-OS instance. First you have to create a registered IP tag, DAG, and security rule, and commit the instance. You can then register additional IP addresses to the tag without committing the instance.


***Creating or updating the encryption master key of Palo Alto Networks Firewall or Panorama invalidates the current API key and requires obtaining a new one. All subsequent commands will raise an "Invalid Credential" error until a new API key is obtained and the integration instance is updated accordingly.***

For more information, visit the [Palo Alto Networks documentation](https://docs.paloaltonetworks.com/panorama).

---
You need to create a separate integration instance for Palo Alto Networks Firewall and Palo Alto Networks. Unless specified otherwise, all commands are valid for both Firewall and Panorama.

---
### Firewall: Configure the vsys
- The vsys is located in the Firewall URL; e.g., https://<server>#device::<vsys>::device/setup

### Panorama: Configure a device group
- Access the Panorama UI.
- Go to **Panorama** > **Device Groups**.
- Choose a device group name.

---
### Fetch Incidents
 The Panorama integration now supports fetch incidents.
The incidents are fetched according to a number of different optional log type queries. The log types are: **Traffic, Threat, URL, Data, Correlation, System, Wildfire, Decryption**.


 ##### Max incidents per fetch
The max incidents per fetch parameter specifies the maximum number of incidents to fetch **per** Log Type Query.

##### Log Type
 The queries that will be included during the fetch are decided according to the "Log Type" parameter (Multiple select dropdown).
- Selecting "All" will use all the log type queries in the fetch.
- To choose a specific set of queries, select their log types from the dropdown (make sure "All" option is unselected).

 ##### Log Type Query
- Each log type has its own query field in the instance configuration.
- Note that the default query values has some example text in it, make sure to enter a valid query.

##### Log Type Query Examples

- **Traffic**: `(addr.src in 'source') and (addr.dst in 'destination') and (action eq 'action')`
- **Threat**: `(severity geq 'high')`
- **URL**: `((action eq 'block-override') or (action eq 'block-url')) and (severity geq 'high')`
- **Data**: `((action eq 'alert') or (action eq 'wildfire-upload-success') or (action eq 'forward')) and (severity geq 'high')`
- **Correlation**: `(hostid eq 'host_id') and (match_time in 'last_x_time') and (objectname eq 'object_name') and (severity geq 'severity') and (src in 'source_address')`
- **System**: `(subtype eq 'sub_type') and (severity geq 'severity')`
- **Wildfire Submission**: `((action eq 'wildfire-upload-fail') or (action eq 'wildfire-upload-skip') or (action eq 'sinkhole'))`
- **Decryption**: `(app eq 'application') and (policy_name geq 'policy_name') and ((src in 'source') or (dst in 'destination'))`

##### Classifiers and Mappers

This integration supports a default Classifier (Panorama Classifier) and Mapper (Panorama Mapper) that handles incidents returned from the API.

---