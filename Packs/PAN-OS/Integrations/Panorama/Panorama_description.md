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
Please make sure that the `log` XML API feature is enabled for your [Admin role](https://docs.paloaltonetworks.com/pan-os/9-0/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/enable-api-access.html)
You can apply additional (optional) filters for the fetch-incident query using the *Query to fetch logs* integration parameter. For more information on how to use the filter syntax:
- Visit [PAN-OS Filter Logs Documentation](https://docs.paloaltonetworks.com/pan-os/8-0/pan-os-admin/monitoring/view-and-manage-logs/filter-logs.html) for explanation about logs.
- Visit [PAN-OS Basics of Traffic Monitor Filtering](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClSlCAK) for explanation about logs filtering syntax.
#### Query Examples:
For log type `threat`: (severity geq medium)
For log type `traffic`:(category eq phishing) or (category eq command-and-control) or (category eq malware)