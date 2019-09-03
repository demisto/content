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