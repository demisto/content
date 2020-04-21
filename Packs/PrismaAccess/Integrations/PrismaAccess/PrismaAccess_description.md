The integration uses both the Panorama XML API and SSH into the PAN-OS CLI to retrieve certain data.
To obtain an API Key, run the following REST command and copy the key:
https://[PanoramaIP]/api/?type=keygen&user=[user]&password=[password]

SSH credentials should be your username and password - they can be tested using a standalone SSH client to verify that you are able to connect to the CLI on the SSH port.

---
### Firewall: Configure the vsys
- The vsys is located in the Firewall URL; e.g, https://<server>#device::<vsys>::device/setup

### Panorama: Configure a device group
- Access the Panorama UI.
- Go to Panorama --> Device Groups.
- Choose a device group name.
