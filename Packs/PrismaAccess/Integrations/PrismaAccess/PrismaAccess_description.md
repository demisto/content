## Prisma Access Integration

The integration uses both the Panorama XML API and SSH into the PAN-OS CLI.

### Common parameters
The **Server Host or IP** parameter is required by both.

## SSH connection

The following commands require the SSH access to be configured:
 - prisma-access-active-users
 - prisma-access-cli-command
 - prisma-access-query

The SSH connection requires the **SSH Credentials for CLI**, **Password** and **SSH Port**  are provided.

SSH credentials should be your username and password for the PAN-OS CLI - they can be tested using a standalone SSH client to verify that you are able to connect to the CLI on the SSH port.


###  API connection

The following commands require the API access to be configured:
 - prisma-access-logout-user

The API connection requires the **API Port** and **API Key** parameters as well as a **Device Group** or **Vsys**.

To obtain an API Key, run the following REST command and copy the key:
**https://[PanoramaIP]/api/?type=keygen&user=[user]&password=[password]**

---
If you are connecting directly to a ...
####  Firewall: Configure the vsys
- The vsys is located in the Firewall URL; e.g, **https://<server>#device::<vsys>::device/setup**

####  Panorama: Configure a device group
- Access the Panorama UI.
- Go to Panorama --> Device Groups.
- Choose a device group name.
