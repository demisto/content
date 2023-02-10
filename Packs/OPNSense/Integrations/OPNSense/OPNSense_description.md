## OPNSense Firewall
Manage [OPNsense Firewall](https://opnsense.org/). For more information see OPNsense documentation.
OPNsense® is an open source, easy-to-use and easy-to-build HardenedBSD based firewall and routing platform.

### Create an API key in OPNsense

From the OPNsense GUI, create an API key for a user that will run PowerShell scripts:

- **Open System** > **Access** > **Users**.
- Click on a user that will be used for accessing the REST api.
- Under the section **API keys**, click on the Add **[+]** button to generate a key/secret pair.
- Download the txt file.
- Use the **key** and **secret** values to configure OPNsense integration.
