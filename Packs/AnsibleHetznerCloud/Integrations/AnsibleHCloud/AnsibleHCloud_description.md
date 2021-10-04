# Ansible Hetzner Cloud
Manage Hetzner Cloud resources.

# Authorize Cortex XSOAR for Hetzner Cloud

To use this integration you must generate an API token for your HCloud project.

1. Navigate to the [HCloud Console](https://console.hetzner.cloud/projects)
2. Select the project you wish to manage with XSOAR
3. Navigate to **Security** > **API Tokens** and generate an API token with Read & Write
4. Provide this token when you add a configure a Instance of this integration in XSOAR.

**NOTE**: If using 6.0.2 or lower version, put your API Token in the **Password** field, leave the **Username** field empty.
