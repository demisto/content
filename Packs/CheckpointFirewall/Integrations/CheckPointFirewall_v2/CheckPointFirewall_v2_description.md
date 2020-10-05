Product Name: CheckPoint Firewall Product Type: Network Security Product Version: R80.30

Integration Overview Manage CheckPoint Firewall. Read information and to send commands to the Check Point Firewall server. 
This integration was integrated and tested with version R80.30 of CheckPoint SmartConsole.

How to configure the integration:

In the Smart Console, enable the web api: Management & Setting → Blades → Management API, Advanced Setting → All IP address

Enable sftp on your server CheckPoint guide to walk you through: https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk82281 

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CheckPoint_FW.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| server | Server URL \(e.g. example.net or 8.8.8.8\) | True |
| port | Server Port \(e.g. 4434\) | True |
| username | username | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

