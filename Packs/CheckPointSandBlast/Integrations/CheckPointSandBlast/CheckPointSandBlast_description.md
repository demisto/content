# Check Point Threat Emulation (SandBlast)
Uploads files using polling. The service supports Microsoft Office files, as well as PDF, SWF, archives and executables. Active content will be cleaned from any documents that you upload (Microsoft Office and PDF files only). Queries on existing IOCs, file status, analysis, reports. Downloads files from the database. Supports both appliance and cloud. Supported Threat Emulation versions are any R80x.

# See the API Documentation
The API documentation can be found in: [Check Point Threat Prevention API](https://sc1.checkpoint.com/documents/TPAPI/CP_1.0_ThreatPreventionAPI_APIRefGuide/html_frameset.htm).

# Access the Integration
The integration supports access through appliance and cloud.
Both appliance and cloud require a URL and an API key to access. The appliance URL must specify port 18194 as follows: https://<service_address>:18194.

# Polling Command
The **Upload** command supports polling, which is done through the **Query** command. Once polling is done, a full analysis report is returned to the user.

# Integration Commands
Appliance and cloud both support the **Upload**, **Query** and **Download** commands. The **Quota** command is only supported on cloud.