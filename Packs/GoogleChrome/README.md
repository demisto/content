# Google Chrome
 
<~XSIAM>
 
This pack includes Cortex XSIAM content.
 

## Overview

Google Workspace integration allows you to ingest logs and data from Google Workspace into Cortex XSIAM.

This integration supports the following data:

- __Google Chrome__ — Chrome browser and Chrome OS events included in the Chrome activity reports.

- __Admin Console__ — Account information about different types of administrator activity events included in the Admin console application's activity reports.

- __Google Chat__ — Chat activity events included in the Chat activity reports.

- __Enterprise Groups__ — Enterprise group activity events included in the Enterprise Groups activity reports.

- __Login__ — Account information about different types of login activity events included in the Login application's activity reports.

- __Rules__ — Rules activity events included in the Rules activity report.

- __Google drive__ — Google Drive activity events included in the Google Drive application's activity reports.

- __Token__ — Token activity events included in the Token application's activity reports.

- __User Accounts__ — Account information about different types of User Accounts activity events included in the User Accounts application's activity reports.

- __SAML__ — SAML activity events included in the SAML activity report.

- __Alerts__ — Alerts from the Alert Center API beta version, which is still subject to change.

- __Emails__ — Collects email data (not emails reports). All message details except email headers and email content (payload.body, payload.parts, and snippet).



## What does this pack do?

This pack provides various browser events monitoring and management such as user logins, passwords usages and websites access.

 
## Use Cases

1. __Password Management and Security:__
Prevent from users to use their passwords on dangerous/ unauthorized websites.
Preventing password reuse protect the organization from compromised accounts.

2. __Websites Access Management and File Downloading:__
Monitor and block accesses to malicious/ suspicious websites and control of harmful/ unwanted files downloading.

3. __Browser Extensions Management:__
Extensions management allows IT administrators to test and evaluate extension for the organization,  allow/ block certain extensions and force installed extensions. 





## Configure Google Workspace
 
To configure ingestion of data from Google Workspace follow the procedure below:
[Ingest Logs and Data from Google Workspace](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Ingest-Logs-and-Data-from-Google-Workspace)
 

- To configure Google Workspace you must have user with the corresponding permissions.
- To configure emails data ingestion you must set up compliance email account as mentioned in the above link.
 
## Configure Cortex XSIAM

1. Go to Configuration 
2. Select *Data Sources*
3. Search *Google Workspace*
4. Click on Connect
5. Click on the three dots on the right of the data source 
6. Add new instance
7. Name the log collection
8. Insert the service account key from previous step (Configuration on Server Side)
9. Select *Google Chrome* under Collect field
10. Add service account email
 
 
 
</~XSIAM>