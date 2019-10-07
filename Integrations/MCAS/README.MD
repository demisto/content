# Microsoft Cloud Application Security (MCAS) Azure and O365 alert and activity integration ## Use Cases * Retrieve alerts from MCAS platform (includes Azure and O365 alerting enabled in MCAS) * Look up threat IPs (published IOCs or otherwise) that are associated with MCAS activity or alerting * Query recent MCAS activities by username ## Detailed Description Populate this section with the .md file contents for detailed description. ## Prerequisites 1\. MCAS Portal URL 2\. API Key ### Generate an API Token 1\. On the **Settings** menu, select **Security extensions** and then **API tokens** 2\. Click the plus icon, **Generate new token** and provide a name to identify the token in the future, and click **Next**. 3\. Copy the token value and save it somewhere for recovery - if you lose it you need to regenerate the token. The token has the privileges of the user who issued it. For example, a security reader can't issue a token that can alter data. 4\. You can filter the tokens by status: Active, Inactive, or Generated. * Generated are tokens that have never been used. * Active are tokens that were generated and were used within the past seven days. * Inactive were used but there was no activity in the last seven days. 6\. After you generate a new token, you'll be provided with a new URL to use to access the Cloud App Security portal. ## Configure Microsoft Cloud App Security on Demisto 1\. Navigate to **Settings** > **Integrations**  > **Servers & Services**. 2\. Search for Microsoft Cloud App Security. 3\. Click **Add instance** to create and configure a new integration instance. 4\. Click **Test** to validate the new instance. ## Commands You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details. 1\. mcas-lookup-ip: mcas-lookup-ip 2\. mcas-lookup-user: mcas-lookup-user 3\. mcas-list-alerts: mcas-list-alerts ### 1\. mcas-list-alerts List MCAS Alerts ##### Base Command `mcas-list-alerts` ##### Required Permissions The following permissions are required for all commands. * Read ##### Input

<table style="width:750px" border="2" cellpadding="6">

<thead>

<tr>

<th>**Argument Name**</th>

<th>**Description**</th>

<th>**Required**</th>

</tr>

</thead>

<tbody>

<tr>

<td>limit</td>

<td>Max number of alerts to return (default is 20)</td>

<td>Optional</td>

</tr>

<tr>

<td>severity</td>

<td>Severity of alerts to display (default is All)</td>

<td>Optional</td>

</tr>

</tbody>

</table>

##### Context Output

<table style="width:750px" border="2" cellpadding="6">

<thead>

<tr>

<th>**Path**</th>

<th>**Type**</th>

<th>**Description**</th>

</tr>

</thead>

<tbody>

<tr>

<td>McasAlert.ID</td>

<td>string</td>

<td>Root ID of Alert</td>

</tr>

<tr>

<td>McasAlert.Title</td>

<td>string</td>

<td>Alert Name</td>

</tr>

<tr>

<td>McasAlert.Description</td>

<td>string</td>

<td>Alert Description</td>

</tr>

<tr>

<td>McasAlert.PolicyName</td>

<td>string</td>

<td>Name of Alert Policy</td>

</tr>

<tr>

<td>McasAlert.PolicyType</td>

<td>string</td>

<td>Type of Alert Policy</td>

</tr>

<tr>

<td>McasAlert.Timestamp</td>

<td>date</td>

<td>Date and time the alert occurred</td>

</tr>

<tr>

<td>McasAlert.User</td>

<td>string</td>

<td>User</td>

</tr>

<tr>

<td>McasAlert.Email</td>

<td>string</td>

<td>Email</td>

</tr>

<tr>

<td>McasAlert.IP</td>

<td>string</td>

<td>IP Address</td>

</tr>

<tr>

<td>McasAlert.Country</td>

<td>string</td>

<td>Country</td>

</tr>

</tbody>

</table>

##### Command Example `!mcas-list-alerts limit=2 severity=All` ##### Context Example

<pre>{
    "McasAlert": [
        {
            "Country": "HK",
            "Description": "The user Last Name, First Name (username@domain.com) performed an impossible travel activity.The user was active from xxx.xxx.xxx.xxx in China and xxx.xxx.xxx.xxx in Hong Kong SAR within 65 minutes.If these are IP addresses that are known and safe, add them in the IP address range page to improve the accuracy of the alerts.\nAdditional risks in this user session:\n\n  ISP xxxx was used for the first time in 80 days in your organization.\n",
            "Email": "username@domain.com",
            "ID": "5d8891a7014624824aefd54c",
            "IP": "xxx.xxx.xxx.xxx",
            "PolicyName": "Impossible travel",
            "PolicyType": "ANOMALY_DETECTION",
            "Timestamp": "2019-09-23T09:27:15",
            "Title": "Impossible travel activity",
            "User": "Last Name, First Name"
        },
        {
            "Country": "RO",
            "Description": "The user Last Name, First Name (username@domain.com) performed an impossible travel activity.The user was active from xxx.xxx.xxx.xxx in United Kingdom and xxx.xxx.xxx.xxx in Romania within 80 minutes.If these are IP addresses that are known and safe, add them in the IP address range page to improve the accuracy of the alerts.\nAdditional risks in this user session:\n\n  Romania was visited for the first time in 80 days by this user.\n  xxx.xxx.xxx.xxx was used for the first time in 80 days in your organization.\n  ISP xxxx was used for the first time in 94 days in your organization.\n  ISP xxxx was used for the first time in 80 days by this user.\n",
            "Email": "username@domain.com",
            "ID": "5d886fa1014624824a7b6429",
            "IP": "xxx.xxx.xxx.xxx",
            "PolicyName": "Impossible travel",
            "PolicyType": "ANOMALY_DETECTION",
            "Timestamp": "2019-09-23T07:04:26",
            "Title": "Impossible travel activity",
            "User": "Last Name, First Name"
        }
    ]
}
</pre>

##### Human Readable Output ### MCAS Alerts

<table style="width:750px" border="2" cellpadding="6">

<thead>

<tr>

<th>**Country**</th>

<th>**Description**</th>

<th>**Email**</th>

<th>**ID**</th>

<th>**IP**</th>

<th>**PolicyName**</th>

<th>**PolicyType**</th>

<th>**Timestamp**</th>

<th>**Title**</th>

<th>**User**</th>

</tr>

</thead>

<tbody>

<tr>

<td>HK</td>

<td>The user Last Name, First Name (username@domain.com) performed an impossible travel activity.The user was active from xxx.xxx.xxx.xxx in China and xxx.xxx.xxx.xxx in Hong Kong SAR within 65 minutes.If these are IP addresses that are known and safe, add them in the IP address range page to improve the accuracy of the alerts. Additional risks in this user session: ISP xxxx was used for the first time in 80 days in your organization.</td>

<td>username@domain.com</td>

<td>5d8891a7014624824aefd54c</td>

<td>xxx.xxx.xxx.xxx</td>

<td>Impossible travel</td>

<td>ANOMALY_DETECTION</td>

<td>2019-09-23T09:27:15</td>

<td>Impossible travel activity</td>

<td>Last Name, First Name</td>

</tr>

<tr>

<td>RO</td>

<td>The user Last Name, First Name (username@domain.com) performed an impossible travel activity.The user was active from xxx.xxx.xxx.xxx in United Kingdom and xxx.xxx.xxx.xxx in Romania within 80 minutes.If these are IP addresses that are known and safe, add them in the IP address range page to improve the accuracy of the alerts. Additional risks in this user session: Romania was visited for the first time in 80 days by this user. xxx.xxx.xxx.xxx was used for the first time in 80 days in your organization. ISP xxxx was used for the first time in 94 days in your organization. ISP xxxx was used for the first time in 80 days by this user.</td>

<td>username@domain.com</td>

<td>5d886fa1014624824a7b6429</td>

<td>xxx.xxx.xxx.xxx</td>

<td>Impossible travel</td>

<td>ANOMALY_DETECTION</td>

<td>2019-09-23T07:04:26</td>

<td>Impossible travel activity</td>

<td>Last Name, First Name</td>

</tr>

</tbody>

</table>

### 2\. mcas-lookup-ip This performs an IP lookup ##### Base Command `mcas-lookup-ip` ##### Required Permissions The following permissions are required for all commands. * Read ##### Input

<table style="width:750px" border="2" cellpadding="6">

<thead>

<tr>

<th>**Argument Name**</th>

<th>**Description**</th>

<th>**Required**</th>

</tr>

</thead>

<tbody>

<tr>

<td>ip</td>

<td>IP Address</td>

<td>Required</td>

</tr>

</tbody>

</table>

##### Context Output

<table style="width:750px" border="2" cellpadding="6">

<thead>

<tr>

<th>**Path**</th>

<th>**Type**</th>

<th>**Description**</th>

</tr>

</thead>

<tbody>

<tr>

<td>McasAlert.AppName</td>

<td>string</td>

<td>Microsoft Application associated with activity</td>

</tr>

<tr>

<td>McasAlert.Severity</td>

<td>string</td>

<td>Severity of the associated alert</td>

</tr>

<tr>

<td>McasAlert.Description</td>

<td>string</td>

<td>Description of the activity</td>

</tr>

<tr>

<td>McasAlert.Timestamp</td>

<td>date</td>

<td>Date and Time activity occurred</td>

</tr>

<tr>

<td>McasAlert.City</td>

<td>string</td>

<td>City the activity originated from</td>

</tr>

<tr>

<td>McasAlert.Country</td>

<td>string</td>

<td>Country the activity originated from</td>

</tr>

<tr>

<td>McasAlert.ItemName</td>

<td>string</td>

<td>Name of the item that triggered event</td>

</tr>

<tr>

<td>McasAlert.ItemType</td>

<td>string</td>

<td>Type of item that triggered event</td>

</tr>

<tr>

<td>McasAlert.User</td>

<td>string</td>

<td>User associated with the activity</td>

</tr>

<tr>

<td>McasAlert.Email</td>

<td>string</td>

<td>Email of user associated with the activity</td>

</tr>

</tbody>

</table>

##### Command Example `!mcas-lookup-ip ip=xxx.xxx.xxx.xxx` ##### Context Example

<pre>{
    "McasAlert": [
        {
            "AppName": "Microsoft Exchange Online",
            "City": "Kensington and Norwood",
            "Country": "AU",
            "Description": "Move messages to Deleted Items folder: email Check in now to access your Elite Benefits.",
            "Email": "user@domain.com",
            "IP": "xxx.xxx.xxx.xxx",
            "ItemName": null,
            "ItemType": null,
            "Severity": "INFO",
            "Timestamp": "2019-09-22T17:21:43",
            "User": "Last Name, First Name"
        },
        {
            "AppName": "Microsoft Exchange Online",
            "City": "Kensington and Norwood",
            "Country": "AU",
            "Description": "Move messages to Deleted Items folder: email Canceled: Franchise/ Key IP Meeting [ reschedule from 16 Sept]",
            "Email": "user@domain.com",
            "IP": "xxx.xxx.xxx.xxx",
            "ItemName": null,
            "ItemType": null,
            "Severity": "INFO",
            "Timestamp": "2019-09-22T17:21:00",
            "User": "Last Name, First Name"
        },
    ]
}
</pre>

##### Human Readable Output ### MCAS list

<table style="width:750px" border="2" cellpadding="6">

<thead>

<tr>

<th>**AppName**</th>

<th>**City**</th>

<th>**Country**</th>

<th>**Description**</th>

<th>**Email**</th>

<th>**IP**</th>

<th>**Severity**</th>

<th>**Timestamp**</th>

<th>**User**</th>

</tr>

</thead>

<tbody>

<tr>

<td>Microsoft Exchange Online</td>

<td>Kensington and Norwood</td>

<td>AU</td>

<td>Move messages to Deleted Items folder: email Check in now to access your Elite Benefits.</td>

<td>user@domain.com</td>

<td>xxx.xxx.xxx.xxx</td>

<td>INFO</td>

<td>2019-09-22T17:21:43</td>

<td>Last Name, First Name</td>

</tr>

<tr>

<td>Microsoft Exchange Online</td>

<td>Kensington and Norwood</td>

<td>AU</td>

<td>Move messages to Deleted Items folder: email Canceled: Franchise/ Key IP Meeting [ reschedule from 16 Sept]</td>

<td>user@domain.com</td>

<td>xxx.xxx.xxx.xxx</td>

<td>INFO</td>

<td>2019-09-22T17:21:00</td>

<td>Last Name, First Name</td>

</tr>

</tbody>

</table>

### 3\. mcas-lookup-user This command looks up alert descriptions by username. ##### Base Command `mcas-lookup-user` ##### Required Permissions The following permissions are required for all commands. * Read ##### Input

<table style="width:750px" border="2" cellpadding="6">

<thead>

<tr>

<th>**Argument Name**</th>

<th>**Description**</th>

<th>**Required**</th>

</tr>

</thead>

<tbody>

<tr>

<td>username</td>

<td>Username</td>

<td>Required</td>

</tr>

</tbody>

</table>

##### Context Output

<table style="width:750px" border="2" cellpadding="6">

<thead>

<tr>

<th>**Path**</th>

<th>**Type**</th>

<th>**Description**</th>

</tr>

</thead>

<tbody>

<tr>

<td>McasUsername.ID</td>

<td>string</td>

<td>Root ID of Alert</td>

</tr>

<tr>

<td>McasUsername.Title</td>

<td>string</td>

<td>Alert Name</td>

</tr>

<tr>

<td>McasUsername.Description</td>

<td>string</td>

<td>Alert Description</td>

</tr>

<tr>

<td>McasUsername.PolicyName</td>

<td>string</td>

<td>Name of Alert Policy</td>

</tr>

<tr>

<td>McasUsername.PolicyType</td>

<td>string</td>

<td>Type of Alert Policy</td>

</tr>

<tr>

<td>McasUsername.Timestamp</td>

<td>date</td>

<td>Date and time the alert occurred</td>

</tr>

<tr>

<td>McasUsername.User</td>

<td>string</td>

<td>User</td>

</tr>

<tr>

<td>McasUsername.Email</td>

<td>string</td>

<td>Email</td>

</tr>

<tr>

<td>McasUsername.IP</td>

<td>string</td>

<td>IP Address</td>

</tr>

<tr>

<td>McasUsername.Country</td>

<td>string</td>

<td>Country</td>

</tr>

</tbody>

</table>

##### Command Example `!mcas-lookup-user username=user@domain.com` ##### Context Example

<pre>{
    "McasUsername": [
        {
            "Country": "US",
            "Description": "The user Last Name, First Name (user@domain.com) performed an impossible travel activity.The user was active from xxx.xxx.xxx.xxx in Australia and xxx.xxx.xxx.xxx in United States within 27 minutes.If these are IP addresses that are known and safe, add them in the IP address range page to improve the accuracy of the alerts.\nAdditional risks in this user session:\n\n  xxx.xxx.xxx.xxx was used for the first time in 79 days in your organization.\n  47.153.130.131 was used for the first time in 79 days in your organization.\n  ISP xxxx was used for the first time in 79 days by this user.\n",
            "Email": "user@domain.com",
            "ID": "5d87b53c014624824a075b3b",
            "IP": "xxx.xxx.xxx.xxx",
            "PolicyName": "Impossible travel",
            "PolicyType": "ANOMALY_DETECTION",
            "Timestamp": "2019-09-22T17:48:52",
            "Title": "Impossible travel activity",
            "User": "Last Name, First Name"
        }
    ]
}
</pre>

##### Human Readable Output ### MCAS list

<table style="width:750px" border="2" cellpadding="6">

<thead>

<tr>

<th>**Country**</th>

<th>**Description**</th>

<th>**Email**</th>

<th>**ID**</th>

<th>**IP**</th>

<th>**PolicyName**</th>

<th>**PolicyType**</th>

<th>**Timestamp**</th>

<th>**Title**</th>

<th>**User**</th>

</tr>

</thead>

<tbody>

<tr>

<td>US</td>

<td>The user Last Name, First Name (user@domain.com) performed an impossible travel activity.The user was active from xxx.xxx.xxx.xxx in Australia and xxx.xxx.xxx.xxx in United States within 27 minutes.If these are IP addresses that are known and safe, add them in the IP address range page to improve the accuracy of the alerts. Additional risks in this user session: 1.125.111.0 was used for the first time in 79 days in your organization. 47.153.130.131 was used for the first time in 79 days in your organization. ISP Frontier Communications was used for the first time in 79 days by this user.</td>

<td>user@domain.com</td>

<td>5d87b53c014624824a075b3b</td>

<td>xxx.xxx.xxx.xxx</td>

<td>Impossible travel</td>

<td>ANOMALY_DETECTION</td>

<td>2019-09-22T17:48:52</td>

<td>Impossible travel activity</td>

<td>Last Name, First Name</td>

</tr>

</tbody>

</table>

## Additional Information Please note that IP lookups return recent **Activity** whereas username lookups return recent **Alerts** ## Known Limitations ## Troubleshooting
