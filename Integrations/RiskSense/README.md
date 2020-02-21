## Overview
---

RiskSense is a cloud based platform that provides vulnerability management and prioritization to measure and control cybersecurity risk.
This integration was integrated and tested with version xx of RiskSense

## Use Cases
---
The SOAR market is still an emerging market and is often used as an umbrella term that covers security operations, security incident response and threat intelligence. Many vendors, even market leaders  like Splunk, are adding features and functionality to their existing solutions in the fight for market leadership. One major commonality between new SOAR vendors and vendors trying to make their existing solution fit into this market definition is the need to be able to ingest security centric data including threat intelligence to address the biggest use-case for SOAR i.e. security operations. 

Gartner claims that organizations need to have a continuous adaptive risk and trust assessment (CARTA) strategy to make their investments in SOAR technology pay off. CARTA’s value is that it is continuous, and one element helps and informs other elements, allowing for continuous improvement in your organization’s ability to improve both security posture and digital resilience.

## Configure RiskSense on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for RiskSense.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __URL__
    * __API Key__
    * __Client Name__
    * __HTTP Request Timeout (Specify the time interval in seconds. All the RiskSense API calls would timeout if the response is not returned within the configured time interval).__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.

## Commands
---
You can execute these commands from the Demisto CLI, as part of automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. risksense-get-hosts
2. risksense-get-host-detail
3. risksense-get-unique-cves
4. risksense-get-unique-open-findings
5. risksense-get-open-host-findings
6. risksense-get-closed-host-findings
7. risksense-get-apps
8. risksense-get-host-finding-detail
9. risksense-get-app-detail
### 1. risksense-get-hosts
---
Look up the host details. The host details can be searched based on input parameters like fieldname (hostname, ipaddress, criticality, etc), operator (EXACT, IN, LIKE), page, size, sort by and sort order.

##### Base Command

`risksense-get-hosts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fieldname | The RiskSense host field that should be considered for filtering the results. Users can specify any RiskSense field which use to filter. If specified, the 'value' argument is mandatory. | Optional | 
| operator | The match operator should be applied for filtering the hosts based on 'fieldname' and 'value'. Available options are 'EXACT' - filter records exactly matching the criteria; 'IN' - filter records matching any one of the comma-separated values;'LIKE' - filter records with specific pattern provided. | Optional | 
| exclusive_operator | The exclusive operator flag that determines whether the returned records matches filter criteria or not. By default set to False. If set to True, host not matching the specified values are fetched. | Optional | 
| value | The value of the host property mentioned in 'fieldname' to be considered for filter criteria. | Optional | 
| page | The index of the page. The index is numeric value starting with 0. | Optional | 
| size | The maximum number of records to be fetched in one page. | Optional | 
| sort_by | The fieldname that should be considered for sorting the returned records. | Optional | 
| sort_order | The sorting order to be considered for returned records. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Host.Hostname | string | The hostname of the host. | 
| Host.ID | string | The unique ID within the tool retrieving the host. | 
| Host.IP | string | The IP address of the host. | 
| Host.OS | string | The operating system of the host. | 
| RiskSense.Host.Id | number | The unique identifier of the host. | 
| RiskSense.Host.ClientId | number | The client id of the host. | 
| RiskSense.Host.GroupId | number | The id of the group belonging to the host. | 
| RiskSense.Host.GroupName | string | The name of the group belonging to the host. | 
| RiskSense.Host.Groups | Unknown | The list of groups. | 
| RiskSense.Host.Rs3 | number | The asset security score calculated by the RiskSense platform (includes vulnerability risk on related web applications). | 
| RiskSense.Host.Xrs3 | string | The asset security score calculated by the RiskSense platform (includes vulnerability risk on related web applications). | 
| RiskSense.Host.Criticality | number | The asset importance using a scale of 1 (lowest importance) to 5 (highest importance). | 
| RiskSense.Host.Tag.Id | number | The ID of the tag. | 
| RiskSense.Host.Tag.Name | string | The name of the tag. | 
| RiskSense.Host.Tag.Category | string | The category of the tag. | 
| RiskSense.Host.Tag.Description | string | The description of the tag. | 
| RiskSense.Host.Tag.Created | string | The time when the tag was created. | 
| RiskSense.Host.Tag.Updated | string | The time when the tag was last updated. | 
| RiskSense.Host.Tag.Color | string | The color code of the tag. | 
| RiskSense.Host.NetworkId | number | The Network ID of the host. | 
| RiskSense.Host.NetworkName | string | The name of the network used by the host. | 
| RiskSense.Host.NetworkType | string | The type of the network used by the host. | 
| RiskSense.Host.DiscoveredOn | string | The time when the host was discovered. | 
| RiskSense.Host.LastFoundOn | string | The time when the host was last found. | 
| RiskSense.Host.LastScanTime | string | The last time when the host was scanned. | 
| RiskSense.Host.HostName | string | The hostname of the host. | 
| RiskSense.Host.IpAddress | string | The IP address of the host. | 
| RiskSense.Host.PortNumbers | String | The list of ports that are currently bound. | 
| RiskSense.Host.OS.Name | string | The operating system of the host. | 
| RiskSense.Host.OS.Family | string | The family of the operating system of the host. | 
| RiskSense.Host.OS.Class | string | The class of the operating system of the host. | 
| RiskSense.Host.OS.Vendor | string | The vendor information of the operating system of the host | 
| RiskSense.Host.CMDB.Order | number | The CMDB order number of the host. | 
| RiskSense.Host.CMDB.Key | string | The CMDB key identifier of the host. | 
| RiskSense.Host.CMDB.Value | string | The CMDB value identifier of the host. | 
| RiskSense.Host.CMDB.Label | string | The CMDB label identifier of the host. | 
| RiskSense.Host.Services | string | The name of the services thar are used by the host. | 
| RiskSense.Host.Note.UserId | string | The User ID of the user who added a note for the host. | 
| RiskSense.Host.Note.UserName | string | The Username of the user who added a note for the host. | 
| RiskSense.Host.Note.Note | string | The notes that are added by the user for the host. | 
| RiskSense.Host.Note.Date | string | The time when note is added by the user for the host. | 
| RiskSense.Host.Source.Name | string | The name of the source associated with the host. | 
| RiskSense.Host.Source.Uuid | string | The unique ID of the source associated with the host. | 
| RiskSense.Host.Source.ScannerType | string | The type of scanner that discovered the host. | 
| RiskSense.Host.Ticket.TicketNumber | string | The number of the ticket associated with the host. | 
| RiskSense.Host.Ticket.TicketStatus | string | The status of the ticket associated with the host. | 
| RiskSense.Host.Ticket.DeepLink | string | The deeplink associated with the ticket associated with the host. | 
| RiskSense.Host.Ticket.Type | string | The type of ticket associated with the host. | 
| RiskSense.Host.Ticket.ConnectorName | string | The connector name of the ticket associated with the host. | 
| RiskSense.Host.Ticket.DetailedStatus | string | The detailed status of the ticket associated with the host. | 
| RiskSense.Host.LastVulnTrendingOn | string | The time when the last vulnerability was trending on the host. | 
| RiskSense.Host.LastThreatTrendingOn | string | The time when the last threat was trending on the host. | 
| RiskSense.Host.OldestOpenFindingWithThreatDiscoveredOn | string | The timestamp when the oldest open finding with the threat was discovered. | 
| RiskSense.Host.Xrs3date | string | The time when the xrs3 is calculated by the RiskSense platform. | 
| RiskSense.Host.DiscoveredByRS | string | The flag that determines whether the host is discovered by the RiskSense platform or not. | 
| RiskSense.Host.Href | string | The deeplink pointing to the host details on RiskSense. | 
| RiskSense.Host.Total | number | The number of total open findings of the host. | 
| RiskSense.Host.Critical | number | The number of open findings of the host with critical severity. | 
| RiskSense.Host.High | number | The number of open findings of the host with high severity. | 
| RiskSense.Host.Medium | number | The number of open findings of the host with medium severity. | 
| RiskSense.Host.Low | number | The number of open findings of the host with low severity. | 
| RiskSense.Host.Info | number | The number of open findings of the host with info severity. | 


##### Command Example
```
!risksense-get-hosts fieldname="criticality" value="5" page="0" size="2" sort_by="Total Findings" sort_order="DESC"
```

##### Context Example
```
{
    "RiskSense.Host": [
        {
            "NetworkId": 78038, 
            "OldestOpenFindingWithThreatDiscoveredOn": "2017-09-14", 
            "HostName": "iz0.y2.gov", 
            "Group": [
                {
                    "Id": 7990, 
                    "Name": "Default Group"
                }
            ], 
            "ClientId": 747, 
            "Note": [], 
            "Source": [
                {
                    "ScannerType": null, 
                    "Name": "QUALYS", 
                    "Uuid": "QUALYS_SCANNER"
                }
            ], 
            "Critical": 86, 
            "Low": 18, 
            "IpAddress": "45.19.214.161", 
            "Xrs3": null, 
            "Medium": 148, 
            "Criticality": 5, 
            "LastVulnTrendingOn": "2020-02-18", 
            "Xrs3date": null, 
            "DiscoveredByRS": false, 
            "Tag": [
                {
                    "Category": "PEOPLE", 
                    "Updated": "2019-04-24T21:39:59", 
                    "Name": "Linux_Team_2", 
                    "Created": "2019-04-24T21:39:59", 
                    "Color": "#78a19b", 
                    "Id": 215554, 
                    "Description": ""
                }, 
                {
                    "Category": "LOCATION", 
                    "Updated": "2019-04-24T21:37:06", 
                    "Name": "Data_Center_2", 
                    "Created": "2019-04-24T21:37:06", 
                    "Color": "#dd8361", 
                    "Id": 215552, 
                    "Description": ""
                }
            ], 
            "Services": "ssh, telnet, ftp", 
            "Ticket": [], 
            "Info": 0, 
            "DiscoveredOn": "2007-06-14", 
            "PortNumbers": "22, 21, 23", 
            "LastScanTime": "2007-06-14T21:14:04", 
            "GroupName": "Default Group", 
            "CMDB": [
                {
                    "Value": "", 
                    "Order": 1, 
                    "Key": "busines_criticality", 
                    "Label": "Asset Criticality"
                }, 
                {
                    "Value": "", 
                    "Order": 2, 
                    "Key": "os", 
                    "Label": "Operating System"
                }, 
                {
                    "Value": "", 
                    "Order": 3, 
                    "Key": "manufacturer", 
                    "Label": "Manufactured By"
                }, 
                {
                    "Value": "", 
                    "Order": 4, 
                    "Key": "model_id", 
                    "Label": "Model"
                }, 
                {
                    "Value": "", 
                    "Order": 5, 
                    "Key": "location", 
                    "Label": "Location"
                }, 
                {
                    "Value": "", 
                    "Order": 6, 
                    "Key": "managed_by", 
                    "Label": "Managed By"
                }, 
                {
                    "Value": "", 
                    "Order": 7, 
                    "Key": "owned_by", 
                    "Label": "Owned By"
                }, 
                {
                    "Value": "", 
                    "Order": 8, 
                    "Key": "supported_by", 
                    "Label": "Supported By"
                }, 
                {
                    "Value": "", 
                    "Order": 9, 
                    "Key": "support_group", 
                    "Label": "Support Group"
                }, 
                {
                    "Value": "", 
                    "Order": 10, 
                    "Key": "sys_updated_on", 
                    "Label": "Last Scanned"
                }, 
                {
                    "Value": "", 
                    "Order": 11, 
                    "Key": "asset_tag", 
                    "Label": "Asset tags"
                }, 
                {
                    "Value": "", 
                    "Order": 12, 
                    "Key": "mac_address", 
                    "Label": "Mac Address"
                }, 
                {
                    "Value": "", 
                    "Order": 16, 
                    "Key": "sys_id", 
                    "Label": "Unique Id"
                }, 
                {
                    "Value": "", 
                    "Order": 18, 
                    "Key": "cf_1", 
                    "Label": "Mike Name 1"
                }, 
                {
                    "Value": "", 
                    "Order": 19, 
                    "Key": "cf_2", 
                    "Label": "Custom Field 2"
                }, 
                {
                    "Value": "", 
                    "Order": 20, 
                    "Key": "cf_3", 
                    "Label": "Custom Field 3"
                }, 
                {
                    "Value": "", 
                    "Order": 21, 
                    "Key": "cf_4", 
                    "Label": "Custom Field 4"
                }, 
                {
                    "Value": "", 
                    "Order": 22, 
                    "Key": "cf_5", 
                    "Label": "Custom Field 5"
                }, 
                {
                    "Value": "", 
                    "Order": 23, 
                    "Key": "cf_6", 
                    "Label": "Custom Field 6"
                }, 
                {
                    "Value": "", 
                    "Order": 24, 
                    "Key": "cf_7", 
                    "Label": "Custom Field 7"
                }, 
                {
                    "Value": "", 
                    "Order": 25, 
                    "Key": "cf_8", 
                    "Label": "Custom Field 8"
                }, 
                {
                    "Value": "", 
                    "Order": 26, 
                    "Key": "cf_9", 
                    "Label": "Custom Field 9"
                }, 
                {
                    "Value": "", 
                    "Order": 29, 
                    "Key": "cf_10", 
                    "Label": "Custom Field 10"
                }, 
                {
                    "Value": "", 
                    "Order": 13, 
                    "Key": "Asset Compliance", 
                    "Label": "Asset Compliance"
                }
            ], 
            "LastThreatTrendingOn": "2020-02-18", 
            "OS": {
                "Vendor": "Red Hat", 
                "Class": "Not Reported", 
                "Family": "Linux", 
                "Name": "Red Hat Enterprise Linux Server 6.1"
            }, 
            "GroupId": 7990, 
            "High": 166, 
            "Href": "http://platform.risksense.com/api/v1/client/747/host/search?page=0&size=2&sort=findingsDistribution.total,desc", 
            "LastFoundOn": "2007-06-14", 
            "NetworkType": "IP", 
            "Total": 418, 
            "NetworkName": "IP Network", 
            "Id": 3570259, 
            "Rs3": 514
        }, 
        {
            "NetworkId": 78038, 
            "OldestOpenFindingWithThreatDiscoveredOn": "2015-02-10", 
            "HostName": "ftpserver", 
            "Group": [
                {
                    "Id": 7990, 
                    "Name": "Default Group"
                }
            ], 
            "ClientId": 747, 
            "Note": [], 
            "Source": [
                {
                    "ScannerType": null, 
                    "Name": "QUALYS", 
                    "Uuid": "QUALYS_SCANNER"
                }
            ], 
            "Critical": 50, 
            "Low": 22, 
            "IpAddress": "34.17.197.127", 
            "Xrs3": null, 
            "Medium": 127, 
            "Criticality": 5, 
            "LastVulnTrendingOn": "2019-11-06", 
            "Xrs3date": null, 
            "DiscoveredByRS": false, 
            "Tag": [
                {
                    "Category": "PEOPLE", 
                    "Updated": "2019-04-24T21:39:59", 
                    "Name": "Linux_Team_2", 
                    "Created": "2019-04-24T21:39:59", 
                    "Color": "#78a19b", 
                    "Id": 215554, 
                    "Description": ""
                }, 
                {
                    "Category": "LOCATION", 
                    "Updated": "2019-04-24T21:37:06", 
                    "Name": "Data_Center_2", 
                    "Created": "2019-04-24T21:37:06", 
                    "Color": "#dd8361", 
                    "Id": 215552, 
                    "Description": ""
                }
            ], 
            "Services": "ssh, ftps, unknown, ftp, unknown, unknown, unknown", 
            "Ticket": [], 
            "Info": 0, 
            "DiscoveredOn": "2006-12-06", 
            "PortNumbers": "990, 80, 55443, 22, 65443, 443", 
            "LastScanTime": "2006-12-06T17:08:05", 
            "GroupName": "Default Group", 
            "CMDB": [
                {
                    "Value": "", 
                    "Order": 1, 
                    "Key": "busines_criticality", 
                    "Label": "Asset Criticality"
                }, 
                {
                    "Value": "", 
                    "Order": 2, 
                    "Key": "os", 
                    "Label": "Operating System"
                }, 
                {
                    "Value": "", 
                    "Order": 3, 
                    "Key": "manufacturer", 
                    "Label": "Manufactured By"
                }, 
                {
                    "Value": "", 
                    "Order": 4, 
                    "Key": "model_id", 
                    "Label": "Model"
                }, 
                {
                    "Value": "", 
                    "Order": 5, 
                    "Key": "location", 
                    "Label": "Location"
                }, 
                {
                    "Value": "", 
                    "Order": 6, 
                    "Key": "managed_by", 
                    "Label": "Managed By"
                }, 
                {
                    "Value": "", 
                    "Order": 7, 
                    "Key": "owned_by", 
                    "Label": "Owned By"
                }, 
                {
                    "Value": "", 
                    "Order": 8, 
                    "Key": "supported_by", 
                    "Label": "Supported By"
                }, 
                {
                    "Value": "", 
                    "Order": 9, 
                    "Key": "support_group", 
                    "Label": "Support Group"
                }, 
                {
                    "Value": "", 
                    "Order": 10, 
                    "Key": "sys_updated_on", 
                    "Label": "Last Scanned"
                }, 
                {
                    "Value": "", 
                    "Order": 11, 
                    "Key": "asset_tag", 
                    "Label": "Asset tags"
                }, 
                {
                    "Value": "", 
                    "Order": 12, 
                    "Key": "mac_address", 
                    "Label": "Mac Address"
                }, 
                {
                    "Value": "", 
                    "Order": 16, 
                    "Key": "sys_id", 
                    "Label": "Unique Id"
                }, 
                {
                    "Value": "", 
                    "Order": 18, 
                    "Key": "cf_1", 
                    "Label": "Mike Name 1"
                }, 
                {
                    "Value": "", 
                    "Order": 19, 
                    "Key": "cf_2", 
                    "Label": "Custom Field 2"
                }, 
                {
                    "Value": "", 
                    "Order": 20, 
                    "Key": "cf_3", 
                    "Label": "Custom Field 3"
                }, 
                {
                    "Value": "", 
                    "Order": 21, 
                    "Key": "cf_4", 
                    "Label": "Custom Field 4"
                }, 
                {
                    "Value": "", 
                    "Order": 22, 
                    "Key": "cf_5", 
                    "Label": "Custom Field 5"
                }, 
                {
                    "Value": "", 
                    "Order": 23, 
                    "Key": "cf_6", 
                    "Label": "Custom Field 6"
                }, 
                {
                    "Value": "", 
                    "Order": 24, 
                    "Key": "cf_7", 
                    "Label": "Custom Field 7"
                }, 
                {
                    "Value": "", 
                    "Order": 25, 
                    "Key": "cf_8", 
                    "Label": "Custom Field 8"
                }, 
                {
                    "Value": "", 
                    "Order": 26, 
                    "Key": "cf_9", 
                    "Label": "Custom Field 9"
                }, 
                {
                    "Value": "", 
                    "Order": 29, 
                    "Key": "cf_10", 
                    "Label": "Custom Field 10"
                }, 
                {
                    "Value": "", 
                    "Order": 13, 
                    "Key": "Asset Compliance", 
                    "Label": "Asset Compliance"
                }
            ], 
            "LastThreatTrendingOn": "2019-11-06", 
            "OS": {
                "Vendor": "Red Hat", 
                "Class": "Not Reported", 
                "Family": "Linux", 
                "Name": "Red Hat Enterprise Linux Server 5.4"
            }, 
            "GroupId": 7990, 
            "High": 92, 
            "Href": "http://platform.risksense.com/api/v1/client/747/host/search?page=0&size=2&sort=findingsDistribution.total,desc", 
            "LastFoundOn": "2006-12-06", 
            "NetworkType": "IP", 
            "Total": 291, 
            "NetworkName": "IP Network", 
            "Id": 3571622, 
            "Rs3": 528
        }
    ], 
    "Host": [
        {
            "IP": "45.19.214.161", 
            "Hostname": "iz0.y2.gov", 
            "OS": "Red Hat Enterprise Linux Server 6.1", 
            "ID": 3570259
        }, 
        {
            "IP": "34.17.197.127", 
            "Hostname": "ftpserver", 
            "OS": "Red Hat Enterprise Linux Server 5.4", 
            "ID": 3571622
        }
    ]
}
```

##### Human Readable Output
### Total hosts found: 1970		Page: 0/984		Client: The Demo Client
### RiskSense host(s) details:
|Rs3|HostName|Total Findings|Critical Findings|High Findings|Medium Findings|Low Findings|Info Findings|Id|OS|Tags|Notes|XRs3|Criticality|IpAddress|Network|Group|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 514 | iz0.y2.gov | 418 | 86 | 166 | 148 | 18 | 0 | 3570259 | Red Hat Enterprise Linux Server 6.1 | 2 | 0 |  | 5 | 45.19.214.161 | IP Network | 1 |
| 528 | ftpserver | 291 | 50 | 92 | 127 | 22 | 0 | 3571622 | Red Hat Enterprise Linux Server 5.4 | 2 | 0 |  | 5 | 34.17.197.127 | IP Network | 1 |


### 2. risksense-get-host-detail
---
Look up single host details in depth. This command accepts either hostname or host id as an argument.

##### Base Command

`risksense-get-host-detail`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | The host ID is unique for the host. Host ID is either known by RiskSense users or it can be searched in context output (RiskSense.Host.Id) or in human-readable output of 'risksense-get-hosts' command. | Optional | 
| host | The host is identified by hostname. Host name is either known by RiskSense users or it can be searched in context output (RiskSense.Host.HostName) or in human-readable output of 'risksense-get-hosts' command. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Host.Hostname | String | The hostname of the host. | 
| Host.ID | String | The unique ID within the tool retrieving the host. | 
| Host.IP | String | The IP address of the host. | 
| Host.OS | String | The operating system of the host. | 
| RiskSense.Host.Id | Number | The unique identifier of the host. | 
| RiskSense.Host.ClientId | Number | The client id of the host. | 
| RiskSense.Host.GroupId | Number | The id of the group belonging to the host. | 
| RiskSense.Host.GroupName | String | The name of the group belonging to the host. | 
| RiskSense.Host.Groups | Unknown | The list of the groups. | 
| RiskSense.Host.Rs3 | Number | The asset security score calculated by the RiskSense platform (includes vulnerability risk on related web applications). | 
| RiskSense.Host.Xrs3 | String | The asset security score calculated by the RiskSense platform. | 
| RiskSense.Host.Criticality | Number | The asset importance using a scale of 1 (lowest importance) to 5 (highest importance). | 
| RiskSense.Host.Tag.Id | Number | The ID of the tag. | 
| RiskSense.Host.Tag.Name | String | The Name of the tag. | 
| RiskSense.Host.Tag.Category | String | The category of the tag. | 
| RiskSense.Host.Tag.Description | String | The description of the tag. | 
| RiskSense.Host.Tag.Created | String | The time when the tag was created. | 
| RiskSense.Host.Tag.Updated | String | The time when the tag was last updated. | 
| RiskSense.Host.Tag.Color | String | The color code of the tag. | 
| RiskSense.Host.NetworkId | Number | The network ID of the host. | 
| RiskSense.Host.NetworkName | String | The name of the network used by the host. | 
| RiskSense.Host.NetworkType | String | The type of the network used by the host. | 
| RiskSense.Host.DiscoveredOn | String | The time when the host was discovered. | 
| RiskSense.Host.LastFoundOn | String | The time when the host was last found. | 
| RiskSense.Host.LastScanTime | String | The last time when the host was scanned. | 
| RiskSense.Host.HostName | String | The hostname of the host. | 
| RiskSense.Host.IpAddress | String | The IP Address of the host. | 
| RiskSense.Host.PortNumbers | String | The list of ports that are currently bound. | 
| RiskSense.Host.OS.Name | String | The operating system of the host. | 
| RiskSense.Host.OS.Family | String | The family of the operating system of the host. | 
| RiskSense.Host.OS.Class | String | The class of the operating system of the host. | 
| RiskSense.Host.OS.Vendor | String | The vendor information of the operating system of the host. | 
| RiskSense.Host.CMDB.Order | Number | The CMDB order number of the host. | 
| RiskSense.Host.CMDB.Key | String | The CMDB key identifier of the host. | 
| RiskSense.Host.CMDB.Value | String | The CMDB value identifier of the host. | 
| RiskSense.Host.CMDB.Label | String | The CMDB label identifier of the host. | 
| RiskSense.Host.Services | String | The name of the services that are used by the host. | 
| RiskSense.Host.Note.UserId | String | The User ID of the user who added a note for the host. | 
| RiskSense.Host.Note.UserName | String | The Username of the user who added a note for the host. | 
| RiskSense.Host.Note.Note | String | The notes that are added by the user for the host. | 
| RiskSense.Host.Note.Date | String | The time when note is added by the user for the host. | 
| RiskSense.Host.Source.Name | String | The name of the source associated with the host. | 
| RiskSense.Host.Source.Uuid | String | The unique ID of the source associated with the host. | 
| RiskSense.Host.Source.ScannerType | String | The type of scanner that discovered the host. | 
| RiskSense.Host.Ticket.TicketNumber | String | The number of the ticket associated with the host. | 
| RiskSense.Host.Ticket.TicketStatus | String | The status of the ticket associated with the host. | 
| RiskSense.Host.Ticket.DeepLink | String | The deeplink of the ticket associated with the host. | 
| RiskSense.Host.Ticket.Type | String | The type of the ticket associated with the host. | 
| RiskSense.Host.Ticket.ConnectorName | String | The connector name of the ticket associated with the host. | 
| RiskSense.Host.Ticket.DetailedStatus | String | The detailed status of the ticket associated with the host. | 
| RiskSense.Host.LastVulnTrendingOn | String | The time when the last vulnerability was trending on the host. | 
| RiskSense.Host.LastThreatTrendingOn | String | The time when the last threat was trending on the host. | 
| RiskSense.Host.OldestOpenFindingWithThreatDiscoveredOn | String | The timestamp when the oldest open finding with the threat was discovered. | 
| RiskSense.Host.Xrs3date | String | The time when the xrs3 is calculated by RiskSense platform. | 
| RiskSense.Host.DiscoveredByRS | String | The flag that determines whether the host is discovered by the RiskSense platform or not. | 
| RiskSense.Host.Href | String | The deeplink pointing to the host details on RiskSense. | 
| RiskSense.Host.Total | Number | The number of total open findings of the host. | 
| RiskSense.Host.Critical | Number | The number of open findings of the host with critical severity. | 
| RiskSense.Host.High | Number | The number of open findings of the host with high severity. | 
| RiskSense.Host.Medium | Number | The number of open findings of the host with medium severity. | 
| RiskSense.Host.Low | Number | The number of open findings of the host with low severity. | 
| RiskSense.Host.Info | Number | The number of open findings of the host with info severity. | 


##### Command Example
```
!risksense-get-host-detail host=united-78c957c5
```

##### Context Example
```
 {
        "Host": [
            {
                "Hostname": "united-78c957c5",
                "ID": 3571259,
                "IP": "53.132.37.52",
                "OS": "Windows 2008/7"
            }
        ],
        "RiskSense.Host": [
            {
                "CMDB": [
                    {
                        "Key": "busines_criticality",
                        "Label": "Asset Criticality",
                        "Order": 1,
                        "Value": ""
                    },
                    {
                        "Key": "os",
                        "Label": "Operating System",
                        "Order": 2,
                        "Value": ""
                    },
                    {
                        "Key": "manufacturer",
                        "Label": "Manufactured By",
                        "Order": 3,
                        "Value": ""
                    },
                    {
                        "Key": "model_id",
                        "Label": "Model",
                        "Order": 4,
                        "Value": ""
                    },
                    {
                        "Key": "location",
                        "Label": "Location",
                        "Order": 5,
                        "Value": ""
                    },
                    {
                        "Key": "managed_by",
                        "Label": "Managed By",
                        "Order": 6,
                        "Value": ""
                    },
                    {
                        "Key": "owned_by",
                        "Label": "Owned By",
                        "Order": 7,
                        "Value": ""
                    },
                    {
                        "Key": "supported_by",
                        "Label": "Supported By",
                        "Order": 8,
                        "Value": ""
                    },
                    {
                        "Key": "support_group",
                        "Label": "Support Group",
                        "Order": 9,
                        "Value": ""
                    },
                    {
                        "Key": "sys_updated_on",
                        "Label": "Last Scanned",
                        "Order": 10,
                        "Value": ""
                    },
                    {
                        "Key": "asset_tag",
                        "Label": "Asset tags",
                        "Order": 11,
                        "Value": ""
                    },
                    {
                        "Key": "mac_address",
                        "Label": "Mac Address",
                        "Order": 12,
                        "Value": ""
                    },
                    {
                        "Key": "sys_id",
                        "Label": "Unique Id",
                        "Order": 16,
                        "Value": ""
                    },
                    {
                        "Key": "cf_1",
                        "Label": "Mike Name 1",
                        "Order": 18,
                        "Value": ""
                    },
                    {
                        "Key": "cf_2",
                        "Label": "Custom Field 2",
                        "Order": 19,
                        "Value": ""
                    },
                    {
                        "Key": "cf_3",
                        "Label": "Custom Field 3",
                        "Order": 20,
                        "Value": ""
                    },
                    {
                        "Key": "cf_4",
                        "Label": "Custom Field 4",
                        "Order": 21,
                        "Value": ""
                    },
                    {
                        "Key": "cf_5",
                        "Label": "Custom Field 5",
                        "Order": 22,
                        "Value": ""
                    },
                    {
                        "Key": "cf_6",
                        "Label": "Custom Field 6",
                        "Order": 23,
                        "Value": ""
                    },
                    {
                        "Key": "cf_7",
                        "Label": "Custom Field 7",
                        "Order": 24,
                        "Value": ""
                    },
                    {
                        "Key": "cf_8",
                        "Label": "Custom Field 8",
                        "Order": 25,
                        "Value": ""
                    },
                    {
                        "Key": "cf_9",
                        "Label": "Custom Field 9",
                        "Order": 26,
                        "Value": ""
                    },
                    {
                        "Key": "cf_10",
                        "Label": "Custom Field 10",
                        "Order": 29,
                        "Value": ""
                    },
                    {
                        "Key": "Asset Compliance",
                        "Label": "Asset Compliance",
                        "Order": 13,
                        "Value": ""
                    }
                ],
                "ClientId": 747,
                "Critical": 2,
                "Criticality": 5,
                "DiscoveredByRS": false,
                "DiscoveredOn": "2007-01-23",
                "Group": [
                    {
                        "Id": 7990,
                        "Name": "Default Group"
                    },
                    {
                        "Id": 8002,
                        "Name": "BU2_Other_Devices"
                    }
                ],
                "GroupId": 7990,
                "GroupName": "Default Group",
                "High": 0,
                "HostName": "united-78c957c5",
                "Href": "http://platform.risksense.com/api/v1/client/747/host/search?page=0&size=20&sort=id,asc",
                "Id": 3571259,
                "Info": 0,
                "IpAddress": "53.132.37.52",
                "LastFoundOn": "2007-01-23",
                "LastScanTime": "2007-01-23T16:46:50",
                "LastThreatTrendingOn": null,
                "LastVulnTrendingOn": null,
                "Low": 0,
                "Medium": 0,
                "NetworkId": 78038,
                "NetworkName": "IP Network",
                "NetworkType": "IP",
                "Note": [
                    {
                        "Date": "2019-12-30T11:35:41",
                        "Note": "Testing note\n",
                        "UserId": 5969,
                        "UserName": "Ravindra Sojitra"
                    },
                    {
                        "Date": "2019-12-30T11:38:25",
                        "Note": "This is second note for testing",
                        "UserId": 5969,
                        "UserName": "Ravindra Sojitra"
                    }
                ],
                "OS": {
                    "Class": "Not Reported",
                    "Family": "Windows",
                    "Name": "Windows 2008/7",
                    "Vendor": "Microsoft"
                },
                "OldestOpenFindingWithThreatDiscoveredOn": "2014-09-24",
                "PortNumbers": "135, 1025, 1494, 80, 139, 3389, 5353, 445",
                "Rs3": 351,
                "Services": "msrpc-epmap, blackjack, microsoft-ds, ica, ms-wbt-server, www, netbios-ssn, VxWorks",
                "Source": [
                    {
                        "Name": "QUALYS",
                        "ScannerType": null,
                        "Uuid": "QUALYS_SCANNER"
                    }
                ],
                "Tag": [
                    {
                        "Category": "LOCATION",
                        "Color": "#dd8361",
                        "Created": "2019-04-24T21:37:06",
                        "Description": "",
                        "Id": 215552,
                        "Name": "Data_Center_2",
                        "Updated": "2019-04-24T21:37:06"
                    },
                    {
                        "Category": "PEOPLE",
                        "Color": "#78a19b",
                        "Created": "2019-04-24T21:42:34",
                        "Description": "",
                        "Id": 215557,
                        "Name": "Windows_Server_Team_1",
                        "Updated": "2019-04-24T21:42:34"
                    },
                    {
                        "Category": "CUSTOM",
                        "Color": "#648d9f",
                        "Created": "2019-10-29T20:22:25",
                        "Description": "",
                        "Id": 229865,
                        "Name": "Dev_Servers",
                        "Updated": "2019-10-29T20:22:25"
                    },
                    {
                        "Category": "SCANNER",
                        "Color": "#648d9f",
                        "Created": "2019-12-30T11:27:57",
                        "Description": "",
                        "Id": 232940,
                        "Name": "Test Ticket for host",
                        "Updated": "2019-12-30T11:28:00"
                    }
                ],
                "Ticket": [
                    {
                        "ConnectorName": "Test JIRA ",
                        "DeepLink": "https://risksense.atlassian.net/browse/JINT-525",
                        "DetailedStatus": "",
                        "TicketNumber": "JINT-525",
                        "TicketStatus": "To Do",
                        "Type": "JIRA"
                    }
                ],
                "Total": 2,
                "Xrs3": null,
                "Xrs3date": null
            }
        ]
    }
```

##### Human Readable Output

### Client: The Demo Client

### Host Details:

  **Name**         | **IP**       |  **RS3** |  **Discovered On** |  **Last Found On**
  -----------------| -------------| ---------|  ------------------|  -------------------
  united-78c957c5  | 53.132.37.52 | 351      | 2007-01-23         | 2007-01-23
                                                                 

### Findings Distribution:

  **Total**  | **Critical** |  **High** |  **Medium** |   **Low** |    **Info**
  -----------| -------------|---------- | ------------| --------- | ----------
  2          | 2            |  0        |  0          |  0        |  0
                                                               

### Operating System:

  **Name**        | **Vendor**  | **Class**     |  **Family**
  ----------------| ------------| --------------|    ------------
  Windows 2008/7  |  Microsoft  | Not Reported  |  Windows
                                               

### Tag(s) (4):

  **Name**                  | **Category**  | **Description**  | **Created**          | **Updated**
  --------------------------| --------------| -----------------| ---------------------| ---------------------
  Data\_Center\_2           | LOCATION      |                  | 2019-04-24T21:37:06  | 2019-04-24T21:37:06
  Windows\_Server\_Team\_1  | PEOPLE        |                  | 2019-04-24T21:42:34  | 2019-04-24T21:42:34
  Dev\_Servers              | CUSTOM        |                  | 2019-10-29T20:22:25  | 2019-10-29T20:22:25
  Test Ticket for host      | SCANNER       |                  | 2019-12-30T11:27:57  | 2019-12-30T11:28:00

### Ticket(s) (1):

  **Ticket Number**  | **Ticket Status**  | **Deep Link**                                    | **Type**  | **Connector Name**
  -------------------| -------------------| ------------------------------------------------ | ----------| --------------------
  JINT-525           | To Do              | https://risksense.atlassian.net/browse/JINT-525  | JIRA      | Test JIRA
                                                                                                       

### Group Details:
 Name: Default Group 
### Most Recently
Identified Service(s): msrpc-epmap, blackjack, microsoft-ds, ica,
ms-wbt-server, www, netbios-ssn, VxWorks
 ### Sources: Scanner(s):
QUALYS

### 3. risksense-get-unique-cves
---
Lookup vulnerability details per host finding with its base score.
##### Base Command

`risksense-get-unique-cves`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostFindingId | The unique host finding ID.HostFindingId is either known by RiskSense users or it can be found in human-readable output or context data(RiskSense.HostFinding.Id) after executing 'risksense-get-open-host-findings' or 'risksense-get-close-host-findings' command. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RiskSense.HostFinding.Vulnerability.Cve | String | Common Vulnerabilities and Exposures name. | 
| RiskSense.HostFinding.Vulnerability.BaseScore | Unknown | The base score represents Severity(informational, low, medium, high, critical) of risk. | 
| RiskSense.HostFinding.Vulnerability.ThreatCount | Number | Total number of Threats found. | 
| RiskSense.HostFinding.Vulnerability.AttackVector | String | The Attack vectors are a path by which attackers can gain access to the network. | 
| RiskSense.HostFinding.Vulnerability.AccessComplexity | String | The Access complexity describes conditions that are beyond the attacker's control that must exist to exploit the vulnerability. | 
| RiskSense.HostFinding.Vulnerability.Authentication | String | The Authentication value represents the attacker's authorization to get network access. | 
| RiskSense.HostFinding.Vulnerability.ConfidentialityImpact | String | The Confidentiality impact measures the potential impact on the confidentiality of a successfully exploited misuse vulnerability. | 
| RiskSense.HostFinding.Vulnerability.Integrity | String | Integrity refers to the trustworthiness and veracity of information. | 
| RiskSense.HostFinding.Vulnerability.AvailabilityImpact | String | The Availability refers to the accessibility of network resources. | 
| RiskSense.HostFinding.Vulnerability.Trending | Boolean | Trending is defined by RiskSense as vulnerabilities that are being actively abused by attackers in the wild based on activity in hacker forums, Twitter feeds as well as analysis of 3rd party threat intelligence sources. | 
| RiskSense.HostFinding.Vulnerability.VulnLastTrendingOn | String | The Last trending date of vulnerability. | 


##### Command Example
```
!risksense-get-unique-cves hostFindingId=115469504
```

##### Context Example
```
 {
        "RiskSense.HostFinding.Vulnerability": [
            {
                "AccessComplexity": "Low",
                "AttackVector": "Network",
                "Authentication": "None",
                "AvailabilityImpact": "Complete",
                "BaseScore": 10,
                "ConfidentialityImpact": "Complete",
                "Cve": "CVE-2007-0882",
                "Integrity": "Complete",
                "ThreatCount": 5,
                "Trending": false,
                "VulnLastTrendingOn": null
            }
        ]
    }
```

##### Human Readable Output

### Client: The Demo Client

### Vulnerabilities found:

  **Name**       | **V2/Score** |  **Attack Vector** |  **Attack Complexity** |  **Authentication** |  **Confidentiality Impact** |  **Integrity Impact** |  **Availability Impact**  | **Summary**
  ---------------|--------------| -------------------| -----------------------| --------------------| ----------------------------| ----------------------| ------------------------- |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  CVE-2007-0882  | 10.0         |  Network           |  Low                   |  None               |  Complete                   |  Complete             |  Complete                 | Argument injection vulnerability in the telnet daemon (in.telnetd) in Solaris 10 and 11 (SunOS 5.10 and 5.11) misinterprets certain client "-f" sequences as valid requests for the login program to skip authentication, which allows remote attackers to log into certain accounts, as demonstrated by the bin account.

### 4. risksense-get-unique-open-findings
---
This command is used to find unique open host findings.The open findings can be searched based on input parameters like fieldname (severity, title, source etc), operator (exact, in, like), page and size.
##### Base Command

`risksense-get-unique-open-findings`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fieldname | The RiskSense unique open finding fields that should be considered for filtering the results like title, severity and source. Users can specify any RiskSense field which use to filter. If specified, the 'value' argument is mandatory. | Optional | 
| operator | The match operator that should be applied for filtering the unique open finding based on 'fieldname' and 'value'. Available options are 'EXACT' - filter records exactly matching the criteria; 'IN' - filter records matching any one of the comma-separated values;'LIKE' - filter records with specific pattern provided. | Optional | 
| value | The value of the unique open finding property mentioned in 'fieldname' to be considered for filter criteria. | Optional | 
| exclusive_operator | The exclusive operator flag that determines whether the returned records matches filter criteria or not. By default set to False. | Optional | 
| page | The index of the page. The index is a numeric value and starting with 0. | Optional | 
| size | The maximum number of records to be fetched in one page. | Optional | 
| sort_by | The fieldname that should be considered for sorting the returned records. | Optional | 
| sort_order | The sorting order to be considerd for retunred records. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RiskSense.UniqueHostFinding.Title | String | The title of the unique host finding. | 
| RiskSense.UniqueHostFinding.Severity | Number | Similar to risk rating, the severity of a vulnerability conveys the potential threat posed. | 
| RiskSense.UniqueHostFinding.HostCount | Number | The total number of the host found in unique host finding. | 
| RiskSense.UniqueHostFinding.Source | String | The name of the source associated with the unique host finding. | 
| RiskSense.UniqueHostFinding.SourceId | String | The unique ID of the source. | 
| RiskSense.UniqueHostFinding.Href | String | Reference API link of unique host finding search. | 


##### Command Example
```
!risksense-get-unique-open-findings fieldname=source value=QUALYS sort_by=Severity sort_order=DESC size="3"
```

##### Context Example
```
{
    "RiskSense.UniqueHostFinding": [
        {
            "Severity": 10, 
            "Title": "Solaris 10 and Solaris 11 (SolarisExpress) Remote Access Telnet Daemon Flaw", 
            "SourceId": "QUALYS38574", 
            "HostCount": 22, 
            "Source": "QUALYS", 
            "Href": "http://platform.risksense.com/api/v1/client/747/uniqueHostFinding/search?page=0&size=3&sort=severity,desc"
        }, 
        {
            "Severity": 10, 
            "Title": "FreeBSD Telnetd Code Execution Vulnerability (FreeBSD-SA-11:08)", 
            "SourceId": "QUALYS119834", 
            "HostCount": 17, 
            "Source": "QUALYS", 
            "Href": "http://platform.risksense.com/api/v1/client/747/uniqueHostFinding/search?page=0&size=3&sort=severity,desc"
        }, 
        {
            "Severity": 10, 
            "Title": "Microsoft SMB Server Remote Code Execution Vulnerability (MS17-010) and Shadow Brokers", 
            "SourceId": "QUALYS91345", 
            "HostCount": 140, 
            "Source": "QUALYS", 
            "Href": "http://platform.risksense.com/api/v1/client/747/uniqueHostFinding/search?page=0&size=3&sort=severity,desc"
        }
    ]
}
```

##### Human Readable Output
### Total unique open findings: 3949		 Page: 0/1316		 Client: The Demo Client
### Unique open finding(s) details:
|Title|Severity|Asset Count|Source|Source Id|
|---|---|---|---|---|
| Solaris 10 and Solaris 11 (SolarisExpress) Remote Access Telnet Daemon Flaw | 10.0 | 22 | QUALYS | QUALYS38574 |
| FreeBSD Telnetd Code Execution Vulnerability (FreeBSD-SA-11:08) | 10.0 | 17 | QUALYS | QUALYS119834 |
| Microsoft SMB Server Remote Code Execution Vulnerability (MS17-010) and Shadow Brokers | 10.0 | 140 | QUALYS | QUALYS91345 |


### 5. risksense-get-open-host-findings
---
A detailed open host finding view with the severity level. Displays vulnerability information like CVE, Threats associated with current findings and origin of findings.
##### Base Command

`risksense-get-open-host-findings`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fieldname | The list of fields that are used to filter the host results like Hostname, IP Address, Titles, etc. Users can specify any RiskSense field which use to filter. If the fieldname is selected, the 'value' argument is mandatory. | Optional | 
| operator | The match operator that should be applied for filtering the hosts based on 'fieldname' and 'value'. Available options are 'EXACT' - filter records exactly matching the criteria; 'IN' - filter records matching any one of the comma-separated values; 'LIKE' - filter records with specific pattern provided. | Optional | 
| exclusive_operator | The exclusive operator flag that determines whether the returned records matches filter criteria or not. By default set to False. | Optional | 
| value | The value of the 'fieldname' to be considered for filter criteria. | Optional | 
| page | The status of the current page. | Optional | 
| size | The maximum number of records to be fetched in one page. | Optional | 
| sort_by | The fieldname that should be considered for sorting the returned records. | Optional | 
| sort_order | The sorting order to be considered for returned records. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RiskSense.HostFinding.Id | string | The unique ID of the host finding. | 
| RiskSense.HostFinding.Source | string | Host discovered by the scanner. | 
| RiskSense.HostFinding.SourceId | string | Scanner Id of discovered scanner. | 
| RiskSense.HostFinding.Title | string | The title of the host finding. | 
| RiskSense.HostFinding.Port | integer | The port number of the host finding. | 
| RiskSense.HostFinding.GroupCount | integer | The total number of groups for host finding. | 
| RiskSense.HostFinding.Group.Id | integer | The unique ID of the group associated with the host finding. | 
| RiskSense.HostFinding.Group.Name | string | The name of the group associated with the host finding. | 
| RiskSense.HostFinding.Host.HostId | integer | The unique ID of the host associated with the host finding. | 
| RiskSense.HostFinding.Host.HostName | string | The Hostname of the host associated with the host finding. | 
| RiskSense.HostFinding.Host.IpAddress | string | The IP Address of the host associated with the host finding. | 
| RiskSense.HostFinding.Host.Criticality | integer | The criticality of the host associated with the host finding. | 
| RiskSense.HostFinding.Host.External | boolean | To identify if the host is external or internal. | 
| RiskSense.HostFinding.Host.Port.Id | integer | The unique ID of the Host(s) Port associated with the host finding. | 
| RiskSense.HostFinding.Host.Port.Number | integer | The port number of the host associated with the host finding. | 
| RiskSense.HostFinding.Host.Rs3 | integer | The Asset Security Score calculated by the RiskSense platform (includes vulnerability risk on related web applications). | 
| RiskSense.HostFinding.Network.Id | integer | The network ID of the host finding. | 
| RiskSense.HostFinding.Network.Name | string | The name of the network used by the host finding. | 
| RiskSense.HostFinding.Network.Type | string | The type of the network used by the host finding. | 
| RiskSense.HostFinding.Assessment.Id | integer | The assessment ID of the host finding. | 
| RiskSense.HostFinding.Assessment.Name | String | The name of the assessment associated with the host finding. | 
| RiskSense.HostFinding.Assessment.Date | String | The time when the assessment is created. | 
| RiskSense.HostFinding.Vulnerability.Cve | String | The name of the Common Vulnerabilities and Exposures associated with the host finding. | 
| RiskSense.HostFinding.Vulnerability.BaseScore | number | CVE Score. | 
| RiskSense.HostFinding.Vulnerability.ThreatCount | integer | The total number of threats associated with the host finding. | 
| RiskSense.HostFinding.Vulnerability.AttackVector | String | Vector information in which it has been attacked. | 
| RiskSense.HostFinding.Vulnerability.AccessComplexity | String | Complexity Level. | 
| RiskSense.HostFinding.Vulnerability.Authentication | String | Authentication value represents attackers authorization to get network access. | 
| RiskSense.HostFinding.Vulnerability.ConfidentialityImpact | String | Confidentiality impact measures the potential impact on confidentiality of a successfully exploited misuse vulnerability. | 
| RiskSense.HostFinding.Vulnerability.Integrity | String | Integrity refers to the trustworthiness and veracity of information. | 
| RiskSense.HostFinding.Vulnerability.AvailabilityImpact | String | Availability refers to accessibility of network resources. | 
| RiskSense.HostFinding.Vulnerability.Trending | boolean | This signifies whether the vulnerability (which is associated with the hostFinding) has been reported by our internal functions as being trending. | 
| RiskSense.HostFinding.Vulnerability.VulnLastTrendingOn | String | Date when last trending found. | 
| RiskSense.HostFinding.ThreatCount | integer | The total number of threats. | 
| RiskSense.HostFinding.Threat.Title | String | The title of threat. | 
| RiskSense.HostFinding.Threat.Category | String | The category of threat. | 
| RiskSense.HostFinding.Threat.Severity | String | The severity level of threat. | 
| RiskSense.HostFinding.Threat.Description | String | The threat description. | 
| RiskSense.HostFinding.Threat.Cve | Unknown | The Common Vulnerabilities and Exposures name of the threat. | 
| RiskSense.HostFinding.Threat.Source | String | The source of the threat. | 
| RiskSense.HostFinding.Threat.Published | String | The time when threat was published. | 
| RiskSense.HostFinding.Threat.Updated | String | The time when the threat was last updated. | 
| RiskSense.HostFinding.Threat.ThreatLastTrendingOn | String | The last time when threat was in trending. | 
| RiskSense.HostFinding.Threat.Trending | boolean | To check whether threat is trending or not. | 
| RiskSense.HostFinding.Patch.Name | String | The patch name of the host finding. | 
| RiskSense.HostFinding.Patch.Url | String | The patch url of the host finding. | 
| RiskSense.HostFinding.TagCount | integer | The total number of tags associated with host finding. | 
| RiskSense.HostFinding.Tag.Id | integer | The Tag identifier of the host finding. | 
| RiskSense.HostFinding.Tag.Name | String | The tag name of the host finding. | 
| RiskSense.HostFinding.Tag.Category | String | The tag category of the host finding. | 
| RiskSense.HostFinding.Tag.Description | String | The tag description of the host finding. | 
| RiskSense.HostFinding.Tag.Created | String | The time when the tag is created. | 
| RiskSense.HostFinding.Tag.Updated | String | The time when the tag is last updated. | 
| RiskSense.HostFinding.Tag.Color | String | The color of the tag. | 
| RiskSense.HostFinding.TagAssetCount | integer | The total number of tag assets. | 
| RiskSense.HostFinding.TagAsset.Id | integer | The ID of the tag asset. | 
| RiskSense.HostFinding.TagAsset.Name | String | The name of the tag asset. | 
| RiskSense.HostFinding.TagAsset.Category | String | The category of the tag asset. | 
| RiskSense.HostFinding.TagAsset.Description | String | The description of the tag asset. | 
| RiskSense.HostFinding.TagAsset.Created | String | The time Date when tag asset created. | 
| RiskSense.HostFinding.TagAsset.Updated | String | The time when tag asset was last updated. | 
| RiskSense.HostFinding.TagAsset.Color | String | The color name of the tag asset. | 
| RiskSense.HostFinding.Output | String | The output of the host finding. | 
| RiskSense.HostFinding.Severity | number | The severity of the host finding. | 
| RiskSense.HostFinding.SeverityDetail.Combined | number | The combined name of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.Overridden | boolean | The overridden name of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.Scanner | string | The scanner of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.CvssV2 | number | The cvssv2 value of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.CvssV3 | number | The cvssv3 value of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.Aggregated | number | The aggregated value of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.State | string | The state of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.StateName | string | The state name of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.ExpirationDate | string | The time when severity detail was expired. | 
| RiskSense.HostFinding.RiskRating | number | The risk rate of the host finding. | 
| RiskSense.HostFinding.Xrs3Impact | string | The impact of xrs3 for the host finding. | 
| RiskSense.HostFinding.Xrs3ImpactOnCategory | String | The category impact of xrs3 for the host finding. | 
| RiskSense.HostFinding.LastFoundOn | String | The latest time when the particular host finding is found. | 
| RiskSense.HostFinding.DiscoveredOn | String | The time when hostfinding was discovered. | 
| RiskSense.HostFinding.ResolvedOn | String | The time when the host finding was resolved. | 
| RiskSense.HostFinding.ScannerName | String | The name of the scanner of the host finding. | 
| RiskSense.HostFinding.FindingType | String | The finding type of the host finding. | 
| RiskSense.HostFinding.MachineId | String | The machine ID of the host finding. | 
| RiskSense.HostFinding.StatusEmbedded.State | String | The current state of embedded status associated with the host finding. | 
| RiskSense.HostFinding.StatusEmbedded.StateName | String | The state name of embedded status associated with the host finding. | 
| RiskSense.HostFinding.StatusEmbedded.StateDescription | String | The state description of embedded status associated with the host finding. | 
| RiskSense.HostFinding.StatusEmbedded.Status | boolean | The status of embedded status associated with the host finding. | 
| RiskSense.HostFinding.StatusEmbedded.DurationInDays | String | The time duration (In days) of embedded status associated with the host finding. | 
| RiskSense.HostFinding.StatusEmbedded.DueDate | String | The due date of embedded status associated with the host finding. | 
| RiskSense.HostFinding.StatusEmbedded.ExpirationDate | String | The time when status is expired associated with the host findin.. | 
| RiskSense.HostFinding.ManualFindingReportCount | integer | The total number of manual finding reports associated with the host finding. | 
| RiskSense.HostFinding.ManualFindingReport.Id | integer | The ID of manual finding reports associated with the host finding. | 
| RiskSense.HostFinding.ManualFindingReport.Title | String | The title of manual finding reports associated with the host finding. | 
| RiskSense.HostFinding.ManualFindingReport.Label | String | The label of manual finding reports associated with the host finding. | 
| RiskSense.HostFinding.ManualFindingReport.Pii | String | The pii number of manual finding reports associated with the host finding. | 
| RiskSense.HostFinding.ManualFindingReport.Source | String | The source of manual finding reports associated with the host finding. | 
| RiskSense.HostFinding.ManualFindingReport.IsManualExploit | boolean | To check whether manual finding report exploit or not. | 
| RiskSense.HostFinding.ManualFindingReport.EaseOfExploit | String | The total number of manual finding reports associated with the host finding. | 
| RiskSense.HostFinding.NoteCount | integer | Number of notes found. | 
| RiskSense.HostFinding.Note.Date | String | The time when note is added by the user for the host finding. | 
| RiskSense.HostFinding.Note.Note | String | The notes that are added by the user for the host finding. | 
| RiskSense.HostFinding.Note.UserId | integer | The User ID of the user who added a note for the host finding. | 
| RiskSense.HostFinding.Note.UserName | String | The Username of the user who added a note for the host finding. | 
| RiskSense.HostFinding.Assignment.Id | integer | The unique ID of the assignment associated with the host finding. | 
| RiskSense.HostFinding.Assignment.FirstName | String | The first name of the assigned user for the host finding. | 
| RiskSense.HostFinding.Assignment.LastName | String | The last name of the assigned user for the host finding. | 
| RiskSense.HostFinding.Assignment.ReceiveEmails | boolean | Indicates whether email is received or not. | 
| RiskSense.HostFinding.Assignment.Email | string | The email of the assigned user for the host finding. | 
| RiskSense.HostFinding.Assignment.Username | string | The username of the assigned user for the host finding. | 
| RiskSense.HostFinding.Services | string | The name of the services for the host finding. | 


##### Command Example
```
!risksense-get-open-host-findings fieldname=hostName value=loz.xg.mil sort_by="Risk Rating" sort_order=DESC size="2"
```

##### Context Example
```
{
    "RiskSense.HostFinding": [
        {
            "ResolvedOn": "", 
            "Group": [
                {
                    "Id": 7990, 
                    "Name": "Default Group"
                }
            ], 
            "Network": {
                "Type": "IP", 
                "Id": 78038, 
                "Name": "IP Network"
            }, 
            "StatusEmbedded": {
                "Status": true, 
                "StateDescription": "Finding not assigned to a user", 
                "StateName": "Unassigned", 
                "State": "UNASSIGNED", 
                "ExpirationDate": "", 
                "DurationInDays": "3315", 
                "DueDate": "2019-12-01T00:00:00"
            }, 
            "Title": "Sendmail SSL Certificate NULL Character Spoofing Vulnerability", 
            "SourceId": "QUALYS74240", 
            "GroupCount": 1, 
            "Note": [], 
            "Source": "QUALYS", 
            "SeverityDetail": {
                "CvssV3": null, 
                "CvssV2": 7.5, 
                "Scanner": "3", 
                "Overridden": false, 
                "StateName": null, 
                "State": null, 
                "ExpirationDate": "", 
                "Aggregated": 7.5, 
                "Combined": 7.5
            }, 
            "Assessment": [
                {
                    "Date": "2019-04-23", 
                    "Id": 67442, 
                    "Name": "First Assessment"
                }
            ], 
            "TagCount": 4, 
            "Severity": 7.5, 
            "RiskRating": 5.67, 
            "Assignment": [], 
            "Xrs3ImpactOnCategory": null, 
            "TagAsset": [
                {
                    "Category": "Location", 
                    "Updated": "2019-06-19T19:23:08", 
                    "Name": "Data_Center_1", 
                    "Created": "2019-04-24T21:35:12", 
                    "Color": "#dd8361", 
                    "Id": 215551
                }, 
                {
                    "Category": "People", 
                    "Updated": "2019-04-24T21:39:59", 
                    "Name": "Linux_Team_2", 
                    "Created": "2019-04-24T21:39:59", 
                    "Color": "#78a19b", 
                    "Id": 215554
                }
            ], 
            "Host": {
                "HostId": 3569982, 
                "Criticality": 5, 
                "HostName": "loz.xg.mil", 
                "External": true, 
                "IpAddress": "116.145.139.179", 
                "Port": [
                    {
                        "Id": 42841210, 
                        "Number": 21
                    }, 
                    {
                        "Id": 42841323, 
                        "Number": 22
                    }, 
                    {
                        "Id": 42841347, 
                        "Number": 23
                    }, 
                    {
                        "Id": 42841183, 
                        "Number": 25
                    }, 
                    {
                        "Id": 42841178, 
                        "Number": 111
                    }, 
                    {
                        "Id": 42841312, 
                        "Number": 123
                    }, 
                    {
                        "Id": 42841336, 
                        "Number": 587
                    }, 
                    {
                        "Id": 42841279, 
                        "Number": 852
                    }, 
                    {
                        "Id": 42841222, 
                        "Number": 6112
                    }, 
                    {
                        "Id": 42841168, 
                        "Number": 7100
                    }, 
                    {
                        "Id": 42841236, 
                        "Number": 8005
                    }, 
                    {
                        "Id": 42841197, 
                        "Number": 8007
                    }, 
                    {
                        "Id": 42841329, 
                        "Number": 32771
                    }, 
                    {
                        "Id": 42841246, 
                        "Number": 32772
                    }, 
                    {
                        "Id": 42841259, 
                        "Number": 32775
                    }, 
                    {
                        "Id": 42841269, 
                        "Number": 32776
                    }, 
                    {
                        "Id": 42841361, 
                        "Number": 32777
                    }, 
                    {
                        "Id": 42841370, 
                        "Number": 32778
                    }, 
                    {
                        "Id": 42841172, 
                        "Number": 32779
                    }
                ], 
                "Rs3": 644
            }, 
            "MachineId": "", 
            "Services": "smtp", 
            "ThreatCount": 0, 
            "Xrs3Impact": null, 
            "DiscoveredOn": "2011-01-21", 
            "NoteCount": 0, 
            "Vulnerability": [
                {
                    "Trending": false, 
                    "AttackVector": "Network", 
                    "VulnLastTrendingOn": null, 
                    "BaseScore": 7.5, 
                    "AvailabilityImpact": "Partial", 
                    "Authentication": "None", 
                    "AccessComplexity": "Low", 
                    "ConfidentialityImpact": "Partial", 
                    "Cve": "CVE-2009-4565", 
                    "Integrity": "Partial", 
                    "ThreatCount": 0
                }
            ], 
            "Patch": [
                {
                    "Url": "http://www.sendmail.org/releases/8.14.4", 
                    "Name": "qualys74240"
                }
            ], 
            "Threat": [], 
            "Output": "220 lOz.Xg.mil ESMTP Sendmail lna.To.us+Sun/lna.To.us; Fri, 23 Nov 2012 00:54:14 -0500 (EST)", 
            "ManualFindingReport": [], 
            "TagAssetCount": [
                {
                    "category": "Location", 
                    "updated": "2019-06-19T19:23:08", 
                    "description": "", 
                    "created": "2019-04-24T21:35:12", 
                    "color": "#dd8361", 
                    "id": 215551, 
                    "name": "Data_Center_1"
                }, 
                {
                    "category": "People", 
                    "updated": "2019-04-24T21:39:59", 
                    "description": "", 
                    "created": "2019-04-24T21:39:59", 
                    "color": "#78a19b", 
                    "id": 215554, 
                    "name": "Linux_Team_2"
                }
            ], 
            "ManualFindingReportCount": 0, 
            "FindingType": "Auth/Unauthenticated", 
            "Id": 115469577, 
            "Tag": [
                {
                    "Category": "Location", 
                    "Updated": "2019-06-19T19:23:08", 
                    "Name": "Data_Center_1", 
                    "Created": "2019-04-24T21:35:12", 
                    "Color": "#dd8361", 
                    "Id": 215551, 
                    "Description": ""
                }, 
                {
                    "Category": "People", 
                    "Updated": "2019-04-24T21:39:59", 
                    "Name": "Linux_Team_2", 
                    "Created": "2019-04-24T21:39:59", 
                    "Color": "#78a19b", 
                    "Id": 215554, 
                    "Description": ""
                }, 
                {
                    "Category": "Custom", 
                    "Updated": "2019-08-28T17:27:15", 
                    "Name": "State Assigned  Unassigned", 
                    "Created": "2019-08-28T17:27:15", 
                    "Color": "#648d9f", 
                    "Id": 225744, 
                    "Description": ""
                }, 
                {
                    "Category": "Project", 
                    "Updated": "2019-10-31T03:40:55", 
                    "Name": "PCI Assets", 
                    "Created": "2019-08-28T18:50:30", 
                    "Color": "#648d9f", 
                    "Id": 225750, 
                    "Description": ""
                }
            ], 
            "LastFoundOn": "2011-01-21", 
            "Port": 25, 
            "ScannerName": "QUALYS"
        }, 
        {
            "ResolvedOn": "", 
            "Group": [
                {
                    "Id": 7990, 
                    "Name": "Default Group"
                }
            ], 
            "Network": {
                "Type": "IP", 
                "Id": 78038, 
                "Name": "IP Network"
            }, 
            "StatusEmbedded": {
                "Status": true, 
                "StateDescription": "Finding not assigned to a user", 
                "StateName": "Unassigned", 
                "State": "UNASSIGNED", 
                "ExpirationDate": "", 
                "DurationInDays": "3315", 
                "DueDate": "2019-12-01T00:00:00"
            }, 
            "Title": "Sendmail SSL Certificate NULL Character Spoofing Vulnerability", 
            "SourceId": "QUALYS74240", 
            "GroupCount": 1, 
            "Note": [], 
            "Source": "QUALYS", 
            "SeverityDetail": {
                "CvssV3": null, 
                "CvssV2": 7.5, 
                "Scanner": "3", 
                "Overridden": false, 
                "StateName": null, 
                "State": null, 
                "ExpirationDate": "", 
                "Aggregated": 7.5, 
                "Combined": 7.5
            }, 
            "Assessment": [
                {
                    "Date": "2019-04-23", 
                    "Id": 67442, 
                    "Name": "First Assessment"
                }
            ], 
            "TagCount": 4, 
            "Severity": 7.5, 
            "RiskRating": 5.67, 
            "Assignment": [], 
            "Xrs3ImpactOnCategory": null, 
            "TagAsset": [
                {
                    "Category": "Location", 
                    "Updated": "2019-06-19T19:23:08", 
                    "Name": "Data_Center_1", 
                    "Created": "2019-04-24T21:35:12", 
                    "Color": "#dd8361", 
                    "Id": 215551
                }, 
                {
                    "Category": "People", 
                    "Updated": "2019-04-24T21:39:59", 
                    "Name": "Linux_Team_2", 
                    "Created": "2019-04-24T21:39:59", 
                    "Color": "#78a19b", 
                    "Id": 215554
                }
            ], 
            "Host": {
                "HostId": 3569982, 
                "Criticality": 5, 
                "HostName": "loz.xg.mil", 
                "External": true, 
                "IpAddress": "116.145.139.179", 
                "Port": [
                    {
                        "Id": 42841210, 
                        "Number": 21
                    }, 
                    {
                        "Id": 42841323, 
                        "Number": 22
                    }, 
                    {
                        "Id": 42841347, 
                        "Number": 23
                    }, 
                    {
                        "Id": 42841183, 
                        "Number": 25
                    }, 
                    {
                        "Id": 42841178, 
                        "Number": 111
                    }, 
                    {
                        "Id": 42841312, 
                        "Number": 123
                    }, 
                    {
                        "Id": 42841336, 
                        "Number": 587
                    }, 
                    {
                        "Id": 42841279, 
                        "Number": 852
                    }, 
                    {
                        "Id": 42841222, 
                        "Number": 6112
                    }, 
                    {
                        "Id": 42841168, 
                        "Number": 7100
                    }, 
                    {
                        "Id": 42841236, 
                        "Number": 8005
                    }, 
                    {
                        "Id": 42841197, 
                        "Number": 8007
                    }, 
                    {
                        "Id": 42841329, 
                        "Number": 32771
                    }, 
                    {
                        "Id": 42841246, 
                        "Number": 32772
                    }, 
                    {
                        "Id": 42841259, 
                        "Number": 32775
                    }, 
                    {
                        "Id": 42841269, 
                        "Number": 32776
                    }, 
                    {
                        "Id": 42841361, 
                        "Number": 32777
                    }, 
                    {
                        "Id": 42841370, 
                        "Number": 32778
                    }, 
                    {
                        "Id": 42841172, 
                        "Number": 32779
                    }
                ], 
                "Rs3": 644
            }, 
            "MachineId": "", 
            "Services": "smtp, submission", 
            "ThreatCount": 0, 
            "Xrs3Impact": null, 
            "DiscoveredOn": "2011-01-21", 
            "NoteCount": 0, 
            "Vulnerability": [
                {
                    "Trending": false, 
                    "AttackVector": "Network", 
                    "VulnLastTrendingOn": null, 
                    "BaseScore": 7.5, 
                    "AvailabilityImpact": "Partial", 
                    "Authentication": "None", 
                    "AccessComplexity": "Low", 
                    "ConfidentialityImpact": "Partial", 
                    "Cve": "CVE-2009-4565", 
                    "Integrity": "Partial", 
                    "ThreatCount": 0
                }
            ], 
            "Patch": [
                {
                    "Url": "http://www.sendmail.org/releases/8.14.4", 
                    "Name": "qualys74240"
                }
            ], 
            "Threat": [], 
            "Output": "220 lOz.Xg.mil ESMTP Sendmail lna.To.us+Sun/lna.To.us; Fri, 23 Nov 2012 00:58:04 -0500 (EST)", 
            "ManualFindingReport": [], 
            "TagAssetCount": [
                {
                    "category": "Location", 
                    "updated": "2019-06-19T19:23:08", 
                    "description": "", 
                    "created": "2019-04-24T21:35:12", 
                    "color": "#dd8361", 
                    "id": 215551, 
                    "name": "Data_Center_1"
                }, 
                {
                    "category": "People", 
                    "updated": "2019-04-24T21:39:59", 
                    "description": "", 
                    "created": "2019-04-24T21:39:59", 
                    "color": "#78a19b", 
                    "id": 215554, 
                    "name": "Linux_Team_2"
                }
            ], 
            "ManualFindingReportCount": 0, 
            "FindingType": "Auth/Unauthenticated", 
            "Id": 115469699, 
            "Tag": [
                {
                    "Category": "Location", 
                    "Updated": "2019-06-19T19:23:08", 
                    "Name": "Data_Center_1", 
                    "Created": "2019-04-24T21:35:12", 
                    "Color": "#dd8361", 
                    "Id": 215551, 
                    "Description": ""
                }, 
                {
                    "Category": "People", 
                    "Updated": "2019-04-24T21:39:59", 
                    "Name": "Linux_Team_2", 
                    "Created": "2019-04-24T21:39:59", 
                    "Color": "#78a19b", 
                    "Id": 215554, 
                    "Description": ""
                }, 
                {
                    "Category": "Custom", 
                    "Updated": "2019-08-28T17:27:15", 
                    "Name": "State Assigned  Unassigned", 
                    "Created": "2019-08-28T17:27:15", 
                    "Color": "#648d9f", 
                    "Id": 225744, 
                    "Description": ""
                }, 
                {
                    "Category": "Project", 
                    "Updated": "2019-10-31T03:40:55", 
                    "Name": "PCI Assets", 
                    "Created": "2019-08-28T18:50:30", 
                    "Color": "#648d9f", 
                    "Id": 225750, 
                    "Description": ""
                }
            ], 
            "LastFoundOn": "2011-01-21", 
            "Port": 587, 
            "ScannerName": "QUALYS"
        }
    ]
}
```

##### Human Readable Output
### Total open host findings: 13		 Page: 0/6		 Client: The Demo Client
### Open host finding(s) details:
|Id|Hostname|IP Address|Title|Risk|Threats|Rs3|Criticality|Severity|Groups|Port|State|Assignments|Tags|Asset Tags|Note|Manual Finding Report Count|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 115469577 | loz.xg.mil | 116.145.139.179 | Sendmail SSL Certificate NULL Character Spoofing Vulnerability | 5.67 | 0 | 644 | 5 | 7.5 | 1 | 25 | UNASSIGNED |  | 4 | 2 | 0 | 0 |
| 115469699 | loz.xg.mil | 116.145.139.179 | Sendmail SSL Certificate NULL Character Spoofing Vulnerability | 5.67 | 0 | 644 | 5 | 7.5 | 1 | 587 | UNASSIGNED |  | 4 | 2 | 0 | 0 |


### 6. risksense-get-closed-host-findings
---
A detail of close host finding with its severity level divided into Critical, High, Medium, Low and info part.Displays vulnerability information like CVE, threats associated with current findings and origin of findings.
##### Base Command

`risksense-get-closed-host-findings`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fieldname | List of fields that are used to filter host results like hostName, ipAddress, titles, etc. Users can specify any RiskSense field which use to filter. If the field name is selected, the 'value' argument is mandatory. | Optional | 
| operator | The operator values like EXACT, IN, LIKE. Default it works as 'EXACT' if no operator value provided.EXACT - will search by exact match.IN - accept a comma-separated value. It will search for all valid matches.LIKE - It will work as a wildcard operator. | Optional | 
| exclusive_operator | By default set to False, where open host findings matching the specified values are fetched. If set to True, host findings not matching the specified values are fetched. | Optional | 
| value | The value which is given by the user. | Optional | 
| page | Status of the current page. | Optional | 
| size | Display number of records on a specific page. | Optional | 
| sort_by | Fieldname which is used to perform sorting. | Optional | 
| sort_order | The sorting order to be considered for returned records. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RiskSense.HostFinding.Id | string | The unique ID of the host finding. | 
| RiskSense.HostFinding.Source | string | Host discovered by the scanner. | 
| RiskSense.HostFinding.SourceId | string | Scanner Id of discovered scanner. | 
| RiskSense.HostFinding.Title | string | The title of the host finding. | 
| RiskSense.HostFinding.Port | integer | The port number of the host finding. | 
| RiskSense.HostFinding.GroupCount | integer | The total number of groups for host finding. | 
| RiskSense.HostFinding.Group.Id | integer | The unique ID of the group associated with the host finding. | 
| RiskSense.HostFinding.Group.Name | string | The name of the group associated with the host finding. | 
| RiskSense.HostFinding.Host.HostId | integer | The unique ID of the host associated with the host finding. | 
| RiskSense.HostFinding.Host.HostName | string | The Hostname of the host associated with the host finding. | 
| RiskSense.HostFinding.Host.IpAddress | string | The IP Address of the host associated with the host finding. | 
| RiskSense.HostFinding.Host.Criticality | integer | The criticality of the host associated with the host finding. | 
| RiskSense.HostFinding.Host.External | boolean | To identify if the host is external or internal. | 
| RiskSense.HostFinding.Host.Port.Id | integer | The unique ID of the Host(s) Port associated with the host finding. | 
| RiskSense.HostFinding.Host.Port.Number | integer | The port number of the host associated with the host finding. | 
| RiskSense.HostFinding.Host.Rs3 | integer | The Asset Security Score calculated by the RiskSense platform (includes vulnerability risk on related web applications). | 
| RiskSense.HostFinding.Network.Id | integer | The network ID of the host finding. | 
| RiskSense.HostFinding.Network.Name | string | The name of the network used by the host finding. | 
| RiskSense.HostFinding.Network.Type | string | The type of the network used by the host finding. | 
| RiskSense.HostFinding.Assessment.Id | integer | The assessment ID of the host finding. | 
| RiskSense.HostFinding.Assessment.Name | String | The name of the assessment associated with the host finding. | 
| RiskSense.HostFinding.Assessment.Date | String | The time when the assessment is created. | 
| RiskSense.HostFinding.Vulnerability.Cve | String | The name of the Common Vulnerabilities and Exposures associated with the host finding. | 
| RiskSense.HostFinding.Vulnerability.BaseScore | number | CVE Score. | 
| RiskSense.HostFinding.Vulnerability.ThreatCount | integer | The total number of threats associated with the host finding. | 
| RiskSense.HostFinding.Vulnerability.AttackVector | String | Vector information in which it has been attacked. | 
| RiskSense.HostFinding.Vulnerability.AccessComplexity | String | Complexity Level. | 
| RiskSense.HostFinding.Vulnerability.Authentication | String | Authentication value represents attacker's authorization to get network access. | 
| RiskSense.HostFinding.Vulnerability.ConfidentialityImpact | String | Confidentiality impact measures the potential impact on confidentiality of a successfully exploited misuse vulnerability. | 
| RiskSense.HostFinding.Vulnerability.Integrity | String | Integrity refers to the trustworthiness and veracity of information. | 
| RiskSense.HostFinding.Vulnerability.AvailabilityImpact | String | Availability refers to accessibility of network resources. | 
| RiskSense.HostFinding.Vulnerability.Trending | boolean | This signifies whether the vulnerability (which is associated with the hostFinding) has been reported by our internal functions as being trending. | 
| RiskSense.HostFinding.Vulnerability.VulnLastTrendingOn | String | Date when last trending found. | 
| RiskSense.HostFinding.ThreatCount | integer | The total number of threats. | 
| RiskSense.HostFinding.Threat.Title | String | The title of threat. | 
| RiskSense.HostFinding.Threat.Category | String | The category of threat. | 
| RiskSense.HostFinding.Threat.Severity | String | The severity level of threat. | 
| RiskSense.HostFinding.Threat.Description | String | The threat description. | 
| RiskSense.HostFinding.Threat.Cve | Unknown | The Common Vulnerabilities and Exposures name of the threat. | 
| RiskSense.HostFinding.Threat.Source | String | The source of the threat. | 
| RiskSense.HostFinding.Threat.Published | String | The time when threat was published. | 
| RiskSense.HostFinding.Threat.Updated | String | The time when the threat was last updated. | 
| RiskSense.HostFinding.Threat.ThreatLastTrendingOn | String | The last time when threat was in trending. | 
| RiskSense.HostFinding.Threat.Trending | boolean | To check whether threat is trending or not. | 
| RiskSense.HostFinding.Patch.Name | String | The patch name of the host finding. | 
| RiskSense.HostFinding.Patch.Url | String | The patch url of the host finding. | 
| RiskSense.HostFinding.TagCount | integer | The total number of tags associated with host finding. | 
| RiskSense.HostFinding.Tag.Id | integer | The Tag identifier of the host finding. | 
| RiskSense.HostFinding.Tag.Name | String | The tag name of the host finding. | 
| RiskSense.HostFinding.Tag.Category | String | The tag category of the host finding. | 
| RiskSense.HostFinding.Tag.Description | String | The tag description of the host finding. | 
| RiskSense.HostFinding.Tag.Created | String | The time when the tag is created. | 
| RiskSense.HostFinding.Tag.Updated | String | The time when the tag is last updated. | 
| RiskSense.HostFinding.Tag.Color | String | The color of the tag. | 
| RiskSense.HostFinding.TagAssetCount | integer | The total number of tag assets. | 
| RiskSense.HostFinding.TagAsset.Id | integer | The ID of the tag asset. | 
| RiskSense.HostFinding.TagAsset.Name | String | The name of the tag asset. | 
| RiskSense.HostFinding.TagAsset.Category | String | The category of the tag asset. | 
| RiskSense.HostFinding.TagAsset.Description | String | The description of the tag asset. | 
| RiskSense.HostFinding.TagAsset.Created | String | The time Date when tag asset created. | 
| RiskSense.HostFinding.TagAsset.Updated | String | The time when tag asset was last updated. | 
| RiskSense.HostFinding.TagAsset.Color | String | The color name of the tag asset. | 
| RiskSense.HostFinding.Output | String | The output of the host finding. | 
| RiskSense.HostFinding.Severity | number | The severity of the host finding. | 
| RiskSense.HostFinding.SeverityDetail.Combined | number | The combined name of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.Overridden | boolean | The overridden name of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.Scanner | string | The scanner of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.CvssV2 | number | The cvssv2 value of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.CvssV3 | number | The cvssv3 value of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.Aggregated | number | The aggregated value of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.State | string | The state of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.StateName | string | The state name of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.ExpirationDate | string | The time when severity detail was expired. | 
| RiskSense.HostFinding.RiskRating | number | The risk rate of the host finding. | 
| RiskSense.HostFinding.Xrs3Impact | string | The impact of xrs3 for the host finding. | 
| RiskSense.HostFinding.Xrs3ImpactOnCategory | String | The category impact of xrs3 for the host finding. | 
| RiskSense.HostFinding.LastFoundOn | String | The latest time when the particular host finding is found. | 
| RiskSense.HostFinding.DiscoveredOn | String | The time when hostfinding was discovered. | 
| RiskSense.HostFinding.ResolvedOn | String | The time when the host finding was resolved. | 
| RiskSense.HostFinding.ScannerName | String | The name of the scanner of the host finding. | 
| RiskSense.HostFinding.FindingType | String | The finding type of the host finding. | 
| RiskSense.HostFinding.MachineId | String | The machine ID of the host finding. | 
| RiskSense.HostFinding.StatusEmbedded.State | String | The current state of embedded status associated with the host finding. | 
| RiskSense.HostFinding.StatusEmbedded.StateName | String | The state name of embedded status associated with the host finding. | 
| RiskSense.HostFinding.StatusEmbedded.StateDescription | String | The state description of embedded status associated with the host finding. | 
| RiskSense.HostFinding.StatusEmbedded.Status | boolean | The status of embedded status associated with the host finding. | 
| RiskSense.HostFinding.StatusEmbedded.DurationInDays | String | The time duration (In days) of embedded status associated with the host finding. | 
| RiskSense.HostFinding.StatusEmbedded.DueDate | String | The due date of embedded status associated with the host finding. | 
| RiskSense.HostFinding.StatusEmbedded.ExpirationDate | String | The time when status is expired associated with the host finding | 
| RiskSense.HostFinding.ManualFindingReportCount | integer | The total number of manual finding reports associated with the host finding. | 
| RiskSense.HostFinding.ManualFindingReport.Id | integer | The ID of manual finding reports associated with the host finding. | 
| RiskSense.HostFinding.ManualFindingReport.Title | String | The title of manual finding reports associated with the host finding. | 
| RiskSense.HostFinding.ManualFindingReport.Label | String | The label of manual finding reports associated with the host finding. | 
| RiskSense.HostFinding.ManualFindingReport.Pii | String | The pii number of manual finding reports associated with the host finding. | 
| RiskSense.HostFinding.ManualFindingReport.Source | String | The source of manual finding reports associated with the host finding. | 
| RiskSense.HostFinding.ManualFindingReport.IsManualExploit | boolean | To check whether manual finding report exploit or not. | 
| RiskSense.HostFinding.ManualFindingReport.EaseOfExploit | String | The total number of manual finding reports associated with the host finding. | 
| RiskSense.HostFinding.NoteCount | integer | Number of notes found. | 
| RiskSense.HostFinding.Note.Date | String | The time when note is added by the user for the host finding. | 
| RiskSense.HostFinding.Note.Note | String | The notes that are added by the user for the host finding. | 
| RiskSense.HostFinding.Note.UserId | integer | The User ID of the user who added a note for the host finding. | 
| RiskSense.HostFinding.Note.UserName | String | The Username of the user who added a note for the host finding. | 
| RiskSense.HostFinding.Assignment.Id | integer | The unique ID of the assignment associated with the host finding. | 
| RiskSense.HostFinding.Assignment.FirstName | String | The first name of the assigned user for the host finding. | 
| RiskSense.HostFinding.Assignment.LastName | String | The last name of the assigned user for the host finding. | 
| RiskSense.HostFinding.Assignment.ReceiveEmails | boolean | Indicates whether email is received or not. | 
| RiskSense.HostFinding.Assignment.Email | string | The email of the assigned user for the host finding. | 
| RiskSense.HostFinding.Assignment.Username | string | The username of the assigned user for the host finding. | 
| RiskSense.HostFinding.Services | string | The name of the services for the host finding. | 


##### Command Example
```
!risksense-get-closed-host-findings fieldname=hostName value=platform.risksense.com sort_by="Risk Rating" sort_order=DESC size="2"
```

##### Context Example
```
{
    "RiskSense.HostFinding": [
        {
            "ResolvedOn": "2019-11-07", 
            "Group": [
                {
                    "Id": 7990, 
                    "Name": "Default Group"
                }
            ], 
            "Network": {
                "Type": "IP", 
                "Id": 116086, 
                "Name": "SRS IP"
            }, 
            "StatusEmbedded": {
                "Status": false, 
                "StateDescription": "Finding was no longer found by Update Remediation by Assessment (URbA) and was automatically put into Approved by Scan", 
                "StateName": "RM Approved by Scan", 
                "State": "REVIEWED_BY_SCAN", 
                "ExpirationDate": "", 
                "DurationInDays": "46", 
                "DueDate": ""
            }, 
            "Title": "Vulnerability: CVE-2012-1180", 
            "SourceId": "SRS-CVE-2012-1180", 
            "GroupCount": 1, 
            "Note": [], 
            "Source": "SRS", 
            "SeverityDetail": {
                "CvssV3": null, 
                "CvssV2": 5, 
                "Scanner": "", 
                "Overridden": false, 
                "StateName": null, 
                "State": null, 
                "ExpirationDate": "", 
                "Aggregated": 10, 
                "Combined": 10
            }, 
            "Assessment": [
                {
                    "Date": "2019-11-06", 
                    "Id": 91199, 
                    "Name": "RC_1573018389"
                }
            ], 
            "TagCount": 5, 
            "Severity": 10, 
            "RiskRating": 10, 
            "Assignment": [], 
            "Xrs3ImpactOnCategory": 6, 
            "TagAsset": [
                {
                    "Category": "Connector", 
                    "Updated": "2020-01-07T06:58:03", 
                    "Name": "SRS:Parent Asset:risksense.com", 
                    "Created": "2020-01-07T06:58:03", 
                    "Color": "", 
                    "Id": 233429
                }
            ], 
            "Host": {
                "HostId": 3889301, 
                "Criticality": 1, 
                "HostName": "platform.risksense.com", 
                "External": true, 
                "IpAddress": "96.127.56.194", 
                "Port": [], 
                "Rs3": null
            }, 
            "MachineId": "", 
            "Services": "", 
            "ThreatCount": 0, 
            "Xrs3Impact": 1, 
            "DiscoveredOn": "2019-09-22", 
            "NoteCount": 0, 
            "Vulnerability": [
                {
                    "Trending": false, 
                    "AttackVector": "Network", 
                    "VulnLastTrendingOn": null, 
                    "BaseScore": 5, 
                    "AvailabilityImpact": "None", 
                    "Authentication": "None", 
                    "AccessComplexity": "Low", 
                    "ConfidentialityImpact": "Partial", 
                    "Cve": "CVE-2012-1180", 
                    "Integrity": "None", 
                    "ThreatCount": 0
                }
            ], 
            "Patch": [], 
            "Threat": [], 
            "Output": null, 
            "ManualFindingReport": [], 
            "TagAssetCount": [
                {
                    "category": "Connector", 
                    "updated": "2020-01-07T06:58:03", 
                    "description": "SRS:Parent Asset:risksense.com", 
                    "created": "2020-01-07T06:58:03", 
                    "color": "", 
                    "id": 233429, 
                    "name": "SRS:Parent Asset:risksense.com"
                }
            ], 
            "ManualFindingReportCount": 0, 
            "FindingType": "Auth/Unauthenticated", 
            "Id": 127065628, 
            "Tag": [
                {
                    "Category": "Connector", 
                    "Updated": "2019-11-06T05:34:06", 
                    "Name": "SRS:Category:Application Security", 
                    "Created": "2019-11-06T05:34:06", 
                    "Color": "", 
                    "Id": 230265, 
                    "Description": "SRS:Category:Application Security"
                }, 
                {
                    "Category": "Connector", 
                    "Updated": "2019-11-06T05:34:06", 
                    "Name": "SRS:Subcategory:WEB-APPLICATION-FRAMEWORK", 
                    "Created": "2019-11-06T05:34:06", 
                    "Color": "", 
                    "Id": 230269, 
                    "Description": "SRS:Subcategory:WEB-APPLICATION-FRAMEWORK"
                }, 
                {
                    "Category": "Connector", 
                    "Updated": "2019-11-06T05:34:07", 
                    "Name": "SRS:Solution Type:Patch Deployment", 
                    "Created": "2019-11-06T05:34:07", 
                    "Color": "", 
                    "Id": 230274, 
                    "Description": "SRS:Solution Type:Patch Deployment"
                }, 
                {
                    "Category": "Custom", 
                    "Updated": "2019-11-19T23:40:40", 
                    "Name": "CVSS_Sev_Crit_Test", 
                    "Created": "2019-11-19T23:40:40", 
                    "Color": "#648d9f", 
                    "Id": 230966, 
                    "Description": "CVSS Crits"
                }, 
                {
                    "Category": "Custom", 
                    "Updated": "2019-11-19T23:41:36", 
                    "Name": "RR_Crit_Test", 
                    "Created": "2019-11-19T23:41:36", 
                    "Color": "#648d9f", 
                    "Id": 230967, 
                    "Description": "Risk Rating Crit Test"
                }
            ], 
            "LastFoundOn": "2019-11-06", 
            "Port": null, 
            "ScannerName": "SRS"
        }, 
        {
            "ResolvedOn": "2019-11-07", 
            "Group": [
                {
                    "Id": 7990, 
                    "Name": "Default Group"
                }
            ], 
            "Network": {
                "Type": "IP", 
                "Id": 116086, 
                "Name": "SRS IP"
            }, 
            "StatusEmbedded": {
                "Status": false, 
                "StateDescription": "Finding was no longer found by Update Remediation by Assessment (URbA) and was automatically put into Approved by Scan", 
                "StateName": "RM Approved by Scan", 
                "State": "REVIEWED_BY_SCAN", 
                "ExpirationDate": "", 
                "DurationInDays": "46", 
                "DueDate": ""
            }, 
            "Title": "Vulnerability: CVE-2013-2070", 
            "SourceId": "SRS-CVE-2013-2070", 
            "GroupCount": 1, 
            "Note": [], 
            "Source": "SRS", 
            "SeverityDetail": {
                "CvssV3": null, 
                "CvssV2": 5.8, 
                "Scanner": "", 
                "Overridden": false, 
                "StateName": null, 
                "State": null, 
                "ExpirationDate": "", 
                "Aggregated": 10, 
                "Combined": 10
            }, 
            "Assessment": [
                {
                    "Date": "2019-11-06", 
                    "Id": 91199, 
                    "Name": "RC_1573018389"
                }
            ], 
            "TagCount": 5, 
            "Severity": 10, 
            "RiskRating": 10, 
            "Assignment": [], 
            "Xrs3ImpactOnCategory": 6, 
            "TagAsset": [
                {
                    "Category": "Connector", 
                    "Updated": "2020-01-07T06:58:03", 
                    "Name": "SRS:Parent Asset:risksense.com", 
                    "Created": "2020-01-07T06:58:03", 
                    "Color": "", 
                    "Id": 233429
                }
            ], 
            "Host": {
                "HostId": 3889301, 
                "Criticality": 1, 
                "HostName": "platform.risksense.com", 
                "External": true, 
                "IpAddress": "96.127.56.194", 
                "Port": [], 
                "Rs3": null
            }, 
            "MachineId": "", 
            "Services": "", 
            "ThreatCount": 0, 
            "Xrs3Impact": 1, 
            "DiscoveredOn": "2019-09-22", 
            "NoteCount": 0, 
            "Vulnerability": [
                {
                    "Trending": false, 
                    "AttackVector": "Network", 
                    "VulnLastTrendingOn": null, 
                    "BaseScore": 5.8, 
                    "AvailabilityImpact": "Partial", 
                    "Authentication": "None", 
                    "AccessComplexity": "Medium", 
                    "ConfidentialityImpact": "Partial", 
                    "Cve": "CVE-2013-2070", 
                    "Integrity": "None", 
                    "ThreatCount": 0
                }
            ], 
            "Patch": [], 
            "Threat": [], 
            "Output": null, 
            "ManualFindingReport": [], 
            "TagAssetCount": [
                {
                    "category": "Connector", 
                    "updated": "2020-01-07T06:58:03", 
                    "description": "SRS:Parent Asset:risksense.com", 
                    "created": "2020-01-07T06:58:03", 
                    "color": "", 
                    "id": 233429, 
                    "name": "SRS:Parent Asset:risksense.com"
                }
            ], 
            "ManualFindingReportCount": 0, 
            "FindingType": "Auth/Unauthenticated", 
            "Id": 127065637, 
            "Tag": [
                {
                    "Category": "Connector", 
                    "Updated": "2019-11-06T05:34:06", 
                    "Name": "SRS:Category:Application Security", 
                    "Created": "2019-11-06T05:34:06", 
                    "Color": "", 
                    "Id": 230265, 
                    "Description": "SRS:Category:Application Security"
                }, 
                {
                    "Category": "Connector", 
                    "Updated": "2019-11-06T05:34:06", 
                    "Name": "SRS:Subcategory:WEB-APPLICATION-FRAMEWORK", 
                    "Created": "2019-11-06T05:34:06", 
                    "Color": "", 
                    "Id": 230269, 
                    "Description": "SRS:Subcategory:WEB-APPLICATION-FRAMEWORK"
                }, 
                {
                    "Category": "Connector", 
                    "Updated": "2019-11-06T05:34:07", 
                    "Name": "SRS:Solution Type:Patch Deployment", 
                    "Created": "2019-11-06T05:34:07", 
                    "Color": "", 
                    "Id": 230274, 
                    "Description": "SRS:Solution Type:Patch Deployment"
                }, 
                {
                    "Category": "Custom", 
                    "Updated": "2019-11-19T23:40:40", 
                    "Name": "CVSS_Sev_Crit_Test", 
                    "Created": "2019-11-19T23:40:40", 
                    "Color": "#648d9f", 
                    "Id": 230966, 
                    "Description": "CVSS Crits"
                }, 
                {
                    "Category": "Custom", 
                    "Updated": "2019-11-19T23:41:36", 
                    "Name": "RR_Crit_Test", 
                    "Created": "2019-11-19T23:41:36", 
                    "Color": "#648d9f", 
                    "Id": 230967, 
                    "Description": "Risk Rating Crit Test"
                }
            ], 
            "LastFoundOn": "2019-11-06", 
            "Port": null, 
            "ScannerName": "SRS"
        }
    ]
}
```

##### Human Readable Output
### Total closed host findings: 19		 Page: 0/9		 Client: The Demo Client
### Closed host Finding(s) Details:
|Id|Hostname|IP Address|Title|Risk|Threats|Rs3|Criticality|Severity|Groups|Port|State|Assignments|Tags|Asset Tags|Note|Manual Finding Report Count|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 127065628 | platform.risksense.com | 96.127.56.194 | Vulnerability: CVE-2012-1180 | 10.0 | 0 |  | 1 | 10.0 | 1 |  | REVIEWED_BY_SCAN |  | 5 | 1 | 0 | 0 |
| 127065637 | platform.risksense.com | 96.127.56.194 | Vulnerability: CVE-2013-2070 | 10.0 | 0 |  | 1 | 10.0 | 1 |  | REVIEWED_BY_SCAN |  | 5 | 1 | 0 | 0 |


### 7. risksense-get-apps
---
Look up the application details. The application details can be searched based on input parameters like fieldname (name, network, etc.), operator (EXACT, IN, LIKE), page, size, sort by and sort order.
##### Base Command

`risksense-get-apps`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fieldname | The RiskSense apps field that should be considered for filtering the results. Users can specify any RiskSense field which use to filter. If specified, the 'value' argument is mandatory. | Optional | 
| operator | The match operator that should be applied for filtering the apps based on 'fieldname' and 'value'. Available options are 'EXACT' - filter records exactly matching the criteria; 'IN' - filter records matching any one of the comma-separated values;'LIKE' - filter records with specific pattern provided. | Optional | 
| value | The value of the apps property mentioned in 'fieldname' to be considered for filter criteria. | Optional | 
| exclusive_operator | The exclusive operator flag that determines whether the returned records matches filter criteria or not. By default set to False. | Optional | 
| page | The index of the page. The index is a numeric value and starting with 0. | Optional | 
| size | The maximum number of records to be fetched in one page. | Optional | 
| sort_by | The fieldname that should be considered for sorting the returned records. | Optional | 
| sort_order | The sorting order to be considered for retunrned records. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RiskSense.Application.Id | Number | The unique ID within the tool retrieving the application. | 
| RiskSense.Application.GroupId | Number | The group ID of the application. | 
| RiskSense.Application.GroupName | String | The group name of the application. | 
| RiskSense.Application.Groups | Unknown | The list of groups. | 
| RiskSense.Application.Network.Id | Number | The network ID of the application. | 
| RiskSense.Application.Network.Name | String | The network name of the application. | 
| RiskSense.Application.Network.Type | String | The network type of the application. | 
| RiskSense.Application.ClientId | Number | The client ID of the application. | 
| RiskSense.Application.HostId | Number | The host ID of the application. | 
| RiskSense.Application.Uri | String | The reference uri of the application. | 
| RiskSense.Application.Name | String | The name of the application. | 
| RiskSense.Application.Description | String | The detailed description of the application. | 
| RiskSense.Application.NoteCount | Number | The total number of notes found in the application. | 
| RiskSense.Application.DiscoveredOn | String | The time when application is discovered. | 
| RiskSense.Application.LastFoundOn | String | The time when the application was last found. | 
| RiskSense.Application.Total | Number | The total numbers of open findings of the application. | 
| RiskSense.Application.Critical | Number | The number of open findings of application with critical severity. | 
| RiskSense.Application.High | Number | The number of open findings of application with high severity. | 
| RiskSense.Application.Medium | Number | The number of open findings of application with medium severity. | 
| RiskSense.Application.Low | Number | The number of open findings of application with low severity. | 
| RiskSense.Application.Info | Number | The number of open findings of application with info severity. | 
| RiskSense.Application.Icon.Type | String | The type of icon of the application. | 
| RiskSense.Application.Icon.OverlayText | String | The overlay text of the icon of the application. | 
| RiskSense.Application.TagCount | Number | The total number of tags of the application. | 
| RiskSense.Application.UrlCount | Number | The total number of urls of the application. | 
| RiskSense.Application.Href | String | The deeplink pointing to the application details on RiskSense. | 
| RiskSense.Application.CMDB.ManufacturedBy | String | The name of the manufacturer in configuration management DB (CMDB) from application details. | 
| RiskSense.Application.CMDB.Model | String | The CMDB model name of the application. | 
| RiskSense.Application.CMDB.MacAddress | String | The CMDB MAC Address of the application. | 
| RiskSense.Application.CMDB.Location | String | The CMDB location of the application. | 
| RiskSense.Application.CMDB.ManagedBy | String | The CMDB entity name that managed the application. | 
| RiskSense.Application.CMDB.OwnedBy | String | The CMDB entity name that owned the application. | 
| RiskSense.Application.CMDB.SupportedBy | String | The CMDB entity name that supported the application | 
| RiskSense.Application.CMDB.SupportGroup | String | The CMDB supporting group of the application. | 
| RiskSense.Application.CMDB.SysId | String | The CMDB system ID of the application. | 
| RiskSense.Application.CMDB.OperatingSystem | String | The CMDB Operating system of the application. | 
| RiskSense.Application.CMDB.LastScanDate | String | The CMDB last scan date of the application. | 
| RiskSense.Application.CMDB.FerpaComplianceAsset | Boolean | The Family Educational Rights and Privacy Act. | 
| RiskSense.Application.CMDB.HipaaComplianceAsset | Boolean | Health Insurance Portability and Accountability Act. | 
| RiskSense.Application.CMDB.PciComplianceAsset | String | The Payment Card Industry (PCI) Council continues to make changes to ensure that their standards are up to date with emerging threats and changes in the market. | 
| RiskSense.Application.Ticket.TicketNumber | String | The number of the ticket associated with the application. | 
| RiskSense.Application.Ticket.TicketStatus | String | The status of the ticket associated with the application. | 
| RiskSense.Application.Ticket.Type | String | The type of the ticket associated with the application. | 
| RiskSense.Application.Ticket.ConnectorName | String | The connector name of the ticket associated with the application. | 
| RiskSense.Application.Ticket.DetailedStatus | String | The detailed status of ticket associated with the application. | 
| RiskSense.Application.Ticket.DeepLink | String | The deeplink associated with the ticket associated with the application. | 
| RiskSense.Application.Source.Name | String | The name of the source associated with the application. | 
| RiskSense.Application.Source.Uuid | String | The unique ID of the source associated with the application. | 
| RiskSense.Application.Source.ScannerType | String | The type of scanner of the source associated with the application.. | 
| RiskSense.Application.Note.UserId | String | The user ID of the user who added a note for the application. | 
| RiskSense.Application.Note.UserName | String | The user name of the user who added a note for the application. | 
| RiskSense.Application.Note.Note | String | The notes that are added by the user for the application. | 
| RiskSense.Application.Note.Date | String | The time when note is added by the user for the application. | 
| RiskSense.Application.Tag.Id | integer | The ID of the tag. | 
| RiskSense.Application.Tag.Name | String | The name of the tag. | 
| RiskSense.Application.Tag.Category | String | The category of the tag. | 
| RiskSense.Application.Tag.Description | String | The description of the tag. | 
| RiskSense.Application.Tag.Created | String | The time when the tag was created. | 
| RiskSense.Application.Tag.Updated | String | The time when the tag was last updated. | 
| RiskSense.Application.Tag.Color | String | The color code of the tag of the application. | 


##### Command Example
```
!risksense-get-apps fieldname=Network value=App-data sort_by="Total Findings" sort_order=DESC size="3"
```

##### Context Example
```
{
    "RiskSense.Application": [
        {
            "Network": {
                "Type": "IP", 
                "Id": 91502, 
                "Name": "App-data"
            }, 
            "ClientId": 747, 
            "Note": [
                {
                    "Date": "2020-01-28T12:21:06", 
                    "Note": "Hiiii", 
                    "UserId": 5969, 
                    "UserName": "Ravindra Sojitra"
                }
            ], 
            "Source": [
                {
                    "ScannerType": "SAST", 
                    "Name": "VERACODESAST", 
                    "Uuid": "VERACODESAST"
                }
            ], 
            "Critical": 2, 
            "Low": 21, 
            "TagCount": 0, 
            "Medium": 281, 
            "Description": null, 
            "Tag": [], 
            "Groups": [
                {
                    "Id": 7990, 
                    "Name": "Default Group"
                }
            ], 
            "Ticket": [], 
            "Icon": [
                {
                    "Type": "VERACODESAST", 
                    "OverlayText": null
                }, 
                {
                    "Type": "OWASP", 
                    "OverlayText": "A1"
                }, 
                {
                    "Type": "OWASP", 
                    "OverlayText": "A3"
                }, 
                {
                    "Type": "OWASP", 
                    "OverlayText": "A2"
                }, 
                {
                    "Type": "WASC", 
                    "OverlayText": "SQL Injection"
                }, 
                {
                    "Type": "WASC", 
                    "OverlayText": "HTTP Response Splitting"
                }, 
                {
                    "Type": "WASC", 
                    "OverlayText": "OS Commanding"
                }, 
                {
                    "Type": "WASC", 
                    "OverlayText": "URl Redirector Abuse"
                }, 
                {
                    "Type": "WASC", 
                    "OverlayText": "HTTP Request Splitting"
                }, 
                {
                    "Type": "WASC", 
                    "OverlayText": "Brute Force"
                }, 
                {
                    "Type": "WASC", 
                    "OverlayText": "Session Fixation"
                }
            ], 
            "Info": 1, 
            "DiscoveredOn": "2019-06-11", 
            "Name": "RS TestApp 1", 
            "NoteCount": 1, 
            "Uri": "RS TestApp 1", 
            "GroupName": "Default Group", 
            "CMDB": {
                "MacAddress": null, 
                "SupportGroup": null, 
                "SysId": null, 
                "HipaaComplianceAsset": false, 
                "OperatingSystem": null, 
                "ManufacturedBy": null, 
                "ManagedBy": null, 
                "Location": null, 
                "OwnedBy": null, 
                "Model": null, 
                "LastScanDate": "2019-06-11", 
                "FerpaComplianceAsset": false, 
                "SupportedBy": null, 
                "PciComplianceAsset": false
            }, 
            "UrlCount": 74, 
            "HostId": null, 
            "GroupId": 7990, 
            "High": 20, 
            "Href": "http://platform.risksense.com/api/v1/client/747/application/search?page=0&size=3&sort=findingsDistribution.total,desc", 
            "LastFoundOn": "2019-06-11", 
            "Total": 325, 
            "Id": 19391
        }, 
        {
            "Network": {
                "Type": "IP", 
                "Id": 91502, 
                "Name": "App-data"
            }, 
            "ClientId": 747, 
            "Note": [], 
            "Source": [
                {
                    "ScannerType": "DAST", 
                    "Name": "HPWEBINSPECT", 
                    "Uuid": "HPWEBINSPECT"
                }
            ], 
            "Critical": 19, 
            "Low": 157, 
            "TagCount": 0, 
            "Medium": 8, 
            "Description": null, 
            "Tag": [], 
            "Groups": [
                {
                    "Id": 7990, 
                    "Name": "Default Group"
                }
            ], 
            "Ticket": [], 
            "Icon": [
                {
                    "Type": "WEBINSPECT", 
                    "OverlayText": null
                }, 
                {
                    "Type": "OWASP", 
                    "OverlayText": "A6"
                }, 
                {
                    "Type": "OWASP", 
                    "OverlayText": "A5"
                }, 
                {
                    "Type": "OWASP", 
                    "OverlayText": "A1"
                }, 
                {
                    "Type": "OWASP", 
                    "OverlayText": "A2"
                }, 
                {
                    "Type": "OWASP", 
                    "OverlayText": "A3"
                }, 
                {
                    "Type": "OWASP", 
                    "OverlayText": "A7"
                }, 
                {
                    "Type": "WASC", 
                    "OverlayText": "Directory Indexing"
                }, 
                {
                    "Type": "WASC", 
                    "OverlayText": "Information Leakage"
                }, 
                {
                    "Type": "WASC", 
                    "OverlayText": "Path Traversal"
                }, 
                {
                    "Type": "WASC", 
                    "OverlayText": "Predictable Resource Location"
                }, 
                {
                    "Type": "WASC", 
                    "OverlayText": "Insufficient Authentication"
                }, 
                {
                    "Type": "WASC", 
                    "OverlayText": "Insufficient Authorization"
                }, 
                {
                    "Type": "WASC", 
                    "OverlayText": "LDAP Injection"
                }, 
                {
                    "Type": "WASC", 
                    "OverlayText": "Cross-site Request Forgery"
                }, 
                {
                    "Type": "WASC", 
                    "OverlayText": "Cross-site Scripting"
                }, 
                {
                    "Type": "WASC", 
                    "OverlayText": "OS Commanding"
                }, 
                {
                    "Type": "WASC", 
                    "OverlayText": "Improper Output Handling"
                }, 
                {
                    "Type": "WASC", 
                    "OverlayText": "Buffer Overflow"
                }
            ], 
            "Info": 0, 
            "DiscoveredOn": "2019-06-12", 
            "Name": "http://zero.webappsecurity.com:80", 
            "NoteCount": 0, 
            "Uri": "http://zero.webappsecurity.com:80", 
            "GroupName": "Default Group", 
            "CMDB": {
                "MacAddress": null, 
                "SupportGroup": null, 
                "SysId": null, 
                "HipaaComplianceAsset": false, 
                "OperatingSystem": null, 
                "ManufacturedBy": null, 
                "ManagedBy": null, 
                "Location": null, 
                "OwnedBy": null, 
                "Model": null, 
                "LastScanDate": null, 
                "FerpaComplianceAsset": false, 
                "SupportedBy": null, 
                "PciComplianceAsset": false
            }, 
            "UrlCount": 152, 
            "HostId": null, 
            "GroupId": 7990, 
            "High": 0, 
            "Href": "http://platform.risksense.com/api/v1/client/747/application/search?page=0&size=3&sort=findingsDistribution.total,desc", 
            "LastFoundOn": "2019-06-11", 
            "Total": 184, 
            "Id": 19396
        }, 
        {
            "Network": {
                "Type": "IP", 
                "Id": 91502, 
                "Name": "App-data"
            }, 
            "ClientId": 747, 
            "Note": [], 
            "Source": [
                {
                    "ScannerType": "DAST", 
                    "Name": "IBMAPPSCANENTERPRISE", 
                    "Uuid": "IBMAPPSCANENTERPRISE"
                }
            ], 
            "Critical": 28, 
            "Low": 13, 
            "TagCount": 0, 
            "Medium": 0, 
            "Description": null, 
            "Tag": [], 
            "Groups": [
                {
                    "Id": 7990, 
                    "Name": "Default Group"
                }
            ], 
            "Ticket": [], 
            "Icon": [
                {
                    "Type": "IBM_APP_SCANNER", 
                    "OverlayText": null
                }
            ], 
            "Info": 0, 
            "DiscoveredOn": "2019-06-12", 
            "Name": "https:/test.thatcompany.com", 
            "NoteCount": 0, 
            "Uri": "https:/test.thatcompany.com", 
            "GroupName": "Default Group", 
            "CMDB": {
                "MacAddress": null, 
                "SupportGroup": null, 
                "SysId": null, 
                "HipaaComplianceAsset": false, 
                "OperatingSystem": null, 
                "ManufacturedBy": null, 
                "ManagedBy": null, 
                "Location": null, 
                "OwnedBy": null, 
                "Model": null, 
                "LastScanDate": null, 
                "FerpaComplianceAsset": false, 
                "SupportedBy": null, 
                "PciComplianceAsset": false
            }, 
            "UrlCount": 33, 
            "HostId": null, 
            "GroupId": 7990, 
            "High": 0, 
            "Href": "http://platform.risksense.com/api/v1/client/747/application/search?page=0&size=3&sort=findingsDistribution.total,desc", 
            "LastFoundOn": "2019-06-11", 
            "Total": 41, 
            "Id": 19395
        }
    ]
}
```

##### Human Readable Output
### Total applications: 7		Page: 0/2		Client: The Demo Client
### RiskSense application(s) details:
|Id|Address|Name|Network|Total Findings|Critical Findings|High Findings|Medium Findings|Low Findings|Info Findings|Groups|URLs|Tags|Notes|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 19391 | RS TestApp 1 | RS TestApp 1 | App-data | 325 | 2 | 20 | 281 | 21 | 1 | 1 | 74 | 0 | 1 |
| 19396 | http://zero.webappsecurity.com:80 | http://zero.webappsecurity.com:80 | App-data | 184 | 19 | 0 | 8 | 157 | 0 | 1 | 152 | 0 | 0 |
| 19395 | https:/test.thatcompany.com | https:/test.thatcompany.com | App-data | 41 | 28 | 0 | 0 | 13 | 0 | 1 | 33 | 0 | 0 |


### 8. risksense-get-host-finding-detail
---
This command is used to lookup single host finding details in depth. Command accepts host finding id as an argument.
##### Base Command

`risksense-get-host-finding-detail`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostfinding_id | The unique host finding ID.HostFindingId is either known by RiskSense users or it can be found in human-readable output or context data(RiskSense.HostFinding.Id) after executing 'risksense-get-open-host-findings' or 'risksense-get-close-host-findings' command. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RiskSense.HostFinding.Id | string | The unique ID of the host finding. | 
| RiskSense.HostFinding.Source | string | Host discovered by the scanner. | 
| RiskSense.HostFinding.SourceId | string | Scanner Id of discovered scanner. | 
| RiskSense.HostFinding.Title | string | The title of the host finding. | 
| RiskSense.HostFinding.Port | integer | The port number of the host finding. | 
| RiskSense.HostFinding.GroupCount | integer | The total number of groups for host finding. | 
| RiskSense.HostFinding.Group.Id | integer | The unique ID of the group associated with the host finding. | 
| RiskSense.HostFinding.Group.Name | string | The name of the group associated with the host finding. | 
| RiskSense.HostFinding.Host.HostId | integer | The unique ID of the host associated with the host finding. | 
| RiskSense.HostFinding.Host.HostName | string | The Hostname of the host associated with the host finding. | 
| RiskSense.HostFinding.Host.IpAddress | string | The IP Address of the host associated with the host finding. | 
| RiskSense.HostFinding.Host.Criticality | integer | The criticality of the host associated with the host finding. | 
| RiskSense.HostFinding.Host.External | boolean | To identify if the host is external or internal. | 
| RiskSense.HostFinding.Host.Port.Id | integer | The unique ID of the Host(s) Port associated with the host finding. | 
| RiskSense.HostFinding.Host.Port.Number | integer | The port number of the host associated with the host finding. | 
| RiskSense.HostFinding.Host.Rs3 | integer | The Asset Security Score calculated by the RiskSense platform (includes vulnerability risk on related web applications). | 
| RiskSense.HostFinding.Network.Id | integer | The network ID of the host finding. | 
| RiskSense.HostFinding.Network.Name | string | The name of the network used by the host finding. | 
| RiskSense.HostFinding.Network.Type | string | The type of the network used by the host finding. | 
| RiskSense.HostFinding.Assessment.Id | integer | The assessment ID of the host finding. | 
| RiskSense.HostFinding.Assessment.Name | String | The name of the assessment associated with the host finding. | 
| RiskSense.HostFinding.Assessment.Date | String | The time when the assessment is created. | 
| RiskSense.HostFinding.Vulnerability.Cve | String | The name of the Common Vulnerabilities and Exposures associated with the host finding. | 
| RiskSense.HostFinding.Vulnerability.BaseScore | number | CVE Score. | 
| RiskSense.HostFinding.Vulnerability.ThreatCount | integer | The total number of threats associated with the host finding. | 
| RiskSense.HostFinding.Vulnerability.AttackVector | String | Vector information in which it has been attacked. | 
| RiskSense.HostFinding.Vulnerability.AccessComplexity | String | Complexity Level. | 
| RiskSense.HostFinding.Vulnerability.Authentication | String | Authentication value represents attackers authorization to get network access. | 
| RiskSense.HostFinding.Vulnerability.ConfidentialityImpact | String | Confidentiality impact measures the potential impact on confidentiality of a successfully exploited misuse vulnerability. | 
| RiskSense.HostFinding.Vulnerability.Integrity | String | Integrity refers to the trustworthiness and veracity of information. | 
| RiskSense.HostFinding.Vulnerability.AvailabilityImpact | String | Availability refers to accessibility of network resources. | 
| RiskSense.HostFinding.Vulnerability.Trending | boolean | This signifies whether the vulnerability (which is associated with the hostFinding) has been reported by our internal functions as being trending. | 
| RiskSense.HostFinding.Vulnerability.VulnLastTrendingOn | String | Date when last trending found. | 
| RiskSense.HostFinding.ThreatCount | integer | The total number of threats. | 
| RiskSense.HostFinding.Threat.Title | String | The title of threat. | 
| RiskSense.HostFinding.Threat.Category | String | The category of threat. | 
| RiskSense.HostFinding.Threat.Severity | String | The severity level of threat. | 
| RiskSense.HostFinding.Threat.Description | String | The threat description. | 
| RiskSense.HostFinding.Threat.Cve | Unknown | The Common Vulnerabilities and Exposures name of the threat. | 
| RiskSense.HostFinding.Threat.Source | String | The source of the threat. | 
| RiskSense.HostFinding.Threat.Published | String | The time when threat was published. | 
| RiskSense.HostFinding.Threat.Updated | String | The time when the threat was last updated. | 
| RiskSense.HostFinding.Threat.ThreatLastTrendingOn | String | The last time when threat was in trending. | 
| RiskSense.HostFinding.Threat.Trending | boolean | To check whether threat is trending or not. | 
| RiskSense.HostFinding.Patch.Name | String | The patch name of the host finding. | 
| RiskSense.HostFinding.Patch.Url | String | The patch url of the host finding. | 
| RiskSense.HostFinding.TagCount | integer | The total number of tags associated with host finding. | 
| RiskSense.HostFinding.Tag.Id | integer | The Tag identifier of the host finding. | 
| RiskSense.HostFinding.Tag.Name | String | The tag name of the host finding. | 
| RiskSense.HostFinding.Tag.Category | String | The tag category of the host finding. | 
| RiskSense.HostFinding.Tag.Description | String | The tag description of the host finding. | 
| RiskSense.HostFinding.Tag.Created | String | The time when the tag is created. | 
| RiskSense.HostFinding.Tag.Updated | String | The time when the tag is last updated. | 
| RiskSense.HostFinding.Tag.Color | String | The color of the tag. | 
| RiskSense.HostFinding.TagAssetCount | integer | The total number of tag assets. | 
| RiskSense.HostFinding.TagAsset.Id | integer | The ID of the tag asset. | 
| RiskSense.HostFinding.TagAsset.Name | String | The name of the tag asset. | 
| RiskSense.HostFinding.TagAsset.Category | String | The category of the tag asset. | 
| RiskSense.HostFinding.TagAsset.Description | String | The description of the tag asset. | 
| RiskSense.HostFinding.TagAsset.Created | String | The time Date when tag asset created. | 
| RiskSense.HostFinding.TagAsset.Updated | String | The time when tag asset was last updated. | 
| RiskSense.HostFinding.TagAsset.Color | String | The color name of the tag asset. | 
| RiskSense.HostFinding.Output | String | The output of the host finding. | 
| RiskSense.HostFinding.Severity | number | The severity of the host finding. | 
| RiskSense.HostFinding.SeverityDetail.Combined | number | The combined name of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.Overridden | boolean | The overridden name of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.Scanner | string | The scanner of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.CvssV2 | number | The cvssv2 value of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.CvssV3 | number | The cvssv3 value of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.Aggregated | number | The aggregated value of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.State | string | The state of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.StateName | string | The state name of severity detail for the host finding. | 
| RiskSense.HostFinding.SeverityDetail.ExpirationDate | string | The time when severity detail was expired. | 
| RiskSense.HostFinding.RiskRating | number | The risk rate of the host finding. | 
| RiskSense.HostFinding.Xrs3Impact | string | The impact of xrs3 for the host finding. | 
| RiskSense.HostFinding.Xrs3ImpactOnCategory | String | The category impact of xrs3 for the host finding. | 
| RiskSense.HostFinding.LastFoundOn | String | The latest time when the particular host finding is found. | 
| RiskSense.HostFinding.DiscoveredOn | String | The time when hostfinding was discovered. | 
| RiskSense.HostFinding.ResolvedOn | String | The time when the host finding was resolved. | 
| RiskSense.HostFinding.ScannerName | String | The name of the scanner of the host finding. | 
| RiskSense.HostFinding.FindingType | String | The finding type of the host finding. | 
| RiskSense.HostFinding.MachineId | String | The machine ID of the host finding. | 
| RiskSense.HostFinding.StatusEmbedded.State | String | The current state of embedded status associated with the host finding. | 
| RiskSense.HostFinding.StatusEmbedded.StateName | String | The state name of embedded status associated with the host finding. | 
| RiskSense.HostFinding.StatusEmbedded.StateDescription | String | The state description of embedded status associated with the host finding. | 
| RiskSense.HostFinding.StatusEmbedded.Status | boolean | The status of embedded status associated with the host finding. | 
| RiskSense.HostFinding.StatusEmbedded.DurationInDays | String | The time duration (In days) of embedded status associated with the host finding. | 
| RiskSense.HostFinding.StatusEmbedded.DueDate | String | The due date of embedded status associated with the host finding. | 
| RiskSense.HostFinding.StatusEmbedded.ExpirationDate | String | The time when status is expired associated with the host finding | 
| RiskSense.HostFinding.ManualFindingReportCount | integer | The total number of manual finding reports associated with the host finding. | 
| RiskSense.HostFinding.ManualFindingReport.Id | integer | The ID of manual finding reports associated with the host finding. | 
| RiskSense.HostFinding.ManualFindingReport.Title | String | The title of manual finding reports associated with the host finding. | 
| RiskSense.HostFinding.ManualFindingReport.Label | String | The label of manual finding reports associated with the host finding. | 
| RiskSense.HostFinding.ManualFindingReport.Pii | String | The pii number of manual finding reports associated with the host finding. | 
| RiskSense.HostFinding.ManualFindingReport.Source | String | The source of manual finding reports associated with the host finding. | 
| RiskSense.HostFinding.ManualFindingReport.IsManualExploit | boolean | To check whether manual finding report exploit or not. | 
| RiskSense.HostFinding.ManualFindingReport.EaseOfExploit | String | The total number of manual finding reports associated with the host finding. | 
| RiskSense.HostFinding.NoteCount | integer | Number of notes found. | 
| RiskSense.HostFinding.Note.Date | String | The time when note is added by the user for the host finding. | 
| RiskSense.HostFinding.Note.Note | String | The notes that are added by the user for the host finding. | 
| RiskSense.HostFinding.Note.UserId | integer | The User ID of the user who added a note for the host finding. | 
| RiskSense.HostFinding.Note.UserName | String | The Username of the user who added a note for the host finding. | 
| RiskSense.HostFinding.Assignment.Id | integer | The unique ID of the assignment associated with the host finding. | 
| RiskSense.HostFinding.Assignment.FirstName | String | The first name of the assigned user for the host finding. | 
| RiskSense.HostFinding.Assignment.LastName | String | The last name of the assigned user for the host finding. | 
| RiskSense.HostFinding.Assignment.ReceiveEmails | boolean | Indicates whether email is received or not. | 
| RiskSense.HostFinding.Assignment.Email | string | The email of the assigned user for the host finding. | 
| RiskSense.HostFinding.Assignment.Username | string | The username of the assigned user for the host finding. | 
| RiskSense.HostFinding.Services | string | The name of the services for the host finding. | 


##### Command Example
```
!risksense-get-host-finding-detail hostfinding_id=115469504
```

##### Context Example
```
{
        "RiskSense.HostFinding": [
            {
                "Assessment": [
                    {
                        "Date": "2019-04-23",
                        "Id": 67442,
                        "Name": "First Assessment"
                    }
                ],
                "Assignment": [],
                "DiscoveredOn": "2010-07-22",
                "FindingType": "Auth/Unauthenticated",
                "Group": [
                    {
                        "Id": 7990,
                        "Name": "Default Group"
                    }
                ],
                "GroupCount": 1,
                "Host": {
                    "Criticality": 5,
                    "External": true,
                    "HostId": 3569980,
                    "HostName": "lmd.ql.nl",
                    "IpAddress": "31.207.62.145",
                    "Port": [
                        {
                            "Id": 42841324,
                            "Number": 21
                        },
                        {
                            "Id": 42841352,
                            "Number": 22
                        },
                        {
                            "Id": 42841261,
                            "Number": 23
                        },
                        {
                            "Id": 42841311,
                            "Number": 25
                        },
                        {
                            "Id": 42841250,
                            "Number": 111
                        },
                        {
                            "Id": 42841211,
                            "Number": 123
                        },
                        {
                            "Id": 42841239,
                            "Number": 587
                        },
                        {
                            "Id": 42841345,
                            "Number": 852
                        },
                        {
                            "Id": 42841176,
                            "Number": 4045
                        },
                        {
                            "Id": 42841331,
                            "Number": 6112
                        },
                        {
                            "Id": 42841226,
                            "Number": 6481
                        },
                        {
                            "Id": 42841297,
                            "Number": 7100
                        },
                        {
                            "Id": 42841170,
                            "Number": 8400
                        },
                        {
                            "Id": 42841182,
                            "Number": 8402
                        },
                        {
                            "Id": 42841359,
                            "Number": 32771
                        },
                        {
                            "Id": 42841189,
                            "Number": 32772
                        },
                        {
                            "Id": 42841340,
                            "Number": 32775
                        },
                        {
                            "Id": 42841196,
                            "Number": 32776
                        },
                        {
                            "Id": 42841476,
                            "Number": 32777
                        },
                        {
                            "Id": 42841287,
                            "Number": 32778
                        },
                        {
                            "Id": 42841363,
                            "Number": 32780
                        },
                        {
                            "Id": 42841302,
                            "Number": 32794
                        }
                    ],
                    "Rs3": 600
                },
                "Id": 115469504,
                "LastFoundOn": "2010-07-22",
                "MachineId": "",
                "ManualFindingReport": [],
                "ManualFindingReportCount": 0,
                "Network": {
                    "Id": 78038,
                    "Name": "IP Network",
                    "Type": "IP"
                },
                "Note": [],
                "NoteCount": 0,
                "Output": "Detected service telnet and os SOLARIS 9-11",
                "Patch": [],
                "Port": null,
                "ResolvedOn": "2019-06-12",
                "RiskRating": 10,
                "ScannerName": "QUALYS",
                "Services": "",
                "Severity": 10,
                "SeverityDetail": {
                    "Aggregated": 10,
                    "Combined": 10,
                    "CvssV2": 10,
                    "CvssV3": null,
                    "ExpirationDate": "",
                    "Overridden": false,
                    "Scanner": "5",
                    "State": null,
                    "StateName": null
                },
                "Source": "QUALYS",
                "SourceId": "QUALYS38574",
                "StatusEmbedded": {
                    "DueDate": "2019-12-01T00:00:00",
                    "DurationInDays": "3246",
                    "ExpirationDate": "",
                    "State": "ACCEPTED",
                    "StateDescription": "Finding was approved in risk acceptance workflow",
                    "StateName": "RA Approved",
                    "Status": false
                },
                "Tag": [
                    {
                        "Category": "Location",
                        "Color": "#dd8361",
                        "Created": "2019-04-24T21:35:12",
                        "Description": "",
                        "Id": 215551,
                        "Name": "Data_Center_1",
                        "Updated": "2019-06-19T19:23:08"
                    },
                    {
                        "Category": "People",
                        "Color": "#78a19b",
                        "Created": "2019-04-24T21:39:59",
                        "Description": "",
                        "Id": 215554,
                        "Name": "Linux_Team_2",
                        "Updated": "2019-04-24T21:39:59"
                    },
                    {
                        "Category": "Project",
                        "Color": "#648d9f",
                        "Created": "2019-08-28T18:50:30",
                        "Description": "",
                        "Id": 225750,
                        "Name": "PCI Assets",
                        "Updated": "2019-10-31T03:40:55"
                    },
                    {
                        "Category": "Custom",
                        "Color": "#648d9f",
                        "Created": "2019-11-19T23:40:40",
                        "Description": "CVSS Crits",
                        "Id": 230966,
                        "Name": "CVSS_Sev_Crit_Test",
                        "Updated": "2019-11-19T23:40:40"
                    },
                    {
                        "Category": "Custom",
                        "Color": "#648d9f",
                        "Created": "2019-11-19T23:41:36",
                        "Description": "Risk Rating Crit Test",
                        "Id": 230967,
                        "Name": "RR_Crit_Test",
                        "Updated": "2019-11-19T23:41:36"
                    }
                ],
                "TagAsset": [
                    {
                        "Category": "Location",
                        "Color": "#dd8361",
                        "Created": "2019-04-24T21:35:12",
                        "Id": 215551,
                        "Name": "Data_Center_1",
                        "Updated": "2019-06-19T19:23:08"
                    },
                    {
                        "Category": "People",
                        "Color": "#78a19b",
                        "Created": "2019-04-24T21:39:59",
                        "Id": 215554,
                        "Name": "Linux_Team_2",
                        "Updated": "2019-04-24T21:39:59"
                    }
                ],
                "TagAssetCount": [
                    {
                        "category": "Location",
                        "color": "#dd8361",
                        "created": "2019-04-24T21:35:12",
                        "description": "",
                        "id": 215551,
                        "name": "Data_Center_1",
                        "updated": "2019-06-19T19:23:08"
                    },
                    {
                        "category": "People",
                        "color": "#78a19b",
                        "created": "2019-04-24T21:39:59",
                        "description": "",
                        "id": 215554,
                        "name": "Linux_Team_2",
                        "updated": "2019-04-24T21:39:59"
                    }
                ],
                "TagCount": 5,
                "Threat": [
                    {
                        "Category": "Exploit",
                        "Cve": "CVE-2007-0882",
                        "Description": "This module exploits the argument injection vulnerability\n        in the telnet daemon (in.telnetd) of Solaris 10 and 11.",
                        "Published": "2007-02-17T00:00:00",
                        "Severity": null,
                        "Source": "METASPLOIT",
                        "ThreatLastTrendingOn": null,
                        "Title": "Sun Solaris Telnet Remote Authentication Bypass Vulnerability",
                        "Trending": false,
                        "Updated": "2020-02-13T15:32:52"
                    },
                    {
                        "Category": "Exploit",
                        "Cve": "CVE-2007-0882",
                        "Description": "Sun Solaris Telnet - Remote Authentication Bypass (Metasploit)",
                        "Published": "2010-06-22T00:00:00",
                        "Severity": null,
                        "Source": "EXPLOIT DB",
                        "ThreatLastTrendingOn": null,
                        "Title": "Sun Solaris Telnet - Remote Authentication Bypass (Metasploit)",
                        "Trending": false,
                        "Updated": "2020-02-08T07:54:43"
                    },
                    {
                        "Category": "Exploit",
                        "Cve": "CVE-2007-0882",
                        "Description": "Solaris 10/11 Telnet - Remote Authentication Bypass (Metasploit)",
                        "Published": "2007-02-12T00:00:00",
                        "Severity": null,
                        "Source": "EXPLOIT DB",
                        "ThreatLastTrendingOn": null,
                        "Title": "Solaris 10/11 Telnet - Remote Authentication Bypass (Metasploit)",
                        "Trending": false,
                        "Updated": "2020-02-08T07:54:43"
                    },
                    {
                        "Category": "Exploit",
                        "Cve": "CVE-2007-0882",
                        "Description": "SunOS 5.10/5.11 in.TelnetD - Remote Authentication Bypass",
                        "Published": "2007-02-11T00:00:00",
                        "Severity": null,
                        "Source": "EXPLOIT DB",
                        "ThreatLastTrendingOn": null,
                        "Title": "SunOS 5.10/5.11 in.TelnetD - Remote Authentication Bypass",
                        "Trending": false,
                        "Updated": "2020-02-08T07:54:43"
                    },
                    {
                        "Category": "Worm",
                        "Cve": "CVE-2007-0882",
                        "Description": "",
                        "Published": "2007-02-28T00:00:00",
                        "Severity": null,
                        "Source": "SYMANTEC",
                        "ThreatLastTrendingOn": null,
                        "Title": "Solaris.Wanuk.Worm",
                        "Trending": false,
                        "Updated": "2019-08-16T15:50:12"
                    }
                ],
                "ThreatCount": 5,
                "Title": "Solaris 10 and Solaris 11 (SolarisExpress) Remote Access Telnet Daemon Flaw",
                "Vulnerability": [
                    {
                        "AccessComplexity": "Low",
                        "AttackVector": "Network",
                        "Authentication": "None",
                        "AvailabilityImpact": "Complete",
                        "BaseScore": 10,
                        "ConfidentialityImpact": "Complete",
                        "Cve": "CVE-2007-0882",
                        "Integrity": "Complete",
                        "ThreatCount": 5,
                        "Trending": false,
                        "VulnLastTrendingOn": null
                    }
                ],
                "Xrs3Impact": null,
                "Xrs3ImpactOnCategory": null
            }
        ]
    }
```

##### Human Readable Output

### Client: The Demo Client

### Host Finding Details:

  **Host Name**  | **Ip Address**  | **Network**  | **Source**  | **Risk Rating**  |  **Title**
  ---------------| ----------------| -------------| ------------| -----------------| -----------------------------------------------------------------------------
  lmd.ql.nl      | 31.207.62.145   | IP Network   | QUALYS      | 10.0             | Solaris 10 and Solaris 11 (SolarisExpress) Remote Access Telnet Daemon Flaw
  
                                                                                

### Threat(s) (5):

  **Title**                                                         | **Category**  | **Source**  | **CVEs**       | **Published**        | **Updated**
  ------------------------------------------------------------------| --------------| ------------| ---------------| ---------------------| ---------------------
  Sun Solaris Telnet Remote Authentication Bypass Vulnerability     | Exploit       | METASPLOIT  | CVE-2007-0882  | 2007-02-17T00:00:00  | 2020-02-13T15:32:52
  Sun Solaris Telnet - Remote Authentication Bypass (Metasploit)    | Exploit       | EXPLOIT DB  | CVE-2007-0882  | 2010-06-22T00:00:00  | 2020-02-08T07:54:43
  Solaris 10/11 Telnet - Remote Authentication Bypass (Metasploit)  | Exploit       | EXPLOIT DB  | CVE-2007-0882  | 2007-02-12T00:00:00  | 2020-02-08T07:54:43
  SunOS 5.10/5.11 in.TelnetD - Remote Authentication Bypass         | Exploit       | EXPLOIT DB  | CVE-2007-0882  | 2007-02-11T00:00:00  | 2020-02-08T07:54:43
  Solaris.Wanuk.Worm                                                | Worm          | SYMANTEC    | CVE-2007-0882  | 2007-02-28T00:00:00  | 2019-08-16T15:50:12

### Vulnerabilities (1):

  **Name**       | **V2/Score**  | **Threat Count** |  **Attack Vector** |  **Access Complexity** |  **Authentication**
  ---------------| --------------| -----------------| -------------------| -----------------------| --------------------
  CVE-2007-0882  | 10.0          | 5                |  Network           |  Low                   |  None
                                                                                                

### Status:

  **State** |  **Current State** |  **Description**                                  |  **Duration** |  **Due Date**        |  **Resolved On**
  ----------| -------------------| --------------------------------------------------| --------------| ---------------------| -----------------
  ACCEPTED  |  RA Approved       |  Finding was approved in risk acceptance workflow |  3246 day(s)  |  2019-12-01T00:00:00 |  
                                                                                                                          

### Tag(s) (5):

  **Name**              |  **Category** |  **Created**         |  **Updated**
  ----------------------| --------------| ---------------------| ---------------------
  Data\_Center\_1       |  Location     |  2019-04-24T21:35:12 |  2019-06-19T19:23:08
  Linux\_Team\_2        |  People       |  2019-04-24T21:39:59 |  2019-04-24T21:39:59
  PCI Assets            |  Project      |  2019-08-28T18:50:30 |  2019-10-31T03:40:55
  CVSS\_Sev\_Crit\_Test |  Custom       |  2019-11-19T23:40:40 |  2019-11-19T23:40:40
  RR\_Crit\_Test        |  Custom       |  2019-11-19T23:41:36 |  2019-11-19T23:41:36

### Manual Finding Report(s) (0):

**No entries.**

### Ticket(s) (0):

**No entries.**

### Assessment(s) (1):

  **Name**          | **Date**
  ------------------| ------------
  First Assessment  | 2019-04-23
                     

### Group Name:

Default Group

### Host Finding Description:

Solaris 10 and 11 hosts are vulnerable to a telnet daemon flaw.

The telnet daemon passes switches directly to the login process which
looks for a switch that allows root to login to any account without a
password. If your telnet daemon is running as root it allows
unauthenticated remote login.

Telnet poses a risk because data transferred between clients may not be
encrypted. Telnet is also a frequent target for port scanners.

### 9. risksense-get-app-detail
---
This command is used to lookup single application details in depth. Command accepts application id as an argument.
##### Base Command

`risksense-get-app-detail`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| application_id | The application ID is unique for the application. Application ID is either known by RiskSense users or it can be searched in context output (RiskSense.Application.Id) or in the human-readable output of 'risksense-get-apps' command. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RiskSense.Application.Id | Number | The unique ID within the tool retrieving the application. | 
| RiskSense.Application.GroupId | Number | The group ID of the application. | 
| RiskSense.Application.GroupName | String | The group name of the application. | 
| RiskSense.Application.Groups | Unknown | The list of groups. | 
| RiskSense.Application.Network.Id | Number | The network ID of the application. | 
| RiskSense.Application.Network.Name | String | The network name of the application. | 
| RiskSense.Application.Network.Type | String | The network type of the application. | 
| RiskSense.Application.ClientId | Number | The client ID of the application. | 
| RiskSense.Application.HostId | Number | The host ID of the application. | 
| RiskSense.Application.Uri | String | The reference uri of the application. | 
| RiskSense.Application.Name | String | The name of the application. | 
| RiskSense.Application.Description | String | The detailed description of the application. | 
| RiskSense.Application.NoteCount | Number | The total number of notes found in the application. | 
| RiskSense.Application.DiscoveredOn | String | The time when application is discovered. | 
| RiskSense.Application.LastFoundOn | String | The time when the application was last found. | 
| RiskSense.Application.Total | Number | The total numbers of open findings of the application. | 
| RiskSense.Application.Critical | Number | The number of open findings of application with critical severity. | 
| RiskSense.Application.High | Number | The number of open findings of application with high severity. | 
| RiskSense.Application.Medium | Number | The number of open findings of application with medium severity. | 
| RiskSense.Application.Low | Number | The number of open findings of application with low severity. | 
| RiskSense.Application.Info | Number | The number of open findings of application with info severity. | 
| RiskSense.Application.Icon.Type | String | The type of icon of the application. | 
| RiskSense.Application.Icon.OverlayText | String | The overlay text of the icon of the application. | 
| RiskSense.Application.TagCount | Number | The total number of tags of the application. | 
| RiskSense.Application.UrlCount | Number | The total number of urls of the application. | 
| RiskSense.Application.Href | String | The deeplink pointing to the application details on RiskSense. | 
| RiskSense.Application.CMDB.ManufacturedBy | String | The name of the manufacturer in configuration management DB (CMDB) from application details. | 
| RiskSense.Application.CMDB.Model | String | The CMDB model name of the application. | 
| RiskSense.Application.CMDB.MacAddress | String | The CMDB MAC Address of the application. | 
| RiskSense.Application.CMDB.Location | String | The CMDB location of the application. | 
| RiskSense.Application.CMDB.ManagedBy | String | The CMDB entity name that managed the application. | 
| RiskSense.Application.CMDB.OwnedBy | String | The CMDB entity name that owned the application. | 
| RiskSense.Application.CMDB.SupportedBy | String | The CMDB entity name that supported the application | 
| RiskSense.Application.CMDB.SupportGroup | String | The CMDB supporting group of the application. | 
| RiskSense.Application.CMDB.SysId | String | The CMDB system ID of the application. | 
| RiskSense.Application.CMDB.OperatingSystem | String | The CMDB Operating system of the application. | 
| RiskSense.Application.CMDB.LastScanDate | String | The CMDB last scan date of the application. | 
| RiskSense.Application.CMDB.FerpaComplianceAsset | Boolean | The Family Educational Rights and Privacy Act. | 
| RiskSense.Application.CMDB.HipaaComplianceAsset | Boolean | Health Insurance Portability and Accountability Act | 
| RiskSense.Application.CMDB.PciComplianceAsset | String | The Payment Card Industry (PCI) Council continues to make changes to ensure that their standards are up to date with emerging threats and changes in the market. | 
| RiskSense.Application.Ticket.TicketNumber | String | The number of the ticket associated with the application. | 
| RiskSense.Application.Ticket.TicketStatus | String | The status of the ticket associated with the application. | 
| RiskSense.Application.Ticket.Type | String | The type of the ticket associated with the application. | 
| RiskSense.Application.Ticket.ConnectorName | String | The connector name of the ticket associated with the application. | 
| RiskSense.Application.Ticket.DetailedStatus | String | The detailed status of ticket associated with the application. | 
| RiskSense.Application.Ticket.DeepLink | String | The deeplink associated with the ticket associated with the application. | 
| RiskSense.Application.Source.Name | String | The name of the source associated with the application. | 
| RiskSense.Application.Source.Uuid | String | The unique ID of the source associated with the application. | 
| RiskSense.Application.Source.ScannerType | String | The type of scanner of the source associated with the application.. | 
| RiskSense.Application.Note.UserId | String | The user ID of the user who added a note for the application. | 
| RiskSense.Application.Note.UserName | String | The user name of the user who added a note for the application. | 
| RiskSense.Application.Note.Note | String | The notes that are added by the user for the application. | 
| RiskSense.Application.Note.Date | String | The time when note is added by the user for the application. | 
| RiskSense.Application.Tag.Id | integer | The ID of the tag. | 
| RiskSense.Application.Tag.Name | String | The name of the tag. | 
| RiskSense.Application.Tag.Category | String | The category of the tag. | 
| RiskSense.Application.Tag.Description | String | The description of the tag. | 
| RiskSense.Application.Tag.Created | String | The time when the tag was created. | 
| RiskSense.Application.Tag.Updated | String | The time when the tag was last updated. | 
| RiskSense.Application.Tag.Color | String | The color code of the tag of the application. | 


##### Command Example
```!risksense-get-app-detail application_id=19394```

##### Context Example
```
{
    "RiskSense.Application": [
        {
            "Network": {
                "Type": "IP", 
                "Id": 91502, 
                "Name": "App-data"
            }, 
            "ClientId": 747, 
            "Note": [
                {
                    "Date": "2020-01-15T23:16:12", 
                    "Note": "Add note to app", 
                    "UserId": 2222, 
                    "UserName": "Natalia Donaldson"
                }, 
                {
                    "Date": "2020-01-15T23:26:43", 
                    "Note": "Add note to app", 
                    "UserId": 2222, 
                    "UserName": "Natalia Donaldson"
                }, 
                {
                    "Date": "2020-01-17T05:00:12", 
                    "Note": "Add note to app", 
                    "UserId": 2222, 
                    "UserName": "Natalia Donaldson"
                }
            ], 
            "Source": [
                {
                    "ScannerType": "DAST", 
                    "Name": "IBMAPPSCANENTERPRISE", 
                    "Uuid": "IBMAPPSCANENTERPRISE"
                }
            ], 
            "Critical": 0, 
            "Low": 15, 
            "TagCount": 1, 
            "Medium": 0, 
            "Description": null, 
            "Tag": [
                {
                    "Category": "Project", 
                    "Updated": "2020-01-17T23:59:22", 
                    "Name": "PCI Orch Test ", 
                    "Created": "2020-01-17T23:59:22", 
                    "Color": "#af3a29", 
                    "Id": 234039, 
                    "Description": "PCI Orch Test"
                }
            ], 
            "Groups": [
                {
                    "Id": 7990, 
                    "Name": "Default Group"
                }
            ], 
            "Ticket": [], 
            "Icon": [
                {
                    "Type": "IBM_APP_SCANNER", 
                    "OverlayText": null
                }
            ], 
            "Info": 0, 
            "DiscoveredOn": "2019-06-12", 
            "Name": "https://freebirddemo.dev.ccs.thatcompany.net", 
            "NoteCount": 3, 
            "Uri": "https://freebirddemo.dev.ccs.thatcompany.net", 
            "GroupName": "Default Group", 
            "CMDB": {
                "MacAddress": null, 
                "SupportGroup": null, 
                "SysId": null, 
                "HipaaComplianceAsset": false, 
                "OperatingSystem": null, 
                "ManufacturedBy": null, 
                "ManagedBy": null, 
                "Location": null, 
                "OwnedBy": null, 
                "Model": null, 
                "LastScanDate": null, 
                "FerpaComplianceAsset": false, 
                "SupportedBy": null, 
                "PciComplianceAsset": false
            }, 
            "UrlCount": 15, 
            "HostId": null, 
            "GroupId": 7990, 
            "High": 0, 
            "Href": "http://platform.risksense.com/api/v1/client/747/application/search?page=0&size=20&sort=id,asc", 
            "LastFoundOn": "2019-06-11", 
            "Total": 15, 
            "Id": 19394
        }
    ]
}
```

##### Human Readable Output
### Client: The Demo Client
### Application Details:
|Address|Name|Network Name|Network Type|Discovered On|Last Found On|
|---|---|---|---|---|---|
| https://freebirddemo.dev.ccs.thatcompany.net | https://freebirddemo.dev.ccs.thatcompany.net | App-data | IP | 2019-06-12 | 2019-06-11 |
|  |  |  |  |  |  |

### Findings Distribution:
|Total|Critical|High|Medium|Low|Info|
|---|---|---|---|---|---|
| 15 | 0 | 0 | 0 | 15 | 0 |
|  |  |  |  |  |  |
### Tag(s) (1):
|Name|Category|Description|Created|Updated|
|---|---|---|---|---|
| PCI Orch Test  | Project | PCI Orch Test | 2020-01-17T23:59:22 | 2020-01-17T23:59:22 |
|  |  |  |  |  |
### Ticket(s) (0):
**No entries.**

 ### Group Details: 
 Name: Default Group
 ### Sources: 
 Scanner(s): IBMAPPSCANENTERPRISE
