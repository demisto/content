Use the Claroty CTD integration to manage assets and alerts.
This integration was integrated and tested with version 4.0.1 of Claroty

## Claroty Playbook
Playbook 1: OT Asset Discovery
Maintaining an accurate enterprise asset database is extremely difficult,
but without it effective security is near impossible. This playbook automates the population and maintenance of the 
enterprise’s configuration management database (CMDB) with OT asset information.
 The rich contextual data provided for each asset makes it realistic to prioritize security processes and actions 
 based on the CMDB.
Proactive vulnerability management is a fundamental control because it hardens assets against the most common exploits
 seen in the wild. This playbook automates OT vulnerability management: it identifies high-severity vulnerabilities on
 OT assets, and creates context-rich tickets in the enterprise service manager for action. Crucially, it focuses on
 high-risk issues on truly important assets, so that non-critical issues do not overwhelm the vulnerability management
 process and obfuscate the issues that demand immediate attention.

Playbook 3: OT Threat Detection Alerts
In order to scale, enterprises must centralize and automate the processing of alerts that are indicators of risk or
 compromise. This playbook automates the passing of OT threat detection alerts from the Claroty CTD system to the
 enterprise SIEM and ticketing system. CTD correlates the alert with asset and flow information observed in the OT 
 environment and passes it upstream via the integration, allowing security analysts to quickly evaluate the alert and
 take corrective action if necessary.


## Use Cases
Retrieve and resolve alerts related to OT devices (communicating outside of the network,
 policy violations such as active outside working hours, etc.)

Insights: get information about vulnerable assets in the network (retrieve vulnerabilities and CVEs per asset,
divide according to CVE risk and mitigate accordingly (high will have different mitigation steps)

## Configure Claroty on Cortex XSOAR
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Claroty.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __CTD Server URL (e.g. https://\<IP\>:5000)__
    * __Username__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
    * __Incident type__
    * __Fetch incidents__
    * __The initial time to fetch from__
    * __Minimal severity to fetch by__
    * __Site ID to fetch by__
    * __Fetch by alert type__
    * __Exclude resolved alerts__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. claroty-get-assets
2. claroty-query-alerts
3. claroty-resolve-alert
4. claroty-get-single-alert
### 1. claroty-get-assets
---
Gets all assets from CTD. You can apply one or more filters.
##### Required Permissions
Admin user.
##### Base Command

`claroty-get-assets`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | Asset fields to return. The default value is "all". | Optional | 
| criticality | Returns assets with this criticality. Can be "Low", "Medium", or "High". | Optional | 
| insight_name | Get assets with that include the given insight name | Optional | 
| should_enrich_assets | Add aditional value for the asset CVEs. | Optional | 
| asset_limit | Maximal value of assets to query at once. | Optional | 
| assets_last_seen | Get all assets seen last from the given date. Format - YYYY-MM-DDThh:mm:ssZ. Example - 2020-02-02T01:02:03Z | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Claroty.Asset.AssetID | Number | The ID of the asset. | 
| Claroty.Asset.AssetType | String | The asset type. | 
| Claroty.Asset.CVE.CVSS | String | CVE Score. | 
| Claroty.Asset.CVE.Description | String | CVE Description. | 
| Claroty.Asset.CVE.ID | String | CVE ID. | 
| Claroty.Asset.CVE.Modified | Date | CVE modification date. | 
| Claroty.Asset.CVE.Published | Date | CVE publish date. | 
| CVE.CVSS | String | CVE Score. | 
| CVE.Description | String | CVE Description. | 
| CVE.ID | String | CVE ID. | 
| CVE.Modified | Date | CVE modification date. | 
| CVE.Published | Date | CVE publish date. | 
| Claroty.Asset.ClassType | String | The OT/IT class type. | 
| Claroty.Asset.Criticality | String | The criticality of the asset, according to the Purdue model. | 
| Claroty.Asset.FirmwareVersion | String | The FM version of the asset. | 
| Claroty.Asset.HighestCVEScore | Number | Highest CVE Score for the Asset. | 
| Claroty.Asset.IP | String | The IPv4 address of the asset. | 
| Claroty.Asset.InsightName | String | The asset insight names generated by CTD. | 
| Claroty.Asset.LastSeen | Date | The date the asset was last seen. | 
| Claroty.Asset.MAC | String | The MAC address of the asset. | 
| Claroty.Asset.Name | String | The asset name. | 
| Claroty.Asset.ResourceID | String | The asset RID (AssetID-SiteID). | 
| Claroty.Asset.RiskLevel | Number | The risk indicator. | 
| Claroty.Asset.SiteID | Number | The site ID of the asset. | 
| Claroty.Asset.SiteName | String | The site name of the asset. | 
| Claroty.Asset.Vendor | String | The vendor of the asset. | 
| Claroty.Asset.VirtualZone | String | The virtual zone of the asset. | 
| Claroty.Asset.WasParsed | String | Whether the project was parsed. | 


##### Command Example
```!claroty-get-assets asset_limit=1 criticality=High should_enrich_assets=True```

##### Context Example
```
{
    "CVE": [
        [
            {
                "ID": "RA-470154-1", 
                "Published": "2012-01-19", 
                "CVSS": "8.8", 
                "Modified": "2018-01-11", 
                "Description": "Denial of Service by receiving valid CIP message"
            }, 
            {
                "ID": "RA-470154-3", 
                "Published": "2012-01-19", 
                "CVSS": "8.8", 
                "Modified": "2018-01-11", 
                "Description": "Denial of Service (reset the product) by receiving valid CIP message"
            }, 
            {
                "ID": "RA-470155-1", 
                "Published": "2012-01-19", 
                "CVSS": "8.8", 
                "Modified": "2018-01-11", 
                "Description": "Denial of Service by receiving malformed CIP packet"
            }
        ]
    ], 
    "Claroty.Asset": [
        {
            "ResourceID": "9-1", 
            "AssetType": "PLC", 
            "Vendor": "Rockwell Automation", 
            "Name": "10.1.0.10", 
            "Criticality": "High", 
            "AssetID": 9, 
            "ClassType": "OT", 
            "SiteName": "site-1", 
            "InsightName": [
                "Full Match CVEs", 
                "Open Ports"
            ], 
            "VirtualZone": "PLC: Rockwell", 
            "RiskLevel": 1, 
            "MAC": [
                "E4:90:69:A7:70:0F"
            ], 
            "SiteID": 1, 
            "HighestCVEScore": 8.8, 
            "IP": [
                "10.1.0.10"
            ], 
            "WasParsed": null, 
            "CVE": [
                {
                    "ID": "RA-470154-1", 
                    "Published": "2012-01-19", 
                    "CVSS": "8.8", 
                    "Modified": "2018-01-11", 
                    "Description": "Denial of Service by receiving valid CIP message"
                }, 
                {
                    "ID": "RA-470154-3", 
                    "Published": "2012-01-19", 
                    "CVSS": "8.8", 
                    "Modified": "2018-01-11", 
                    "Description": "Denial of Service (reset the product) by receiving valid CIP message"
                }, 
                {
                    "ID": "RA-470155-1", 
                    "Published": "2012-01-19", 
                    "CVSS": "8.8", 
                    "Modified": "2018-01-11", 
                    "Description": "Denial of Service by receiving malformed CIP packet"
                }
            ], 
            "FirmwareVersion": "V4.003", 
            "LastSeen": "2020-02-19T07:42:16+00:00"
        }
    ]
}
```

##### Human Readable Output
### Claroty Asset List
|AssetID|AssetType|CVE|ClassType|Criticality|FirmwareVersion|HighestCVEScore|IP|InsightName|LastSeen|MAC|Name|ResourceID|RiskLevel|SiteID|SiteName|Vendor|VirtualZone|WasParsed|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 9 | PLC | {'ID': 'RA-470154-1', 'CVSS': '8.8', 'Published': '2012-01-19', 'Modified': '2018-01-11', 'Description': 'Denial of Service by receiving valid CIP message'},<br/>{'ID': 'RA-470154-3', 'CVSS': '8.8', 'Published': '2012-01-19', 'Modified': '2018-01-11', 'Description': 'Denial of Service (reset the product) by receiving valid CIP message'},<br/>{'ID': 'RA-470155-1', 'CVSS': '8.8', 'Published': '2012-01-19', 'Modified': '2018-01-11', 'Description': 'Denial of Service by receiving malformed CIP packet'} | OT | High | V4.003 | 8.8 | 10.1.0.10 | Full Match CVEs,<br/>Open Ports | 2020-02-19T07:42:16+00:00 | E4:90:69:A7:70:0F | 10.1.0.10 | 9-1 | 1 | 1 | site-1 | Rockwell Automation | PLC: Rockwell |  |


### 2. claroty-query-alerts
---
Gets alerts from CTD.
##### Required Permissions
Admin user.
##### Base Command

`claroty-query-alerts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | Alert fields to return. | Optional | 
| sort_by | The field by which to sort the results. The default value is "timestamp".<br/>Default sort order is ascending | Optional | 
| type | Returns alerts that match this alert type. | Optional | 
| date_from | The start date from which to get alerts. Format - YYYY-MM-DDThh:mm:ssZ. Example - 2020-02-02T01:02:03Z | Optional | 
| sort_order | The sorting order of the alerts - descending or ascending | Optional | 
| alert_limit | The maximum number of alerts to query. | Optional | 
| minimal_severity | Set minimal severity to query by. | Optional | 
| exclude_resolved_alerts | Returns only unresloved alerts. | Optional |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Claroty.Alert.AlertType | String | The alert type. | 
| Claroty.Alert.AlertTypeID | Number | The alert type int value | 
| Claroty.Alert.Description | String | The alert description. | 
| Claroty.Alert.Indicator | String | The alert indicators. | 
| Claroty.Alert.NetworkID | Number | The network ID. | 
| Claroty.Alert.RelatedAssets | String | Assets related to the alert. | 
| Claroty.Alert.RelatedAssets.AssetID | Number | The ID of the asset. | 
| Claroty.Alert.RelatedAssets.AssetType | String | The asset type. | 
| Claroty.Alert.RelatedAssets.ClassType | String | The OT/IT class type. | 
| Claroty.Alert.RelatedAssets.Criticality | String | The criticality of the asset, according to the Purdue model. | 
| Claroty.Alert.RelatedAssets.FirmwareVersion | String | The FM version of the asset. | 
| Claroty.Alert.RelatedAssets.IP | String | The IPv4 address of the asset. | 
| Claroty.Alert.RelatedAssets.InsightName | String | The asset insight names generated by CTD. | 
| Claroty.Alert.RelatedAssets.LastSeen | Date | The date the asset was last seen. | 
| Claroty.Alert.RelatedAssets.MAC | String | The MAC address of the asset. | 
| Claroty.Alert.RelatedAssets.Name | String | The asset name. | 
| Claroty.Alert.RelatedAssets.ResourceID | String | The asset RID (AssetID-SiteID). | 
| Claroty.Alert.RelatedAssets.RiskLevel | Number | The risk indicator. | 
| Claroty.Alert.RelatedAssets.SiteID | Number | The site ID of the asset. | 
| Claroty.Alert.RelatedAssets.SiteName | String | The site name of the asset. | 
| Claroty.Alert.RelatedAssets.Vendor | String | The vendor of the asset. | 
| Claroty.Alert.RelatedAssets.VirtualZone | String | The virtual zone of the asset. | 
| Claroty.Alert.RelatedAssets.WasParsed | String | Whether the project was parsed. | 
| Claroty.Alert.Resolved | Number | The resolve status of the alert. | 
| Claroty.Alert.ResourceID | String | The alert resource ID (AlertID-SiteID). | 
| Claroty.Alert.Severity | String | The alert severity. | 
| Claroty.Alert.Category | String | The alert category. | 


##### Command Example
```!claroty-query-alerts alert_limit=1 type=`Known Threat Alert````

##### Context Example
```
{
    "Claroty.Alert": [
        {
            "Category": "Security", 
            "NetworkID": 1, 
            "Indicator": "Alert ID - 14\r\nDescription - Event occurred out of working hours\r\nPoints - 10\r\n\nAlert ID - 14\r\nDescription - First time over the past 30 days, this Threat Signature is seen in the network\r\nPoints - 100\r\n\n", 
            "AlertType": "KnownThreatAlert", 
            "Description": "Known Threat: Threat ET TROJAN Conficker.b Shellcode was detected from 192.168.0.121 to 192.168.0.100", 
            "ResourceID": "14-1", 
            "AlertTypeID": 23, 
            "RelatedAssets": [
                {
                    "ResourceID": "15-1", 
                    "AssetType": "Endpoint", 
                    "Vendor": "Advantech Technology", 
                    "Name": "GTWB", 
                    "Criticality": null, 
                    "AssetID": 15, 
                    "IP": null, 
                    "SiteName": null, 
                    "VirtualZone": null, 
                    "RiskLevel": null, 
                    "MAC": [
                        "00:0B:AB:1A:DD:DD"
                    ], 
                    "SiteID": 1, 
                    "InsightName": null, 
                    "ClassType": null, 
                    "WasParsed": null, 
                    "FirmwareVersion": null, 
                    "LastSeen": null
                }, 
                {
                    "ResourceID": "33-1", 
                    "AssetType": "Endpoint", 
                    "Vendor": "Advantech Technology", 
                    "Name": "OISERVM", 
                    "Criticality": null, 
                    "AssetID": 33, 
                    "IP": null, 
                    "SiteName": null, 
                    "VirtualZone": null, 
                    "RiskLevel": null, 
                    "MAC": [
                        "00:0B:AB:1A:DE:BE", 
                        "00:0B:AB:1A:DE:BF"
                    ], 
                    "SiteID": 1, 
                    "InsightName": null, 
                    "ClassType": null, 
                    "WasParsed": null, 
                    "FirmwareVersion": null, 
                    "LastSeen": null
                }, 
                {
                    "ResourceID": "19-1", 
                    "AssetType": "Endpoint", 
                    "Vendor": "Advantech Technology", 
                    "Name": "GTWA", 
                    "Criticality": null, 
                    "AssetID": 19, 
                    "IP": null, 
                    "SiteName": null, 
                    "VirtualZone": null, 
                    "RiskLevel": null, 
                    "MAC": [
                        "00:0B:AB:1A:DD:F8"
                    ], 
                    "SiteID": 1, 
                    "InsightName": null, 
                    "ClassType": null, 
                    "WasParsed": null, 
                    "FirmwareVersion": null, 
                    "LastSeen": null
                }, 
                {
                    "ResourceID": "18-1", 
                    "AssetType": "Endpoint", 
                    "Vendor": "Advantech Technology", 
                    "Name": "DRWSTN", 
                    "Criticality": null, 
                    "AssetID": 18, 
                    "IP": null, 
                    "SiteName": null, 
                    "VirtualZone": null, 
                    "RiskLevel": null, 
                    "MAC": [
                        "00:0B:AB:1A:DE:BC"
                    ], 
                    "SiteID": 1, 
                    "InsightName": null, 
                    "ClassType": null, 
                    "WasParsed": null, 
                    "FirmwareVersion": null, 
                    "LastSeen": null
                }, 
                {
                    "ResourceID": "17-1", 
                    "AssetType": "Endpoint", 
                    "Vendor": "Dell", 
                    "Name": "OISERVR", 
                    "Criticality": null, 
                    "AssetID": 17, 
                    "IP": null, 
                    "SiteName": null, 
                    "VirtualZone": null, 
                    "RiskLevel": null, 
                    "MAC": [
                        "F0:4D:A2:EF:FF:11"
                    ], 
                    "SiteID": 1, 
                    "InsightName": null, 
                    "ClassType": null, 
                    "WasParsed": null, 
                    "FirmwareVersion": null, 
                    "LastSeen": null
                }
            ], 
            "Resolved": true, 
            "Severity": "Critical"
        }
    ]
}
```

##### Human Readable Output
### Claroty Alert List
|AlertType|AlertTypeID|Category|Description|Indicator|NetworkID|RelatedAssets|Resolved|ResourceID|Severity|
|---|---|---|---|---|---|---|---|---|---|
| KnownThreatAlert | 23 | Security | Known Threat: Threat ET TROJAN Conficker.b Shellcode was detected from 192.168.0.121 to 192.168.0.100 | Alert ID - 14<br/>Description - Event occurred out of working hours<br/>Points - 10<br/><br/>Alert ID - 14<br/>Description - First time over the past 30 days, this Threat Signature is seen in the network<br/>Points - 100<br/><br/> | 1 | {'AssetID': 15, 'Name': 'GTWB', 'InsightName': None, 'Vendor': 'Advantech Technology', 'Criticality': None, 'AssetType': 'Endpoint', 'LastSeen': None, 'IP': None, 'MAC': ['00:0B:AB:1A:DD:DD'], 'VirtualZone': None, 'ClassType': None, 'SiteName': None, 'SiteID': 1, 'WasParsed': None, 'RiskLevel': None, 'FirmwareVersion': None, 'ResourceID': '15-1'},<br/>{'AssetID': 33, 'Name': 'OISERVM', 'InsightName': None, 'Vendor': 'Advantech Technology', 'Criticality': None, 'AssetType': 'Endpoint', 'LastSeen': None, 'IP': None, 'MAC': ['00:0B:AB:1A:DE:BE', '00:0B:AB:1A:DE:BF'], 'VirtualZone': None, 'ClassType': None, 'SiteName': None, 'SiteID': 1, 'WasParsed': None, 'RiskLevel': None, 'FirmwareVersion': None, 'ResourceID': '33-1'},<br/>{'AssetID': 19, 'Name': 'GTWA', 'InsightName': None, 'Vendor': 'Advantech Technology', 'Criticality': None, 'AssetType': 'Endpoint', 'LastSeen': None, 'IP': None, 'MAC': ['00:0B:AB:1A:DD:F8'], 'VirtualZone': None, 'ClassType': None, 'SiteName': None, 'SiteID': 1, 'WasParsed': None, 'RiskLevel': None, 'FirmwareVersion': None, 'ResourceID': '19-1'},<br/>{'AssetID': 18, 'Name': 'DRWSTN', 'InsightName': None, 'Vendor': 'Advantech Technology', 'Criticality': None, 'AssetType': 'Endpoint', 'LastSeen': None, 'IP': None, 'MAC': ['00:0B:AB:1A:DE:BC'], 'VirtualZone': None, 'ClassType': None, 'SiteName': None, 'SiteID': 1, 'WasParsed': None, 'RiskLevel': None, 'FirmwareVersion': None, 'ResourceID': '18-1'},<br/>{'AssetID': 17, 'Name': 'OISERVR', 'InsightName': None, 'Vendor': 'Dell', 'Criticality': None, 'AssetType': 'Endpoint', 'LastSeen': None, 'IP': None, 'MAC': ['F0:4D:A2:EF:FF:11'], 'VirtualZone': None, 'ClassType': None, 'SiteName': None, 'SiteID': 1, 'WasParsed': None, 'RiskLevel': None, 'FirmwareVersion': None, 'ResourceID': '17-1'} | true | 14-1 | Critical |


### 3. claroty-resolve-alert
---
Resolves alerts.
##### Required Permissions
Admin user.
##### Base Command

`claroty-resolve-alert`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| selected_alerts | The ResourceId of the Alerts to resolve (in <alert_id>-<site_id> format) | Required | 
| resolve_as | How to resolve the alert. Can be "archive" or "resolve". The default value is "resolve". | Optional | 
| resolve_comment | A comment to add when resolving an alert. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Claroty.Resolve_out.success | String | Success output of alert resolving. | 


##### Command Example
```!claroty-resolve-alert selected_alerts="75-1" resolve_as=archive resolve_comment="Claroty is much wow!"```

##### Context Example
```
{
    "Claroty.Resolve_out": {
        "success": true
    }
}
```

##### Human Readable Output
## Alert was resolved successfully

### 4. claroty-get-single-alert
---
Get a single alert from CTD.
##### Required Permissions
Admin user.
##### Base Command

`claroty-get-single-alert`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | Asset fields to return. The default value is "all". | Optional | 
| alert_rid | Resource ID of the desired alert. Expected value - <alert_id>-<site_id> | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Claroty.Alert.AlertType | String | The alert type. | 
| Claroty.Alert.AlertTypeID | Number | The alert type int value | 
| Claroty.Alert.Description | String | The alert description. | 
| Claroty.Alert.Indicator | String | The alert indicators. | 
| Claroty.Alert.NetworkID | Number | The network ID. | 
| Claroty.Alert.RelatedAssets | String | Assets related to the alert. | 
| Claroty.Alert.Resolved | Number | The resolve status of the alert. | 
| Claroty.Alert.ResourceID | String | The alert resource ID (AlertID-SiteID). | 
| Claroty.Alert.Severity | String | The alert severity. | 


##### Command Example
```!claroty-get-single-alert alert_rid="75-1"```

##### Context Example
```
{
    "Claroty.Alert": {
        "Category": "Integrity", 
        "NetworkID": 1, 
        "Indicator": "Alert ID - 75\r\nDescription - This Event does not currently support Alert Indicators\r\nPoints - 100\r\n\n", 
        "AlertType": "PortScan", 
        "Description": "UDP Port scan: Asset 192.168.1.10 sent probe packets to 192.168.1.25 IP address on different ports", 
        "ResourceID": "75-1", 
        "AlertTypeID": 28, 
        "RelatedAssets": [
            {
                "ResourceID": "47-1", 
                "AssetType": "Endpoint", 
                "Vendor": "Hewlett Packard", 
                "Name": "192.168.1.10", 
                "Criticality": "Low", 
                "AssetID": 47, 
                "IP": null, 
                "SiteName": "site-1", 
                "VirtualZone": "Endpoint: Other", 
                "RiskLevel": 0, 
                "MAC": [
                    "00:1A:4B:6A:CE:FE"
                ], 
                "SiteID": 1, 
                "InsightName": null, 
                "ClassType": "IT", 
                "WasParsed": null, 
                "FirmwareVersion": null, 
                "LastSeen": null
            }, 
            {
                "ResourceID": "48-1", 
                "AssetType": "Endpoint", 
                "Vendor": "VMware", 
                "Name": "192.168.1.25", 
                "Criticality": "Low", 
                "AssetID": 48, 
                "IP": null, 
                "SiteName": "site-1", 
                "VirtualZone": "Endpoint: Other", 
                "RiskLevel": 0, 
                "MAC": [
                    "00:0C:29:86:C8:36"
                ], 
                "SiteID": 1, 
                "InsightName": null, 
                "ClassType": "IT", 
                "WasParsed": null, 
                "FirmwareVersion": null, 
                "LastSeen": null
            }
        ], 
        "Resolved": false, 
        "Severity": "Critical"
    }
}
```

##### Human Readable Output
### Claroty Alert List
|AlertType|AlertTypeID|Category|Description|Indicator|NetworkID|RelatedAssets|Resolved|ResourceID|Severity|
|---|---|---|---|---|---|---|---|---|---|
| PortScan | 28 | Integrity | UDP Port scan: Asset 192.168.1.10 sent probe packets to 192.168.1.25 IP address on different ports | Alert ID - 75<br/>Description - This Event does not currently support Alert Indicators<br/>Points - 100<br/><br/> | 1 | {'AssetID': 47, 'Name': '192.168.1.10', 'InsightName': None, 'Vendor': 'Hewlett Packard', 'Criticality': 'Low', 'AssetType': 'Endpoint', 'LastSeen': None, 'IP': None, 'MAC': ['00:1A:4B:6A:CE:FE'], 'VirtualZone': 'Endpoint: Other', 'ClassType': 'IT', 'SiteName': 'site-1', 'SiteID': 1, 'WasParsed': None, 'RiskLevel': 0, 'FirmwareVersion': None, 'ResourceID': '47-1'},<br/>{'AssetID': 48, 'Name': '192.168.1.25', 'InsightName': None, 'Vendor': 'VMware', 'Criticality': 'Low', 'AssetType': 'Endpoint', 'LastSeen': None, 'IP': None, 'MAC': ['00:0C:29:86:C8:36'], 'VirtualZone': 'Endpoint: Other', 'ClassType': 'IT', 'SiteName': 'site-1', 'SiteID': 1, 'WasParsed': None, 'RiskLevel': 0, 'FirmwareVersion': None, 'ResourceID': '48-1'} | false | 75-1 | Critical |
