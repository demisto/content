## Configure Infinipoint on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Infinipoint.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| access_key | Access Key | True |
| private_key | Private Key | True |
| isFetch | Fetch incidents | False |
| incident_type | Incident type - event, alert | False |
| max_fetch | Maximum number of incidents per fetch | False |
| first_fetch | First fetch time | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| incidentType | Incident type | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### infinipoint-get-vulnerable-devices
***
Get Vulnerable Devices


#### Base Command

`infinipoint-get-vulnerable-devices`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_os | The device operating system, e.g. Ubutnu, Amazon Linux AMI, CentOS, etc | Optional | 
| device_risk | Device risk score | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Vulnerability.Devices.$device | String | Infinipoint device ID | 
| Infinipoint.Vulnerability.Devices.$host | String | Hostname | 
| Infinipoint.Vulnerability.Devices.cve_id | Unknown | CVE id | 
| Infinipoint.Vulnerability.Devices.device_risk | Number | Device risk level | 
| Infinipoint.Vulnerability.Devices.device_risk_type | Number | Device risk type | 
| Infinipoint.Vulnerability.Devices.software_name | Unknown | Vulnerabilities software name | 
| Infinipoint.Vulnerability.Devices.vulnerability_count | Number | Vulnerabilities count | 


#### Command Example
```!infinipoint-get-vulnerable-devices device_risk=3```

#### Context Example
```
{
    "Infinipoint": {
        "Vulnerability": {
            "Devices": [
                {
                    "$device": "XXXX-XXXX-XXXX-XXXX-XXXX",
                    "$host": "ubuntu-test",
                    "cve_id": null,
                    "device_risk": 10,
                    "device_risk_type": 4,
                    "mac_address": "-",
                    "os_name": "Ubuntu",
                    "platform": "ubuntu",
                    "software_name": null,
                    "vulnerability_count": 245
                },
                {
                    "$device": "XXXX-XXXX-YYYY-XXXX-YYYY",
                    "$host": "DESKTOP-test",
                    "cve_id": null,
                    "device_risk": 6.34,
                    "device_risk_type": 3,
                    "mac_address": "-",
                    "os_name": "Microsoft Windows 10 Enterprise Evaluation",
                    "platform": "windows",
                    "software_name": null,
                    "vulnerability_count": 83
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|$device|$host|cve_id|device_risk|device_risk_type|mac_address|os_name|platform|software_name|vulnerability_count|
>|---|---|---|---|---|---|---|---|---|---|
>| XXXX-XXXX-XXXX-XXXX-XXXX | OSX-Machine |  | 10 | 4 | - | Mac OS X 10.15.3 | darwin |  | 103 |
>| XXXX-XXXX-XXXX-XXXX-YYYY | ubuntu |  | 10 | 4 | - | Ubuntu | ubuntu |  | 245 |
>| XXXX-XXXX-XXXX-XXXX-WWWW | DESKTOP-Machine |  | 6.34 | 3 | - | Microsoft Windows 10 Enterprise Evaluation | windows |  | 83 |


### infinipoint-get-assets-programs
***
infinipoint get assets programs


#### Base Command

`infinipoint-get-assets-programs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Software name, e.g. VMware | Optional | 
| publisher | Software publisher name, e.g. Microsoft Corporation | Optional | 
| version | Software version, e.g. 12.0.21005 | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Assets.Programs.items.$device | String | Infinipoint device ID | 
| Infinipoint.Assets.Programs.items.$host | String | Hostname | 
| Infinipoint.Assets.Programs.items.$time | Number | Timestamp | 
| Infinipoint.Assets.Programs.items.$type | String | Assets type | 
| Infinipoint.Assets.Programs.items.name | String | Programs name | 
| Infinipoint.Assets.Programs.items.os_type | String | OS type \- 1 = Windows | 2 = Linux | 4 = macOS | 
| Infinipoint.Assets.Programs.items.program_exists | String | Software exists on disk | 
| Infinipoint.Assets.Programs.items.publisher | String | Software publisher name | 
| Infinipoint.Assets.Programs.items.version | String | Software version | 
| Infinipoint.Assets.Programs.items.install_update_date | Date | Install update date | 
| Infinipoint.Assets.Programs.itemsTotal | Number | Total software | 


#### Command Example
```!infinipoint-get-assets-programs name="VMware"```

#### Context Example
```
{
    "Infinipoint": {
        "Assets": {
            "Programs": [
                {
                    "$device": "XXXX-XXXX-XXXX-XXXX-XXXX",
                    "$host": "ubuntu-VM",
                    "$time": "2020-08-04T10:30:37+00:00",
                    "$type": "csv",
                    "name": "xserver-xorg-video-vmware-hwe-18.04",
                    "os_type": "2",
                    "program_exists": "",
                    "publisher": "",
                    "version": "1:13.3.0-2build1~18.04.1"
                },
                {
                    "$device": "XXXX-XXXX-XXXX-XXXX-YYYY",
                    "$host": "DESKTOP-VM",
                    "$time": "2020-07-13T10:52:59+00:00",
                    "$type": "csv",
                    "install_update_date": "2020-05-21",
                    "name": "VMware Tools",
                    "os_type": "1",
                    "program_exists": "Found On Disk",
                    "publisher": "VMware, Inc.",
                    "version": "11.0.5.15389592"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|$device|$host|$time|$type|name|os_type|program_exists|publisher|version|
>|---|---|---|---|---|---|---|---|---|
>| XXXX-XXXX-XXXX-XXXX-XXXX | ubuntu-VM | 2020-07-20T09:13:31+00:00 | csv | xserver-xorg-video-vmware-hwe-18.04 | 2 |  |  | 1:13.3.0-2build1~18.04.1 |
>| XXXX-XXXX-XXXX-XXXX-YYYY | ubuntu-VM | 2020-08-04T10:30:37+00:00 | csv | xserver-xorg-video-vmware-hwe-18.04 | 2 |  |  | 1:13.3.0-2build1~18.04.1 |
>| XXXX-XXXX-XXXX-XXXX-ZZZZ | DESKTOP-VM | 2020-07-13T10:52:59+00:00 | csv | VMware Tools | 1 | Found On Disk | VMware, Inc. | 11.0.5.15389592 |


### infinipoint-get-cve
***
infinipoint get cve


#### Base Command

`infinipoint-get-cve`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_id | cve id, e.g. CVE-2020-1301 | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Cve.Details.campaign_intelligence.apt | String | apt | 
| Infinipoint.Cve.Details.campaign_intelligence.description | String | CVE description | 
| Infinipoint.Cve.Details.campaign_intelligence.targeted_countries | String | CVE targeted countries | 
| Infinipoint.Cve.Details.campaign_intelligence.targeted_industries | String | CVE targeted industries | 
| Infinipoint.Cve.Details.cve_description | String | CVE description | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.ac_insuf_info | String | ac insuf info | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.access_vector | String | access vector | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.attack_complexity | String | attack complexity | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.authentication | String | authentication | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.availability_impact | String | availability impact | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.base_score | String | base score | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.confidentiality_impact | String | confidentiality impact | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.exploitability_score | String | exploitability score | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.impact_score | String | impact score | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2. | String | integrity impact | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.obtain_all_privilege | String | obtain all privilege | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.obtain_other_privilege | String | obtain other privilege | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.obtain_user_privilege | String | obtain user privilege | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.severity | String | severity | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.user_interaction_required | String | user interaction required | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.vector_string | String | vector string | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.attack_complexity | String | attack complexity | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.attack_vector | String | attack vector | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.availability_impact | String | availability impact | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.base_score | String | base score | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.base_severity | String | base severity | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.confidentiality_impact | String | confidentiality impact | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.exploitability_score | String | exploitability score | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.impact_score | String | impact score | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.integrity_impact | String | integrity impact | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.privileges_required | String | privileges required | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.scope | String | scope | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.user_interaction | String | user interaction | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.vector_string | String | vector string | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.attack_complexity | String | attack complexity | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.campaigns | Number | campaigns | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.device_count | Number | device count | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.exploitability_risk | String | exploitability risk | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.exploits | Number | exploits | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.risk_label | String | risk label | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.risk_level | Number | risk level | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.risk_type | Number | risk type | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.trends_level | String | trends level | 
| Infinipoint.Cve.Details.cve_id | String | cve id | 
| Infinipoint.Cve.Details.cwe_description | String | cwe description | 
| Infinipoint.Cve.Details.cwe_id | String | cwe id | 
| Infinipoint.Cve.Details.devices.$device | String | Infinipoint device ID | 
| Infinipoint.Cve.Details.devices.device_name_string | String | Device name | 
| Infinipoint.Cve.Details.devices.device_os | String | Device OS | 
| Infinipoint.Cve.Details.devices.device_risk | Number | Device risk | 
| Infinipoint.Cve.Details.devices.map_id | String | Infinipoint map id | 
| Infinipoint.Cve.Details.devices.vulnerableProduct | String | Vulnerable product | 
| Infinipoint.Cve.Details.devices.vulnerableVersion | String | Vulnerable Version | 
| Infinipoint.Cve.Details.scan_date | Unknown | scan date | 
| Infinipoint.Cve.Details.software_list.cpe_name_string | String | cpe name string | 
| Infinipoint.Cve.Details.software_list.cpe_type | String | cpe type | 
| Infinipoint.Cve.Details.top_devices.$device | String | Infinipoint device ID | 
| Infinipoint.Cve.Details.top_devices.device_name_string | String | Device name | 
| Infinipoint.Cve.Details.top_devices.device_os | String | Device OS | 
| Infinipoint.Cve.Details.top_devices.device_risk | Number | Device risk | 
| Infinipoint.Cve.Details.top_devices.map_id | String | Infinipoint map id | 
| Infinipoint.Cve.Details.top_devices.vulnerableProduct | String | Vulnerable product | 
| Infinipoint.Cve.Details.top_devices.vulnerableVersion | String | Vulnerable version | 


#### Command Example
```!infinipoint-get-cve cve_id="CVE-2020-9859"```

#### Context Example
```
{
    "CVE": {
        "CVSS": "7.2",
        "Description": "A memory consumption issue was addressed with improved memory handling. This issue is fixed in iOS 13.5.1 and iPadOS 13.5.1, macOS Catalina 10.15.5 Supplemental Update, tvOS 13.4.6, watchOS 6.2.6. An application may be able to execute arbitrary code with kernel privileges.",
        "ID": "CVE-2020-9859"
    },
    "DBotScore": {
        "Indicator": "CVE-2020-9859",
        "Score": 0,
        "Type": "cve",
        "Vendor": null
    },
    "Infinipoint": {
        "Cve": {
            "Details": {
                "campaign_intelligence": [
                    {
                        "apt": "Publicly Available Exploit",
                        "description": "The zero-day vulnerability tracked as CVE-2020-9859 is exploited by the Unc0ver jailbreak tool ",
                        "targeted_countries": [
                            ""
                        ],
                        "targeted_industries": [
                            ""
                        ]
                    }
                ],
                "cve_description": "A memory consumption issue was addressed with improved memory handling. This issue is fixed in iOS 13.5.1 and iPadOS 13.5.1, macOS Catalina 10.15.5 Supplemental Update, tvOS 13.4.6, watchOS 6.2.6. An application may be able to execute arbitrary code with kernel privileges.",
                "cve_dynamic_data": {
                    "base_metric_v2": {
                        "ac_insuf_info": "False",
                        "access_vector": "LOCAL",
                        "attack_complexity": "LOW",
                        "authentication": "NONE",
                        "availability_impact": "COMPLETE",
                        "base_score": "7.2",
                        "confidentiality_impact": "COMPLETE",
                        "exploitability_score": "3.9",
                        "impact_score": "10.0",
                        "integrity_impact": "COMPLETE",
                        "obtain_all_privilege": "False",
                        "obtain_other_privilege": "False",
                        "obtain_user_privilege": "False",
                        "severity": "HIGH",
                        "user_interaction_required": "False",
                        "vector_string": "AV:L/AC:L/Au:N/C:C/I:C/A:C"
                    },
                    "base_metric_v3": {
                        "attack_complexity": "LOW",
                        "attack_vector": "LOCAL",
                        "availability_impact": "HIGH",
                        "base_score": "7.8",
                        "base_severity": "HIGH",
                        "confidentiality_impact": "HIGH",
                        "exploitability_score": "1.8",
                        "impact_score": "5.9",
                        "integrity_impact": "HIGH",
                        "privileges_required": "LOW",
                        "scope": "UNCHANGED",
                        "user_interaction": "NONE",
                        "vector_string": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
                    },
                    "infinipoint_base_metric": {
                        "attack_complexity": "10",
                        "campaigns": 1,
                        "device_count": 1,
                        "exploitability_risk": "3.9",
                        "exploits": 1,
                        "risk_label": "Critical",
                        "risk_level": 10,
                        "risk_type": 4,
                        "trends_level": "10"
                    }
                },
                "cve_id": "CVE-2020-9859",
                "cwe_description": "Uncontrolled Resource Consumption (Resource Exhaustion)",
                "cwe_id": "CWE-400",
                "devices": [
                    {
                        "$device": "XXXX-XXXX-XXXX-XXXX-YYYY",
                        "device_name_string": "OSX-Machine",
                        "device_os": "Mac OS X 10.15.3",
                        "device_risk": 10,
                        "is_managed": true,
                        "map_id": "XXXX-XXXX-XXXX-XXXX-YYYY",
                        "vulnerableProduct": "Mac OS X 10.15.3",
                        "vulnerableVersion": "Mac OS X 10.15.3"
                    }
                ],
                "scan_date": null,
                "software_list": [
                    {
                        "cpe_name_string": "Mac OS X 10.15.3 10.15.3",
                        "cpe_strings": [],
                        "cpe_type": "OS_ONLY"
                    }
                ],
                "top_devices": [
                    {
                        "$device": "XXXX-XXXX-XXXX-XXXX-YYYY",
                        "device_name_string": "OSX-Machine",
                        "device_os": "Mac OS X 10.15.3",
                        "device_risk": 10,
                        "is_managed": true,
                        "map_id": "XXXX-XXXX-XXXX-XXXX-YYYY",
                        "vulnerableProduct": "Mac OS X 10.15.3",
                        "vulnerableVersion": "Mac OS X 10.15.3"
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|campaign_intelligence|cve_description|cve_dynamic_data|cve_id|cwe_description|cwe_id|devices|scan_date|software_list|top_devices|
>|---|---|---|---|---|---|---|---|---|---|
>| {'apt': 'Publicly Available Exploit', 'description': 'The zero-day vulnerability tracked as CVE-2020-9859 is exploited by the Unc0ver jailbreak tool ', 'targeted_countries': [''], 'targeted_industries': ['']} | A memory consumption issue was addressed with improved memory handling. This issue is fixed in iOS 13.5.1 and iPadOS 13.5.1, macOS Catalina 10.15.5 Supplemental Update, tvOS 13.4.6, watchOS 6.2.6. An application may be able to execute arbitrary code with kernel privileges. | infinipoint_base_metric: {"device_count": 1, "risk_level": 10, "attack_complexity": "10", "campaigns": 1, "exploits": 1, "trends_level": "10", "exploitability_risk": "3.9", "risk_label": "Critical", "risk_type": 4}<br/>base_metric_v2: {"vector_string": "AV:L/AC:L/Au:N/C:C/I:C/A:C", "access_vector": "LOCAL", "attack_complexity": "LOW", "authentication": "NONE", "confidentiality_impact": "COMPLETE", "integrity_impact": "COMPLETE", "availability_impact": "COMPLETE", "base_score": "7.2", "severity": "HIGH", "exploitability_score": "3.9", "impact_score": "10.0", "ac_insuf_info": "False", "obtain_all_privilege": "False", "obtain_other_privilege": "False", "obtain_user_privilege": "False", "user_interaction_required": "False"}<br/>base_metric_v3: {"vector_string": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "attack_vector": "LOCAL", "attack_complexity": "LOW", "privileges_required": "LOW", "user_interaction": "NONE", "scope": "UNCHANGED", "confidentiality_impact": "HIGH", "integrity_impact": "HIGH", "availability_impact": "HIGH", "base_score": "7.8", "base_severity": "HIGH", "exploitability_score": "1.8", "impact_score": "5.9"} | CVE-2020-9859 | Uncontrolled Resource Consumption (Resource Exhaustion) | CWE-400 | {'$device': 'XXXX-XXXX-XXXX-XXXX-YYYY', 'device_name_string': 'OSX-Machine', 'vulnerableProduct': 'Mac OS X 10.15.3', 'vulnerableVersion': 'Mac OS X 10.15.3', 'device_risk': 10, 'map_id': 'XXXX-XXXX-XXXX-XXXX-YYYY', 'device_os': 'Mac OS X 10.15.3', 'is_managed': True} |  | {'cpe_name_string': 'Mac OS X 10.15.3 10.15.3', 'cpe_type': 'OS_ONLY', 'cpe_strings': []} | {'$device': 'XXXX-XXXX-XXXX-XXXX-YYYY', 'device_name_string': 'OSX-Machine', 'vulnerableProduct': 'Mac OS X 10.15.3', 'vulnerableVersion': 'Mac OS X 10.15.3', 'device_risk': 10, 'map_id': 'XXXX-XXXX-XXXX-XXXX-YYYY', 'device_os': 'Mac OS X 10.15.3', 'is_managed': True} |


### infinipoint-get-device
***
get device


#### Base Command

`infinipoint-get-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname, e.g. DESKTOP-CIK123 | Optional | 
| osType | choose a OS type - 1 = Windows \| 2 = Linux \| 4 = macOS | Optional | 
| osName | Device operating system full name e.g. windows-10.0.18363.836 | Optional | 
| status | Device current status:- 0 = Offline \| 1 = Online | Optional | 
| agentVersion | Infinipoint agent version, e.g. 3.200.10.0 | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Devices.agentVersion | String | Infinipoint agent version | 
| Infinipoint.Devices.clientType | Number | Client type | 
| Infinipoint.Devices.discoveryId | String | Infinipoint discovery id | 
| Infinipoint.Devices.domain | String | Domin name | 
| Infinipoint.Devices.edge | Number | Infinipoint edge | 
| Infinipoint.Devices.ftDidRespond | Number | ftDidRespond | 
| Infinipoint.Devices.ftIsSuccessful | Number | ftIsSuccessful | 
| Infinipoint.Devices.ftResult | String | ftResult | 
| Infinipoint.Devices.gatewayIp | Number | Getway IP | 
| Infinipoint.Devices.gatewayMACAddress | Date | Gateway MAC Address | 
| Infinipoint.Devices.host | String | hostname | 
| Infinipoint.Devices.id | String | Infinipoint device id | 
| Infinipoint.Devices.ip | Number | IP address | 
| Infinipoint.Devices.lastSeen | Date | Last Seen device | 
| Infinipoint.Devices.macAddress | String | MAC Address | 
| Infinipoint.Devices.networkId | Number | Infinipoint network ID | 
| Infinipoint.Devices.networks.alias | String | Networks alias | 
| Infinipoint.Devices.networks.cidr | String | cidr | 
| Infinipoint.Devices.networks.gatewayIp | Number | Gateway IP | 
| Infinipoint.Devices.networks.gatewayMACAddress | Date | Gateway MACAddress | 
| Infinipoint.Devices.osName | String | OS name | 
| Infinipoint.Devices.osType | Number | OS Type | 
| Infinipoint.Devices.policyVersion | String | Infinipoint policy version | 
| Infinipoint.Devices.productType | String | Product type | 
| Infinipoint.Devices.regDate | Date | Register date | 
| Infinipoint.Devices.status | Number | Infinipoint Device status | 
| Infinipoint.Devices.statusCode | Unknown | Infinipoint status Code | 
| Infinipoint.Devices.statusDescription | Unknown | Infinipoint status Description | 
| Infinipoint.Devices.supportId | Unknown | Infinipoint support Id | 
| Infinipoint.Devices.tags.color | String | Tag color | 
| Infinipoint.Devices.tags.name | String | Tag name | 
| Infinipoint.Devices.tags.tagId | String | Infinipoint Tag ID | 
| Infinipoint.Devices.uniqueHostname | String | Infinipoint unique Hostname | 


#### Command Example
```!infinipoint-get-device osType=1```

#### Context Example
```
{
    "Infinipoint": {
        "Devices": {
            "agentVersion": "3.200.20.0",
            "clientType": 0,
            "discoveryId": "",
            "domain": "WORKGROUP",
            "edge": true,
            "ftDidRespond": false,
            "ftIsSuccessful": false,
            "ftResult": "",
            "gatewayIp": -10000001,
            "gatewayMACAddress": "00:50:56:00:00:00",
            "host": "DESKTOP-U0QSLQ8",
            "id": "XXXX-XXXX-XXXX-XXXX-YYYY",
            "ip": -10000001,
            "lastSeen": "2020-07-13T11:06:06.632976Z",
            "macAddress": "00:0C:29:BB:74:92",
            "networkAlias": "GCP",
            "networkId": 5866697,
            "networks": [
                {
                    "alias": "GCP",
                    "cidr": "192.1.1.0/24",
                    "gatewayIp": -10000001,
                    "gatewayMACAddress": "00:50:56:00:00:00"
                }
            ],
            "osName": "windows-10.0.17763.1282",
            "osType": 1,
            "policyVersion": "1.0.0",
            "productType": "Work Station",
            "regDate": "2020-07-13T09:46:43.385267Z",
            "status": 0,
            "statusCode": null,
            "statusDescription": null,
            "supportId": null,
            "tags": [
                {
                    "color": "fefb08",
                    "name": "et",
                    "tagId": "XXXX-XXXX-XXXX-XXXX-YYYY"
                }
            ],
            "uniqueHostname": "DESKTOP-U0QSLQ8-xkp"
        }
    }
}
```

#### Human Readable Output

>### Results
>|agentVersion|clientType|discoveryId|domain|edge|ftDidRespond|ftIsSuccessful|ftResult|gatewayIp|gatewayMACAddress|host|id|ip|lastSeen|macAddress|networkAlias|networkId|networks|osName|osType|policyVersion|productType|regDate|status|statusCode|statusDescription|supportId|tags|uniqueHostname|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 3.200.20.0 | 0 |  | WORKGROUP | true | false | false |  | -1062671102 | 00:50:56:00:00:00 | DESKTOP-VM | XXXX-XXXX-XXXX-XXXX-YYYY | -10000001 | 2020-07-13T11:06:06.632976Z | 00:0C:29:BB:74:92 | GCP | 5866697 | {'alias': 'GCP', 'cidr': '192.1.1.0/24', 'gatewayIp': -100000001, 'gatewayMACAddress': '00:50:56:00:00:00'} | windows-10.0.17763.1282 | 1 | 1.0.0 | Work Station | 2020-07-13T09:46:43.385267Z | 0 |  |  |  | {'color': 'fefb08', 'name': 'et', 'tagId': 'XXXX-XXXX-XXXX-XXXX-YYYY'} | DESKTOP-VM-xkp |


### infinipoint-get-tag
***
get tag


#### Base Command

`infinipoint-get-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Tag name, e.g. it-department-tag | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Tags.color | String | Tag color | 
| Infinipoint.Tags.count | Number | Amount of devices under tag | 
| Infinipoint.Tags.description | String | Tag description | 
| Infinipoint.Tags.name | String | Tag name | 
| Infinipoint.Tags.tagId | String | Infinipoint tag id | 
| Infinipoint.Tags.type | Number | Tag type | 


#### Command Example
```!infinipoint-get-tag name=et```

#### Context Example
```
{
    "Infinipoint": {
        "Tags": {
            "color": "fefb08",
            "count": 1,
            "description": "et",
            "name": "et",
            "tagId": "XXXX-XXXX-XXXX-XXXX-YYYY",
            "type": 0
        }
    }
}
```

#### Human Readable Output

>### Results
>|color|count|description|name|tagId|type|
>|---|---|---|---|---|---|
>| fefb08 | 1 | et | et | 6d0b5156-eb2d-4b28-9c7c-3cb6e80f2cfb | 0 |


### infinipoint-get-networks
***
get networks


#### Base Command

`infinipoint-get-networks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alias, e.g. office | network alias name | Optional | 
| cidr | cidr, e.g. 10.65.0.1/16 | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Networks.Info.alias | String | Alias name | 
| Infinipoint.Networks.Info.cidr | String | Cidr | 
| Infinipoint.Networks.Info.city | Unknown | City | 
| Infinipoint.Networks.Info.country | Unknown | Country | 
| Infinipoint.Networks.Info.cronExpression | String | Cron Expression | 
| Infinipoint.Networks.Info.dnsName | String | DNS name | 
| Infinipoint.Networks.Info.externalIp | Number | External ip | 
| Infinipoint.Networks.Info.firstSeen | Date | Date first seen | 
| Infinipoint.Networks.Info.floor | Unknown | floor | 
| Infinipoint.Networks.Info.gatewayIp | Number | gateway IP | 
| Infinipoint.Networks.Info.gatewayMacAddress | String | gateway MAC Address | 
| Infinipoint.Networks.Info.ip | Number | IP address | 
| Infinipoint.Networks.Info.ipSubnetMask | Number | IP subnet mask | 
| Infinipoint.Networks.Info.lastRun | Date | Last scan Run | 
| Infinipoint.Networks.Info.lastSeen | Date | Last Seen | 
| Infinipoint.Networks.Info.latitude | Unknown | Latitude | 
| Infinipoint.Networks.Info.longitude | Unknown | Longitude | 
| Infinipoint.Networks.Info.managedCount | Number | managed devices count | 
| Infinipoint.Networks.Info.name | String | Network name | 
| Infinipoint.Networks.Info.networkId | Number | Infinipoint network ID | 
| Infinipoint.Networks.Info.nextRun | Date | Next scan | 
| Infinipoint.Networks.Info.onPrem | Number | OnPrem | 
| Infinipoint.Networks.Info.room | Unknown | room | 
| Infinipoint.Networks.Info.scheduleStatus | Number | infinipoint Schedule Status | 
| Infinipoint.Networks.Info.state | Unknown | state | 
| Infinipoint.Networks.Info.street | Unknown | street | 
| Infinipoint.Networks.Info.type | Number | Type | 
| Infinipoint.Networks.Info.unmanagedCount | Number | Unmanaged devices count | 


#### Command Example
```!infinipoint-get-networks alias=GCP```

#### Context Example
```
{
    "Infinipoint": {
        "Networks": {
            "Info": {
                "alias": "GCP",
                "cidr": "192.0.0.0/24",
                "city": null,
                "country": null,
                "cronExpression": "",
                "dnsName": "",
                "externalIp": 0,
                "firstSeen": "2020-07-13T09:46:43.376984Z",
                "floor": "",
                "gatewayIp": -10000001,
                "gatewayMacAddress": "00:50:56:00:00:00",
                "hidden": false,
                "ip": 0,
                "ipSubnetMask": 0,
                "lastRun": "1970-01-01T00:00:00Z",
                "lastSeen": "2020-08-09T14:13:47.084573Z",
                "latitude": null,
                "longitude": null,
                "managedCount": 3,
                "name": "",
                "networkId": 5866697,
                "nextRun": "1970-01-01T00:00:00Z",
                "onPrem": false,
                "room": "",
                "scheduleStatus": 3,
                "state": null,
                "street": null,
                "type": 0,
                "unmanagedCount": 0
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|alias|cidr|city|country|cronExpression|dnsName|externalIp|firstSeen|floor|gatewayIp|gatewayMacAddress|hidden|ip|ipSubnetMask|lastRun|lastSeen|latitude|longitude|managedCount|name|networkId|nextRun|onPrem|room|scheduleStatus|state|street|type|unmanagedCount|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| GCP | 192.1.1.0/24 |  |  |  |  | 0 | 2020-07-13T09:46:43.376984Z |  | -1062671102 | 00:50:56:F9:90:54 | false | 0 | 0 | 1970-01-01T00:00:00Z | 2020-08-09T14:13:47.084573Z |  |  | 3 |  | 5866697 | 1970-01-01T00:00:00Z | false |  | 3 |  |  | 0 | 0 |


### infinipoint-get-assets-devices
***
get assets hardware


#### Base Command

`infinipoint-get-assets-devices`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname, e.g. DESKTOP-CIK123 | Optional | 
| os_type | choose a OS type - 1 = Windows \| 2 = Linux \| 4 = macOS | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Assets.Hardware.$device | String | Infinipoint device ID | 
| Infinipoint.Assets.Hardware.$host | String | hostname | 
| Infinipoint.Assets.Hardware.$time | Number | Timestamp | 
| Infinipoint.Assets.Hardware.$type | String | Assets type | 
| Infinipoint.Assets.Hardware.cpu_brand | String | CPU brand | 
| Infinipoint.Assets.Hardware.cpu_logical_cores | String | CPU logical cores | 
| Infinipoint.Assets.Hardware.cpu_physical_cores | String | CPU physical cores | 
| Infinipoint.Assets.Hardware.hardware_model | String | Hardware model | 
| Infinipoint.Assets.Hardware.hardware_serial | String | Hardware serial | 
| Infinipoint.Assets.Hardware.hardware_vendor | String | Hardware vendor | 
| Infinipoint.Assets.Hardware.kernel_version | String | Kernel version | 
| Infinipoint.Assets.Hardware.os_build | String | OS build | 
| Infinipoint.Assets.Hardware.os_name | String | OS name | 
| Infinipoint.Assets.Hardware.os_patch_version | String | OS patch version | 
| Infinipoint.Assets.Hardware.os_type | String | infinipint OS type | 
| Infinipoint.Assets.Hardware.os_version | String | OS version | 
| Infinipoint.Assets.Hardware.physical_memory | String | Physical memory | 
| Infinipoint.Assets.Hardware.platform | String | Platform | 
| Infinipoint.Assets.Hardware.user | String | Last logged in user | 


#### Command Example
```!infinipoint-get-assets-devices os_type="1"```

#### Context Example
```
{
    "Infinipoint": {
        "Assets": {
            "Hardware": {
                "$device": "XXXX-XXXX-XXXX-XXXX-YYYY",
                "$host": "DESKTOP-VM",
                "$time": "2020-07-13T11:19:57+00:00",
                "$type": "csv",
                "cpu_brand": "Intel(R) Core(TM) i7-10510U CPU @ 1.80GHz",
                "cpu_logical_cores": "2",
                "cpu_physical_cores": "1",
                "hardware_model": "VMware Virtual Platform",
                "hardware_serial": "VMware-56 4d 8c d8 6d 32 31 e2-ed 43 1f 09 ff bb 74 92",
                "hardware_vendor": "VMware, Inc.",
                "kernel_version": "10.0.17763.1282",
                "os_build": "17763",
                "os_name": "Microsoft Windows 10 Enterprise Evaluation",
                "os_patch_version": "",
                "os_type": "1",
                "os_version": "10.0.17763",
                "physical_memory": "4.0",
                "platform": "windows",
                "user": "tesst2"
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|$device|$host|$time|$type|cpu_brand|cpu_logical_cores|cpu_physical_cores|hardware_model|hardware_serial|hardware_vendor|kernel_version|os_build|os_name|os_patch_version|os_type|os_version|physical_memory|platform|user|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 22ddf738-7e1c-4f20-a9c7-07620d1f2110 | DESKTOP-U0QSLQ8 | 2020-07-13T11:19:57+00:00 | csv | Intel(R) Core(TM) i7-10510U CPU @ 1.80GHz | 2 | 1 | VMware Virtual Platform | VMware-56 4d 8c d8 6d 32 31 e2-ed 43 1f 09 ff bb 74 92 | VMware, Inc. | 10.0.17763.1282 | 17763 | Microsoft Windows 10 Enterprise Evaluation |  | 1 | 10.0.17763 | 4.0 | windows | tesst2 |


### infinipoint-get-assets-cloud
***
get assets cloud


#### Base Command

`infinipoint-get-assets-cloud`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | hostname | Optional | 
| os_type | OS Type - 1 = Windows \| 2 = Linux \| 4 = macOS | Optional | 
| source | "AWS API" \| "GCP API" | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Assets.Cloud.$device | String | Infinipoint device ID | 
| Infinipoint.Assets.Cloud.$host | String | Hostname | 
| Infinipoint.Assets.Cloud.$time | Number | Timestamp | 
| Infinipoint.Assets.Cloud.$type | String | Assets type | 
| Infinipoint.Assets.Cloud.cloud_scan_timestamp | Number | cloud scan timestamp | 
| Infinipoint.Assets.Cloud.cpu_brand | String | CPU brand | 
| Infinipoint.Assets.Cloud.cpu_logical_cores | String | CPU logical cores | 
| Infinipoint.Assets.Cloud.cpu_physical_cores | String | CPU physical cores | 
| Infinipoint.Assets.Cloud.creation_time | String | Creation time | 
| Infinipoint.Assets.Cloud.hardware_model | String | Hardware model | 
| Infinipoint.Assets.Cloud.hardware_serial | String | Hardware serial | 
| Infinipoint.Assets.Cloud.hardware_vendor | String | Hardware vendor | 
| Infinipoint.Assets.Cloud.instance_id | Date | Instance id | 
| Infinipoint.Assets.Cloud.instance_state | String | Instance state | 
| Infinipoint.Assets.Cloud.instance_type | String | Instance type | 
| Infinipoint.Assets.Cloud.os_build | String | OS build | 
| Infinipoint.Assets.Cloud.os_name | String | OS name | 
| Infinipoint.Assets.Cloud.os_patch_version | String | OS patch version | 
| Infinipoint.Assets.Cloud.os_type | String | OS type | 
| Infinipoint.Assets.Cloud.physical_memory | String | Physical memory | 
| Infinipoint.Assets.Cloud.platform | String | Platform | 
| Infinipoint.Assets.Cloud.source | String | Cloud source | 
| Infinipoint.Assets.Cloud.user | String | Username | 
| Infinipoint.Assets.Cloud.zone | String | Zone | 
| Infinipoint.Assets.Cloud.open_ports | Number | List of open ports | 


#### Command Example
```!infinipoint-get-assets-cloud source="GCP API"```

#### Context Example
```
{
    "Infinipoint": {
        "Assets": {
            "Cloud": {
                "$device": "XXXX-XXXX-XXXX-XXXX-YYYY",
                "$host": "ubu-et",
                "$time": "2020-07-13T13:19:37+00:00",
                "$type": "csv",
                "cloud_scan_timestamp": 1594644075,
                "cpu_brand": "Intel(R) Xeon(R) CPU @ 2.30GHz",
                "cpu_logical_cores": "1",
                "cpu_physical_cores": "1",
                "hardware_model": "Google Compute Engine",
                "hardware_serial": "GoogleCloud-46BCBFA9C0E1789A71BA4A36CAD5E7A0",
                "hardware_vendor": "Google",
                "instance_id": "10000000001",
                "kernel_version": "5.4.0-1019-gcp",
                "os_build": "",
                "os_name": "Ubuntu",
                "os_patch_version": "",
                "os_type": "2",
                "os_version": "20.04 LTS (Focal Fossa)",
                "physical_memory": "4.0",
                "platform": "ubuntu",
                "source": "GCP API",
                "user": "et"
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|$device|$host|$time|$type|cloud_scan_timestamp|cpu_brand|cpu_logical_cores|cpu_physical_cores|hardware_model|hardware_serial|hardware_vendor|instance_id|kernel_version|os_build|os_name|os_patch_version|os_type|os_version|physical_memory|platform|source|user|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| a523014f-1612-4b65-90a8-7974b116cb44 | ubu-et | 2020-07-13T13:19:37+00:00 | csv | 1594644075 | Intel(R) Xeon(R) CPU @ 2.30GHz | 1 | 1 | Google Compute Engine | GoogleCloud-46BCBFA9C0E1789A71BA4A36CAD5E7A0 | Google | 7730283300603950466 | 5.4.0-1019-gcp |  | Ubuntu |  | 2 | 20.04 LTS (Focal Fossa) | 4.0 | ubuntu | GCP API | eturjeman_riscale_com |


### infinipoint-get-assets-users
***
get assets users


#### Base Command

`infinipoint-get-assets-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | host name | Optional | 
| username | user name | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Assets.User.$device | String | Infinipoint device ID | 
| Infinipoint.Assets.User.$host | String | hostname | 
| Infinipoint.Assets.User.$time | Number | Timestamp | 
| Infinipoint.Assets.User.$type | String | Assets type | 
| Infinipoint.Assets.User.description | String | Description | 
| Infinipoint.Assets.User.directory | String | User directory | 
| Infinipoint.Assets.User.username | String | Username | 


#### Command Example
```!infinipoint-get-assets-users username="et"```

#### Context Example
```
{
    "Infinipoint": {
        "Assets": {
            "User": [
                {
                    "$device": "XXXX-XXXX-XXXX-XXXX-YYYY",
                    "$host": "OSX-Machine",
                    "$time": "2020-08-05T07:01:49+00:00",
                    "$type": "csv",
                    "description": "ET",
                    "directory": "/Users/et",
                    "username": "et"
                },
                {
                    "$device": "XXXX-XXXX-XXXX-XXXX-ZZZZ",
                    "$host": "DESKTOP-VM",
                    "$time": "2020-07-13T10:52:41+00:00",
                    "$type": "csv",
                    "description": "",
                    "directory": "",
                    "username": "et"
                },
                {
                    "$device": "XXXX-XXXX-XXXX-XXXX-QQQQ",
                    "$host": "ubu-et",
                    "$time": "2020-07-13T12:42:17+00:00",
                    "$type": "csv",
                    "description": "",
                    "directory": "/home/et",
                    "username": "et"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|$device|$host|$time|$type|description|directory|username|
>|---|---|---|---|---|---|---|
>| XXXX-XXXX-XXXX-XXXX-YYYY | OSX-Machine | 2020-08-05T07:01:49+00:00 | csv | Setup User | /var/setup | _mbsetupuser |
>| XXXX-XXXX-XXXX-XXXX-QQQQ | DESKTOP-VM | 2020-07-13T10:52:41+00:00 | csv |  |  | et |
>| XXXX-XXXX-XXXX-XXXX-WWWW | OSX-VM | 2020-08-05T07:01:49+00:00 | csv | ET | /Users/et | et |
>| XXXX-XXXX-XXXX-XXXX-EEEE | ubu-et | 2020-07-13T12:42:17+00:00 | csv |  | /home/et | et |


### infinipoint-get-action-results
***
get action


#### Base Command

`infinipoint-get-action-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_id, e.g. 9ef2494d-862e-43c8-963c-3587cde75c4d | Action id (infinipoint) | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Responses.$data | String | Timestamp | 
| Infinipoint.Responses.$device | String | Infinipoint device ID | 
| Infinipoint.Responses.$host | String | Hostname | 
| Infinipoint.Responses.$time | Number | Expoh time | 
| Infinipoint.Responses.$type | String | Responses type | 


#### Command Example
```!infinipoint-get-action-results action_id=8761df7a-05fd-4343-8c7e-794bc6d06940```

#### Human Readable Output



### infinipoint-get-queries
***
get queries


#### Base Command

`infinipoint-get-queries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Query name, e.g Windows Logon Session | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Scripts.Search.aggregation | Number | Aggregation included | 
| Infinipoint.Scripts.Search.createdOn | Date | Date query created on | 
| Infinipoint.Scripts.Search.format | Number | Query format | 
| Infinipoint.Scripts.Search.id | String | Infinipoint query id | 
| Infinipoint.Scripts.Search.interp | Number | interp | 
| Infinipoint.Scripts.Search.module | Number | Infinipoint module | 
| Infinipoint.Scripts.Search.name | String | Query name | 
| Infinipoint.Scripts.Search.osType | Number | OS type | 


#### Command Example
```!infinipoint-get-queries name=os_version```

#### Context Example
```
{
    "Infinipoint": {
        "Scripts": {
            "Search": {
                "aggregation": true,
                "createdOn": "2020-02-02T09:28:00.500226Z",
                "description": "Retrieves information FROM the Operative Systems.",
                "format": 2,
                "id": "XXXX-XXXX-XXXX-XXXX-YYYY",
                "interp": 0,
                "module": 4,
                "name": "OS versions",
                "osType": 7
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|aggregation|createdOn|description|format|id|interp|module|name|osType|
>|---|---|---|---|---|---|---|---|---|
>| true | 2020-02-02T09:28:00.500226Z | Retrieves information FROM the Operative Systems. | 2 | XXXX-XXXX-XXXX-XXXX-YYYY | 0 | 4 | OS versions | 7 |


### infinipoint-execute-action
***
run queries


#### Base Command

`infinipoint-execute-action`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Query ID, e.g 9b071f4c-da87-409c-9cd1-59a275e52c9d | Required | 
| target | Target devices ID,e.g ["4f16532e-AAAAA-4b78-BBBB-946d3d3619ca"] | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Scripts.execute.actionId | String | Action ID | 
| Infinipoint.Scripts.execute.aggColumns | String | Aggregation columns | 
| Infinipoint.Scripts.execute.devicesCount | Number | Amount of devices | 
| Infinipoint.Scripts.execute.name | String | Query name | 


#### Command Example
```!infinipoint-execute-action id=0b5004ce-0a18-11ea-9a9f-362b9e155667```

#### Context Example
```
{
    "Infinipoint": {
        "Scripts": {
            "execute": {
                "actionId": "40151026-c5a6-4a3a-92a4-39a0bbee5902",
                "aggColumns": [
                    "Name"
                ],
                "devicesCount": 0,
                "name": "User Profile Not In Use (90 days)"
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|actionId|aggColumns|devicesCount|name|
>|---|---|---|---|
>| 40151026-c5a6-4a3a-92a4-39a0bbee5902 | Name | 0 | User Profile Not In Use (90 days) |


### infinipoint-get-events
***
get non compliance devices


#### Base Command

`infinipoint-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Infinipoint offset - First fetch time | Required | 
| limit | Limit of responses | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Compliance.Incidents.deviceID | String | Infinipoint device ID | 
| Infinipoint.Compliance.Incidents.eventTime | Number | Event Time | 
| Infinipoint.Compliance.Incidents.hostname | Date | hostname | 
| Infinipoint.Compliance.Incidents.issues.issueID | String | Infinipoint issue ID | 
| Infinipoint.Compliance.Incidents.issues.issueType | String | Issue Type | 
| Infinipoint.Compliance.Incidents.issues.policyIdx | Number | Infinipoint policyIdx | 
| Infinipoint.Compliance.Incidents.issues.ref | String | Infinipoint ref | 
| Infinipoint.Compliance.Incidents.policyID | String | policy ID | 
| Infinipoint.Compliance.Incidents.policyName | String | policy name | 
| Infinipoint.Compliance.Incidents.policyVersion | Number | policy version | 
| Infinipoint.Compliance.Incidents.timestamp | Number | timestamp | 


#### Command Example
``` !infinipoint-get-events limit=100 offset=0```

#### Human Readable Output



### infinipoint-get-device-details
***
get device details


#### Base Command

`infinipoint-get-device-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| discoveryId | discovery id, e.g 23eb50e7ceb907975686ba5cebbd3520 | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Device.Details.$device | String | Infinipoint device ID | 
| Infinipoint.Device.Details.$type | String | Info Type | 
| Infinipoint.Device.Details._key | String | Infinipoint key | 
| Infinipoint.Device.Details.archive | Number | Infinipoint archive | 
| Infinipoint.Device.Details.building | String | building | 
| Infinipoint.Device.Details.classification | String | classification | 
| Infinipoint.Device.Details.department | String | department | 
| Infinipoint.Device.Details.email | String | email | 
| Infinipoint.Device.Details.enroll_date | Date | enroll date | 
| Infinipoint.Device.Details.first_seen | Number | first\_seen | 
| Infinipoint.Device.Details.hidden | Number | hidden | 
| Infinipoint.Device.Details.host_name.name | String | hostname | 
| Infinipoint.Device.Details.host_name.value | String | Infinipoint value | 
| Infinipoint.Device.Details.jamf_tag | String | jamf tag | 
| Infinipoint.Device.Details.last_report_date | Number | last report date | 
| Infinipoint.Device.Details.last_seen | Number | last seen | 
| Infinipoint.Device.Details.mac_address.name | String | Infinipoint name | 
| Infinipoint.Device.Details.mac_address.value | String | Infinipoint value | 
| Infinipoint.Device.Details.model | String | Infinipoint model | 
| Infinipoint.Device.Details.name_tag | String | Infinipoint name\_tag | 
| Infinipoint.Device.Details.os_name.name | String | Infinipoint name | 
| Infinipoint.Device.Details.os_name.value | String | Infinipoint value | 
| Infinipoint.Device.Details.phone_number | String | phone number | 
| Infinipoint.Device.Details.position | String | position | 
| Infinipoint.Device.Details.providers | String | providers | 
| Infinipoint.Device.Details.room | String | Room | 
| Infinipoint.Device.Details.serial | String | serial | 
| Infinipoint.Device.Details.site | String | site | 
| Infinipoint.Device.Details.udid | String | udid | 
| Infinipoint.Device.Details.unique_id | String | unique id | 
| Infinipoint.Device.Details.username | String | User name | 


#### Command Example
```!infinipoint-get-device-details discoveryId=23eb50e7ceb907975686ba5cebbd3520```

#### Human Readable Output



### infinipoint-get-compliance-status
***
get compliance status


#### Base Command

`infinipoint-get-compliance-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | device id | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Compliance.Device.response.compliance | Number | compliance statius \- 0 \- errot | 1 \- compliance | 2 \- non\-compliance | 
| Infinipoint.Compliance.Device.success | Number | success | 


#### Command Example
``` !infinipoint-get-compliance-status device_id=40151026-c5a6-4a3a-92a4-39a0bbee5902```

#### Human Readable Output


