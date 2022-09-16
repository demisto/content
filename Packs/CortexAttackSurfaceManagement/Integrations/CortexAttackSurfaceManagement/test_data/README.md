Integration to pull asset and other ASM related information
This integration was integrated and tested with version xx of Cortex Attack Surface Management

## Configure Cortex Attack Surface Management on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cortex Attack Surface Management.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g., https://api-xsiam.paloaltonetworks.com) | Should be the web UI with \`api-\` appended to front. | True |
    | API Key ID | reference https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-api/cortex-xdr-api-overview/get-started-with-cortex-xdr-apis | True |
    | API Key |  | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### asm-getexternalservices
***
Get a list of all your external services filtered by business units, externally detected providers, domain, externally inferred CVEs, acve classificaons, inacve classificaons, service name, service type, protocol, IP address, is acve, and discovery type. Maximum result limit is 100 assets.


#### Base Command

`asm-getexternalservices`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | IP Address to search on. | Optional | 
| domain | Domain to search on. | Optional | 
| is_active | is the service active or not. Possible values are: yes, no. | Optional | 
| discovery_type | how service was discovered. Possible values are: colocated_on_ip, directly_discovery, unknown. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.GetExternalServices.service_id | String | External service UUID | 
| ASM.GetExternalServices.service_name | String | Name of the external service | 
| ASM.GetExternalServices.service_type | String | Type of external service | 
| ASM.GetExternalServices.ip_address | String | IP address of external service | 
| ASM.GetExternalServices.externally_detected_providers | String | Providers of external service | 
| ASM.GetExternalServices.is_active | String | Is external service active or not | 
| ASM.GetExternalServices.first_observed | Date | Date of first observation of external service | 
| ASM.GetExternalServices.last_observed | Date | Date of last observation of external service | 
| ASM.GetExternalServices.port | Number | Port number of external service | 
| ASM.GetExternalServices.protocol | String | Protocol number of external service | 
| ASM.GetExternalServices.inactive_classifications | String | External service classifications that are no longer active | 
| ASM.GetExternalServices.discovery_type | String | How external service was discovered | 
| ASM.GetExternalServices.business_units | String | External service associated business units | 
| ASM.GetExternalServices.externally_inferred_vulnerability_score | Unknown | External service vulnerability score | 

#### Command example
```!asm-getexternalservices```
#### Context Example
```json
{
    "ASM": {
        "GetExternalServices": [
            {
                "active_classifications": [
                    "DnsServer"
                ],
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Other"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1661308020000,
                "inactive_classifications": [],
                "ip_address": [
                    "104.207.249.74"
                ],
                "is_active": "Active",
                "last_observed": 1663284960000,
                "port": 53,
                "protocol": "UDP",
                "service_id": "8b8f9d0a-4acd-3d88-9042-c7d17c2b44e9",
                "service_name": "DNS Server at 104.207.249.74:53",
                "service_type": "DnsServer"
            },
            {
                "active_classifications": [
                    "DnsServer",
                    "ISCBIND9"
                ],
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Other"
                ],
                "externally_inferred_cves": [
                    "CVE-2021-25216",
                    "CVE-2020-8616",
                    "CVE-2020-8625",
                    "CVE-2015-5722",
                    "CVE-2015-5477",
                    "CVE-2017-3141",
                    "CVE-2016-9131",
                    "CVE-2016-9444",
                    "CVE-2016-8864",
                    "CVE-2016-9147",
                    "CVE-2017-3137",
                    "CVE-2018-5743",
                    "CVE-2017-3145",
                    "CVE-2021-25215",
                    "CVE-2016-2776",
                    "CVE-2018-5740",
                    "CVE-2015-5986",
                    "CVE-2016-6170",
                    "CVE-2021-25214",
                    "CVE-2018-5741",
                    "CVE-2020-8622",
                    "CVE-2016-9778",
                    "CVE-2016-2775",
                    "CVE-2017-3135",
                    "CVE-2017-3136",
                    "CVE-2017-3143",
                    "CVE-2020-8617",
                    "CVE-2017-3138",
                    "CVE-2021-25219",
                    "CVE-2019-6465",
                    "CVE-2018-5745",
                    "CVE-2017-3142"
                ],
                "externally_inferred_vulnerability_score": 9.8,
                "first_observed": 1661298300000,
                "inactive_classifications": [],
                "ip_address": [
                    "112.95.160.91"
                ],
                "is_active": "Active",
                "last_observed": 1663197480000,
                "port": 53,
                "protocol": "UDP",
                "service_id": "7a4ce6ec-9ce3-3002-ac66-862854b2d7f7",
                "service_name": "DNS Server at 112.95.160.91:53",
                "service_type": "DnsServer"
            },
            {
                "active_classifications": [
                    "DnsServer",
                    "ISCBIND9"
                ],
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Other"
                ],
                "externally_inferred_cves": [
                    "CVE-2021-25216",
                    "CVE-2020-8616",
                    "CVE-2020-8625",
                    "CVE-2015-5722",
                    "CVE-2015-5477",
                    "CVE-2017-3141",
                    "CVE-2016-9131",
                    "CVE-2016-9444",
                    "CVE-2016-8864",
                    "CVE-2016-9147",
                    "CVE-2017-3137",
                    "CVE-2018-5743",
                    "CVE-2017-3145",
                    "CVE-2021-25215",
                    "CVE-2016-2776",
                    "CVE-2018-5740",
                    "CVE-2015-5986",
                    "CVE-2016-6170",
                    "CVE-2021-25214",
                    "CVE-2018-5741",
                    "CVE-2020-8622",
                    "CVE-2016-9778",
                    "CVE-2016-2775",
                    "CVE-2017-3135",
                    "CVE-2017-3136",
                    "CVE-2017-3143",
                    "CVE-2020-8617",
                    "CVE-2017-3138",
                    "CVE-2021-25219",
                    "CVE-2019-6465",
                    "CVE-2018-5745",
                    "CVE-2017-3142"
                ],
                "externally_inferred_vulnerability_score": 9.8,
                "first_observed": 1660317960000,
                "inactive_classifications": [],
                "ip_address": [
                    "120.202.26.15"
                ],
                "is_active": "Active",
                "last_observed": 1663326660000,
                "port": 53,
                "protocol": "UDP",
                "service_id": "25c6abc2-5c1b-35e4-8952-4054689c47ce",
                "service_name": "DNS Server at 120.202.26.15:53",
                "service_type": "DnsServer"
            },
            {
                "active_classifications": [
                    "DnsServer",
                    "ISCBIND9"
                ],
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Other"
                ],
                "externally_inferred_cves": [
                    "CVE-2021-25216",
                    "CVE-2020-8616",
                    "CVE-2020-8625",
                    "CVE-2015-5722",
                    "CVE-2017-3141",
                    "CVE-2015-5477",
                    "CVE-2016-9147",
                    "CVE-2016-8864",
                    "CVE-2016-9444",
                    "CVE-2017-3137",
                    "CVE-2016-9131",
                    "CVE-2016-2776",
                    "CVE-2018-5740",
                    "CVE-2021-25215",
                    "CVE-2017-3145",
                    "CVE-2018-5743",
                    "CVE-2015-5986",
                    "CVE-2016-6170",
                    "CVE-2021-25214",
                    "CVE-2020-8622",
                    "CVE-2018-5741",
                    "CVE-2016-2775",
                    "CVE-2017-3135",
                    "CVE-2016-9778",
                    "CVE-2020-8617",
                    "CVE-2017-3136",
                    "CVE-2017-3143",
                    "CVE-2017-3138",
                    "CVE-2021-25219",
                    "CVE-2019-6465",
                    "CVE-2018-5745",
                    "CVE-2017-3142"
                ],
                "externally_inferred_vulnerability_score": 9.8,
                "first_observed": 1659492240000,
                "inactive_classifications": [],
                "ip_address": [
                    "120.236.19.126"
                ],
                "is_active": "Active",
                "last_observed": 1663267080000,
                "port": 53,
                "protocol": "UDP",
                "service_id": "cab849c5-f317-397e-91c0-59fb3372dbd3",
                "service_name": "DNS Server at 120.236.19.126:53",
                "service_type": "DnsServer"
            },
            {
                "active_classifications": [
                    "DnsServer",
                    "Dnsmasq"
                ],
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Other"
                ],
                "externally_inferred_cves": [
                    "CVE-2017-14492",
                    "CVE-2017-14491",
                    "CVE-2017-14493",
                    "CVE-2020-25682",
                    "CVE-2020-25681",
                    "CVE-2017-15107",
                    "CVE-2017-14496",
                    "CVE-2017-13704",
                    "CVE-2017-14495",
                    "CVE-2020-25687",
                    "CVE-2020-25683",
                    "CVE-2017-14494",
                    "CVE-2021-3448",
                    "CVE-2019-14834",
                    "CVE-2020-25686",
                    "CVE-2020-25684",
                    "CVE-2020-25685"
                ],
                "externally_inferred_vulnerability_score": 9.8,
                "first_observed": 1661256660000,
                "inactive_classifications": [],
                "ip_address": [
                    "192.190.221.160"
                ],
                "is_active": "Active",
                "last_observed": 1663263360000,
                "port": 53,
                "protocol": "UDP",
                "service_id": "96ce454d-f617-3418-9e79-c28e92ec573a",
                "service_name": "DNS Server at 192.190.221.160:53",
                "service_type": "DnsServer"
            },
            {
                "active_classifications": [
                    "DnsServer"
                ],
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [],
                "externally_detected_providers": [
                    "On Prem"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659465360000,
                "inactive_classifications": [],
                "ip_address": [
                    "192.225.57.3"
                ],
                "is_active": "Active",
                "last_observed": 1663320480000,
                "port": 53,
                "protocol": "UDP",
                "service_id": "47ac5a8d-b745-3fcd-bae0-7c00e4dbee4d",
                "service_name": "DNS Server at 192.225.57.3:53",
                "service_type": "DnsServer"
            },
            {
                "active_classifications": [
                    "DnsServer"
                ],
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [],
                "externally_detected_providers": [
                    "On Prem"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659548100000,
                "inactive_classifications": [],
                "ip_address": [
                    "192.225.57.4"
                ],
                "is_active": "Active",
                "last_observed": 1663296660000,
                "port": 53,
                "protocol": "UDP",
                "service_id": "8a55b6d7-04f3-373a-9d21-37ede8d3cf7a",
                "service_name": "DNS Server at 192.225.57.4:53",
                "service_type": "DnsServer"
            },
            {
                "active_classifications": [
                    "DnsServer"
                ],
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [],
                "externally_detected_providers": [
                    "On Prem"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659517200000,
                "inactive_classifications": [],
                "ip_address": [
                    "194.186.243.106"
                ],
                "is_active": "Active",
                "last_observed": 1663126260000,
                "port": 53,
                "protocol": "UDP",
                "service_id": "266ef110-23d8-319f-ab58-ceb4f48c1930",
                "service_name": "DNS Server at 194.186.243.106:53",
                "service_type": "DnsServer"
            },
            {
                "active_classifications": [
                    "DnsServer"
                ],
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [],
                "externally_detected_providers": [
                    "On Prem"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659415680000,
                "inactive_classifications": [],
                "ip_address": [
                    "195.239.144.186"
                ],
                "is_active": "Active",
                "last_observed": 1663276980000,
                "port": 53,
                "protocol": "UDP",
                "service_id": "aa00c51f-6a97-3600-aa43-69e1581e47f3",
                "service_name": "DNS Server at 195.239.144.186:53",
                "service_type": "DnsServer"
            },
            {
                "active_classifications": [
                    "DnsServer",
                    "ISCBIND9"
                ],
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Other"
                ],
                "externally_inferred_cves": [
                    "CVE-2021-25216",
                    "CVE-2020-8616",
                    "CVE-2020-8625",
                    "CVE-2017-3141",
                    "CVE-2015-5477",
                    "CVE-2015-5722",
                    "CVE-2016-9444",
                    "CVE-2017-3137",
                    "CVE-2016-8864",
                    "CVE-2016-9147",
                    "CVE-2016-9131",
                    "CVE-2021-25215",
                    "CVE-2017-3145",
                    "CVE-2018-5740",
                    "CVE-2016-2776",
                    "CVE-2018-5743",
                    "CVE-2015-5986",
                    "CVE-2016-6170",
                    "CVE-2021-25214",
                    "CVE-2020-8622",
                    "CVE-2018-5741",
                    "CVE-2017-3135",
                    "CVE-2016-9778",
                    "CVE-2016-2775",
                    "CVE-2020-8617",
                    "CVE-2017-3136",
                    "CVE-2017-3143",
                    "CVE-2017-3138",
                    "CVE-2019-6465",
                    "CVE-2021-25219",
                    "CVE-2018-5745",
                    "CVE-2017-3142"
                ],
                "externally_inferred_vulnerability_score": 9.8,
                "first_observed": 1659494040000,
                "inactive_classifications": [],
                "ip_address": [
                    "202.96.162.203"
                ],
                "is_active": "Active",
                "last_observed": 1663279860000,
                "port": 53,
                "protocol": "UDP",
                "service_id": "3011f810-8aec-3c49-a571-34d6d904ee03",
                "service_name": "DNS Server at 202.96.162.203:53",
                "service_type": "DnsServer"
            },
            {
                "active_classifications": [
                    "DnsServer"
                ],
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Other"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660272780000,
                "inactive_classifications": [],
                "ip_address": [
                    "208.80.127.4"
                ],
                "is_active": "Active",
                "last_observed": 1663296480000,
                "port": 53,
                "protocol": "UDP",
                "service_id": "fe3c5a69-bc0e-382c-9993-0b4e5ef0e1de",
                "service_name": "DNS Server at 208.80.127.4:53",
                "service_type": "DnsServer"
            },
            {
                "active_classifications": [
                    "DnsServer"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Other"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659505440000,
                "inactive_classifications": [],
                "ip_address": [
                    "210.166.216.147"
                ],
                "is_active": "Active",
                "last_observed": 1663293060000,
                "port": 53,
                "protocol": "UDP",
                "service_id": "40968292-0130-3fc9-b3e5-d8e431715252",
                "service_name": "DNS Server at 210.166.216.147:53",
                "service_type": "DnsServer"
            },
            {
                "active_classifications": [
                    "DnsServer",
                    "ISCBIND9"
                ],
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Other"
                ],
                "externally_inferred_cves": [
                    "CVE-2021-25216",
                    "CVE-2020-8616",
                    "CVE-2020-8625",
                    "CVE-2015-5722",
                    "CVE-2015-5477",
                    "CVE-2017-3141",
                    "CVE-2016-9131",
                    "CVE-2016-9444",
                    "CVE-2016-8864",
                    "CVE-2016-9147",
                    "CVE-2017-3137",
                    "CVE-2018-5743",
                    "CVE-2017-3145",
                    "CVE-2021-25215",
                    "CVE-2016-2776",
                    "CVE-2018-5740",
                    "CVE-2015-5986",
                    "CVE-2016-6170",
                    "CVE-2021-25214",
                    "CVE-2018-5741",
                    "CVE-2020-8622",
                    "CVE-2016-9778",
                    "CVE-2016-2775",
                    "CVE-2017-3135",
                    "CVE-2017-3136",
                    "CVE-2017-3143",
                    "CVE-2020-8617",
                    "CVE-2017-3138",
                    "CVE-2021-25219",
                    "CVE-2019-6465",
                    "CVE-2018-5745",
                    "CVE-2017-3142"
                ],
                "externally_inferred_vulnerability_score": 9.8,
                "first_observed": 1659537660000,
                "inactive_classifications": [],
                "ip_address": [
                    "61.183.84.239"
                ],
                "is_active": "Active",
                "last_observed": 1662793200000,
                "port": 53,
                "protocol": "UDP",
                "service_id": "2d510619-e24e-3a7b-b3a2-03cb425042c4",
                "service_name": "DNS Server at 61.183.84.239:53",
                "service_type": "DnsServer"
            },
            {
                "active_classifications": [
                    "UnencryptedFtpServer",
                    "FtpServer"
                ],
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [],
                "externally_detected_providers": [
                    "On Prem"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660147500000,
                "inactive_classifications": [],
                "ip_address": [
                    "12.5.116.147"
                ],
                "is_active": "Active",
                "last_observed": 1663305060000,
                "port": 21,
                "protocol": "TCP",
                "service_id": "05dd80fc-e04c-368b-b383-d2411b5c44f5",
                "service_name": "FTP Server at 12.5.116.147:21",
                "service_type": "FtpServer"
            },
            {
                "active_classifications": [
                    "UnencryptedFtpServer",
                    "FtpServer"
                ],
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [],
                "externally_detected_providers": [
                    "On Prem"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659452640000,
                "inactive_classifications": [],
                "ip_address": [
                    "166.76.254.147"
                ],
                "is_active": "Active",
                "last_observed": 1663254840000,
                "port": 21,
                "protocol": "TCP",
                "service_id": "533fc779-2d65-3f21-9489-1e179dbfe223",
                "service_name": "FTP Server at 166.76.254.147:21",
                "service_type": "FtpServer"
            },
            {
                "active_classifications": [
                    "WildcardCertificate",
                    "FtpsServer",
                    "FtpServer"
                ],
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Other"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660230840000,
                "inactive_classifications": [],
                "ip_address": [
                    "192.190.221.160"
                ],
                "is_active": "Active",
                "last_observed": 1663256460000,
                "port": 21,
                "protocol": "TCP",
                "service_id": "d14a8823-c3f2-387f-aded-71462960323e",
                "service_name": "FTP Server at 192.190.221.160:21",
                "service_type": "FtpServer"
            },
            {
                "active_classifications": [
                    "FtpsServer",
                    "FtpServer"
                ],
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Other"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1663007160000,
                "inactive_classifications": [],
                "ip_address": [
                    "192.190.221.160"
                ],
                "is_active": "Active",
                "last_observed": 1663007160000,
                "port": 990,
                "protocol": "TCP",
                "service_id": "80a64a96-4057-3b54-91a2-7d6f499aeb17",
                "service_name": "FTP Server at 192.190.221.160:990",
                "service_type": "FtpServer"
            },
            {
                "active_classifications": [
                    "UnencryptedFtpServer",
                    "FtpServer"
                ],
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [],
                "externally_detected_providers": [
                    "On Prem"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659453600000,
                "inactive_classifications": [],
                "ip_address": [
                    "195.222.186.100"
                ],
                "is_active": "Active",
                "last_observed": 1663263480000,
                "port": 21,
                "protocol": "TCP",
                "service_id": "24efe1e6-5198-3788-9be2-3bf0dc52860a",
                "service_name": "FTP Server at 195.222.186.100:21",
                "service_type": "FtpServer"
            },
            {
                "active_classifications": [
                    "NetworkingAndSecurityInfrastructure",
                    "FtpServer",
                    "MikroTikRouter",
                    "UnencryptedFtpServer"
                ],
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [],
                "externally_detected_providers": [
                    "On Prem"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659455220000,
                "inactive_classifications": [],
                "ip_address": [
                    "195.68.131.22"
                ],
                "is_active": "Active",
                "last_observed": 1663262520000,
                "port": 21,
                "protocol": "TCP",
                "service_id": "aa9a697e-337a-3007-aaf3-f037c0838dbc",
                "service_name": "FTP Server at 195.68.131.22:21",
                "service_type": "FtpServer"
            },
            {
                "active_classifications": [
                    "UnencryptedFtpServer",
                    "FtpServer"
                ],
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [],
                "externally_detected_providers": [
                    "On Prem"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659476820000,
                "inactive_classifications": [],
                "ip_address": [
                    "195.68.153.227"
                ],
                "is_active": "Active",
                "last_observed": 1663099620000,
                "port": 21,
                "protocol": "TCP",
                "service_id": "6ab71c4b-7ff5-3d5b-a04b-266c82f0a378",
                "service_name": "FTP Server at 195.68.153.227:21",
                "service_type": "FtpServer"
            },
            {
                "active_classifications": [
                    "UnencryptedFtpServer",
                    "FtpServer"
                ],
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [],
                "externally_detected_providers": [
                    "On Prem"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659455280000,
                "inactive_classifications": [],
                "ip_address": [
                    "213.221.7.34"
                ],
                "is_active": "Active",
                "last_observed": 1663255860000,
                "port": 21,
                "protocol": "TCP",
                "service_id": "a3e101d0-ed64-3b5d-a267-1fea527bcbf6",
                "service_name": "FTP Server at 213.221.7.34:21",
                "service_type": "FtpServer"
            },
            {
                "active_classifications": [
                    "UnencryptedFtpServer",
                    "FtpServer"
                ],
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Other"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660254360000,
                "inactive_classifications": [],
                "ip_address": [
                    "218.17.210.177"
                ],
                "is_active": "Active",
                "last_observed": 1663263720000,
                "port": 21,
                "protocol": "TCP",
                "service_id": "677c7916-f1df-38d1-bad8-c42511c424ac",
                "service_name": "FTP Server at 218.17.210.177:21",
                "service_type": "FtpServer"
            },
            {
                "active_classifications": [
                    "ShortKeyCertificate",
                    "InsecureSignatureCertificate",
                    "SelfSignedCertificate",
                    "LongExpirationCertificate",
                    "FtpServer",
                    "FtpsServer",
                    "ExpiredWhenScannedCertificate"
                ],
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Other"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660273920000,
                "inactive_classifications": [],
                "ip_address": [
                    "218.17.210.177"
                ],
                "is_active": "Active",
                "last_observed": 1663176360000,
                "port": 990,
                "protocol": "TCP",
                "service_id": "1bcc954e-cf76-3064-9ffe-d7d5e771df4d",
                "service_name": "FTP Server at 218.17.210.177:990",
                "service_type": "FtpServer"
            },
            {
                "active_classifications": [
                    "LongExpirationCertificate",
                    "FtpsServer",
                    "FtpServer",
                    "SelfSignedCertificate"
                ],
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Other"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660065660000,
                "inactive_classifications": [],
                "ip_address": [
                    "23.234.27.33"
                ],
                "is_active": "Active",
                "last_observed": 1663263480000,
                "port": 21,
                "protocol": "TCP",
                "service_id": "1deff500-acbc-34e8-8062-b05574625274",
                "service_name": "FTP Server at 23.234.27.33:21",
                "service_type": "FtpServer"
            },
            {
                "active_classifications": [
                    "ShortKeyCertificate",
                    "InsecureSignatureCertificate",
                    "FtpsServer",
                    "FtpServer",
                    "SelfSignedCertificate",
                    "ExpiredWhenScannedCertificate"
                ],
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [],
                "externally_detected_providers": [
                    "On Prem"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659518880000,
                "inactive_classifications": [],
                "ip_address": [
                    "63.241.126.248"
                ],
                "is_active": "Active",
                "last_observed": 1663060020000,
                "port": 990,
                "protocol": "TCP",
                "service_id": "34402fb9-ab26-338f-ad86-51431df801e2",
                "service_name": "FTP Server at 63.241.126.248:990",
                "service_type": "FtpServer"
            },
            {
                "active_classifications": [
                    "FtpsServer",
                    "FtpServer"
                ],
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [],
                "externally_detected_providers": [
                    "On Prem"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659454800000,
                "inactive_classifications": [],
                "ip_address": [
                    "69.170.10.220"
                ],
                "is_active": "Active",
                "last_observed": 1663168800000,
                "port": 21,
                "protocol": "TCP",
                "service_id": "0e61d9f4-d2df-3648-b62a-d6fd5fdf94e8",
                "service_name": "FTP Server at 69.170.10.220:21",
                "service_type": "FtpServer"
            },
            {
                "active_classifications": [
                    "FtpServer",
                    "FtpsServer"
                ],
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [],
                "externally_detected_providers": [
                    "On Prem"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660146840000,
                "inactive_classifications": [],
                "ip_address": [
                    "69.170.10.220"
                ],
                "is_active": "Active",
                "last_observed": 1663033140000,
                "port": 990,
                "protocol": "TCP",
                "service_id": "d7ae9f2b-6386-31b4-8002-d683e25b9995",
                "service_name": "FTP Server at 69.170.10.220:990",
                "service_type": "FtpServer"
            },
            {
                "active_classifications": [
                    "InternalIpAddressAdvertisement",
                    "UnencryptedFtpServer",
                    "FtpServer"
                ],
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [],
                "externally_detected_providers": [
                    "On Prem"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659462960000,
                "inactive_classifications": [],
                "ip_address": [
                    "87.249.1.35"
                ],
                "is_active": "Active",
                "last_observed": 1663257480000,
                "port": 21,
                "protocol": "TCP",
                "service_id": "05f07f29-25e5-33e9-8259-01fb3136980c",
                "service_name": "FTP Server at 87.249.1.35:21",
                "service_type": "FtpServer"
            },
            {
                "active_classifications": [
                    "HttpServer",
                    "WildcardCertificate",
                    "ServerSoftware"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1662755220000,
                "inactive_classifications": [],
                "ip_address": [
                    "100.25.178.60"
                ],
                "is_active": "Active",
                "last_observed": 1663303620000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "0c9f1a24-9726-3def-a27d-a30e697d49bc",
                "service_name": "HTTP Server at 100.25.178.60:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "HttpServer",
                    "ServerSoftware"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659519180000,
                "inactive_classifications": [],
                "ip_address": [
                    "100.25.178.60"
                ],
                "is_active": "Active",
                "last_observed": 1663285980000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "c1c0cd6f-f5e8-35d2-b847-6780702bca92",
                "service_name": "HTTP Server at 100.25.178.60:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "WildcardCertificate",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingCacheControlHeader",
                    "WebLogin",
                    "MissingPublicKeyPinsHeader",
                    "NodeJs"
                ],
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Other"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1661243340000,
                "inactive_classifications": [],
                "ip_address": [
                    "104.207.249.74"
                ],
                "is_active": "Active",
                "last_observed": 1663088100000,
                "port": 2443,
                "protocol": "TCP",
                "service_id": "f66a8680-d3de-3b53-bd50-e942002b033c",
                "service_name": "HTTP Server at 104.207.249.74:2443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "HttpServer",
                    "ApacheWebServer",
                    "ServerSoftware",
                    "WildcardCertificate"
                ],
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Other"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660277280000,
                "inactive_classifications": [
                    "DevelopmentEnvironment"
                ],
                "ip_address": [
                    "104.207.249.74"
                ],
                "is_active": "Active",
                "last_observed": 1663323660000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "645a8f31-24a4-3fca-bdd0-2e6c40b3fd1b",
                "service_name": "HTTP Server at 104.207.249.74:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "HttpServer",
                    "ApacheWebServer",
                    "ServerSoftware"
                ],
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Other"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660194720000,
                "inactive_classifications": [],
                "ip_address": [
                    "104.207.249.74"
                ],
                "is_active": "Active",
                "last_observed": 1663330560000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "915c4358-3e7e-3b37-a77d-21fc6cc51cbb",
                "service_name": "HTTP Server at 104.207.249.74:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659408240000,
                "inactive_classifications": [
                    "HttpServer",
                    "WildcardCertificate",
                    "ExpiredWhenScannedCertificate"
                ],
                "ip_address": [
                    "107.23.198.175"
                ],
                "is_active": "Inactive",
                "last_observed": 1661546160000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "696f4245-22ea-3203-99db-406a8b7d08cb",
                "service_name": "HTTP Server at 107.23.198.175:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "AdobeExperienceManager",
                    "MissingCacheControlHeader",
                    "JQuery",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "OpenSSL",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "ApplicationServerSoftware",
                    "WildcardCertificate",
                    "HttpServer",
                    "PHP",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "PanOsDevice",
                    "ExpiredWhenScannedCertificate"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [
                    "CVE-2017-7679",
                    "CVE-2016-0705",
                    "CVE-2022-31813",
                    "CVE-2022-22720",
                    "CVE-2018-1312",
                    "CVE-2016-2108",
                    "CVE-2016-0799",
                    "CVE-2016-2177",
                    "CVE-2017-3169",
                    "CVE-2021-39275",
                    "CVE-2016-2182",
                    "CVE-2017-3167",
                    "CVE-2016-2842",
                    "CVE-2021-26691",
                    "CVE-2017-8923",
                    "CVE-2016-6303",
                    "CVE-2022-23943",
                    "CVE-2021-44790",
                    "CVE-2022-2068",
                    "CVE-2022-1292",
                    "CVE-2022-28615",
                    "CVE-2022-22721",
                    "CVE-2017-9788",
                    "CVE-2020-7043",
                    "CVE-2021-40438",
                    "CVE-2021-44224",
                    "CVE-2016-2176",
                    "CVE-2017-15715",
                    "CVE-2016-5387",
                    "CVE-2022-26377",
                    "CVE-2022-30556",
                    "CVE-2016-0736",
                    "CVE-2016-2180",
                    "CVE-2022-22719",
                    "CVE-2015-1789",
                    "CVE-2016-0797",
                    "CVE-2020-13950",
                    "CVE-2018-17199",
                    "CVE-2021-36160",
                    "CVE-2016-2106",
                    "CVE-2016-7052",
                    "CVE-2016-8743",
                    "CVE-2017-3731",
                    "CVE-2021-33193",
                    "CVE-2015-3194",
                    "CVE-2021-26690",
                    "CVE-2019-0217",
                    "CVE-2016-6304",
                    "CVE-2022-29404",
                    "CVE-2017-15710",
                    "CVE-2016-2179",
                    "CVE-2018-1303",
                    "CVE-2015-3193",
                    "CVE-2017-9798",
                    "CVE-2021-34798",
                    "CVE-2016-0798",
                    "CVE-2016-2109",
                    "CVE-2016-2181",
                    "CVE-2016-6302",
                    "CVE-2016-2105",
                    "CVE-2021-32785",
                    "CVE-2016-2183",
                    "CVE-2016-2161",
                    "CVE-2022-0778",
                    "CVE-2021-4044",
                    "CVE-2016-8610",
                    "CVE-2021-23840",
                    "CVE-2018-0732",
                    "CVE-2021-3712",
                    "CVE-2020-35452",
                    "CVE-2015-1791",
                    "CVE-2015-0209",
                    "CVE-2014-0226",
                    "CVE-2015-1793",
                    "CVE-2018-0739",
                    "CVE-2017-3736",
                    "CVE-2016-4975",
                    "CVE-2020-11023",
                    "CVE-2021-32792",
                    "CVE-2019-11358",
                    "CVE-2020-11022",
                    "CVE-2019-10092",
                    "CVE-2021-32786",
                    "CVE-2020-1927",
                    "CVE-2019-10098",
                    "CVE-2016-2107",
                    "CVE-2017-3738",
                    "CVE-2018-1301",
                    "CVE-2021-32791",
                    "CVE-2016-0704",
                    "CVE-2016-0703",
                    "CVE-2017-3737",
                    "CVE-2016-6306",
                    "CVE-2016-0800",
                    "CVE-2017-3732",
                    "CVE-2018-1302",
                    "CVE-2015-3197",
                    "CVE-2018-0737",
                    "CVE-2021-4160",
                    "CVE-2019-1559",
                    "CVE-2020-1971",
                    "CVE-2021-23841",
                    "CVE-2016-7055",
                    "CVE-2018-0734",
                    "CVE-2009-3555",
                    "CVE-2016-2178",
                    "CVE-2020-13938",
                    "CVE-2018-1283",
                    "CVE-2020-11985",
                    "CVE-2017-3735",
                    "CVE-2022-28614",
                    "CVE-2019-17567",
                    "CVE-2022-28330",
                    "CVE-2019-0220",
                    "CVE-2020-1934",
                    "CVE-2021-30641",
                    "CVE-2020-7041",
                    "CVE-2015-3195",
                    "CVE-2020-7042",
                    "CVE-2019-1551",
                    "CVE-2016-0702",
                    "CVE-2015-3183",
                    "CVE-2015-0207",
                    "CVE-2015-0288",
                    "CVE-2015-0290",
                    "CVE-2014-0231",
                    "CVE-2015-1792",
                    "CVE-2015-0286",
                    "CVE-2014-0098",
                    "CVE-2014-3581",
                    "CVE-2015-0228",
                    "CVE-2015-0291",
                    "CVE-2015-1794",
                    "CVE-2015-0289",
                    "CVE-2015-3184",
                    "CVE-2014-3523",
                    "CVE-2015-0293",
                    "CVE-2013-5704",
                    "CVE-2013-6438",
                    "CVE-2015-1790",
                    "CVE-2015-0287",
                    "CVE-2019-1547",
                    "CVE-2018-5407",
                    "CVE-2014-0118",
                    "CVE-2016-8612",
                    "CVE-2014-0117",
                    "CVE-2015-3185",
                    "CVE-2014-8109",
                    "CVE-2015-0208",
                    "CVE-2015-0285",
                    "CVE-2015-1788",
                    "CVE-2016-0701",
                    "CVE-2020-1968",
                    "CVE-2015-4000",
                    "CVE-2021-23839",
                    "CVE-2019-1563",
                    "CVE-2019-1552",
                    "CVE-2015-1787"
                ],
                "externally_inferred_vulnerability_score": 9.8,
                "first_observed": 1662751980000,
                "inactive_classifications": [],
                "ip_address": [
                    "108.138.106.106"
                ],
                "is_active": "Active",
                "last_observed": 1663323720000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "ae57c07d-9d70-3a85-9867-b3ff7b8c3e2f",
                "service_name": "HTTP Server at 108.138.106.106:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1662753360000,
                "inactive_classifications": [],
                "ip_address": [
                    "108.138.106.106"
                ],
                "is_active": "Active",
                "last_observed": 1663323600000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "672061b6-3995-3ff9-a3c1-649d7edd80f6",
                "service_name": "HTTP Server at 108.138.106.106:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660951980000,
                "inactive_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "MissingCacheControlHeader",
                    "JQuery",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "MissingContentSecurityPolicyHeader",
                    "WildcardCertificate",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader"
                ],
                "ip_address": [
                    "108.138.106.127"
                ],
                "is_active": "Inactive",
                "last_observed": 1661121840000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "142a21c4-2528-3f65-9d90-374c848b19be",
                "service_name": "HTTP Server at 108.138.106.127:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660956480000,
                "inactive_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment"
                ],
                "ip_address": [
                    "108.138.106.127"
                ],
                "is_active": "Inactive",
                "last_observed": 1661128500000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "e9261cb4-dec4-3bed-b733-54d700c2cfd6",
                "service_name": "HTTP Server at 108.138.106.127:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "MissingCacheControlHeader",
                    "JQuery",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "ApplicationServerSoftware",
                    "WildcardCertificate",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [
                    "CVE-2020-11023",
                    "CVE-2015-9251",
                    "CVE-2020-11022",
                    "CVE-2019-11358"
                ],
                "externally_inferred_vulnerability_score": 6.1,
                "first_observed": 1662752940000,
                "inactive_classifications": [],
                "ip_address": [
                    "108.138.106.128"
                ],
                "is_active": "Active",
                "last_observed": 1663323300000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "4a5e6c06-39e5-3b84-9717-e7f771bc3be2",
                "service_name": "HTTP Server at 108.138.106.128:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1662752640000,
                "inactive_classifications": [],
                "ip_address": [
                    "108.138.106.128"
                ],
                "is_active": "Active",
                "last_observed": 1663330980000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "d8a9ee32-d433-31ac-8980-de280ca799b1",
                "service_name": "HTTP Server at 108.138.106.128:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660962360000,
                "inactive_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader",
                    "NodeJs",
                    "MissingXFrameOptionsHeader",
                    "MissingContentSecurityPolicyHeader",
                    "ApplicationServerSoftware",
                    "WildcardCertificate",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader"
                ],
                "ip_address": [
                    "108.138.106.26"
                ],
                "is_active": "Inactive",
                "last_observed": 1661122080000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "36185c0b-5c06-30af-9461-44dc381189e7",
                "service_name": "HTTP Server at 108.138.106.26:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660943760000,
                "inactive_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader"
                ],
                "ip_address": [
                    "108.138.106.26"
                ],
                "is_active": "Inactive",
                "last_observed": 1661120940000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "2ad6e114-6a8a-3a1b-8da0-db6c74d7a2ba",
                "service_name": "HTTP Server at 108.138.106.26:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "MissingCacheControlHeader",
                    "JQuery",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "MicrosoftIisWebServer",
                    "ApplicationServerSoftware",
                    "WildcardCertificate",
                    "LongExpirationCertificate",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "PanOsDevice"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [
                    "CVE-2020-11022",
                    "CVE-2020-11023"
                ],
                "externally_inferred_vulnerability_score": 6.1,
                "first_observed": 1662753480000,
                "inactive_classifications": [],
                "ip_address": [
                    "108.138.106.35"
                ],
                "is_active": "Active",
                "last_observed": 1663329720000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "6062f780-ab3e-321d-a814-584da9eb99f8",
                "service_name": "HTTP Server at 108.138.106.35:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1662753900000,
                "inactive_classifications": [],
                "ip_address": [
                    "108.138.106.35"
                ],
                "is_active": "Active",
                "last_observed": 1663331580000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "67d429ed-0c85-3d17-8c3f-ec530061968c",
                "service_name": "HTTP Server at 108.138.106.35:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "MissingCacheControlHeader",
                    "WebLogin",
                    "JQuery",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "ApplicationServerSoftware",
                    "WildcardCertificate",
                    "HttpServer",
                    "PHP",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "ExpiredWhenScannedCertificate"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [
                    "CVE-2021-39275",
                    "CVE-2022-31813",
                    "CVE-2022-23943",
                    "CVE-2021-44790",
                    "CVE-2017-8923",
                    "CVE-2022-22720",
                    "CVE-2021-26691",
                    "CVE-2022-28615",
                    "CVE-2022-22721",
                    "CVE-2021-40438",
                    "CVE-2021-44224",
                    "CVE-2021-26690",
                    "CVE-2020-13950",
                    "CVE-2021-36160",
                    "CVE-2021-34798",
                    "CVE-2022-22719",
                    "CVE-2021-32785",
                    "CVE-2021-33193",
                    "CVE-2022-26377",
                    "CVE-2022-30556",
                    "CVE-2022-29404",
                    "CVE-2020-35452",
                    "CVE-2021-21703",
                    "CVE-2021-21706",
                    "CVE-2019-11358",
                    "CVE-2021-32792",
                    "CVE-2020-11022",
                    "CVE-2020-11023",
                    "CVE-2021-32786",
                    "CVE-2021-32791",
                    "CVE-2020-13938",
                    "CVE-2022-28330",
                    "CVE-2022-28614",
                    "CVE-2019-17567",
                    "CVE-2021-30641",
                    "CVE-2021-21707"
                ],
                "externally_inferred_vulnerability_score": 9.8,
                "first_observed": 1662753480000,
                "inactive_classifications": [],
                "ip_address": [
                    "108.138.106.70"
                ],
                "is_active": "Active",
                "last_observed": 1663328820000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "9784500c-88fe-3b66-93e1-ecd33c3129d2",
                "service_name": "HTTP Server at 108.138.106.70:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [
                    "CVE-2022-22720",
                    "CVE-2022-23943",
                    "CVE-2021-39275",
                    "CVE-2017-3169",
                    "CVE-2017-7679",
                    "CVE-2017-3167",
                    "CVE-2021-26691",
                    "CVE-2021-44790",
                    "CVE-2022-31813",
                    "CVE-2018-1312",
                    "CVE-2022-22721",
                    "CVE-2017-9788",
                    "CVE-2022-28615",
                    "CVE-2021-40438",
                    "CVE-2021-44224",
                    "CVE-2017-15715",
                    "CVE-2016-5387",
                    "CVE-2022-26377",
                    "CVE-2018-1303",
                    "CVE-2022-30556",
                    "CVE-2016-0736",
                    "CVE-2017-15710",
                    "CVE-2022-29404",
                    "CVE-2021-26690",
                    "CVE-2019-0217",
                    "CVE-2016-2161",
                    "CVE-2021-32785",
                    "CVE-2021-34798",
                    "CVE-2016-8743",
                    "CVE-2018-17199",
                    "CVE-2022-22719",
                    "CVE-2017-9798",
                    "CVE-2020-35452",
                    "CVE-2021-32792",
                    "CVE-2021-32786",
                    "CVE-2019-10098",
                    "CVE-2016-4975",
                    "CVE-2019-10092",
                    "CVE-2020-1927",
                    "CVE-2018-1301",
                    "CVE-2021-32791",
                    "CVE-2018-1302",
                    "CVE-2020-13938",
                    "CVE-2022-28614",
                    "CVE-2020-11985",
                    "CVE-2020-1934",
                    "CVE-2019-17567",
                    "CVE-2018-1283",
                    "CVE-2019-0220",
                    "CVE-2022-28330",
                    "CVE-2015-3184",
                    "CVE-2016-8612"
                ],
                "externally_inferred_vulnerability_score": 9.8,
                "first_observed": 1662753840000,
                "inactive_classifications": [],
                "ip_address": [
                    "108.138.106.70"
                ],
                "is_active": "Active",
                "last_observed": 1663325280000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "20cd9af5-bdc3-3355-983b-1a8f4514b70a",
                "service_name": "HTTP Server at 108.138.106.70:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660955880000,
                "inactive_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "WildcardCertificate",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment"
                ],
                "ip_address": [
                    "108.138.106.73"
                ],
                "is_active": "Inactive",
                "last_observed": 1661122020000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "db1504b5-9e70-33ef-b8e7-0416672f8925",
                "service_name": "HTTP Server at 108.138.106.73:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660975260000,
                "inactive_classifications": [
                    "HttpServer",
                    "ServerSoftware",
                    "DevelopmentEnvironment"
                ],
                "ip_address": [
                    "108.138.106.73"
                ],
                "is_active": "Inactive",
                "last_observed": 1661116740000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "42ba41a4-f4bc-314d-85a6-93e56b58df07",
                "service_name": "HTTP Server at 108.138.106.73:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660948200000,
                "inactive_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "MicrosoftIisWebServer",
                    "WildcardCertificate",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader"
                ],
                "ip_address": [
                    "108.138.106.79"
                ],
                "is_active": "Inactive",
                "last_observed": 1661122500000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "62a1d4ab-a8ce-3bf7-a445-7cc637850d7c",
                "service_name": "HTTP Server at 108.138.106.79:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660943040000,
                "inactive_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader"
                ],
                "ip_address": [
                    "108.138.106.79"
                ],
                "is_active": "Inactive",
                "last_observed": 1661122680000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "f7e72480-7690-3f15-8e71-d2906364b182",
                "service_name": "HTTP Server at 108.138.106.79:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1661272140000,
                "inactive_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "ApplicationServerSoftware",
                    "WildcardCertificate",
                    "HttpServer",
                    "PHP",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader"
                ],
                "ip_address": [
                    "108.138.159.8"
                ],
                "is_active": "Inactive",
                "last_observed": 1661474100000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "1258e0c6-19ab-3aee-b2fd-4c7766de28ee",
                "service_name": "HTTP Server at 108.138.159.8:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1661264040000,
                "inactive_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "MissingContentSecurityPolicyHeader",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader",
                    "NodeJs"
                ],
                "ip_address": [
                    "108.138.159.8"
                ],
                "is_active": "Inactive",
                "last_observed": 1661473260000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "7fb86d36-14a3-332e-bb4d-5044e0a80474",
                "service_name": "HTTP Server at 108.138.159.8:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "PythonApplication",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "WildcardCertificate",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [
                    "CVE-2022-23943",
                    "CVE-2021-44790",
                    "CVE-2021-26691",
                    "CVE-2017-7679",
                    "CVE-2022-22720",
                    "CVE-2022-31813",
                    "CVE-2018-1312",
                    "CVE-2017-3167",
                    "CVE-2015-20107",
                    "CVE-2021-39275",
                    "CVE-2019-9636",
                    "CVE-2020-27619",
                    "CVE-2021-3177",
                    "CVE-2016-0718",
                    "CVE-2019-10160",
                    "CVE-2016-9063",
                    "CVE-2022-28615",
                    "CVE-2017-9788",
                    "CVE-2022-22721",
                    "CVE-2019-9948",
                    "CVE-2021-40438",
                    "CVE-2020-29396",
                    "CVE-2017-17522",
                    "CVE-2021-44224",
                    "CVE-2016-5387",
                    "CVE-2017-15715",
                    "CVE-2016-4472",
                    "CVE-2020-15523",
                    "CVE-2018-1303",
                    "CVE-2021-26690",
                    "CVE-2017-9798",
                    "CVE-2018-20406",
                    "CVE-2018-17199",
                    "CVE-2022-22719",
                    "CVE-2022-29404",
                    "CVE-2021-32785",
                    "CVE-2016-2161",
                    "CVE-2016-0736",
                    "CVE-2017-15710",
                    "CVE-2022-30556",
                    "CVE-2016-8743",
                    "CVE-2022-26377",
                    "CVE-2019-9674",
                    "CVE-2021-34798",
                    "CVE-2019-0217",
                    "CVE-2022-0391",
                    "CVE-2018-14647",
                    "CVE-2019-20907",
                    "CVE-2019-16056",
                    "CVE-2019-15903",
                    "CVE-2018-1060",
                    "CVE-2019-5010",
                    "CVE-2019-17514",
                    "CVE-2017-9233",
                    "CVE-2018-1061",
                    "CVE-2021-3737",
                    "CVE-2021-28861",
                    "CVE-2020-35452",
                    "CVE-2020-26116",
                    "CVE-2022-26488",
                    "CVE-2014-0226",
                    "CVE-2013-0340",
                    "CVE-2018-1000117",
                    "CVE-2017-18207",
                    "CVE-2020-8492",
                    "CVE-2021-3733",
                    "CVE-2021-32786",
                    "CVE-2019-10092",
                    "CVE-2020-1927",
                    "CVE-2019-10098",
                    "CVE-2016-4975",
                    "CVE-2021-32792",
                    "CVE-2019-16935",
                    "CVE-2019-9740",
                    "CVE-2019-9947",
                    "CVE-2019-18348",
                    "CVE-2021-28359",
                    "CVE-2018-1302",
                    "CVE-2021-32791",
                    "CVE-2018-1301",
                    "CVE-2021-23336",
                    "CVE-2020-14422",
                    "CVE-2021-3426",
                    "CVE-2020-13938",
                    "CVE-2020-8315",
                    "CVE-2022-28614",
                    "CVE-2019-0220",
                    "CVE-2022-28330",
                    "CVE-2020-1934",
                    "CVE-2020-11985",
                    "CVE-2018-1283",
                    "CVE-2019-17567",
                    "CVE-2018-20852",
                    "CVE-2021-4189",
                    "CVE-2014-0098",
                    "CVE-2014-3523",
                    "CVE-2015-0228",
                    "CVE-2013-6438",
                    "CVE-2015-3183",
                    "CVE-2013-5704",
                    "CVE-2015-3184",
                    "CVE-2014-3581",
                    "CVE-2014-0231",
                    "CVE-2015-3185",
                    "CVE-2014-0117",
                    "CVE-2014-8109",
                    "CVE-2014-0118",
                    "CVE-2016-8612"
                ],
                "externally_inferred_vulnerability_score": 9.8,
                "first_observed": 1659493980000,
                "inactive_classifications": [
                    "MicrosoftIisWebServer",
                    "ApplicationServerSoftware",
                    "NginxWebServer",
                    "PHP",
                    "WordpressServer",
                    "JQuery",
                    "DomainControlValidatedCertificate",
                    "NodeJs"
                ],
                "ip_address": [
                    "108.138.167.111"
                ],
                "is_active": "Active",
                "last_observed": 1663330680000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "37445ff2-12eb-3a9d-8361-bfea8fa236c3",
                "service_name": "HTTP Server at 108.138.167.111:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659515940000,
                "inactive_classifications": [
                    "JQuery",
                    "NginxWebServer"
                ],
                "ip_address": [
                    "108.138.167.111"
                ],
                "is_active": "Active",
                "last_observed": 1663331460000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "8aafd70d-7fa3-336c-a713-ae628da3e653",
                "service_name": "HTTP Server at 108.138.167.111:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "WordpressServer",
                    "MissingCacheControlHeader",
                    "JQuery",
                    "MissingPublicKeyPinsHeader",
                    "AdobeFlash",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "WildcardCertificate",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "ExpiredWhenScannedCertificate"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [
                    "CVE-2021-26691",
                    "CVE-2021-44790",
                    "CVE-2021-39275",
                    "CVE-2022-31813",
                    "CVE-2022-23943",
                    "CVE-2022-22720",
                    "CVE-2018-1312",
                    "CVE-2022-28615",
                    "CVE-2022-22721",
                    "CVE-2019-10082",
                    "CVE-2021-40438",
                    "CVE-2021-44224",
                    "CVE-2017-15715",
                    "CVE-2019-0211",
                    "CVE-2022-22719",
                    "CVE-2021-34798",
                    "CVE-2020-9490",
                    "CVE-2019-0217",
                    "CVE-2022-30556",
                    "CVE-2021-32785",
                    "CVE-2017-15710",
                    "CVE-2021-33193",
                    "CVE-2020-11993",
                    "CVE-2022-26377",
                    "CVE-2021-26690",
                    "CVE-2019-10081",
                    "CVE-2018-17199",
                    "CVE-2022-29404",
                    "CVE-2018-1333",
                    "CVE-2018-1303",
                    "CVE-2020-35452",
                    "CVE-2019-10092",
                    "CVE-2020-1927",
                    "CVE-2019-10098",
                    "CVE-2021-32786",
                    "CVE-2021-32792",
                    "CVE-2021-32791",
                    "CVE-2018-11763",
                    "CVE-2018-1302",
                    "CVE-2018-1301",
                    "CVE-2020-13938",
                    "CVE-2019-0196",
                    "CVE-2022-28330",
                    "CVE-2019-17567",
                    "CVE-2018-1283",
                    "CVE-2020-1934",
                    "CVE-2018-17189",
                    "CVE-2022-28614",
                    "CVE-2019-0220"
                ],
                "externally_inferred_vulnerability_score": 9.8,
                "first_observed": 1659492780000,
                "inactive_classifications": [
                    "ApplicationServerSoftware",
                    "PHP"
                ],
                "ip_address": [
                    "108.138.167.113"
                ],
                "is_active": "Active",
                "last_observed": 1663330620000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "0b6c9037-a030-3806-ba72-8b8aa68ee385",
                "service_name": "HTTP Server at 108.138.167.113:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659522600000,
                "inactive_classifications": [],
                "ip_address": [
                    "108.138.167.113"
                ],
                "is_active": "Active",
                "last_observed": 1663331460000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "167e47d4-db99-33d1-bf37-b69472329316",
                "service_name": "HTTP Server at 108.138.167.113:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "WordpressServer",
                    "MissingCacheControlHeader",
                    "JQuery",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "ApplicationServerSoftware",
                    "WildcardCertificate",
                    "HttpServer",
                    "PHP",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "ExpiredWhenScannedCertificate"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [
                    "CVE-2022-31813",
                    "CVE-2022-28615",
                    "CVE-2022-31626",
                    "CVE-2022-31625",
                    "CVE-2022-30556",
                    "CVE-2022-29404",
                    "CVE-2022-26377",
                    "CVE-2022-30522",
                    "CVE-2022-28614",
                    "CVE-2022-28330"
                ],
                "externally_inferred_vulnerability_score": 9.8,
                "first_observed": 1662820320000,
                "inactive_classifications": [],
                "ip_address": [
                    "108.138.167.39"
                ],
                "is_active": "Active",
                "last_observed": 1663330980000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "1963ffca-641c-3b2e-92a2-e7322bb34c1b",
                "service_name": "HTTP Server at 108.138.167.39:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "HttpServer",
                    "ServerSoftware",
                    "NginxWebServer",
                    "DevelopmentEnvironment"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659544680000,
                "inactive_classifications": [
                    "JQuery"
                ],
                "ip_address": [
                    "108.138.167.39"
                ],
                "is_active": "Active",
                "last_observed": 1663331580000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "d60dc1cb-bba3-3d4c-85e9-2caa256af02e",
                "service_name": "HTTP Server at 108.138.167.39:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "MissingCacheControlHeader",
                    "WebLogin",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "WildcardCertificate",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "ExpiredWhenScannedCertificate"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659494040000,
                "inactive_classifications": [
                    "AtlassianConfluenceServer",
                    "MicrosoftIisWebServer",
                    "ApplicationServerSoftware",
                    "KestrelWebServer",
                    "WordpressServer",
                    "F5AdvancedWebApplicationFirewall",
                    "JQuery",
                    "AdobeFlash",
                    "NodeJs"
                ],
                "ip_address": [
                    "108.138.167.71"
                ],
                "is_active": "Active",
                "last_observed": 1663266720000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "601bf040-40f4-3398-85c4-84d233ac7733",
                "service_name": "HTTP Server at 108.138.167.71:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659573600000,
                "inactive_classifications": [
                    "JQuery",
                    "ApacheWebServer",
                    "WordpressServer"
                ],
                "ip_address": [
                    "108.138.167.71"
                ],
                "is_active": "Active",
                "last_observed": 1663267020000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "cd31da6f-46e0-3867-8133-6ad9fc1c19af",
                "service_name": "HTTP Server at 108.138.167.71:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "WordpressServer",
                    "MissingCacheControlHeader",
                    "JQuery",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "MicrosoftIisWebServer",
                    "ApplicationServerSoftware",
                    "WildcardCertificate",
                    "HttpServer",
                    "PHP",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [
                    "CVE-2018-1312",
                    "CVE-2019-11043",
                    "CVE-2019-11049",
                    "CVE-2021-44790",
                    "CVE-2022-23943",
                    "CVE-2021-39275",
                    "CVE-2019-13224",
                    "CVE-2017-8923",
                    "CVE-2022-22720",
                    "CVE-2021-26691",
                    "CVE-2022-31813",
                    "CVE-2019-10082",
                    "CVE-2020-7060",
                    "CVE-2020-7059",
                    "CVE-2022-22721",
                    "CVE-2020-7061",
                    "CVE-2022-28615",
                    "CVE-2021-40438",
                    "CVE-2020-7065",
                    "CVE-2021-44224",
                    "CVE-2017-15715",
                    "CVE-2019-0211",
                    "CVE-2020-7062",
                    "CVE-2021-33193",
                    "CVE-2022-30556",
                    "CVE-2017-15710",
                    "CVE-2018-1303",
                    "CVE-2019-11046",
                    "CVE-2018-1333",
                    "CVE-2020-11993",
                    "CVE-2019-0217",
                    "CVE-2021-26690",
                    "CVE-2022-29404",
                    "CVE-2019-10081",
                    "CVE-2021-21702",
                    "CVE-2018-17199",
                    "CVE-2021-32785",
                    "CVE-2020-9490",
                    "CVE-2019-11044",
                    "CVE-2021-34798",
                    "CVE-2022-22719",
                    "CVE-2022-26377",
                    "CVE-2019-19246",
                    "CVE-2020-7067",
                    "CVE-2020-35452",
                    "CVE-2019-11041",
                    "CVE-2019-11042",
                    "CVE-2021-21703",
                    "CVE-2019-11047",
                    "CVE-2019-11050",
                    "CVE-2020-7069",
                    "CVE-2021-21706",
                    "CVE-2020-11023",
                    "CVE-2021-32792",
                    "CVE-2019-10098",
                    "CVE-2020-11022",
                    "CVE-2019-11358",
                    "CVE-2019-10092",
                    "CVE-2020-1927",
                    "CVE-2021-32786",
                    "CVE-2015-9251",
                    "CVE-2018-1301",
                    "CVE-2019-11045",
                    "CVE-2021-21704",
                    "CVE-2018-11763",
                    "CVE-2018-1302",
                    "CVE-2021-32791",
                    "CVE-2020-13938",
                    "CVE-2020-7064",
                    "CVE-2020-7070",
                    "CVE-2020-7063",
                    "CVE-2022-28614",
                    "CVE-2019-17567",
                    "CVE-2020-1934",
                    "CVE-2019-0196",
                    "CVE-2020-7071",
                    "CVE-2021-21705",
                    "CVE-2021-21707",
                    "CVE-2018-1283",
                    "CVE-2019-0220",
                    "CVE-2019-11048",
                    "CVE-2018-17189",
                    "CVE-2022-28330",
                    "CVE-2014-4078",
                    "CVE-2020-7066",
                    "CVE-2020-7068"
                ],
                "externally_inferred_vulnerability_score": 9.8,
                "first_observed": 1662596400000,
                "inactive_classifications": [],
                "ip_address": [
                    "108.156.120.108"
                ],
                "is_active": "Active",
                "last_observed": 1663108260000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "8e2f22c2-2d96-3c76-819c-d96de46ba24f",
                "service_name": "HTTP Server at 108.156.120.108:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "HttpServer",
                    "ApacheWebServer",
                    "ServerSoftware",
                    "PythonApplication",
                    "JQuery",
                    "DevelopmentEnvironment"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [
                    "CVE-2021-39275",
                    "CVE-2022-31813",
                    "CVE-2022-23943",
                    "CVE-2020-27619",
                    "CVE-2021-3177",
                    "CVE-2022-22720",
                    "CVE-2021-44790",
                    "CVE-2015-20107",
                    "CVE-2022-28615",
                    "CVE-2022-22721",
                    "CVE-2021-40438",
                    "CVE-2020-29396",
                    "CVE-2021-44224",
                    "CVE-2019-9674",
                    "CVE-2018-20406",
                    "CVE-2021-36160",
                    "CVE-2022-22719",
                    "CVE-2022-29404",
                    "CVE-2022-26377",
                    "CVE-2021-32785",
                    "CVE-2022-0391",
                    "CVE-2021-33193",
                    "CVE-2021-34798",
                    "CVE-2022-30556",
                    "CVE-2021-3737",
                    "CVE-2021-28861",
                    "CVE-2022-26488",
                    "CVE-2013-0340",
                    "CVE-2021-3733",
                    "CVE-2021-28359",
                    "CVE-2021-32792",
                    "CVE-2020-11022",
                    "CVE-2021-32786",
                    "CVE-2020-11023",
                    "CVE-2019-11358",
                    "CVE-2021-32791",
                    "CVE-2021-23336",
                    "CVE-2021-3426",
                    "CVE-2021-4189",
                    "CVE-2022-28330",
                    "CVE-2022-28614"
                ],
                "externally_inferred_vulnerability_score": 9.8,
                "first_observed": 1662596520000,
                "inactive_classifications": [],
                "ip_address": [
                    "108.156.120.108"
                ],
                "is_active": "Active",
                "last_observed": 1663085880000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "3c215660-e833-39a7-8363-ae36ef9f289e",
                "service_name": "HTTP Server at 108.156.120.108:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "MissingCacheControlHeader",
                    "WebLogin",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "NodeJs",
                    "MissingXFrameOptionsHeader",
                    "MissingContentSecurityPolicyHeader",
                    "ApplicationServerSoftware",
                    "WildcardCertificate",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "ExpiredWhenScannedCertificate"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659580440000,
                "inactive_classifications": [
                    "F5BigIpPlatform",
                    "ApacheWebServer",
                    "MicrosoftIisWebServer",
                    "MoodleCMS",
                    "AdobeCommerce",
                    "PHP",
                    "LoadBalancer",
                    "WordpressServer",
                    "JQuery"
                ],
                "ip_address": [
                    "108.156.120.121"
                ],
                "is_active": "Active",
                "last_observed": 1663328040000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "2f61a4ce-ee3b-3807-b996-736283679c8a",
                "service_name": "HTTP Server at 108.156.120.121:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "ApplicationServerSoftware",
                    "NginxWebServer",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659590160000,
                "inactive_classifications": [
                    "UnclaimedS3Bucket",
                    "ApacheWebServer",
                    "DevelopmentEnvironment"
                ],
                "ip_address": [
                    "108.156.120.121"
                ],
                "is_active": "Active",
                "last_observed": 1663330380000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "b0407b44-3838-3c94-adc1-4b73ce5ebfbb",
                "service_name": "HTTP Server at 108.156.120.121:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "WordpressServer",
                    "KongGateway",
                    "MissingCacheControlHeader",
                    "JQuery",
                    "MissingPublicKeyPinsHeader",
                    "NodeJs",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "MicrosoftIisWebServer",
                    "InternalIpAddressAdvertisement",
                    "ApplicationServerSoftware",
                    "WildcardCertificate",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [
                    "CVE-2022-22720",
                    "CVE-2018-1312",
                    "CVE-2022-23943",
                    "CVE-2022-31813",
                    "CVE-2021-44790",
                    "CVE-2021-26691",
                    "CVE-2021-39275",
                    "CVE-2022-28615",
                    "CVE-2019-10082",
                    "CVE-2022-22721",
                    "CVE-2021-40438",
                    "CVE-2021-44224",
                    "CVE-2017-15715",
                    "CVE-2019-0211",
                    "CVE-2022-29404",
                    "CVE-2021-33193",
                    "CVE-2017-15710",
                    "CVE-2022-26377",
                    "CVE-2019-0217",
                    "CVE-2019-10081",
                    "CVE-2022-22719",
                    "CVE-2018-1333",
                    "CVE-2018-1303",
                    "CVE-2021-34798",
                    "CVE-2018-17199",
                    "CVE-2021-32785",
                    "CVE-2021-26690",
                    "CVE-2020-9490",
                    "CVE-2022-30556",
                    "CVE-2020-11993",
                    "CVE-2020-35452",
                    "CVE-2021-32786",
                    "CVE-2019-10098",
                    "CVE-2020-1927",
                    "CVE-2019-10092",
                    "CVE-2021-32792",
                    "CVE-2018-1302",
                    "CVE-2018-11763",
                    "CVE-2021-32791",
                    "CVE-2018-1301",
                    "CVE-2020-13938",
                    "CVE-2019-17567",
                    "CVE-2019-0220",
                    "CVE-2019-0196",
                    "CVE-2022-28614",
                    "CVE-2018-17189",
                    "CVE-2020-1934",
                    "CVE-2022-28330",
                    "CVE-2018-1283"
                ],
                "externally_inferred_vulnerability_score": 9.8,
                "first_observed": 1662770100000,
                "inactive_classifications": [],
                "ip_address": [
                    "108.156.120.16"
                ],
                "is_active": "Active",
                "last_observed": 1663326420000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "03dbb327-fc35-37a4-91b1-75d167754f7f",
                "service_name": "HTTP Server at 108.156.120.16:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader",
                    "NodeJs",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "ApplicationServerSoftware",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659590100000,
                "inactive_classifications": [],
                "ip_address": [
                    "108.156.120.16"
                ],
                "is_active": "Active",
                "last_observed": 1663326300000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "bdabbd2b-859d-3d3c-b167-7354383ed29c",
                "service_name": "HTTP Server at 108.156.120.16:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "WordpressServer",
                    "MissingCacheControlHeader",
                    "JQuery",
                    "WebLogin",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "MicrosoftIisWebServer",
                    "OktaSSO",
                    "ApplicationServerSoftware",
                    "WildcardCertificate",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [
                    "CVE-2021-39275",
                    "CVE-2020-28036",
                    "CVE-2022-23943",
                    "CVE-2017-16510",
                    "CVE-2020-11984",
                    "CVE-2020-28032",
                    "CVE-2021-44790",
                    "CVE-2019-17669",
                    "CVE-2021-44223",
                    "CVE-2016-10033",
                    "CVE-2021-26691",
                    "CVE-2020-36326",
                    "CVE-2017-5611",
                    "CVE-2022-31813",
                    "CVE-2020-28035",
                    "CVE-2018-20148",
                    "CVE-2016-10045",
                    "CVE-2019-17670",
                    "CVE-2022-22720",
                    "CVE-2017-14723",
                    "CVE-2019-20041",
                    "CVE-2020-28037",
                    "CVE-2020-28039",
                    "CVE-2022-28615",
                    "CVE-2022-22721",
                    "CVE-2021-40438",
                    "CVE-2022-21664",
                    "CVE-2017-5492",
                    "CVE-2018-12895",
                    "CVE-2017-9064",
                    "CVE-2020-26596",
                    "CVE-2018-19296",
                    "CVE-2018-1000773",
                    "CVE-2019-8942",
                    "CVE-2017-17091",
                    "CVE-2017-1000600",
                    "CVE-2017-5489",
                    "CVE-2019-9787",
                    "CVE-2019-17675",
                    "CVE-2017-9066",
                    "CVE-2017-9062",
                    "CVE-2021-44224",
                    "CVE-2020-11027",
                    "CVE-2021-26690",
                    "CVE-2020-28033",
                    "CVE-2018-20151",
                    "CVE-2018-6389",
                    "CVE-2022-29404",
                    "CVE-2020-13950",
                    "CVE-2022-22719",
                    "CVE-2017-14719",
                    "CVE-2020-9490",
                    "CVE-2022-30556",
                    "CVE-2022-26377",
                    "CVE-2021-33193",
                    "CVE-2020-11993",
                    "CVE-2021-32785",
                    "CVE-2017-5493",
                    "CVE-2022-21661",
                    "CVE-2012-6707",
                    "CVE-2020-11028",
                    "CVE-2017-9065",
                    "CVE-2021-36160",
                    "CVE-2021-34798",
                    "CVE-2019-17673",
                    "CVE-2020-35452",
                    "CVE-2022-21663",
                    "CVE-2020-4047",
                    "CVE-2017-6819",
                    "CVE-2018-20147",
                    "CVE-2018-20152",
                    "CVE-2019-8943",
                    "CVE-2016-7169",
                    "CVE-2019-17672",
                    "CVE-2018-10101",
                    "CVE-2019-20042",
                    "CVE-2019-16222",
                    "CVE-2018-20150",
                    "CVE-2020-1927",
                    "CVE-2019-16220",
                    "CVE-2018-5776",
                    "CVE-2019-16218",
                    "CVE-2020-11023",
                    "CVE-2017-6815",
                    "CVE-2018-10100",
                    "CVE-2017-14724",
                    "CVE-2019-11358",
                    "CVE-2017-6818",
                    "CVE-2019-16221",
                    "CVE-2021-32792",
                    "CVE-2020-11022",
                    "CVE-2020-11029",
                    "CVE-2017-5488",
                    "CVE-2020-28034",
                    "CVE-2019-16217",
                    "CVE-2017-14720",
                    "CVE-2017-5612",
                    "CVE-2017-9061",
                    "CVE-2018-10102",
                    "CVE-2017-14721",
                    "CVE-2020-28038",
                    "CVE-2017-14726",
                    "CVE-2017-14718",
                    "CVE-2017-9063",
                    "CVE-2017-5490",
                    "CVE-2019-16219",
                    "CVE-2021-32786",
                    "CVE-2021-32791",
                    "CVE-2017-8295",
                    "CVE-2020-4048",
                    "CVE-2020-13938",
                    "CVE-2020-11030",
                    "CVE-2017-17094",
                    "CVE-2017-6814",
                    "CVE-2019-16780",
                    "CVE-2019-17674",
                    "CVE-2020-11026",
                    "CVE-2017-6817",
                    "CVE-2022-21662",
                    "CVE-2020-4046",
                    "CVE-2017-17092",
                    "CVE-2019-16781",
                    "CVE-2019-16223",
                    "CVE-2018-20149",
                    "CVE-2017-17093",
                    "CVE-2018-20153",
                    "CVE-2017-14725",
                    "CVE-2022-28614",
                    "CVE-2022-28330",
                    "CVE-2017-5487",
                    "CVE-2020-1934",
                    "CVE-2019-20043",
                    "CVE-2017-5491",
                    "CVE-2019-17567",
                    "CVE-2017-5610",
                    "CVE-2019-17671",
                    "CVE-2021-30641",
                    "CVE-2020-25286",
                    "CVE-2017-6816",
                    "CVE-2016-7168",
                    "CVE-2016-9263",
                    "CVE-2020-28040",
                    "CVE-2020-4050",
                    "CVE-2020-4049"
                ],
                "externally_inferred_vulnerability_score": 9.8,
                "first_observed": 1659580020000,
                "inactive_classifications": [
                    "PHP",
                    "NodeJs",
                    "ExpiredWhenScannedCertificate"
                ],
                "ip_address": [
                    "108.156.120.33"
                ],
                "is_active": "Active",
                "last_observed": 1663329300000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "0ad80c63-c9b7-30b3-905c-ff78e9c52f5e",
                "service_name": "HTTP Server at 108.156.120.33:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader",
                    "NodeJs",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "ApplicationServerSoftware",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659588960000,
                "inactive_classifications": [
                    "NginxWebServer",
                    "MicrosoftIisWebServer"
                ],
                "ip_address": [
                    "108.156.120.33"
                ],
                "is_active": "Active",
                "last_observed": 1663326360000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "517df659-8ede-3168-8377-cb57137680b3",
                "service_name": "HTTP Server at 108.156.120.33:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "MissingCacheControlHeader",
                    "JQuery",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "MissingContentSecurityPolicyHeader",
                    "MicrosoftIisWebServer",
                    "ApplicationServerSoftware",
                    "WildcardCertificate",
                    "HttpServer",
                    "PHP",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "ExpiredWhenScannedCertificate"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [
                    "CVE-2017-8923",
                    "CVE-2012-6708",
                    "CVE-2020-11023",
                    "CVE-2020-7656",
                    "CVE-2019-11358",
                    "CVE-2015-9251",
                    "CVE-2020-11022",
                    "CVE-2014-4078"
                ],
                "externally_inferred_vulnerability_score": 9.8,
                "first_observed": 1659580140000,
                "inactive_classifications": [
                    "ApacheWebServer",
                    "WordpressServer",
                    "NodeJs"
                ],
                "ip_address": [
                    "108.156.120.41"
                ],
                "is_active": "Active",
                "last_observed": 1663330560000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "29bf4744-3a2e-315b-8f6b-f9b97f9aad32",
                "service_name": "HTTP Server at 108.156.120.41:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "HttpServer",
                    "ServerSoftware",
                    "DevelopmentEnvironment"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659590880000,
                "inactive_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "AtlassianJiraServer",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader"
                ],
                "ip_address": [
                    "108.156.120.41"
                ],
                "is_active": "Active",
                "last_observed": 1663331460000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "fbd9cd41-a525-343e-a91a-49a2343c8021",
                "service_name": "HTTP Server at 108.156.120.41:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "MissingCacheControlHeader",
                    "JQuery",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "MissingContentSecurityPolicyHeader",
                    "WildcardCertificate",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [
                    "CVE-2012-6708",
                    "CVE-2020-11023",
                    "CVE-2019-11358",
                    "CVE-2015-9251",
                    "CVE-2020-11022",
                    "CVE-2020-7656"
                ],
                "externally_inferred_vulnerability_score": 6.1,
                "first_observed": 1662596460000,
                "inactive_classifications": [],
                "ip_address": [
                    "108.156.120.72"
                ],
                "is_active": "Active",
                "last_observed": 1663085520000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "2f445d7e-0bfe-3fe1-a3af-0c82bd3196c5",
                "service_name": "HTTP Server at 108.156.120.72:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "HttpServer",
                    "ServerSoftware",
                    "DevelopmentEnvironment"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1662596520000,
                "inactive_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "JQuery",
                    "MissingPublicKeyPinsHeader"
                ],
                "ip_address": [
                    "108.156.120.72"
                ],
                "is_active": "Active",
                "last_observed": 1663086720000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "b395559f-01c2-3184-923b-e848189d624f",
                "service_name": "HTTP Server at 108.156.120.72:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "WildcardCertificate",
                    "HttpServer",
                    "MissingXContentTypeOptionsHeader",
                    "ServerSoftware"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [
                    "CVE-2017-3169",
                    "CVE-2022-22720",
                    "CVE-2018-1312",
                    "CVE-2017-7679",
                    "CVE-2022-23943",
                    "CVE-2022-31813",
                    "CVE-2021-44790",
                    "CVE-2021-26691",
                    "CVE-2021-39275",
                    "CVE-2017-3167",
                    "CVE-2022-28615",
                    "CVE-2019-10082",
                    "CVE-2017-9788",
                    "CVE-2022-22721",
                    "CVE-2021-40438",
                    "CVE-2021-44224",
                    "CVE-2017-15715",
                    "CVE-2016-5387",
                    "CVE-2019-0211",
                    "CVE-2022-29404",
                    "CVE-2021-33193",
                    "CVE-2017-15710",
                    "CVE-2022-26377",
                    "CVE-2016-8743",
                    "CVE-2019-0217",
                    "CVE-2019-10081",
                    "CVE-2022-22719",
                    "CVE-2018-1333",
                    "CVE-2018-1303",
                    "CVE-2021-34798",
                    "CVE-2018-17199",
                    "CVE-2016-8740",
                    "CVE-2021-32785",
                    "CVE-2016-4979",
                    "CVE-2021-26690",
                    "CVE-2020-9490",
                    "CVE-2022-30556",
                    "CVE-2017-9798",
                    "CVE-2020-11993",
                    "CVE-2020-35452",
                    "CVE-2021-32786",
                    "CVE-2019-10098",
                    "CVE-2020-1927",
                    "CVE-2016-4975",
                    "CVE-2019-10092",
                    "CVE-2021-32792",
                    "CVE-2018-1302",
                    "CVE-2018-11763",
                    "CVE-2021-32791",
                    "CVE-2016-1546",
                    "CVE-2018-1301",
                    "CVE-2020-13938",
                    "CVE-2019-17567",
                    "CVE-2019-0220",
                    "CVE-2019-0196",
                    "CVE-2022-28614",
                    "CVE-2020-11985",
                    "CVE-2018-17189",
                    "CVE-2020-1934",
                    "CVE-2022-28330",
                    "CVE-2018-1283",
                    "CVE-2016-8612"
                ],
                "externally_inferred_vulnerability_score": 9.8,
                "first_observed": 1662596460000,
                "inactive_classifications": [
                    "JQuery",
                    "WordpressServer"
                ],
                "ip_address": [
                    "108.156.120.99"
                ],
                "is_active": "Active",
                "last_observed": 1663108380000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "2c120c3e-3ec1-3447-82c1-bbb055c01d8b",
                "service_name": "HTTP Server at 108.156.120.99:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1662596520000,
                "inactive_classifications": [],
                "ip_address": [
                    "108.156.120.99"
                ],
                "is_active": "Active",
                "last_observed": 1663081680000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "633c6c62-206a-3e85-ad78-b2d87673c46f",
                "service_name": "HTTP Server at 108.156.120.99:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "MissingCacheControlHeader",
                    "JQuery",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "WildcardCertificate",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [
                    "CVE-2018-1312",
                    "CVE-2022-31813",
                    "CVE-2022-23943",
                    "CVE-2021-39275",
                    "CVE-2022-22720",
                    "CVE-2021-26691",
                    "CVE-2021-44790",
                    "CVE-2019-10082",
                    "CVE-2022-28615",
                    "CVE-2022-22721",
                    "CVE-2021-40438",
                    "CVE-2021-44224",
                    "CVE-2017-15715",
                    "CVE-2019-0211",
                    "CVE-2019-0217",
                    "CVE-2022-22719",
                    "CVE-2022-29404",
                    "CVE-2019-10081",
                    "CVE-2021-34798",
                    "CVE-2018-1303",
                    "CVE-2018-1333",
                    "CVE-2021-26690",
                    "CVE-2018-17199",
                    "CVE-2020-11993",
                    "CVE-2022-26377",
                    "CVE-2020-9490",
                    "CVE-2021-32785",
                    "CVE-2017-15710",
                    "CVE-2021-33193",
                    "CVE-2022-30556",
                    "CVE-2020-35452",
                    "CVE-2020-1927",
                    "CVE-2015-9251",
                    "CVE-2020-7656",
                    "CVE-2020-11022",
                    "CVE-2012-6708",
                    "CVE-2021-32786",
                    "CVE-2019-10098",
                    "CVE-2019-11358",
                    "CVE-2021-32792",
                    "CVE-2019-10092",
                    "CVE-2020-11023",
                    "CVE-2018-1302",
                    "CVE-2021-32791",
                    "CVE-2018-11763",
                    "CVE-2018-1301",
                    "CVE-2020-13938",
                    "CVE-2019-0196",
                    "CVE-2022-28330",
                    "CVE-2022-28614",
                    "CVE-2019-0220",
                    "CVE-2018-17189",
                    "CVE-2020-1934",
                    "CVE-2018-1283",
                    "CVE-2019-17567"
                ],
                "externally_inferred_vulnerability_score": 9.8,
                "first_observed": 1662596460000,
                "inactive_classifications": [
                    "ApplicationServerSoftware",
                    "PHP",
                    "WordpressServer"
                ],
                "ip_address": [
                    "108.156.120.9"
                ],
                "is_active": "Active",
                "last_observed": 1663101360000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "251605bf-4ccf-398f-bfb1-f62b68e24928",
                "service_name": "HTTP Server at 108.156.120.9:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "HttpServer",
                    "ServerSoftware",
                    "NginxWebServer",
                    "DevelopmentEnvironment"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1662596520000,
                "inactive_classifications": [],
                "ip_address": [
                    "108.156.120.9"
                ],
                "is_active": "Active",
                "last_observed": 1663086180000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "c1c31487-6714-3a6f-af63-5066b078ed04",
                "service_name": "HTTP Server at 108.156.120.9:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659588840000,
                "inactive_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "ApacheWebServer",
                    "MissingStrictTransportSecurityHeader",
                    "MissingContentSecurityPolicyHeader",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment"
                ],
                "ip_address": [
                    "108.157.142.105"
                ],
                "is_active": "Inactive",
                "last_observed": 1662575940000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "c7a3a84a-8f7b-391f-b440-5a235333715f",
                "service_name": "HTTP Server at 108.157.142.105:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "MissingCacheControlHeader",
                    "F5AdvancedWebApplicationFirewall",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "EclipseJettyWebServer",
                    "WildcardCertificate",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659407880000,
                "inactive_classifications": [
                    "ApplicationServerSoftware",
                    "WordpressServer",
                    "KongGateway",
                    "JQuery",
                    "NodeJs",
                    "DrupalWebServer",
                    "ExpiredWhenScannedCertificate"
                ],
                "ip_address": [
                    "108.157.142.68"
                ],
                "is_active": "Active",
                "last_observed": 1663302060000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "7408fa29-0296-3070-826c-cdc0593b2b08",
                "service_name": "HTTP Server at 108.157.142.68:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659588840000,
                "inactive_classifications": [
                    "WordpressServer",
                    "JQuery",
                    "NginxWebServer",
                    "DevelopmentEnvironment"
                ],
                "ip_address": [
                    "108.157.142.68"
                ],
                "is_active": "Active",
                "last_observed": 1663303140000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "02a68b81-7e97-3afd-ac05-bad0f546baab",
                "service_name": "HTTP Server at 108.157.142.68:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "MissingCacheControlHeader",
                    "JQuery",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "OpenSSL",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "WildcardCertificate",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [
                    "CVE-2016-2842",
                    "CVE-2016-2177",
                    "CVE-2017-3167",
                    "CVE-2022-31813",
                    "CVE-2022-22720",
                    "CVE-2018-1312",
                    "CVE-2021-44790",
                    "CVE-2022-23943",
                    "CVE-2017-7679",
                    "CVE-2016-0799",
                    "CVE-2021-39275",
                    "CVE-2016-2108",
                    "CVE-2021-26691",
                    "CVE-2016-6303",
                    "CVE-2016-0705",
                    "CVE-2016-2182",
                    "CVE-2022-2068",
                    "CVE-2022-1292",
                    "CVE-2017-9788",
                    "CVE-2022-28615",
                    "CVE-2022-22721",
                    "CVE-2020-7043",
                    "CVE-2021-40438",
                    "CVE-2016-2176",
                    "CVE-2016-5387",
                    "CVE-2017-15715",
                    "CVE-2016-2183",
                    "CVE-2016-2161",
                    "CVE-2016-8743",
                    "CVE-2021-34798",
                    "CVE-2015-3194",
                    "CVE-2022-26377",
                    "CVE-2017-15710",
                    "CVE-2016-6304",
                    "CVE-2022-29404",
                    "CVE-2016-2179",
                    "CVE-2022-30556",
                    "CVE-2016-0736",
                    "CVE-2015-3193",
                    "CVE-2016-0798",
                    "CVE-2016-2109",
                    "CVE-2016-2181",
                    "CVE-2016-2105",
                    "CVE-2018-17199",
                    "CVE-2016-0797",
                    "CVE-2021-32785",
                    "CVE-2016-2106",
                    "CVE-2017-3731",
                    "CVE-2022-22719",
                    "CVE-2016-7052",
                    "CVE-2017-9798",
                    "CVE-2016-2180",
                    "CVE-2018-1303",
                    "CVE-2016-6302",
                    "CVE-2019-0217",
                    "CVE-2021-26690",
                    "CVE-2015-1789",
                    "CVE-2021-4044",
                    "CVE-2018-0732",
                    "CVE-2016-8610",
                    "CVE-2022-0778",
                    "CVE-2021-23840",
                    "CVE-2021-3712",
                    "CVE-2020-35452",
                    "CVE-2014-0226",
                    "CVE-2015-0209",
                    "CVE-2015-1791",
                    "CVE-2015-1793",
                    "CVE-2018-0739",
                    "CVE-2017-3736",
                    "CVE-2019-10092",
                    "CVE-2020-1927",
                    "CVE-2019-10098",
                    "CVE-2021-32786",
                    "CVE-2021-32792",
                    "CVE-2016-4975",
                    "CVE-2016-0703",
                    "CVE-2016-2107",
                    "CVE-2017-3737",
                    "CVE-2017-3738",
                    "CVE-2016-0800",
                    "CVE-2017-3732",
                    "CVE-2016-0704",
                    "CVE-2015-3197",
                    "CVE-2021-32791",
                    "CVE-2018-1302",
                    "CVE-2016-6306",
                    "CVE-2018-1301",
                    "CVE-2019-1559",
                    "CVE-2020-1971",
                    "CVE-2016-7055",
                    "CVE-2021-23841",
                    "CVE-2021-4160",
                    "CVE-2018-0737",
                    "CVE-2018-0734",
                    "CVE-2009-3555",
                    "CVE-2020-13938",
                    "CVE-2016-2178",
                    "CVE-2018-1283",
                    "CVE-2022-28330",
                    "CVE-2017-3735",
                    "CVE-2022-28614",
                    "CVE-2019-0220",
                    "CVE-2020-1934",
                    "CVE-2019-17567",
                    "CVE-2020-11985",
                    "CVE-2019-1551",
                    "CVE-2015-3195",
                    "CVE-2020-7042",
                    "CVE-2020-7041",
                    "CVE-2016-0702",
                    "CVE-2013-5704",
                    "CVE-2015-0286",
                    "CVE-2014-0231",
                    "CVE-2015-3184",
                    "CVE-2015-3183",
                    "CVE-2015-1794",
                    "CVE-2015-0288",
                    "CVE-2015-0290",
                    "CVE-2014-3523",
                    "CVE-2015-0293",
                    "CVE-2015-0287",
                    "CVE-2015-1792",
                    "CVE-2013-6438",
                    "CVE-2015-1790",
                    "CVE-2014-0098",
                    "CVE-2014-3581",
                    "CVE-2015-0228",
                    "CVE-2015-0291",
                    "CVE-2015-0207",
                    "CVE-2015-0289",
                    "CVE-2019-1547",
                    "CVE-2018-5407",
                    "CVE-2014-8109",
                    "CVE-2015-0285",
                    "CVE-2016-8612",
                    "CVE-2015-1788",
                    "CVE-2014-0117",
                    "CVE-2014-0118",
                    "CVE-2015-3185",
                    "CVE-2013-4352",
                    "CVE-2015-0208",
                    "CVE-2016-0701",
                    "CVE-2021-23839",
                    "CVE-2015-4000",
                    "CVE-2020-1968",
                    "CVE-2019-1563",
                    "CVE-2019-1552",
                    "CVE-2015-1787"
                ],
                "externally_inferred_vulnerability_score": 9.8,
                "first_observed": 1662861180000,
                "inactive_classifications": [],
                "ip_address": [
                    "108.157.142.85"
                ],
                "is_active": "Active",
                "last_observed": 1663079340000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "b46de908-5c8e-3619-9c16-8f2aec791811",
                "service_name": "HTTP Server at 108.157.142.85:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659593580000,
                "inactive_classifications": [
                    "NginxWebServer",
                    "DevelopmentEnvironment"
                ],
                "ip_address": [
                    "108.157.142.85"
                ],
                "is_active": "Active",
                "last_observed": 1663072800000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "d02a5748-08e5-3a88-a78f-c229adf6d2d0",
                "service_name": "HTTP Server at 108.157.142.85:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "NginxWebServer",
                    "WebLogin",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "MicrosoftIisWebServer",
                    "ApplicationServerSoftware",
                    "WildcardCertificate",
                    "HttpServer",
                    "ServerSoftware"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659407880000,
                "inactive_classifications": [
                    "MissingStrictTransportSecurityHeader",
                    "PHP",
                    "WordpressServer",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "JQuery",
                    "ExpiredWhenScannedCertificate"
                ],
                "ip_address": [
                    "108.157.142.91"
                ],
                "is_active": "Active",
                "last_observed": 1663330980000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "f1d21bbc-33bf-3cef-b6b9-4ec93ab794b8",
                "service_name": "HTTP Server at 108.157.142.91:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "HttpServer",
                    "ServerSoftware",
                    "DevelopmentEnvironment"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659458340000,
                "inactive_classifications": [
                    "ApacheWebServer"
                ],
                "ip_address": [
                    "108.157.142.91"
                ],
                "is_active": "Active",
                "last_observed": 1663331580000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "6943990e-74be-35fe-87f5-30d4f8ee5fdc",
                "service_name": "HTTP Server at 108.157.142.91:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "HttpServer",
                    "ServerSoftware",
                    "DevelopmentEnvironment"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659835800000,
                "inactive_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "WordpressServer",
                    "MissingCacheControlHeader",
                    "JQuery",
                    "MissingPublicKeyPinsHeader",
                    "NodeJs",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "ApplicationServerSoftware",
                    "WildcardCertificate",
                    "MissingXContentTypeOptionsHeader"
                ],
                "ip_address": [
                    "108.157.150.105"
                ],
                "is_active": "Active",
                "last_observed": 1662662460000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "957e25f0-0d6e-3c1c-a822-4899322dab1c",
                "service_name": "HTTP Server at 108.157.150.105:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659828960000,
                "inactive_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment"
                ],
                "ip_address": [
                    "108.157.150.105"
                ],
                "is_active": "Inactive",
                "last_observed": 1662615900000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "d9a87953-b82a-3ca9-8abf-79f4388cdd55",
                "service_name": "HTTP Server at 108.157.150.105:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "WordpressServer",
                    "MissingCacheControlHeader",
                    "SharepointServer",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "MissingContentSecurityPolicyHeader",
                    "ApplicationServerSoftware",
                    "WildcardCertificate",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659835800000,
                "inactive_classifications": [
                    "JQuery",
                    "ApacheWebServer",
                    "NginxWebServer"
                ],
                "ip_address": [
                    "108.157.150.120"
                ],
                "is_active": "Active",
                "last_observed": 1662798180000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "10e8a02e-ef8f-36c9-86ee-b860ac69ad56",
                "service_name": "HTTP Server at 108.157.150.120:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "HttpServer",
                    "ServerSoftware"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659829020000,
                "inactive_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "JQuery",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment"
                ],
                "ip_address": [
                    "108.157.150.120"
                ],
                "is_active": "Active",
                "last_observed": 1662799020000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "b7ef3aea-c24d-32ce-ac77-255c3eff7e79",
                "service_name": "HTTP Server at 108.157.150.120:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1662510660000,
                "inactive_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "MissingCacheControlHeader",
                    "JQuery",
                    "MissingPublicKeyPinsHeader",
                    "MissingXFrameOptionsHeader",
                    "MissingContentSecurityPolicyHeader",
                    "MicrosoftIisWebServer",
                    "ApplicationServerSoftware",
                    "WildcardCertificate",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader"
                ],
                "ip_address": [
                    "108.157.150.43"
                ],
                "is_active": "Inactive",
                "last_observed": 1662615720000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "ed75d3ae-7c34-36ab-b21c-c7f8a6803645",
                "service_name": "HTTP Server at 108.157.150.43:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659828900000,
                "inactive_classifications": [
                    "HttpServer",
                    "ServerSoftware",
                    "DevelopmentEnvironment"
                ],
                "ip_address": [
                    "108.157.150.43"
                ],
                "is_active": "Inactive",
                "last_observed": 1662615720000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "00c74bca-f427-3c3a-b4fa-b284e97b5793",
                "service_name": "HTTP Server at 108.157.150.43:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "HttpServer",
                    "ServerSoftware"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1662510900000,
                "inactive_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "WildcardCertificate",
                    "MissingXContentTypeOptionsHeader",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment"
                ],
                "ip_address": [
                    "108.157.150.46"
                ],
                "is_active": "Active",
                "last_observed": 1662662640000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "78cdba1b-c7db-389b-be88-43ea40a0a860",
                "service_name": "HTTP Server at 108.157.150.46:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1662510900000,
                "inactive_classifications": [
                    "HttpServer",
                    "ServerSoftware",
                    "DevelopmentEnvironment"
                ],
                "ip_address": [
                    "108.157.150.46"
                ],
                "is_active": "Inactive",
                "last_observed": 1662620400000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "3c4d609e-d428-33b5-bfb2-cdff15c7a916",
                "service_name": "HTTP Server at 108.157.150.46:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660774080000,
                "inactive_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "WordpressServer",
                    "MissingCacheControlHeader",
                    "JQuery",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "MicrosoftIisWebServer",
                    "ApplicationServerSoftware",
                    "InternalIpAddressAdvertisement",
                    "WildcardCertificate",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "ExpiredWhenScannedCertificate"
                ],
                "ip_address": [
                    "108.157.214.109"
                ],
                "is_active": "Inactive",
                "last_observed": 1661295780000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "57e1d138-d843-3edd-8faf-b8a6557cc65c",
                "service_name": "HTTP Server at 108.157.214.109:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660773780000,
                "inactive_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "MissingContentSecurityPolicyHeader",
                    "InternalIpAddressAdvertisement",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment"
                ],
                "ip_address": [
                    "108.157.214.109"
                ],
                "is_active": "Inactive",
                "last_observed": 1661315460000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "52fe65cb-c386-336d-93a5-350f0246c2f2",
                "service_name": "HTTP Server at 108.157.214.109:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660773960000,
                "inactive_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "MissingCacheControlHeader",
                    "JQuery",
                    "MissingPublicKeyPinsHeader",
                    "DrupalWebServer",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "WildcardCertificate",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader"
                ],
                "ip_address": [
                    "108.157.214.118"
                ],
                "is_active": "Inactive",
                "last_observed": 1661295240000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "a34f79ae-8778-30e4-b63a-8d681b2267e9",
                "service_name": "HTTP Server at 108.157.214.118:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660772220000,
                "inactive_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "WordpressServer",
                    "MissingCacheControlHeader",
                    "JQuery",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "MissingContentSecurityPolicyHeader",
                    "MicrosoftIisWebServer",
                    "ApplicationServerSoftware",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader"
                ],
                "ip_address": [
                    "108.157.214.118"
                ],
                "is_active": "Inactive",
                "last_observed": 1661308140000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "2bb221bd-9ba1-3ba5-bd8f-8bd67a8e1bb2",
                "service_name": "HTTP Server at 108.157.214.118:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660774440000,
                "inactive_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "WildcardCertificate",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader"
                ],
                "ip_address": [
                    "108.157.214.36"
                ],
                "is_active": "Inactive",
                "last_observed": 1661302440000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "6c73ced9-311b-32d2-8e88-efc68a44a704",
                "service_name": "HTTP Server at 108.157.214.36:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660773960000,
                "inactive_classifications": [
                    "HttpServer",
                    "ServerSoftware",
                    "DevelopmentEnvironment"
                ],
                "ip_address": [
                    "108.157.214.36"
                ],
                "is_active": "Inactive",
                "last_observed": 1661296020000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "39a750a2-d427-3aa3-ac0a-692b834d069b",
                "service_name": "HTTP Server at 108.157.214.36:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660775040000,
                "inactive_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "MissingCacheControlHeader",
                    "WebLogin",
                    "JQuery",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "ApplicationServerSoftware",
                    "WildcardCertificate",
                    "HttpServer",
                    "PHP",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "MicrosoftASPNETCore",
                    "ExpiredWhenScannedCertificate"
                ],
                "ip_address": [
                    "108.157.214.49"
                ],
                "is_active": "Inactive",
                "last_observed": 1661295780000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "45d2e1e9-a1a1-3109-a5db-ea40a32cb27d",
                "service_name": "HTTP Server at 108.157.214.49:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1660782360000,
                "inactive_classifications": [
                    "HttpServer",
                    "ServerSoftware",
                    "DevelopmentEnvironment"
                ],
                "ip_address": [
                    "108.157.214.49"
                ],
                "is_active": "Inactive",
                "last_observed": 1661313120000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "f27a6ac5-8736-3c68-acd1-176da8e720dd",
                "service_name": "HTTP Server at 108.157.214.49:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "NginxWebServer",
                    "WordpressServer",
                    "MissingCacheControlHeader",
                    "WebLogin",
                    "JQuery",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment",
                    "MissingXFrameOptionsHeader",
                    "ApacheWebServer",
                    "MissingContentSecurityPolicyHeader",
                    "ApplicationServerSoftware",
                    "WildcardCertificate",
                    "HttpServer",
                    "PHP",
                    "ServerSoftware",
                    "MissingXContentTypeOptionsHeader",
                    "ExpiredWhenScannedCertificate"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "ColocatedOnIp",
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [
                    "CVE-2018-1312",
                    "CVE-2021-44790",
                    "CVE-2022-23943",
                    "CVE-2021-39275",
                    "CVE-2022-22720",
                    "CVE-2021-26691",
                    "CVE-2022-31813",
                    "CVE-2019-11043",
                    "CVE-2017-8923",
                    "CVE-2019-10082",
                    "CVE-2022-22721",
                    "CVE-2022-28615",
                    "CVE-2020-7059",
                    "CVE-2020-7060",
                    "CVE-2020-7061",
                    "CVE-2021-40438",
                    "CVE-2021-44224",
                    "CVE-2017-15715",
                    "CVE-2019-0211",
                    "CVE-2021-33193",
                    "CVE-2022-30556",
                    "CVE-2017-15710",
                    "CVE-2018-1303",
                    "CVE-2018-1333",
                    "CVE-2020-11993",
                    "CVE-2019-0217",
                    "CVE-2021-26690",
                    "CVE-2022-29404",
                    "CVE-2019-10081",
                    "CVE-2018-17199",
                    "CVE-2021-32785",
                    "CVE-2020-9490",
                    "CVE-2021-34798",
                    "CVE-2022-22719",
                    "CVE-2022-26377",
                    "CVE-2019-11046",
                    "CVE-2019-11044",
                    "CVE-2020-7062",
                    "CVE-2020-7067",
                    "CVE-2020-35452",
                    "CVE-2019-11047",
                    "CVE-2019-11050",
                    "CVE-2020-7069",
                    "CVE-2019-11358",
                    "CVE-2020-11022",
                    "CVE-2021-32792",
                    "CVE-2019-10098",
                    "CVE-2015-9251",
                    "CVE-2019-10092",
                    "CVE-2020-11023",
                    "CVE-2020-1927",
                    "CVE-2021-32786",
                    "CVE-2018-1301",
                    "CVE-2018-11763",
                    "CVE-2018-1302",
                    "CVE-2021-32791",
                    "CVE-2019-11045",
                    "CVE-2020-13938",
                    "CVE-2020-7064",
                    "CVE-2022-28614",
                    "CVE-2019-17567",
                    "CVE-2020-1934",
                    "CVE-2019-0196",
                    "CVE-2018-1283",
                    "CVE-2019-0220",
                    "CVE-2018-17189",
                    "CVE-2022-28330",
                    "CVE-2019-11048",
                    "CVE-2020-7070",
                    "CVE-2020-7063",
                    "CVE-2020-7066",
                    "CVE-2020-7068"
                ],
                "externally_inferred_vulnerability_score": 9.8,
                "first_observed": 1662537960000,
                "inactive_classifications": [],
                "ip_address": [
                    "108.159.227.23"
                ],
                "is_active": "Active",
                "last_observed": 1663328040000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "33a72996-511f-34d4-88ea-e6ab52690f68",
                "service_name": "HTTP Server at 108.159.227.23:443",
                "service_type": "HttpServer"
            }
        ]
    }
}
```

#### Human Readable Output

>### External Services
>|active_classifications|business_units|discovery_type|externally_detected_providers|externally_inferred_cves|externally_inferred_vulnerability_score|first_observed|inactive_classifications|ip_address|is_active|last_observed|port|protocol|service_id|service_name|service_type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| DnsServer | jwilkes - Toys R US | ColocatedOnIp | Other |  |  | 1661308020000 |  | 104.207.249.74 | Active | 1663284960000 | 53 | UDP | 8b8f9d0a-4acd-3d88-9042-c7d17c2b44e9 | DNS Server at 104.207.249.74:53 | DnsServer |
>| DnsServer,<br/>ISCBIND9 | jwilkes test - VanDelay Industries | ColocatedOnIp | Other | CVE-2021-25216,<br/>CVE-2020-8616,<br/>CVE-2020-8625,<br/>CVE-2015-5722,<br/>CVE-2015-5477,<br/>CVE-2017-3141,<br/>CVE-2016-9131,<br/>CVE-2016-9444,<br/>CVE-2016-8864,<br/>CVE-2016-9147,<br/>CVE-2017-3137,<br/>CVE-2018-5743,<br/>CVE-2017-3145,<br/>CVE-2021-25215,<br/>CVE-2016-2776,<br/>CVE-2018-5740,<br/>CVE-2015-5986,<br/>CVE-2016-6170,<br/>CVE-2021-25214,<br/>CVE-2018-5741,<br/>CVE-2020-8622,<br/>CVE-2016-9778,<br/>CVE-2016-2775,<br/>CVE-2017-3135,<br/>CVE-2017-3136,<br/>CVE-2017-3143,<br/>CVE-2020-8617,<br/>CVE-2017-3138,<br/>CVE-2021-25219,<br/>CVE-2019-6465,<br/>CVE-2018-5745,<br/>CVE-2017-3142 | 9.8 | 1661298300000 |  | 112.95.160.91 | Active | 1663197480000 | 53 | UDP | 7a4ce6ec-9ce3-3002-ac66-862854b2d7f7 | DNS Server at 112.95.160.91:53 | DnsServer |
>| DnsServer,<br/>ISCBIND9 | jwilkes test - VanDelay Industries | ColocatedOnIp | Other | CVE-2021-25216,<br/>CVE-2020-8616,<br/>CVE-2020-8625,<br/>CVE-2015-5722,<br/>CVE-2015-5477,<br/>CVE-2017-3141,<br/>CVE-2016-9131,<br/>CVE-2016-9444,<br/>CVE-2016-8864,<br/>CVE-2016-9147,<br/>CVE-2017-3137,<br/>CVE-2018-5743,<br/>CVE-2017-3145,<br/>CVE-2021-25215,<br/>CVE-2016-2776,<br/>CVE-2018-5740,<br/>CVE-2015-5986,<br/>CVE-2016-6170,<br/>CVE-2021-25214,<br/>CVE-2018-5741,<br/>CVE-2020-8622,<br/>CVE-2016-9778,<br/>CVE-2016-2775,<br/>CVE-2017-3135,<br/>CVE-2017-3136,<br/>CVE-2017-3143,<br/>CVE-2020-8617,<br/>CVE-2017-3138,<br/>CVE-2021-25219,<br/>CVE-2019-6465,<br/>CVE-2018-5745,<br/>CVE-2017-3142 | 9.8 | 1660317960000 |  | 120.202.26.15 | Active | 1663326660000 | 53 | UDP | 25c6abc2-5c1b-35e4-8952-4054689c47ce | DNS Server at 120.202.26.15:53 | DnsServer |
>| DnsServer,<br/>ISCBIND9 | jwilkes test - VanDelay Industries | ColocatedOnIp | Other | CVE-2021-25216,<br/>CVE-2020-8616,<br/>CVE-2020-8625,<br/>CVE-2015-5722,<br/>CVE-2017-3141,<br/>CVE-2015-5477,<br/>CVE-2016-9147,<br/>CVE-2016-8864,<br/>CVE-2016-9444,<br/>CVE-2017-3137,<br/>CVE-2016-9131,<br/>CVE-2016-2776,<br/>CVE-2018-5740,<br/>CVE-2021-25215,<br/>CVE-2017-3145,<br/>CVE-2018-5743,<br/>CVE-2015-5986,<br/>CVE-2016-6170,<br/>CVE-2021-25214,<br/>CVE-2020-8622,<br/>CVE-2018-5741,<br/>CVE-2016-2775,<br/>CVE-2017-3135,<br/>CVE-2016-9778,<br/>CVE-2020-8617,<br/>CVE-2017-3136,<br/>CVE-2017-3143,<br/>CVE-2017-3138,<br/>CVE-2021-25219,<br/>CVE-2019-6465,<br/>CVE-2018-5745,<br/>CVE-2017-3142 | 9.8 | 1659492240000 |  | 120.236.19.126 | Active | 1663267080000 | 53 | UDP | cab849c5-f317-397e-91c0-59fb3372dbd3 | DNS Server at 120.236.19.126:53 | DnsServer |
>| DnsServer,<br/>Dnsmasq | jwilkes - Toys R US | ColocatedOnIp | Other | CVE-2017-14492,<br/>CVE-2017-14491,<br/>CVE-2017-14493,<br/>CVE-2020-25682,<br/>CVE-2020-25681,<br/>CVE-2017-15107,<br/>CVE-2017-14496,<br/>CVE-2017-13704,<br/>CVE-2017-14495,<br/>CVE-2020-25687,<br/>CVE-2020-25683,<br/>CVE-2017-14494,<br/>CVE-2021-3448,<br/>CVE-2019-14834,<br/>CVE-2020-25686,<br/>CVE-2020-25684,<br/>CVE-2020-25685 | 9.8 | 1661256660000 |  | 192.190.221.160 | Active | 1663263360000 | 53 | UDP | 96ce454d-f617-3418-9e79-c28e92ec573a | DNS Server at 192.190.221.160:53 | DnsServer |
>| DnsServer | jwilkes test - VanDelay Industries | DirectlyDiscovered | On Prem |  |  | 1659465360000 |  | 192.225.57.3 | Active | 1663320480000 | 53 | UDP | 47ac5a8d-b745-3fcd-bae0-7c00e4dbee4d | DNS Server at 192.225.57.3:53 | DnsServer |
>| DnsServer | jwilkes test - VanDelay Industries | DirectlyDiscovered | On Prem |  |  | 1659548100000 |  | 192.225.57.4 | Active | 1663296660000 | 53 | UDP | 8a55b6d7-04f3-373a-9d21-37ede8d3cf7a | DNS Server at 192.225.57.4:53 | DnsServer |
>| DnsServer | jwilkes test - VanDelay Industries | DirectlyDiscovered | On Prem |  |  | 1659517200000 |  | 194.186.243.106 | Active | 1663126260000 | 53 | UDP | 266ef110-23d8-319f-ab58-ceb4f48c1930 | DNS Server at 194.186.243.106:53 | DnsServer |
>| DnsServer | jwilkes test - VanDelay Industries | DirectlyDiscovered | On Prem |  |  | 1659415680000 |  | 195.239.144.186 | Active | 1663276980000 | 53 | UDP | aa00c51f-6a97-3600-aa43-69e1581e47f3 | DNS Server at 195.239.144.186:53 | DnsServer |
>| DnsServer,<br/>ISCBIND9 | jwilkes test - VanDelay Industries | ColocatedOnIp | Other | CVE-2021-25216,<br/>CVE-2020-8616,<br/>CVE-2020-8625,<br/>CVE-2017-3141,<br/>CVE-2015-5477,<br/>CVE-2015-5722,<br/>CVE-2016-9444,<br/>CVE-2017-3137,<br/>CVE-2016-8864,<br/>CVE-2016-9147,<br/>CVE-2016-9131,<br/>CVE-2021-25215,<br/>CVE-2017-3145,<br/>CVE-2018-5740,<br/>CVE-2016-2776,<br/>CVE-2018-5743,<br/>CVE-2015-5986,<br/>CVE-2016-6170,<br/>CVE-2021-25214,<br/>CVE-2020-8622,<br/>CVE-2018-5741,<br/>CVE-2017-3135,<br/>CVE-2016-9778,<br/>CVE-2016-2775,<br/>CVE-2020-8617,<br/>CVE-2017-3136,<br/>CVE-2017-3143,<br/>CVE-2017-3138,<br/>CVE-2019-6465,<br/>CVE-2021-25219,<br/>CVE-2018-5745,<br/>CVE-2017-3142 | 9.8 | 1659494040000 |  | 202.96.162.203 | Active | 1663279860000 | 53 | UDP | 3011f810-8aec-3c49-a571-34d6d904ee03 | DNS Server at 202.96.162.203:53 | DnsServer |
>| DnsServer | jwilkes - Toys R US | ColocatedOnIp | Other |  |  | 1660272780000 |  | 208.80.127.4 | Active | 1663296480000 | 53 | UDP | fe3c5a69-bc0e-382c-9993-0b4e5ef0e1de | DNS Server at 208.80.127.4:53 | DnsServer |
>| DnsServer | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Other |  |  | 1659505440000 |  | 210.166.216.147 | Active | 1663293060000 | 53 | UDP | 40968292-0130-3fc9-b3e5-d8e431715252 | DNS Server at 210.166.216.147:53 | DnsServer |
>| DnsServer,<br/>ISCBIND9 | jwilkes test - VanDelay Industries | ColocatedOnIp | Other | CVE-2021-25216,<br/>CVE-2020-8616,<br/>CVE-2020-8625,<br/>CVE-2015-5722,<br/>CVE-2015-5477,<br/>CVE-2017-3141,<br/>CVE-2016-9131,<br/>CVE-2016-9444,<br/>CVE-2016-8864,<br/>CVE-2016-9147,<br/>CVE-2017-3137,<br/>CVE-2018-5743,<br/>CVE-2017-3145,<br/>CVE-2021-25215,<br/>CVE-2016-2776,<br/>CVE-2018-5740,<br/>CVE-2015-5986,<br/>CVE-2016-6170,<br/>CVE-2021-25214,<br/>CVE-2018-5741,<br/>CVE-2020-8622,<br/>CVE-2016-9778,<br/>CVE-2016-2775,<br/>CVE-2017-3135,<br/>CVE-2017-3136,<br/>CVE-2017-3143,<br/>CVE-2020-8617,<br/>CVE-2017-3138,<br/>CVE-2021-25219,<br/>CVE-2019-6465,<br/>CVE-2018-5745,<br/>CVE-2017-3142 | 9.8 | 1659537660000 |  | 61.183.84.239 | Active | 1662793200000 | 53 | UDP | 2d510619-e24e-3a7b-b3a2-03cb425042c4 | DNS Server at 61.183.84.239:53 | DnsServer |
>| UnencryptedFtpServer,<br/>FtpServer | jwilkes - Toys R US | DirectlyDiscovered | On Prem |  |  | 1660147500000 |  | 12.5.116.147 | Active | 1663305060000 | 21 | TCP | 05dd80fc-e04c-368b-b383-d2411b5c44f5 | FTP Server at 12.5.116.147:21 | FtpServer |
>| UnencryptedFtpServer,<br/>FtpServer | jwilkes test - VanDelay Industries | DirectlyDiscovered | On Prem |  |  | 1659452640000 |  | 166.76.254.147 | Active | 1663254840000 | 21 | TCP | 533fc779-2d65-3f21-9489-1e179dbfe223 | FTP Server at 166.76.254.147:21 | FtpServer |
>| WildcardCertificate,<br/>FtpsServer,<br/>FtpServer | jwilkes - Toys R US | ColocatedOnIp | Other |  |  | 1660230840000 |  | 192.190.221.160 | Active | 1663256460000 | 21 | TCP | d14a8823-c3f2-387f-aded-71462960323e | FTP Server at 192.190.221.160:21 | FtpServer |
>| FtpsServer,<br/>FtpServer | jwilkes - Toys R US | ColocatedOnIp | Other |  |  | 1663007160000 |  | 192.190.221.160 | Active | 1663007160000 | 990 | TCP | 80a64a96-4057-3b54-91a2-7d6f499aeb17 | FTP Server at 192.190.221.160:990 | FtpServer |
>| UnencryptedFtpServer,<br/>FtpServer | jwilkes test - VanDelay Industries | DirectlyDiscovered | On Prem |  |  | 1659453600000 |  | 195.222.186.100 | Active | 1663263480000 | 21 | TCP | 24efe1e6-5198-3788-9be2-3bf0dc52860a | FTP Server at 195.222.186.100:21 | FtpServer |
>| NetworkingAndSecurityInfrastructure,<br/>FtpServer,<br/>MikroTikRouter,<br/>UnencryptedFtpServer | jwilkes test - VanDelay Industries | DirectlyDiscovered | On Prem |  |  | 1659455220000 |  | 195.68.131.22 | Active | 1663262520000 | 21 | TCP | aa9a697e-337a-3007-aaf3-f037c0838dbc | FTP Server at 195.68.131.22:21 | FtpServer |
>| UnencryptedFtpServer,<br/>FtpServer | jwilkes test - VanDelay Industries | DirectlyDiscovered | On Prem |  |  | 1659476820000 |  | 195.68.153.227 | Active | 1663099620000 | 21 | TCP | 6ab71c4b-7ff5-3d5b-a04b-266c82f0a378 | FTP Server at 195.68.153.227:21 | FtpServer |
>| UnencryptedFtpServer,<br/>FtpServer | jwilkes test - VanDelay Industries | DirectlyDiscovered | On Prem |  |  | 1659455280000 |  | 213.221.7.34 | Active | 1663255860000 | 21 | TCP | a3e101d0-ed64-3b5d-a267-1fea527bcbf6 | FTP Server at 213.221.7.34:21 | FtpServer |
>| UnencryptedFtpServer,<br/>FtpServer | jwilkes - Toys R US | ColocatedOnIp | Other |  |  | 1660254360000 |  | 218.17.210.177 | Active | 1663263720000 | 21 | TCP | 677c7916-f1df-38d1-bad8-c42511c424ac | FTP Server at 218.17.210.177:21 | FtpServer |
>| ShortKeyCertificate,<br/>InsecureSignatureCertificate,<br/>SelfSignedCertificate,<br/>LongExpirationCertificate,<br/>FtpServer,<br/>FtpsServer,<br/>ExpiredWhenScannedCertificate | jwilkes - Toys R US | ColocatedOnIp | Other |  |  | 1660273920000 |  | 218.17.210.177 | Active | 1663176360000 | 990 | TCP | 1bcc954e-cf76-3064-9ffe-d7d5e771df4d | FTP Server at 218.17.210.177:990 | FtpServer |
>| LongExpirationCertificate,<br/>FtpsServer,<br/>FtpServer,<br/>SelfSignedCertificate | jwilkes test - VanDelay Industries | ColocatedOnIp | Other |  |  | 1660065660000 |  | 23.234.27.33 | Active | 1663263480000 | 21 | TCP | 1deff500-acbc-34e8-8062-b05574625274 | FTP Server at 23.234.27.33:21 | FtpServer |
>| ShortKeyCertificate,<br/>InsecureSignatureCertificate,<br/>FtpsServer,<br/>FtpServer,<br/>SelfSignedCertificate,<br/>ExpiredWhenScannedCertificate | jwilkes test - VanDelay Industries | DirectlyDiscovered | On Prem |  |  | 1659518880000 |  | 63.241.126.248 | Active | 1663060020000 | 990 | TCP | 34402fb9-ab26-338f-ad86-51431df801e2 | FTP Server at 63.241.126.248:990 | FtpServer |
>| FtpsServer,<br/>FtpServer | jwilkes test - VanDelay Industries | DirectlyDiscovered | On Prem |  |  | 1659454800000 |  | 69.170.10.220 | Active | 1663168800000 | 21 | TCP | 0e61d9f4-d2df-3648-b62a-d6fd5fdf94e8 | FTP Server at 69.170.10.220:21 | FtpServer |
>| FtpServer,<br/>FtpsServer | jwilkes test - VanDelay Industries | DirectlyDiscovered | On Prem |  |  | 1660146840000 |  | 69.170.10.220 | Active | 1663033140000 | 990 | TCP | d7ae9f2b-6386-31b4-8002-d683e25b9995 | FTP Server at 69.170.10.220:990 | FtpServer |
>| InternalIpAddressAdvertisement,<br/>UnencryptedFtpServer,<br/>FtpServer | jwilkes test - VanDelay Industries | DirectlyDiscovered | On Prem |  |  | 1659462960000 |  | 87.249.1.35 | Active | 1663257480000 | 21 | TCP | 05f07f29-25e5-33e9-8259-01fb3136980c | FTP Server at 87.249.1.35:21 | FtpServer |
>| HttpServer,<br/>WildcardCertificate,<br/>ServerSoftware | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1662755220000 |  | 100.25.178.60 | Active | 1663303620000 | 443 | TCP | 0c9f1a24-9726-3def-a27d-a30e697d49bc | HTTP Server at 100.25.178.60:443 | HttpServer |
>| HttpServer,<br/>ServerSoftware | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1659519180000 |  | 100.25.178.60 | Active | 1663285980000 | 80 | TCP | c1c0cd6f-f5e8-35d2-b847-6780702bca92 | HTTP Server at 100.25.178.60:80 | HttpServer |
>| ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>WildcardCertificate,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingCacheControlHeader,<br/>WebLogin,<br/>MissingPublicKeyPinsHeader,<br/>NodeJs | jwilkes - Toys R US | ColocatedOnIp | Other |  |  | 1661243340000 |  | 104.207.249.74 | Active | 1663088100000 | 2443 | TCP | f66a8680-d3de-3b53-bd50-e942002b033c | HTTP Server at 104.207.249.74:2443 | HttpServer |
>| HttpServer,<br/>ApacheWebServer,<br/>ServerSoftware,<br/>WildcardCertificate | jwilkes - Toys R US | ColocatedOnIp | Other |  |  | 1660277280000 | DevelopmentEnvironment | 104.207.249.74 | Active | 1663323660000 | 443 | TCP | 645a8f31-24a4-3fca-bdd0-2e6c40b3fd1b | HTTP Server at 104.207.249.74:443 | HttpServer |
>| HttpServer,<br/>ApacheWebServer,<br/>ServerSoftware | jwilkes - Toys R US | ColocatedOnIp | Other |  |  | 1660194720000 |  | 104.207.249.74 | Active | 1663330560000 | 80 | TCP | 915c4358-3e7e-3b37-a77d-21fc6cc51cbb | HTTP Server at 104.207.249.74:80 | HttpServer |
>|  | jwilkes test - VanDelay Industries | DirectlyDiscovered | Amazon Web Services |  |  | 1659408240000 | HttpServer,<br/>WildcardCertificate,<br/>ExpiredWhenScannedCertificate | 107.23.198.175 | Inactive | 1661546160000 | 443 | TCP | 696f4245-22ea-3203-99db-406a8b7d08cb | HTTP Server at 107.23.198.175:443 | HttpServer |
>| MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>AdobeExperienceManager,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>OpenSSL,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>ApplicationServerSoftware,<br/>WildcardCertificate,<br/>HttpServer,<br/>PHP,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>PanOsDevice,<br/>ExpiredWhenScannedCertificate | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services | CVE-2017-7679,<br/>CVE-2016-0705,<br/>CVE-2022-31813,<br/>CVE-2022-22720,<br/>CVE-2018-1312,<br/>CVE-2016-2108,<br/>CVE-2016-0799,<br/>CVE-2016-2177,<br/>CVE-2017-3169,<br/>CVE-2021-39275,<br/>CVE-2016-2182,<br/>CVE-2017-3167,<br/>CVE-2016-2842,<br/>CVE-2021-26691,<br/>CVE-2017-8923,<br/>CVE-2016-6303,<br/>CVE-2022-23943,<br/>CVE-2021-44790,<br/>CVE-2022-2068,<br/>CVE-2022-1292,<br/>CVE-2022-28615,<br/>CVE-2022-22721,<br/>CVE-2017-9788,<br/>CVE-2020-7043,<br/>CVE-2021-40438,<br/>CVE-2021-44224,<br/>CVE-2016-2176,<br/>CVE-2017-15715,<br/>CVE-2016-5387,<br/>CVE-2022-26377,<br/>CVE-2022-30556,<br/>CVE-2016-0736,<br/>CVE-2016-2180,<br/>CVE-2022-22719,<br/>CVE-2015-1789,<br/>CVE-2016-0797,<br/>CVE-2020-13950,<br/>CVE-2018-17199,<br/>CVE-2021-36160,<br/>CVE-2016-2106,<br/>CVE-2016-7052,<br/>CVE-2016-8743,<br/>CVE-2017-3731,<br/>CVE-2021-33193,<br/>CVE-2015-3194,<br/>CVE-2021-26690,<br/>CVE-2019-0217,<br/>CVE-2016-6304,<br/>CVE-2022-29404,<br/>CVE-2017-15710,<br/>CVE-2016-2179,<br/>CVE-2018-1303,<br/>CVE-2015-3193,<br/>CVE-2017-9798,<br/>CVE-2021-34798,<br/>CVE-2016-0798,<br/>CVE-2016-2109,<br/>CVE-2016-2181,<br/>CVE-2016-6302,<br/>CVE-2016-2105,<br/>CVE-2021-32785,<br/>CVE-2016-2183,<br/>CVE-2016-2161,<br/>CVE-2022-0778,<br/>CVE-2021-4044,<br/>CVE-2016-8610,<br/>CVE-2021-23840,<br/>CVE-2018-0732,<br/>CVE-2021-3712,<br/>CVE-2020-35452,<br/>CVE-2015-1791,<br/>CVE-2015-0209,<br/>CVE-2014-0226,<br/>CVE-2015-1793,<br/>CVE-2018-0739,<br/>CVE-2017-3736,<br/>CVE-2016-4975,<br/>CVE-2020-11023,<br/>CVE-2021-32792,<br/>CVE-2019-11358,<br/>CVE-2020-11022,<br/>CVE-2019-10092,<br/>CVE-2021-32786,<br/>CVE-2020-1927,<br/>CVE-2019-10098,<br/>CVE-2016-2107,<br/>CVE-2017-3738,<br/>CVE-2018-1301,<br/>CVE-2021-32791,<br/>CVE-2016-0704,<br/>CVE-2016-0703,<br/>CVE-2017-3737,<br/>CVE-2016-6306,<br/>CVE-2016-0800,<br/>CVE-2017-3732,<br/>CVE-2018-1302,<br/>CVE-2015-3197,<br/>CVE-2018-0737,<br/>CVE-2021-4160,<br/>CVE-2019-1559,<br/>CVE-2020-1971,<br/>CVE-2021-23841,<br/>CVE-2016-7055,<br/>CVE-2018-0734,<br/>CVE-2009-3555,<br/>CVE-2016-2178,<br/>CVE-2020-13938,<br/>CVE-2018-1283,<br/>CVE-2020-11985,<br/>CVE-2017-3735,<br/>CVE-2022-28614,<br/>CVE-2019-17567,<br/>CVE-2022-28330,<br/>CVE-2019-0220,<br/>CVE-2020-1934,<br/>CVE-2021-30641,<br/>CVE-2020-7041,<br/>CVE-2015-3195,<br/>CVE-2020-7042,<br/>CVE-2019-1551,<br/>CVE-2016-0702,<br/>CVE-2015-3183,<br/>CVE-2015-0207,<br/>CVE-2015-0288,<br/>CVE-2015-0290,<br/>CVE-2014-0231,<br/>CVE-2015-1792,<br/>CVE-2015-0286,<br/>CVE-2014-0098,<br/>CVE-2014-3581,<br/>CVE-2015-0228,<br/>CVE-2015-0291,<br/>CVE-2015-1794,<br/>CVE-2015-0289,<br/>CVE-2015-3184,<br/>CVE-2014-3523,<br/>CVE-2015-0293,<br/>CVE-2013-5704,<br/>CVE-2013-6438,<br/>CVE-2015-1790,<br/>CVE-2015-0287,<br/>CVE-2019-1547,<br/>CVE-2018-5407,<br/>CVE-2014-0118,<br/>CVE-2016-8612,<br/>CVE-2014-0117,<br/>CVE-2015-3185,<br/>CVE-2014-8109,<br/>CVE-2015-0208,<br/>CVE-2015-0285,<br/>CVE-2015-1788,<br/>CVE-2016-0701,<br/>CVE-2020-1968,<br/>CVE-2015-4000,<br/>CVE-2021-23839,<br/>CVE-2019-1563,<br/>CVE-2019-1552,<br/>CVE-2015-1787 | 9.8 | 1662751980000 |  | 108.138.106.106 | Active | 1663323720000 | 443 | TCP | ae57c07d-9d70-3a85-9867-b3ff7b8c3e2f | HTTP Server at 108.138.106.106:443 | HttpServer |
>| MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1662753360000 |  | 108.138.106.106 | Active | 1663323600000 | 80 | TCP | 672061b6-3995-3ff9-a3c1-649d7edd80f6 | HTTP Server at 108.138.106.106:80 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1660951980000 | MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>MissingContentSecurityPolicyHeader,<br/>WildcardCertificate,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader | 108.138.106.127 | Inactive | 1661121840000 | 443 | TCP | 142a21c4-2528-3f65-9d90-374c848b19be | HTTP Server at 108.138.106.127:443 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1660956480000 | MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment | 108.138.106.127 | Inactive | 1661128500000 | 80 | TCP | e9261cb4-dec4-3bed-b733-54d700c2cfd6 | HTTP Server at 108.138.106.127:80 | HttpServer |
>| MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>ApplicationServerSoftware,<br/>WildcardCertificate,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services | CVE-2020-11023,<br/>CVE-2015-9251,<br/>CVE-2020-11022,<br/>CVE-2019-11358 | 6.1 | 1662752940000 |  | 108.138.106.128 | Active | 1663323300000 | 443 | TCP | 4a5e6c06-39e5-3b84-9717-e7f771bc3be2 | HTTP Server at 108.138.106.128:443 | HttpServer |
>| MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1662752640000 |  | 108.138.106.128 | Active | 1663330980000 | 80 | TCP | d8a9ee32-d433-31ac-8980-de280ca799b1 | HTTP Server at 108.138.106.128:80 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1660962360000 | MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader,<br/>NodeJs,<br/>MissingXFrameOptionsHeader,<br/>MissingContentSecurityPolicyHeader,<br/>ApplicationServerSoftware,<br/>WildcardCertificate,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader | 108.138.106.26 | Inactive | 1661122080000 | 443 | TCP | 36185c0b-5c06-30af-9461-44dc381189e7 | HTTP Server at 108.138.106.26:443 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1660943760000 | MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader | 108.138.106.26 | Inactive | 1661120940000 | 80 | TCP | 2ad6e114-6a8a-3a1b-8da0-db6c74d7a2ba | HTTP Server at 108.138.106.26:80 | HttpServer |
>| MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>MicrosoftIisWebServer,<br/>ApplicationServerSoftware,<br/>WildcardCertificate,<br/>LongExpirationCertificate,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>PanOsDevice | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services | CVE-2020-11022,<br/>CVE-2020-11023 | 6.1 | 1662753480000 |  | 108.138.106.35 | Active | 1663329720000 | 443 | TCP | 6062f780-ab3e-321d-a814-584da9eb99f8 | HTTP Server at 108.138.106.35:443 | HttpServer |
>| MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1662753900000 |  | 108.138.106.35 | Active | 1663331580000 | 80 | TCP | 67d429ed-0c85-3d17-8c3f-ec530061968c | HTTP Server at 108.138.106.35:80 | HttpServer |
>| MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>MissingCacheControlHeader,<br/>WebLogin,<br/>JQuery,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>ApplicationServerSoftware,<br/>WildcardCertificate,<br/>HttpServer,<br/>PHP,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>ExpiredWhenScannedCertificate | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services | CVE-2021-39275,<br/>CVE-2022-31813,<br/>CVE-2022-23943,<br/>CVE-2021-44790,<br/>CVE-2017-8923,<br/>CVE-2022-22720,<br/>CVE-2021-26691,<br/>CVE-2022-28615,<br/>CVE-2022-22721,<br/>CVE-2021-40438,<br/>CVE-2021-44224,<br/>CVE-2021-26690,<br/>CVE-2020-13950,<br/>CVE-2021-36160,<br/>CVE-2021-34798,<br/>CVE-2022-22719,<br/>CVE-2021-32785,<br/>CVE-2021-33193,<br/>CVE-2022-26377,<br/>CVE-2022-30556,<br/>CVE-2022-29404,<br/>CVE-2020-35452,<br/>CVE-2021-21703,<br/>CVE-2021-21706,<br/>CVE-2019-11358,<br/>CVE-2021-32792,<br/>CVE-2020-11022,<br/>CVE-2020-11023,<br/>CVE-2021-32786,<br/>CVE-2021-32791,<br/>CVE-2020-13938,<br/>CVE-2022-28330,<br/>CVE-2022-28614,<br/>CVE-2019-17567,<br/>CVE-2021-30641,<br/>CVE-2021-21707 | 9.8 | 1662753480000 |  | 108.138.106.70 | Active | 1663328820000 | 443 | TCP | 9784500c-88fe-3b66-93e1-ecd33c3129d2 | HTTP Server at 108.138.106.70:443 | HttpServer |
>| MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services | CVE-2022-22720,<br/>CVE-2022-23943,<br/>CVE-2021-39275,<br/>CVE-2017-3169,<br/>CVE-2017-7679,<br/>CVE-2017-3167,<br/>CVE-2021-26691,<br/>CVE-2021-44790,<br/>CVE-2022-31813,<br/>CVE-2018-1312,<br/>CVE-2022-22721,<br/>CVE-2017-9788,<br/>CVE-2022-28615,<br/>CVE-2021-40438,<br/>CVE-2021-44224,<br/>CVE-2017-15715,<br/>CVE-2016-5387,<br/>CVE-2022-26377,<br/>CVE-2018-1303,<br/>CVE-2022-30556,<br/>CVE-2016-0736,<br/>CVE-2017-15710,<br/>CVE-2022-29404,<br/>CVE-2021-26690,<br/>CVE-2019-0217,<br/>CVE-2016-2161,<br/>CVE-2021-32785,<br/>CVE-2021-34798,<br/>CVE-2016-8743,<br/>CVE-2018-17199,<br/>CVE-2022-22719,<br/>CVE-2017-9798,<br/>CVE-2020-35452,<br/>CVE-2021-32792,<br/>CVE-2021-32786,<br/>CVE-2019-10098,<br/>CVE-2016-4975,<br/>CVE-2019-10092,<br/>CVE-2020-1927,<br/>CVE-2018-1301,<br/>CVE-2021-32791,<br/>CVE-2018-1302,<br/>CVE-2020-13938,<br/>CVE-2022-28614,<br/>CVE-2020-11985,<br/>CVE-2020-1934,<br/>CVE-2019-17567,<br/>CVE-2018-1283,<br/>CVE-2019-0220,<br/>CVE-2022-28330,<br/>CVE-2015-3184,<br/>CVE-2016-8612 | 9.8 | 1662753840000 |  | 108.138.106.70 | Active | 1663325280000 | 80 | TCP | 20cd9af5-bdc3-3355-983b-1a8f4514b70a | HTTP Server at 108.138.106.70:80 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1660955880000 | MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>WildcardCertificate,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment | 108.138.106.73 | Inactive | 1661122020000 | 443 | TCP | db1504b5-9e70-33ef-b8e7-0416672f8925 | HTTP Server at 108.138.106.73:443 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1660975260000 | HttpServer,<br/>ServerSoftware,<br/>DevelopmentEnvironment | 108.138.106.73 | Inactive | 1661116740000 | 80 | TCP | 42ba41a4-f4bc-314d-85a6-93e56b58df07 | HTTP Server at 108.138.106.73:80 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1660948200000 | MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>MicrosoftIisWebServer,<br/>WildcardCertificate,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader | 108.138.106.79 | Inactive | 1661122500000 | 443 | TCP | 62a1d4ab-a8ce-3bf7-a445-7cc637850d7c | HTTP Server at 108.138.106.79:443 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1660943040000 | MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader | 108.138.106.79 | Inactive | 1661122680000 | 80 | TCP | f7e72480-7690-3f15-8e71-d2906364b182 | HTTP Server at 108.138.106.79:80 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1661272140000 | MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>ApplicationServerSoftware,<br/>WildcardCertificate,<br/>HttpServer,<br/>PHP,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader | 108.138.159.8 | Inactive | 1661474100000 | 443 | TCP | 1258e0c6-19ab-3aee-b2fd-4c7766de28ee | HTTP Server at 108.138.159.8:443 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1661264040000 | MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>MissingContentSecurityPolicyHeader,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader,<br/>NodeJs | 108.138.159.8 | Inactive | 1661473260000 | 80 | TCP | 7fb86d36-14a3-332e-bb4d-5044e0a80474 | HTTP Server at 108.138.159.8:80 | HttpServer |
>| MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>PythonApplication,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>WildcardCertificate,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services | CVE-2022-23943,<br/>CVE-2021-44790,<br/>CVE-2021-26691,<br/>CVE-2017-7679,<br/>CVE-2022-22720,<br/>CVE-2022-31813,<br/>CVE-2018-1312,<br/>CVE-2017-3167,<br/>CVE-2015-20107,<br/>CVE-2021-39275,<br/>CVE-2019-9636,<br/>CVE-2020-27619,<br/>CVE-2021-3177,<br/>CVE-2016-0718,<br/>CVE-2019-10160,<br/>CVE-2016-9063,<br/>CVE-2022-28615,<br/>CVE-2017-9788,<br/>CVE-2022-22721,<br/>CVE-2019-9948,<br/>CVE-2021-40438,<br/>CVE-2020-29396,<br/>CVE-2017-17522,<br/>CVE-2021-44224,<br/>CVE-2016-5387,<br/>CVE-2017-15715,<br/>CVE-2016-4472,<br/>CVE-2020-15523,<br/>CVE-2018-1303,<br/>CVE-2021-26690,<br/>CVE-2017-9798,<br/>CVE-2018-20406,<br/>CVE-2018-17199,<br/>CVE-2022-22719,<br/>CVE-2022-29404,<br/>CVE-2021-32785,<br/>CVE-2016-2161,<br/>CVE-2016-0736,<br/>CVE-2017-15710,<br/>CVE-2022-30556,<br/>CVE-2016-8743,<br/>CVE-2022-26377,<br/>CVE-2019-9674,<br/>CVE-2021-34798,<br/>CVE-2019-0217,<br/>CVE-2022-0391,<br/>CVE-2018-14647,<br/>CVE-2019-20907,<br/>CVE-2019-16056,<br/>CVE-2019-15903,<br/>CVE-2018-1060,<br/>CVE-2019-5010,<br/>CVE-2019-17514,<br/>CVE-2017-9233,<br/>CVE-2018-1061,<br/>CVE-2021-3737,<br/>CVE-2021-28861,<br/>CVE-2020-35452,<br/>CVE-2020-26116,<br/>CVE-2022-26488,<br/>CVE-2014-0226,<br/>CVE-2013-0340,<br/>CVE-2018-1000117,<br/>CVE-2017-18207,<br/>CVE-2020-8492,<br/>CVE-2021-3733,<br/>CVE-2021-32786,<br/>CVE-2019-10092,<br/>CVE-2020-1927,<br/>CVE-2019-10098,<br/>CVE-2016-4975,<br/>CVE-2021-32792,<br/>CVE-2019-16935,<br/>CVE-2019-9740,<br/>CVE-2019-9947,<br/>CVE-2019-18348,<br/>CVE-2021-28359,<br/>CVE-2018-1302,<br/>CVE-2021-32791,<br/>CVE-2018-1301,<br/>CVE-2021-23336,<br/>CVE-2020-14422,<br/>CVE-2021-3426,<br/>CVE-2020-13938,<br/>CVE-2020-8315,<br/>CVE-2022-28614,<br/>CVE-2019-0220,<br/>CVE-2022-28330,<br/>CVE-2020-1934,<br/>CVE-2020-11985,<br/>CVE-2018-1283,<br/>CVE-2019-17567,<br/>CVE-2018-20852,<br/>CVE-2021-4189,<br/>CVE-2014-0098,<br/>CVE-2014-3523,<br/>CVE-2015-0228,<br/>CVE-2013-6438,<br/>CVE-2015-3183,<br/>CVE-2013-5704,<br/>CVE-2015-3184,<br/>CVE-2014-3581,<br/>CVE-2014-0231,<br/>CVE-2015-3185,<br/>CVE-2014-0117,<br/>CVE-2014-8109,<br/>CVE-2014-0118,<br/>CVE-2016-8612 | 9.8 | 1659493980000 | MicrosoftIisWebServer,<br/>ApplicationServerSoftware,<br/>NginxWebServer,<br/>PHP,<br/>WordpressServer,<br/>JQuery,<br/>DomainControlValidatedCertificate,<br/>NodeJs | 108.138.167.111 | Active | 1663330680000 | 443 | TCP | 37445ff2-12eb-3a9d-8361-bfea8fa236c3 | HTTP Server at 108.138.167.111:443 | HttpServer |
>| MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1659515940000 | JQuery,<br/>NginxWebServer | 108.138.167.111 | Active | 1663331460000 | 80 | TCP | 8aafd70d-7fa3-336c-a713-ae628da3e653 | HTTP Server at 108.138.167.111:80 | HttpServer |
>| MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>WordpressServer,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>MissingPublicKeyPinsHeader,<br/>AdobeFlash,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>WildcardCertificate,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>ExpiredWhenScannedCertificate | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services | CVE-2021-26691,<br/>CVE-2021-44790,<br/>CVE-2021-39275,<br/>CVE-2022-31813,<br/>CVE-2022-23943,<br/>CVE-2022-22720,<br/>CVE-2018-1312,<br/>CVE-2022-28615,<br/>CVE-2022-22721,<br/>CVE-2019-10082,<br/>CVE-2021-40438,<br/>CVE-2021-44224,<br/>CVE-2017-15715,<br/>CVE-2019-0211,<br/>CVE-2022-22719,<br/>CVE-2021-34798,<br/>CVE-2020-9490,<br/>CVE-2019-0217,<br/>CVE-2022-30556,<br/>CVE-2021-32785,<br/>CVE-2017-15710,<br/>CVE-2021-33193,<br/>CVE-2020-11993,<br/>CVE-2022-26377,<br/>CVE-2021-26690,<br/>CVE-2019-10081,<br/>CVE-2018-17199,<br/>CVE-2022-29404,<br/>CVE-2018-1333,<br/>CVE-2018-1303,<br/>CVE-2020-35452,<br/>CVE-2019-10092,<br/>CVE-2020-1927,<br/>CVE-2019-10098,<br/>CVE-2021-32786,<br/>CVE-2021-32792,<br/>CVE-2021-32791,<br/>CVE-2018-11763,<br/>CVE-2018-1302,<br/>CVE-2018-1301,<br/>CVE-2020-13938,<br/>CVE-2019-0196,<br/>CVE-2022-28330,<br/>CVE-2019-17567,<br/>CVE-2018-1283,<br/>CVE-2020-1934,<br/>CVE-2018-17189,<br/>CVE-2022-28614,<br/>CVE-2019-0220 | 9.8 | 1659492780000 | ApplicationServerSoftware,<br/>PHP | 108.138.167.113 | Active | 1663330620000 | 443 | TCP | 0b6c9037-a030-3806-ba72-8b8aa68ee385 | HTTP Server at 108.138.167.113:443 | HttpServer |
>| MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1659522600000 |  | 108.138.167.113 | Active | 1663331460000 | 80 | TCP | 167e47d4-db99-33d1-bf37-b69472329316 | HTTP Server at 108.138.167.113:80 | HttpServer |
>| MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>WordpressServer,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>ApplicationServerSoftware,<br/>WildcardCertificate,<br/>HttpServer,<br/>PHP,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>ExpiredWhenScannedCertificate | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services | CVE-2022-31813,<br/>CVE-2022-28615,<br/>CVE-2022-31626,<br/>CVE-2022-31625,<br/>CVE-2022-30556,<br/>CVE-2022-29404,<br/>CVE-2022-26377,<br/>CVE-2022-30522,<br/>CVE-2022-28614,<br/>CVE-2022-28330 | 9.8 | 1662820320000 |  | 108.138.167.39 | Active | 1663330980000 | 443 | TCP | 1963ffca-641c-3b2e-92a2-e7322bb34c1b | HTTP Server at 108.138.167.39:443 | HttpServer |
>| HttpServer,<br/>ServerSoftware,<br/>NginxWebServer,<br/>DevelopmentEnvironment | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1659544680000 | JQuery | 108.138.167.39 | Active | 1663331580000 | 80 | TCP | d60dc1cb-bba3-3d4c-85e9-2caa256af02e | HTTP Server at 108.138.167.39:80 | HttpServer |
>| MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>MissingCacheControlHeader,<br/>WebLogin,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>WildcardCertificate,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>ExpiredWhenScannedCertificate | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1659494040000 | AtlassianConfluenceServer,<br/>MicrosoftIisWebServer,<br/>ApplicationServerSoftware,<br/>KestrelWebServer,<br/>WordpressServer,<br/>F5AdvancedWebApplicationFirewall,<br/>JQuery,<br/>AdobeFlash,<br/>NodeJs | 108.138.167.71 | Active | 1663266720000 | 443 | TCP | 601bf040-40f4-3398-85c4-84d233ac7733 | HTTP Server at 108.138.167.71:443 | HttpServer |
>| MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1659573600000 | JQuery,<br/>ApacheWebServer,<br/>WordpressServer | 108.138.167.71 | Active | 1663267020000 | 80 | TCP | cd31da6f-46e0-3867-8133-6ad9fc1c19af | HTTP Server at 108.138.167.71:80 | HttpServer |
>| MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>WordpressServer,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>MicrosoftIisWebServer,<br/>ApplicationServerSoftware,<br/>WildcardCertificate,<br/>HttpServer,<br/>PHP,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services | CVE-2018-1312,<br/>CVE-2019-11043,<br/>CVE-2019-11049,<br/>CVE-2021-44790,<br/>CVE-2022-23943,<br/>CVE-2021-39275,<br/>CVE-2019-13224,<br/>CVE-2017-8923,<br/>CVE-2022-22720,<br/>CVE-2021-26691,<br/>CVE-2022-31813,<br/>CVE-2019-10082,<br/>CVE-2020-7060,<br/>CVE-2020-7059,<br/>CVE-2022-22721,<br/>CVE-2020-7061,<br/>CVE-2022-28615,<br/>CVE-2021-40438,<br/>CVE-2020-7065,<br/>CVE-2021-44224,<br/>CVE-2017-15715,<br/>CVE-2019-0211,<br/>CVE-2020-7062,<br/>CVE-2021-33193,<br/>CVE-2022-30556,<br/>CVE-2017-15710,<br/>CVE-2018-1303,<br/>CVE-2019-11046,<br/>CVE-2018-1333,<br/>CVE-2020-11993,<br/>CVE-2019-0217,<br/>CVE-2021-26690,<br/>CVE-2022-29404,<br/>CVE-2019-10081,<br/>CVE-2021-21702,<br/>CVE-2018-17199,<br/>CVE-2021-32785,<br/>CVE-2020-9490,<br/>CVE-2019-11044,<br/>CVE-2021-34798,<br/>CVE-2022-22719,<br/>CVE-2022-26377,<br/>CVE-2019-19246,<br/>CVE-2020-7067,<br/>CVE-2020-35452,<br/>CVE-2019-11041,<br/>CVE-2019-11042,<br/>CVE-2021-21703,<br/>CVE-2019-11047,<br/>CVE-2019-11050,<br/>CVE-2020-7069,<br/>CVE-2021-21706,<br/>CVE-2020-11023,<br/>CVE-2021-32792,<br/>CVE-2019-10098,<br/>CVE-2020-11022,<br/>CVE-2019-11358,<br/>CVE-2019-10092,<br/>CVE-2020-1927,<br/>CVE-2021-32786,<br/>CVE-2015-9251,<br/>CVE-2018-1301,<br/>CVE-2019-11045,<br/>CVE-2021-21704,<br/>CVE-2018-11763,<br/>CVE-2018-1302,<br/>CVE-2021-32791,<br/>CVE-2020-13938,<br/>CVE-2020-7064,<br/>CVE-2020-7070,<br/>CVE-2020-7063,<br/>CVE-2022-28614,<br/>CVE-2019-17567,<br/>CVE-2020-1934,<br/>CVE-2019-0196,<br/>CVE-2020-7071,<br/>CVE-2021-21705,<br/>CVE-2021-21707,<br/>CVE-2018-1283,<br/>CVE-2019-0220,<br/>CVE-2019-11048,<br/>CVE-2018-17189,<br/>CVE-2022-28330,<br/>CVE-2014-4078,<br/>CVE-2020-7066,<br/>CVE-2020-7068 | 9.8 | 1662596400000 |  | 108.156.120.108 | Active | 1663108260000 | 443 | TCP | 8e2f22c2-2d96-3c76-819c-d96de46ba24f | HTTP Server at 108.156.120.108:443 | HttpServer |
>| HttpServer,<br/>ApacheWebServer,<br/>ServerSoftware,<br/>PythonApplication,<br/>JQuery,<br/>DevelopmentEnvironment | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services | CVE-2021-39275,<br/>CVE-2022-31813,<br/>CVE-2022-23943,<br/>CVE-2020-27619,<br/>CVE-2021-3177,<br/>CVE-2022-22720,<br/>CVE-2021-44790,<br/>CVE-2015-20107,<br/>CVE-2022-28615,<br/>CVE-2022-22721,<br/>CVE-2021-40438,<br/>CVE-2020-29396,<br/>CVE-2021-44224,<br/>CVE-2019-9674,<br/>CVE-2018-20406,<br/>CVE-2021-36160,<br/>CVE-2022-22719,<br/>CVE-2022-29404,<br/>CVE-2022-26377,<br/>CVE-2021-32785,<br/>CVE-2022-0391,<br/>CVE-2021-33193,<br/>CVE-2021-34798,<br/>CVE-2022-30556,<br/>CVE-2021-3737,<br/>CVE-2021-28861,<br/>CVE-2022-26488,<br/>CVE-2013-0340,<br/>CVE-2021-3733,<br/>CVE-2021-28359,<br/>CVE-2021-32792,<br/>CVE-2020-11022,<br/>CVE-2021-32786,<br/>CVE-2020-11023,<br/>CVE-2019-11358,<br/>CVE-2021-32791,<br/>CVE-2021-23336,<br/>CVE-2021-3426,<br/>CVE-2021-4189,<br/>CVE-2022-28330,<br/>CVE-2022-28614 | 9.8 | 1662596520000 |  | 108.156.120.108 | Active | 1663085880000 | 80 | TCP | 3c215660-e833-39a7-8363-ae36ef9f289e | HTTP Server at 108.156.120.108:80 | HttpServer |
>| MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>MissingCacheControlHeader,<br/>WebLogin,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>NodeJs,<br/>MissingXFrameOptionsHeader,<br/>MissingContentSecurityPolicyHeader,<br/>ApplicationServerSoftware,<br/>WildcardCertificate,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>ExpiredWhenScannedCertificate | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1659580440000 | F5BigIpPlatform,<br/>ApacheWebServer,<br/>MicrosoftIisWebServer,<br/>MoodleCMS,<br/>AdobeCommerce,<br/>PHP,<br/>LoadBalancer,<br/>WordpressServer,<br/>JQuery | 108.156.120.121 | Active | 1663328040000 | 443 | TCP | 2f61a4ce-ee3b-3807-b996-736283679c8a | HTTP Server at 108.156.120.121:443 | HttpServer |
>| MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>ApplicationServerSoftware,<br/>NginxWebServer,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1659590160000 | UnclaimedS3Bucket,<br/>ApacheWebServer,<br/>DevelopmentEnvironment | 108.156.120.121 | Active | 1663330380000 | 80 | TCP | b0407b44-3838-3c94-adc1-4b73ce5ebfbb | HTTP Server at 108.156.120.121:80 | HttpServer |
>| MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>WordpressServer,<br/>KongGateway,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>MissingPublicKeyPinsHeader,<br/>NodeJs,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>MicrosoftIisWebServer,<br/>InternalIpAddressAdvertisement,<br/>ApplicationServerSoftware,<br/>WildcardCertificate,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services | CVE-2022-22720,<br/>CVE-2018-1312,<br/>CVE-2022-23943,<br/>CVE-2022-31813,<br/>CVE-2021-44790,<br/>CVE-2021-26691,<br/>CVE-2021-39275,<br/>CVE-2022-28615,<br/>CVE-2019-10082,<br/>CVE-2022-22721,<br/>CVE-2021-40438,<br/>CVE-2021-44224,<br/>CVE-2017-15715,<br/>CVE-2019-0211,<br/>CVE-2022-29404,<br/>CVE-2021-33193,<br/>CVE-2017-15710,<br/>CVE-2022-26377,<br/>CVE-2019-0217,<br/>CVE-2019-10081,<br/>CVE-2022-22719,<br/>CVE-2018-1333,<br/>CVE-2018-1303,<br/>CVE-2021-34798,<br/>CVE-2018-17199,<br/>CVE-2021-32785,<br/>CVE-2021-26690,<br/>CVE-2020-9490,<br/>CVE-2022-30556,<br/>CVE-2020-11993,<br/>CVE-2020-35452,<br/>CVE-2021-32786,<br/>CVE-2019-10098,<br/>CVE-2020-1927,<br/>CVE-2019-10092,<br/>CVE-2021-32792,<br/>CVE-2018-1302,<br/>CVE-2018-11763,<br/>CVE-2021-32791,<br/>CVE-2018-1301,<br/>CVE-2020-13938,<br/>CVE-2019-17567,<br/>CVE-2019-0220,<br/>CVE-2019-0196,<br/>CVE-2022-28614,<br/>CVE-2018-17189,<br/>CVE-2020-1934,<br/>CVE-2022-28330,<br/>CVE-2018-1283 | 9.8 | 1662770100000 |  | 108.156.120.16 | Active | 1663326420000 | 443 | TCP | 03dbb327-fc35-37a4-91b1-75d167754f7f | HTTP Server at 108.156.120.16:443 | HttpServer |
>| MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader,<br/>NodeJs,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>ApplicationServerSoftware,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1659590100000 |  | 108.156.120.16 | Active | 1663326300000 | 80 | TCP | bdabbd2b-859d-3d3c-b167-7354383ed29c | HTTP Server at 108.156.120.16:80 | HttpServer |
>| MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>WordpressServer,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>WebLogin,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>MicrosoftIisWebServer,<br/>OktaSSO,<br/>ApplicationServerSoftware,<br/>WildcardCertificate,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services | CVE-2021-39275,<br/>CVE-2020-28036,<br/>CVE-2022-23943,<br/>CVE-2017-16510,<br/>CVE-2020-11984,<br/>CVE-2020-28032,<br/>CVE-2021-44790,<br/>CVE-2019-17669,<br/>CVE-2021-44223,<br/>CVE-2016-10033,<br/>CVE-2021-26691,<br/>CVE-2020-36326,<br/>CVE-2017-5611,<br/>CVE-2022-31813,<br/>CVE-2020-28035,<br/>CVE-2018-20148,<br/>CVE-2016-10045,<br/>CVE-2019-17670,<br/>CVE-2022-22720,<br/>CVE-2017-14723,<br/>CVE-2019-20041,<br/>CVE-2020-28037,<br/>CVE-2020-28039,<br/>CVE-2022-28615,<br/>CVE-2022-22721,<br/>CVE-2021-40438,<br/>CVE-2022-21664,<br/>CVE-2017-5492,<br/>CVE-2018-12895,<br/>CVE-2017-9064,<br/>CVE-2020-26596,<br/>CVE-2018-19296,<br/>CVE-2018-1000773,<br/>CVE-2019-8942,<br/>CVE-2017-17091,<br/>CVE-2017-1000600,<br/>CVE-2017-5489,<br/>CVE-2019-9787,<br/>CVE-2019-17675,<br/>CVE-2017-9066,<br/>CVE-2017-9062,<br/>CVE-2021-44224,<br/>CVE-2020-11027,<br/>CVE-2021-26690,<br/>CVE-2020-28033,<br/>CVE-2018-20151,<br/>CVE-2018-6389,<br/>CVE-2022-29404,<br/>CVE-2020-13950,<br/>CVE-2022-22719,<br/>CVE-2017-14719,<br/>CVE-2020-9490,<br/>CVE-2022-30556,<br/>CVE-2022-26377,<br/>CVE-2021-33193,<br/>CVE-2020-11993,<br/>CVE-2021-32785,<br/>CVE-2017-5493,<br/>CVE-2022-21661,<br/>CVE-2012-6707,<br/>CVE-2020-11028,<br/>CVE-2017-9065,<br/>CVE-2021-36160,<br/>CVE-2021-34798,<br/>CVE-2019-17673,<br/>CVE-2020-35452,<br/>CVE-2022-21663,<br/>CVE-2020-4047,<br/>CVE-2017-6819,<br/>CVE-2018-20147,<br/>CVE-2018-20152,<br/>CVE-2019-8943,<br/>CVE-2016-7169,<br/>CVE-2019-17672,<br/>CVE-2018-10101,<br/>CVE-2019-20042,<br/>CVE-2019-16222,<br/>CVE-2018-20150,<br/>CVE-2020-1927,<br/>CVE-2019-16220,<br/>CVE-2018-5776,<br/>CVE-2019-16218,<br/>CVE-2020-11023,<br/>CVE-2017-6815,<br/>CVE-2018-10100,<br/>CVE-2017-14724,<br/>CVE-2019-11358,<br/>CVE-2017-6818,<br/>CVE-2019-16221,<br/>CVE-2021-32792,<br/>CVE-2020-11022,<br/>CVE-2020-11029,<br/>CVE-2017-5488,<br/>CVE-2020-28034,<br/>CVE-2019-16217,<br/>CVE-2017-14720,<br/>CVE-2017-5612,<br/>CVE-2017-9061,<br/>CVE-2018-10102,<br/>CVE-2017-14721,<br/>CVE-2020-28038,<br/>CVE-2017-14726,<br/>CVE-2017-14718,<br/>CVE-2017-9063,<br/>CVE-2017-5490,<br/>CVE-2019-16219,<br/>CVE-2021-32786,<br/>CVE-2021-32791,<br/>CVE-2017-8295,<br/>CVE-2020-4048,<br/>CVE-2020-13938,<br/>CVE-2020-11030,<br/>CVE-2017-17094,<br/>CVE-2017-6814,<br/>CVE-2019-16780,<br/>CVE-2019-17674,<br/>CVE-2020-11026,<br/>CVE-2017-6817,<br/>CVE-2022-21662,<br/>CVE-2020-4046,<br/>CVE-2017-17092,<br/>CVE-2019-16781,<br/>CVE-2019-16223,<br/>CVE-2018-20149,<br/>CVE-2017-17093,<br/>CVE-2018-20153,<br/>CVE-2017-14725,<br/>CVE-2022-28614,<br/>CVE-2022-28330,<br/>CVE-2017-5487,<br/>CVE-2020-1934,<br/>CVE-2019-20043,<br/>CVE-2017-5491,<br/>CVE-2019-17567,<br/>CVE-2017-5610,<br/>CVE-2019-17671,<br/>CVE-2021-30641,<br/>CVE-2020-25286,<br/>CVE-2017-6816,<br/>CVE-2016-7168,<br/>CVE-2016-9263,<br/>CVE-2020-28040,<br/>CVE-2020-4050,<br/>CVE-2020-4049 | 9.8 | 1659580020000 | PHP,<br/>NodeJs,<br/>ExpiredWhenScannedCertificate | 108.156.120.33 | Active | 1663329300000 | 443 | TCP | 0ad80c63-c9b7-30b3-905c-ff78e9c52f5e | HTTP Server at 108.156.120.33:443 | HttpServer |
>| MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader,<br/>NodeJs,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>ApplicationServerSoftware,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1659588960000 | NginxWebServer,<br/>MicrosoftIisWebServer | 108.156.120.33 | Active | 1663326360000 | 80 | TCP | 517df659-8ede-3168-8377-cb57137680b3 | HTTP Server at 108.156.120.33:80 | HttpServer |
>| MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MicrosoftIisWebServer,<br/>ApplicationServerSoftware,<br/>WildcardCertificate,<br/>HttpServer,<br/>PHP,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>ExpiredWhenScannedCertificate | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services | CVE-2017-8923,<br/>CVE-2012-6708,<br/>CVE-2020-11023,<br/>CVE-2020-7656,<br/>CVE-2019-11358,<br/>CVE-2015-9251,<br/>CVE-2020-11022,<br/>CVE-2014-4078 | 9.8 | 1659580140000 | ApacheWebServer,<br/>WordpressServer,<br/>NodeJs | 108.156.120.41 | Active | 1663330560000 | 443 | TCP | 29bf4744-3a2e-315b-8f6b-f9b97f9aad32 | HTTP Server at 108.156.120.41:443 | HttpServer |
>| HttpServer,<br/>ServerSoftware,<br/>DevelopmentEnvironment | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1659590880000 | MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>AtlassianJiraServer,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader | 108.156.120.41 | Active | 1663331460000 | 80 | TCP | fbd9cd41-a525-343e-a91a-49a2343c8021 | HTTP Server at 108.156.120.41:80 | HttpServer |
>| MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>MissingContentSecurityPolicyHeader,<br/>WildcardCertificate,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services | CVE-2012-6708,<br/>CVE-2020-11023,<br/>CVE-2019-11358,<br/>CVE-2015-9251,<br/>CVE-2020-11022,<br/>CVE-2020-7656 | 6.1 | 1662596460000 |  | 108.156.120.72 | Active | 1663085520000 | 443 | TCP | 2f445d7e-0bfe-3fe1-a3af-0c82bd3196c5 | HTTP Server at 108.156.120.72:443 | HttpServer |
>| HttpServer,<br/>ServerSoftware,<br/>DevelopmentEnvironment | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1662596520000 | MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>MissingPublicKeyPinsHeader | 108.156.120.72 | Active | 1663086720000 | 80 | TCP | b395559f-01c2-3184-923b-e848189d624f | HTTP Server at 108.156.120.72:80 | HttpServer |
>| MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>WildcardCertificate,<br/>HttpServer,<br/>MissingXContentTypeOptionsHeader,<br/>ServerSoftware | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services | CVE-2017-3169,<br/>CVE-2022-22720,<br/>CVE-2018-1312,<br/>CVE-2017-7679,<br/>CVE-2022-23943,<br/>CVE-2022-31813,<br/>CVE-2021-44790,<br/>CVE-2021-26691,<br/>CVE-2021-39275,<br/>CVE-2017-3167,<br/>CVE-2022-28615,<br/>CVE-2019-10082,<br/>CVE-2017-9788,<br/>CVE-2022-22721,<br/>CVE-2021-40438,<br/>CVE-2021-44224,<br/>CVE-2017-15715,<br/>CVE-2016-5387,<br/>CVE-2019-0211,<br/>CVE-2022-29404,<br/>CVE-2021-33193,<br/>CVE-2017-15710,<br/>CVE-2022-26377,<br/>CVE-2016-8743,<br/>CVE-2019-0217,<br/>CVE-2019-10081,<br/>CVE-2022-22719,<br/>CVE-2018-1333,<br/>CVE-2018-1303,<br/>CVE-2021-34798,<br/>CVE-2018-17199,<br/>CVE-2016-8740,<br/>CVE-2021-32785,<br/>CVE-2016-4979,<br/>CVE-2021-26690,<br/>CVE-2020-9490,<br/>CVE-2022-30556,<br/>CVE-2017-9798,<br/>CVE-2020-11993,<br/>CVE-2020-35452,<br/>CVE-2021-32786,<br/>CVE-2019-10098,<br/>CVE-2020-1927,<br/>CVE-2016-4975,<br/>CVE-2019-10092,<br/>CVE-2021-32792,<br/>CVE-2018-1302,<br/>CVE-2018-11763,<br/>CVE-2021-32791,<br/>CVE-2016-1546,<br/>CVE-2018-1301,<br/>CVE-2020-13938,<br/>CVE-2019-17567,<br/>CVE-2019-0220,<br/>CVE-2019-0196,<br/>CVE-2022-28614,<br/>CVE-2020-11985,<br/>CVE-2018-17189,<br/>CVE-2020-1934,<br/>CVE-2022-28330,<br/>CVE-2018-1283,<br/>CVE-2016-8612 | 9.8 | 1662596460000 | JQuery,<br/>WordpressServer | 108.156.120.99 | Active | 1663108380000 | 443 | TCP | 2c120c3e-3ec1-3447-82c1-bbb055c01d8b | HTTP Server at 108.156.120.99:443 | HttpServer |
>| MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1662596520000 |  | 108.156.120.99 | Active | 1663081680000 | 80 | TCP | 633c6c62-206a-3e85-ad78-b2d87673c46f | HTTP Server at 108.156.120.99:80 | HttpServer |
>| MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>WildcardCertificate,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services | CVE-2018-1312,<br/>CVE-2022-31813,<br/>CVE-2022-23943,<br/>CVE-2021-39275,<br/>CVE-2022-22720,<br/>CVE-2021-26691,<br/>CVE-2021-44790,<br/>CVE-2019-10082,<br/>CVE-2022-28615,<br/>CVE-2022-22721,<br/>CVE-2021-40438,<br/>CVE-2021-44224,<br/>CVE-2017-15715,<br/>CVE-2019-0211,<br/>CVE-2019-0217,<br/>CVE-2022-22719,<br/>CVE-2022-29404,<br/>CVE-2019-10081,<br/>CVE-2021-34798,<br/>CVE-2018-1303,<br/>CVE-2018-1333,<br/>CVE-2021-26690,<br/>CVE-2018-17199,<br/>CVE-2020-11993,<br/>CVE-2022-26377,<br/>CVE-2020-9490,<br/>CVE-2021-32785,<br/>CVE-2017-15710,<br/>CVE-2021-33193,<br/>CVE-2022-30556,<br/>CVE-2020-35452,<br/>CVE-2020-1927,<br/>CVE-2015-9251,<br/>CVE-2020-7656,<br/>CVE-2020-11022,<br/>CVE-2012-6708,<br/>CVE-2021-32786,<br/>CVE-2019-10098,<br/>CVE-2019-11358,<br/>CVE-2021-32792,<br/>CVE-2019-10092,<br/>CVE-2020-11023,<br/>CVE-2018-1302,<br/>CVE-2021-32791,<br/>CVE-2018-11763,<br/>CVE-2018-1301,<br/>CVE-2020-13938,<br/>CVE-2019-0196,<br/>CVE-2022-28330,<br/>CVE-2022-28614,<br/>CVE-2019-0220,<br/>CVE-2018-17189,<br/>CVE-2020-1934,<br/>CVE-2018-1283,<br/>CVE-2019-17567 | 9.8 | 1662596460000 | ApplicationServerSoftware,<br/>PHP,<br/>WordpressServer | 108.156.120.9 | Active | 1663101360000 | 443 | TCP | 251605bf-4ccf-398f-bfb1-f62b68e24928 | HTTP Server at 108.156.120.9:443 | HttpServer |
>| HttpServer,<br/>ServerSoftware,<br/>NginxWebServer,<br/>DevelopmentEnvironment | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1662596520000 |  | 108.156.120.9 | Active | 1663086180000 | 80 | TCP | c1c31487-6714-3a6f-af63-5066b078ed04 | HTTP Server at 108.156.120.9:80 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1659588840000 | MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>ApacheWebServer,<br/>MissingStrictTransportSecurityHeader,<br/>MissingContentSecurityPolicyHeader,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment | 108.157.142.105 | Inactive | 1662575940000 | 80 | TCP | c7a3a84a-8f7b-391f-b440-5a235333715f | HTTP Server at 108.157.142.105:80 | HttpServer |
>| MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>MissingCacheControlHeader,<br/>F5AdvancedWebApplicationFirewall,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>EclipseJettyWebServer,<br/>WildcardCertificate,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1659407880000 | ApplicationServerSoftware,<br/>WordpressServer,<br/>KongGateway,<br/>JQuery,<br/>NodeJs,<br/>DrupalWebServer,<br/>ExpiredWhenScannedCertificate | 108.157.142.68 | Active | 1663302060000 | 443 | TCP | 7408fa29-0296-3070-826c-cdc0593b2b08 | HTTP Server at 108.157.142.68:443 | HttpServer |
>| MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1659588840000 | WordpressServer,<br/>JQuery,<br/>NginxWebServer,<br/>DevelopmentEnvironment | 108.157.142.68 | Active | 1663303140000 | 80 | TCP | 02a68b81-7e97-3afd-ac05-bad0f546baab | HTTP Server at 108.157.142.68:80 | HttpServer |
>| MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>OpenSSL,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>WildcardCertificate,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services | CVE-2016-2842,<br/>CVE-2016-2177,<br/>CVE-2017-3167,<br/>CVE-2022-31813,<br/>CVE-2022-22720,<br/>CVE-2018-1312,<br/>CVE-2021-44790,<br/>CVE-2022-23943,<br/>CVE-2017-7679,<br/>CVE-2016-0799,<br/>CVE-2021-39275,<br/>CVE-2016-2108,<br/>CVE-2021-26691,<br/>CVE-2016-6303,<br/>CVE-2016-0705,<br/>CVE-2016-2182,<br/>CVE-2022-2068,<br/>CVE-2022-1292,<br/>CVE-2017-9788,<br/>CVE-2022-28615,<br/>CVE-2022-22721,<br/>CVE-2020-7043,<br/>CVE-2021-40438,<br/>CVE-2016-2176,<br/>CVE-2016-5387,<br/>CVE-2017-15715,<br/>CVE-2016-2183,<br/>CVE-2016-2161,<br/>CVE-2016-8743,<br/>CVE-2021-34798,<br/>CVE-2015-3194,<br/>CVE-2022-26377,<br/>CVE-2017-15710,<br/>CVE-2016-6304,<br/>CVE-2022-29404,<br/>CVE-2016-2179,<br/>CVE-2022-30556,<br/>CVE-2016-0736,<br/>CVE-2015-3193,<br/>CVE-2016-0798,<br/>CVE-2016-2109,<br/>CVE-2016-2181,<br/>CVE-2016-2105,<br/>CVE-2018-17199,<br/>CVE-2016-0797,<br/>CVE-2021-32785,<br/>CVE-2016-2106,<br/>CVE-2017-3731,<br/>CVE-2022-22719,<br/>CVE-2016-7052,<br/>CVE-2017-9798,<br/>CVE-2016-2180,<br/>CVE-2018-1303,<br/>CVE-2016-6302,<br/>CVE-2019-0217,<br/>CVE-2021-26690,<br/>CVE-2015-1789,<br/>CVE-2021-4044,<br/>CVE-2018-0732,<br/>CVE-2016-8610,<br/>CVE-2022-0778,<br/>CVE-2021-23840,<br/>CVE-2021-3712,<br/>CVE-2020-35452,<br/>CVE-2014-0226,<br/>CVE-2015-0209,<br/>CVE-2015-1791,<br/>CVE-2015-1793,<br/>CVE-2018-0739,<br/>CVE-2017-3736,<br/>CVE-2019-10092,<br/>CVE-2020-1927,<br/>CVE-2019-10098,<br/>CVE-2021-32786,<br/>CVE-2021-32792,<br/>CVE-2016-4975,<br/>CVE-2016-0703,<br/>CVE-2016-2107,<br/>CVE-2017-3737,<br/>CVE-2017-3738,<br/>CVE-2016-0800,<br/>CVE-2017-3732,<br/>CVE-2016-0704,<br/>CVE-2015-3197,<br/>CVE-2021-32791,<br/>CVE-2018-1302,<br/>CVE-2016-6306,<br/>CVE-2018-1301,<br/>CVE-2019-1559,<br/>CVE-2020-1971,<br/>CVE-2016-7055,<br/>CVE-2021-23841,<br/>CVE-2021-4160,<br/>CVE-2018-0737,<br/>CVE-2018-0734,<br/>CVE-2009-3555,<br/>CVE-2020-13938,<br/>CVE-2016-2178,<br/>CVE-2018-1283,<br/>CVE-2022-28330,<br/>CVE-2017-3735,<br/>CVE-2022-28614,<br/>CVE-2019-0220,<br/>CVE-2020-1934,<br/>CVE-2019-17567,<br/>CVE-2020-11985,<br/>CVE-2019-1551,<br/>CVE-2015-3195,<br/>CVE-2020-7042,<br/>CVE-2020-7041,<br/>CVE-2016-0702,<br/>CVE-2013-5704,<br/>CVE-2015-0286,<br/>CVE-2014-0231,<br/>CVE-2015-3184,<br/>CVE-2015-3183,<br/>CVE-2015-1794,<br/>CVE-2015-0288,<br/>CVE-2015-0290,<br/>CVE-2014-3523,<br/>CVE-2015-0293,<br/>CVE-2015-0287,<br/>CVE-2015-1792,<br/>CVE-2013-6438,<br/>CVE-2015-1790,<br/>CVE-2014-0098,<br/>CVE-2014-3581,<br/>CVE-2015-0228,<br/>CVE-2015-0291,<br/>CVE-2015-0207,<br/>CVE-2015-0289,<br/>CVE-2019-1547,<br/>CVE-2018-5407,<br/>CVE-2014-8109,<br/>CVE-2015-0285,<br/>CVE-2016-8612,<br/>CVE-2015-1788,<br/>CVE-2014-0117,<br/>CVE-2014-0118,<br/>CVE-2015-3185,<br/>CVE-2013-4352,<br/>CVE-2015-0208,<br/>CVE-2016-0701,<br/>CVE-2021-23839,<br/>CVE-2015-4000,<br/>CVE-2020-1968,<br/>CVE-2019-1563,<br/>CVE-2019-1552,<br/>CVE-2015-1787 | 9.8 | 1662861180000 |  | 108.157.142.85 | Active | 1663079340000 | 443 | TCP | b46de908-5c8e-3619-9c16-8f2aec791811 | HTTP Server at 108.157.142.85:443 | HttpServer |
>| MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1659593580000 | NginxWebServer,<br/>DevelopmentEnvironment | 108.157.142.85 | Active | 1663072800000 | 80 | TCP | d02a5748-08e5-3a88-a78f-c229adf6d2d0 | HTTP Server at 108.157.142.85:80 | HttpServer |
>| MissingXXssProtectionHeader,<br/>NginxWebServer,<br/>WebLogin,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>MicrosoftIisWebServer,<br/>ApplicationServerSoftware,<br/>WildcardCertificate,<br/>HttpServer,<br/>ServerSoftware | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1659407880000 | MissingStrictTransportSecurityHeader,<br/>PHP,<br/>WordpressServer,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>ExpiredWhenScannedCertificate | 108.157.142.91 | Active | 1663330980000 | 443 | TCP | f1d21bbc-33bf-3cef-b6b9-4ec93ab794b8 | HTTP Server at 108.157.142.91:443 | HttpServer |
>| HttpServer,<br/>ServerSoftware,<br/>DevelopmentEnvironment | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1659458340000 | ApacheWebServer | 108.157.142.91 | Active | 1663331580000 | 80 | TCP | 6943990e-74be-35fe-87f5-30d4f8ee5fdc | HTTP Server at 108.157.142.91:80 | HttpServer |
>| HttpServer,<br/>ServerSoftware,<br/>DevelopmentEnvironment | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1659835800000 | MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>WordpressServer,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>MissingPublicKeyPinsHeader,<br/>NodeJs,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>ApplicationServerSoftware,<br/>WildcardCertificate,<br/>MissingXContentTypeOptionsHeader | 108.157.150.105 | Active | 1662662460000 | 443 | TCP | 957e25f0-0d6e-3c1c-a822-4899322dab1c | HTTP Server at 108.157.150.105:443 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1659828960000 | MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment | 108.157.150.105 | Inactive | 1662615900000 | 80 | TCP | d9a87953-b82a-3ca9-8abf-79f4388cdd55 | HTTP Server at 108.157.150.105:80 | HttpServer |
>| MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>WordpressServer,<br/>MissingCacheControlHeader,<br/>SharepointServer,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>MissingContentSecurityPolicyHeader,<br/>ApplicationServerSoftware,<br/>WildcardCertificate,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1659835800000 | JQuery,<br/>ApacheWebServer,<br/>NginxWebServer | 108.157.150.120 | Active | 1662798180000 | 443 | TCP | 10e8a02e-ef8f-36c9-86ee-b860ac69ad56 | HTTP Server at 108.157.150.120:443 | HttpServer |
>| HttpServer,<br/>ServerSoftware | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1659829020000 | MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment | 108.157.150.120 | Active | 1662799020000 | 80 | TCP | b7ef3aea-c24d-32ce-ac77-255c3eff7e79 | HTTP Server at 108.157.150.120:80 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1662510660000 | MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>MissingPublicKeyPinsHeader,<br/>MissingXFrameOptionsHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MicrosoftIisWebServer,<br/>ApplicationServerSoftware,<br/>WildcardCertificate,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader | 108.157.150.43 | Inactive | 1662615720000 | 443 | TCP | ed75d3ae-7c34-36ab-b21c-c7f8a6803645 | HTTP Server at 108.157.150.43:443 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1659828900000 | HttpServer,<br/>ServerSoftware,<br/>DevelopmentEnvironment | 108.157.150.43 | Inactive | 1662615720000 | 80 | TCP | 00c74bca-f427-3c3a-b4fa-b284e97b5793 | HTTP Server at 108.157.150.43:80 | HttpServer |
>| HttpServer,<br/>ServerSoftware | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1662510900000 | MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>WildcardCertificate,<br/>MissingXContentTypeOptionsHeader,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment | 108.157.150.46 | Active | 1662662640000 | 443 | TCP | 78cdba1b-c7db-389b-be88-43ea40a0a860 | HTTP Server at 108.157.150.46:443 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1662510900000 | HttpServer,<br/>ServerSoftware,<br/>DevelopmentEnvironment | 108.157.150.46 | Inactive | 1662620400000 | 80 | TCP | 3c4d609e-d428-33b5-bfb2-cdff15c7a916 | HTTP Server at 108.157.150.46:80 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1660774080000 | MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>WordpressServer,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>MicrosoftIisWebServer,<br/>ApplicationServerSoftware,<br/>InternalIpAddressAdvertisement,<br/>WildcardCertificate,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>ExpiredWhenScannedCertificate | 108.157.214.109 | Inactive | 1661295780000 | 443 | TCP | 57e1d138-d843-3edd-8faf-b8a6557cc65c | HTTP Server at 108.157.214.109:443 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1660773780000 | MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>MissingContentSecurityPolicyHeader,<br/>InternalIpAddressAdvertisement,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment | 108.157.214.109 | Inactive | 1661315460000 | 80 | TCP | 52fe65cb-c386-336d-93a5-350f0246c2f2 | HTTP Server at 108.157.214.109:80 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1660773960000 | MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>MissingPublicKeyPinsHeader,<br/>DrupalWebServer,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>WildcardCertificate,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader | 108.157.214.118 | Inactive | 1661295240000 | 443 | TCP | a34f79ae-8778-30e4-b63a-8d681b2267e9 | HTTP Server at 108.157.214.118:443 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1660772220000 | MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>WordpressServer,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MicrosoftIisWebServer,<br/>ApplicationServerSoftware,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader | 108.157.214.118 | Inactive | 1661308140000 | 80 | TCP | 2bb221bd-9ba1-3ba5-bd8f-8bd67a8e1bb2 | HTTP Server at 108.157.214.118:80 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1660774440000 | MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>WildcardCertificate,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader | 108.157.214.36 | Inactive | 1661302440000 | 443 | TCP | 6c73ced9-311b-32d2-8e88-efc68a44a704 | HTTP Server at 108.157.214.36:443 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1660773960000 | HttpServer,<br/>ServerSoftware,<br/>DevelopmentEnvironment | 108.157.214.36 | Inactive | 1661296020000 | 80 | TCP | 39a750a2-d427-3aa3-ac0a-692b834d069b | HTTP Server at 108.157.214.36:80 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1660775040000 | MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>MissingCacheControlHeader,<br/>WebLogin,<br/>JQuery,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>ApplicationServerSoftware,<br/>WildcardCertificate,<br/>HttpServer,<br/>PHP,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MicrosoftASPNETCore,<br/>ExpiredWhenScannedCertificate | 108.157.214.49 | Inactive | 1661295780000 | 443 | TCP | 45d2e1e9-a1a1-3109-a5db-ea40a32cb27d | HTTP Server at 108.157.214.49:443 | HttpServer |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services |  |  | 1660782360000 | HttpServer,<br/>ServerSoftware,<br/>DevelopmentEnvironment | 108.157.214.49 | Inactive | 1661313120000 | 80 | TCP | f27a6ac5-8736-3c68-acd1-176da8e720dd | HTTP Server at 108.157.214.49:80 | HttpServer |
>| MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>NginxWebServer,<br/>WordpressServer,<br/>MissingCacheControlHeader,<br/>WebLogin,<br/>JQuery,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment,<br/>MissingXFrameOptionsHeader,<br/>ApacheWebServer,<br/>MissingContentSecurityPolicyHeader,<br/>ApplicationServerSoftware,<br/>WildcardCertificate,<br/>HttpServer,<br/>PHP,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>ExpiredWhenScannedCertificate | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | ColocatedOnIp | Amazon Web Services | CVE-2018-1312,<br/>CVE-2021-44790,<br/>CVE-2022-23943,<br/>CVE-2021-39275,<br/>CVE-2022-22720,<br/>CVE-2021-26691,<br/>CVE-2022-31813,<br/>CVE-2019-11043,<br/>CVE-2017-8923,<br/>CVE-2019-10082,<br/>CVE-2022-22721,<br/>CVE-2022-28615,<br/>CVE-2020-7059,<br/>CVE-2020-7060,<br/>CVE-2020-7061,<br/>CVE-2021-40438,<br/>CVE-2021-44224,<br/>CVE-2017-15715,<br/>CVE-2019-0211,<br/>CVE-2021-33193,<br/>CVE-2022-30556,<br/>CVE-2017-15710,<br/>CVE-2018-1303,<br/>CVE-2018-1333,<br/>CVE-2020-11993,<br/>CVE-2019-0217,<br/>CVE-2021-26690,<br/>CVE-2022-29404,<br/>CVE-2019-10081,<br/>CVE-2018-17199,<br/>CVE-2021-32785,<br/>CVE-2020-9490,<br/>CVE-2021-34798,<br/>CVE-2022-22719,<br/>CVE-2022-26377,<br/>CVE-2019-11046,<br/>CVE-2019-11044,<br/>CVE-2020-7062,<br/>CVE-2020-7067,<br/>CVE-2020-35452,<br/>CVE-2019-11047,<br/>CVE-2019-11050,<br/>CVE-2020-7069,<br/>CVE-2019-11358,<br/>CVE-2020-11022,<br/>CVE-2021-32792,<br/>CVE-2019-10098,<br/>CVE-2015-9251,<br/>CVE-2019-10092,<br/>CVE-2020-11023,<br/>CVE-2020-1927,<br/>CVE-2021-32786,<br/>CVE-2018-1301,<br/>CVE-2018-11763,<br/>CVE-2018-1302,<br/>CVE-2021-32791,<br/>CVE-2019-11045,<br/>CVE-2020-13938,<br/>CVE-2020-7064,<br/>CVE-2022-28614,<br/>CVE-2019-17567,<br/>CVE-2020-1934,<br/>CVE-2019-0196,<br/>CVE-2018-1283,<br/>CVE-2019-0220,<br/>CVE-2018-17189,<br/>CVE-2022-28330,<br/>CVE-2019-11048,<br/>CVE-2020-7070,<br/>CVE-2020-7063,<br/>CVE-2020-7066,<br/>CVE-2020-7068 | 9.8 | 1662537960000 |  | 108.159.227.23 | Active | 1663328040000 | 443 | TCP | 33a72996-511f-34d4-88ea-e6ab52690f68 | HTTP Server at 108.159.227.23:443 | HttpServer |


### asm-getexternalservice
***
Get service details according to the service ID.


#### Base Command

`asm-getexternalservice`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_id | A string represenng the service ID you want get details for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.GetExternalService.service_id | String | External service UUID | 
| ASM.GetExternalService.service_name | String | Name of the external service | 
| ASM.GetExternalService.service_type | String | Type of external service | 
| ASM.GetExternalService.ip_address | String | IP address of external service | 
| ASM.GetExternalService.externally_detected_providers | String | Providers of external service | 
| ASM.GetExternalService.is_active | String | Is external service active or not | 
| ASM.GetExternalService.first_observed | Date | Date of first observation of external service | 
| ASM.GetExternalService.last_observed | Date | Date of last observation of external service | 
| ASM.GetExternalService.port | Number | Port number of external service | 
| ASM.GetExternalService.protocol | String | Protocol of external service | 
| ASM.GetExternalService.inactive_classifications | String | External service classifications that are no longer active | 
| ASM.GetExternalService.discovery_type | String | How external service was discovered | 
| ASM.GetExternalService.business_units | String | External service associated business units | 
| ASM.GetExternalService.externally_inferred_vulnerability_score | Unknown | External service vulnerability score | 
| ASM.GetExternalService.details | String | Additional details | 

#### Command example
```!asm-getexternalservice service_id=94232f8a-f001-3292-aa65-63fa9d981427```
#### Context Example
```json
{
    "ASM": {
        "GetExternalService": {
            "active_classifications": [
                "SSHWeakMACAlgorithmsEnabled",
                "SshServer",
                "OpenSSH"
            ],
            "business_units": [
                "jwilkes - Toys R US"
            ],
            "details": {
                "businessUnits": [
                    {
                        "name": "jwilkes - Toys R US"
                    }
                ],
                "certificates": [],
                "classifications": [
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774120000,
                        "lastObserved": 1663313640000,
                        "name": "SshServer",
                        "values": [
                            {
                                "firstObserved": 1662774169000,
                                "jsonValue": "{\"version\":\"2.0\",\"serverVersion\":\"OpenSSH_7.6p1\",\"extraInfo\":\"Ubuntu-4ubuntu0.7\"}",
                                "lastObserved": 1663313640000
                            }
                        ]
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774120000,
                        "lastObserved": 1663302840000,
                        "name": "SSHWeakMACAlgorithmsEnabled",
                        "values": [
                            {
                                "firstObserved": 1662774169000,
                                "jsonValue": "{}",
                                "lastObserved": 1663302867000
                            }
                        ]
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774120000,
                        "lastObserved": 1663313640000,
                        "name": "OpenSSH",
                        "values": [
                            {
                                "firstObserved": 1662774169000,
                                "jsonValue": "{\"version\":\"7.6\"}",
                                "lastObserved": 1663313640000
                            }
                        ]
                    }
                ],
                "domains": [],
                "enrichedObservationSource": "CLOUD",
                "inferredCvesObserved": [
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "inferredCve": {
                            "cveId": "CVE-2020-15778",
                            "cveSeverityV2": "MEDIUM",
                            "cveSeverityV3": "HIGH",
                            "cvssScoreV2": 6.8,
                            "cvssScoreV3": 7.8,
                            "inferredCveMatchMetadata": {
                                "confidence": "High",
                                "inferredCveMatchType": "ExactVersionMatch",
                                "product": "openssh",
                                "vendor": "openbsd",
                                "version": "7.6"
                            }
                        },
                        "lastObserved": 1663313640000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "inferredCve": {
                            "cveId": "CVE-2021-41617",
                            "cveSeverityV2": "MEDIUM",
                            "cveSeverityV3": "HIGH",
                            "cvssScoreV2": 4.4,
                            "cvssScoreV3": 7,
                            "inferredCveMatchMetadata": {
                                "confidence": "High",
                                "inferredCveMatchType": "ExactVersionMatch",
                                "product": "openssh",
                                "vendor": "openbsd",
                                "version": "7.6"
                            }
                        },
                        "lastObserved": 1663313640000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "inferredCve": {
                            "cveId": "CVE-2019-6110",
                            "cveSeverityV2": "MEDIUM",
                            "cveSeverityV3": "MEDIUM",
                            "cvssScoreV2": 4,
                            "cvssScoreV3": 6.8,
                            "inferredCveMatchMetadata": {
                                "confidence": "High",
                                "inferredCveMatchType": "ExactVersionMatch",
                                "product": "openssh",
                                "vendor": "openbsd",
                                "version": "7.6"
                            }
                        },
                        "lastObserved": 1663313640000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "inferredCve": {
                            "cveId": "CVE-2019-6109",
                            "cveSeverityV2": "MEDIUM",
                            "cveSeverityV3": "MEDIUM",
                            "cvssScoreV2": 4,
                            "cvssScoreV3": 6.8,
                            "inferredCveMatchMetadata": {
                                "confidence": "High",
                                "inferredCveMatchType": "ExactVersionMatch",
                                "product": "openssh",
                                "vendor": "openbsd",
                                "version": "7.6"
                            }
                        },
                        "lastObserved": 1663313640000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "inferredCve": {
                            "cveId": "CVE-2020-14145",
                            "cveSeverityV2": "MEDIUM",
                            "cveSeverityV3": "MEDIUM",
                            "cvssScoreV2": 4.3,
                            "cvssScoreV3": 5.9,
                            "inferredCveMatchMetadata": {
                                "confidence": "High",
                                "inferredCveMatchType": "ExactVersionMatch",
                                "product": "openssh",
                                "vendor": "openbsd",
                                "version": "7.6"
                            }
                        },
                        "lastObserved": 1663313640000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "inferredCve": {
                            "cveId": "CVE-2019-6111",
                            "cveSeverityV2": "MEDIUM",
                            "cveSeverityV3": "MEDIUM",
                            "cvssScoreV2": 5.8,
                            "cvssScoreV3": 5.9,
                            "inferredCveMatchMetadata": {
                                "confidence": "High",
                                "inferredCveMatchType": "ExactVersionMatch",
                                "product": "openssh",
                                "vendor": "openbsd",
                                "version": "7.6"
                            }
                        },
                        "lastObserved": 1663313640000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "inferredCve": {
                            "cveId": "CVE-2016-20012",
                            "cveSeverityV2": "MEDIUM",
                            "cveSeverityV3": "MEDIUM",
                            "cvssScoreV2": 4.3,
                            "cvssScoreV3": 5.3,
                            "inferredCveMatchMetadata": {
                                "confidence": "High",
                                "inferredCveMatchType": "ExactVersionMatch",
                                "product": "openssh",
                                "vendor": "openbsd",
                                "version": "7.6"
                            }
                        },
                        "lastObserved": 1663313640000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "inferredCve": {
                            "cveId": "CVE-2018-15473",
                            "cveSeverityV2": "MEDIUM",
                            "cveSeverityV3": "MEDIUM",
                            "cvssScoreV2": 5,
                            "cvssScoreV3": 5.3,
                            "inferredCveMatchMetadata": {
                                "confidence": "High",
                                "inferredCveMatchType": "ExactVersionMatch",
                                "product": "openssh",
                                "vendor": "openbsd",
                                "version": "7.6"
                            }
                        },
                        "lastObserved": 1663313640000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "inferredCve": {
                            "cveId": "CVE-2018-15919",
                            "cveSeverityV2": "MEDIUM",
                            "cveSeverityV3": "MEDIUM",
                            "cvssScoreV2": 5,
                            "cvssScoreV3": 5.3,
                            "inferredCveMatchMetadata": {
                                "confidence": "High",
                                "inferredCveMatchType": "ExactVersionMatch",
                                "product": "openssh",
                                "vendor": "openbsd",
                                "version": "7.6"
                            }
                        },
                        "lastObserved": 1663313640000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "inferredCve": {
                            "cveId": "CVE-2018-20685",
                            "cveSeverityV2": "LOW",
                            "cveSeverityV3": "MEDIUM",
                            "cvssScoreV2": 2.6,
                            "cvssScoreV3": 5.3,
                            "inferredCveMatchMetadata": {
                                "confidence": "High",
                                "inferredCveMatchType": "ExactVersionMatch",
                                "product": "openssh",
                                "vendor": "openbsd",
                                "version": "7.6"
                            }
                        },
                        "lastObserved": 1663313640000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "inferredCve": {
                            "cveId": "CVE-2021-36368",
                            "cveSeverityV2": "LOW",
                            "cveSeverityV3": "LOW",
                            "cvssScoreV2": 2.6,
                            "cvssScoreV3": 3.7,
                            "inferredCveMatchMetadata": {
                                "confidence": "High",
                                "inferredCveMatchType": "ExactVersionMatch",
                                "product": "openssh",
                                "vendor": "openbsd",
                                "version": "7.6"
                            }
                        },
                        "lastObserved": 1663313640000
                    }
                ],
                "ip_ranges": {},
                "ips": [
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "geolocation": {
                            "city": "ASHBURN",
                            "countryCode": "US",
                            "latitude": 39.0438,
                            "longitude": -77.4879,
                            "regionCode": "VA",
                            "timeZone": null
                        },
                        "ip": 873887795,
                        "lastObserved": 1663313640000,
                        "protocol": "TCP",
                        "provider": "AWS"
                    }
                ],
                "providerDetails": [
                    {
                        "firstObserved": 1662774169000,
                        "lastObserved": 1663313640000,
                        "name": "AWS"
                    }
                ],
                "serviceKey": "52.22.120.51:22",
                "serviceKeyType": "IP",
                "tlsVersions": []
            },
            "discovery_type": "ColocatedOnIp",
            "domain": [],
            "externally_detected_providers": [
                "Amazon Web Services"
            ],
            "externally_inferred_cves": [
                "CVE-2020-15778",
                "CVE-2021-41617",
                "CVE-2019-6110",
                "CVE-2019-6109",
                "CVE-2020-14145",
                "CVE-2019-6111",
                "CVE-2016-20012",
                "CVE-2018-15473",
                "CVE-2018-15919",
                "CVE-2018-20685",
                "CVE-2021-36368"
            ],
            "externally_inferred_vulnerability_score": 7.8,
            "first_observed": 1662774120000,
            "inactive_classifications": [],
            "ip_address": [
                "52.22.120.51"
            ],
            "is_active": "Active",
            "last_observed": 1663313640000,
            "port": 22,
            "protocol": "TCP",
            "service_id": "94232f8a-f001-3292-aa65-63fa9d981427",
            "service_name": "SSH Server at 52.22.120.51:22",
            "service_type": "SshServer"
        }
    }
}
```

#### Human Readable Output

>### External Service
>|active_classifications|business_units|details|discovery_type|externally_detected_providers|externally_inferred_cves|externally_inferred_vulnerability_score|first_observed|ip_address|is_active|last_observed|port|protocol|service_id|service_name|service_type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| SSHWeakMACAlgorithmsEnabled,<br/>SshServer,<br/>OpenSSH | jwilkes - Toys R US | serviceKey: 52.22.120.51:22<br/>serviceKeyType: IP<br/>businessUnits: {'name': 'jwilkes - Toys R US'}<br/>providerDetails: {'name': 'AWS', 'firstObserved': 1662774169000, 'lastObserved': 1663313640000}<br/>certificates: <br/>domains: <br/>ips: {'ip': 873887795, 'protocol': 'TCP', 'provider': 'AWS', 'geolocation': {'latitude': 39.0438, 'longitude': -77.4879, 'countryCode': 'US', 'city': 'ASHBURN', 'regionCode': 'VA', 'timeZone': None}, 'activityStatus': 'Active', 'lastObserved': 1663313640000, 'firstObserved': 1662774169000}<br/>classifications: {'name': 'SshServer', 'activityStatus': 'Active', 'values': [{'jsonValue': '{"version":"2.0","serverVersion":"OpenSSH_7.6p1","extraInfo":"Ubuntu-4ubuntu0.7"}', 'firstObserved': 1662774169000, 'lastObserved': 1663313640000}], 'firstObserved': 1662774120000, 'lastObserved': 1663313640000},<br/>{'name': 'SSHWeakMACAlgorithmsEnabled', 'activityStatus': 'Active', 'values': [{'jsonValue': '{}', 'firstObserved': 1662774169000, 'lastObserved': 1663302867000}], 'firstObserved': 1662774120000, 'lastObserved': 1663302840000},<br/>{'name': 'OpenSSH', 'activityStatus': 'Active', 'values': [{'jsonValue': '{"version":"7.6"}', 'firstObserved': 1662774169000, 'lastObserved': 1663313640000}], 'firstObserved': 1662774120000, 'lastObserved': 1663313640000}<br/>tlsVersions: <br/>inferredCvesObserved: {'inferredCve': {'cveId': 'CVE-2020-15778', 'cvssScoreV2': 6.8, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 7.8, 'cveSeverityV3': 'HIGH', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663313640000},<br/>{'inferredCve': {'cveId': 'CVE-2021-41617', 'cvssScoreV2': 4.4, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 7.0, 'cveSeverityV3': 'HIGH', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663313640000},<br/>{'inferredCve': {'cveId': 'CVE-2019-6110', 'cvssScoreV2': 4.0, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 6.8, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663313640000},<br/>{'inferredCve': {'cveId': 'CVE-2019-6109', 'cvssScoreV2': 4.0, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 6.8, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663313640000},<br/>{'inferredCve': {'cveId': 'CVE-2020-14145', 'cvssScoreV2': 4.3, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 5.9, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663313640000},<br/>{'inferredCve': {'cveId': 'CVE-2019-6111', 'cvssScoreV2': 5.8, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 5.9, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663313640000},<br/>{'inferredCve': {'cveId': 'CVE-2016-20012', 'cvssScoreV2': 4.3, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 5.3, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663313640000},<br/>{'inferredCve': {'cveId': 'CVE-2018-15473', 'cvssScoreV2': 5.0, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 5.3, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663313640000},<br/>{'inferredCve': {'cveId': 'CVE-2018-15919', 'cvssScoreV2': 5.0, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 5.3, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663313640000},<br/>{'inferredCve': {'cveId': 'CVE-2018-20685', 'cvssScoreV2': 2.6, 'cveSeverityV2': 'LOW', 'cvssScoreV3': 5.3, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663313640000},<br/>{'inferredCve': {'cveId': 'CVE-2021-36368', 'cvssScoreV2': 2.6, 'cveSeverityV2': 'LOW', 'cvssScoreV3': 3.7, 'cveSeverityV3': 'LOW', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663313640000}<br/>enrichedObservationSource: CLOUD<br/>ip_ranges: {} | ColocatedOnIp | Amazon Web Services | CVE-2020-15778,<br/>CVE-2021-41617,<br/>CVE-2019-6110,<br/>CVE-2019-6109,<br/>CVE-2020-14145,<br/>CVE-2019-6111,<br/>CVE-2016-20012,<br/>CVE-2018-15473,<br/>CVE-2018-15919,<br/>CVE-2018-20685,<br/>CVE-2021-36368 | 7.8 | 1662774120000 | 52.22.120.51 | Active | 1663313640000 | 22 | TCP | 94232f8a-f001-3292-aa65-63fa9d981427 | SSH Server at 52.22.120.51:22 | SshServer |


### asm-getexternalipaddressranges
***
Get a list of all your Internet exposure filtered by business units and organization handles. Maximum result limit is 100 ranges.


#### Base Command

`asm-getexternalipaddressranges`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.GetExternalIpAddressRanges.range_id | String | External IP address range UUID | 
| ASM.GetExternalIpAddressRanges.first_ip | String | First IP address of external IP address range | 
| ASM.GetExternalIpAddressRanges.last_ip | String | Last IP address of external IP address range | 
| ASM.GetExternalIpAddressRanges.ips_count | Number | Number of IP addresses of external IP address range | 
| ASM.GetExternalIpAddressRanges.active_responsive_ips_count | Number | How many IPs in external address range are actively responsive | 
| ASM.GetExternalIpAddressRanges.date_added | Date | Date the external IP address range was added | 
| ASM.GetExternalIpAddressRanges.business_units | String | External IP address range associated business units | 
| ASM.GetExternalIpAddressRanges.organization_handles | String | External IP address range associated organization handles | 

#### Command example
```!asm-getexternalipaddressranges```
#### Context Example
```json
{
    "ASM": {
        "GetExternalIpAddressRanges": [
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448439,
                "first_ip": "220.241.52.192",
                "ips_count": 64,
                "last_ip": "220.241.52.255",
                "organization_handles": [
                    "MAINT-HK-PCCW-BIA-CS",
                    "BNA2-AP",
                    "TA66-AP"
                ],
                "range_id": "4da29b7f-3086-3b52-981b-aa8ee5da1e60"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448439,
                "first_ip": "217.206.176.80",
                "ips_count": 16,
                "last_ip": "217.206.176.95",
                "organization_handles": [
                    "EH92-RIPE",
                    "AR17615-RIPE",
                    "EASYNET-UK-MNT",
                    "JW372-RIPE"
                ],
                "range_id": "6ef4638e-7788-3ef5-98a5-ad5b7f4e02f5"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "date_added": 1663333448439,
                "first_ip": "217.146.128.193",
                "ips_count": 1,
                "last_ip": "217.146.128.193",
                "organization_handles": [
                    "BF359-RIPE",
                    "GHM-RIPE",
                    "ORG-PG203-RIPE",
                    "BZ1613-RIPE",
                    "QSC-NOC",
                    "MW10972-RIPE",
                    "QSC1-RIPE",
                    "RW4876-RIPE",
                    "CV1903",
                    "PLUS-DE",
                    "PLUSNET-LIR"
                ],
                "range_id": "c3255500-d44e-352f-ba6a-b83f185ea892"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448438,
                "first_ip": "217.33.31.24",
                "ips_count": 8,
                "last_ip": "217.33.31.31",
                "organization_handles": [
                    "BTNET-MNT",
                    "CD7018-RIPE",
                    "AR13878-RIPE"
                ],
                "range_id": "f373c1d1-bcbe-322e-8408-feb764ce055d"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448438,
                "first_ip": "216.219.77.96",
                "ips_count": 16,
                "last_ip": "216.219.77.111",
                "organization_handles": [
                    "ENTRI-3",
                    "PSE26-ARIN",
                    "ENTRI-ARIN"
                ],
                "range_id": "6a9aa802-a8c1-3d96-ac34-5370f51eaf33"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448438,
                "first_ip": "216.160.122.120",
                "ips_count": 8,
                "last_ip": "216.160.122.127",
                "organization_handles": [
                    "FSA-11",
                    "IO-ORG-ARIN"
                ],
                "range_id": "d05881bc-7a98-3600-85df-cd0bf7fd897f"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448438,
                "first_ip": "216.27.168.152",
                "ips_count": 8,
                "last_ip": "216.27.168.159",
                "organization_handles": [
                    "C01379342"
                ],
                "range_id": "8649dfb1-8768-370b-9fd4-836024d89142"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448437,
                "first_ip": "216.14.189.176",
                "ips_count": 16,
                "last_ip": "216.14.189.191",
                "organization_handles": [
                    "RCU6-ARIN",
                    "RGS8-ARIN",
                    "GAM43-ARIN",
                    "POPPC-1",
                    "PAI2-ARIN"
                ],
                "range_id": "932019a5-0be3-3306-8cc6-6038b3cd233e"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448437,
                "first_ip": "216.10.237.48",
                "ips_count": 8,
                "last_ip": "216.10.237.55",
                "organization_handles": [
                    "C05805781"
                ],
                "range_id": "35502bfc-bf61-35b0-8d6c-6baa89d45c09"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448437,
                "first_ip": "213.221.18.142",
                "ips_count": 1,
                "last_ip": "213.221.18.142",
                "organization_handles": [
                    "SNK35-RIPE",
                    "ORG-ES15-RIPE",
                    "SVNT1-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT2-RIPE"
                ],
                "range_id": "b6a40889-27b2-3374-94c2-23a607d13f7b"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448437,
                "first_ip": "213.221.7.132",
                "ips_count": 1,
                "last_ip": "213.221.7.132",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SVNT2-RIPE"
                ],
                "range_id": "c136c373-8650-3418-a5e7-ea81507cbff2"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448437,
                "first_ip": "213.221.7.34",
                "ips_count": 1,
                "last_ip": "213.221.7.34",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SVNT2-RIPE"
                ],
                "range_id": "2160df6c-8009-3696-8794-185d312c960b"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "date_added": 1663333448436,
                "first_ip": "213.160.15.168",
                "ips_count": 8,
                "last_ip": "213.160.15.175",
                "organization_handles": [
                    "BF359-RIPE",
                    "GHM-RIPE",
                    "ORG-PG203-RIPE",
                    "BZ1613-RIPE",
                    "QSC-NOC",
                    "MW10972-RIPE",
                    "QSC1-RIPE",
                    "RW4876-RIPE",
                    "CV1903",
                    "PLUS-DE",
                    "PLUSNET-LIR"
                ],
                "range_id": "17da75f2-bb5a-3a56-8da0-e809182345e1"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448436,
                "first_ip": "213.62.189.64",
                "ips_count": 64,
                "last_ip": "213.62.189.127",
                "organization_handles": [
                    "EU-IBM-NIC-MNT",
                    "SB1432-RIPE",
                    "AR13530-RIPE",
                    "MAINT-AS2686"
                ],
                "range_id": "75bd74d9-6751-3c19-b400-789e8adc3303"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448436,
                "first_ip": "213.62.187.48",
                "ips_count": 16,
                "last_ip": "213.62.187.63",
                "organization_handles": [
                    "EU-IBM-NIC-MNT",
                    "AR13530-RIPE",
                    "MAINT-AS2686",
                    "PW373-RIPE",
                    "PT366-RIPE",
                    "EU-IBM-NIC-MNT",
                    "AR13530-RIPE",
                    "MAINT-AS2686"
                ],
                "range_id": "a165bf59-73df-3557-b912-cc1bf38c8acc"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448436,
                "first_ip": "213.62.185.192",
                "ips_count": 64,
                "last_ip": "213.62.185.255",
                "organization_handles": [
                    "EU-IBM-NIC-MNT",
                    "TS10976-RIPE",
                    "AR13530-RIPE",
                    "MAINT-AS2686"
                ],
                "range_id": "aa7c7b2b-7539-307e-90de-40ef864abce2"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448435,
                "first_ip": "213.33.183.115",
                "ips_count": 1,
                "last_ip": "213.33.183.115",
                "organization_handles": [
                    "ORG-ES15-RIPE",
                    "SVNT1-RIPE",
                    "SOVINTEL-MNT",
                    "AN30686-RIPE",
                    "SVNT2-RIPE"
                ],
                "range_id": "a7e4e17d-ebb1-34a8-b6f7-da037f41bd09"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448435,
                "first_ip": "213.33.171.220",
                "ips_count": 1,
                "last_ip": "213.33.171.220",
                "organization_handles": [
                    "ORG-ES15-RIPE",
                    "SVNT1-RIPE",
                    "KI1346-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT2-RIPE"
                ],
                "range_id": "a343cda5-4dbc-3316-ac2e-bb222cc325ef"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448435,
                "first_ip": "213.33.146.41",
                "ips_count": 1,
                "last_ip": "213.33.146.41",
                "organization_handles": [
                    "AVS408-RIPE",
                    "ORG-ES15-RIPE",
                    "SVNT1-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT2-RIPE"
                ],
                "range_id": "4eb59610-aa21-3d16-b2fe-04f4116cd99d"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "date_added": 1663333448435,
                "first_ip": "212.202.236.96",
                "ips_count": 4,
                "last_ip": "212.202.236.99",
                "organization_handles": [
                    "BF359-RIPE",
                    "GHM-RIPE",
                    "ORG-PG203-RIPE",
                    "BZ1613-RIPE",
                    "QSC-NOC",
                    "MW10972-RIPE",
                    "QSC1-RIPE",
                    "RW4876-RIPE",
                    "CV1903",
                    "PLUS-DE",
                    "PLUSNET-LIR"
                ],
                "range_id": "b31c527f-785b-37c9-b2ba-c1057554f5c2"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "date_added": 1663333448435,
                "first_ip": "212.202.117.87",
                "ips_count": 1,
                "last_ip": "212.202.117.87",
                "organization_handles": [
                    "BF359-RIPE",
                    "GHM-RIPE",
                    "ORG-PG203-RIPE",
                    "BZ1613-RIPE",
                    "QSC-NOC",
                    "MW10972-RIPE",
                    "QSC1-RIPE",
                    "RW4876-RIPE",
                    "CV1903",
                    "PLUS-DE",
                    "PLUSNET-LIR"
                ],
                "range_id": "a0d86fcf-16ab-3114-a3e2-f435b656c0c9"
            },
            {
                "active_responsive_ips_count": 6,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448434,
                "first_ip": "212.187.197.248",
                "ips_count": 8,
                "last_ip": "212.187.197.255",
                "organization_handles": [
                    "LEVEL3-MNT",
                    "AR13812-RIPE",
                    "PS20887-RIPE"
                ],
                "range_id": "3d3d611b-b2da-3850-8d29-6f3b1552cc32"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448434,
                "first_ip": "212.119.250.34",
                "ips_count": 1,
                "last_ip": "212.119.250.34",
                "organization_handles": [
                    "ORG-ES15-RIPE",
                    "SVNT1-RIPE",
                    "AA26239-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT2-RIPE"
                ],
                "range_id": "089048a9-da4d-32dd-871c-1f956388ba77"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448434,
                "first_ip": "212.119.241.164",
                "ips_count": 1,
                "last_ip": "212.119.241.164",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SVNT2-RIPE"
                ],
                "range_id": "9e9bf8b3-232e-383e-8efa-63b4ead51890"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448434,
                "first_ip": "212.119.193.34",
                "ips_count": 1,
                "last_ip": "212.119.193.34",
                "organization_handles": [
                    "NM7815-RIPE",
                    "ORG-ES15-RIPE",
                    "SVNT1-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT2-RIPE"
                ],
                "range_id": "31daae58-94fa-3b95-aa1d-9b6c06fb8792"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "date_added": 1663333448433,
                "first_ip": "212.60.209.246",
                "ips_count": 1,
                "last_ip": "212.60.209.246",
                "organization_handles": [
                    "BF359-RIPE",
                    "GHM-RIPE",
                    "ORG-PG203-RIPE",
                    "BZ1613-RIPE",
                    "QSC-NOC",
                    "MW10972-RIPE",
                    "QSC1-RIPE",
                    "RW4876-RIPE",
                    "CV1903",
                    "PLUS-DE",
                    "PLUSNET-LIR"
                ],
                "range_id": "17f816ef-b4c3-330c-ac83-31250b34504f"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448433,
                "first_ip": "212.44.158.89",
                "ips_count": 1,
                "last_ip": "212.44.158.89",
                "organization_handles": [
                    "ORG-ES15-RIPE",
                    "SVNT1-RIPE",
                    "SA38081-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT2-RIPE"
                ],
                "range_id": "bf773fb8-2395-3835-9175-5d86c22a393c"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448433,
                "first_ip": "212.44.139.46",
                "ips_count": 1,
                "last_ip": "212.44.139.46",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SVNT2-RIPE"
                ],
                "range_id": "9527e5ef-5fa5-393a-9451-747822cd1e50"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448433,
                "first_ip": "209.219.204.104",
                "ips_count": 16,
                "last_ip": "209.219.204.119",
                "organization_handles": [
                    "IED6-ARIN",
                    "TRU9",
                    "ZN90-ARIN",
                    "TRU7",
                    "IED5-ARIN",
                    "ZN90-ARIN"
                ],
                "range_id": "589e7967-28e5-3d86-a29a-082295223730"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448432,
                "first_ip": "209.206.211.24",
                "ips_count": 8,
                "last_ip": "209.206.211.31",
                "organization_handles": [
                    "C01915073"
                ],
                "range_id": "ce1d6f51-91fb-30d5-b724-eafd6f15cd0d"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448432,
                "first_ip": "209.115.157.120",
                "ips_count": 8,
                "last_ip": "209.115.157.127",
                "organization_handles": [
                    "C06962808"
                ],
                "range_id": "871d0d29-da75-38bf-9e09-2415fe1200d3"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448432,
                "first_ip": "209.92.240.104",
                "ips_count": 8,
                "last_ip": "209.92.240.111",
                "organization_handles": [
                    "WINDS-6",
                    "GRADY2-ARIN",
                    "WINDS-ARIN",
                    "WINDS1-ARIN"
                ],
                "range_id": "35fe2ae3-eca0-34b6-a208-e32c72fabe83"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448432,
                "first_ip": "208.226.184.0",
                "ips_count": 128,
                "last_ip": "208.226.184.127",
                "organization_handles": [
                    "C00550142"
                ],
                "range_id": "76544531-1d4f-330b-8942-94248a3b5dcf"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448432,
                "first_ip": "208.131.237.16",
                "ips_count": 16,
                "last_ip": "208.131.237.31",
                "organization_handles": [
                    "SSE18-ARIN",
                    "HALMA",
                    "SSE49-ARIN"
                ],
                "range_id": "99e5c6cd-c903-363d-b4ad-3499b64a5c8f"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448431,
                "first_ip": "208.125.32.56",
                "ips_count": 8,
                "last_ip": "208.125.32.63",
                "organization_handles": [
                    "C08337002"
                ],
                "range_id": "178b15ce-ad99-3e2b-8b1a-a6aeff149a8d"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448431,
                "first_ip": "208.124.239.100",
                "ips_count": 4,
                "last_ip": "208.124.239.103",
                "organization_handles": [
                    "C05851024"
                ],
                "range_id": "54aa9441-5f86-3721-9b6f-29d6b935c96a"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448431,
                "first_ip": "208.124.217.248",
                "ips_count": 8,
                "last_ip": "208.124.217.255",
                "organization_handles": [
                    "C02258612"
                ],
                "range_id": "1f6bc450-b6e4-33f3-b09b-7de058997a7b"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448431,
                "first_ip": "208.97.111.168",
                "ips_count": 8,
                "last_ip": "208.97.111.175",
                "organization_handles": [
                    "C02260591"
                ],
                "range_id": "c3f3270e-e4de-36b4-a501-4a595984017c"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448430,
                "first_ip": "208.57.117.240",
                "ips_count": 8,
                "last_ip": "208.57.117.247",
                "organization_handles": [
                    "LSE19-ARIN",
                    "MSDMCD"
                ],
                "range_id": "ec2a44fa-6f94-3765-9e54-a4606ea87547"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448430,
                "first_ip": "208.46.77.88",
                "ips_count": 8,
                "last_ip": "208.46.77.95",
                "organization_handles": [
                    "VSE9-ARIN",
                    "ANDER-66"
                ],
                "range_id": "99b04966-7c3e-3df9-93d3-d41a2f627d61"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448430,
                "first_ip": "208.46.4.120",
                "ips_count": 8,
                "last_ip": "208.46.4.127",
                "organization_handles": [
                    "MCC-563",
                    "BISSE12-ARIN"
                ],
                "range_id": "26206a59-21d8-386b-8811-7b0b6b520ebd"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448430,
                "first_ip": "208.1.76.0",
                "ips_count": 256,
                "last_ip": "208.1.76.255",
                "organization_handles": [
                    "SEARS-1",
                    "HHE34-ARIN"
                ],
                "range_id": "1795fae5-ed7c-3237-a1b3-11ccddb29d23"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448430,
                "first_ip": "207.234.31.224",
                "ips_count": 16,
                "last_ip": "207.234.31.239",
                "organization_handles": [
                    "COGC",
                    "COGEN-ARIN",
                    "ZC108-ARIN",
                    "IPALL-ARIN"
                ],
                "range_id": "82f29bae-f477-370e-9a8a-fb0954e6d121"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448429,
                "first_ip": "207.229.236.64",
                "ips_count": 16,
                "last_ip": "207.229.236.79",
                "organization_handles": [
                    "C00951251"
                ],
                "range_id": "e9bc992b-845e-36be-86c6-b800f33159e0"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448429,
                "first_ip": "207.119.236.96",
                "ips_count": 8,
                "last_ip": "207.119.236.103",
                "organization_handles": [
                    "C02422271"
                ],
                "range_id": "7b968af1-d553-3990-ab8d-c4d888dfbad3"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448429,
                "first_ip": "207.61.90.0",
                "ips_count": 16,
                "last_ip": "207.61.90.15",
                "organization_handles": [
                    "IRRAD-ARIN",
                    "LINX",
                    "ABUSE1127-ARIN",
                    "SOCEV-ARIN",
                    "DHANJ1-ARIN",
                    "ANR1-ARIN",
                    "SYSAD-ARIN",
                    "ABAI1-ARIN"
                ],
                "range_id": "ccaeaac3-6e4c-39a8-ad2a-757471fa2b5a"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448429,
                "first_ip": "206.155.110.128",
                "ips_count": 8,
                "last_ip": "206.155.110.135",
                "organization_handles": [
                    "BUHLE-ARIN",
                    "SHMC-2"
                ],
                "range_id": "36a4ae83-bfc4-321f-9d5e-a4d9c2533575"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448428,
                "first_ip": "206.95.36.0",
                "ips_count": 256,
                "last_ip": "206.95.36.255",
                "organization_handles": [
                    "C00008950"
                ],
                "range_id": "9730f67a-5a30-3706-9202-175db0d7ba15"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448428,
                "first_ip": "206.73.239.64",
                "ips_count": 16,
                "last_ip": "206.73.239.79",
                "organization_handles": [
                    "C02230373"
                ],
                "range_id": "ba34e536-2a7c-3eae-8fa2-020e50d096f7"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448428,
                "first_ip": "206.70.0.0",
                "ips_count": 65536,
                "last_ip": "206.70.255.255",
                "organization_handles": [
                    "ARMP-ARIN",
                    "IPMAN40-ARIN",
                    "IPROU3-ARIN",
                    "AEA8-ARIN",
                    "AT-88-Z",
                    "ANO24-ARIN",
                    "AANO1-ARIN"
                ],
                "range_id": "7843b0e2-b0ae-37aa-9a58-b047a5ff8a13"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448428,
                "first_ip": "206.61.114.0",
                "ips_count": 64,
                "last_ip": "206.61.114.63",
                "organization_handles": [
                    "SWIS1-ARIN",
                    "SIE-ARIN",
                    "SPRINT-NOC-ARIN",
                    "SPRN-Z",
                    "FIUMA2-ARIN",
                    "SWAET-ARIN",
                    "CHUYI-ARIN"
                ],
                "range_id": "328d96ff-ca76-3199-8dfe-ff15eb260b37"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448427,
                "first_ip": "206.31.31.24",
                "ips_count": 8,
                "last_ip": "206.31.31.31",
                "organization_handles": [
                    "SHMC-1",
                    "MORAW2-ARIN"
                ],
                "range_id": "5aeefdf0-25e3-31d6-b3e5-3ff93a1b583c"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448427,
                "first_ip": "206.31.22.96",
                "ips_count": 24,
                "last_ip": "206.31.22.119",
                "organization_handles": [
                    "SEARS-5",
                    "JMO368-ARIN",
                    "JMO391-ARIN",
                    "SEARS-5",
                    "JMO368-ARIN",
                    "JMO391-ARIN"
                ],
                "range_id": "229bdac6-1641-346a-be24-342589903bb5"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448427,
                "first_ip": "206.31.22.72",
                "ips_count": 8,
                "last_ip": "206.31.22.79",
                "organization_handles": [
                    "SEARS-5",
                    "JMO368-ARIN",
                    "JMO391-ARIN"
                ],
                "range_id": "ca996353-06f9-330d-bb30-b4ce2ef32053"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448427,
                "first_ip": "206.31.19.0",
                "ips_count": 256,
                "last_ip": "206.31.19.255",
                "organization_handles": [
                    "SEARS-5",
                    "JMO368-ARIN"
                ],
                "range_id": "f6dd9287-4494-383f-9b8d-7fed3a951377"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448427,
                "first_ip": "206.25.242.104",
                "ips_count": 8,
                "last_ip": "206.25.242.111",
                "organization_handles": [
                    "SHMC-5",
                    "BUHLE3-ARIN"
                ],
                "range_id": "693a1d3c-d477-33c2-8054-5a9bc27a53ec"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448426,
                "first_ip": "206.25.242.64",
                "ips_count": 16,
                "last_ip": "206.25.242.79",
                "organization_handles": [
                    "BUHLE2-ARIN",
                    "SHMC-4"
                ],
                "range_id": "4ba2a741-8533-3095-ba60-4dc257d3ba17"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448426,
                "first_ip": "205.217.5.176",
                "ips_count": 16,
                "last_ip": "205.217.5.191",
                "organization_handles": [
                    "ENTRI-3",
                    "PSE26-ARIN",
                    "ENTRI-ARIN"
                ],
                "range_id": "e4005032-44b2-3b70-848a-db97087350ae"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448426,
                "first_ip": "205.217.4.152",
                "ips_count": 8,
                "last_ip": "205.217.4.159",
                "organization_handles": [
                    "ENTRI-3",
                    "PSE26-ARIN",
                    "ENTRI-ARIN"
                ],
                "range_id": "9d923c7a-f051-3b62-b653-81170ff17a88"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448426,
                "first_ip": "204.238.251.0",
                "ips_count": 256,
                "last_ip": "204.238.251.255",
                "organization_handles": [
                    "JG525-ARIN",
                    "ISSM"
                ],
                "range_id": "0a237ed4-c5a2-317b-9812-243419b76d12"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448425,
                "first_ip": "204.138.50.88",
                "ips_count": 4,
                "last_ip": "204.138.50.91",
                "organization_handles": [
                    "C03394405"
                ],
                "range_id": "232ddbb1-3de1-31cd-aed4-32d9a53cc2bb"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448425,
                "first_ip": "202.84.36.200",
                "ips_count": 8,
                "last_ip": "202.84.36.207",
                "organization_handles": [
                    "IRT-BOL-BD",
                    "AB1162-AP",
                    "BNA20-AP",
                    "MAINT-BD-BOL",
                    "BOC1-AP"
                ],
                "range_id": "55588822-40dc-3fa8-945d-ec7d4991047e"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448425,
                "first_ip": "199.245.184.0",
                "ips_count": 256,
                "last_ip": "199.245.184.255",
                "organization_handles": [
                    "PAULSE",
                    "PS82-ARIN"
                ],
                "range_id": "a705dbb6-1f66-34d0-90fa-9908bc689df4"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448425,
                "first_ip": "199.181.104.0",
                "ips_count": 256,
                "last_ip": "199.181.104.255",
                "organization_handles": [
                    "KS139-ARIN",
                    "OPUSII"
                ],
                "range_id": "b8d070ee-870d-319e-aaf9-ee4700e87e36"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448425,
                "first_ip": "199.101.129.222",
                "ips_count": 1,
                "last_ip": "199.101.129.222",
                "organization_handles": [
                    "CARST4-ARIN",
                    "XN-46",
                    "FROST151-ARIN"
                ],
                "range_id": "2ed225e0-d10f-3276-ac5f-0246a4f9724a"
            },
            {
                "active_responsive_ips_count": 9,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448424,
                "first_ip": "199.48.79.128",
                "ips_count": 64,
                "last_ip": "199.48.79.191",
                "organization_handles": [
                    "C02948824"
                ],
                "range_id": "44f4868f-d83c-344f-9755-2612d09637e5"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448424,
                "first_ip": "198.187.177.0",
                "ips_count": 256,
                "last_ip": "198.187.177.255",
                "organization_handles": [
                    "SSCRCS",
                    "RW20-ARIN"
                ],
                "range_id": "1bbdda10-023a-35f0-b725-fe8724b5ab1d"
            },
            {
                "active_responsive_ips_count": 39,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448424,
                "first_ip": "198.179.146.0",
                "ips_count": 1280,
                "last_ip": "198.179.150.255",
                "organization_handles": [
                    "TK551-ARIN",
                    "SDR",
                    "TK551-ARIN",
                    "SDR-4",
                    "TK551-ARIN",
                    "SDR",
                    "TK551-ARIN",
                    "SDR",
                    "TK551-ARIN",
                    "SDR"
                ],
                "range_id": "6ad9f0b8-72a9-3435-8fad-8b1a70eaa17c"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448423,
                "first_ip": "195.239.243.131",
                "ips_count": 1,
                "last_ip": "195.239.243.131",
                "organization_handles": [
                    "ORG-ES15-RIPE",
                    "SVNT1-RIPE",
                    "SOVINTEL-MNT",
                    "FNV16-RIPE",
                    "SVNT2-RIPE"
                ],
                "range_id": "13317e10-847b-3867-8685-e1aa98486e67"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448423,
                "first_ip": "195.239.216.254",
                "ips_count": 1,
                "last_ip": "195.239.216.254",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SVNT2-RIPE"
                ],
                "range_id": "f3604508-6dd1-3811-9b85-22a909466f25"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448422,
                "first_ip": "195.239.185.5",
                "ips_count": 1,
                "last_ip": "195.239.185.5",
                "organization_handles": [
                    "SSS154-RIPE",
                    "ORG-ES15-RIPE",
                    "SVNT1-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT2-RIPE"
                ],
                "range_id": "f424a12d-a5c6-3ab1-b179-b3d674898c96"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448422,
                "first_ip": "195.239.182.70",
                "ips_count": 1,
                "last_ip": "195.239.182.70",
                "organization_handles": [
                    "ORG-ES15-RIPE",
                    "SVNT1-RIPE",
                    "RV7226-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT2-RIPE"
                ],
                "range_id": "cada51b8-d533-39db-bee7-3c36d75aa5f5"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448422,
                "first_ip": "195.239.149.214",
                "ips_count": 1,
                "last_ip": "195.239.149.214",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SVNT2-RIPE"
                ],
                "range_id": "6bc20932-49ec-3ec1-949d-d0bde2919c09"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448422,
                "first_ip": "195.239.144.186",
                "ips_count": 1,
                "last_ip": "195.239.144.186",
                "organization_handles": [
                    "ORG-ES15-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SVNT2-RIPE",
                    "SVNT1-RIPE",
                    "AS3216-MNT"
                ],
                "range_id": "0a494860-7a95-37a9-a155-29b476c77d66"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448421,
                "first_ip": "195.239.71.52",
                "ips_count": 1,
                "last_ip": "195.239.71.52",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SVNT2-RIPE"
                ],
                "range_id": "e8c77b84-4ba9-3e70-82f7-c0934df13c47"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448421,
                "first_ip": "195.239.67.42",
                "ips_count": 1,
                "last_ip": "195.239.67.42",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SVNT2-RIPE"
                ],
                "range_id": "dacf677c-f282-341d-b83a-945917c1cac8"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448421,
                "first_ip": "195.239.57.170",
                "ips_count": 1,
                "last_ip": "195.239.57.170",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SVNT2-RIPE"
                ],
                "range_id": "60801299-e0bc-3f66-8ee9-61806eedb05a"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448421,
                "first_ip": "195.239.57.94",
                "ips_count": 1,
                "last_ip": "195.239.57.94",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SVNT2-RIPE"
                ],
                "range_id": "ddb65106-ac78-32cc-a3a0-1742de79efa0"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448421,
                "first_ip": "195.239.55.134",
                "ips_count": 1,
                "last_ip": "195.239.55.134",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SVNT2-RIPE"
                ],
                "range_id": "968f2610-34b8-3f25-922a-1010a86dd335"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448420,
                "first_ip": "195.239.35.114",
                "ips_count": 1,
                "last_ip": "195.239.35.114",
                "organization_handles": [
                    "ORG-ES15-RIPE",
                    "SVNT1-RIPE",
                    "EB8881-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT2-RIPE"
                ],
                "range_id": "2772142b-b0b1-3c1b-9d42-2508f3f05d03"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448420,
                "first_ip": "195.222.186.100",
                "ips_count": 1,
                "last_ip": "195.222.186.100",
                "organization_handles": [
                    "ORG-ES15-RIPE",
                    "SVNT1-RIPE",
                    "SOVINTEL-MNT",
                    "BN2575-RIPE",
                    "SVNT2-RIPE"
                ],
                "range_id": "b5460599-43a8-3ba7-bda6-fb0ea38fe443"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448420,
                "first_ip": "195.222.181.53",
                "ips_count": 1,
                "last_ip": "195.222.181.53",
                "organization_handles": [
                    "ORG-ES15-RIPE",
                    "SVNT1-RIPE",
                    "SOVINTEL-MNT",
                    "TN1700-RIPE",
                    "SVNT2-RIPE"
                ],
                "range_id": "0b8cb3aa-cd64-3591-b49c-8bcda0569a4e"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448420,
                "first_ip": "195.212.0.0",
                "ips_count": 16,
                "last_ip": "195.212.0.15",
                "organization_handles": [
                    "MB2864-RIPE",
                    "EU-IBM-NIC-MNT",
                    "AR13530-RIPE",
                    "MAINT-AS2686"
                ],
                "range_id": "25b63226-9f5c-33eb-a6f8-70e6110b6538"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448419,
                "first_ip": "195.183.81.0",
                "ips_count": 32,
                "last_ip": "195.183.81.31",
                "organization_handles": [
                    "EU-IBM-NIC-MNT",
                    "PD127-RIPE",
                    "AR13530-RIPE",
                    "MAINT-AS2686"
                ],
                "range_id": "098a9e3e-4a9b-31f0-abdf-c61741a7d894"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448419,
                "first_ip": "195.183.61.0",
                "ips_count": 64,
                "last_ip": "195.183.61.63",
                "organization_handles": [
                    "EU-IBM-NIC-MNT",
                    "MA1079-RIPE",
                    "AR13530-RIPE",
                    "MAINT-AS2686"
                ],
                "range_id": "9b26dd2c-bba5-3d6c-a3c0-188d8cd02599"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448419,
                "first_ip": "195.157.206.104",
                "ips_count": 8,
                "last_ip": "195.157.206.111",
                "organization_handles": [
                    "AS8426-MNT",
                    "CH309-RIPE",
                    "CH309-RIPE",
                    "ORG-CA48-RIPE"
                ],
                "range_id": "735d84ba-2c06-3e98-87a6-46636ccee9b8"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448419,
                "first_ip": "195.153.34.192",
                "ips_count": 16,
                "last_ip": "195.153.34.207",
                "organization_handles": [
                    "PSINET-UK-SYSADMIN",
                    "AR17873-RIPE",
                    "KW322-RIPE",
                    "REACHUK-MNT"
                ],
                "range_id": "bfcd8547-aa3c-3788-a999-d57d4a91af12"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448418,
                "first_ip": "195.118.127.192",
                "ips_count": 64,
                "last_ip": "195.118.127.255",
                "organization_handles": [
                    "EU-IBM-NIC-MNT",
                    "AR13530-RIPE",
                    "MAINT-AS2686",
                    "DF498-RIPE"
                ],
                "range_id": "03fc6d7e-a8bc-3633-b517-f45e158cbf47"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448418,
                "first_ip": "195.68.188.220",
                "ips_count": 1,
                "last_ip": "195.68.188.220",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SVNT2-RIPE"
                ],
                "range_id": "fe3ac6c1-5e6c-36aa-826b-4529cb8f4c4e"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448418,
                "first_ip": "195.68.168.13",
                "ips_count": 1,
                "last_ip": "195.68.168.13",
                "organization_handles": [
                    "SSV242-RIPE",
                    "ORG-ES15-RIPE",
                    "SVNT1-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT2-RIPE"
                ],
                "range_id": "c055e8f6-83c0-3e17-8043-7c73a917ea53"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448418,
                "first_ip": "195.68.166.251",
                "ips_count": 1,
                "last_ip": "195.68.166.251",
                "organization_handles": [
                    "VVZ30-RIPE",
                    "ORG-ES15-RIPE",
                    "SVNT1-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT2-RIPE"
                ],
                "range_id": "b12479a0-eb71-3ed9-8b7a-42ea9c19116c"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448418,
                "first_ip": "195.68.165.75",
                "ips_count": 1,
                "last_ip": "195.68.165.75",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SVNT2-RIPE"
                ],
                "range_id": "5f90df40-36ec-3434-b4e8-4e78254f20dd"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448417,
                "first_ip": "195.68.153.227",
                "ips_count": 1,
                "last_ip": "195.68.153.227",
                "organization_handles": [
                    "ORG-ES15-RIPE",
                    "SVNT1-RIPE",
                    "SOVINTEL-MNT",
                    "NAZ4-RIPE",
                    "SVNT2-RIPE"
                ],
                "range_id": "1df62e7d-a40b-3155-a83b-7b62b960c45c"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448417,
                "first_ip": "195.68.153.34",
                "ips_count": 1,
                "last_ip": "195.68.153.34",
                "organization_handles": [
                    "ORG-ES15-RIPE",
                    "SVNT1-RIPE",
                    "SOVINTEL-MNT",
                    "BD9650-RIPE",
                    "SVNT2-RIPE"
                ],
                "range_id": "f683c442-a1dd-3dbb-8fe7-36ccda1ae2b2"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448417,
                "first_ip": "195.68.147.38",
                "ips_count": 1,
                "last_ip": "195.68.147.38",
                "organization_handles": [
                    "GI3018-RIPE",
                    "ORG-ES15-RIPE",
                    "SVNT1-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT2-RIPE"
                ],
                "range_id": "80f4a852-e2b7-36b9-b28f-c1a29b36faf6"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448417,
                "first_ip": "195.68.145.155",
                "ips_count": 1,
                "last_ip": "195.68.145.155",
                "organization_handles": [
                    "ORG-ES15-RIPE",
                    "SVNT1-RIPE",
                    "YM1941-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT2-RIPE"
                ],
                "range_id": "9337cc05-15c7-3926-ae91-dbb55980af15"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448416,
                "first_ip": "195.68.131.22",
                "ips_count": 1,
                "last_ip": "195.68.131.22",
                "organization_handles": [
                    "ORG-ES15-RIPE",
                    "SVNT1-RIPE",
                    "VS2745-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT2-RIPE"
                ],
                "range_id": "e47e147f-4436-3b5e-b3e3-29f6613f3312"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448416,
                "first_ip": "195.59.205.0",
                "ips_count": 16,
                "last_ip": "195.59.205.15",
                "organization_handles": [
                    "GSOC-RIPE",
                    "CW-EUROPE-GSOC",
                    "CW-DNS-MNT",
                    "AR40377-RIPE"
                ],
                "range_id": "69c26f54-7f07-331f-b700-5882ab12a5d6"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448416,
                "first_ip": "195.59.203.176",
                "ips_count": 16,
                "last_ip": "195.59.203.191",
                "organization_handles": [
                    "GSOC-RIPE",
                    "CW-EUROPE-GSOC",
                    "CW-DNS-MNT",
                    "AR40377-RIPE"
                ],
                "range_id": "9da67af4-3a1b-3e01-b43f-8a19a9a150bb"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1663333448416,
                "first_ip": "195.53.117.184",
                "ips_count": 8,
                "last_ip": "195.53.117.191",
                "organization_handles": [
                    "JS27349-RIPE",
                    "MAINT-AS3352",
                    "NSYS2-RIPE"
                ],
                "range_id": "3375227a-ba1c-3e32-ae39-756d303f3da3"
            }
        ]
    }
}
```

#### Human Readable Output

>### External IP Address Ranges
>|active_responsive_ips_count|business_units|date_added|first_ip|ips_count|last_ip|organization_handles|range_id|
>|---|---|---|---|---|---|---|---|
>| 0 | jwilkes test - VanDelay Industries | 1663333448439 | 220.241.52.192 | 64 | 220.241.52.255 | MAINT-HK-PCCW-BIA-CS,<br/>BNA2-AP,<br/>TA66-AP | 4da29b7f-3086-3b52-981b-aa8ee5da1e60 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448439 | 217.206.176.80 | 16 | 217.206.176.95 | EH92-RIPE,<br/>AR17615-RIPE,<br/>EASYNET-UK-MNT,<br/>JW372-RIPE | 6ef4638e-7788-3ef5-98a5-ad5b7f4e02f5 |
>| 0 | jwilkes - Toys R US | 1663333448439 | 217.146.128.193 | 1 | 217.146.128.193 | BF359-RIPE,<br/>GHM-RIPE,<br/>ORG-PG203-RIPE,<br/>BZ1613-RIPE,<br/>QSC-NOC,<br/>MW10972-RIPE,<br/>QSC1-RIPE,<br/>RW4876-RIPE,<br/>CV1903,<br/>PLUS-DE,<br/>PLUSNET-LIR | c3255500-d44e-352f-ba6a-b83f185ea892 |
>| 1 | jwilkes test - VanDelay Industries | 1663333448438 | 217.33.31.24 | 8 | 217.33.31.31 | BTNET-MNT,<br/>CD7018-RIPE,<br/>AR13878-RIPE | f373c1d1-bcbe-322e-8408-feb764ce055d |
>| 0 | jwilkes test - VanDelay Industries | 1663333448438 | 216.219.77.96 | 16 | 216.219.77.111 | ENTRI-3,<br/>PSE26-ARIN,<br/>ENTRI-ARIN | 6a9aa802-a8c1-3d96-ac34-5370f51eaf33 |
>| 1 | jwilkes test - VanDelay Industries | 1663333448438 | 216.160.122.120 | 8 | 216.160.122.127 | FSA-11,<br/>IO-ORG-ARIN | d05881bc-7a98-3600-85df-cd0bf7fd897f |
>| 0 | jwilkes test - VanDelay Industries | 1663333448438 | 216.27.168.152 | 8 | 216.27.168.159 | C01379342 | 8649dfb1-8768-370b-9fd4-836024d89142 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448437 | 216.14.189.176 | 16 | 216.14.189.191 | RCU6-ARIN,<br/>RGS8-ARIN,<br/>GAM43-ARIN,<br/>POPPC-1,<br/>PAI2-ARIN | 932019a5-0be3-3306-8cc6-6038b3cd233e |
>| 0 | jwilkes test - VanDelay Industries | 1663333448437 | 216.10.237.48 | 8 | 216.10.237.55 | C05805781 | 35502bfc-bf61-35b0-8d6c-6baa89d45c09 |
>| 1 | jwilkes test - VanDelay Industries | 1663333448437 | 213.221.18.142 | 1 | 213.221.18.142 | SNK35-RIPE,<br/>ORG-ES15-RIPE,<br/>SVNT1-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT2-RIPE | b6a40889-27b2-3374-94c2-23a607d13f7b |
>| 1 | jwilkes test - VanDelay Industries | 1663333448437 | 213.221.7.132 | 1 | 213.221.7.132 | SVNT1-RIPE,<br/>ORG-ES15-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SVNT2-RIPE | c136c373-8650-3418-a5e7-ea81507cbff2 |
>| 1 | jwilkes test - VanDelay Industries | 1663333448437 | 213.221.7.34 | 1 | 213.221.7.34 | SVNT1-RIPE,<br/>ORG-ES15-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SVNT2-RIPE | 2160df6c-8009-3696-8794-185d312c960b |
>| 0 | jwilkes - Toys R US | 1663333448436 | 213.160.15.168 | 8 | 213.160.15.175 | BF359-RIPE,<br/>GHM-RIPE,<br/>ORG-PG203-RIPE,<br/>BZ1613-RIPE,<br/>QSC-NOC,<br/>MW10972-RIPE,<br/>QSC1-RIPE,<br/>RW4876-RIPE,<br/>CV1903,<br/>PLUS-DE,<br/>PLUSNET-LIR | 17da75f2-bb5a-3a56-8da0-e809182345e1 |
>| 0 | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | 1663333448436 | 213.62.189.64 | 64 | 213.62.189.127 | EU-IBM-NIC-MNT,<br/>SB1432-RIPE,<br/>AR13530-RIPE,<br/>MAINT-AS2686 | 75bd74d9-6751-3c19-b400-789e8adc3303 |
>| 0 | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | 1663333448436 | 213.62.187.48 | 16 | 213.62.187.63 | EU-IBM-NIC-MNT,<br/>AR13530-RIPE,<br/>MAINT-AS2686,<br/>PW373-RIPE,<br/>PT366-RIPE,<br/>EU-IBM-NIC-MNT,<br/>AR13530-RIPE,<br/>MAINT-AS2686 | a165bf59-73df-3557-b912-cc1bf38c8acc |
>| 0 | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | 1663333448436 | 213.62.185.192 | 64 | 213.62.185.255 | EU-IBM-NIC-MNT,<br/>TS10976-RIPE,<br/>AR13530-RIPE,<br/>MAINT-AS2686 | aa7c7b2b-7539-307e-90de-40ef864abce2 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448435 | 213.33.183.115 | 1 | 213.33.183.115 | ORG-ES15-RIPE,<br/>SVNT1-RIPE,<br/>SOVINTEL-MNT,<br/>AN30686-RIPE,<br/>SVNT2-RIPE | a7e4e17d-ebb1-34a8-b6f7-da037f41bd09 |
>| 1 | jwilkes test - VanDelay Industries | 1663333448435 | 213.33.171.220 | 1 | 213.33.171.220 | ORG-ES15-RIPE,<br/>SVNT1-RIPE,<br/>KI1346-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT2-RIPE | a343cda5-4dbc-3316-ac2e-bb222cc325ef |
>| 1 | jwilkes test - VanDelay Industries | 1663333448435 | 213.33.146.41 | 1 | 213.33.146.41 | AVS408-RIPE,<br/>ORG-ES15-RIPE,<br/>SVNT1-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT2-RIPE | 4eb59610-aa21-3d16-b2fe-04f4116cd99d |
>| 0 | jwilkes - Toys R US | 1663333448435 | 212.202.236.96 | 4 | 212.202.236.99 | BF359-RIPE,<br/>GHM-RIPE,<br/>ORG-PG203-RIPE,<br/>BZ1613-RIPE,<br/>QSC-NOC,<br/>MW10972-RIPE,<br/>QSC1-RIPE,<br/>RW4876-RIPE,<br/>CV1903,<br/>PLUS-DE,<br/>PLUSNET-LIR | b31c527f-785b-37c9-b2ba-c1057554f5c2 |
>| 1 | jwilkes - Toys R US | 1663333448435 | 212.202.117.87 | 1 | 212.202.117.87 | BF359-RIPE,<br/>GHM-RIPE,<br/>ORG-PG203-RIPE,<br/>BZ1613-RIPE,<br/>QSC-NOC,<br/>MW10972-RIPE,<br/>QSC1-RIPE,<br/>RW4876-RIPE,<br/>CV1903,<br/>PLUS-DE,<br/>PLUSNET-LIR | a0d86fcf-16ab-3114-a3e2-f435b656c0c9 |
>| 6 | jwilkes test - VanDelay Industries | 1663333448434 | 212.187.197.248 | 8 | 212.187.197.255 | LEVEL3-MNT,<br/>AR13812-RIPE,<br/>PS20887-RIPE | 3d3d611b-b2da-3850-8d29-6f3b1552cc32 |
>| 1 | jwilkes test - VanDelay Industries | 1663333448434 | 212.119.250.34 | 1 | 212.119.250.34 | ORG-ES15-RIPE,<br/>SVNT1-RIPE,<br/>AA26239-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT2-RIPE | 089048a9-da4d-32dd-871c-1f956388ba77 |
>| 1 | jwilkes test - VanDelay Industries | 1663333448434 | 212.119.241.164 | 1 | 212.119.241.164 | SVNT1-RIPE,<br/>ORG-ES15-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SVNT2-RIPE | 9e9bf8b3-232e-383e-8efa-63b4ead51890 |
>| 1 | jwilkes test - VanDelay Industries | 1663333448434 | 212.119.193.34 | 1 | 212.119.193.34 | NM7815-RIPE,<br/>ORG-ES15-RIPE,<br/>SVNT1-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT2-RIPE | 31daae58-94fa-3b95-aa1d-9b6c06fb8792 |
>| 0 | jwilkes - Toys R US | 1663333448433 | 212.60.209.246 | 1 | 212.60.209.246 | BF359-RIPE,<br/>GHM-RIPE,<br/>ORG-PG203-RIPE,<br/>BZ1613-RIPE,<br/>QSC-NOC,<br/>MW10972-RIPE,<br/>QSC1-RIPE,<br/>RW4876-RIPE,<br/>CV1903,<br/>PLUS-DE,<br/>PLUSNET-LIR | 17f816ef-b4c3-330c-ac83-31250b34504f |
>| 1 | jwilkes test - VanDelay Industries | 1663333448433 | 212.44.158.89 | 1 | 212.44.158.89 | ORG-ES15-RIPE,<br/>SVNT1-RIPE,<br/>SA38081-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT2-RIPE | bf773fb8-2395-3835-9175-5d86c22a393c |
>| 1 | jwilkes test - VanDelay Industries | 1663333448433 | 212.44.139.46 | 1 | 212.44.139.46 | SVNT1-RIPE,<br/>ORG-ES15-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SVNT2-RIPE | 9527e5ef-5fa5-393a-9451-747822cd1e50 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448433 | 209.219.204.104 | 16 | 209.219.204.119 | IED6-ARIN,<br/>TRU9,<br/>ZN90-ARIN,<br/>TRU7,<br/>IED5-ARIN,<br/>ZN90-ARIN | 589e7967-28e5-3d86-a29a-082295223730 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448432 | 209.206.211.24 | 8 | 209.206.211.31 | C01915073 | ce1d6f51-91fb-30d5-b724-eafd6f15cd0d |
>| 0 | jwilkes test - VanDelay Industries | 1663333448432 | 209.115.157.120 | 8 | 209.115.157.127 | C06962808 | 871d0d29-da75-38bf-9e09-2415fe1200d3 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448432 | 209.92.240.104 | 8 | 209.92.240.111 | WINDS-6,<br/>GRADY2-ARIN,<br/>WINDS-ARIN,<br/>WINDS1-ARIN | 35fe2ae3-eca0-34b6-a208-e32c72fabe83 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448432 | 208.226.184.0 | 128 | 208.226.184.127 | C00550142 | 76544531-1d4f-330b-8942-94248a3b5dcf |
>| 0 | jwilkes test - VanDelay Industries | 1663333448432 | 208.131.237.16 | 16 | 208.131.237.31 | SSE18-ARIN,<br/>HALMA,<br/>SSE49-ARIN | 99e5c6cd-c903-363d-b4ad-3499b64a5c8f |
>| 0 | jwilkes test - VanDelay Industries | 1663333448431 | 208.125.32.56 | 8 | 208.125.32.63 | C08337002 | 178b15ce-ad99-3e2b-8b1a-a6aeff149a8d |
>| 0 | jwilkes test - VanDelay Industries | 1663333448431 | 208.124.239.100 | 4 | 208.124.239.103 | C05851024 | 54aa9441-5f86-3721-9b6f-29d6b935c96a |
>| 0 | jwilkes test - VanDelay Industries | 1663333448431 | 208.124.217.248 | 8 | 208.124.217.255 | C02258612 | 1f6bc450-b6e4-33f3-b09b-7de058997a7b |
>| 0 | jwilkes test - VanDelay Industries | 1663333448431 | 208.97.111.168 | 8 | 208.97.111.175 | C02260591 | c3f3270e-e4de-36b4-a501-4a595984017c |
>| 0 | jwilkes test - VanDelay Industries | 1663333448430 | 208.57.117.240 | 8 | 208.57.117.247 | LSE19-ARIN,<br/>MSDMCD | ec2a44fa-6f94-3765-9e54-a4606ea87547 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448430 | 208.46.77.88 | 8 | 208.46.77.95 | VSE9-ARIN,<br/>ANDER-66 | 99b04966-7c3e-3df9-93d3-d41a2f627d61 |
>| 1 | jwilkes test - VanDelay Industries | 1663333448430 | 208.46.4.120 | 8 | 208.46.4.127 | MCC-563,<br/>BISSE12-ARIN | 26206a59-21d8-386b-8811-7b0b6b520ebd |
>| 0 | jwilkes test - VanDelay Industries | 1663333448430 | 208.1.76.0 | 256 | 208.1.76.255 | SEARS-1,<br/>HHE34-ARIN | 1795fae5-ed7c-3237-a1b3-11ccddb29d23 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448430 | 207.234.31.224 | 16 | 207.234.31.239 | COGC,<br/>COGEN-ARIN,<br/>ZC108-ARIN,<br/>IPALL-ARIN | 82f29bae-f477-370e-9a8a-fb0954e6d121 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448429 | 207.229.236.64 | 16 | 207.229.236.79 | C00951251 | e9bc992b-845e-36be-86c6-b800f33159e0 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448429 | 207.119.236.96 | 8 | 207.119.236.103 | C02422271 | 7b968af1-d553-3990-ab8d-c4d888dfbad3 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448429 | 207.61.90.0 | 16 | 207.61.90.15 | IRRAD-ARIN,<br/>LINX,<br/>ABUSE1127-ARIN,<br/>SOCEV-ARIN,<br/>DHANJ1-ARIN,<br/>ANR1-ARIN,<br/>SYSAD-ARIN,<br/>ABAI1-ARIN | ccaeaac3-6e4c-39a8-ad2a-757471fa2b5a |
>| 0 | jwilkes test - VanDelay Industries | 1663333448429 | 206.155.110.128 | 8 | 206.155.110.135 | BUHLE-ARIN,<br/>SHMC-2 | 36a4ae83-bfc4-321f-9d5e-a4d9c2533575 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448428 | 206.95.36.0 | 256 | 206.95.36.255 | C00008950 | 9730f67a-5a30-3706-9202-175db0d7ba15 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448428 | 206.73.239.64 | 16 | 206.73.239.79 | C02230373 | ba34e536-2a7c-3eae-8fa2-020e50d096f7 |
>| 0 | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | 1663333448428 | 206.70.0.0 | 65536 | 206.70.255.255 | ARMP-ARIN,<br/>IPMAN40-ARIN,<br/>IPROU3-ARIN,<br/>AEA8-ARIN,<br/>AT-88-Z,<br/>ANO24-ARIN,<br/>AANO1-ARIN | 7843b0e2-b0ae-37aa-9a58-b047a5ff8a13 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448428 | 206.61.114.0 | 64 | 206.61.114.63 | SWIS1-ARIN,<br/>SIE-ARIN,<br/>SPRINT-NOC-ARIN,<br/>SPRN-Z,<br/>FIUMA2-ARIN,<br/>SWAET-ARIN,<br/>CHUYI-ARIN | 328d96ff-ca76-3199-8dfe-ff15eb260b37 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448427 | 206.31.31.24 | 8 | 206.31.31.31 | SHMC-1,<br/>MORAW2-ARIN | 5aeefdf0-25e3-31d6-b3e5-3ff93a1b583c |
>| 0 | jwilkes test - VanDelay Industries | 1663333448427 | 206.31.22.96 | 24 | 206.31.22.119 | SEARS-5,<br/>JMO368-ARIN,<br/>JMO391-ARIN,<br/>SEARS-5,<br/>JMO368-ARIN,<br/>JMO391-ARIN | 229bdac6-1641-346a-be24-342589903bb5 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448427 | 206.31.22.72 | 8 | 206.31.22.79 | SEARS-5,<br/>JMO368-ARIN,<br/>JMO391-ARIN | ca996353-06f9-330d-bb30-b4ce2ef32053 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448427 | 206.31.19.0 | 256 | 206.31.19.255 | SEARS-5,<br/>JMO368-ARIN | f6dd9287-4494-383f-9b8d-7fed3a951377 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448427 | 206.25.242.104 | 8 | 206.25.242.111 | SHMC-5,<br/>BUHLE3-ARIN | 693a1d3c-d477-33c2-8054-5a9bc27a53ec |
>| 0 | jwilkes test - VanDelay Industries | 1663333448426 | 206.25.242.64 | 16 | 206.25.242.79 | BUHLE2-ARIN,<br/>SHMC-4 | 4ba2a741-8533-3095-ba60-4dc257d3ba17 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448426 | 205.217.5.176 | 16 | 205.217.5.191 | ENTRI-3,<br/>PSE26-ARIN,<br/>ENTRI-ARIN | e4005032-44b2-3b70-848a-db97087350ae |
>| 0 | jwilkes test - VanDelay Industries | 1663333448426 | 205.217.4.152 | 8 | 205.217.4.159 | ENTRI-3,<br/>PSE26-ARIN,<br/>ENTRI-ARIN | 9d923c7a-f051-3b62-b653-81170ff17a88 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448426 | 204.238.251.0 | 256 | 204.238.251.255 | JG525-ARIN,<br/>ISSM | 0a237ed4-c5a2-317b-9812-243419b76d12 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448425 | 204.138.50.88 | 4 | 204.138.50.91 | C03394405 | 232ddbb1-3de1-31cd-aed4-32d9a53cc2bb |
>| 1 | jwilkes test - VanDelay Industries | 1663333448425 | 202.84.36.200 | 8 | 202.84.36.207 | IRT-BOL-BD,<br/>AB1162-AP,<br/>BNA20-AP,<br/>MAINT-BD-BOL,<br/>BOC1-AP | 55588822-40dc-3fa8-945d-ec7d4991047e |
>| 0 | jwilkes test - VanDelay Industries | 1663333448425 | 199.245.184.0 | 256 | 199.245.184.255 | PAULSE,<br/>PS82-ARIN | a705dbb6-1f66-34d0-90fa-9908bc689df4 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448425 | 199.181.104.0 | 256 | 199.181.104.255 | KS139-ARIN,<br/>OPUSII | b8d070ee-870d-319e-aaf9-ee4700e87e36 |
>| 1 | jwilkes test - VanDelay Industries | 1663333448425 | 199.101.129.222 | 1 | 199.101.129.222 | CARST4-ARIN,<br/>XN-46,<br/>FROST151-ARIN | 2ed225e0-d10f-3276-ac5f-0246a4f9724a |
>| 9 | jwilkes test - VanDelay Industries | 1663333448424 | 199.48.79.128 | 64 | 199.48.79.191 | C02948824 | 44f4868f-d83c-344f-9755-2612d09637e5 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448424 | 198.187.177.0 | 256 | 198.187.177.255 | SSCRCS,<br/>RW20-ARIN | 1bbdda10-023a-35f0-b725-fe8724b5ab1d |
>| 39 | jwilkes test - VanDelay Industries | 1663333448424 | 198.179.146.0 | 1280 | 198.179.150.255 | TK551-ARIN,<br/>SDR,<br/>TK551-ARIN,<br/>SDR-4,<br/>TK551-ARIN,<br/>SDR,<br/>TK551-ARIN,<br/>SDR,<br/>TK551-ARIN,<br/>SDR | 6ad9f0b8-72a9-3435-8fad-8b1a70eaa17c |
>| 0 | jwilkes test - VanDelay Industries | 1663333448423 | 195.239.243.131 | 1 | 195.239.243.131 | ORG-ES15-RIPE,<br/>SVNT1-RIPE,<br/>SOVINTEL-MNT,<br/>FNV16-RIPE,<br/>SVNT2-RIPE | 13317e10-847b-3867-8685-e1aa98486e67 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448423 | 195.239.216.254 | 1 | 195.239.216.254 | SVNT1-RIPE,<br/>ORG-ES15-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SVNT2-RIPE | f3604508-6dd1-3811-9b85-22a909466f25 |
>| 1 | jwilkes test - VanDelay Industries | 1663333448422 | 195.239.185.5 | 1 | 195.239.185.5 | SSS154-RIPE,<br/>ORG-ES15-RIPE,<br/>SVNT1-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT2-RIPE | f424a12d-a5c6-3ab1-b179-b3d674898c96 |
>| 1 | jwilkes test - VanDelay Industries | 1663333448422 | 195.239.182.70 | 1 | 195.239.182.70 | ORG-ES15-RIPE,<br/>SVNT1-RIPE,<br/>RV7226-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT2-RIPE | cada51b8-d533-39db-bee7-3c36d75aa5f5 |
>| 1 | jwilkes test - VanDelay Industries | 1663333448422 | 195.239.149.214 | 1 | 195.239.149.214 | SVNT1-RIPE,<br/>ORG-ES15-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SVNT2-RIPE | 6bc20932-49ec-3ec1-949d-d0bde2919c09 |
>| 1 | jwilkes test - VanDelay Industries | 1663333448422 | 195.239.144.186 | 1 | 195.239.144.186 | ORG-ES15-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SVNT2-RIPE,<br/>SVNT1-RIPE,<br/>AS3216-MNT | 0a494860-7a95-37a9-a155-29b476c77d66 |
>| 1 | jwilkes test - VanDelay Industries | 1663333448421 | 195.239.71.52 | 1 | 195.239.71.52 | SVNT1-RIPE,<br/>ORG-ES15-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SVNT2-RIPE | e8c77b84-4ba9-3e70-82f7-c0934df13c47 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448421 | 195.239.67.42 | 1 | 195.239.67.42 | SVNT1-RIPE,<br/>ORG-ES15-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SVNT2-RIPE | dacf677c-f282-341d-b83a-945917c1cac8 |
>| 1 | jwilkes test - VanDelay Industries | 1663333448421 | 195.239.57.170 | 1 | 195.239.57.170 | SVNT1-RIPE,<br/>ORG-ES15-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SVNT2-RIPE | 60801299-e0bc-3f66-8ee9-61806eedb05a |
>| 1 | jwilkes test - VanDelay Industries | 1663333448421 | 195.239.57.94 | 1 | 195.239.57.94 | SVNT1-RIPE,<br/>ORG-ES15-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SVNT2-RIPE | ddb65106-ac78-32cc-a3a0-1742de79efa0 |
>| 1 | jwilkes test - VanDelay Industries | 1663333448421 | 195.239.55.134 | 1 | 195.239.55.134 | SVNT1-RIPE,<br/>ORG-ES15-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SVNT2-RIPE | 968f2610-34b8-3f25-922a-1010a86dd335 |
>| 1 | jwilkes test - VanDelay Industries | 1663333448420 | 195.239.35.114 | 1 | 195.239.35.114 | ORG-ES15-RIPE,<br/>SVNT1-RIPE,<br/>EB8881-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT2-RIPE | 2772142b-b0b1-3c1b-9d42-2508f3f05d03 |
>| 1 | jwilkes test - VanDelay Industries | 1663333448420 | 195.222.186.100 | 1 | 195.222.186.100 | ORG-ES15-RIPE,<br/>SVNT1-RIPE,<br/>SOVINTEL-MNT,<br/>BN2575-RIPE,<br/>SVNT2-RIPE | b5460599-43a8-3ba7-bda6-fb0ea38fe443 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448420 | 195.222.181.53 | 1 | 195.222.181.53 | ORG-ES15-RIPE,<br/>SVNT1-RIPE,<br/>SOVINTEL-MNT,<br/>TN1700-RIPE,<br/>SVNT2-RIPE | 0b8cb3aa-cd64-3591-b49c-8bcda0569a4e |
>| 0 | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | 1663333448420 | 195.212.0.0 | 16 | 195.212.0.15 | MB2864-RIPE,<br/>EU-IBM-NIC-MNT,<br/>AR13530-RIPE,<br/>MAINT-AS2686 | 25b63226-9f5c-33eb-a6f8-70e6110b6538 |
>| 0 | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | 1663333448419 | 195.183.81.0 | 32 | 195.183.81.31 | EU-IBM-NIC-MNT,<br/>PD127-RIPE,<br/>AR13530-RIPE,<br/>MAINT-AS2686 | 098a9e3e-4a9b-31f0-abdf-c61741a7d894 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448419 | 195.183.61.0 | 64 | 195.183.61.63 | EU-IBM-NIC-MNT,<br/>MA1079-RIPE,<br/>AR13530-RIPE,<br/>MAINT-AS2686 | 9b26dd2c-bba5-3d6c-a3c0-188d8cd02599 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448419 | 195.157.206.104 | 8 | 195.157.206.111 | AS8426-MNT,<br/>CH309-RIPE,<br/>CH309-RIPE,<br/>ORG-CA48-RIPE | 735d84ba-2c06-3e98-87a6-46636ccee9b8 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448419 | 195.153.34.192 | 16 | 195.153.34.207 | PSINET-UK-SYSADMIN,<br/>AR17873-RIPE,<br/>KW322-RIPE,<br/>REACHUK-MNT | bfcd8547-aa3c-3788-a999-d57d4a91af12 |
>| 0 | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | 1663333448418 | 195.118.127.192 | 64 | 195.118.127.255 | EU-IBM-NIC-MNT,<br/>AR13530-RIPE,<br/>MAINT-AS2686,<br/>DF498-RIPE | 03fc6d7e-a8bc-3633-b517-f45e158cbf47 |
>| 1 | jwilkes test - VanDelay Industries | 1663333448418 | 195.68.188.220 | 1 | 195.68.188.220 | SVNT1-RIPE,<br/>ORG-ES15-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SVNT2-RIPE | fe3ac6c1-5e6c-36aa-826b-4529cb8f4c4e |
>| 1 | jwilkes test - VanDelay Industries | 1663333448418 | 195.68.168.13 | 1 | 195.68.168.13 | SSV242-RIPE,<br/>ORG-ES15-RIPE,<br/>SVNT1-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT2-RIPE | c055e8f6-83c0-3e17-8043-7c73a917ea53 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448418 | 195.68.166.251 | 1 | 195.68.166.251 | VVZ30-RIPE,<br/>ORG-ES15-RIPE,<br/>SVNT1-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT2-RIPE | b12479a0-eb71-3ed9-8b7a-42ea9c19116c |
>| 1 | jwilkes test - VanDelay Industries | 1663333448418 | 195.68.165.75 | 1 | 195.68.165.75 | SVNT1-RIPE,<br/>ORG-ES15-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SVNT2-RIPE | 5f90df40-36ec-3434-b4e8-4e78254f20dd |
>| 1 | jwilkes test - VanDelay Industries | 1663333448417 | 195.68.153.227 | 1 | 195.68.153.227 | ORG-ES15-RIPE,<br/>SVNT1-RIPE,<br/>SOVINTEL-MNT,<br/>NAZ4-RIPE,<br/>SVNT2-RIPE | 1df62e7d-a40b-3155-a83b-7b62b960c45c |
>| 0 | jwilkes test - VanDelay Industries | 1663333448417 | 195.68.153.34 | 1 | 195.68.153.34 | ORG-ES15-RIPE,<br/>SVNT1-RIPE,<br/>SOVINTEL-MNT,<br/>BD9650-RIPE,<br/>SVNT2-RIPE | f683c442-a1dd-3dbb-8fe7-36ccda1ae2b2 |
>| 0 | jwilkes test - VanDelay Industries | 1663333448417 | 195.68.147.38 | 1 | 195.68.147.38 | GI3018-RIPE,<br/>ORG-ES15-RIPE,<br/>SVNT1-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT2-RIPE | 80f4a852-e2b7-36b9-b28f-c1a29b36faf6 |
>| 1 | jwilkes test - VanDelay Industries | 1663333448417 | 195.68.145.155 | 1 | 195.68.145.155 | ORG-ES15-RIPE,<br/>SVNT1-RIPE,<br/>YM1941-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT2-RIPE | 9337cc05-15c7-3926-ae91-dbb55980af15 |
>| 1 | jwilkes test - VanDelay Industries | 1663333448416 | 195.68.131.22 | 1 | 195.68.131.22 | ORG-ES15-RIPE,<br/>SVNT1-RIPE,<br/>VS2745-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT2-RIPE | e47e147f-4436-3b5e-b3e3-29f6613f3312 |
>| 0 | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | 1663333448416 | 195.59.205.0 | 16 | 195.59.205.15 | GSOC-RIPE,<br/>CW-EUROPE-GSOC,<br/>CW-DNS-MNT,<br/>AR40377-RIPE | 69c26f54-7f07-331f-b700-5882ab12a5d6 |
>| 0 | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | 1663333448416 | 195.59.203.176 | 16 | 195.59.203.191 | GSOC-RIPE,<br/>CW-EUROPE-GSOC,<br/>CW-DNS-MNT,<br/>AR40377-RIPE | 9da67af4-3a1b-3e01-b43f-8a19a9a150bb |
>| 0 | jwilkes test - VanDelay Industries | 1663333448416 | 195.53.117.184 | 8 | 195.53.117.191 | JS27349-RIPE,<br/>MAINT-AS3352,<br/>NSYS2-RIPE | 3375227a-ba1c-3e32-ae39-756d303f3da3 |


### asm-getexternalipaddressrange
***
Get external IP address range details according to the range IDs.


#### Base Command

`asm-getexternalipaddressrange`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range_id | A string representing the range ID for which you want to get the details for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.GetExternalIpAddressRange.range_id | String | External IP address range UUID | 
| ASM.GetExternalIpAddressRange.first_ip | String | First IP address of external IP address range | 
| ASM.GetExternalIpAddressRange.last_ip | String | Last IP address of external IP address range | 
| ASM.GetExternalIpAddressRange.ips_count | Number | Number of IP addresses of external IP address range | 
| ASM.GetExternalIpAddressRange.active_responsive_ips_count | Number | How many IPs in external address range are actively responsive | 
| ASM.GetExternalIpAddressRange.date_added | Date | Date the external IP address range was added | 
| ASM.GetExternalIpAddressRange.business_units | String | External IP address range associated business units | 
| ASM.GetExternalIpAddressRange.organization_handles | String | External IP address range associated organization handles | 
| ASM.GetExternalIpAddressRange.details | String | Additional information | 

#### Command example
```!asm-getexternalipaddressrange range_id=4da29b7f-3086-3b52-981b-aa8ee5da1e60```
#### Context Example
```json
{
    "ASM": {
        "GetExternalIpAddressRange": {
            "active_responsive_ips_count": 0,
            "business_units": [
                "jwilkes test - VanDelay Industries"
            ],
            "date_added": 1663333448439,
            "details": {
                "networkRecords": [
                    {
                        "firstIp": "220.241.52.192",
                        "handle": "220.241.52.192 - 220.241.52.255",
                        "lastChanged": 1663332663411,
                        "lastIp": "220.241.52.255",
                        "name": "SEARS-HK",
                        "organizationRecords": [
                            {
                                "address": "",
                                "dateAdded": 1663331807846,
                                "email": "noc@imsbiz.com",
                                "firstRegistered": null,
                                "formattedName": "",
                                "handle": "MAINT-HK-PCCW-BIA-CS",
                                "kind": "group",
                                "lastChanged": null,
                                "org": "",
                                "phone": "",
                                "remarks": "",
                                "roles": [
                                    "registrant"
                                ]
                            },
                            {
                                "address": "27/F, PCCW Tower, Taikoo Place,\n979 King's Road, Quarry Bay, HK          ",
                                "dateAdded": 1663331807846,
                                "email": "cs@imsbiz.com",
                                "firstRegistered": 1220514857000,
                                "formattedName": "BIZ NETVIGATOR ADMINISTRATORS",
                                "handle": "BNA2-AP",
                                "kind": "group",
                                "lastChanged": 1514892767000,
                                "org": "",
                                "phone": "+852-2888-6932",
                                "remarks": "",
                                "roles": [
                                    "administrative"
                                ]
                            },
                            {
                                "address": "HKT Limited\nPO Box 9896 GPO          ",
                                "dateAdded": 1663331807846,
                                "email": "noc@imsbiz.com",
                                "firstRegistered": 1220514856000,
                                "formattedName": "TECHNICAL ADMINISTRATORS",
                                "handle": "TA66-AP",
                                "kind": "group",
                                "lastChanged": 1468555410000,
                                "org": "",
                                "phone": "+852-2883-5151",
                                "remarks": "",
                                "roles": [
                                    "technical"
                                ]
                            }
                        ],
                        "remarks": "Sears Holdings Global Sourcing Ltd",
                        "whoIsServer": "whois.apnic.net"
                    }
                ]
            },
            "first_ip": "220.241.52.192",
            "ips_count": 64,
            "last_ip": "220.241.52.255",
            "organization_handles": [
                "MAINT-HK-PCCW-BIA-CS",
                "BNA2-AP",
                "TA66-AP"
            ],
            "range_id": "4da29b7f-3086-3b52-981b-aa8ee5da1e60"
        }
    }
}
```

#### Human Readable Output

>### External IP Address Range
>|active_responsive_ips_count|business_units|date_added|details|first_ip|ips_count|last_ip|organization_handles|range_id|
>|---|---|---|---|---|---|---|---|---|
>| 0 | jwilkes test - VanDelay Industries | 1663333448439 | networkRecords: {'handle': '220.241.52.192 - 220.241.52.255', 'firstIp': '220.241.52.192', 'lastIp': '220.241.52.255', 'name': 'SEARS-HK', 'whoIsServer': 'whois.apnic.net', 'lastChanged': 1663332663411, 'organizationRecords': [{'handle': 'MAINT-HK-PCCW-BIA-CS', 'dateAdded': 1663331807846, 'address': '', 'email': 'noc@imsbiz.com', 'phone': '', 'org': '', 'formattedName': '', 'kind': 'group', 'roles': ['registrant'], 'lastChanged': None, 'firstRegistered': None, 'remarks': ''}, {'handle': 'BNA2-AP', 'dateAdded': 1663331807846, 'address': "27/F, PCCW Tower, Taikoo Place,\n979 King's Road, Quarry Bay, HK          ", 'email': 'cs@imsbiz.com', 'phone': '+852-2888-6932', 'org': '', 'formattedName': 'BIZ NETVIGATOR ADMINISTRATORS', 'kind': 'group', 'roles': ['administrative'], 'lastChanged': 1514892767000, 'firstRegistered': 1220514857000, 'remarks': ''}, {'handle': 'TA66-AP', 'dateAdded': 1663331807846, 'address': 'HKT Limited\nPO Box 9896 GPO          ', 'email': 'noc@imsbiz.com', 'phone': '+852-2883-5151', 'org': '', 'formattedName': 'TECHNICAL ADMINISTRATORS', 'kind': 'group', 'roles': ['technical'], 'lastChanged': 1468555410000, 'firstRegistered': 1220514856000, 'remarks': ''}], 'remarks': 'Sears Holdings Global Sourcing Ltd'} | 220.241.52.192 | 64 | 220.241.52.255 | MAINT-HK-PCCW-BIA-CS,<br/>BNA2-AP,<br/>TA66-AP | 4da29b7f-3086-3b52-981b-aa8ee5da1e60 |


### asm-getassetsinternetexposure
***
Get a list of all your Internet exposure filtered by ip address, domain, type, and/or if there is an active external service. Maximum result limit is 100 assets.


#### Base Command

`asm-getassetsinternetexposure`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | IP Address to search on. | Optional | 
| name | name of asset to search on. | Optional | 
| type | type of external service. Possible values are: certificate, cloud_compute_instance, on_prem, domain, unassociated_responsive_ip. | Optional | 
| has_active_external_services | does the internet exposure have an active external service. Possible values are: yes, no. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.GetAssetsInternetExposure.asm_ids | String | Attack surface managment UUID | 
| ASM.GetAssetsInternetExposure.name | String | Name of the exposed asset | 
| ASM.GetAssetsInternetExposure.asset_type | String | Type of the exposed asset | 
| ASM.GetAssetsInternetExposure.cloud_provider | Unknown | The cloud provider used to collect these cloud assets as either GCP, AWS, or Azure | 
| ASM.GetAssetsInternetExposure.region | Unknown | Displays the region as provided by the Cloud provider | 
| ASM.GetAssetsInternetExposure.last_observed | Unknown | Last time exposure was observed | 
| ASM.GetAssetsInternetExposure.first_observed | Unknown | First time exposure was observed | 
| ASM.GetAssetsInternetExposure.has_active_externally_services | Boolean | If the internet exposure is associated with active external service\(s\) | 
| ASM.GetAssetsInternetExposure.has_xdr_agent | String | If the internet exposure asset has an XDR agent | 
| ASM.GetAssetsInternetExposure.cloud_id | Unknown | Displays the Resource ID as provided from the cloud provider | 
| ASM.GetAssetsInternetExposure.domain_resolves | Boolean | is the asset domain resolvable | 
| ASM.GetAssetsInternetExposure.operation_system | Unknown | The operang system reported by the source for this asset | 
| ASM.GetAssetsInternetExposure.agent_id | Unknown | If there is an endpoint installed on this asset, this is the endpoint ID | 
| ASM.GetAssetsInternetExposure.externally_detected_providers | String | The provider of the asset as determined by an external assessment | 
| ASM.GetAssetsInternetExposure.service_type | String | Type of asset | 
| ASM.GetAssetsInternetExposure.externally_inferred_cves | String | If the internet exposure has associated CVEs | 
| ASM.GetAssetsInternetExposure.ips | String | IP addresses associated wih the internet exposure | 

#### Command example
```!asm-getassetsinternetexposure```
#### Context Example
```json
{
    "ASM": {
        "GetAssetsInternetExposure": [
            {
                "agent_id": null,
                "asm_ids": [
                    "3c176460-8735-333c-b618-8262e2fb660c"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA1withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired",
                    "InsecureSignature"
                ],
                "certificate_issuer": "Thawte",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.babiesrus.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "43164fde-8e87-3d1e-8530-82f14cd3ae9a"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "COMODO",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.ch3.intra.kmart.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "2e560b90-bd0c-3c5f-b075-7cf0c7b68860"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "COMODO",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.ch3.intra.sears.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "3554f7cc-c9ad-3ca5-9fd4-5b6e4f206142"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "COMODO",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.ch4.intra.sears.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "96e780ca-5c06-3e6b-8db3-dc58a34da339"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.craftsman.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "c2360474-2800-379c-852c-ed4ad141a8b6"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.craftsman.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "eec66ec2-5a7d-395a-860c-d83362100d8a"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.craftsman.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "1387c574-5a18-3832-8784-42cf9f207c3b"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "COMODO",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.craftsman.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "30c16061-1910-3814-8fd1-669bcde67340"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "COMODO",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.diehard.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "cfa1cd5a-77f1-3963-8557-7f652309a143"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "LongExpiration",
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.digital-dev.toysrus.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "78a11e94-58a9-329c-99ca-e527d2db6cfb"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "LongExpiration",
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.digital-prod.toysrus.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "b5363eb5-775a-33f5-ab51-70f73657737e"
                ],
                "asm_va_score": 7.5,
                "asset_type": "DOMAIN",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": null,
                "certificate_classifications": [],
                "certificate_issuer": null,
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": true,
                "externally_detected_providers": [
                    "Other"
                ],
                "externally_inferred_cves": [
                    "CVE-2017-9229",
                    "CVE-2019-9638",
                    "CVE-2007-6422"
                ],
                "first_observed": 1659344376992,
                "has_active_externally_services": true,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": 1663216568137,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.enron.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": [
                    "HttpServer"
                ]
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "c35f103c-140d-3318-bac1-057bc4496480"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.fitstudio.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "ec8caf82-f0f0-31ff-aa42-f227a1a4393e"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.fitstudio.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "d27c2415-19a2-3022-bf0c-8d6e9879311e"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.fitstudio.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "1b346ded-7761-3969-99b2-2ebbc8b324b2"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.fitstudio.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "e220e39a-5566-3dff-987d-915454b96914"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.kenmore.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "934ae8e0-3154-3000-a7b2-72a1293d6bd8"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.kenmore.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "84727397-a158-3fc8-baae-f831ccac9c90"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.kenmore.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "a7c56b7c-390b-32a7-aa32-95413cd62708"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "COMODO",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.kenmore.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "03a6de65-ccb9-3e8d-9dfe-3b944e226801"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.kenmore.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "553845cf-d1f1-353b-b122-1b5b499c238f"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.kenmore.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "b28d461b-aadd-3aed-b96f-81a40eba2cab"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Corporation Service Company",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.kenmorepowercord.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "e526a199-d558-319b-b81a-04d26cb30198"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.kmart.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "7d2c1a14-b223-329b-aa75-dd19f19a5f77"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.kmart.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "f30e9117-c521-36fa-9711-83ff3428489d"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.kmart.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "4b8d8ddb-fcae-30c8-9a23-ae857a4d156c"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.kmart.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "7c327b5f-443c-3934-8a85-b0d095075a39"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.managemyhome.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "7997f043-d5fa-3c6b-90f0-6e86a4bdac9f"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.managemyhome.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "b92751d5-e83c-3714-bd78-1a84f0f532b6"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.managemyhome.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "daa76a92-52be-3ab9-8626-4737136010f9"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.managemyhome.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "d5943d48-ba3b-3bff-90cc-b074570df21f"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.managemylife.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "76d52f2d-a51a-3ce7-9c41-a17b4b8ac1b3"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.managemylife.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "cd0f03dc-d795-3e3f-80c9-9072f551017c"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.managemylife.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "ce4bfd78-951e-321b-a1c6-94e5e89791fd"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.mygofer.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "c11817ab-a51c-39f8-ba53-5cdcd967f898"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.mygofer.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "5362a102-d620-32c8-b931-8c9a0dc237e4"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.mygofer.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "115a21e1-04d1-359f-80a9-02cd5d491dba"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.mykmart.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "2f340816-d1c4-3f00-95c2-b2ea3b49f503"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.mykmart.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "6e9fef73-0838-3be3-8185-a414520491be"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.mykmart.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "50bcf89e-31cf-3081-a441-0e723985be11"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.mykmart.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "4b1f3765-de40-3a1a-8535-667420408fd9"
                ],
                "asm_va_score": null,
                "asset_type": "DOMAIN",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": null,
                "certificate_classifications": [],
                "certificate_issuer": null,
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": true,
                "externally_detected_providers": [
                    "Akamai Technologies"
                ],
                "externally_inferred_cves": [],
                "first_observed": 1659326177977,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": 1663233661703,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.pets.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "71c98bcc-6480-3d8a-86cf-76a5fdf75586"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA512withRSA",
                "certificate_classifications": [
                    "LongExpiration",
                    "Wildcard"
                ],
                "certificate_issuer": "Sears Holdings Corp.",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [
                    "Other"
                ],
                "externally_inferred_cves": [],
                "first_observed": 1659409579000,
                "has_active_externally_services": true,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": 1663060444000,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.prod.ch3.s.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": [
                    "HttpServer"
                ]
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "7aeb1046-ca32-3361-8816-1509bd589e61"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA512withRSA",
                "certificate_classifications": [
                    "LongExpiration",
                    "Wildcard"
                ],
                "certificate_issuer": "Sears Holdings Corp.",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.prod.ch4.s.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "4fda9fd7-5a27-310b-beb0-3a0a04bf8ceb"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA512withRSA",
                "certificate_classifications": [
                    "LongExpiration",
                    "Wildcard"
                ],
                "certificate_issuer": "Sears Holdings Corp.",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.prod.global.s.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "a0d338d0-46f4-371e-bc04-fde201e1f2d5"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.sears.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "93bbbda3-16f3-3f6f-b736-688fe2d564c8"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.sears.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "e0d802fd-e70d-375c-9dc7-04ab3ab3a67d"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.sears.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "277e4d9e-8f38-3b90-8f73-19243006e922"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [
                    "MCI Communications",
                    "Other"
                ],
                "externally_inferred_cves": [],
                "first_observed": 1659380449000,
                "has_active_externally_services": true,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": 1663310153000,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.sears.com.mx",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": [
                    "HttpServer"
                ]
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "89b782d2-10dd-3f0c-8cc5-c3fab0655bf9"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.sears.com.pr",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "011ade11-ab27-3484-ab80-fe14a4180ab8"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.sears.com.pr",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "7208e284-c582-368b-a769-d1604d726bd9"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.sears.com.pr",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "47f620b7-5016-369d-be42-7286430d7c92"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.sears.com.pr",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "946dbb7d-a002-3e5f-82cf-935943ddd753"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "LongExpiration",
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Network Solutions",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.searshomepro.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "7fee6dfd-15b8-3d29-95f5-452053b771c5"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.searshomeservices.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "47ed7048-0332-3934-a758-817ad0e95b60"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.searshomeservices.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "9351ee34-d666-3fc7-9456-620ca78c43d9"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.searshomeservices.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "c4dfa2b7-7bda-3d64-99ba-868264fa5a0f"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.searshomeservices.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "efc211f0-2501-3654-9e7a-105fd22f594e"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "COMODO",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.searshomeservices.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "3a8489ed-86c8-33cd-9314-315e3e010bfa"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.searsoutlet.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "7184d7ee-6dcd-3f4e-adc7-c529550eef56"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.searsoutlet.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "2c85d4be-e6e6-3bee-86bd-5fd295c83d91"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.searsoutlet.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "b460cbd5-af03-33d8-85c6-4a06c9efc8a4"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.searsoutlet.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "33624b71-c4e6-31d9-96ab-ca203e2bbc53"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.searspartsdirect.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "ae996f2d-704c-342d-b00f-fb9f3a3f217d"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.searspartsdirect.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "940e8985-0604-360d-a651-b1da052eddbe"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.searspartsdirect.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "f2d897ee-1cdc-3f8b-8f50-5f99c5307960"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.searspartsdirect.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "533e0b7a-e296-3502-9208-05b37732501c"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "LongExpiration",
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Network Solutions",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.searssiding.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "b09526c1-e395-35a2-9246-a6f25d2189b3"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "COMODO",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.segnosystems.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "08ced839-21bf-3cc3-8143-e997ad503f88"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.shld.net",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "0fd301cd-ccf9-31ed-90c6-bf5a08b3ebee"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.shld.net",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "5185bd8a-154d-3d3a-b73d-22e5ad2c805b"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.shld.net",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "ef70c2ac-b116-334c-9922-1644805e0933"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.shopyourway.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "8f9b7cd2-f2cc-3b4a-aacb-4aaf41144ee4"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.shopyourway.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "4b218587-1e8b-386c-97b9-d411b9a93c1c"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.shopyourway.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "1832890e-5b02-3db9-b288-fdd935422b8a"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "COMODO",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "first_observed": 1659230429000,
                "has_active_externally_services": true,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": 1663321313000,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.shs-core.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": [
                    "HttpServer"
                ]
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "55275c3e-eb2e-3608-893c-1f2ed3447ea5"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "COMODO",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.shs.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "334367df-a131-307a-a597-e85cb1a6be34"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.social.sears.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "cdbcd67b-fb54-39e4-b9b7-c53d3fe421f9"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.social.sears.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "89c864f4-c816-34ae-812d-73a16a8c1059"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.social.sears.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "451f3622-0219-3675-b9e7-b9db3730c678"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.social.sears.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "5309a09b-7670-3602-a5bd-e620a9e39bae"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.sywspeedplatform.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "0dff4458-c9bc-313d-a299-71bde25fe7b3"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withECDSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.sywspeedplatform.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "5817abad-f6d5-38b9-bff4-46730b56d2fb"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withECDSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.sywspeedplatform.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "fb6dfd4b-2642-3db6-8af5-526bf0f04bc5"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.sywspeedplatform.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "ef82b7b0-fb81-33ac-a2ed-44bda682d976"
                ],
                "asm_va_score": 9.8,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "GeoTrust",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [
                    "CVE-2016-1908",
                    "CVE-2015-5600",
                    "CVE-2016-10012",
                    "CVE-2015-8325",
                    "CVE-2020-15778",
                    "CVE-2016-6515",
                    "CVE-2016-10708",
                    "CVE-2016-10009",
                    "CVE-2016-10010",
                    "CVE-2021-41617",
                    "CVE-2015-6564",
                    "CVE-2019-6110",
                    "CVE-2019-6109",
                    "CVE-2016-3115",
                    "CVE-2016-6210",
                    "CVE-2019-6111",
                    "CVE-2020-14145",
                    "CVE-2014-2653",
                    "CVE-2016-10011",
                    "CVE-2018-20685",
                    "CVE-2018-15919",
                    "CVE-2017-15906",
                    "CVE-2016-20012",
                    "CVE-2018-15473",
                    "CVE-2015-5352",
                    "CVE-2021-36368",
                    "CVE-2015-6563"
                ],
                "first_observed": 1659229324000,
                "has_active_externally_services": true,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": 1663321931000,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.thespeedyou.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": [
                    "HttpServer",
                    "SshServer"
                ]
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "2cf99b64-8bb7-3e27-ada5-447a71b37280"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Thawte",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.toysrus.at",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "b8572d63-18df-3358-a818-63aacd68990b"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Thawte",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.toysrus.at",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "a5d6a0cd-5dbc-3ffb-89e2-1c5a33032fe7"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Thawte",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.toysrus.ch",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "dfc90e29-c244-3194-9632-885dc39cc9e1"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Thawte",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.toysrus.ch",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "589b80e1-2623-3321-9486-6f4f2ec177f5"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Network Solutions",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.toysrus.co.uk",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "ff3ce679-0e42-3070-829e-db0ee9248a3f"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA1withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired",
                    "InsecureSignature"
                ],
                "certificate_issuer": "Network Solutions",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.toysrus.co.uk",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "46d2ee77-f951-3dc8-80ac-79efb33bf34d"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "LongExpiration",
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.toysrus.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "1fba11d5-3ab2-34de-bd2e-69c407e99915"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.toysrus.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "ded44dc1-18f2-3ac5-a66f-5e51559cfcfc"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "LongExpiration",
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.toysrus.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "0098ab7a-7f20-3729-9d0c-f7014bdacd14"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "LongExpiration",
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "SymAntec Corporation",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.toysrus.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "c66a99bd-352d-3526-9176-0d46d4abab49"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "LongExpiration",
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Symantec",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.toysrus.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "fc0ebd17-ebd2-3fd5-a581-56d7c9b68735"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Thawte",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.toysrus.de",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "cc96af10-fb0b-392c-985f-bece54c41463"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "Thawte",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.toysrus.de",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "b1608c57-beeb-3746-8f19-11437d2650de"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA1withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired",
                    "InsecureSignature"
                ],
                "certificate_issuer": "Thawte",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.toysrus.de",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            }
        ]
    }
}
```

#### Human Readable Output

>### Asset Internet Exposures
>|asm_ids|asm_va_score|asset_type|business_units|certificate_algorithm|certificate_classifications|certificate_issuer|domain_resolves|externally_detected_providers|externally_inferred_cves|first_observed|has_active_externally_services|has_xdr_agent|last_observed|name|sensor|service_type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 3c176460-8735-333c-b618-8262e2fb660c |  | CERTIFICATE | jwilkes - Toys R US | SHA1withRSA | Wildcard,<br/>Expired,<br/>InsecureSignature | Thawte | false |  |  |  | false | NA |  | *.babiesrus.com | XPANSE |  |
>| 43164fde-8e87-3d1e-8530-82f14cd3ae9a |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | COMODO | false |  |  |  | false | NA |  | *.ch3.intra.kmart.com | XPANSE |  |
>| 2e560b90-bd0c-3c5f-b075-7cf0c7b68860 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | COMODO | false |  |  |  | false | NA |  | *.ch3.intra.sears.com | XPANSE |  |
>| 3554f7cc-c9ad-3ca5-9fd4-5b6e4f206142 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | COMODO | false |  |  |  | false | NA |  | *.ch4.intra.sears.com | XPANSE |  |
>| 96e780ca-5c06-3e6b-8db3-dc58a34da339 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.craftsman.com | XPANSE |  |
>| c2360474-2800-379c-852c-ed4ad141a8b6 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.craftsman.com | XPANSE |  |
>| eec66ec2-5a7d-395a-860c-d83362100d8a |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.craftsman.com | XPANSE |  |
>| 1387c574-5a18-3832-8784-42cf9f207c3b |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | COMODO | false |  |  |  | false | NA |  | *.craftsman.com | XPANSE |  |
>| 30c16061-1910-3814-8fd1-669bcde67340 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | COMODO | false |  |  |  | false | NA |  | *.diehard.com | XPANSE |  |
>| cfa1cd5a-77f1-3963-8557-7f652309a143 |  | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.digital-dev.toysrus.com | XPANSE |  |
>| 78a11e94-58a9-329c-99ca-e527d2db6cfb |  | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.digital-prod.toysrus.com | XPANSE |  |
>| b5363eb5-775a-33f5-ab51-70f73657737e | 7.5 | DOMAIN | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries |  |  |  | true | Other | CVE-2017-9229,<br/>CVE-2019-9638,<br/>CVE-2007-6422 | 1659344376992 | true | NA | 1663216568137 | *.enron.com | XPANSE | HttpServer |
>| c35f103c-140d-3318-bac1-057bc4496480 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.fitstudio.com | XPANSE |  |
>| ec8caf82-f0f0-31ff-aa42-f227a1a4393e |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.fitstudio.com | XPANSE |  |
>| d27c2415-19a2-3022-bf0c-8d6e9879311e |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.fitstudio.com | XPANSE |  |
>| 1b346ded-7761-3969-99b2-2ebbc8b324b2 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.fitstudio.com | XPANSE |  |
>| e220e39a-5566-3dff-987d-915454b96914 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.kenmore.com | XPANSE |  |
>| 934ae8e0-3154-3000-a7b2-72a1293d6bd8 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.kenmore.com | XPANSE |  |
>| 84727397-a158-3fc8-baae-f831ccac9c90 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.kenmore.com | XPANSE |  |
>| a7c56b7c-390b-32a7-aa32-95413cd62708 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | COMODO | false |  |  |  | false | NA |  | *.kenmore.com | XPANSE |  |
>| 03a6de65-ccb9-3e8d-9dfe-3b944e226801 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.kenmore.com | XPANSE |  |
>| 553845cf-d1f1-353b-b122-1b5b499c238f |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.kenmore.com | XPANSE |  |
>| b28d461b-aadd-3aed-b96f-81a40eba2cab |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Corporation Service Company | false |  |  |  | false | NA |  | *.kenmorepowercord.com | XPANSE |  |
>| e526a199-d558-319b-b81a-04d26cb30198 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.kmart.com | XPANSE |  |
>| 7d2c1a14-b223-329b-aa75-dd19f19a5f77 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.kmart.com | XPANSE |  |
>| f30e9117-c521-36fa-9711-83ff3428489d |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.kmart.com | XPANSE |  |
>| 4b8d8ddb-fcae-30c8-9a23-ae857a4d156c |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.kmart.com | XPANSE |  |
>| 7c327b5f-443c-3934-8a85-b0d095075a39 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.managemyhome.com | XPANSE |  |
>| 7997f043-d5fa-3c6b-90f0-6e86a4bdac9f |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.managemyhome.com | XPANSE |  |
>| b92751d5-e83c-3714-bd78-1a84f0f532b6 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.managemyhome.com | XPANSE |  |
>| daa76a92-52be-3ab9-8626-4737136010f9 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.managemyhome.com | XPANSE |  |
>| d5943d48-ba3b-3bff-90cc-b074570df21f |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.managemylife.com | XPANSE |  |
>| 76d52f2d-a51a-3ce7-9c41-a17b4b8ac1b3 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.managemylife.com | XPANSE |  |
>| cd0f03dc-d795-3e3f-80c9-9072f551017c |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.managemylife.com | XPANSE |  |
>| ce4bfd78-951e-321b-a1c6-94e5e89791fd |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.mygofer.com | XPANSE |  |
>| c11817ab-a51c-39f8-ba53-5cdcd967f898 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.mygofer.com | XPANSE |  |
>| 5362a102-d620-32c8-b931-8c9a0dc237e4 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.mygofer.com | XPANSE |  |
>| 115a21e1-04d1-359f-80a9-02cd5d491dba |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.mykmart.com | XPANSE |  |
>| 2f340816-d1c4-3f00-95c2-b2ea3b49f503 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.mykmart.com | XPANSE |  |
>| 6e9fef73-0838-3be3-8185-a414520491be |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.mykmart.com | XPANSE |  |
>| 50bcf89e-31cf-3081-a441-0e723985be11 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.mykmart.com | XPANSE |  |
>| 4b1f3765-de40-3a1a-8535-667420408fd9 |  | DOMAIN | jwilkes test - VanDelay Industries |  |  |  | true | Akamai Technologies |  | 1659326177977 | false | NA | 1663233661703 | *.pets.com | XPANSE |  |
>| 71c98bcc-6480-3d8a-86cf-76a5fdf75586 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA512withRSA | LongExpiration,<br/>Wildcard | Sears Holdings Corp. | false | Other |  | 1659409579000 | true | NA | 1663060444000 | *.prod.ch3.s.com | XPANSE | HttpServer |
>| 7aeb1046-ca32-3361-8816-1509bd589e61 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA512withRSA | LongExpiration,<br/>Wildcard | Sears Holdings Corp. | false |  |  |  | false | NA |  | *.prod.ch4.s.com | XPANSE |  |
>| 4fda9fd7-5a27-310b-beb0-3a0a04bf8ceb |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA512withRSA | LongExpiration,<br/>Wildcard | Sears Holdings Corp. | false |  |  |  | false | NA |  | *.prod.global.s.com | XPANSE |  |
>| a0d338d0-46f4-371e-bc04-fde201e1f2d5 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.sears.com | XPANSE |  |
>| 93bbbda3-16f3-3f6f-b736-688fe2d564c8 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.sears.com | XPANSE |  |
>| e0d802fd-e70d-375c-9dc7-04ab3ab3a67d |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.sears.com | XPANSE |  |
>| 277e4d9e-8f38-3b90-8f73-19243006e922 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false | MCI Communications,<br/>Other |  | 1659380449000 | true | NA | 1663310153000 | *.sears.com.mx | XPANSE | HttpServer |
>| 89b782d2-10dd-3f0c-8cc5-c3fab0655bf9 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.sears.com.pr | XPANSE |  |
>| 011ade11-ab27-3484-ab80-fe14a4180ab8 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.sears.com.pr | XPANSE |  |
>| 7208e284-c582-368b-a769-d1604d726bd9 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.sears.com.pr | XPANSE |  |
>| 47f620b7-5016-369d-be42-7286430d7c92 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.sears.com.pr | XPANSE |  |
>| 946dbb7d-a002-3e5f-82cf-935943ddd753 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Wildcard,<br/>Expired | Network Solutions | false |  |  |  | false | NA |  | *.searshomepro.com | XPANSE |  |
>| 7fee6dfd-15b8-3d29-95f5-452053b771c5 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.searshomeservices.com | XPANSE |  |
>| 47ed7048-0332-3934-a758-817ad0e95b60 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.searshomeservices.com | XPANSE |  |
>| 9351ee34-d666-3fc7-9456-620ca78c43d9 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.searshomeservices.com | XPANSE |  |
>| c4dfa2b7-7bda-3d64-99ba-868264fa5a0f |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.searshomeservices.com | XPANSE |  |
>| efc211f0-2501-3654-9e7a-105fd22f594e |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | COMODO | false |  |  |  | false | NA |  | *.searshomeservices.com | XPANSE |  |
>| 3a8489ed-86c8-33cd-9314-315e3e010bfa |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.searsoutlet.com | XPANSE |  |
>| 7184d7ee-6dcd-3f4e-adc7-c529550eef56 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.searsoutlet.com | XPANSE |  |
>| 2c85d4be-e6e6-3bee-86bd-5fd295c83d91 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.searsoutlet.com | XPANSE |  |
>| b460cbd5-af03-33d8-85c6-4a06c9efc8a4 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.searsoutlet.com | XPANSE |  |
>| 33624b71-c4e6-31d9-96ab-ca203e2bbc53 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.searspartsdirect.com | XPANSE |  |
>| ae996f2d-704c-342d-b00f-fb9f3a3f217d |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.searspartsdirect.com | XPANSE |  |
>| 940e8985-0604-360d-a651-b1da052eddbe |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.searspartsdirect.com | XPANSE |  |
>| f2d897ee-1cdc-3f8b-8f50-5f99c5307960 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.searspartsdirect.com | XPANSE |  |
>| 533e0b7a-e296-3502-9208-05b37732501c |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Wildcard,<br/>Expired | Network Solutions | false |  |  |  | false | NA |  | *.searssiding.com | XPANSE |  |
>| b09526c1-e395-35a2-9246-a6f25d2189b3 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | COMODO | false |  |  |  | false | NA |  | *.segnosystems.com | XPANSE |  |
>| 08ced839-21bf-3cc3-8143-e997ad503f88 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.shld.net | XPANSE |  |
>| 0fd301cd-ccf9-31ed-90c6-bf5a08b3ebee |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.shld.net | XPANSE |  |
>| 5185bd8a-154d-3d3a-b73d-22e5ad2c805b |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.shld.net | XPANSE |  |
>| ef70c2ac-b116-334c-9922-1644805e0933 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.shopyourway.com | XPANSE |  |
>| 8f9b7cd2-f2cc-3b4a-aacb-4aaf41144ee4 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.shopyourway.com | XPANSE |  |
>| 4b218587-1e8b-386c-97b9-d411b9a93c1c |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.shopyourway.com | XPANSE |  |
>| 1832890e-5b02-3db9-b288-fdd935422b8a |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | COMODO | false | Amazon Web Services |  | 1659230429000 | true | NA | 1663321313000 | *.shs-core.com | XPANSE | HttpServer |
>| 55275c3e-eb2e-3608-893c-1f2ed3447ea5 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | COMODO | false |  |  |  | false | NA |  | *.shs.com | XPANSE |  |
>| 334367df-a131-307a-a597-e85cb1a6be34 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.social.sears.com | XPANSE |  |
>| cdbcd67b-fb54-39e4-b9b7-c53d3fe421f9 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.social.sears.com | XPANSE |  |
>| 89c864f4-c816-34ae-812d-73a16a8c1059 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.social.sears.com | XPANSE |  |
>| 451f3622-0219-3675-b9e7-b9db3730c678 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.social.sears.com | XPANSE |  |
>| 5309a09b-7670-3602-a5bd-e620a9e39bae |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.sywspeedplatform.com | XPANSE |  |
>| 0dff4458-c9bc-313d-a299-71bde25fe7b3 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withECDSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.sywspeedplatform.com | XPANSE |  |
>| 5817abad-f6d5-38b9-bff4-46730b56d2fb |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withECDSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.sywspeedplatform.com | XPANSE |  |
>| fb6dfd4b-2642-3db6-8af5-526bf0f04bc5 |  | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.sywspeedplatform.com | XPANSE |  |
>| ef82b7b0-fb81-33ac-a2ed-44bda682d976 | 9.8 | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | GeoTrust | false | Amazon Web Services | CVE-2016-1908,<br/>CVE-2015-5600,<br/>CVE-2016-10012,<br/>CVE-2015-8325,<br/>CVE-2020-15778,<br/>CVE-2016-6515,<br/>CVE-2016-10708,<br/>CVE-2016-10009,<br/>CVE-2016-10010,<br/>CVE-2021-41617,<br/>CVE-2015-6564,<br/>CVE-2019-6110,<br/>CVE-2019-6109,<br/>CVE-2016-3115,<br/>CVE-2016-6210,<br/>CVE-2019-6111,<br/>CVE-2020-14145,<br/>CVE-2014-2653,<br/>CVE-2016-10011,<br/>CVE-2018-20685,<br/>CVE-2018-15919,<br/>CVE-2017-15906,<br/>CVE-2016-20012,<br/>CVE-2018-15473,<br/>CVE-2015-5352,<br/>CVE-2021-36368,<br/>CVE-2015-6563 | 1659229324000 | true | NA | 1663321931000 | *.thespeedyou.com | XPANSE | HttpServer,<br/>SshServer |
>| 2cf99b64-8bb7-3e27-ada5-447a71b37280 |  | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Wildcard,<br/>Expired | Thawte | false |  |  |  | false | NA |  | *.toysrus.at | XPANSE |  |
>| b8572d63-18df-3358-a818-63aacd68990b |  | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Wildcard,<br/>Expired | Thawte | false |  |  |  | false | NA |  | *.toysrus.at | XPANSE |  |
>| a5d6a0cd-5dbc-3ffb-89e2-1c5a33032fe7 |  | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Wildcard,<br/>Expired | Thawte | false |  |  |  | false | NA |  | *.toysrus.ch | XPANSE |  |
>| dfc90e29-c244-3194-9632-885dc39cc9e1 |  | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Wildcard,<br/>Expired | Thawte | false |  |  |  | false | NA |  | *.toysrus.ch | XPANSE |  |
>| 589b80e1-2623-3321-9486-6f4f2ec177f5 |  | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Wildcard,<br/>Expired | Network Solutions | false |  |  |  | false | NA |  | *.toysrus.co.uk | XPANSE |  |
>| ff3ce679-0e42-3070-829e-db0ee9248a3f |  | CERTIFICATE | jwilkes - Toys R US | SHA1withRSA | Wildcard,<br/>Expired,<br/>InsecureSignature | Network Solutions | false |  |  |  | false | NA |  | *.toysrus.co.uk | XPANSE |  |
>| 46d2ee77-f951-3dc8-80ac-79efb33bf34d |  | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.toysrus.com | XPANSE |  |
>| 1fba11d5-3ab2-34de-bd2e-69c407e99915 |  | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  |  | false | NA |  | *.toysrus.com | XPANSE |  |
>| ded44dc1-18f2-3ac5-a66f-5e51559cfcfc |  | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | LongExpiration,<br/>Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.toysrus.com | XPANSE |  |
>| 0098ab7a-7f20-3729-9d0c-f7014bdacd14 |  | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | LongExpiration,<br/>Wildcard,<br/>Expired | SymAntec Corporation | false |  |  |  | false | NA |  | *.toysrus.com | XPANSE |  |
>| c66a99bd-352d-3526-9176-0d46d4abab49 |  | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | LongExpiration,<br/>Wildcard,<br/>Expired | Symantec | false |  |  |  | false | NA |  | *.toysrus.com | XPANSE |  |
>| fc0ebd17-ebd2-3fd5-a581-56d7c9b68735 |  | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Wildcard,<br/>Expired | Thawte | false |  |  |  | false | NA |  | *.toysrus.de | XPANSE |  |
>| cc96af10-fb0b-392c-985f-bece54c41463 |  | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Wildcard,<br/>Expired | Thawte | false |  |  |  | false | NA |  | *.toysrus.de | XPANSE |  |
>| b1608c57-beeb-3746-8f19-11437d2650de |  | CERTIFICATE | jwilkes - Toys R US | SHA1withRSA | Wildcard,<br/>Expired,<br/>InsecureSignature | Thawte | false |  |  |  | false | NA |  | *.toysrus.de | XPANSE |  |


### asm-getassetinternetexposure
***
Get Internet exposure asset details according to the asset ID.


#### Base Command

`asm-getassetinternetexposure`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asm_id | A string representing the asset ID for which you want to get the details for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.GetAssetInternetExposure.asm_ids | String | Attack surface managment UUID | 
| ASM.GetAssetInternetExposure.name | String | Name of the exposed asset | 
| ASM.GetAssetInternetExposure.type | String | Type of the exposed asset | 
| ASM.GetAssetInternetExposure.last_observed | Unknown | Last time exposure was observed | 
| ASM.GetAssetInternetExposure.first_observed | Unknown | First time exposure was observed | 
| ASM.GetAssetInternetExposure.created | Date | Date the ASM Issue was created | 
| ASM.GetAssetInternetExposure.business_units | String | Asset associated business units | 
| ASM.GetAssetInternetExposure.domain | Unknown | Asset associated domain | 
| ASM.GetAssetInternetExposure.certificate_issuer | String | Asset certificate issuer | 
| ASM.GetAssetInternetExposure.certificate_algorithm | String | Asset certificate algorithm | 
| ASM.GetAssetInternetExposure.certificate_classifications | String | Asset certificate classifications | 
| ASM.GetAssetInternetExposure.resolves | Boolean | Does the asset have DNS resolution | 
| ASM.GetAssetInternetExposure.details | Unknown | Additional details | 
| ASM.GetAssetInternetExposure.externally_inferred_vulnerability_score | Unknown | Asset vulnerability score | 

#### Command example
```!asm-getassetinternetexposure asm_id=3c176460-8735-333c-b618-8262e2fb660c```
#### Context Example
```json
{
    "ASM": {
        "GetAssetInternetExposure": {
            "active_external_services_types": [],
            "active_service_ids": [],
            "all_service_ids": [],
            "asm_ids": "3c176460-8735-333c-b618-8262e2fb660c",
            "business_units": [
                "jwilkes - Toys R US"
            ],
            "certificate_algorithm": "SHA1withRSA",
            "certificate_classifications": [
                "Wildcard",
                "Expired",
                "InsecureSignature"
            ],
            "certificate_issuer": "Thawte",
            "created": 1663332516299,
            "details": {
                "businessUnits": [
                    {
                        "name": "jwilkes - Toys R US"
                    }
                ],
                "certificateDetails": {
                    "formattedIssuerOrg": "Thawte",
                    "issuer": "C=US,O=Thawte\\, Inc.,CN=Thawte SSL CA",
                    "issuerAlternativeNames": "",
                    "issuerCountry": "US",
                    "issuerEmail": null,
                    "issuerLocality": null,
                    "issuerName": "Thawte SSL CA",
                    "issuerOrg": "Thawte\\\\, Inc.",
                    "issuerOrgUnit": null,
                    "issuerState": null,
                    "md5Fingerprint": "498ec19ebd6c6883ecd43d064e713002",
                    "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp21W/QVHuo0Nyy9l6Qp6Ye7yniuCccplWLdkL34pB0roNWBiklLJFftFTXJLtUuYEBhEbUtOPtNr5QRZFo+LQSj+JMQsGajEgNvIIMDms2xtc+vYkuJeNRsN/0zRm8iBjCNEZ0zBbWdupO6xee+Lngq5RiyRzAN2+Q5HlmHmVOcc7NtY5VIQhajp3a5Gc7tmLXa7ZxwQb+afdlpmE0iv4ZxmXFyHwlPXUlIxfETDDjtv2EzAgrnpZ5juo7TEFZA7AjsT0lO6cC2qPE9x9kC02PeC1Heg4hWf70CsXcKQBsprLqusrPYM9+OYfZnj+Dq9j6FjZD314Nz4qTGwmZrwDQIDAQAB",
                    "publicKeyAlgorithm": "RSA",
                    "publicKeyBits": 2048,
                    "publicKeyModulus": "a76d56fd0547ba8d0dcb2f65e90a7a61eef29e2b8271ca6558b7642f7e29074ae83560629252c915fb454d724bb54b981018446d4b4e3ed36be50459168f8b4128fe24c42c19a8c480dbc820c0e6b36c6d73ebd892e25e351b0dff4cd19bc8818c2344674cc16d676ea4eeb179ef8b9e0ab9462c91cc0376f90e479661e654e71cecdb58e5521085a8e9ddae4673bb662d76bb671c106fe69f765a661348afe19c665c5c87c253d75252317c44c30e3b6fd84cc082b9e96798eea3b4c415903b023b13d253ba702daa3c4f71f640b4d8f782d477a0e2159fef40ac5dc29006ca6b2eabacacf60cf7e3987d99e3f83abd8fa163643df5e0dcf8a931b0999af00d",
                    "publicKeyRsaExponent": 65537,
                    "publicKeySpki": "Up3fHwOddA9cXEeO4XBOgn63bfnvkXsOrOv6AycwQAk=",
                    "serialNumber": "91384582774546160650506315451812470612",
                    "sha1Fingerprint": "77d025c36f055e254063ae2ac3625fd4bf4507fb",
                    "sha256Fingerprint": "9a37c952ee1169cfa6e91efb57fe6d405d1ca48b26a714e9a46f008c15ea62e8",
                    "signatureAlgorithm": "SHA1withRSA",
                    "subject": "C=US,ST=New Jersey,L=Wayne,O=Toys R Us,OU=MIS,CN=*.babiesrus.com",
                    "subjectAlternativeNames": "*.babiesrus.com",
                    "subjectCountry": "US",
                    "subjectEmail": null,
                    "subjectLocality": "Wayne",
                    "subjectName": "*.babiesrus.com",
                    "subjectOrg": "Toys R Us",
                    "subjectOrgUnit": "MIS",
                    "subjectState": "New Jersey",
                    "validNotAfter": 1444780799000,
                    "validNotBefore": 1413158400000,
                    "version": "3"
                },
                "dnsZone": null,
                "domain": null,
                "domainAssetType": null,
                "domainDetails": null,
                "inferredCvesObserved": [],
                "ip_ranges": {},
                "isPaidLevelDomain": false,
                "latestSampledIp": null,
                "providerDetails": [],
                "recentIps": [],
                "subdomainMetadata": null,
                "topLevelAssetMapperDomain": null
            },
            "domain": null,
            "external_services": [],
            "externally_detected_providers": [],
            "externally_inferred_cves": [],
            "externally_inferred_vulnerability_score": null,
            "first_observed": null,
            "ips": [],
            "last_observed": null,
            "name": "*.babiesrus.com",
            "resolves": false,
            "type": "Certificate"
        }
    }
}
```

#### Human Readable Output

>### Asset Internet Exposure
>|asm_ids|business_units|certificate_algorithm|certificate_classifications|certificate_issuer|created|details|name|resolves|type|
>|---|---|---|---|---|---|---|---|---|---|
>| 3c176460-8735-333c-b618-8262e2fb660c | jwilkes - Toys R US | SHA1withRSA | Wildcard,<br/>Expired,<br/>InsecureSignature | Thawte | 1663332516299 | providerDetails: <br/>domain: null<br/>topLevelAssetMapperDomain: null<br/>domainAssetType: null<br/>isPaidLevelDomain: false<br/>domainDetails: null<br/>dnsZone: null<br/>latestSampledIp: null<br/>subdomainMetadata: null<br/>recentIps: <br/>businessUnits: {'name': 'jwilkes - Toys R US'}<br/>certificateDetails: {"issuer": "C=US,O=Thawte\\, Inc.,CN=Thawte SSL CA", "issuerAlternativeNames": "", "issuerCountry": "US", "issuerEmail": null, "issuerLocality": null, "issuerName": "Thawte SSL CA", "issuerOrg": "Thawte\\\\, Inc.", "formattedIssuerOrg": "Thawte", "issuerOrgUnit": null, "issuerState": null, "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp21W/QVHuo0Nyy9l6Qp6Ye7yniuCccplWLdkL34pB0roNWBiklLJFftFTXJLtUuYEBhEbUtOPtNr5QRZFo+LQSj+JMQsGajEgNvIIMDms2xtc+vYkuJeNRsN/0zRm8iBjCNEZ0zBbWdupO6xee+Lngq5RiyRzAN2+Q5HlmHmVOcc7NtY5VIQhajp3a5Gc7tmLXa7ZxwQb+afdlpmE0iv4ZxmXFyHwlPXUlIxfETDDjtv2EzAgrnpZ5juo7TEFZA7AjsT0lO6cC2qPE9x9kC02PeC1Heg4hWf70CsXcKQBsprLqusrPYM9+OYfZnj+Dq9j6FjZD314Nz4qTGwmZrwDQIDAQAB", "publicKeyAlgorithm": "RSA", "publicKeyRsaExponent": 65537, "signatureAlgorithm": "SHA1withRSA", "subject": "C=US,ST=New Jersey,L=Wayne,O=Toys R Us,OU=MIS,CN=*.babiesrus.com", "subjectAlternativeNames": "*.babiesrus.com", "subjectCountry": "US", "subjectEmail": null, "subjectLocality": "Wayne", "subjectName": "*.babiesrus.com", "subjectOrg": "Toys R Us", "subjectOrgUnit": "MIS", "subjectState": "New Jersey", "serialNumber": "91384582774546160650506315451812470612", "validNotBefore": 1413158400000, "validNotAfter": 1444780799000, "version": "3", "publicKeyBits": 2048, "publicKeyModulus": "a76d56fd0547ba8d0dcb2f65e90a7a61eef29e2b8271ca6558b7642f7e29074ae83560629252c915fb454d724bb54b981018446d4b4e3ed36be50459168f8b4128fe24c42c19a8c480dbc820c0e6b36c6d73ebd892e25e351b0dff4cd19bc8818c2344674cc16d676ea4eeb179ef8b9e0ab9462c91cc0376f90e479661e654e71cecdb58e5521085a8e9ddae4673bb662d76bb671c106fe69f765a661348afe19c665c5c87c253d75252317c44c30e3b6fd84cc082b9e96798eea3b4c415903b023b13d253ba702daa3c4f71f640b4d8f782d477a0e2159fef40ac5dc29006ca6b2eabacacf60cf7e3987d99e3f83abd8fa163643df5e0dcf8a931b0999af00d", "publicKeySpki": "Up3fHwOddA9cXEeO4XBOgn63bfnvkXsOrOv6AycwQAk=", "sha1Fingerprint": "77d025c36f055e254063ae2ac3625fd4bf4507fb", "sha256Fingerprint": "9a37c952ee1169cfa6e91efb57fe6d405d1ca48b26a714e9a46f008c15ea62e8", "md5Fingerprint": "498ec19ebd6c6883ecd43d064e713002"}<br/>inferredCvesObserved: <br/>ip_ranges: {} | *.babiesrus.com | false | Certificate |

