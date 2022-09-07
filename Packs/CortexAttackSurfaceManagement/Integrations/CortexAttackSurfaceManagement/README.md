Integration to pull asset and other ASM related information
This integration was integrated and tested with version xx of Cortex Attack Surface Management

## Configure Cortex Attack Surface Management on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cortex Attack Surface Management.
3. Click **Add instance** to create and configure a new integration instance.

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
```!asm-getexternalservices domain=toysrus.com is_active=yes discovery_type=directly_discovery```
#### Context Example
```json
{
    "ASM": {
        "GetExternalServices": [
            {
                "active_classifications": [
                    "HttpServer",
                    "ServerSoftware"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "babiesrus.toysrus.com"
                ],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659396480000,
                "inactive_classifications": [],
                "ip_address": [
                    "52.85.247.24"
                ],
                "is_active": "Active",
                "last_observed": 1661971320000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "32c85ab1-fc98-3061-a813-2fe5daf7e7c5",
                "service_name": "HTTP Server at babiesrus.toysrus.com:80",
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
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "babyregistry.toysrus.com"
                ],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659394320000,
                "inactive_classifications": [],
                "ip_address": [
                    "52.84.52.93"
                ],
                "is_active": "Active",
                "last_observed": 1662159600000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "e93eb602-3ed5-354e-b21e-aa33f3e2de28",
                "service_name": "HTTP Server at babyregistry.toysrus.com:80",
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
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "bru.truimg.toysrus.com"
                ],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659395460000,
                "inactive_classifications": [],
                "ip_address": [
                    "13.249.85.25",
                    "13.249.141.28",
                    "13.249.85.94",
                    "13.249.141.126",
                    "18.160.249.72",
                    "13.249.85.80",
                    "13.249.141.20",
                    "18.66.122.51",
                    "18.160.249.115",
                    "13.249.85.10",
                    "18.66.122.87",
                    "18.66.122.53",
                    "18.160.249.88",
                    "18.66.122.24",
                    "18.160.249.93",
                    "13.249.141.102"
                ],
                "is_active": "Active",
                "last_observed": 1662427980000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "7fd927d3-1740-36e0-b61b-b92ca32c16fb",
                "service_name": "HTTP Server at bru.truimg.toysrus.com:443",
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
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "bru.truimg.toysrus.com"
                ],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659387360000,
                "inactive_classifications": [],
                "ip_address": [
                    "13.249.85.94"
                ],
                "is_active": "Active",
                "last_observed": 1662064740000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "f0ed015d-ccca-3f18-9983-8d5598aa7e23",
                "service_name": "HTTP Server at bru.truimg.toysrus.com:80",
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
                    "JQuery",
                    "MissingPublicKeyPinsHeader"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "careers.toysrus.com"
                ],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [
                    "CVE-2020-11023",
                    "CVE-2020-11022"
                ],
                "externally_inferred_vulnerability_score": 6.1,
                "first_observed": 1659386460000,
                "inactive_classifications": [],
                "ip_address": [
                    "18.165.122.84",
                    "18.160.213.51",
                    "13.249.85.63",
                    "13.249.85.81",
                    "13.249.85.128",
                    "18.160.213.73",
                    "18.160.213.28",
                    "18.160.213.124",
                    "13.249.85.84"
                ],
                "is_active": "Active",
                "last_observed": 1662425040000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "c546386c-e568-34d3-90eb-44792c99aee3",
                "service_name": "HTTP Server at careers.toysrus.com:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "HttpServer"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "click.mail.toysrus.com"
                ],
                "externally_detected_providers": [
                    "Other"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659714720000,
                "inactive_classifications": [],
                "ip_address": [
                    "128.245.97.223"
                ],
                "is_active": "Active",
                "last_observed": 1662311160000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "9f3a7b63-c8e8-3a9e-9266-ba98a6d2d833",
                "service_name": "HTTP Server at click.mail.toysrus.com:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "HttpServer"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "click.mail.toysrus.com"
                ],
                "externally_detected_providers": [
                    "Other"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659417900000,
                "inactive_classifications": [],
                "ip_address": [
                    "128.245.97.223"
                ],
                "is_active": "Active",
                "last_observed": 1662100380000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "aaffe4d0-5e1a-3e9a-86cb-3a836c5e6838",
                "service_name": "HTTP Server at click.mail.toysrus.com:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "HttpServer",
                    "ServerSoftware",
                    "JQuery",
                    "MissingPublicKeyPinsHeader",
                    "DevelopmentEnvironment"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "dev.toysrus.com"
                ],
                "externally_detected_providers": [
                    "CloudFlare"
                ],
                "externally_inferred_cves": [
                    "CVE-2020-11022",
                    "CVE-2020-11023",
                    "CVE-2015-9251",
                    "CVE-2019-11358"
                ],
                "externally_inferred_vulnerability_score": 6.1,
                "first_observed": 1659472200000,
                "inactive_classifications": [],
                "ip_address": [
                    "104.18.233.92",
                    "104.18.234.92"
                ],
                "is_active": "Active",
                "last_observed": 1662428520000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "4734cde0-8841-32e5-be7e-7ff240fb946c",
                "service_name": "HTTP Server at dev.toysrus.com:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXFrameOptionsHeader",
                    "HttpServer",
                    "ServerSoftware",
                    "MissingStrictTransportSecurityHeader",
                    "MissingContentSecurityPolicyHeader",
                    "MissingPublicKeyPinsHeader"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "metrics.toysrus.com"
                ],
                "externally_detected_providers": [
                    "Adobe"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659419940000,
                "inactive_classifications": [],
                "ip_address": [
                    "63.140.38.100",
                    "63.140.38.165",
                    "63.140.38.186"
                ],
                "is_active": "Active",
                "last_observed": 1662130560000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "a972934f-c83b-31cd-b1cd-7686020c2414",
                "service_name": "HTTP Server at metrics.toysrus.com:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "HttpServer"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "msoid.toysrus.com"
                ],
                "externally_detected_providers": [
                    "Microsoft Azure"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659395940000,
                "inactive_classifications": [],
                "ip_address": [
                    "40.126.29.13"
                ],
                "is_active": "Active",
                "last_observed": 1661969880000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "5e000e24-fcb6-3e3c-ab99-f7f053d5ef51",
                "service_name": "HTTP Server at msoid.toysrus.com:80",
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
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "rdcservicedesk.toysrus.com"
                ],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659476340000,
                "inactive_classifications": [],
                "ip_address": [
                    "3.212.20.158",
                    "54.146.255.102",
                    "3.224.224.12",
                    "100.25.178.60"
                ],
                "is_active": "Active",
                "last_observed": 1662423240000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "451f87a7-e326-3d0e-bd1f-97ae155dcb83",
                "service_name": "HTTP Server at rdcservicedesk.toysrus.com:443",
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
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "rintlservicedesk.toysrus.com"
                ],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659471900000,
                "inactive_classifications": [],
                "ip_address": [
                    "3.212.20.158",
                    "54.146.255.102",
                    "3.224.224.12",
                    "100.25.178.60"
                ],
                "is_active": "Active",
                "last_observed": 1662425940000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "e9f60323-0c24-3cc3-b20a-884d26c2c194",
                "service_name": "HTTP Server at rintlservicedesk.toysrus.com:443",
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
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "rservicedesk.toysrus.com"
                ],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659478080000,
                "inactive_classifications": [],
                "ip_address": [
                    "3.212.20.158",
                    "54.146.255.102",
                    "3.224.224.12",
                    "100.25.178.60"
                ],
                "is_active": "Active",
                "last_observed": 1662416400000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "f5753db9-7083-32f7-abeb-343d1cc007b0",
                "service_name": "HTTP Server at rservicedesk.toysrus.com:443",
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
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "rstoreservicedesk.toysrus.com"
                ],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659478380000,
                "inactive_classifications": [],
                "ip_address": [
                    "3.212.20.158",
                    "54.146.255.102",
                    "3.224.224.12",
                    "100.25.178.60"
                ],
                "is_active": "Active",
                "last_observed": 1662411240000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "408d9b01-9836-3aa5-8a3a-13c0f109de30",
                "service_name": "HTTP Server at rstoreservicedesk.toysrus.com:443",
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
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "stores.toysrus.com"
                ],
                "externally_detected_providers": [
                    "CloudFlare"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659400020000,
                "inactive_classifications": [],
                "ip_address": [
                    "104.18.70.71",
                    "104.18.71.71"
                ],
                "is_active": "Active",
                "last_observed": 1662439680000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "c4d99802-1668-37a5-b6d2-bac8e01c1131",
                "service_name": "HTTP Server at stores.toysrus.com:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "MissingContentSecurityPolicyHeader",
                    "MissingStrictTransportSecurityHeader",
                    "HttpServer",
                    "MissingXContentTypeOptionsHeader",
                    "MissingCacheControlHeader",
                    "MissingPublicKeyPinsHeader"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "teamtru.toysrus.com"
                ],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659386820000,
                "inactive_classifications": [],
                "ip_address": [
                    "13.33.243.96",
                    "18.66.122.129",
                    "13.32.208.101",
                    "13.226.225.101",
                    "13.33.243.105",
                    "108.159.227.23",
                    "13.224.189.40",
                    "13.33.65.104",
                    "99.86.224.25",
                    "13.249.141.43",
                    "18.65.25.19",
                    "18.165.122.119",
                    "13.32.208.119",
                    "18.65.25.86",
                    "13.249.141.32",
                    "13.226.225.127",
                    "13.226.225.60",
                    "18.65.25.30",
                    "18.66.122.34",
                    "108.159.227.63",
                    "108.157.150.120",
                    "13.249.141.92",
                    "13.32.208.71",
                    "18.65.25.42",
                    "13.33.243.74",
                    "108.159.227.51",
                    "13.32.208.15",
                    "18.165.122.20",
                    "13.224.189.18",
                    "108.157.150.46",
                    "108.157.150.105",
                    "108.157.150.43",
                    "18.66.122.52",
                    "52.84.52.98",
                    "13.33.65.87",
                    "13.224.189.23",
                    "13.224.189.88",
                    "13.33.243.88",
                    "18.165.122.31",
                    "13.33.65.95",
                    "108.159.227.33",
                    "13.249.141.71",
                    "18.66.122.61"
                ],
                "is_active": "Active",
                "last_observed": 1662466920000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "34593e05-736b-35ce-a97e-e844bce16e54",
                "service_name": "HTTP Server at teamtru.toysrus.com:443",
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
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "teamtru.toysrus.com"
                ],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659394500000,
                "inactive_classifications": [],
                "ip_address": [
                    "108.159.227.63"
                ],
                "is_active": "Active",
                "last_observed": 1662154740000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "20398abe-b1f1-3ec1-ab25-7fe70e51a410",
                "service_name": "HTTP Server at teamtru.toysrus.com:80",
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
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "toysrus.com"
                ],
                "externally_detected_providers": [
                    "CloudFlare"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1662253080000,
                "inactive_classifications": [],
                "ip_address": [
                    "104.18.70.71",
                    "104.18.71.71"
                ],
                "is_active": "Active",
                "last_observed": 1662439680000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "935aa68a-c529-31b6-952d-4a1c2cc921a2",
                "service_name": "HTTP Server at toysrus.com:443",
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
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "toysrus.com"
                ],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659387000000,
                "inactive_classifications": [],
                "ip_address": [
                    "52.217.77.163"
                ],
                "is_active": "Active",
                "last_observed": 1662068880000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "50b8a0cd-6142-3a02-9d7e-2dba255f3e0e",
                "service_name": "HTTP Server at toysrus.com:80",
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
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "truimg.toysrus.com"
                ],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659386940000,
                "inactive_classifications": [],
                "ip_address": [
                    "99.84.160.84",
                    "13.32.151.33",
                    "54.192.81.65",
                    "52.84.125.93",
                    "13.32.151.42",
                    "99.84.160.95",
                    "54.192.81.76",
                    "13.225.78.110",
                    "52.85.247.65",
                    "52.85.132.64",
                    "52.85.132.77",
                    "18.67.65.91",
                    "18.66.122.91",
                    "54.230.21.124",
                    "13.225.78.122",
                    "13.33.243.129",
                    "52.85.247.119",
                    "54.230.21.68",
                    "52.84.125.119",
                    "54.192.81.102",
                    "18.160.249.6",
                    "18.160.249.8",
                    "18.165.122.12",
                    "18.66.122.104",
                    "13.33.65.13",
                    "13.249.190.84",
                    "52.85.132.123",
                    "18.67.65.109",
                    "18.160.249.23",
                    "54.230.21.92",
                    "18.66.122.126",
                    "13.225.78.94",
                    "13.33.65.97",
                    "54.192.81.3",
                    "18.165.122.99",
                    "52.85.247.18",
                    "18.160.249.104",
                    "13.32.208.104",
                    "13.225.78.41",
                    "52.85.247.24",
                    "108.138.167.71",
                    "18.67.65.12",
                    "52.84.125.6",
                    "18.165.122.119",
                    "52.85.132.128",
                    "13.33.65.121",
                    "13.33.243.67",
                    "13.33.243.69",
                    "108.138.167.111",
                    "52.84.125.49",
                    "18.165.122.66",
                    "99.84.160.62",
                    "13.33.65.75",
                    "18.67.65.54",
                    "13.32.208.86",
                    "99.84.160.35",
                    "18.66.122.58",
                    "54.230.21.24"
                ],
                "is_active": "Active",
                "last_observed": 1662466800000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "f833a3a2-c3bc-30a1-b6f9-73df27175889",
                "service_name": "HTTP Server at truimg.toysrus.com:443",
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
                    "JQuery",
                    "MissingPublicKeyPinsHeader"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "wholesale.toysrus.com"
                ],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [
                    "CVE-2020-11023",
                    "CVE-2020-11022"
                ],
                "externally_inferred_vulnerability_score": 6.1,
                "first_observed": 1659395820000,
                "inactive_classifications": [],
                "ip_address": [
                    "65.8.49.73",
                    "108.156.120.41",
                    "108.156.120.121",
                    "65.8.49.14",
                    "13.249.85.129",
                    "108.156.120.16",
                    "108.156.120.33",
                    "65.8.49.86",
                    "13.249.85.7",
                    "65.8.49.87"
                ],
                "is_active": "Active",
                "last_observed": 1662422100000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "32ab36fa-4c9a-3e14-ba8a-6bee598ed88c",
                "service_name": "HTTP Server at wholesale.toysrus.com:443",
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
                    "JQuery",
                    "MissingPublicKeyPinsHeader"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "www.careers.toysrus.com"
                ],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [
                    "CVE-2020-11023",
                    "CVE-2020-11022"
                ],
                "externally_inferred_vulnerability_score": 6.1,
                "first_observed": 1659386460000,
                "inactive_classifications": [],
                "ip_address": [
                    "52.85.247.103",
                    "18.160.213.51",
                    "13.249.85.63",
                    "52.85.247.50",
                    "52.85.247.13",
                    "13.249.85.81",
                    "18.160.213.73",
                    "13.249.85.128",
                    "18.160.213.124",
                    "18.160.213.28",
                    "13.249.85.84",
                    "52.85.247.90"
                ],
                "is_active": "Active",
                "last_observed": 1662427560000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "38264ee2-a2d0-3910-b50f-0ab97abb0fd7",
                "service_name": "HTTP Server at www.careers.toysrus.com:443",
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
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "www.careers.toysrus.com"
                ],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659397920000,
                "inactive_classifications": [],
                "ip_address": [
                    "52.85.247.13",
                    "18.160.213.28",
                    "13.249.85.128"
                ],
                "is_active": "Active",
                "last_observed": 1662141780000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "f20a9f52-21db-3ff5-a15f-e1f89855afac",
                "service_name": "HTTP Server at www.careers.toysrus.com:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "MissingXFrameOptionsHeader",
                    "MissingXXssProtectionHeader",
                    "MissingStrictTransportSecurityHeader",
                    "HttpServer",
                    "ServerSoftware",
                    "JQuery",
                    "MissingPublicKeyPinsHeader"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "www.toysrus.com"
                ],
                "externally_detected_providers": [
                    "CloudFlare"
                ],
                "externally_inferred_cves": [
                    "CVE-2020-11023",
                    "CVE-2015-9251",
                    "CVE-2020-11022",
                    "CVE-2019-11358"
                ],
                "externally_inferred_vulnerability_score": 6.1,
                "first_observed": 1659396240000,
                "inactive_classifications": [
                    "MissingXContentTypeOptionsHeader",
                    "MissingContentSecurityPolicyHeader"
                ],
                "ip_address": [
                    "104.18.70.71",
                    "104.18.71.71"
                ],
                "is_active": "Active",
                "last_observed": 1662417180000,
                "port": 443,
                "protocol": "TCP",
                "service_id": "dafffacb-235a-3bfa-bade-40743c9d8485",
                "service_name": "HTTP Server at www.toysrus.com:443",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "DevelopmentEnvironment"
                ],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "dev.toysrus.com"
                ],
                "externally_detected_providers": [
                    "CloudFlare"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659400620000,
                "inactive_classifications": [],
                "ip_address": [
                    "104.18.233.92",
                    "104.18.234.92"
                ],
                "is_active": "Active",
                "last_observed": 1662410520000,
                "port": 8443,
                "protocol": "TCP",
                "service_id": "bfa86f48-1b21-377f-a3eb-b8b0af2b6e3e",
                "service_name": "Unidentified Service at dev.toysrus.com:8443",
                "service_type": "UnidentifiedService"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "stores.toysrus.com"
                ],
                "externally_detected_providers": [
                    "CloudFlare"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659397080000,
                "inactive_classifications": [],
                "ip_address": [
                    "104.18.71.71",
                    "104.18.70.71"
                ],
                "is_active": "Active",
                "last_observed": 1662417180000,
                "port": 8443,
                "protocol": "TCP",
                "service_id": "91d41c39-5eb1-35d9-a381-d19695e112e9",
                "service_name": "Unidentified Service at stores.toysrus.com:8443",
                "service_type": "UnidentifiedService"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "toysrus.com"
                ],
                "externally_detected_providers": [
                    "CloudFlare"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1661911020000,
                "inactive_classifications": [],
                "ip_address": [
                    "104.18.70.71",
                    "104.18.71.71"
                ],
                "is_active": "Active",
                "last_observed": 1662417180000,
                "port": 8443,
                "protocol": "TCP",
                "service_id": "0eb4e5db-a21f-3b87-9abe-9c4818ea1d57",
                "service_name": "Unidentified Service at toysrus.com:8443",
                "service_type": "UnidentifiedService"
            },
            {
                "active_classifications": [],
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "www.toysrus.com"
                ],
                "externally_detected_providers": [
                    "CloudFlare"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659396900000,
                "inactive_classifications": [],
                "ip_address": [
                    "104.18.71.71",
                    "104.18.70.71"
                ],
                "is_active": "Active",
                "last_observed": 1662455640000,
                "port": 8443,
                "protocol": "TCP",
                "service_id": "1d9ad8d3-7e16-3e27-a12b-5476793d6bda",
                "service_name": "Unidentified Service at www.toysrus.com:8443",
                "service_type": "UnidentifiedService"
            }
        ]
    }
}
```

#### Human Readable Output

>### External Services
>|active_classifications|business_units|discovery_type|domain|externally_detected_providers|externally_inferred_cves|externally_inferred_vulnerability_score|first_observed|inactive_classifications|ip_address|is_active|last_observed|port|protocol|service_id|service_name|service_type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| HttpServer,<br/>ServerSoftware | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | babiesrus.toysrus.com | Amazon Web Services |  |  | 1659396480000 |  | 52.85.247.24 | Active | 1661971320000 | 80 | TCP | 32c85ab1-fc98-3061-a813-2fe5daf7e7c5 | HTTP Server at babiesrus.toysrus.com:80 | HttpServer |
>| HttpServer,<br/>ServerSoftware | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | babyregistry.toysrus.com | Amazon Web Services |  |  | 1659394320000 |  | 52.84.52.93 | Active | 1662159600000 | 80 | TCP | e93eb602-3ed5-354e-b21e-aa33f3e2de28 | HTTP Server at babyregistry.toysrus.com:80 | HttpServer |
>| HttpServer,<br/>ServerSoftware | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | bru.truimg.toysrus.com | Amazon Web Services |  |  | 1659395460000 |  | 13.249.85.25,<br/>13.249.141.28,<br/>13.249.85.94,<br/>13.249.141.126,<br/>18.160.249.72,<br/>13.249.85.80,<br/>13.249.141.20,<br/>18.66.122.51,<br/>18.160.249.115,<br/>13.249.85.10,<br/>18.66.122.87,<br/>18.66.122.53,<br/>18.160.249.88,<br/>18.66.122.24,<br/>18.160.249.93,<br/>13.249.141.102 | Active | 1662427980000 | 443 | TCP | 7fd927d3-1740-36e0-b61b-b92ca32c16fb | HTTP Server at bru.truimg.toysrus.com:443 | HttpServer |
>| HttpServer,<br/>ServerSoftware | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | bru.truimg.toysrus.com | Amazon Web Services |  |  | 1659387360000 |  | 13.249.85.94 | Active | 1662064740000 | 80 | TCP | f0ed015d-ccca-3f18-9983-8d5598aa7e23 | HTTP Server at bru.truimg.toysrus.com:80 | HttpServer |
>| MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>MissingPublicKeyPinsHeader | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | careers.toysrus.com | Amazon Web Services | CVE-2020-11023,<br/>CVE-2020-11022 | 6.1 | 1659386460000 |  | 18.165.122.84,<br/>18.160.213.51,<br/>13.249.85.63,<br/>13.249.85.81,<br/>13.249.85.128,<br/>18.160.213.73,<br/>18.160.213.28,<br/>18.160.213.124,<br/>13.249.85.84 | Active | 1662425040000 | 443 | TCP | c546386c-e568-34d3-90eb-44792c99aee3 | HTTP Server at careers.toysrus.com:443 | HttpServer |
>| HttpServer | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | click.mail.toysrus.com | Other |  |  | 1659714720000 |  | 128.245.97.223 | Active | 1662311160000 | 443 | TCP | 9f3a7b63-c8e8-3a9e-9266-ba98a6d2d833 | HTTP Server at click.mail.toysrus.com:443 | HttpServer |
>| HttpServer | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | click.mail.toysrus.com | Other |  |  | 1659417900000 |  | 128.245.97.223 | Active | 1662100380000 | 80 | TCP | aaffe4d0-5e1a-3e9a-86cb-3a836c5e6838 | HTTP Server at click.mail.toysrus.com:80 | HttpServer |
>| MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>HttpServer,<br/>ServerSoftware,<br/>JQuery,<br/>MissingPublicKeyPinsHeader,<br/>DevelopmentEnvironment | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | dev.toysrus.com | CloudFlare | CVE-2020-11022,<br/>CVE-2020-11023,<br/>CVE-2015-9251,<br/>CVE-2019-11358 | 6.1 | 1659472200000 |  | 104.18.233.92,<br/>104.18.234.92 | Active | 1662428520000 | 443 | TCP | 4734cde0-8841-32e5-be7e-7ff240fb946c | HTTP Server at dev.toysrus.com:443 | HttpServer |
>| MissingXFrameOptionsHeader,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingStrictTransportSecurityHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MissingPublicKeyPinsHeader | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | metrics.toysrus.com | Adobe |  |  | 1659419940000 |  | 63.140.38.100,<br/>63.140.38.165,<br/>63.140.38.186 | Active | 1662130560000 | 80 | TCP | a972934f-c83b-31cd-b1cd-7686020c2414 | HTTP Server at metrics.toysrus.com:80 | HttpServer |
>| HttpServer | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | msoid.toysrus.com | Microsoft Azure |  |  | 1659395940000 |  | 40.126.29.13 | Active | 1661969880000 | 80 | TCP | 5e000e24-fcb6-3e3c-ab99-f7f053d5ef51 | HTTP Server at msoid.toysrus.com:80 | HttpServer |
>| HttpServer,<br/>ServerSoftware | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | rdcservicedesk.toysrus.com | Amazon Web Services |  |  | 1659476340000 |  | 3.212.20.158,<br/>54.146.255.102,<br/>3.224.224.12,<br/>100.25.178.60 | Active | 1662423240000 | 443 | TCP | 451f87a7-e326-3d0e-bd1f-97ae155dcb83 | HTTP Server at rdcservicedesk.toysrus.com:443 | HttpServer |
>| HttpServer,<br/>ServerSoftware | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | rintlservicedesk.toysrus.com | Amazon Web Services |  |  | 1659471900000 |  | 3.212.20.158,<br/>54.146.255.102,<br/>3.224.224.12,<br/>100.25.178.60 | Active | 1662425940000 | 443 | TCP | e9f60323-0c24-3cc3-b20a-884d26c2c194 | HTTP Server at rintlservicedesk.toysrus.com:443 | HttpServer |
>| HttpServer,<br/>ServerSoftware | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | rservicedesk.toysrus.com | Amazon Web Services |  |  | 1659478080000 |  | 3.212.20.158,<br/>54.146.255.102,<br/>3.224.224.12,<br/>100.25.178.60 | Active | 1662416400000 | 443 | TCP | f5753db9-7083-32f7-abeb-343d1cc007b0 | HTTP Server at rservicedesk.toysrus.com:443 | HttpServer |
>| HttpServer,<br/>ServerSoftware | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | rstoreservicedesk.toysrus.com | Amazon Web Services |  |  | 1659478380000 |  | 3.212.20.158,<br/>54.146.255.102,<br/>3.224.224.12,<br/>100.25.178.60 | Active | 1662411240000 | 443 | TCP | 408d9b01-9836-3aa5-8a3a-13c0f109de30 | HTTP Server at rstoreservicedesk.toysrus.com:443 | HttpServer |
>| HttpServer,<br/>ServerSoftware | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | stores.toysrus.com | CloudFlare |  |  | 1659400020000 |  | 104.18.70.71,<br/>104.18.71.71 | Active | 1662439680000 | 443 | TCP | c4d99802-1668-37a5-b6d2-bac8e01c1131 | HTTP Server at stores.toysrus.com:443 | HttpServer |
>| MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>HttpServer,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>MissingPublicKeyPinsHeader | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | teamtru.toysrus.com | Amazon Web Services |  |  | 1659386820000 |  | 13.33.243.96,<br/>18.66.122.129,<br/>13.32.208.101,<br/>13.226.225.101,<br/>13.33.243.105,<br/>108.159.227.23,<br/>13.224.189.40,<br/>13.33.65.104,<br/>99.86.224.25,<br/>13.249.141.43,<br/>18.65.25.19,<br/>18.165.122.119,<br/>13.32.208.119,<br/>18.65.25.86,<br/>13.249.141.32,<br/>13.226.225.127,<br/>13.226.225.60,<br/>18.65.25.30,<br/>18.66.122.34,<br/>108.159.227.63,<br/>108.157.150.120,<br/>13.249.141.92,<br/>13.32.208.71,<br/>18.65.25.42,<br/>13.33.243.74,<br/>108.159.227.51,<br/>13.32.208.15,<br/>18.165.122.20,<br/>13.224.189.18,<br/>108.157.150.46,<br/>108.157.150.105,<br/>108.157.150.43,<br/>18.66.122.52,<br/>52.84.52.98,<br/>13.33.65.87,<br/>13.224.189.23,<br/>13.224.189.88,<br/>13.33.243.88,<br/>18.165.122.31,<br/>13.33.65.95,<br/>108.159.227.33,<br/>13.249.141.71,<br/>18.66.122.61 | Active | 1662466920000 | 443 | TCP | 34593e05-736b-35ce-a97e-e844bce16e54 | HTTP Server at teamtru.toysrus.com:443 | HttpServer |
>| HttpServer,<br/>ServerSoftware | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | teamtru.toysrus.com | Amazon Web Services |  |  | 1659394500000 |  | 108.159.227.63 | Active | 1662154740000 | 80 | TCP | 20398abe-b1f1-3ec1-ab25-7fe70e51a410 | HTTP Server at teamtru.toysrus.com:80 | HttpServer |
>| HttpServer,<br/>ServerSoftware | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | toysrus.com | CloudFlare |  |  | 1662253080000 |  | 104.18.70.71,<br/>104.18.71.71 | Active | 1662439680000 | 443 | TCP | 935aa68a-c529-31b6-952d-4a1c2cc921a2 | HTTP Server at toysrus.com:443 | HttpServer |
>| HttpServer,<br/>ServerSoftware | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | toysrus.com | Amazon Web Services |  |  | 1659387000000 |  | 52.217.77.163 | Active | 1662068880000 | 80 | TCP | 50b8a0cd-6142-3a02-9d7e-2dba255f3e0e | HTTP Server at toysrus.com:80 | HttpServer |
>| HttpServer,<br/>ServerSoftware | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | truimg.toysrus.com | Amazon Web Services |  |  | 1659386940000 |  | 99.84.160.84,<br/>13.32.151.33,<br/>54.192.81.65,<br/>52.84.125.93,<br/>13.32.151.42,<br/>99.84.160.95,<br/>54.192.81.76,<br/>13.225.78.110,<br/>52.85.247.65,<br/>52.85.132.64,<br/>52.85.132.77,<br/>18.67.65.91,<br/>18.66.122.91,<br/>54.230.21.124,<br/>13.225.78.122,<br/>13.33.243.129,<br/>52.85.247.119,<br/>54.230.21.68,<br/>52.84.125.119,<br/>54.192.81.102,<br/>18.160.249.6,<br/>18.160.249.8,<br/>18.165.122.12,<br/>18.66.122.104,<br/>13.33.65.13,<br/>13.249.190.84,<br/>52.85.132.123,<br/>18.67.65.109,<br/>18.160.249.23,<br/>54.230.21.92,<br/>18.66.122.126,<br/>13.225.78.94,<br/>13.33.65.97,<br/>54.192.81.3,<br/>18.165.122.99,<br/>52.85.247.18,<br/>18.160.249.104,<br/>13.32.208.104,<br/>13.225.78.41,<br/>52.85.247.24,<br/>108.138.167.71,<br/>18.67.65.12,<br/>52.84.125.6,<br/>18.165.122.119,<br/>52.85.132.128,<br/>13.33.65.121,<br/>13.33.243.67,<br/>13.33.243.69,<br/>108.138.167.111,<br/>52.84.125.49,<br/>18.165.122.66,<br/>99.84.160.62,<br/>13.33.65.75,<br/>18.67.65.54,<br/>13.32.208.86,<br/>99.84.160.35,<br/>18.66.122.58,<br/>54.230.21.24 | Active | 1662466800000 | 443 | TCP | f833a3a2-c3bc-30a1-b6f9-73df27175889 | HTTP Server at truimg.toysrus.com:443 | HttpServer |
>| MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>JQuery,<br/>MissingPublicKeyPinsHeader | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | wholesale.toysrus.com | Amazon Web Services | CVE-2020-11023,<br/>CVE-2020-11022 | 6.1 | 1659395820000 |  | 65.8.49.73,<br/>108.156.120.41,<br/>108.156.120.121,<br/>65.8.49.14,<br/>13.249.85.129,<br/>108.156.120.16,<br/>108.156.120.33,<br/>65.8.49.86,<br/>13.249.85.7,<br/>65.8.49.87 | Active | 1662422100000 | 443 | TCP | 32ab36fa-4c9a-3e14-ba8a-6bee598ed88c | HTTP Server at wholesale.toysrus.com:443 | HttpServer |
>| MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingContentSecurityPolicyHeader,<br/>MissingStrictTransportSecurityHeader,<br/>HttpServer,<br/>ServerSoftware,<br/>MissingXContentTypeOptionsHeader,<br/>MissingCacheControlHeader,<br/>JQuery,<br/>MissingPublicKeyPinsHeader | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | www.careers.toysrus.com | Amazon Web Services | CVE-2020-11023,<br/>CVE-2020-11022 | 6.1 | 1659386460000 |  | 52.85.247.103,<br/>18.160.213.51,<br/>13.249.85.63,<br/>52.85.247.50,<br/>52.85.247.13,<br/>13.249.85.81,<br/>18.160.213.73,<br/>13.249.85.128,<br/>18.160.213.124,<br/>18.160.213.28,<br/>13.249.85.84,<br/>52.85.247.90 | Active | 1662427560000 | 443 | TCP | 38264ee2-a2d0-3910-b50f-0ab97abb0fd7 | HTTP Server at www.careers.toysrus.com:443 | HttpServer |
>| HttpServer,<br/>ServerSoftware | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | www.careers.toysrus.com | Amazon Web Services |  |  | 1659397920000 |  | 52.85.247.13,<br/>18.160.213.28,<br/>13.249.85.128 | Active | 1662141780000 | 80 | TCP | f20a9f52-21db-3ff5-a15f-e1f89855afac | HTTP Server at www.careers.toysrus.com:80 | HttpServer |
>| MissingXFrameOptionsHeader,<br/>MissingXXssProtectionHeader,<br/>MissingStrictTransportSecurityHeader,<br/>HttpServer,<br/>ServerSoftware,<br/>JQuery,<br/>MissingPublicKeyPinsHeader | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | www.toysrus.com | CloudFlare | CVE-2020-11023,<br/>CVE-2015-9251,<br/>CVE-2020-11022,<br/>CVE-2019-11358 | 6.1 | 1659396240000 | MissingXContentTypeOptionsHeader,<br/>MissingContentSecurityPolicyHeader | 104.18.70.71,<br/>104.18.71.71 | Active | 1662417180000 | 443 | TCP | dafffacb-235a-3bfa-bade-40743c9d8485 | HTTP Server at www.toysrus.com:443 | HttpServer |
>| DevelopmentEnvironment | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | dev.toysrus.com | CloudFlare |  |  | 1659400620000 |  | 104.18.233.92,<br/>104.18.234.92 | Active | 1662410520000 | 8443 | TCP | bfa86f48-1b21-377f-a3eb-b8b0af2b6e3e | Unidentified Service at dev.toysrus.com:8443 | UnidentifiedService |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | stores.toysrus.com | CloudFlare |  |  | 1659397080000 |  | 104.18.71.71,<br/>104.18.70.71 | Active | 1662417180000 | 8443 | TCP | 91d41c39-5eb1-35d9-a381-d19695e112e9 | Unidentified Service at stores.toysrus.com:8443 | UnidentifiedService |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | toysrus.com | CloudFlare |  |  | 1661911020000 |  | 104.18.70.71,<br/>104.18.71.71 | Active | 1662417180000 | 8443 | TCP | 0eb4e5db-a21f-3b87-9abe-9c4818ea1d57 | Unidentified Service at toysrus.com:8443 | UnidentifiedService |
>|  | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | DirectlyDiscovered | www.toysrus.com | CloudFlare |  |  | 1659396900000 |  | 104.18.71.71,<br/>104.18.70.71 | Active | 1662455640000 | 8443 | TCP | 1d9ad8d3-7e16-3e27-a12b-5476793d6bda | Unidentified Service at www.toysrus.com:8443 | UnidentifiedService |


### asm-getexternalservice
***
Get service details according to the service ID.


#### Base Command

`asm-getexternalservice`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_id | An string represenng the service ID you want get details for. | Required | 


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
                        "firstObserved": 1660188540000,
                        "lastObserved": 1662451740000,
                        "name": "SshServer",
                        "values": [
                            {
                                "firstObserved": 1660188560000,
                                "jsonValue": "{\"version\":\"2.0\",\"serverVersion\":\"OpenSSH_7.6p1\",\"extraInfo\":\"Ubuntu-4ubuntu0.7\"}",
                                "lastObserved": 1662451777000
                            },
                            {
                                "firstObserved": 1661234465000,
                                "jsonValue": "{\"version\":\"2.0\",\"serverVersion\":\"OpenSSH_8.2p1\",\"extraInfo\":\"Ubuntu-4ubuntu0.5\"}",
                                "lastObserved": 1661425762000
                            }
                        ]
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1660188540000,
                        "lastObserved": 1662445860000,
                        "name": "SSHWeakMACAlgorithmsEnabled",
                        "values": [
                            {
                                "firstObserved": 1660188560000,
                                "jsonValue": "{}",
                                "lastObserved": 1662445879000
                            }
                        ]
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1660188540000,
                        "lastObserved": 1662451740000,
                        "name": "OpenSSH",
                        "values": [
                            {
                                "firstObserved": 1660188560000,
                                "jsonValue": "{\"version\":\"7.6\"}",
                                "lastObserved": 1662451777000
                            },
                            {
                                "firstObserved": 1661234465000,
                                "jsonValue": "{\"version\":\"8.2\"}",
                                "lastObserved": 1661425762000
                            }
                        ]
                    }
                ],
                "domains": [],
                "enrichedObservationSource": "ON_PREM",
                "inferredCvesObserved": [
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1660188560000,
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
                        "lastObserved": 1662451777000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1660188560000,
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
                        "lastObserved": 1662451777000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1660188560000,
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
                        "lastObserved": 1662451777000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1660188560000,
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
                        "lastObserved": 1662451777000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1660188560000,
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
                        "lastObserved": 1662451777000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1660188560000,
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
                        "lastObserved": 1662451777000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1660188560000,
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
                        "lastObserved": 1662451777000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1660188560000,
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
                        "lastObserved": 1662451777000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1660188560000,
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
                        "lastObserved": 1662451777000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1660188560000,
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
                        "lastObserved": 1662451777000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1660188560000,
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
                        "lastObserved": 1662451777000
                    }
                ],
                "ip_ranges": {
                    "52.22.120.51": {
                        "FIRST_IP": "52.22.120.51",
                        "IP_RANGE_ID": "1093124c-ce26-33ba-8fb8-937fecb4c7b6",
                        "LAST_IP": "52.22.120.51"
                    }
                },
                "ips": [
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1660188560000,
                        "geolocation": {
                            "city": "ASHBURN",
                            "countryCode": "US",
                            "latitude": 39.0438,
                            "longitude": -77.4879,
                            "regionCode": "VA",
                            "timeZone": null
                        },
                        "ip": 873887795,
                        "lastObserved": 1662451777000,
                        "protocol": "TCP",
                        "provider": "OnPrem"
                    }
                ],
                "providerDetails": [
                    {
                        "firstObserved": 1660188560000,
                        "lastObserved": 1662451777000,
                        "name": "OnPrem"
                    }
                ],
                "serviceKey": "52.22.120.51:22",
                "serviceKeyType": "IP",
                "tlsVersions": []
            },
            "discovery_type": "DirectlyDiscovered",
            "domain": [],
            "externally_detected_providers": [
                "On Prem"
            ],
            "externally_inferred_cves": [
                "CVE-2020-15778",
                "CVE-2021-41617",
                "CVE-2019-6109",
                "CVE-2019-6110",
                "CVE-2019-6111",
                "CVE-2020-14145",
                "CVE-2018-20685",
                "CVE-2018-15919",
                "CVE-2018-15473",
                "CVE-2016-20012",
                "CVE-2021-36368"
            ],
            "externally_inferred_vulnerability_score": 7.8,
            "first_observed": 1660188540000,
            "inactive_classifications": [],
            "ip_address": [
                "52.22.120.51"
            ],
            "is_active": "Active",
            "last_observed": 1662451740000,
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
>| SSHWeakMACAlgorithmsEnabled,<br/>SshServer,<br/>OpenSSH | jwilkes - Toys R US | serviceKey: 52.22.120.51:22<br/>serviceKeyType: IP<br/>businessUnits: {'name': 'jwilkes - Toys R US'}<br/>providerDetails: {'name': 'OnPrem', 'firstObserved': 1660188560000, 'lastObserved': 1662451777000}<br/>certificates: <br/>domains: <br/>ips: {'ip': 873887795, 'protocol': 'TCP', 'provider': 'OnPrem', 'geolocation': {'latitude': 39.0438, 'longitude': -77.4879, 'countryCode': 'US', 'city': 'ASHBURN', 'regionCode': 'VA', 'timeZone': None}, 'activityStatus': 'Active', 'lastObserved': 1662451777000, 'firstObserved': 1660188560000}<br/>classifications: {'name': 'SshServer', 'activityStatus': 'Active', 'values': [{'jsonValue': '{"version":"2.0","serverVersion":"OpenSSH_7.6p1","extraInfo":"Ubuntu-4ubuntu0.7"}', 'firstObserved': 1660188560000, 'lastObserved': 1662451777000}, {'jsonValue': '{"version":"2.0","serverVersion":"OpenSSH_8.2p1","extraInfo":"Ubuntu-4ubuntu0.5"}', 'firstObserved': 1661234465000, 'lastObserved': 1661425762000}], 'firstObserved': 1660188540000, 'lastObserved': 1662451740000},<br/>{'name': 'SSHWeakMACAlgorithmsEnabled', 'activityStatus': 'Active', 'values': [{'jsonValue': '{}', 'firstObserved': 1660188560000, 'lastObserved': 1662445879000}], 'firstObserved': 1660188540000, 'lastObserved': 1662445860000},<br/>{'name': 'OpenSSH', 'activityStatus': 'Active', 'values': [{'jsonValue': '{"version":"7.6"}', 'firstObserved': 1660188560000, 'lastObserved': 1662451777000}, {'jsonValue': '{"version":"8.2"}', 'firstObserved': 1661234465000, 'lastObserved': 1661425762000}], 'firstObserved': 1660188540000, 'lastObserved': 1662451740000}<br/>tlsVersions: <br/>inferredCvesObserved: {'inferredCve': {'cveId': 'CVE-2020-15778', 'cvssScoreV2': 6.8, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 7.8, 'cveSeverityV3': 'HIGH', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1660188560000, 'lastObserved': 1662451777000},<br/>{'inferredCve': {'cveId': 'CVE-2021-41617', 'cvssScoreV2': 4.4, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 7.0, 'cveSeverityV3': 'HIGH', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1660188560000, 'lastObserved': 1662451777000},<br/>{'inferredCve': {'cveId': 'CVE-2019-6109', 'cvssScoreV2': 4.0, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 6.8, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1660188560000, 'lastObserved': 1662451777000},<br/>{'inferredCve': {'cveId': 'CVE-2019-6110', 'cvssScoreV2': 4.0, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 6.8, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1660188560000, 'lastObserved': 1662451777000},<br/>{'inferredCve': {'cveId': 'CVE-2019-6111', 'cvssScoreV2': 5.8, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 5.9, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1660188560000, 'lastObserved': 1662451777000},<br/>{'inferredCve': {'cveId': 'CVE-2020-14145', 'cvssScoreV2': 4.3, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 5.9, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1660188560000, 'lastObserved': 1662451777000},<br/>{'inferredCve': {'cveId': 'CVE-2018-20685', 'cvssScoreV2': 2.6, 'cveSeverityV2': 'LOW', 'cvssScoreV3': 5.3, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1660188560000, 'lastObserved': 1662451777000},<br/>{'inferredCve': {'cveId': 'CVE-2018-15919', 'cvssScoreV2': 5.0, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 5.3, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1660188560000, 'lastObserved': 1662451777000},<br/>{'inferredCve': {'cveId': 'CVE-2018-15473', 'cvssScoreV2': 5.0, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 5.3, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1660188560000, 'lastObserved': 1662451777000},<br/>{'inferredCve': {'cveId': 'CVE-2016-20012', 'cvssScoreV2': 4.3, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 5.3, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1660188560000, 'lastObserved': 1662451777000},<br/>{'inferredCve': {'cveId': 'CVE-2021-36368', 'cvssScoreV2': 2.6, 'cveSeverityV2': 'LOW', 'cvssScoreV3': 3.7, 'cveSeverityV3': 'LOW', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1660188560000, 'lastObserved': 1662451777000}<br/>enrichedObservationSource: ON_PREM<br/>ip_ranges: {"52.22.120.51": {"IP_RANGE_ID": "1093124c-ce26-33ba-8fb8-937fecb4c7b6", "FIRST_IP": "52.22.120.51", "LAST_IP": "52.22.120.51"}} | DirectlyDiscovered | On Prem | CVE-2020-15778,<br/>CVE-2021-41617,<br/>CVE-2019-6109,<br/>CVE-2019-6110,<br/>CVE-2019-6111,<br/>CVE-2020-14145,<br/>CVE-2018-20685,<br/>CVE-2018-15919,<br/>CVE-2018-15473,<br/>CVE-2016-20012,<br/>CVE-2021-36368 | 7.8 | 1660188540000 | 52.22.120.51 | Active | 1662451740000 | 22 | TCP | 94232f8a-f001-3292-aa65-63fa9d981427 | SSH Server at 52.22.120.51:22 | SshServer |


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
                "date_added": 1662469268313,
                "first_ip": "220.241.52.192",
                "ips_count": 64,
                "last_ip": "220.241.52.255",
                "organization_handles": [
                    "BNA2-AP",
                    "MAINT-HK-PCCW-BIA-CS",
                    "TA66-AP"
                ],
                "range_id": "4da29b7f-3086-3b52-981b-aa8ee5da1e60"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268313,
                "first_ip": "217.206.176.80",
                "ips_count": 16,
                "last_ip": "217.206.176.95",
                "organization_handles": [
                    "EASYNET-UK-MNT",
                    "JW372-RIPE",
                    "EH92-RIPE",
                    "AR17615-RIPE"
                ],
                "range_id": "6ef4638e-7788-3ef5-98a5-ad5b7f4e02f5"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "date_added": 1662469268312,
                "first_ip": "217.146.128.193",
                "ips_count": 1,
                "last_ip": "217.146.128.193",
                "organization_handles": [
                    "QSC-NOC",
                    "MW10972-RIPE",
                    "PLUSNET-LIR",
                    "ORG-PG203-RIPE",
                    "PLUS-DE",
                    "CV1903",
                    "QSC1-RIPE",
                    "RW4876-RIPE",
                    "BF359-RIPE",
                    "BZ1613-RIPE",
                    "GHM-RIPE"
                ],
                "range_id": "c3255500-d44e-352f-ba6a-b83f185ea892"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268312,
                "first_ip": "217.33.31.24",
                "ips_count": 8,
                "last_ip": "217.33.31.31",
                "organization_handles": [
                    "AR13878-RIPE",
                    "BTNET-MNT",
                    "CD7018-RIPE"
                ],
                "range_id": "f373c1d1-bcbe-322e-8408-feb764ce055d"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268312,
                "first_ip": "216.219.77.96",
                "ips_count": 16,
                "last_ip": "216.219.77.111",
                "organization_handles": [
                    "ENTRI-ARIN",
                    "PSE26-ARIN",
                    "ENTRI-3"
                ],
                "range_id": "6a9aa802-a8c1-3d96-ac34-5370f51eaf33"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268311,
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
                "date_added": 1662469268311,
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
                "date_added": 1662469268311,
                "first_ip": "216.14.189.176",
                "ips_count": 16,
                "last_ip": "216.14.189.191",
                "organization_handles": [
                    "RCU6-ARIN",
                    "GAM43-ARIN",
                    "RGS8-ARIN",
                    "PAI2-ARIN",
                    "POPPC-1"
                ],
                "range_id": "932019a5-0be3-3306-8cc6-6038b3cd233e"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268310,
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
                "date_added": 1662469268310,
                "first_ip": "213.221.18.142",
                "ips_count": 1,
                "last_ip": "213.221.18.142",
                "organization_handles": [
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "SNK35-RIPE",
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "b6a40889-27b2-3374-94c2-23a607d13f7b"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268310,
                "first_ip": "213.221.7.132",
                "ips_count": 1,
                "last_ip": "213.221.7.132",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "c136c373-8650-3418-a5e7-ea81507cbff2"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268310,
                "first_ip": "213.221.7.34",
                "ips_count": 1,
                "last_ip": "213.221.7.34",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "2160df6c-8009-3696-8794-185d312c960b"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "date_added": 1662469268309,
                "first_ip": "213.160.15.168",
                "ips_count": 8,
                "last_ip": "213.160.15.175",
                "organization_handles": [
                    "QSC-NOC",
                    "MW10972-RIPE",
                    "PLUSNET-LIR",
                    "ORG-PG203-RIPE",
                    "PLUS-DE",
                    "CV1903",
                    "QSC1-RIPE",
                    "RW4876-RIPE",
                    "BF359-RIPE",
                    "BZ1613-RIPE",
                    "GHM-RIPE"
                ],
                "range_id": "17da75f2-bb5a-3a56-8da0-e809182345e1"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268309,
                "first_ip": "213.62.189.64",
                "ips_count": 64,
                "last_ip": "213.62.189.127",
                "organization_handles": [
                    "MAINT-AS2686",
                    "SB1432-RIPE",
                    "AR13530-RIPE",
                    "EU-IBM-NIC-MNT"
                ],
                "range_id": "75bd74d9-6751-3c19-b400-789e8adc3303"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268309,
                "first_ip": "213.62.187.48",
                "ips_count": 16,
                "last_ip": "213.62.187.63",
                "organization_handles": [
                    "MAINT-AS2686",
                    "PW373-RIPE",
                    "AR13530-RIPE",
                    "EU-IBM-NIC-MNT",
                    "MAINT-AS2686",
                    "AR13530-RIPE",
                    "EU-IBM-NIC-MNT",
                    "PT366-RIPE"
                ],
                "range_id": "a165bf59-73df-3557-b912-cc1bf38c8acc"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268308,
                "first_ip": "213.62.185.192",
                "ips_count": 64,
                "last_ip": "213.62.185.255",
                "organization_handles": [
                    "MAINT-AS2686",
                    "AR13530-RIPE",
                    "TS10976-RIPE",
                    "EU-IBM-NIC-MNT"
                ],
                "range_id": "aa7c7b2b-7539-307e-90de-40ef864abce2"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268308,
                "first_ip": "213.33.183.115",
                "ips_count": 1,
                "last_ip": "213.33.183.115",
                "organization_handles": [
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "AN30686-RIPE",
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "a7e4e17d-ebb1-34a8-b6f7-da037f41bd09"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268308,
                "first_ip": "213.33.171.220",
                "ips_count": 1,
                "last_ip": "213.33.171.220",
                "organization_handles": [
                    "SVNT2-RIPE",
                    "KI1346-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "a343cda5-4dbc-3316-ac2e-bb222cc325ef"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268308,
                "first_ip": "213.33.146.41",
                "ips_count": 1,
                "last_ip": "213.33.146.41",
                "organization_handles": [
                    "SVNT2-RIPE",
                    "AVS408-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "4eb59610-aa21-3d16-b2fe-04f4116cd99d"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "date_added": 1662469268307,
                "first_ip": "212.202.236.96",
                "ips_count": 4,
                "last_ip": "212.202.236.99",
                "organization_handles": [
                    "QSC-NOC",
                    "MW10972-RIPE",
                    "PLUSNET-LIR",
                    "ORG-PG203-RIPE",
                    "PLUS-DE",
                    "CV1903",
                    "QSC1-RIPE",
                    "RW4876-RIPE",
                    "BF359-RIPE",
                    "BZ1613-RIPE",
                    "GHM-RIPE"
                ],
                "range_id": "b31c527f-785b-37c9-b2ba-c1057554f5c2"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "date_added": 1662469268307,
                "first_ip": "212.202.117.87",
                "ips_count": 1,
                "last_ip": "212.202.117.87",
                "organization_handles": [
                    "QSC-NOC",
                    "MW10972-RIPE",
                    "PLUSNET-LIR",
                    "ORG-PG203-RIPE",
                    "PLUS-DE",
                    "CV1903",
                    "QSC1-RIPE",
                    "RW4876-RIPE",
                    "BF359-RIPE",
                    "BZ1613-RIPE",
                    "GHM-RIPE"
                ],
                "range_id": "a0d86fcf-16ab-3114-a3e2-f435b656c0c9"
            },
            {
                "active_responsive_ips_count": 6,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268307,
                "first_ip": "212.187.197.248",
                "ips_count": 8,
                "last_ip": "212.187.197.255",
                "organization_handles": [
                    "LEVEL3-MNT",
                    "PS20887-RIPE",
                    "AR13812-RIPE"
                ],
                "range_id": "3d3d611b-b2da-3850-8d29-6f3b1552cc32"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268307,
                "first_ip": "212.119.250.34",
                "ips_count": 1,
                "last_ip": "212.119.250.34",
                "organization_handles": [
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "AA26239-RIPE",
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "089048a9-da4d-32dd-871c-1f956388ba77"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268306,
                "first_ip": "212.119.241.164",
                "ips_count": 1,
                "last_ip": "212.119.241.164",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "9e9bf8b3-232e-383e-8efa-63b4ead51890"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268306,
                "first_ip": "212.119.193.34",
                "ips_count": 1,
                "last_ip": "212.119.193.34",
                "organization_handles": [
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "NM7815-RIPE",
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "31daae58-94fa-3b95-aa1d-9b6c06fb8792"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "date_added": 1662469268306,
                "first_ip": "212.60.209.246",
                "ips_count": 1,
                "last_ip": "212.60.209.246",
                "organization_handles": [
                    "QSC-NOC",
                    "MW10972-RIPE",
                    "PLUSNET-LIR",
                    "ORG-PG203-RIPE",
                    "PLUS-DE",
                    "CV1903",
                    "QSC1-RIPE",
                    "RW4876-RIPE",
                    "BF359-RIPE",
                    "BZ1613-RIPE",
                    "GHM-RIPE"
                ],
                "range_id": "17f816ef-b4c3-330c-ac83-31250b34504f"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268305,
                "first_ip": "212.44.158.89",
                "ips_count": 1,
                "last_ip": "212.44.158.89",
                "organization_handles": [
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SA38081-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "bf773fb8-2395-3835-9175-5d86c22a393c"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268305,
                "first_ip": "212.44.139.46",
                "ips_count": 1,
                "last_ip": "212.44.139.46",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "9527e5ef-5fa5-393a-9451-747822cd1e50"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268305,
                "first_ip": "209.219.204.104",
                "ips_count": 16,
                "last_ip": "209.219.204.119",
                "organization_handles": [
                    "IED5-ARIN",
                    "TRU7",
                    "ZN90-ARIN",
                    "TRU9",
                    "IED6-ARIN",
                    "ZN90-ARIN"
                ],
                "range_id": "589e7967-28e5-3d86-a29a-082295223730"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268305,
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
                "date_added": 1662469268304,
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
                "date_added": 1662469268304,
                "first_ip": "209.92.240.104",
                "ips_count": 8,
                "last_ip": "209.92.240.111",
                "organization_handles": [
                    "GRADY2-ARIN",
                    "WINDS-ARIN",
                    "WINDS1-ARIN",
                    "WINDS-6"
                ],
                "range_id": "35fe2ae3-eca0-34b6-a208-e32c72fabe83"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268304,
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
                "date_added": 1662469268304,
                "first_ip": "208.131.237.16",
                "ips_count": 16,
                "last_ip": "208.131.237.31",
                "organization_handles": [
                    "HALMA",
                    "SSE18-ARIN",
                    "SSE49-ARIN"
                ],
                "range_id": "99e5c6cd-c903-363d-b4ad-3499b64a5c8f"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268303,
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
                "date_added": 1662469268303,
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
                "date_added": 1662469268303,
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
                "date_added": 1662469268302,
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
                "date_added": 1662469268302,
                "first_ip": "208.57.117.240",
                "ips_count": 8,
                "last_ip": "208.57.117.247",
                "organization_handles": [
                    "MSDMCD",
                    "LSE19-ARIN"
                ],
                "range_id": "ec2a44fa-6f94-3765-9e54-a4606ea87547"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268302,
                "first_ip": "208.46.77.88",
                "ips_count": 8,
                "last_ip": "208.46.77.95",
                "organization_handles": [
                    "ANDER-66",
                    "VSE9-ARIN"
                ],
                "range_id": "99b04966-7c3e-3df9-93d3-d41a2f627d61"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268301,
                "first_ip": "208.46.4.120",
                "ips_count": 8,
                "last_ip": "208.46.4.127",
                "organization_handles": [
                    "BISSE12-ARIN",
                    "MCC-563"
                ],
                "range_id": "26206a59-21d8-386b-8811-7b0b6b520ebd"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268301,
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
                "date_added": 1662469268301,
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
                "date_added": 1662469268300,
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
                "date_added": 1662469268300,
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
                "date_added": 1662469268300,
                "first_ip": "207.61.90.0",
                "ips_count": 16,
                "last_ip": "207.61.90.15",
                "organization_handles": [
                    "SYSAD-ARIN",
                    "SOCEV-ARIN",
                    "ABUSE1127-ARIN",
                    "ABAI1-ARIN",
                    "ANR1-ARIN",
                    "DHANJ1-ARIN",
                    "LINX",
                    "IRRAD-ARIN"
                ],
                "range_id": "ccaeaac3-6e4c-39a8-ad2a-757471fa2b5a"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268300,
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
                "date_added": 1662469268299,
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
                "date_added": 1662469268299,
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
                "date_added": 1662469268299,
                "first_ip": "206.70.0.0",
                "ips_count": 65536,
                "last_ip": "206.70.255.255",
                "organization_handles": [
                    "IPROU3-ARIN",
                    "AEA8-ARIN",
                    "ARMP-ARIN",
                    "ANO24-ARIN",
                    "AT-88-Z",
                    "AANO1-ARIN",
                    "IPMAN40-ARIN"
                ],
                "range_id": "7843b0e2-b0ae-37aa-9a58-b047a5ff8a13"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268299,
                "first_ip": "206.61.114.0",
                "ips_count": 64,
                "last_ip": "206.61.114.63",
                "organization_handles": [
                    "SWAET-ARIN",
                    "SIE-ARIN",
                    "FIUMA2-ARIN",
                    "SPRINT-NOC-ARIN",
                    "CHUYI-ARIN",
                    "SPRN-Z",
                    "SWIS1-ARIN"
                ],
                "range_id": "328d96ff-ca76-3199-8dfe-ff15eb260b37"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268298,
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
                "date_added": 1662469268298,
                "first_ip": "206.31.22.96",
                "ips_count": 24,
                "last_ip": "206.31.22.119",
                "organization_handles": [
                    "JMO368-ARIN",
                    "JMO391-ARIN",
                    "SEARS-5",
                    "JMO368-ARIN",
                    "JMO391-ARIN",
                    "SEARS-5"
                ],
                "range_id": "229bdac6-1641-346a-be24-342589903bb5"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268298,
                "first_ip": "206.31.22.72",
                "ips_count": 8,
                "last_ip": "206.31.22.79",
                "organization_handles": [
                    "JMO368-ARIN",
                    "JMO391-ARIN",
                    "SEARS-5"
                ],
                "range_id": "ca996353-06f9-330d-bb30-b4ce2ef32053"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268297,
                "first_ip": "206.31.19.0",
                "ips_count": 256,
                "last_ip": "206.31.19.255",
                "organization_handles": [
                    "JMO368-ARIN",
                    "SEARS-5"
                ],
                "range_id": "f6dd9287-4494-383f-9b8d-7fed3a951377"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268297,
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
                "date_added": 1662469268297,
                "first_ip": "206.25.242.64",
                "ips_count": 16,
                "last_ip": "206.25.242.79",
                "organization_handles": [
                    "SHMC-4",
                    "BUHLE2-ARIN"
                ],
                "range_id": "4ba2a741-8533-3095-ba60-4dc257d3ba17"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268296,
                "first_ip": "205.217.5.176",
                "ips_count": 16,
                "last_ip": "205.217.5.191",
                "organization_handles": [
                    "ENTRI-ARIN",
                    "PSE26-ARIN",
                    "ENTRI-3"
                ],
                "range_id": "e4005032-44b2-3b70-848a-db97087350ae"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268296,
                "first_ip": "205.217.4.152",
                "ips_count": 8,
                "last_ip": "205.217.4.159",
                "organization_handles": [
                    "ENTRI-ARIN",
                    "PSE26-ARIN",
                    "ENTRI-3"
                ],
                "range_id": "9d923c7a-f051-3b62-b653-81170ff17a88"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268296,
                "first_ip": "204.238.251.0",
                "ips_count": 256,
                "last_ip": "204.238.251.255",
                "organization_handles": [
                    "ISSM",
                    "JG525-ARIN"
                ],
                "range_id": "0a237ed4-c5a2-317b-9812-243419b76d12"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268296,
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
                "date_added": 1662469268295,
                "first_ip": "202.84.36.200",
                "ips_count": 8,
                "last_ip": "202.84.36.207",
                "organization_handles": [
                    "MAINT-BD-BOL",
                    "BOC1-AP",
                    "BNA20-AP",
                    "AB1162-AP",
                    "IRT-BOL-BD"
                ],
                "range_id": "55588822-40dc-3fa8-945d-ec7d4991047e"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268295,
                "first_ip": "199.245.184.0",
                "ips_count": 256,
                "last_ip": "199.245.184.255",
                "organization_handles": [
                    "PS82-ARIN",
                    "PAULSE"
                ],
                "range_id": "a705dbb6-1f66-34d0-90fa-9908bc689df4"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268295,
                "first_ip": "199.181.104.0",
                "ips_count": 256,
                "last_ip": "199.181.104.255",
                "organization_handles": [
                    "OPUSII",
                    "KS139-ARIN"
                ],
                "range_id": "b8d070ee-870d-319e-aaf9-ee4700e87e36"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268294,
                "first_ip": "199.101.129.222",
                "ips_count": 1,
                "last_ip": "199.101.129.222",
                "organization_handles": [
                    "CARST4-ARIN",
                    "FROST151-ARIN",
                    "XN-46"
                ],
                "range_id": "2ed225e0-d10f-3276-ac5f-0246a4f9724a"
            },
            {
                "active_responsive_ips_count": 9,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268294,
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
                "date_added": 1662469268294,
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
                "date_added": 1662469268293,
                "first_ip": "198.179.146.0",
                "ips_count": 1280,
                "last_ip": "198.179.150.255",
                "organization_handles": [
                    "TK551-ARIN",
                    "SDR",
                    "SDR-4",
                    "TK551-ARIN",
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
                "date_added": 1662469268293,
                "first_ip": "195.239.243.131",
                "ips_count": 1,
                "last_ip": "195.239.243.131",
                "organization_handles": [
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "FNV16-RIPE",
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "13317e10-847b-3867-8685-e1aa98486e67"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268293,
                "first_ip": "195.239.216.254",
                "ips_count": 1,
                "last_ip": "195.239.216.254",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "f3604508-6dd1-3811-9b85-22a909466f25"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268292,
                "first_ip": "195.239.185.5",
                "ips_count": 1,
                "last_ip": "195.239.185.5",
                "organization_handles": [
                    "SVNT2-RIPE",
                    "SSS154-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "f424a12d-a5c6-3ab1-b179-b3d674898c96"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268292,
                "first_ip": "195.239.182.70",
                "ips_count": 1,
                "last_ip": "195.239.182.70",
                "organization_handles": [
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "RV7226-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "cada51b8-d533-39db-bee7-3c36d75aa5f5"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268292,
                "first_ip": "195.239.149.214",
                "ips_count": 1,
                "last_ip": "195.239.149.214",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "6bc20932-49ec-3ec1-949d-d0bde2919c09"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268292,
                "first_ip": "195.239.144.186",
                "ips_count": 1,
                "last_ip": "195.239.144.186",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "AS3216-MNT",
                    "SOVINTEL-MNT",
                    "ORG-ES15-RIPE",
                    "SVNT2-RIPE",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE"
                ],
                "range_id": "0a494860-7a95-37a9-a155-29b476c77d66"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268291,
                "first_ip": "195.239.71.52",
                "ips_count": 1,
                "last_ip": "195.239.71.52",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "e8c77b84-4ba9-3e70-82f7-c0934df13c47"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268291,
                "first_ip": "195.239.67.42",
                "ips_count": 1,
                "last_ip": "195.239.67.42",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "dacf677c-f282-341d-b83a-945917c1cac8"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268291,
                "first_ip": "195.239.57.170",
                "ips_count": 1,
                "last_ip": "195.239.57.170",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "60801299-e0bc-3f66-8ee9-61806eedb05a"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268290,
                "first_ip": "195.239.57.94",
                "ips_count": 1,
                "last_ip": "195.239.57.94",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "ddb65106-ac78-32cc-a3a0-1742de79efa0"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268290,
                "first_ip": "195.239.55.134",
                "ips_count": 1,
                "last_ip": "195.239.55.134",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "968f2610-34b8-3f25-922a-1010a86dd335"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268290,
                "first_ip": "195.239.35.114",
                "ips_count": 1,
                "last_ip": "195.239.35.114",
                "organization_handles": [
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "EB8881-RIPE",
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "2772142b-b0b1-3c1b-9d42-2508f3f05d03"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268290,
                "first_ip": "195.222.186.100",
                "ips_count": 1,
                "last_ip": "195.222.186.100",
                "organization_handles": [
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "BN2575-RIPE",
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "b5460599-43a8-3ba7-bda6-fb0ea38fe443"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268289,
                "first_ip": "195.222.181.53",
                "ips_count": 1,
                "last_ip": "195.222.181.53",
                "organization_handles": [
                    "SVNT2-RIPE",
                    "TN1700-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "0b8cb3aa-cd64-3591-b49c-8bcda0569a4e"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268289,
                "first_ip": "195.212.0.0",
                "ips_count": 16,
                "last_ip": "195.212.0.15",
                "organization_handles": [
                    "MAINT-AS2686",
                    "AR13530-RIPE",
                    "EU-IBM-NIC-MNT",
                    "MB2864-RIPE"
                ],
                "range_id": "25b63226-9f5c-33eb-a6f8-70e6110b6538"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268289,
                "first_ip": "195.183.81.0",
                "ips_count": 32,
                "last_ip": "195.183.81.31",
                "organization_handles": [
                    "MAINT-AS2686",
                    "AR13530-RIPE",
                    "EU-IBM-NIC-MNT",
                    "PD127-RIPE"
                ],
                "range_id": "098a9e3e-4a9b-31f0-abdf-c61741a7d894"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268289,
                "first_ip": "195.183.61.0",
                "ips_count": 64,
                "last_ip": "195.183.61.63",
                "organization_handles": [
                    "MAINT-AS2686",
                    "AR13530-RIPE",
                    "EU-IBM-NIC-MNT",
                    "MA1079-RIPE"
                ],
                "range_id": "9b26dd2c-bba5-3d6c-a3c0-188d8cd02599"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268288,
                "first_ip": "195.157.206.104",
                "ips_count": 8,
                "last_ip": "195.157.206.111",
                "organization_handles": [
                    "CH309-RIPE",
                    "AS8426-MNT",
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
                "date_added": 1662469268288,
                "first_ip": "195.153.34.192",
                "ips_count": 16,
                "last_ip": "195.153.34.207",
                "organization_handles": [
                    "KW322-RIPE",
                    "REACHUK-MNT",
                    "AR17873-RIPE",
                    "PSINET-UK-SYSADMIN"
                ],
                "range_id": "bfcd8547-aa3c-3788-a999-d57d4a91af12"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268288,
                "first_ip": "195.118.127.192",
                "ips_count": 64,
                "last_ip": "195.118.127.255",
                "organization_handles": [
                    "MAINT-AS2686",
                    "AR13530-RIPE",
                    "DF498-RIPE",
                    "EU-IBM-NIC-MNT"
                ],
                "range_id": "03fc6d7e-a8bc-3633-b517-f45e158cbf47"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268287,
                "first_ip": "195.68.188.220",
                "ips_count": 1,
                "last_ip": "195.68.188.220",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "fe3ac6c1-5e6c-36aa-826b-4529cb8f4c4e"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268287,
                "first_ip": "195.68.168.13",
                "ips_count": 1,
                "last_ip": "195.68.168.13",
                "organization_handles": [
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "SSV242-RIPE",
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "c055e8f6-83c0-3e17-8043-7c73a917ea53"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268287,
                "first_ip": "195.68.166.251",
                "ips_count": 1,
                "last_ip": "195.68.166.251",
                "organization_handles": [
                    "SVNT2-RIPE",
                    "VVZ30-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "b12479a0-eb71-3ed9-8b7a-42ea9c19116c"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268287,
                "first_ip": "195.68.165.75",
                "ips_count": 1,
                "last_ip": "195.68.165.75",
                "organization_handles": [
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "SVNT2-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "5f90df40-36ec-3434-b4e8-4e78254f20dd"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268286,
                "first_ip": "195.68.153.227",
                "ips_count": 1,
                "last_ip": "195.68.153.227",
                "organization_handles": [
                    "NAZ4-RIPE",
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "1df62e7d-a40b-3155-a83b-7b62b960c45c"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268286,
                "first_ip": "195.68.153.34",
                "ips_count": 1,
                "last_ip": "195.68.153.34",
                "organization_handles": [
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "BD9650-RIPE",
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "f683c442-a1dd-3dbb-8fe7-36ccda1ae2b2"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268286,
                "first_ip": "195.68.147.38",
                "ips_count": 1,
                "last_ip": "195.68.147.38",
                "organization_handles": [
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "GI3018-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "80f4a852-e2b7-36b9-b28f-c1a29b36faf6"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268285,
                "first_ip": "195.68.145.155",
                "ips_count": 1,
                "last_ip": "195.68.145.155",
                "organization_handles": [
                    "SVNT2-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "YM1941-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "9337cc05-15c7-3926-ae91-dbb55980af15"
            },
            {
                "active_responsive_ips_count": 1,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268285,
                "first_ip": "195.68.131.22",
                "ips_count": 1,
                "last_ip": "195.68.131.22",
                "organization_handles": [
                    "SVNT2-RIPE",
                    "VS2745-RIPE",
                    "SOVINTEL-MNT",
                    "SVNT1-RIPE",
                    "ORG-ES15-RIPE"
                ],
                "range_id": "e47e147f-4436-3b5e-b3e3-29f6613f3312"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268285,
                "first_ip": "195.59.205.0",
                "ips_count": 16,
                "last_ip": "195.59.205.15",
                "organization_handles": [
                    "AR40377-RIPE",
                    "CW-DNS-MNT",
                    "GSOC-RIPE",
                    "CW-EUROPE-GSOC"
                ],
                "range_id": "69c26f54-7f07-331f-b700-5882ab12a5d6"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268285,
                "first_ip": "195.59.203.176",
                "ips_count": 16,
                "last_ip": "195.59.203.191",
                "organization_handles": [
                    "AR40377-RIPE",
                    "CW-DNS-MNT",
                    "GSOC-RIPE",
                    "CW-EUROPE-GSOC"
                ],
                "range_id": "9da67af4-3a1b-3e01-b43f-8a19a9a150bb"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "date_added": 1662469268284,
                "first_ip": "195.53.117.184",
                "ips_count": 8,
                "last_ip": "195.53.117.191",
                "organization_handles": [
                    "MAINT-AS3352",
                    "NSYS2-RIPE",
                    "JS27349-RIPE"
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
>| 0 | jwilkes test - VanDelay Industries | 1662469268313 | 220.241.52.192 | 64 | 220.241.52.255 | BNA2-AP,<br/>MAINT-HK-PCCW-BIA-CS,<br/>TA66-AP | 4da29b7f-3086-3b52-981b-aa8ee5da1e60 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268313 | 217.206.176.80 | 16 | 217.206.176.95 | EASYNET-UK-MNT,<br/>JW372-RIPE,<br/>EH92-RIPE,<br/>AR17615-RIPE | 6ef4638e-7788-3ef5-98a5-ad5b7f4e02f5 |
>| 0 | jwilkes - Toys R US | 1662469268312 | 217.146.128.193 | 1 | 217.146.128.193 | QSC-NOC,<br/>MW10972-RIPE,<br/>PLUSNET-LIR,<br/>ORG-PG203-RIPE,<br/>PLUS-DE,<br/>CV1903,<br/>QSC1-RIPE,<br/>RW4876-RIPE,<br/>BF359-RIPE,<br/>BZ1613-RIPE,<br/>GHM-RIPE | c3255500-d44e-352f-ba6a-b83f185ea892 |
>| 1 | jwilkes test - VanDelay Industries | 1662469268312 | 217.33.31.24 | 8 | 217.33.31.31 | AR13878-RIPE,<br/>BTNET-MNT,<br/>CD7018-RIPE | f373c1d1-bcbe-322e-8408-feb764ce055d |
>| 0 | jwilkes test - VanDelay Industries | 1662469268312 | 216.219.77.96 | 16 | 216.219.77.111 | ENTRI-ARIN,<br/>PSE26-ARIN,<br/>ENTRI-3 | 6a9aa802-a8c1-3d96-ac34-5370f51eaf33 |
>| 1 | jwilkes test - VanDelay Industries | 1662469268311 | 216.160.122.120 | 8 | 216.160.122.127 | FSA-11,<br/>IO-ORG-ARIN | d05881bc-7a98-3600-85df-cd0bf7fd897f |
>| 0 | jwilkes test - VanDelay Industries | 1662469268311 | 216.27.168.152 | 8 | 216.27.168.159 | C01379342 | 8649dfb1-8768-370b-9fd4-836024d89142 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268311 | 216.14.189.176 | 16 | 216.14.189.191 | RCU6-ARIN,<br/>GAM43-ARIN,<br/>RGS8-ARIN,<br/>PAI2-ARIN,<br/>POPPC-1 | 932019a5-0be3-3306-8cc6-6038b3cd233e |
>| 0 | jwilkes test - VanDelay Industries | 1662469268310 | 216.10.237.48 | 8 | 216.10.237.55 | C05805781 | 35502bfc-bf61-35b0-8d6c-6baa89d45c09 |
>| 1 | jwilkes test - VanDelay Industries | 1662469268310 | 213.221.18.142 | 1 | 213.221.18.142 | SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>SNK35-RIPE,<br/>SVNT1-RIPE,<br/>ORG-ES15-RIPE | b6a40889-27b2-3374-94c2-23a607d13f7b |
>| 1 | jwilkes test - VanDelay Industries | 1662469268310 | 213.221.7.132 | 1 | 213.221.7.132 | SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>ORG-ES15-RIPE | c136c373-8650-3418-a5e7-ea81507cbff2 |
>| 1 | jwilkes test - VanDelay Industries | 1662469268310 | 213.221.7.34 | 1 | 213.221.7.34 | SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>ORG-ES15-RIPE | 2160df6c-8009-3696-8794-185d312c960b |
>| 0 | jwilkes - Toys R US | 1662469268309 | 213.160.15.168 | 8 | 213.160.15.175 | QSC-NOC,<br/>MW10972-RIPE,<br/>PLUSNET-LIR,<br/>ORG-PG203-RIPE,<br/>PLUS-DE,<br/>CV1903,<br/>QSC1-RIPE,<br/>RW4876-RIPE,<br/>BF359-RIPE,<br/>BZ1613-RIPE,<br/>GHM-RIPE | 17da75f2-bb5a-3a56-8da0-e809182345e1 |
>| 0 | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | 1662469268309 | 213.62.189.64 | 64 | 213.62.189.127 | MAINT-AS2686,<br/>SB1432-RIPE,<br/>AR13530-RIPE,<br/>EU-IBM-NIC-MNT | 75bd74d9-6751-3c19-b400-789e8adc3303 |
>| 0 | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | 1662469268309 | 213.62.187.48 | 16 | 213.62.187.63 | MAINT-AS2686,<br/>PW373-RIPE,<br/>AR13530-RIPE,<br/>EU-IBM-NIC-MNT,<br/>MAINT-AS2686,<br/>AR13530-RIPE,<br/>EU-IBM-NIC-MNT,<br/>PT366-RIPE | a165bf59-73df-3557-b912-cc1bf38c8acc |
>| 0 | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | 1662469268308 | 213.62.185.192 | 64 | 213.62.185.255 | MAINT-AS2686,<br/>AR13530-RIPE,<br/>TS10976-RIPE,<br/>EU-IBM-NIC-MNT | aa7c7b2b-7539-307e-90de-40ef864abce2 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268308 | 213.33.183.115 | 1 | 213.33.183.115 | SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>AN30686-RIPE,<br/>SVNT1-RIPE,<br/>ORG-ES15-RIPE | a7e4e17d-ebb1-34a8-b6f7-da037f41bd09 |
>| 1 | jwilkes test - VanDelay Industries | 1662469268308 | 213.33.171.220 | 1 | 213.33.171.220 | SVNT2-RIPE,<br/>KI1346-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>ORG-ES15-RIPE | a343cda5-4dbc-3316-ac2e-bb222cc325ef |
>| 1 | jwilkes test - VanDelay Industries | 1662469268308 | 213.33.146.41 | 1 | 213.33.146.41 | SVNT2-RIPE,<br/>AVS408-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>ORG-ES15-RIPE | 4eb59610-aa21-3d16-b2fe-04f4116cd99d |
>| 0 | jwilkes - Toys R US | 1662469268307 | 212.202.236.96 | 4 | 212.202.236.99 | QSC-NOC,<br/>MW10972-RIPE,<br/>PLUSNET-LIR,<br/>ORG-PG203-RIPE,<br/>PLUS-DE,<br/>CV1903,<br/>QSC1-RIPE,<br/>RW4876-RIPE,<br/>BF359-RIPE,<br/>BZ1613-RIPE,<br/>GHM-RIPE | b31c527f-785b-37c9-b2ba-c1057554f5c2 |
>| 1 | jwilkes - Toys R US | 1662469268307 | 212.202.117.87 | 1 | 212.202.117.87 | QSC-NOC,<br/>MW10972-RIPE,<br/>PLUSNET-LIR,<br/>ORG-PG203-RIPE,<br/>PLUS-DE,<br/>CV1903,<br/>QSC1-RIPE,<br/>RW4876-RIPE,<br/>BF359-RIPE,<br/>BZ1613-RIPE,<br/>GHM-RIPE | a0d86fcf-16ab-3114-a3e2-f435b656c0c9 |
>| 6 | jwilkes test - VanDelay Industries | 1662469268307 | 212.187.197.248 | 8 | 212.187.197.255 | LEVEL3-MNT,<br/>PS20887-RIPE,<br/>AR13812-RIPE | 3d3d611b-b2da-3850-8d29-6f3b1552cc32 |
>| 1 | jwilkes test - VanDelay Industries | 1662469268307 | 212.119.250.34 | 1 | 212.119.250.34 | SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>AA26239-RIPE,<br/>SVNT1-RIPE,<br/>ORG-ES15-RIPE | 089048a9-da4d-32dd-871c-1f956388ba77 |
>| 1 | jwilkes test - VanDelay Industries | 1662469268306 | 212.119.241.164 | 1 | 212.119.241.164 | SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>ORG-ES15-RIPE | 9e9bf8b3-232e-383e-8efa-63b4ead51890 |
>| 1 | jwilkes test - VanDelay Industries | 1662469268306 | 212.119.193.34 | 1 | 212.119.193.34 | SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>NM7815-RIPE,<br/>SVNT1-RIPE,<br/>ORG-ES15-RIPE | 31daae58-94fa-3b95-aa1d-9b6c06fb8792 |
>| 0 | jwilkes - Toys R US | 1662469268306 | 212.60.209.246 | 1 | 212.60.209.246 | QSC-NOC,<br/>MW10972-RIPE,<br/>PLUSNET-LIR,<br/>ORG-PG203-RIPE,<br/>PLUS-DE,<br/>CV1903,<br/>QSC1-RIPE,<br/>RW4876-RIPE,<br/>BF359-RIPE,<br/>BZ1613-RIPE,<br/>GHM-RIPE | 17f816ef-b4c3-330c-ac83-31250b34504f |
>| 1 | jwilkes test - VanDelay Industries | 1662469268305 | 212.44.158.89 | 1 | 212.44.158.89 | SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SA38081-RIPE,<br/>ORG-ES15-RIPE | bf773fb8-2395-3835-9175-5d86c22a393c |
>| 1 | jwilkes test - VanDelay Industries | 1662469268305 | 212.44.139.46 | 1 | 212.44.139.46 | SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>ORG-ES15-RIPE | 9527e5ef-5fa5-393a-9451-747822cd1e50 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268305 | 209.219.204.104 | 16 | 209.219.204.119 | IED5-ARIN,<br/>TRU7,<br/>ZN90-ARIN,<br/>TRU9,<br/>IED6-ARIN,<br/>ZN90-ARIN | 589e7967-28e5-3d86-a29a-082295223730 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268305 | 209.206.211.24 | 8 | 209.206.211.31 | C01915073 | ce1d6f51-91fb-30d5-b724-eafd6f15cd0d |
>| 0 | jwilkes test - VanDelay Industries | 1662469268304 | 209.115.157.120 | 8 | 209.115.157.127 | C06962808 | 871d0d29-da75-38bf-9e09-2415fe1200d3 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268304 | 209.92.240.104 | 8 | 209.92.240.111 | GRADY2-ARIN,<br/>WINDS-ARIN,<br/>WINDS1-ARIN,<br/>WINDS-6 | 35fe2ae3-eca0-34b6-a208-e32c72fabe83 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268304 | 208.226.184.0 | 128 | 208.226.184.127 | C00550142 | 76544531-1d4f-330b-8942-94248a3b5dcf |
>| 0 | jwilkes test - VanDelay Industries | 1662469268304 | 208.131.237.16 | 16 | 208.131.237.31 | HALMA,<br/>SSE18-ARIN,<br/>SSE49-ARIN | 99e5c6cd-c903-363d-b4ad-3499b64a5c8f |
>| 0 | jwilkes test - VanDelay Industries | 1662469268303 | 208.125.32.56 | 8 | 208.125.32.63 | C08337002 | 178b15ce-ad99-3e2b-8b1a-a6aeff149a8d |
>| 0 | jwilkes test - VanDelay Industries | 1662469268303 | 208.124.239.100 | 4 | 208.124.239.103 | C05851024 | 54aa9441-5f86-3721-9b6f-29d6b935c96a |
>| 0 | jwilkes test - VanDelay Industries | 1662469268303 | 208.124.217.248 | 8 | 208.124.217.255 | C02258612 | 1f6bc450-b6e4-33f3-b09b-7de058997a7b |
>| 0 | jwilkes test - VanDelay Industries | 1662469268302 | 208.97.111.168 | 8 | 208.97.111.175 | C02260591 | c3f3270e-e4de-36b4-a501-4a595984017c |
>| 0 | jwilkes test - VanDelay Industries | 1662469268302 | 208.57.117.240 | 8 | 208.57.117.247 | MSDMCD,<br/>LSE19-ARIN | ec2a44fa-6f94-3765-9e54-a4606ea87547 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268302 | 208.46.77.88 | 8 | 208.46.77.95 | ANDER-66,<br/>VSE9-ARIN | 99b04966-7c3e-3df9-93d3-d41a2f627d61 |
>| 1 | jwilkes test - VanDelay Industries | 1662469268301 | 208.46.4.120 | 8 | 208.46.4.127 | BISSE12-ARIN,<br/>MCC-563 | 26206a59-21d8-386b-8811-7b0b6b520ebd |
>| 0 | jwilkes test - VanDelay Industries | 1662469268301 | 208.1.76.0 | 256 | 208.1.76.255 | SEARS-1,<br/>HHE34-ARIN | 1795fae5-ed7c-3237-a1b3-11ccddb29d23 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268301 | 207.234.31.224 | 16 | 207.234.31.239 | COGC,<br/>COGEN-ARIN,<br/>ZC108-ARIN,<br/>IPALL-ARIN | 82f29bae-f477-370e-9a8a-fb0954e6d121 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268300 | 207.229.236.64 | 16 | 207.229.236.79 | C00951251 | e9bc992b-845e-36be-86c6-b800f33159e0 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268300 | 207.119.236.96 | 8 | 207.119.236.103 | C02422271 | 7b968af1-d553-3990-ab8d-c4d888dfbad3 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268300 | 207.61.90.0 | 16 | 207.61.90.15 | SYSAD-ARIN,<br/>SOCEV-ARIN,<br/>ABUSE1127-ARIN,<br/>ABAI1-ARIN,<br/>ANR1-ARIN,<br/>DHANJ1-ARIN,<br/>LINX,<br/>IRRAD-ARIN | ccaeaac3-6e4c-39a8-ad2a-757471fa2b5a |
>| 0 | jwilkes test - VanDelay Industries | 1662469268300 | 206.155.110.128 | 8 | 206.155.110.135 | BUHLE-ARIN,<br/>SHMC-2 | 36a4ae83-bfc4-321f-9d5e-a4d9c2533575 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268299 | 206.95.36.0 | 256 | 206.95.36.255 | C00008950 | 9730f67a-5a30-3706-9202-175db0d7ba15 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268299 | 206.73.239.64 | 16 | 206.73.239.79 | C02230373 | ba34e536-2a7c-3eae-8fa2-020e50d096f7 |
>| 0 | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | 1662469268299 | 206.70.0.0 | 65536 | 206.70.255.255 | IPROU3-ARIN,<br/>AEA8-ARIN,<br/>ARMP-ARIN,<br/>ANO24-ARIN,<br/>AT-88-Z,<br/>AANO1-ARIN,<br/>IPMAN40-ARIN | 7843b0e2-b0ae-37aa-9a58-b047a5ff8a13 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268299 | 206.61.114.0 | 64 | 206.61.114.63 | SWAET-ARIN,<br/>SIE-ARIN,<br/>FIUMA2-ARIN,<br/>SPRINT-NOC-ARIN,<br/>CHUYI-ARIN,<br/>SPRN-Z,<br/>SWIS1-ARIN | 328d96ff-ca76-3199-8dfe-ff15eb260b37 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268298 | 206.31.31.24 | 8 | 206.31.31.31 | SHMC-1,<br/>MORAW2-ARIN | 5aeefdf0-25e3-31d6-b3e5-3ff93a1b583c |
>| 0 | jwilkes test - VanDelay Industries | 1662469268298 | 206.31.22.96 | 24 | 206.31.22.119 | JMO368-ARIN,<br/>JMO391-ARIN,<br/>SEARS-5,<br/>JMO368-ARIN,<br/>JMO391-ARIN,<br/>SEARS-5 | 229bdac6-1641-346a-be24-342589903bb5 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268298 | 206.31.22.72 | 8 | 206.31.22.79 | JMO368-ARIN,<br/>JMO391-ARIN,<br/>SEARS-5 | ca996353-06f9-330d-bb30-b4ce2ef32053 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268297 | 206.31.19.0 | 256 | 206.31.19.255 | JMO368-ARIN,<br/>SEARS-5 | f6dd9287-4494-383f-9b8d-7fed3a951377 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268297 | 206.25.242.104 | 8 | 206.25.242.111 | SHMC-5,<br/>BUHLE3-ARIN | 693a1d3c-d477-33c2-8054-5a9bc27a53ec |
>| 0 | jwilkes test - VanDelay Industries | 1662469268297 | 206.25.242.64 | 16 | 206.25.242.79 | SHMC-4,<br/>BUHLE2-ARIN | 4ba2a741-8533-3095-ba60-4dc257d3ba17 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268296 | 205.217.5.176 | 16 | 205.217.5.191 | ENTRI-ARIN,<br/>PSE26-ARIN,<br/>ENTRI-3 | e4005032-44b2-3b70-848a-db97087350ae |
>| 0 | jwilkes test - VanDelay Industries | 1662469268296 | 205.217.4.152 | 8 | 205.217.4.159 | ENTRI-ARIN,<br/>PSE26-ARIN,<br/>ENTRI-3 | 9d923c7a-f051-3b62-b653-81170ff17a88 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268296 | 204.238.251.0 | 256 | 204.238.251.255 | ISSM,<br/>JG525-ARIN | 0a237ed4-c5a2-317b-9812-243419b76d12 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268296 | 204.138.50.88 | 4 | 204.138.50.91 | C03394405 | 232ddbb1-3de1-31cd-aed4-32d9a53cc2bb |
>| 1 | jwilkes test - VanDelay Industries | 1662469268295 | 202.84.36.200 | 8 | 202.84.36.207 | MAINT-BD-BOL,<br/>BOC1-AP,<br/>BNA20-AP,<br/>AB1162-AP,<br/>IRT-BOL-BD | 55588822-40dc-3fa8-945d-ec7d4991047e |
>| 0 | jwilkes test - VanDelay Industries | 1662469268295 | 199.245.184.0 | 256 | 199.245.184.255 | PS82-ARIN,<br/>PAULSE | a705dbb6-1f66-34d0-90fa-9908bc689df4 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268295 | 199.181.104.0 | 256 | 199.181.104.255 | OPUSII,<br/>KS139-ARIN | b8d070ee-870d-319e-aaf9-ee4700e87e36 |
>| 1 | jwilkes test - VanDelay Industries | 1662469268294 | 199.101.129.222 | 1 | 199.101.129.222 | CARST4-ARIN,<br/>FROST151-ARIN,<br/>XN-46 | 2ed225e0-d10f-3276-ac5f-0246a4f9724a |
>| 9 | jwilkes test - VanDelay Industries | 1662469268294 | 199.48.79.128 | 64 | 199.48.79.191 | C02948824 | 44f4868f-d83c-344f-9755-2612d09637e5 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268294 | 198.187.177.0 | 256 | 198.187.177.255 | SSCRCS,<br/>RW20-ARIN | 1bbdda10-023a-35f0-b725-fe8724b5ab1d |
>| 39 | jwilkes test - VanDelay Industries | 1662469268293 | 198.179.146.0 | 1280 | 198.179.150.255 | TK551-ARIN,<br/>SDR,<br/>SDR-4,<br/>TK551-ARIN,<br/>TK551-ARIN,<br/>SDR,<br/>TK551-ARIN,<br/>SDR,<br/>TK551-ARIN,<br/>SDR | 6ad9f0b8-72a9-3435-8fad-8b1a70eaa17c |
>| 0 | jwilkes test - VanDelay Industries | 1662469268293 | 195.239.243.131 | 1 | 195.239.243.131 | SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>FNV16-RIPE,<br/>SVNT1-RIPE,<br/>ORG-ES15-RIPE | 13317e10-847b-3867-8685-e1aa98486e67 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268293 | 195.239.216.254 | 1 | 195.239.216.254 | SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>ORG-ES15-RIPE | f3604508-6dd1-3811-9b85-22a909466f25 |
>| 1 | jwilkes test - VanDelay Industries | 1662469268292 | 195.239.185.5 | 1 | 195.239.185.5 | SVNT2-RIPE,<br/>SSS154-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>ORG-ES15-RIPE | f424a12d-a5c6-3ab1-b179-b3d674898c96 |
>| 1 | jwilkes test - VanDelay Industries | 1662469268292 | 195.239.182.70 | 1 | 195.239.182.70 | SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>RV7226-RIPE,<br/>ORG-ES15-RIPE | cada51b8-d533-39db-bee7-3c36d75aa5f5 |
>| 1 | jwilkes test - VanDelay Industries | 1662469268292 | 195.239.149.214 | 1 | 195.239.149.214 | SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>ORG-ES15-RIPE | 6bc20932-49ec-3ec1-949d-d0bde2919c09 |
>| 1 | jwilkes test - VanDelay Industries | 1662469268292 | 195.239.144.186 | 1 | 195.239.144.186 | SVNT1-RIPE,<br/>AS3216-MNT,<br/>SOVINTEL-MNT,<br/>ORG-ES15-RIPE,<br/>SVNT2-RIPE,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE | 0a494860-7a95-37a9-a155-29b476c77d66 |
>| 1 | jwilkes test - VanDelay Industries | 1662469268291 | 195.239.71.52 | 1 | 195.239.71.52 | SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>ORG-ES15-RIPE | e8c77b84-4ba9-3e70-82f7-c0934df13c47 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268291 | 195.239.67.42 | 1 | 195.239.67.42 | SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>ORG-ES15-RIPE | dacf677c-f282-341d-b83a-945917c1cac8 |
>| 1 | jwilkes test - VanDelay Industries | 1662469268291 | 195.239.57.170 | 1 | 195.239.57.170 | SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>ORG-ES15-RIPE | 60801299-e0bc-3f66-8ee9-61806eedb05a |
>| 1 | jwilkes test - VanDelay Industries | 1662469268290 | 195.239.57.94 | 1 | 195.239.57.94 | SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>ORG-ES15-RIPE | ddb65106-ac78-32cc-a3a0-1742de79efa0 |
>| 1 | jwilkes test - VanDelay Industries | 1662469268290 | 195.239.55.134 | 1 | 195.239.55.134 | SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>ORG-ES15-RIPE | 968f2610-34b8-3f25-922a-1010a86dd335 |
>| 1 | jwilkes test - VanDelay Industries | 1662469268290 | 195.239.35.114 | 1 | 195.239.35.114 | SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>EB8881-RIPE,<br/>SVNT1-RIPE,<br/>ORG-ES15-RIPE | 2772142b-b0b1-3c1b-9d42-2508f3f05d03 |
>| 1 | jwilkes test - VanDelay Industries | 1662469268290 | 195.222.186.100 | 1 | 195.222.186.100 | SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>BN2575-RIPE,<br/>SVNT1-RIPE,<br/>ORG-ES15-RIPE | b5460599-43a8-3ba7-bda6-fb0ea38fe443 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268289 | 195.222.181.53 | 1 | 195.222.181.53 | SVNT2-RIPE,<br/>TN1700-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>ORG-ES15-RIPE | 0b8cb3aa-cd64-3591-b49c-8bcda0569a4e |
>| 0 | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | 1662469268289 | 195.212.0.0 | 16 | 195.212.0.15 | MAINT-AS2686,<br/>AR13530-RIPE,<br/>EU-IBM-NIC-MNT,<br/>MB2864-RIPE | 25b63226-9f5c-33eb-a6f8-70e6110b6538 |
>| 0 | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | 1662469268289 | 195.183.81.0 | 32 | 195.183.81.31 | MAINT-AS2686,<br/>AR13530-RIPE,<br/>EU-IBM-NIC-MNT,<br/>PD127-RIPE | 098a9e3e-4a9b-31f0-abdf-c61741a7d894 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268289 | 195.183.61.0 | 64 | 195.183.61.63 | MAINT-AS2686,<br/>AR13530-RIPE,<br/>EU-IBM-NIC-MNT,<br/>MA1079-RIPE | 9b26dd2c-bba5-3d6c-a3c0-188d8cd02599 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268288 | 195.157.206.104 | 8 | 195.157.206.111 | CH309-RIPE,<br/>AS8426-MNT,<br/>CH309-RIPE,<br/>ORG-CA48-RIPE | 735d84ba-2c06-3e98-87a6-46636ccee9b8 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268288 | 195.153.34.192 | 16 | 195.153.34.207 | KW322-RIPE,<br/>REACHUK-MNT,<br/>AR17873-RIPE,<br/>PSINET-UK-SYSADMIN | bfcd8547-aa3c-3788-a999-d57d4a91af12 |
>| 0 | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | 1662469268288 | 195.118.127.192 | 64 | 195.118.127.255 | MAINT-AS2686,<br/>AR13530-RIPE,<br/>DF498-RIPE,<br/>EU-IBM-NIC-MNT | 03fc6d7e-a8bc-3633-b517-f45e158cbf47 |
>| 1 | jwilkes test - VanDelay Industries | 1662469268287 | 195.68.188.220 | 1 | 195.68.188.220 | SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>ORG-ES15-RIPE | fe3ac6c1-5e6c-36aa-826b-4529cb8f4c4e |
>| 1 | jwilkes test - VanDelay Industries | 1662469268287 | 195.68.168.13 | 1 | 195.68.168.13 | SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>SSV242-RIPE,<br/>SVNT1-RIPE,<br/>ORG-ES15-RIPE | c055e8f6-83c0-3e17-8043-7c73a917ea53 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268287 | 195.68.166.251 | 1 | 195.68.166.251 | SVNT2-RIPE,<br/>VVZ30-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>ORG-ES15-RIPE | b12479a0-eb71-3ed9-8b7a-42ea9c19116c |
>| 1 | jwilkes test - VanDelay Industries | 1662469268287 | 195.68.165.75 | 1 | 195.68.165.75 | SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>SVNT2-RIPE,<br/>ORG-ES15-RIPE | 5f90df40-36ec-3434-b4e8-4e78254f20dd |
>| 1 | jwilkes test - VanDelay Industries | 1662469268286 | 195.68.153.227 | 1 | 195.68.153.227 | NAZ4-RIPE,<br/>SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>ORG-ES15-RIPE | 1df62e7d-a40b-3155-a83b-7b62b960c45c |
>| 0 | jwilkes test - VanDelay Industries | 1662469268286 | 195.68.153.34 | 1 | 195.68.153.34 | SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>BD9650-RIPE,<br/>SVNT1-RIPE,<br/>ORG-ES15-RIPE | f683c442-a1dd-3dbb-8fe7-36ccda1ae2b2 |
>| 0 | jwilkes test - VanDelay Industries | 1662469268286 | 195.68.147.38 | 1 | 195.68.147.38 | SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>GI3018-RIPE,<br/>ORG-ES15-RIPE | 80f4a852-e2b7-36b9-b28f-c1a29b36faf6 |
>| 1 | jwilkes test - VanDelay Industries | 1662469268285 | 195.68.145.155 | 1 | 195.68.145.155 | SVNT2-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>YM1941-RIPE,<br/>ORG-ES15-RIPE | 9337cc05-15c7-3926-ae91-dbb55980af15 |
>| 1 | jwilkes test - VanDelay Industries | 1662469268285 | 195.68.131.22 | 1 | 195.68.131.22 | SVNT2-RIPE,<br/>VS2745-RIPE,<br/>SOVINTEL-MNT,<br/>SVNT1-RIPE,<br/>ORG-ES15-RIPE | e47e147f-4436-3b5e-b3e3-29f6613f3312 |
>| 0 | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | 1662469268285 | 195.59.205.0 | 16 | 195.59.205.15 | AR40377-RIPE,<br/>CW-DNS-MNT,<br/>GSOC-RIPE,<br/>CW-EUROPE-GSOC | 69c26f54-7f07-331f-b700-5882ab12a5d6 |
>| 0 | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | 1662469268285 | 195.59.203.176 | 16 | 195.59.203.191 | AR40377-RIPE,<br/>CW-DNS-MNT,<br/>GSOC-RIPE,<br/>CW-EUROPE-GSOC | 9da67af4-3a1b-3e01-b43f-8a19a9a150bb |
>| 0 | jwilkes test - VanDelay Industries | 1662469268284 | 195.53.117.184 | 8 | 195.53.117.191 | MAINT-AS3352,<br/>NSYS2-RIPE,<br/>JS27349-RIPE | 3375227a-ba1c-3e32-ae39-756d303f3da3 |


### asm-getexternalipaddressrange
***
Get external IP address range details according to the range IDs.


#### Base Command

`asm-getexternalipaddressrange`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range_id | An string representing the range ID for which you want to get the details for. | Required | 


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
```!asm-getexternalipaddressrange range_id=1093124c-ce26-33ba-8fb8-937fecb4c7b6```
#### Context Example
```json
{
    "ASM": {
        "GetExternalIpAddressRange": {
            "active_responsive_ips_count": 1,
            "business_units": [
                "jwilkes - Toys R US"
            ],
            "date_added": 1662469268216,
            "details": {
                "networkRecords": [
                    {
                        "firstIp": "52.22.120.51",
                        "handle": "NET-52-0-0-0-1",
                        "lastChanged": 1662468406992,
                        "lastIp": "52.22.120.51",
                        "name": "AT-88-Z",
                        "organizationRecords": [
                            {
                                "address": "1918 8th Ave\nSeattle WA United States 98109",
                                "dateAdded": 1662467746852,
                                "email": "aws-routing-poc@amazon.com",
                                "firstRegistered": 1563988631863,
                                "formattedName": "Amazon, IP Routing",
                                "handle": "IPROU3-ARIN",
                                "kind": "group",
                                "lastChanged": 1659365491964,
                                "org": "",
                                "phone": "+1-206-266-4064",
                                "remarks": "",
                                "roles": [
                                    "registrant"
                                ]
                            },
                            {
                                "address": "Amazon Web Services Elastic Compute Cloud, EC2\n410 Terry Avenue North\nSeattle WA United States 98109-5210",
                                "dateAdded": 1662467746852,
                                "email": "abuse@amazonaws.com",
                                "firstRegistered": 1206382327000,
                                "formattedName": "Amazon Web Services, LLC, Amazon EC2 Abuse",
                                "handle": "AEA8-ARIN",
                                "kind": "group",
                                "lastChanged": 1661209731401,
                                "org": "",
                                "phone": "+1-206-555-0000",
                                "remarks": "",
                                "roles": [
                                    "abuse"
                                ]
                            },
                            {
                                "address": "13200 Woodland Park Dr\nHerndon\nHerndon VA United States 20171",
                                "dateAdded": 1662467746852,
                                "email": "aws-rpki-routing-poc@amazon.com",
                                "firstRegistered": 1626964962323,
                                "formattedName": "Amazon Web Services, AWS RPKI Management POC",
                                "handle": "ARMP-ARIN",
                                "kind": "group",
                                "lastChanged": 1659365476760,
                                "org": "",
                                "phone": "+1-206-266-4064",
                                "remarks": "",
                                "roles": [
                                    "registrant"
                                ]
                            },
                            {
                                "address": "PO BOX 81226\nSeattle WA United States 98108-1226",
                                "dateAdded": 1662467746852,
                                "email": "amzn-noc-contact@amazon.com",
                                "firstRegistered": 1127124005000,
                                "formattedName": "Amazon Webservices EC2, Amazon EC2 Network Operations",
                                "handle": "ANO24-ARIN",
                                "kind": "group",
                                "lastChanged": 1661361455164,
                                "org": "",
                                "phone": "+1-206-555-0000",
                                "remarks": "",
                                "roles": [
                                    "technical"
                                ]
                            },
                            {
                                "address": "410 Terry Ave N.\nSeattle WA United States 98109",
                                "dateAdded": 1662467746852,
                                "email": "abuse@amazonaws.com",
                                "firstRegistered": 1323369265000,
                                "formattedName": "",
                                "handle": "AT-88-Z",
                                "kind": "org",
                                "lastChanged": 1627503887997,
                                "org": "Amazon Technologies Inc.",
                                "phone": "",
                                "remarks": "All abuse reports MUST include:, * src IP, * dest IP (your IP), * dest port, * Accurate date/timestamp and timezone of activity, * Intensity/frequency (short log extracts), * Your contact details (phone and email) Without these we will be unable to identify the correct owner of the IP address at that point in time.",
                                "roles": [
                                    "registrant"
                                ]
                            },
                            {
                                "address": "410 Terry Ave N\nSeattle WA United States 98109",
                                "dateAdded": 1662467746852,
                                "email": "amzn-noc-contact@amazon.com",
                                "firstRegistered": 1267745910000,
                                "formattedName": "Amazon Web Services, LLC, Amazon AWS Network Operations",
                                "handle": "AANO1-ARIN",
                                "kind": "group",
                                "lastChanged": 1661361469530,
                                "org": "",
                                "phone": "+1-206-555-0000",
                                "remarks": "",
                                "roles": [
                                    "registrant"
                                ]
                            },
                            {
                                "address": "1918 8th Ave\nSeattle WA United States 98109",
                                "dateAdded": 1662467746852,
                                "email": "ip-resource-management@amazon.com, ipmanagement@amazon.com",
                                "firstRegistered": 1384311966000,
                                "formattedName": "Amazon, IP Management",
                                "handle": "IPMAN40-ARIN",
                                "kind": "group",
                                "lastChanged": 1662058460408,
                                "org": "",
                                "phone": "+1-206-555-0000",
                                "remarks": "",
                                "roles": [
                                    "admin"
                                ]
                            }
                        ],
                        "remarks": "",
                        "whoIsServer": "ARIN"
                    }
                ]
            },
            "first_ip": "52.22.120.51",
            "ips_count": 1,
            "last_ip": "52.22.120.51",
            "organization_handles": [
                "IPROU3-ARIN",
                "AEA8-ARIN",
                "ARMP-ARIN",
                "ANO24-ARIN",
                "AT-88-Z",
                "AANO1-ARIN",
                "IPMAN40-ARIN"
            ],
            "range_id": "1093124c-ce26-33ba-8fb8-937fecb4c7b6"
        }
    }
}
```

#### Human Readable Output

>### External IP Address Range
>|active_responsive_ips_count|business_units|date_added|details|first_ip|ips_count|last_ip|organization_handles|range_id|
>|---|---|---|---|---|---|---|---|---|
>| 1 | jwilkes - Toys R US | 1662469268216 | networkRecords: {'handle': 'NET-52-0-0-0-1', 'firstIp': '52.22.120.51', 'lastIp': '52.22.120.51', 'name': 'AT-88-Z', 'whoIsServer': 'ARIN', 'lastChanged': 1662468406992, 'organizationRecords': [{'handle': 'IPROU3-ARIN', 'dateAdded': 1662467746852, 'address': '1918 8th Ave\nSeattle WA United States 98109', 'email': 'aws-routing-poc@amazon.com', 'phone': '+1-206-266-4064', 'org': '', 'formattedName': 'Amazon, IP Routing', 'kind': 'group', 'roles': ['registrant'], 'lastChanged': 1659365491964, 'firstRegistered': 1563988631863, 'remarks': ''}, {'handle': 'AEA8-ARIN', 'dateAdded': 1662467746852, 'address': 'Amazon Web Services Elastic Compute Cloud, EC2\n410 Terry Avenue North\nSeattle WA United States 98109-5210', 'email': 'abuse@amazonaws.com', 'phone': '+1-206-555-0000', 'org': '', 'formattedName': 'Amazon Web Services, LLC, Amazon EC2 Abuse', 'kind': 'group', 'roles': ['abuse'], 'lastChanged': 1661209731401, 'firstRegistered': 1206382327000, 'remarks': ''}, {'handle': 'ARMP-ARIN', 'dateAdded': 1662467746852, 'address': '13200 Woodland Park Dr\nHerndon\nHerndon VA United States 20171', 'email': 'aws-rpki-routing-poc@amazon.com', 'phone': '+1-206-266-4064', 'org': '', 'formattedName': 'Amazon Web Services, AWS RPKI Management POC', 'kind': 'group', 'roles': ['registrant'], 'lastChanged': 1659365476760, 'firstRegistered': 1626964962323, 'remarks': ''}, {'handle': 'ANO24-ARIN', 'dateAdded': 1662467746852, 'address': 'PO BOX 81226\nSeattle WA United States 98108-1226', 'email': 'amzn-noc-contact@amazon.com', 'phone': '+1-206-555-0000', 'org': '', 'formattedName': 'Amazon Webservices EC2, Amazon EC2 Network Operations', 'kind': 'group', 'roles': ['technical'], 'lastChanged': 1661361455164, 'firstRegistered': 1127124005000, 'remarks': ''}, {'handle': 'AT-88-Z', 'dateAdded': 1662467746852, 'address': '410 Terry Ave N.\nSeattle WA United States 98109', 'email': 'abuse@amazonaws.com', 'phone': '', 'org': 'Amazon Technologies Inc.', 'formattedName': '', 'kind': 'org', 'roles': ['registrant'], 'lastChanged': 1627503887997, 'firstRegistered': 1323369265000, 'remarks': 'All abuse reports MUST include:, * src IP, * dest IP (your IP), * dest port, * Accurate date/timestamp and timezone of activity, * Intensity/frequency (short log extracts), * Your contact details (phone and email) Without these we will be unable to identify the correct owner of the IP address at that point in time.'}, {'handle': 'AANO1-ARIN', 'dateAdded': 1662467746852, 'address': '410 Terry Ave N\nSeattle WA United States 98109', 'email': 'amzn-noc-contact@amazon.com', 'phone': '+1-206-555-0000', 'org': '', 'formattedName': 'Amazon Web Services, LLC, Amazon AWS Network Operations', 'kind': 'group', 'roles': ['registrant'], 'lastChanged': 1661361469530, 'firstRegistered': 1267745910000, 'remarks': ''}, {'handle': 'IPMAN40-ARIN', 'dateAdded': 1662467746852, 'address': '1918 8th Ave\nSeattle WA United States 98109', 'email': 'ip-resource-management@amazon.com, ipmanagement@amazon.com', 'phone': '+1-206-555-0000', 'org': '', 'formattedName': 'Amazon, IP Management', 'kind': 'group', 'roles': ['admin'], 'lastChanged': 1662058460408, 'firstRegistered': 1384311966000, 'remarks': ''}], 'remarks': ''} | 52.22.120.51 | 1 | 52.22.120.51 | IPROU3-ARIN,<br/>AEA8-ARIN,<br/>ARMP-ARIN,<br/>ANO24-ARIN,<br/>AT-88-Z,<br/>AANO1-ARIN,<br/>IPMAN40-ARIN | 1093124c-ce26-33ba-8fb8-937fecb4c7b6 |


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
```!asm-getassetsinternetexposure name="toysrus.com" type=certificate has_active_external_services=no```
#### Context Example
```json
{
    "ASM": {
        "GetAssetsInternetExposure": [
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
                    "f251f232-d1de-35ae-b7de-a8adba483904"
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
                "certificate_issuer": "Amazon",
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
                "name": "*.truimg.toysrus.com",
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
                    "4979aced-94bf-3828-a151-be16229bad61"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "Webmaileu.toysrus.com",
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
                    "847b9da9-ca93-3a7d-9502-08aff4290230"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "affiliates.toysrus.com",
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
                    "329d9ad0-5670-39f2-9e74-a5ee515423e3"
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
                "name": "affiliates.toysrus.com",
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
                    "43f25c0b-7742-3e00-9d9b-44cbbfe8b536"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "LongExpiration",
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
                "name": "apitest.toysrus.com",
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
                    "2e09cd69-80bd-3d6b-8902-64265140dfb9"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "apps.toysrus.com",
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
                    "606ea69f-c6b2-3920-bef4-7f9407edb87e"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA1withRSA",
                "certificate_classifications": [
                    "Expired",
                    "InsecureSignature"
                ],
                "certificate_issuer": "VeriSign",
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
                "name": "apps.toysrus.com",
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
                    "fa5a8f6e-7668-34b2-8e6b-e2788a07dfba"
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
                "name": "apps.toysrus.com",
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
                    "c2d0d314-8903-3493-82cb-adc026643271"
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
                "name": "aws-gw.globalapi.toysrus.com",
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
                    "f99a6083-b875-3bc6-bdc9-fffe3c34438a"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA1withRSA",
                "certificate_classifications": [
                    "Expired",
                    "DomainControlValidated",
                    "InsecureSignature"
                ],
                "certificate_issuer": "GoDaddy",
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
                "name": "c.toysrus.com",
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
                    "f77decaf-dbe0-3b81-89c5-600b478d0cd6"
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
                "name": "care-staging.rewardsrus.toysrus.com",
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
                    "e6258c1b-0e1f-3fff-aa50-58529c4269e7"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "care-staging.rewardsrus.toysrus.com",
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
                    "535063d4-ce56-3b73-9e6e-52252c5a2278"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "care.rewardsrus.toysrus.com",
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
                    "91e40218-8493-3b0b-8602-83ce567b0e29"
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
                "name": "care.rewardsrus.toysrus.com",
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
                    "7a739090-779c-3d09-adaa-e1bc7592d90c"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Expired"
                ],
                "certificate_issuer": "Amazon",
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
                "name": "careers.toysrus.com",
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
                    "786bc35f-4588-37be-9d60-562993fcdca7"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Expired"
                ],
                "certificate_issuer": "Amazon",
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
                "name": "careers.toysrus.com",
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
                    "e2fa082c-0fdc-308e-884e-8b851beb7fff"
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
                "name": "dev.ecomm.globalapi.toysrus.com",
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
                    "27da6b91-237a-3eab-85cd-81e3dc8ccc38"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "dev.toysrus.com",
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
                    "628d5481-dc1b-3651-a3ea-8f884bcd0ebe"
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
                "name": "ecomm.globalapi.toysrus.com",
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
                    "4c8a874b-cc36-30cc-960b-740ccf0cea95"
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
                "name": "edq.toysrus.com",
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
                    "9aea8cf0-9a23-3751-96e0-ffac82088431"
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
                "name": "edqdev.toysrus.com",
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
                    "66d2597b-e135-3fc0-8cbb-7d1e2beefdef"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA1withRSA",
                "certificate_classifications": [
                    "Expired",
                    "InsecureSignature"
                ],
                "certificate_issuer": "VeriSign",
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
                "name": "email.toysrus.com",
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
                    "b14c1e21-ce83-38e7-9420-16605222a15a"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "email.toysrus.com",
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
                    "e1c11b5b-4b3e-364f-9931-7615714f06ac"
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
                "name": "email.toysrus.com",
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
                    "d1413148-cc84-3088-b5f5-f0e460713c8e"
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
                "name": "eventfeedback.toysrus.com",
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
                    "445ce3bf-08d0-30eb-bf71-e3f6884bd6c8"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Expired"
                ],
                "certificate_issuer": "Let's Encrypt",
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
                "name": "jenkins.globalapi.toysrus.com",
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
                    "7b81cd90-c64c-30d4-b4fd-9cae14dc63da"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Expired",
                    "DomainControlValidated"
                ],
                "certificate_issuer": "Starfield Technologies",
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
                "name": "join.toysrus.com",
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
                    "f6103562-8838-30c2-9724-9d4cd1a9ff61"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Expired",
                    "DomainControlValidated"
                ],
                "certificate_issuer": "Starfield Technologies",
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
                "name": "join.toysrus.com",
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
                    "c786661d-fff7-3e16-972b-8e7fba2d6a4e"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Expired",
                    "DomainControlValidated"
                ],
                "certificate_issuer": "Starfield Technologies",
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
                "name": "join.toysrus.com",
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
                    "5896d6d2-dec5-389c-b2ea-47dd78a5d215"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Expired"
                ],
                "certificate_issuer": "GeoTrust",
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
                "name": "kiosk.toysrus.com.au",
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
                    "d1caf737-e3fa-3eff-a6b3-1263b344220e"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Expired"
                ],
                "certificate_issuer": "GeoTrust",
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
                "name": "kiosk.toysrus.com.au",
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
                    "6fe11b60-3d7b-3dc9-b135-65a61bcfe7be"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA1withRSA",
                "certificate_classifications": [
                    "ShortKey",
                    "Expired",
                    "InsecureSignature"
                ],
                "certificate_issuer": "Unknown",
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
                "name": "llookups-test.toysrus.com",
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
                    "044e7009-9c78-31e6-a694-4fc98a0cbc19"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "loyaltylookups-staging.toysrus.com",
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
                    "4ea85f00-95dc-3f8a-a211-63cccf5b2dc9"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "loyaltylookups-staging.toysrus.com",
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
                    "7ed1627e-5c71-3470-bb78-8e4fd55875de"
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
                "name": "loyaltylookups-staging.toysrus.com",
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
                    "d299714c-4d7c-3a1f-8a48-1a93837e13f3"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA1withRSA",
                "certificate_classifications": [
                    "Expired",
                    "InsecureSignature"
                ],
                "certificate_issuer": "VeriSign",
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
                "name": "loyaltylookups.toysrus.com",
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
                    "663d3d93-6795-3e2b-9db6-c874b2b7531b"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "loyaltylookups.toysrus.com",
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
                    "499e4ad4-388d-3c40-a046-bce561a6d5b6"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA1withRSA",
                "certificate_classifications": [
                    "Expired",
                    "InsecureSignature"
                ],
                "certificate_issuer": "VeriSign",
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
                "name": "loyaltylookups.toysrus.com",
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
                    "3b2f3ca5-0d2c-35d0-a4fd-1e3ccb4a7006"
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
                "name": "loyaltylookups.toysrus.com",
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
                    "4afb14e5-8bd7-3d47-84be-c9eccaec0545"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "m.toysrus.com",
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
                    "e1acf452-ef9a-35f0-9cc8-507d2f578df0"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "m.toysrus.com",
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
                    "e6475bd0-3a10-32f9-8ca9-cae68452782a"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "m.toysrus.com",
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
                    "960a7f0c-0f6f-34f4-aa8a-04f5b59ef5df"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA1withRSA",
                "certificate_classifications": [
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
                "name": "m.toysrus.com",
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
                    "df44d13d-7dae-31f0-bf8c-b2a7568b2a76"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA1withRSA",
                "certificate_classifications": [
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
                "name": "m.toysrus.com",
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
                    "66594f5d-abdf-3f42-8b04-4ba7babd6800"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "m.toysrus.com",
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
                    "66857a4a-383e-329d-9bd0-92717e539b61"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "m.toysrus.com.au",
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
                    "ddb22485-a053-31e5-95cd-13b37eace21d"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Expired"
                ],
                "certificate_issuer": "GeoTrust",
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
                "name": "m.toysrus.com.au",
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
                    "ab212979-3c68-35a2-a6aa-7547ab6d5c59"
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
                "name": "mobile-app-pnj-pre.toysrus.com",
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
                    "12e9135c-ca97-37e8-ad25-ab6aa0231b84"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "mobile-app.toysrus.com",
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
                    "baa0a0c9-b893-3ddc-a041-57e9395fe32b"
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
                "name": "mobile-app.toysrus.com",
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
                    "44901eb2-c507-3837-a4a2-9380b3e0d5f4"
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
                "name": "mstage.toysrus.com",
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
                    "ef57aade-7e6f-36dd-b1af-444cab08743a"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "SelfSigned",
                    "LongExpiration"
                ],
                "certificate_issuer": "Unknown",
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
                "name": "mvi.toysrus.com",
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
                    "ecee86d9-1f38-3467-9223-88e7e571a547"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA1withRSA",
                "certificate_classifications": [
                    "Expired",
                    "InsecureSignature"
                ],
                "certificate_issuer": "VeriSign",
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
                "name": "ocs.toysrus.com",
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
                    "bf53eec6-8541-3de8-a7d8-d573a42b62f1"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "partners.toysrus.com",
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
                    "bafb6c95-62ac-3480-adad-40da78881e00"
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
                "name": "partners.toysrus.com",
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
                    "80276242-80ff-3c83-9727-e7abfe77cc9d"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA1withRSA",
                "certificate_classifications": [
                    "Expired",
                    "InsecureSignature"
                ],
                "certificate_issuer": "VeriSign",
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
                "name": "partners.toysrus.com",
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
                    "35cf214e-f216-35e1-a43b-fd03ae77e959"
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
                "name": "partnersdev.toysrus.com",
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
                    "5e1552fc-0f8a-3e9e-81da-2e3942dff14f"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "partnersdev.toysrus.com",
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
                    "a2f5abb9-90b6-349a-b676-7207b91243ad"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "partnerstest.toysrus.com",
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
                    "4c3602ed-719a-3023-a211-a2d55d4c8915"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "partnerwebservices-staging.rewardsrus.toysrus.com",
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
                    "ba5a44e2-ffa2-3752-b115-a43bf4bbd640"
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
                "name": "partnerwebservices-staging.rewardsrus.toysrus.com",
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
                    "7e26e433-eb87-36eb-b9ac-22246b8a2e89"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "partnerwebservices.rewardsrus.toysrus.com",
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
                    "c6fda74b-6bf5-3cda-9bad-ffdfdcd52cc0"
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
                "name": "partnerwebservices.rewardsrus.toysrus.com",
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
                    "c8d839e2-6719-3c42-bfe2-b722d3f3806b"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Expired"
                ],
                "certificate_issuer": "Let's Encrypt",
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
                "name": "rdcservicedesk.toysrus.com",
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
                    "eb0ff340-f231-3e5c-a798-b44558cb9de8"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA1withRSA",
                "certificate_classifications": [
                    "Expired",
                    "SelfSigned",
                    "ShortKey",
                    "LongExpiration",
                    "InsecureSignature"
                ],
                "certificate_issuer": "ToysRUs",
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
                "name": "rewardsrus-staging.toysrus.com",
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
                    "d7767bc5-d9db-3e9f-93b7-1989ba2284de"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "rewardsrus-staging.toysrus.com",
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
                    "357b2c06-7603-3996-ba4b-29e2916061c8"
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
                "name": "rewardsrus-staging.toysrus.com",
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
                    "392e6ced-f4ee-3f15-a10e-035639c2701e"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "rewardsrus.toysrus.com",
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
                    "3636d8b3-d81d-3700-a3e3-74541868e71c"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA1withRSA",
                "certificate_classifications": [
                    "Expired",
                    "InsecureSignature"
                ],
                "certificate_issuer": "VeriSign",
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
                "name": "rewardsrus.toysrus.com",
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
                    "5e41fb84-0934-3e60-a8fc-e3372097f08c"
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
                "name": "rewardsrus.toysrus.com",
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
                    "d1300db2-d710-305c-89ac-2260e461af61"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Expired"
                ],
                "certificate_issuer": "Let's Encrypt",
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
                "name": "rintlservicedesk.toysrus.com",
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
                    "855b2ec3-53c8-364f-a826-274d2d6a8b68"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Expired"
                ],
                "certificate_issuer": "Let's Encrypt",
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
                "name": "rservicedesk.toysrus.com",
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
                    "8d4f0c24-b898-3eaa-9363-046d5cf68400"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "rservicedesk.toysrus.com",
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
                    "30d3834d-9e8b-31fc-93d9-8ca619a47a27"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA1withRSA",
                "certificate_classifications": [
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
                "name": "rspeedycheckout.toysrus.com",
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
                    "3e3ff2fa-57ed-3723-a9a8-24807dc53c11"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA1withRSA",
                "certificate_classifications": [
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
                "name": "rspeedycheckoutqa.toysrus.com",
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
                    "6964b1d2-b366-3904-8234-7f8b486e0272"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Expired"
                ],
                "certificate_issuer": "Let's Encrypt",
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
                "name": "rstoreservicedesk.toysrus.com",
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
                    "a8a87230-c6d1-3cb0-8257-4523278ba3f2"
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
                "name": "rusmob.toysrus.com",
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
                    "cd288140-105a-35c4-a77f-f41e4618ac77"
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
                "name": "rusmobd.toysrus.com",
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
                    "f016395a-f9de-3506-9919-8ba5d4df1395"
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
                "name": "rusmobp.toysrus.com",
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
                    "98556cc7-b1a7-3468-ad0a-f76d3a0b603e"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "SelfSigned",
                    "LongExpiration"
                ],
                "certificate_issuer": "Unknown",
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
                "name": "servidor.toysrus.com",
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
                    "c2adaf7f-974d-326e-aabd-60b60b7a7d56"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "smetrics.toysrus.com",
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
                    "046adde2-50ab-3011-b099-cf01957677a0"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA1withRSA",
                "certificate_classifications": [
                    "Expired",
                    "LongExpiration",
                    "DomainControlValidated",
                    "InsecureSignature"
                ],
                "certificate_issuer": "GeoTrust",
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
                "name": "smetrics.toysrus.com",
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
                    "8376b6d5-53cf-382e-826b-8df74726f439"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "smetrics.toysrus.com",
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
                    "b0d8aa8a-a72d-3722-b1b6-2f954c334d27"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "Healthy"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "first_observed": 1660069806000,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": 1661192205000,
                "mac_addresses": [],
                "management_status": [],
                "name": "smetrics.toysrus.com",
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
                    "75145423-529a-3f4a-bfd7-2f41c1b43929"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "smetrics.toysrus.com",
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
                    "e0bc7a2a-11b7-3502-bf3e-12feacc6ada2"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "smetrics.toysrus.com",
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
                    "a2bd231a-9bd3-3524-bbaa-b78f9be8e64e"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "smetrics.toysrus.com",
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
                    "0035678e-4c5f-358a-a355-7a8b10a84b7b"
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
                "name": "stores.toysrus.com",
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
                    "cf7bdcce-9cb9-379d-a0d5-7c7f7c935d30"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA1withRSA",
                "certificate_classifications": [
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
                "name": "t.toysrus.com",
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
                    "81d85787-c125-3d19-a06c-8256d8c64a2c"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "t.toysrus.com",
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
                    "949b98e6-f459-3258-803a-a96c81a7818d"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "t.toysrus.com",
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
                    "dff7b78d-2502-3f45-b86f-26d8ada75e6d"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "t.toysrus.com",
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
                    "dc659c89-5770-389a-8752-ff229aaa309e"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "jwilkes - Toys R US",
                    "jwilkes test - VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
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
                "name": "t.toysrus.com",
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
>|asm_ids|asset_type|business_units|certificate_algorithm|certificate_classifications|certificate_issuer|domain_resolves|externally_detected_providers|first_observed|has_active_externally_services|has_xdr_agent|last_observed|name|sensor|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| cfa1cd5a-77f1-3963-8557-7f652309a143 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Wildcard,<br/>Expired | DigiCert | false |  |  | false | NA |  | *.digital-dev.toysrus.com | XPANSE |
>| 78a11e94-58a9-329c-99ca-e527d2db6cfb | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Wildcard,<br/>Expired | DigiCert | false |  |  | false | NA |  | *.digital-prod.toysrus.com | XPANSE |
>| 0098ab7a-7f20-3729-9d0c-f7014bdacd14 | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | LongExpiration,<br/>Wildcard,<br/>Expired | SymAntec Corporation | false |  |  | false | NA |  | *.toysrus.com | XPANSE |
>| 46d2ee77-f951-3dc8-80ac-79efb33bf34d | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Wildcard,<br/>Expired | Symantec | false |  |  | false | NA |  | *.toysrus.com | XPANSE |
>| 1fba11d5-3ab2-34de-bd2e-69c407e99915 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | DigiCert | false |  |  | false | NA |  | *.toysrus.com | XPANSE |
>| c66a99bd-352d-3526-9176-0d46d4abab49 | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | LongExpiration,<br/>Wildcard,<br/>Expired | Symantec | false |  |  | false | NA |  | *.toysrus.com | XPANSE |
>| ded44dc1-18f2-3ac5-a66f-5e51559cfcfc | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | LongExpiration,<br/>Wildcard,<br/>Expired | Symantec | false |  |  | false | NA |  | *.toysrus.com | XPANSE |
>| f251f232-d1de-35ae-b7de-a8adba483904 | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Wildcard,<br/>Expired | Amazon | false |  |  | false | NA |  | *.truimg.toysrus.com | XPANSE |
>| 4979aced-94bf-3828-a151-be16229bad61 | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | Symantec | false |  |  | false | NA |  | Webmaileu.toysrus.com | XPANSE |
>| 847b9da9-ca93-3a7d-9502-08aff4290230 | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | Symantec | false |  |  | false | NA |  | affiliates.toysrus.com | XPANSE |
>| 329d9ad0-5670-39f2-9e74-a5ee515423e3 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | affiliates.toysrus.com | XPANSE |
>| 43f25c0b-7742-3e00-9d9b-44cbbfe8b536 | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | apitest.toysrus.com | XPANSE |
>| 2e09cd69-80bd-3d6b-8902-64265140dfb9 | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | Symantec | false |  |  | false | NA |  | apps.toysrus.com | XPANSE |
>| 606ea69f-c6b2-3920-bef4-7f9407edb87e | CERTIFICATE | jwilkes - Toys R US | SHA1withRSA | Expired,<br/>InsecureSignature | VeriSign | false |  |  | false | NA |  | apps.toysrus.com | XPANSE |
>| fa5a8f6e-7668-34b2-8e6b-e2788a07dfba | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | apps.toysrus.com | XPANSE |
>| c2d0d314-8903-3493-82cb-adc026643271 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | aws-gw.globalapi.toysrus.com | XPANSE |
>| f99a6083-b875-3bc6-bdc9-fffe3c34438a | CERTIFICATE | jwilkes - Toys R US | SHA1withRSA | Expired,<br/>DomainControlValidated,<br/>InsecureSignature | GoDaddy | false |  |  | false | NA |  | c.toysrus.com | XPANSE |
>| f77decaf-dbe0-3b81-89c5-600b478d0cd6 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | care-staging.rewardsrus.toysrus.com | XPANSE |
>| e6258c1b-0e1f-3fff-aa50-58529c4269e7 | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | Symantec | false |  |  | false | NA |  | care-staging.rewardsrus.toysrus.com | XPANSE |
>| 535063d4-ce56-3b73-9e6e-52252c5a2278 | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | Symantec | false |  |  | false | NA |  | care.rewardsrus.toysrus.com | XPANSE |
>| 91e40218-8493-3b0b-8602-83ce567b0e29 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | care.rewardsrus.toysrus.com | XPANSE |
>| 7a739090-779c-3d09-adaa-e1bc7592d90c | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | Amazon | false |  |  | false | NA |  | careers.toysrus.com | XPANSE |
>| 786bc35f-4588-37be-9d60-562993fcdca7 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | Expired | Amazon | false |  |  | false | NA |  | careers.toysrus.com | XPANSE |
>| e2fa082c-0fdc-308e-884e-8b851beb7fff | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | dev.ecomm.globalapi.toysrus.com | XPANSE |
>| 27da6b91-237a-3eab-85cd-81e3dc8ccc38 | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | DigiCert | false |  |  | false | NA |  | dev.toysrus.com | XPANSE |
>| 628d5481-dc1b-3651-a3ea-8f884bcd0ebe | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | ecomm.globalapi.toysrus.com | XPANSE |
>| 4c8a874b-cc36-30cc-960b-740ccf0cea95 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | edq.toysrus.com | XPANSE |
>| 9aea8cf0-9a23-3751-96e0-ffac82088431 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | edqdev.toysrus.com | XPANSE |
>| 66d2597b-e135-3fc0-8cbb-7d1e2beefdef | CERTIFICATE | jwilkes - Toys R US | SHA1withRSA | Expired,<br/>InsecureSignature | VeriSign | false |  |  | false | NA |  | email.toysrus.com | XPANSE |
>| b14c1e21-ce83-38e7-9420-16605222a15a | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | Symantec | false |  |  | false | NA |  | email.toysrus.com | XPANSE |
>| e1c11b5b-4b3e-364f-9931-7615714f06ac | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | email.toysrus.com | XPANSE |
>| d1413148-cc84-3088-b5f5-f0e460713c8e | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | eventfeedback.toysrus.com | XPANSE |
>| 445ce3bf-08d0-30eb-bf71-e3f6884bd6c8 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | Expired | Let's Encrypt | false |  |  | false | NA |  | jenkins.globalapi.toysrus.com | XPANSE |
>| 7b81cd90-c64c-30d4-b4fd-9cae14dc63da | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired,<br/>DomainControlValidated | Starfield Technologies | false |  |  | false | NA |  | join.toysrus.com | XPANSE |
>| f6103562-8838-30c2-9724-9d4cd1a9ff61 | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired,<br/>DomainControlValidated | Starfield Technologies | false |  |  | false | NA |  | join.toysrus.com | XPANSE |
>| c786661d-fff7-3e16-972b-8e7fba2d6a4e | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired,<br/>DomainControlValidated | Starfield Technologies | false |  |  | false | NA |  | join.toysrus.com | XPANSE |
>| 5896d6d2-dec5-389c-b2ea-47dd78a5d215 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | Expired | GeoTrust | false |  |  | false | NA |  | kiosk.toysrus.com.au | XPANSE |
>| d1caf737-e3fa-3eff-a6b3-1263b344220e | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | Expired | GeoTrust | false |  |  | false | NA |  | kiosk.toysrus.com.au | XPANSE |
>| 6fe11b60-3d7b-3dc9-b135-65a61bcfe7be | CERTIFICATE | jwilkes - Toys R US | SHA1withRSA | ShortKey,<br/>Expired,<br/>InsecureSignature | Unknown | false |  |  | false | NA |  | llookups-test.toysrus.com | XPANSE |
>| 044e7009-9c78-31e6-a694-4fc98a0cbc19 | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | Symantec | false |  |  | false | NA |  | loyaltylookups-staging.toysrus.com | XPANSE |
>| 4ea85f00-95dc-3f8a-a211-63cccf5b2dc9 | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | Symantec | false |  |  | false | NA |  | loyaltylookups-staging.toysrus.com | XPANSE |
>| 7ed1627e-5c71-3470-bb78-8e4fd55875de | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | loyaltylookups-staging.toysrus.com | XPANSE |
>| d299714c-4d7c-3a1f-8a48-1a93837e13f3 | CERTIFICATE | jwilkes - Toys R US | SHA1withRSA | Expired,<br/>InsecureSignature | VeriSign | false |  |  | false | NA |  | loyaltylookups.toysrus.com | XPANSE |
>| 663d3d93-6795-3e2b-9db6-c874b2b7531b | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | Symantec | false |  |  | false | NA |  | loyaltylookups.toysrus.com | XPANSE |
>| 499e4ad4-388d-3c40-a046-bce561a6d5b6 | CERTIFICATE | jwilkes - Toys R US | SHA1withRSA | Expired,<br/>InsecureSignature | VeriSign | false |  |  | false | NA |  | loyaltylookups.toysrus.com | XPANSE |
>| 3b2f3ca5-0d2c-35d0-a4fd-1e3ccb4a7006 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | loyaltylookups.toysrus.com | XPANSE |
>| 4afb14e5-8bd7-3d47-84be-c9eccaec0545 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | Expired | Thawte | false |  |  | false | NA |  | m.toysrus.com | XPANSE |
>| e1acf452-ef9a-35f0-9cc8-507d2f578df0 | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | Thawte | false |  |  | false | NA |  | m.toysrus.com | XPANSE |
>| e6475bd0-3a10-32f9-8ca9-cae68452782a | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | Thawte | false |  |  | false | NA |  | m.toysrus.com | XPANSE |
>| 960a7f0c-0f6f-34f4-aa8a-04f5b59ef5df | CERTIFICATE | jwilkes - Toys R US | SHA1withRSA | Expired,<br/>InsecureSignature | Thawte | false |  |  | false | NA |  | m.toysrus.com | XPANSE |
>| df44d13d-7dae-31f0-bf8c-b2a7568b2a76 | CERTIFICATE | jwilkes - Toys R US | SHA1withRSA | Expired,<br/>InsecureSignature | Thawte | false |  |  | false | NA |  | m.toysrus.com | XPANSE |
>| 66594f5d-abdf-3f42-8b04-4ba7babd6800 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | Expired | Thawte | false |  |  | false | NA |  | m.toysrus.com | XPANSE |
>| 66857a4a-383e-329d-9bd0-92717e539b61 | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Expired | DigiCert | false |  |  | false | NA |  | m.toysrus.com.au | XPANSE |
>| ddb22485-a053-31e5-95cd-13b37eace21d | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | Expired | GeoTrust | false |  |  | false | NA |  | m.toysrus.com.au | XPANSE |
>| ab212979-3c68-35a2-a6aa-7547ab6d5c59 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | mobile-app-pnj-pre.toysrus.com | XPANSE |
>| 12e9135c-ca97-37e8-ad25-ab6aa0231b84 | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | Symantec | false |  |  | false | NA |  | mobile-app.toysrus.com | XPANSE |
>| baa0a0c9-b893-3ddc-a041-57e9395fe32b | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | mobile-app.toysrus.com | XPANSE |
>| 44901eb2-c507-3837-a4a2-9380b3e0d5f4 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | mstage.toysrus.com | XPANSE |
>| ef57aade-7e6f-36dd-b1af-444cab08743a | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | SelfSigned,<br/>LongExpiration | Unknown | false |  |  | false | NA |  | mvi.toysrus.com | XPANSE |
>| ecee86d9-1f38-3467-9223-88e7e571a547 | CERTIFICATE | jwilkes - Toys R US | SHA1withRSA | Expired,<br/>InsecureSignature | VeriSign | false |  |  | false | NA |  | ocs.toysrus.com | XPANSE |
>| bf53eec6-8541-3de8-a7d8-d573a42b62f1 | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | Symantec | false |  |  | false | NA |  | partners.toysrus.com | XPANSE |
>| bafb6c95-62ac-3480-adad-40da78881e00 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | partners.toysrus.com | XPANSE |
>| 80276242-80ff-3c83-9727-e7abfe77cc9d | CERTIFICATE | jwilkes - Toys R US | SHA1withRSA | Expired,<br/>InsecureSignature | VeriSign | false |  |  | false | NA |  | partners.toysrus.com | XPANSE |
>| 35cf214e-f216-35e1-a43b-fd03ae77e959 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | partnersdev.toysrus.com | XPANSE |
>| 5e1552fc-0f8a-3e9e-81da-2e3942dff14f | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | Symantec | false |  |  | false | NA |  | partnersdev.toysrus.com | XPANSE |
>| a2f5abb9-90b6-349a-b676-7207b91243ad | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | Symantec | false |  |  | false | NA |  | partnerstest.toysrus.com | XPANSE |
>| 4c3602ed-719a-3023-a211-a2d55d4c8915 | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | Symantec | false |  |  | false | NA |  | partnerwebservices-staging.rewardsrus.toysrus.com | XPANSE |
>| ba5a44e2-ffa2-3752-b115-a43bf4bbd640 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | partnerwebservices-staging.rewardsrus.toysrus.com | XPANSE |
>| 7e26e433-eb87-36eb-b9ac-22246b8a2e89 | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | Symantec | false |  |  | false | NA |  | partnerwebservices.rewardsrus.toysrus.com | XPANSE |
>| c6fda74b-6bf5-3cda-9bad-ffdfdcd52cc0 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | partnerwebservices.rewardsrus.toysrus.com | XPANSE |
>| c8d839e2-6719-3c42-bfe2-b722d3f3806b | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | Expired | Let's Encrypt | false |  |  | false | NA |  | rdcservicedesk.toysrus.com | XPANSE |
>| eb0ff340-f231-3e5c-a798-b44558cb9de8 | CERTIFICATE | jwilkes - Toys R US | SHA1withRSA | Expired,<br/>SelfSigned,<br/>ShortKey,<br/>LongExpiration,<br/>InsecureSignature | ToysRUs | false |  |  | false | NA |  | rewardsrus-staging.toysrus.com | XPANSE |
>| d7767bc5-d9db-3e9f-93b7-1989ba2284de | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | Symantec | false |  |  | false | NA |  | rewardsrus-staging.toysrus.com | XPANSE |
>| 357b2c06-7603-3996-ba4b-29e2916061c8 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | rewardsrus-staging.toysrus.com | XPANSE |
>| 392e6ced-f4ee-3f15-a10e-035639c2701e | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | Symantec | false |  |  | false | NA |  | rewardsrus.toysrus.com | XPANSE |
>| 3636d8b3-d81d-3700-a3e3-74541868e71c | CERTIFICATE | jwilkes - Toys R US | SHA1withRSA | Expired,<br/>InsecureSignature | VeriSign | false |  |  | false | NA |  | rewardsrus.toysrus.com | XPANSE |
>| 5e41fb84-0934-3e60-a8fc-e3372097f08c | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | rewardsrus.toysrus.com | XPANSE |
>| d1300db2-d710-305c-89ac-2260e461af61 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | Expired | Let's Encrypt | false |  |  | false | NA |  | rintlservicedesk.toysrus.com | XPANSE |
>| 855b2ec3-53c8-364f-a826-274d2d6a8b68 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | Expired | Let's Encrypt | false |  |  | false | NA |  | rservicedesk.toysrus.com | XPANSE |
>| 8d4f0c24-b898-3eaa-9363-046d5cf68400 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | Expired | DigiCert | false |  |  | false | NA |  | rservicedesk.toysrus.com | XPANSE |
>| 30d3834d-9e8b-31fc-93d9-8ca619a47a27 | CERTIFICATE | jwilkes - Toys R US | SHA1withRSA | Expired,<br/>InsecureSignature | Thawte | false |  |  | false | NA |  | rspeedycheckout.toysrus.com | XPANSE |
>| 3e3ff2fa-57ed-3723-a9a8-24807dc53c11 | CERTIFICATE | jwilkes - Toys R US | SHA1withRSA | Expired,<br/>InsecureSignature | Thawte | false |  |  | false | NA |  | rspeedycheckoutqa.toysrus.com | XPANSE |
>| 6964b1d2-b366-3904-8234-7f8b486e0272 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | Expired | Let's Encrypt | false |  |  | false | NA |  | rstoreservicedesk.toysrus.com | XPANSE |
>| a8a87230-c6d1-3cb0-8257-4523278ba3f2 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | rusmob.toysrus.com | XPANSE |
>| cd288140-105a-35c4-a77f-f41e4618ac77 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | rusmobd.toysrus.com | XPANSE |
>| f016395a-f9de-3506-9919-8ba5d4df1395 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | rusmobp.toysrus.com | XPANSE |
>| 98556cc7-b1a7-3468-ad0a-f76d3a0b603e | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | SelfSigned,<br/>LongExpiration | Unknown | false |  |  | false | NA |  | servidor.toysrus.com | XPANSE |
>| c2adaf7f-974d-326e-aabd-60b60b7a7d56 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | Expired | DigiCert | false |  |  | false | NA |  | smetrics.toysrus.com | XPANSE |
>| 046adde2-50ab-3011-b099-cf01957677a0 | CERTIFICATE | jwilkes - Toys R US | SHA1withRSA | Expired,<br/>LongExpiration,<br/>DomainControlValidated,<br/>InsecureSignature | GeoTrust | false |  |  | false | NA |  | smetrics.toysrus.com | XPANSE |
>| 8376b6d5-53cf-382e-826b-8df74726f439 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | Expired | DigiCert | false |  |  | false | NA |  | smetrics.toysrus.com | XPANSE |
>| b0d8aa8a-a72d-3722-b1b6-2f954c334d27 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | Healthy | DigiCert | false | Amazon Web Services | 1660069806000 | false | NA | 1661192205000 | smetrics.toysrus.com | XPANSE |
>| 75145423-529a-3f4a-bfd7-2f41c1b43929 | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | DigiCert | false |  |  | false | NA |  | smetrics.toysrus.com | XPANSE |
>| e0bc7a2a-11b7-3502-bf3e-12feacc6ada2 | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | Expired | DigiCert | false |  |  | false | NA |  | smetrics.toysrus.com | XPANSE |
>| a2bd231a-9bd3-3524-bbaa-b78f9be8e64e | CERTIFICATE | jwilkes test - VanDelay Industries | SHA256withRSA | Expired | DigiCert | false |  |  | false | NA |  | smetrics.toysrus.com | XPANSE |
>| 0035678e-4c5f-358a-a355-7a8b10a84b7b | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Expired | DigiCert | false |  |  | false | NA |  | stores.toysrus.com | XPANSE |
>| cf7bdcce-9cb9-379d-a0d5-7c7f7c935d30 | CERTIFICATE | jwilkes - Toys R US | SHA1withRSA | Expired,<br/>InsecureSignature | Thawte | false |  |  | false | NA |  | t.toysrus.com | XPANSE |
>| 81d85787-c125-3d19-a06c-8256d8c64a2c | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | Thawte | false |  |  | false | NA |  | t.toysrus.com | XPANSE |
>| 949b98e6-f459-3258-803a-a96c81a7818d | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | Expired | Thawte | false |  |  | false | NA |  | t.toysrus.com | XPANSE |
>| dff7b78d-2502-3f45-b86f-26d8ada75e6d | CERTIFICATE | jwilkes - Toys R US | SHA256withRSA | Expired | Thawte | false |  |  | false | NA |  | t.toysrus.com | XPANSE |
>| dc659c89-5770-389a-8752-ff229aaa309e | CERTIFICATE | jwilkes - Toys R US,<br/>jwilkes test - VanDelay Industries | SHA256withRSA | Expired | Thawte | false |  |  | false | NA |  | t.toysrus.com | XPANSE |


### asm-getassetinternetexposure
***
Get Internet exposure asset details according to the asset ID.


#### Base Command

`asm-getassetinternetexposure`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asm_id | An string representing the asset ID for which you want to get the details for. | Required | 


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
```!asm-getassetinternetexposure asm_id=e06f15ce-9ab1-3460-8a31-000ac6d2d37e```
#### Context Example
```json
{
    "ASM": {
        "GetAssetInternetExposure": {
            "active_external_services_types": [
                "RdpServer"
            ],
            "active_service_ids": [
                "5cbc3977-ed7b-3ea7-a63d-ef7aa00a1c4e"
            ],
            "all_service_ids": [
                "5cbc3977-ed7b-3ea7-a63d-ef7aa00a1c4e"
            ],
            "asm_ids": "e06f15ce-9ab1-3460-8a31-000ac6d2d37e",
            "business_units": [
                "jwilkes - Toys R US"
            ],
            "certificate_algorithm": null,
            "certificate_classifications": [],
            "certificate_issuer": null,
            "created": 1660329761415,
            "details": {
                "businessUnits": [
                    {
                        "name": "jwilkes - Toys R US"
                    }
                ],
                "certificateDetails": null,
                "dnsZone": null,
                "domain": null,
                "domainAssetType": null,
                "domainDetails": null,
                "inferredCvesObserved": [],
                "ip_ranges": {
                    "34.238.196.163": {
                        "FIRST_IP": "34.238.196.163",
                        "IP_RANGE_ID": "6b64bddb-2117-3d3c-a41b-fa59a79e0833",
                        "LAST_IP": "34.238.196.163"
                    }
                },
                "isPaidLevelDomain": false,
                "latestSampledIp": null,
                "providerDetails": [
                    {
                        "displayName": "On Prem",
                        "name": "OnPrem"
                    }
                ],
                "recentIps": [],
                "subdomainMetadata": null,
                "topLevelAssetMapperDomain": null
            },
            "domain": null,
            "external_services": [
                {
                    "activityStatus": "Active",
                    "serviceKey": "34.238.196.163:3389",
                    "serviceType": "RdpServer"
                }
            ],
            "externally_detected_providers": [
                "On Prem"
            ],
            "externally_inferred_cves": [],
            "externally_inferred_vulnerability_score": null,
            "first_observed": 1660179284000,
            "ips": [],
            "last_observed": 1662460230000,
            "name": "34.238.196.163",
            "resolves": false,
            "type": "ResponsiveIP"
        }
    }
}
```

#### Human Readable Output

>### Asset Internet Exposure
>|active_external_services_types|active_service_ids|all_service_ids|asm_ids|business_units|created|details|external_services|externally_detected_providers|first_observed|last_observed|name|resolves|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| RdpServer | 5cbc3977-ed7b-3ea7-a63d-ef7aa00a1c4e | 5cbc3977-ed7b-3ea7-a63d-ef7aa00a1c4e | e06f15ce-9ab1-3460-8a31-000ac6d2d37e | jwilkes - Toys R US | 1660329761415 | providerDetails: {'name': 'OnPrem', 'displayName': 'On Prem'}<br/>domain: null<br/>topLevelAssetMapperDomain: null<br/>domainAssetType: null<br/>isPaidLevelDomain: false<br/>domainDetails: null<br/>dnsZone: null<br/>latestSampledIp: null<br/>subdomainMetadata: null<br/>recentIps: <br/>businessUnits: {'name': 'jwilkes - Toys R US'}<br/>certificateDetails: null<br/>inferredCvesObserved: <br/>ip_ranges: {"34.238.196.163": {"IP_RANGE_ID": "6b64bddb-2117-3d3c-a41b-fa59a79e0833", "FIRST_IP": "34.238.196.163", "LAST_IP": "34.238.196.163"}} | {'serviceType': 'RdpServer', 'serviceKey': '34.238.196.163:3389', 'activityStatus': 'Active'} | On Prem | 1660179284000 | 1662460230000 | 34.238.196.163 | false | ResponsiveIP |

