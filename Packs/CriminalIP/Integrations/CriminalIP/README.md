Makes API requests to Criminal IP and performs additional operations through the API.
Users can directly receive API results or perform additional operations

## Configure Aws Secrets Manager in Cortex


| **Parameter**                      | **Description**                                                                                                                                                            | **Required** |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| API Key                            | This is your Criminal IP API key.<br/>You can check the API Key on the My Page after signing up on the [Criminal IP website](https://www.criminalip.io/).   | True         |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details or you can check it in the Context.

### ip-report

***
Provides detailed information about IP addresses through Criminal IP's Asset Search.


#### Base Command

`ip-report`

#### Input

| **Argument Name**   | **Description**                                                                                                                                           | **Required** |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| ip                  | IP address to search                                                                                                                           | Required     |


#### Context Output

| **Path**                                                                                         | **Type** | **Description**                                              |
| ------------------------------------------------------------------------------------------------ | -------- | ------------------------------------------------------------ |
| CriminalIP.IP.status  | number  | Status Code  |
| CriminalIP.IP.ip  | string  | Queried IP Address  |
| CriminalIP.IP.issues  | object  | List of Detected Information  |
| CriminalIP.IP.issues.is_vpn | boolean | VPN Detection  |
| CriminalIP.IP.issues.is_cloud | boolean | Cloud Detection  |
| CriminalIP.IP.issues.is_tor | boolean | Tor Detection  |
| CriminalIP.IP.issues.is_proxy | boolean | Proxy Detection  |
| CriminalIP.IP.issues.is_hosting | boolean | Hosting Detection  |
| CriminalIP.IP.issues.is_mobile  | boolean | Mobile Detection  |
| CriminalIP.IP.issues.is_darkweb | boolean | Darkweb Detection  |
| CriminalIP.IP.issues.is_scanner | boolean | Scanner Detection  |
| CriminalIP.IP.issues.is_snort | boolean | Snort Detection  |
| CriminalIP.IP.issues.is_anonymous_vpn | boolean | Anonymous VPN Detection  |
| CriminalIP.IP.score | object  | Score Information  |
| CriminalIP.IP.score.inbound | string  | Inbound Score  |
| CriminalIP.IP.score.outbound  | string  | Outbound Score  |
| CriminalIP.IP.user_search_count | int | User Query Count  |
| CriminalIP.IP.protected_ip  | object  | Detected Real IP  |
| CriminalIP.IP.protected_ip.count  | int | Count of Detected Real IP  |
| CriminalIP.IP.protected_ip.data | list(object)  | List of Detected Real IPs  |
| CriminalIP.IP.protected_ip.data.ip_address  | string  | Real IP Address  |
| CriminalIP.IP.protected_ip.data.confirmed_time  | string(date)  | Real IP Detection Date  |
| CriminalIP.IP.domain  | object  | Detected Domains  |
| CriminalIP.IP.domain.count  | int | Count of Detected Domains  |
| CriminalIP.IP.domain.data | list(object)  | List of Detected Domains  |
| CriminalIP.IP.domain.data.domain  | string  | Domain Name  |
| CriminalIP.IP.domain.data.ip_type | string  | Domain IP Type  |
| CriminalIP.IP.domain.data.registrar | string  | Domain Registrar  |
| CriminalIP.IP.domain.data.create_date | string(date)  | Domain Creation Date  |
| CriminalIP.IP.domain.data.confirmed_time  | string(date)  | Domain Detection Date  |
| CriminalIP.IP.domain.data.email | string  | Domain Email  |
| CriminalIP.IP.whois | object  | Detected Whois Information  |
| CriminalIP.IP.whois.count | int | Count of Detected Whois Records  |
| CriminalIP.IP.whois.data  | list(object)  | List of Detected Whois Records  |
| CriminalIP.IP.whois.data.as_name  | string  | AS Name  |
| CriminalIP.IP.whois.data.as_no  | int | AS Number  |
| CriminalIP.IP.whois.data.city | string  | City  |
| CriminalIP.IP.whois.data.region | string  | Region  |
| CriminalIP.IP.whois.data.org_name | string  | Organization Name  |
| CriminalIP.IP.whois.data.postal_code  | string  | Postal Code  |
| CriminalIP.IP.whois.data.longitude  | float | Longitude  |
| CriminalIP.IP.whois.data.latitude | float | Latitude  |
| CriminalIP.IP.whois.data.org_country_code | string  | Country Code  |
| CriminalIP.IP.whois.data.confirmed_time | string(date)  | Whois Detection Date  |
| CriminalIP.IP.hostname  | object  | Detected Hostname Information  |
| CriminalIP.IP.hostname.count  | int | Count of Detected Hostnames  |
| CriminalIP.IP.hostname.data | list(object)  | List of Detected Hostnames  |
| CriminalIP.IP.hostname.data.domain_name_rep | string  | Hostname Main Domain  |
| CriminalIP.IP.hostname.data.domain_name_full  | string  | Hostname Domain  |
| CriminalIP.IP.hostname.data.confirmed_time  | string  | Hostname Detection Date  |
| CriminalIP.IP.ids | object  | Detected IDS Rule Records  |
| CriminalIP.IP.ids.count | int | Count of Detected IDS Rules  |
| CriminalIP.IP.ids.data  | list(object)  | List of Detected IDS Rules  |
| CriminalIP.IP.ids.data.classification | string  | IDS Classification  |
| CriminalIP.IP.ids.data.url  | string  | IDS URL  |
| CriminalIP.IP.ids.data.message  | string  | IDS Message  |
| CriminalIP.IP.ids.data.confirmed_time | string(date)  | IDS Detection Date  |
| CriminalIP.IP.ids.data.source_system  | string  | IDS Source System  |
| CriminalIP.IP.vpn | object  | Detected VPN Detection Information  |
| CriminalIP.IP.vpn.count | int | Count of Detected VPN Records  |
| CriminalIP.IP.vpn.data  | list(object)  | List of Detected VPN Records  |
| CriminalIP.IP.vpn.data.vpn_name | string  | VPN Name  |
| CriminalIP.IP.vpn.data.vpn_url  | string  | VPN URL  |
| CriminalIP.IP.vpn.data.vpn_source_url | string  | VPN Source URL  |
| CriminalIP.IP.vpn.data.socket_type  | string  | VPN Socket Type  |
| CriminalIP.IP.vpn.data.confirmed_time | string(date)  | VPN Detection Date  |
| CriminalIP.IP.anonymous_vpn | object  | Detected Anonymous VPN Detection Information  |
| CriminalIP.IP.anonymous_vpn.count | int | Count of Detected Anonymous VPN Records  |
| CriminalIP.IP.anonymous_vpn.data  | list(object)  | List of Detected Anonymous VPN Records  |
| CriminalIP.IP.anonymous_vpn.data.vpn_name | string  | Anonymous VPN Name  |
| CriminalIP.IP.anonymous_vpn.data.vpn_url  | string  | Anonymous VPN URL  |
| CriminalIP.IP.anonymous_vpn.data.vpn_source_url | string  | Anonymous VPN Source URL  |
| CriminalIP.IP.anonymous_vpn.data.socket_type  | string  | Anonymous VPN Socket Type  |
| CriminalIP.IP.anonymous_vpn.data.confirmed_time | string(date)  | Anonymous VPN Detection Date  |
| CriminalIP.IP.webcam  | object  | Detected Webcam Record Information  |
| CriminalIP.IP.webcam.count  | int | Count of Detected Webcam Records  |
| CriminalIP.IP.webcam.data | list(object)  | List of Detected Webcam Records  |
| CriminalIP.IP.webcam.data.image_path  | string  | Webcam Image Path  |
| CriminalIP.IP.webcam.data.cam_url | string  | Webcam Cam URL  |
| CriminalIP.IP.webcam.data.country | string  | Webcam Country  |
| CriminalIP.IP.webcam.data.city  | string  | Webcam City  |
| CriminalIP.IP.webcam.data.open_port_no  | int | Webcam Port  |
| CriminalIP.IP.webcam.data.manufacturer  | string  | Webcam Manufacturer  |
| CriminalIP.IP.webcam.data.confirmed_time  | string(date)  | Webcam Detection Date  |
| CriminalIP.IP.honeypot  | object  | Access Records Detected from Honeypot  |
| CriminalIP.IP.honeypot.count  | int | Count of Access Records Detected from Honeypot  |
| CriminalIP.IP.honeypot.data | list(object)  | List of Access Records Detected from Honeypot  |
| CriminalIP.IP.honeypot.data.ip_address  | string  | Honeypot Access IP  |
| CriminalIP.IP.honeypot.data.log_date  | string  | Honeypot Access Log Date  |
| CriminalIP.IP.honeypot.data.dst_port  | int | Honeypot Access Port  |
| CriminalIP.IP.honeypot.data.message | string  | Honeypot Access Message  |
| CriminalIP.IP.honeypot.data.user_agent  | string  | Honeypot Access User Agent  |
| CriminalIP.IP.honeypot.data.protocol_type | string  | Honeypot Access Protocol  |
| CriminalIP.IP.honeypot.data.confirmed_time  | string(date)  | Honeypot Access Date  |
| CriminalIP.IP.ip_category | object  | Detected IP Category Information  |
| CriminalIP.IP.ip_category.count | int | Count of Detected IP Categories  |
| CriminalIP.IP.ip_category.data  | list(object)  | List of Detected IP Categories  |
| CriminalIP.IP.ip_category.data.detect_source  | string  | IP Category Detection Source  |
| CriminalIP.IP.ip_category.data.type | string  | IP Category Classification Type  |
| CriminalIP.IP.ip_category.data.detect_info  | object  | Additional IP Category Detection Information  |
| CriminalIP.IP.ip_category.data.detect_info.md5  | string  | Detected MISP Data MD5 Hash  |
| CriminalIP.IP.ip_category.data.detect_info.domain | string  | Detected MISP Data Domain Value  |
| CriminalIP.IP.ip_category.data.confirmed_time | string(date)  | IP Category Data Detection Date  |
| CriminalIP.IP.port  | object  | Detected Port Information  |
| CriminalIP.IP.port.count  | int | Count of Detected Ports  |
| CriminalIP.IP.port.data | list(object)  | List of Detected Ports  |
| CriminalIP.IP.port.data.app_name  | string  | Service Identified on Port  |
| CriminalIP.IP.port.data.confirmed_time  | string(date)  | Port Detection Date  |
| CriminalIP.IP.port.data.banner  | string  | Port Banner  |
| CriminalIP.IP.port.data.app_version | string  | Service Version Detected on Port  |
| CriminalIP.IP.port.data.open_port_no  | int | Port Number  |
| CriminalIP.IP.port.data.port_status | string  | Port Status  |
| CriminalIP.IP.port.data.protocol  | string  | Protocol Detected on Port  |
| CriminalIP.IP.port.data.socket  | string  | Port Socket Type  |
| CriminalIP.IP.port.data.tags  | list(string)  | List of Tags Detected on Port  |
| CriminalIP.IP.port.data.dns_names | string  | DNS Names Detected on Port  |
| CriminalIP.IP.port.data.sdn_common_name | string  | SDN Common Name Detected on Port  |
| CriminalIP.IP.port.data.jarm_hash | string  | Jarm Hash Detected on Port  |
| CriminalIP.IP.port.data.ssl_info_raw  | string  | SSL Info Detected on Port  |
| CriminalIP.IP.port.data.technologies  | list(object)  | List of Technology Stacks Detected on Port  |
| CriminalIP.IP.port.data.technologies.tech_name  | string  | Technology Stack Name  |
| CriminalIP.IP.port.data.technologies.tech_version | string  | Technology Stack Version  |
| CriminalIP.IP.port.data.technologies.tech_logo_url  | string  | Technology Stack Logo URL  |
| CriminalIP.IP.port.data. is_vulnerability | boolean | Vulnerability Detection on Port  |
| CriminalIP.IP.vulnerability | object  | Detected Vulnerability Information  |
| CriminalIP.IP.vulnerability.count | int | Count of Detected Vulnerabilities  |
| CriminalIP.IP.vulnerability.data  | list(object)  | List of Detected Vulnerabilities  |
| CriminalIP.IP.vulnerability.data.cve_id | string  | CVE ID  |
| CriminalIP.IP.vulnerability.data.cve_description  | string  | CVE Description  |
| CriminalIP.IP.vulnerability.data.cvssv2_vector  | string  | CVSS v2 Vector  |
| CriminalIP.IP.vulnerability.data.cvssv2_score | float | CVSS v2 Score  |
| CriminalIP.IP.vulnerability.data.cvssv3_vector  | string  | CVSS v3 Vector  |
| CriminalIP.IP.vulnerability.data.cvssv3_score | float | CVSS v3 Score  |
| CriminalIP.IP.vulnerability.data.list_cwe | list(object)  | Associated CWE List  |
| CriminalIP.IP.vulnerability.data.list_cwe.cve_id  | string  | CVE ID  |
| CriminalIP.IP.vulnerability.data.list_cwe.cwe_id  | int | CWE ID  |
| CriminalIP.IP.vulnerability.data.list_cwe.cwe_name  | string  | CWE Name  |
| CriminalIP.IP.vulnerability.data.list_cwe.cwe_description | string  | CWE Description  |
| CriminalIP.IP.vulnerability.data.list_edb | list(object)  | Associated EDB List  |
| CriminalIP.IP.vulnerability.data.list_edb.cve_id  | string  | CVE ID  |
| CriminalIP.IP.vulnerability.data.list_edb.edb_id  | int | EDB ID  |
| CriminalIP.IP.vulnerability.data.list_edb.type  | string  | EDB Type  |
| CriminalIP.IP.vulnerability.data.list_edb.platform  | string  | EDB Platform  |
| CriminalIP.IP.vulnerability.data.list_edb.verify_code | int | EDB Verification Code  |
| CriminalIP.IP.vulnerability.data.list_edb.title | string  | EDB Name  |
| CriminalIP.IP.vulnerability.data.list_edb.confirmed_time  | string(date)  | EDB Date  |
| CriminalIP.IP.vulnerability.data.app_name | string  | Vulnerability Service Name  |
| CriminalIP.IP.vulnerability.data.app_version  | string  | Vulnerability Service Version  |
| CriminalIP.IP.vulnerability.data.open_port_no_list  | object  | Port Information Where Vulnerability Exists  |
| CriminalIP.IP.vulnerability.data.open_port_no_list.TCP  | list(int) | List of Vulnerable TCP Ports  |
| CriminalIP.IP.vulnerability.data.open_port_no_list.UDP  | list(int) | List of Vulnerable UDP Ports  |
| CriminalIP.IP.vulnerability.data.have_more_ports  | boolean | Whether More Than 5 Vulnerable Ports Exist  |
| CriminalIP.IP.vulnerability.data.open_port_no | list(object)  | Port Information Where Vulnerability Exists  |
| CriminalIP.IP.vulnerability.data.open_port_no.port  | int | Port Number  |
| CriminalIP.IP.vulnerability.data.open_port_no.socket  | string  | Port Socket Type  |
| CriminalIP.IP.vulnerability.data.list_child | list(object)  | Associated Vulnerability Information  |
| CriminalIP.IP.vulnerability.data.list_child.app_name  | string  | Associated Vulnerability Service Name  |
| CriminalIP.IP.vulnerability.data.list_child.app_version | string  | Associated Vulnerability Service Version  |
| CriminalIP.IP.vulnerability.data.list_child.vendor  | string  | Associated Vulnerability Service Vendor  |
| CriminalIP.IP.vulnerability.data.list_child.type  | string  | Associated Vulnerability Classification Type  |
| CriminalIP.IP.vulnerability.data.list_child.is_vuln | string  | Vulnerability Presence  |
| CriminalIP.IP.vulnerability.data.list_child.target_hw | string  | Associated Vulnerability Target Hardware  |
| CriminalIP.IP.vulnerability.data.list_child.target_sw | string  | Associated Vulnerability Target Software  |
| CriminalIP.IP.vulnerability.data.list_child.update  | string  | Associated Vulnerability Update Information  |
| CriminalIP.IP.vulnerability.data.list_child.edition | string  | Associated Vulnerability Edition Information  |
| CriminalIP.IP.vulnerability.data.vendor | string  | Vulnerability Service Vendor  |
| CriminalIP.IP.vulnerability.data.type | string  | Vulnerability Classification Type  |
| CriminalIP.IP.vulnerability.data.is_vuln  | string  | Vulnerability Presence  |
| CriminalIP.IP.vulnerability.data.target_hw  | string  | Vulnerability Target Hardware  |
| CriminalIP.IP.vulnerability.data.target_sw  | string  | Vulnerability Target Software  |
| CriminalIP.IP.vulnerability.data.update | string  | Vulnerability Update Information  |
| CriminalIP.IP.vulnerability.data.edition  | string  | Vulnerability Edition Information  |
| CriminalIP.IP.mobile  | object  | Mobile Identification Information  |
| CriminalIP.IP.mobile.count  | int | Count of Mobile Identification Records  |
| CriminalIP.IP.mobile.data | list(object)  | List of Mobile Identification Records  |
| CriminalIP.IP.mobile.data.broadband | string  | Mobile Broadband  |
| CriminalIP.IP.mobile.data.organization  | string  | Mobile Organization  |

#### Command example

```!ip-report ip=1.1.1.1```

#### Context Example

```json
{
    "CriminalIP" : {
        "IP" : {
            "ip": "1.1.1.1",
            "issues": {
                "is_vpn": false,
                "is_cloud": false,
                "is_tor": false,
                "is_proxy": false,
                "is_hosting": true,
                "is_mobile": false,
                "is_darkweb": false,
                "is_scanner": false,
                "is_snort": true,
                "is_anonymous_vpn": true
            },
            "score": {
                "inbound": "Critical",
                "outbound": "Moderate"
            },
            "user_search_count": 2,
            "protected_ip": {
                "count": 1,
                "data": [
                    {
                        "ip_address": "1.1.1.1",
                        "confirmed_time": "2022-12-07 03:09:46"
                    }
                ]
            },
            "domain": {
                "count": 1057,
                "data": [
                    {
                        "domain": "xyhaidy.shop",
                        "ip_type": "Unknown",
                        "registrar": "Namecheap, Inc.",
                        "create_date": "2023-06-15 00:00:00",
                        "confirmed_time": "2023-06-18 19:19:36",
                        "email": "abuse@namecheap.com"
                    }
                ]
            },
            "whois": {
                "count": 1,
                "data": [
                    {
                        "as_name": "MICROSOFT-CORP-MSN-AS-BLOCK",
                        "as_no": 8075,
                        "city": "San Jose",
                        "region": "California",
                        "org_name": "MICROSOFT-CORP-MSN-AS-BLOCK",
                        "postal_code": "",
                        "longitude": -121.8916,
                        "latitude": 37.3388,
                        "org_country_code": "us",
                        "confirmed_time": "2022-04-04 00:00:00"
                    }
                ]
            },
            "hostname": {
                "count": 1,
                "data": [
                    {
                        "domain_name_rep": "cmk.ru",
                        "domain_name_full": "ip-195-182-143-57.clients.cmk.ru",
                        "confirmed_time": "2021-09-03 19:27:44"
                    }
                ]
            },
            "ids": {
                "count": 1,
                "data": [
                    {
                        "classification": "botcc",
                        "url": "doc.emergingthreats.net/bin/view/Main/BotCC",
                        "message": "ET CNC Feodo Tracker Reported CnC Server UDP group 3",
                        "confirmed_time": "2022-01-28 00:12:16",
                        "source_system": "./snort-2.9.0 9949"
                    }
                ]
            },
            "vpn": {
                "count": 1,
                "data": [
                    {
                        "vpn_name": "vpngate",
                        "vpn_url": "vpn369337084.opengw.net",
                        "vpn_source_url": "https://www.vpngate.net",
                        "socket_type": "tcp",
                        "confirmed_time": "2022-04-18 14:02:25"
                    }
                ]
            },
            "anonymous_vpn": {
                "count": 1,
                "data": [
                    {
                        "vpn_name": "piavpn",
                        "vpn_url": "179.61.228.2",
                        "vpn_source_url": "https://www.privateinternetaccess.com",
                        "socket_type": "tcp",
                        "confirmed_time": "2022-12-10 00:16:59"
                    }
                ]
            },
            "webcam": {
                "count": 1,
                "data": [
                    {
                        "image_path": "https://s3.us-west-1.amazonaws.com/cip-web-screenshot-new/cctv/151.192.67.27_8081_cctv.jpg",
                        "cam_url": "http://151.192.67.27:8081/webcapture.jpg?command=snap&channel=1?COUNTER",
                        "country": "Singapore",
                        "city": "Singapore",
                        "open_port_no": 8081,
                        "manufacturer": "Hi3516",
                        "confirmed_time": "2022-03-02 09:53:15"
                    }
                ]
            },
            "honeypot": {
                "count": 1,
                "data": [
                    {
                        "ip_address": "64.62.197.76",
                        "log_date": "2023-06-15",
                        "dst_port": 22,
                        "message": "[15/Jun/2023:00:00:10] SSH-2.0-Go",
                        "user_agent": "-",
                        "protocol_type": "tcp",
                        "confirmed_time": "2023-06-15"
                    }
                ]
            },
            "ip_category": {
                "count": 2,
                "data": [
                    {
                        "detect_source": "",
                        "type": "cloud service",
                        "detect_info": {},
                        "confirmed_time": "2021-05-07 14:56:27"
                    },
                    {
                        "detect_source": "",
                        "type": "MISP",
                        "detect_info": {
                            "md5": "460fb928925cb1fe4ae49dd208d43647",
                            "domain": "ab88be2e175710350.bitcoin.com"
                        },
                        "confirmed_time": "2020-09-10 03:40:06"
                    }
                ]
            },
            "port": {
                "count": 39,
                "data": [
                    {
                        "app_name": "ms-wbt-server",
                        "confirmed_time": "2022-03-10 13:53:06",
                        "banner": "HTTP header: HTTP/1.1 403 Forbidden\nServer: nginx/1.14.0 (Ubuntu)\nDate: Thu, 10 Mar 2022 09:45:57 GMT\nContent-Type: text/html\nContent-Length: 178\nConnection: keep-alive\n  html: \n<html>\n<head><title>403 Forbidden</title></head>\n<body bgcolor=\"white\">\n<center><h1>403 Forbidden</h1></center>\n<hr><center>nginx/1.14.0 (Ubuntu)</center>\n</body>\n</html>",
                        "app_version": "Unknown",
                        "open_port_no": 3389,
                        "port_status": "open",
                        "protocol": "RDP",
                        "socket": "tcp",
                        "tags": [
                            "Data Leak"
                        ],
                        "dns_names": "*.cloudflare-dns.com,one.one.one.one",
                        "sdn_common_name": "cloudflare-dns.com",
                        "jarm_hash": "27d3ed3ed0003ed1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c",
                        "ssl_info_raw": "TLS Certificate\nVersion: 3\nSerial Number: 4997145087721625482890198484998041183\n",
                        "technologies": [
                            {
                                "tech_name": "jQuery",
                                "tech_version": "2.2.4",
                                "tech_logo_url": "https://cip-live-image.s3.us-west-1.amazonaws.com/tech/jQuery.svg"
                            }
                        ],
                        "is_vulnerability": false
                    }
                ]
            },
            "vulnerability": {
                "count": 9,
                "data": [
                    {
                        "cve_id": "CVE-2021-23017",
                        "cve_description": "A security issue in nginx resolver was identified, which might allow an attacker who is able to forge UDP packets from the DNS server to cause 1-byte memory overwrite, resulting in worker process crash or potential other impact.",
                        "cvssv2_vector": "NETWORK",
                        "cvssv2_score": 6.8,
                        "cvssv3_vector": "NETWORK",
                        "cvssv3_score": 9.4,
                        "list_cwe": [
                            {
                                "cve_id": "CVE-2021-23017",
                                "cwe_id": 193,
                                "cwe_name": "Off-by-one Error",
                                "cwe_description": "A product calculates or uses an incorrect maximum or minimum value that is 1 more, or 1 less, than the correct value."
                            }
                        ],
                        "list_edb": [
                            {
                                "cve_id": "CVE-2021-44790",
                                "edb_id": 51193,
                                "type": "WEBAPPS",
                                "platform": "MULTIPLE",
                                "verify_code": 0,
                                "title": "Apache 2.4.x - Buffer Overflow",
                                "confirmed_time": "2023-04-01"
                            }
                        ],
                        "app_name": "nginx",
                        "app_version": "1.14.0",
                        "open_port_no_list": {
                            "TCP": [
                                514
                            ],
                            "UDP": []
                        },
                        "have_more_ports": false,
                        "open_port_no": [
                            {
                                "port": 514,
                                "socket": "tcp"
                            }
                        ],
                        "list_child": [
                            {
                                "app_name": "nginx",
                                "app_version": "1.14.0",
                                "vendor": "nginx",
                                "type": "a",
                                "is_vuln": "True",
                                "target_hw": "iphone_os",
                                "target_sw": "ipad",
                                "update": "sp6a",
                                "edition": "workstation"
                            }
                        ],
                        "vendor": "nginx",
                        "type": "a",
                        "is_vuln": "True",
                        "target_hw": "iphone_os",
                        "target_sw": "ipad",
                        "update": "sp6a",
                        "edition": "workstation"
                    }
                ]
            },
            "mobile": {
                "count": 2,
                "data": [
                    {
                        "broadband": "3G",
                        "organization": "SKT"
                    },
                    {
                        "broadband": "LTE",
                        "organization": "SKT"
                    }
                ]
            },
            "status": 200
        }
    }
}
```

### check-malicious-ip
***
Determines whether an IP is malicious or safe through Criminal IP Asset Search. 
The IP is evaluated by referencing the IP Score, presence of Real IP, and Issues.

#### Base Command
`check-malicious-ip`

#### Input
| **Argument Name**   | **Description**                                                                                                                                           | **Required** |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
|  ip                    | IP Adress to be checked malicious ip                                                                                                                           | Required     |
|  enable_vpn            | When evaluating an IP, VPN is excluded from the judgment criteria. <br/>The default value is True, and if True, it is included in the judgment criteria.                                                                                                                           | Optional     |
|  enable_cloud          | When evaluating an IP, Cloud is excluded from the judgment criteria.<br/>The default value is True, and if True, it is included in the judgment criteria.                                                                                                                           | Optional     |
|  enable_tor            | When evaluating an IP, Tor is excluded from the judgment criteria.<br/>The default value is True, and if True, it is included in the judgment criteria.                                                                                                                           | Optional     |  enable_proxy          | When evaluating an IP, Proxy is excluded from the judgment criteria.<br/>The default value is True, and if True, it is included in the judgment criteria.                                                                                                                           | Optional     |
|  enable_hosting        | When evaluating an IP, Hosting is excluded from the judgment criteria.<br/>The default value is True, and if True, it is included in the judgment criteria.                                                                                                                           | Optional     |
|  enable_mobile         | When evaluating an IP, Mobile is excluded from the judgment criteria.<br/>The default value is True, and if True, it is included in the judgment criteria.                                                                                                                           | Optional     |
|  enable_darkweb        | When evaluating an IP, Dark web is excluded from the judgment criteria.<br/>The default value is True, and if True, it is included in the judgment criteria.                                                                                                                           | Optional     |
|  enable_scanner        | When evaluating an IP, Scanner is excluded from the judgment criteria.<br/>The default value is True, and if True, it is included in the judgment criteria.                                                                                                                           | Optional     |
|  enable_snort          | When evaluating an IP, Snort is excluded from the judgment criteria.<br/>The default value is True, and if True, it is included in the judgment criteria.                                                                                                                           | Optional     |
|  enable_anonymous_vpn  | When evaluating an IP, Anonymous VPN is excluded from the judgment criteria.<br/>The default value is True, and if True, it is included in the judgment criteria.                                                                                                                           | Optional     |

#### Context Output
| **Path**                                                                                         | **Type** | **Description**                                              |
| ------------------------------------------------------------------------------------------------ | -------- | ------------------------------------------------------------ |
| CriminalIP.Mal_IP.ip  | string  | Queried IP    |
| CriminalIP.Mal_IP.malicious  | bool  | Flag indicating whether the IP is malicious; True if malicious, False if safe    |
| CriminalIP.Mal_IP.real_ip_list  | list(object)   | A list of real IPs, if any exist    |
| CriminalIP.Mal_IP.confirmed_time  | string(date)   | Datetime when Real IP was confirmed    |
| CriminalIP.Mal_IP.ip_address  | string   | IP Address of the Real IP    |

#### Command example
``` !check-malicious-ip ip=1.1.1.1 ```

#### Context Example
```json
{
    "CriminalIP" : {
        "Mal_IP" : {
            "ip" : "1.1.1.1",
            "malicious" : true,
            "real_ip" : [
                {
                    "confirmed_time" : "2023-07-09 18:32:00",
                    "ip_address" : "18.222.87.101"
                }
            ]
        }
    }
}
```

### domain-quick-scan
***
Performs a Domain Quick Scan using Criminal IP

#### Base Command
`domain-quick-scan`

#### Input
| **Argument Name**   | **Description**                                                                                                                                           | **Required** |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
|  domain             | Domain to be quickly scaned                                                                                                                           | Required     |

#### Context Output
| **Path**                                                                                         | **Type** | **Description**                                              |
| ------------------------------------------------------------------------------------------------ | -------- | ------------------------------------------------------------ |
|CriminalIP.Domain_Quick.status |number | Status Code | 
|CriminalIP.Domain_Quick.message |string | Status Message | 
|CriminalIP.Domain_Quick.data |Object(Malicious) | Malicious Detail Information | 
|CriminalIP.Domain_Quick.data.call_count | Int | Total Number of Calls | 
|CriminalIP.Domain_Quick.data.domain | str | Target Domain | 
|CriminalIP.Domain_Quick.data.reg_dtime | Datetime | Registration Time | 
|CriminalIP.Domain_Quick.data.type | str | Type of Malicious Activity | 
|CriminalIP.Domain_Quick.data.result | str  | Classification (Malicious / Whitelist / Unknown) <br/>safe: Whitelist <br/>malicious: Malicious <br/> unknown: Unknown |

#### Command example
``` !domain-quick-scan domain=example.com ```

#### Context Example
```json
{
    "CriminalIP" : {
        "Domain_Quick" : {
            "data": {
                "call_count": 21,
                "domain": "naver.com",
                "reg_dtime": "2023-02-09 02:00:43",
                "result": "safe",
                "type": "searchengine"
            },
            "message": "api success",
            "status": 200
        }
    }
}
```

### domain-lite-scan
***
Initiates a Domain Lite Scan in Criminal IP and returns a scan_id. <br/>With this scan_id, you can check the scan progress through `domain-lite-scan-status` and receive scan results through `domain-lite-scan-result`.

#### Base Command
`domain-lite-scan`

#### Input
| **Argument Name**   | **Description**                                                                                                                                           | **Required** |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
|  domain             | Domain to perform Lite Scan                                                                                                                          | Required     |


#### Context Output
| **Path**                                                                                         | **Type** | **Description**                                              |
| ------------------------------------------------------------------------------------------------ | -------- | ------------------------------------------------------------ |
|CriminalIP.Domain_Lite.status | number |  Status Code |
|CriminalIP.Domain_Lite.message | string |  Status Message |
|CriminalIP.Domain_Lite.data | Object(scan_id) |  Includes Scan ID Value |
|CriminalIP.Domain_Lite.data.query | string |  Input Query |
|CriminalIP.Domain_Lite.data.scan_id | string |  Lite Scan Report scan_id |

#### Command example
``` !domain-lite-scan domain=example.com ```

#### Context Example
```json
{
    "CriminalIP": {
        "Domain_Lite": {
            {
                "data": {
                    "query": "http://example.com",
                    "scan_id": "ba3c4e1c53404e6485cef625f9df5060"
                },
                "message": "api success",
                "status": 200
            }
        }
    }
}
```

### CriminalIP.Domain_Lite_Status
***
You can check the progress of Lite Scan. <br/>Before executing this Command, you must first run domain-lite-scan and take the resulting scan_id as an argument.<br/>Also, Lite Scan may take 2 to 5 seconds. <br/>Therefore, it is recommended to use [GenericPolling](https://xsoar.pan.dev/docs/playbooks/generic-polling). <br/>For an example of this, please refer to the Criminal IP Run Micro ASM playbook.

#### Base Command
`domain-lite-scan-status`

#### Input
| **Argument Name**   | **Description**                                                                                                                                           | **Required** |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
|  scan_id             | scan_id to be check lite scan status                                                                                                                        | Required     |

#### Context Output
| **Path**                                                                                         | **Type** | **Description**                                              |
| ------------------------------------------------------------------------------------------------ | -------- | ------------------------------------------------------------ |
|CriminalIP.Domain_Lite_Status.status | number |  Status Code|
|CriminalIP.Domain_Lite_Status.message | string |  Status Message|
|CriminalIP.Domain_Lite_Status.data | object(scan_percentage) |  Includes Scan Percentage Value |
|CriminalIP.Domain_Lite_Status.data.scan_percentage | number |  The value ranges from 0 to 100. <br/>If the scan fails, it returns -1. <br/>If the domain does not exist, it returns -2|

#### Command example
``` !domain-lite-scan-status scan_id=a45ef9995a8f4596b592a38962f298f6```

#### Context Example
```json
{
    "CriminalIP": {
        "Domain_Lite_Status": {
            "data": {
                "scan_percentage": 100
            },
            "message": "api success",
            "status": 200
        }
    }
}
```

### domain-lite-scan-result
***
Lite Scan returns the scan results for the completed scan_id. <br/>Before executing this Command, you must verify that the scan has been completed through domain-lite-scan-status.

#### Base Command
`domain-lite-scan-result`

#### Input
| **Argument Name**   | **Description**                                                                                                                                           | **Required** |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
|  scan_id             | scan_id to be check lite scan result                                                                                                                        | Required     |

#### Context Output
| **Path**                                                                                         | **Type** | **Description**                                              |
| ------------------------------------------------------------------------------------------------ | -------- | ------------------------------------------------------------ |
| CriminalIP.Domain_Lite_Result.status | number | Status Code |
| CriminalIP.Domain_Lite_Result.message | string | Status Message |
| CriminalIP.Domain_Lite_Result.data | object(Report) | Detailed Report Information |
| CriminalIP.Domain_Lite_Result.data.classification | object | Domain Classification Based on CIP |
| CriminalIP.Domain_Lite_Result.data.dns_record | object | Domain DNS Information |
| CriminalIP.Domain_Lite_Result.data.domain_score | string | Domain Score Information |
| CriminalIP.Domain_Lite_Result.data.main_domain_info | object | Main Domain Information |
| CriminalIP.Domain_Lite_Result.data.mapped_ip | array(object) | Mapped IP Addresses of the Domain |
| CriminalIP.Domain_Lite_Result.data.real_ip | array(object) | Cloudflare Real IP |
| CriminalIP.Domain_Lite_Result.data.report_time | string | Domain Report Generation Time |
| CriminalIP.Domain_Lite_Result.data.summary | objet(summary) | Threat Summary Information |
| CriminalIP.Domain_Lite_Result.data.summaryabuse_record | object | Number of Domain-Linked IPs Scored as Critical, Dangerous, or Moderate |
| CriminalIP.Domain_Lite_Result.data.summarydga_score | number | AI Assessment of Whether the Domain Was Created Using Random Naming Rules |
| CriminalIP.Domain_Lite_Result.data.summaryfake_https_url | boolean | Whether the URL Uses a Fake HTTPS Scheme |
| CriminalIP.Domain_Lite_Result.data.summarymail_server | boolean | Whether It Is a Mail Server |
| CriminalIP.Domain_Lite_Result.data.summaryoverlong_domain | boolean | If the hostname length of the URL is 30 characters or more, it is considered suspicious (True); otherwise (False) |
| CriminalIP.Domain_Lite_Result.data.summarypunycode | boolean | If the URL contains xn--, indicating the use of non-Latin characters, then True; otherwise False |
| CriminalIP.Domain_Lite_Result.data.summaryreal_ip | number | Number of Cloudflare Real IPs |
| CriminalIP.Domain_Lite_Result.data.summarysymbol_url | boolean | If the URL contains the '@' character, then True; otherwise False |
| CriminalIP.Domain_Lite_Result.data.summaryurl_phishing_prob | number | A Machine Learning-Based Indicator Showing How Close the Input URL Is to a Phishing URL (0–100% probability; closer to 0% means normal, closer to 100% means more likely phishing) |


#### Command example
``` !domain-lite-scan-result scan_id=a45ef9995a8f4596b592a38962f298f6 ```

#### Context Example
```json
{
    "CriminalIP" : {
        "Domain_Lite_Result" : {
            "data": {
                "classification": {
                    "dga_score": 0.002,
                    "domain_type": [
                        "searchengines",
                        "company"
                    ]
                },
                "dns_record": {
                    "dns_record_type_a": {
                        "ipv4": [
                            "223.130.200.107",
                            "223.130.195.95",
                            "223.130.195.200",
                            "223.130.200.104"
                        ],
                        "ipv6": []
                    },
                    "dns_record_type_cname": [],
                    "dns_record_type_mx": [
                        [
                            "mx2.naver.com",
                            "mx1.naver.com",
                            "mx3.naver.com"
                        ]
                    ],
                    "dns_record_type_ns": [
                        "ns2.naver.com.",
                        "ns1.naver.com."
                    ],
                    "dns_record_type_ptr": [],
                    "dns_record_type_soa": []
                },
                "domain_score": "20% (Safe)",
                "main_domain_info": {
                    "changed_url": "",
                    "domain_created": "1997-09-12",
                    "domain_registrar": "Gabia, Inc.",
                    "inserted_url": "http://www.naver.com",
                    "main_domain": "www.naver.com"
                },
                "mapped_ip": [
                    {
                        "as_name": "AKAMAI-AS",
                        "country": "AU",
                        "ip": "23.202.169.64",
                        "score": "low"
                    }
                ],
                "real_ip": [],
                "summary": {
                    "abuse_record": {
                        "critical": 0,
                        "dangerous": 0,
                        "moderate": 0
                    },
                    "dga_score": 0.002,
                    "fake_https_url": false,
                    "mail_server": true,
                    "overlong_domain": false,
                    "punycode": false,
                    "real_ip": 0,
                    "symbol_url": false,
                    "url_phishing_prob": 0.1
                }
            },
            "message": "api success",
            "status": 200
        }
    }
}
```

### check-last-scan-date
*** 
Full Scan is a time-consuming task, so this checks whether a scan for the domain has been performed within the last 7 days. <br/>If there is a scan history within the last 7 days, the user can receive the scan_id of the most recent scan results.

#### Base Command
`check-last-scan-date`

#### Input
| **Argument Name**   | **Description**                                                                                                                                           | **Required** |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
|  domain             | domain to be check last scan date                                                                                                                       | Required     |

#### Context Output
| **Path**                                                                                         | **Type** | **Description**                                              |
| ------------------------------------------------------------------------------------------------ | -------- | ------------------------------------------------------------ |
| CriminalIP.Scan_Date.scan_id | string | Scan ID if a scan has been performed |
| CriminalIP.Scan_Date.scaned | bool | True if the scan was performed within 7 days; otherwise, False |

#### Command example
``` !check-last-scan-date domain=example.com ```

#### Context Example
```json
{
    "CriminalIP": {
        "Scan_Date": {
            "scan_id": "25064740",
            "scaned": true
        }
    }
}
```

### domain-full-scan
***
Initiates a Domain Full Scan in Criminal IP and returns a scan_id. <br/>With this scan_id, you can check the scan progress through domain-full-scan-status and receive scan results through domain-full-scan-result. <br/>Full Scan may take longer than Lite Scan as it scans more comprehensive information about the domain.

#### Base Command
`domain-full-scan`

#### Input
| **Argument Name**   | **Description**                                                                                                                                           | **Required** |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
|  domain             | domain to be check full scan                                                                                                                       | Required     |

#### Context Output
| **Path**                                                                                         | **Type** | **Description**                                              |
| ------------------------------------------------------------------------------------------------ | -------- | ------------------------------------------------------------ |
|CriminalIP.Full_Scan.status | number |  Status Code |
|CriminalIP.Full_Scan.message | string |  Status Message |
|CriminalIP.Full_Scan.data | Object(scan_id) |  Includes Scan ID Value |
|CriminalIP.Full_Scan.data.query | string |  Input Query |
|CriminalIP.Full_Scan.data.scan_id | number |  Full Scan Report scan_id |

#### Command example
``` !domain-full-scan domain=example.com ```

#### Context Example
```json
{
    "CriminalIP": {
        "Full_Scan": {
            "data": {
                "query": "http://example.com",
                "scan_id": "25436128"
            },
            "message": "api success",
            "status": 200
        }
    }
}
```

### domain-full-scan-status
***
You can check the progress of Full Scan. <br/>Before executing this Command, you must first run domain-full-scan and take the resulting scan_id as an argument.<br/>Also, Full Scan take longer than Lite Scan. <br/>Therefore, it is recommended to use [GenericPolling](https://xsoar.pan.dev/docs/playbooks/generic-polling). <br/>For an example of this, please refer to the Criminal IP Run Micro ASM playbook.

#### Base Command
`domain-full-scan-status`

#### Input
| **Argument Name**   | **Description**                                                                                                                                           | **Required** |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
|  scan_id             | scan_id to be check full scan status                                                                                                                        | Required     |

#### Context Output
| **Path**                                                                                         | **Type** | **Description**                                              |
| ------------------------------------------------------------------------------------------------ | -------- | ------------------------------------------------------------ |
|CriminalIP.Full_Scan_Status.status | number |  Status Code|
|CriminalIP.Full_Scan_Status.message | string |  Status Message|
|CriminalIP.Full_Scan_Status.data | object(scan_percentage) |  Includes Scan Percentage Value |
|CriminalIP.Full_Scan_Status.data.scan_percentage | number |  The value ranges from 0 to 100. <br/>If the scan fails, it returns -1. <br/>If the domain does not exist, it returns -2|

#### Command example
``` !domain-full-scan-status scan_id=25436128 ```

#### Context Example
```json
{
    "CriminalIP": {
        "Full_Scan_Status": {
            "data": {
                "scan_percentage": 100
            },
            "message": "api success",
            "status": 200
        }
    }
}
```

### domain-full-scan-result
***
Full Scan returns the scan results for the completed scan_id. <br/>Before executing this Command, you must verify that the scan has been completed through domain-full-scan-status.

#### Base Command
`domain-full-scan-result`

#### Input
| **Argument Name**   | **Description**                                                                                                                                           | **Required** |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
|  scan_id             | scan_id to be check full scan result                                                                                                                      | Required     |

#### Context Output
| **Path**                                                                                         | **Type** | **Description**                                              |
| ------------------------------------------------------------------------------------------------ | -------- | ------------------------------------------------------------ |
| CriminalIP.Full_Scan_Result.status | number | Status Code   |
| CriminalIP.Full_Scan_Result.message | string | Status Message   |
| CriminalIP.Full_Scan_Result.data | object(Report) | Detailed Report Information |
| CriminalIP.Full_Scan_Result.data.certificates | array(object) | Certificate Information |
| CriminalIP.Full_Scan_Result.data.classification | object | Domain Classification Based on CIP   |
| CriminalIP.Full_Scan_Result.data.connected_domain_subdomain | array(object) | List of Domains/Subdomains Connected During Network Communication |
| CriminalIP.Full_Scan_Result.data.connected_ip | array(object) | Basic Information of Connected IPs During Network Communication |
| CriminalIP.Full_Scan_Result.data.connected_ip_info | array(object) | Detailed Information of Connected IPs During Network Communication |
| CriminalIP.Full_Scan_Result.data.cookies | array(object) | Cookie Information   |
| CriminalIP.Full_Scan_Result.data.detected_program | object | Program Data Activated Inside or Upon Page Execution   |
| CriminalIP.Full_Scan_Result.data.dns_record  | object | Domain DNS Information  |
| CriminalIP.Full_Scan_Result.data.frames | array(object) | Page Frame Information and Number of Request Transfers    |
| CriminalIP.Full_Scan_Result.data.html_page_link_domains | array(object) | List of Domains Extracted from HTML Link Tags |
| CriminalIP.Full_Scan_Result.data.javascript_variables | array(object) | List of JavaScript Global Variables (Including Types and Values)    |
| CriminalIP.Full_Scan_Result.data.links | array(object) | List of HTML Page Links (Including Title and URL)  |
| CriminalIP.Full_Scan_Result.data.main_certificate | object | Main Certificate Information   |
| CriminalIP.Full_Scan_Result.data.main_domain_info | object | Main Domain Information (Including Score)  |
| CriminalIP.Full_Scan_Result.data.mapped_ip | array(object) | Mapped IP Information of the Domain    |
| CriminalIP.Full_Scan_Result.data.network_logs | object | Network Log Information    |
| CriminalIP.Full_Scan_Result.data.page_networking_info | object | Overall Page Communication Information |
| CriminalIP.Full_Scan_Result.data.page_redirections | array(object) | Page Redirection History Information   |
| CriminalIP.Full_Scan_Result.data.report_time | string | Report Scan Time    |
| CriminalIP.Full_Scan_Result.data.screenshots | array(string) | Screenshot URL Paths Captured During Report Scan |
| CriminalIP.Full_Scan_Result.data.security_headers | array(object) | Security-Relevant HTTP Headers  |
| CriminalIP.Full_Scan_Result.data.ssl | boolean | Existence of SSL Certificate Information   |
| CriminalIP.Full_Scan_Result.data.ssl_detail | object | Detailed SSL Certificate Information |
| CriminalIP.Full_Scan_Result.data.subdomains | array(object) | List of Main Domain's Subdomains and Their Scores |
| CriminalIP.Full_Scan_Result.data.technologies | array(object) | Detected Programs on the Page   |
| CriminalIP.Full_Scan_Result.data.summary | object(Summary) | Threat Summary Information |
| CriminalIP.Full_Scan_Result.data.summary.abuse_record | object | Number of Connected IPs Rated as Critical or Dangerous |
| CriminalIP.Full_Scan_Result.data.summary.associated_ip | string | Associated IPs    |
| CriminalIP.Full_Scan_Result.data.summary.connecte_to_ip_directly | number | Number of URLs Using IP Addresses Directly (e.g., http://x.x.x.x/)  |
| CriminalIP.Full_Scan_Result.data.summary.cred_input | string | Form Submission Safety Assessment (None / Safe / Suspicious) |
| CriminalIP.Full_Scan_Result.data.summary.dga_score | number | AI Evaluation of Domain Randomness and Scoring    |
| CriminalIP.Full_Scan_Result.data.summary.diff_domain_favicon | string | Favicon Domain Validation (Safe/Suspicious/Dangerous)   |
| CriminalIP.Full_Scan_Result.data.summary.domain_in_subdomain | boolean | Detection of Subdomain Masquerading as Other Domains   |
| CriminalIP.Full_Scan_Result.data.summary.double_slash_url | boolean | Presence of Double Slashes (//) in URL    |
| CriminalIP.Full_Scan_Result.data.summary.email_domain_check | boolean | Presence of Non-Main-Domain Email Addresses in HTML |
| CriminalIP.Full_Scan_Result.data.summary.fake_domain | boolean | Similarity to Popular Sites (High Similarity with Different URL = True)    |
| CriminalIP.Full_Scan_Result.data.summary.fake_https_url | boolean | Fake HTTPS URL Detection    |
| CriminalIP.Full_Scan_Result.data.summary.fake_ssl | object | Certificate Category (self_signed, expired, no_ssl, mismatch)  |
| CriminalIP.Full_Scan_Result.data.summary.hidden_element | number | Number of Hidden Elements in HTML    |
| CriminalIP.Full_Scan_Result.data.summary.hidden_iframe | number | Number of Hidden iframe Elements  |
| CriminalIP.Full_Scan_Result.data.summary.html_request_url | number | External Media Requests Matching Main Domain   |
| CriminalIP.Full_Scan_Result.data.summary.iframe | number | Number of iframe Elements    |
| CriminalIP.Full_Scan_Result.data.summary.js_obfuscated | number | Number of Threats Related to JavaScript Obfuscation   |
| CriminalIP.Full_Scan_Result.data.summary.list_of_countries | array(string) | Country Information of the Domain  |
| CriminalIP.Full_Scan_Result.data.summary.mail_server | boolean | Whether It Has a Mail Server   |
| CriminalIP.Full_Scan_Result.data.summary.mitm_attack | boolean | Whether Certificate Has 60 or More Domains Linked  |
| CriminalIP.Full_Scan_Result.data.summary.newborn_domain | string | Whether Domain Was Created Within 90 Days    |
| CriminalIP.Full_Scan_Result.data.summary.overlong_domain | boolean | Suspicious if URL Hostname Is 30 Characters or Longer  |
| CriminalIP.Full_Scan_Result.data.summary.page_warning | boolean | Presence of "Oops" or "Warning" Messages in HTML  |
| CriminalIP.Full_Scan_Result.data.summary.phishing_record | number | Number of CIP-Classified Phishing/Malicious Domains |
| CriminalIP.Full_Scan_Result.data.summary.punycode | boolean | Presence of xn-- in URL (Internationalized Domain Name)   |
| CriminalIP.Full_Scan_Result.data.summary.real_ip | number | Number of Real IP Addresses |
| CriminalIP.Full_Scan_Result.data.summary.redirection_diff_asn | number | Number of ASN Changes in Redirection History   |
| CriminalIP.Full_Scan_Result.data.summary.redirection_diff_country | number | Number of Country Changes in Redirection History   |
| CriminalIP.Full_Scan_Result.data.summary.redirection_diff_domain | number | Number of Domain Changes in Redirection History |
| CriminalIP.Full_Scan_Result.data.summary.redirection_onclick | string | Suspicious if Button Events Redirect to Different Domains   |
| CriminalIP.Full_Scan_Result.data.summary.sfh | string | Form Submit Button Action Validity Assessment   |
| CriminalIP.Full_Scan_Result.data.summary.spf1 | string | Whether SPF1 Failure Occurred on MX Query (Indicates Malicious Mail Server)    |
| CriminalIP.Full_Scan_Result.data.summary.suspicious_cookie | boolean | Whether Cookie Domain Differs from Main Domain   |
| CriminalIP.Full_Scan_Result.data.summary.suspicious_element | number | Number of Suspicious Objects in HTML |
| CriminalIP.Full_Scan_Result.data.summary.suspicious_file | number | Number of Downloadable Files Detected as Threats (Via VirusTotal)   |
| CriminalIP.Full_Scan_Result.data.summary.suspicious_footer | boolean | Whether Company Information Exists Outside Footer    |
| CriminalIP.Full_Scan_Result.data.summary.symbol_url | boolean | Presence of '@' in URL  |
| CriminalIP.Full_Scan_Result.data.summary.url_anchor | number | Suspiciousness of 'a' Tag Links in HTML  |
| CriminalIP.Full_Scan_Result.data.summary.url_phishing_prob | number | Machine Learning-Based Phishing Detection Probability (0–100%)    |
| CriminalIP.Full_Scan_Result.data.summary.web_traffic | number | Website Traffic Ranking |

### domain-full-scan-make-email-body
***
In case of conducting a Domain Full Scan, this creates an Email Body to send an overview report of notable findings from the Full Scan results via email. <br/>You can see an example of this command in the Criminal IP Check Malicious Domain playbook

#### Base Command
`domain-full-scan-make-email-body`

#### Input
| **Argument Name**   | **Description**                                                                                                                                           | **Required** |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
|  scan_id            | Domains with completed scans for creating an overview report                                                                                              | Required     |
|  domain             | scan_id of completed scans for creating an overview report                                                                                                | Required     |

#### Context Output
| **Path**                                                                                         | **Type** | **Description**                                              |
| ------------------------------------------------------------------------------------------------ | -------- | ------------------------------------------------------------ |
| CriminalIP.Email_Body.body_element  | string | Target Domain of the Report        |
| CriminalIP.Email_Body.domain  | string | Result of the Report               |
| CriminalIP.Email_Body.scan_id | number | Scan ID Associated with the Report |

#### Command example
``` !domain-full-scan-make-email-body scan_id=25438676 domain=www.criminalip.io ```

#### Context Example
```json
{
    "CriminalIP": {
        "Email_Body": {
            "body_element": "Criminal IP Domain Search Result(www.criminalip.io) : [Probability of Phishing URL : 0.01, Obfuscated Script : 6, Suspicious HTML Element : 5, Page Warning : True, Email Domain Check : True, Abuse Record Critical : 3]",
            "domain": "www.criminalip.io",
            "scan_id": 25438676
        }
    }
}
```

### micro-asm
***
Performs functions similar to ASM for a domain where Full scanning has been completed. 
<br/>If there are any unusual findings in the results, it generates and returns a summary report. 

The following items are checked for the domain
- Checks for CVEs on the domain and its mapped IPs
- Checks for open ports other than 80/443 on the domain and its mapped IPs
- Checks if any certificates for the domain are expiring within 1 month
- Checks for Abuse Records on the domain
- Checks if there are Critical or Dangerous IPs in the Network Logs for the domain
- Checks if there are executable files in the Network Logs for the domain
- Checks for File Exposure on the domain

#### Base Command
`micro-asm`

#### Input
| **Argument Name**   | **Description**                                                                                                                                           | **Required** |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
|  scan_id            | Scan_id of completed scan to perform Micro ASM                                                                                           | Required     |
|  domain             | Domain with completed scan to perform Micro ASM                                                                                             | Required     |

#### Context Output
| **Path**                                                                                         | **Type** | **Description**                                              |
| ------------------------------------------------------------------------------------------------ | -------- | ------------------------------------------------------------ |
| CriminalIP.Micro_ASM.domain  | string | Target Domain of the ASM        |
| CriminalIP.Micro_ASM.result | string | ASM Result and Summary Report            |
| CriminalIP.Micro_ASM.scan_id | number | Scan ID Associated with the ASM Target |

#### Command example
``` !micro-asm scan_id=25438676 domain=www.criminalip.io ```

#### Context Example
```json
{
    "CriminalIP": {
        "Micro_ASM": {
            "domain": "www.criminalip.io",
            "result": "======== www.criminalip.io  ========\nAbuse records : \n\tCritical : 3 \n\tDangerous : 0\nCritical/Dangerous IP in network logs : \n\t{'as_name': 'AUTOMATTIC', 'as_number': '2635', 'country': 'us', 'data_size': '769 B', 'frame_id': '1DE85867ED0FF6E3B7E3978DB63D7D15', 'ip_port': '192.0.78.13:443', 'mime_type': 'application/json', 'protocol': 'h2', 'request': 'GET', 'score': 'critical', 'time': '0.02 ms', 'transfer_size': '0 B', 'type': 'XHR', 'url': 'https://blog.criminalip.io/wp-json/wp/v2/posts?per_page=6&categories=8&lang=en&orderby=date&order=desc&page=1&_fields=id,title,link,jetpack_featured_media_url,date,excerpt'}\n\t{'as_name': 'AUTOMATTIC', 'as_number': '2635', 'country': 'us', 'data_size': '776 B', 'frame_id': '1DE85867ED0FF6E3B7E3978DB63D7D15', 'ip_port': '192.0.78.13:443', 'mime_type': 'application/json', 'protocol': 'h2', 'request': 'GET', 'score': 'critical', 'time': '0.02 ms', 'transfer_size': '0 B', 'type': 'XHR', 'url': 'https://blog.criminalip.io/wp-json/wp/v2/posts?per_page=4&categories=430&lang=en&orderby=date&order=desc&page=1&_fields=id,title,link,jetpack_featured_media_url,date,content,excerpt'}\n\t{'as_name': 'AUTOMATTIC', 'as_number': '2635', 'country': 'us', 'data_size': '715 B', 'frame_id': '1DE85867ED0FF6E3B7E3978DB63D7D15', 'ip_port': '192.0.78.13:443', 'mime_type': 'application/json', 'protocol': 'h2', 'request': 'GET', 'score': 'critical', 'time': '0.02 ms', 'transfer_size': '0 B', 'type': 'XHR', 'url': 'https://blog.criminalip.io/wp-json/wp/v2/posts?per_page=4&categories=1&lang=en&orderby=date&order=desc&page=1'}\n====================================",
            "scan_id": 25438676
        }
    }
}
```