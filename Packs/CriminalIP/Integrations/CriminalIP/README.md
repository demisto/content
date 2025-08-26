# Criminal IP Integration

## Introduction

Criminal IP is a comprehensive threat intelligence platform that provides IP reputation, domain analysis, and security scanning capabilities. This integration enables Palo Alto Cortex XSOAR to leverage Criminal IP's powerful API for threat hunting, incident response, and security investigations.

Criminal IP offers detailed information about IP addresses, domains, and their associated security risks through various scanning and analysis methods. The platform provides real-time threat intelligence, vulnerability assessments, and malicious activity detection to enhance your security operations.

## API Version Tested

This integration has been tested and validated with Criminal IP API version 1.0.

## Configuration Parameters

| **Parameter** | **Description** | **Type** | **Required** |
|---------------|-----------------|----------|--------------|
| API Key | Criminal IP API Key for authentication | Encrypted | True |
| Server URL | Criminal IP API server URL (default: https://api.criminalip.io) | String | False |
| Trust any certificate | Trust any certificate (not recommended for production) | Boolean | False |
| Use system proxy settings | Use system proxy settings for API calls | Boolean | False |

---

## Commands

### criminal-ip-ip-report

***
Provides detailed information about IP addresses through Criminal IP's Asset Search.

#### Base Command
`criminal-ip-ip-report`

#### Input
| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------|--------------|
| ip | IP address to search | Required |

#### Context Output
| **Path** | **Type** | **Description** |
|----------|----------|-----------------|
| CriminalIP.IP.status | number | Status Code |
| CriminalIP.IP.ip | string | Queried IP Address |
| CriminalIP.IP.issues | object | Detected Issues |
| CriminalIP.IP.issues.is_vpn | boolean | VPN Detection |
| CriminalIP.IP.issues.is_cloud | boolean | Cloud Detection |
| CriminalIP.IP.issues.is_tor | boolean | Tor Detection |
| CriminalIP.IP.issues.is_proxy | boolean | Proxy Detection |
| CriminalIP.IP.issues.is_hosting | boolean | Hosting Detection |
| CriminalIP.IP.issues.is_mobile | boolean | Mobile Detection |
| CriminalIP.IP.issues.is_darkweb | boolean | Darkweb Detection |
| CriminalIP.IP.issues.is_scanner | boolean | Scanner Detection |
| CriminalIP.IP.issues.is_snort | boolean | Snort Detection |
| CriminalIP.IP.issues.is_anonymous_vpn | boolean | Anonymous VPN Detection |
| CriminalIP.IP.score | object | Score Information |
| CriminalIP.IP.score.inbound | string | Inbound Score |
| CriminalIP.IP.score.outbound | string | Outbound Score |
| CriminalIP.IP.user_search_count | number | User Query Count |
| CriminalIP.IP.protected_ip | object | Real IP Information |
| CriminalIP.IP.protected_ip.count | number | Number of Real IPs |
| CriminalIP.IP.protected_ip.data | list(object) | List of Real IPs |
| CriminalIP.IP.protected_ip.data.ip_address | string | Real IP Address |
| CriminalIP.IP.protected_ip.data.confirmed_time | date | Detection Time |
| CriminalIP.IP.domain | object | Domain Information |
| CriminalIP.IP.domain.count | number | Number of Domains |
| CriminalIP.IP.domain.data | list(object) | List of Domains |
| CriminalIP.IP.domain.data.domain | string | Domain Name |
| CriminalIP.IP.domain.data.ip_type | string | Domain IP Type |
| CriminalIP.IP.domain.data.registrar | string | Registrar |
| CriminalIP.IP.domain.data.create_date | date | Creation Date |
| CriminalIP.IP.domain.data.confirmed_time | date | Detection Time |
| CriminalIP.IP.domain.data.email | string | Registrant Email |
| CriminalIP.IP.whois | object | Whois Information |
| CriminalIP.IP.whois.count | number | Number of Whois Records |
| CriminalIP.IP.whois.data | list(object) | Whois Records |
| CriminalIP.IP.whois.data.as_name | string | AS Name |
| CriminalIP.IP.whois.data.as_no | number | AS Number |
| CriminalIP.IP.whois.data.city | string | City |
| CriminalIP.IP.whois.data.region | string | Region |
| CriminalIP.IP.whois.data.org_name | string | Organization Name |
| CriminalIP.IP.whois.data.postal_code | string | Postal Code |
| CriminalIP.IP.whois.data.longitude | number | Longitude |
| CriminalIP.IP.whois.data.latitude | number | Latitude |
| CriminalIP.IP.whois.data.org_country_code | string | Country Code |
| CriminalIP.IP.whois.data.confirmed_time | date | Detection Time |
| CriminalIP.IP.hostname | object | Hostname Information |
| CriminalIP.IP.hostname.count | number | Number of Hostnames |
| CriminalIP.IP.hostname.data | list(object) | Hostname Records |
| CriminalIP.IP.hostname.data.domain_name_rep | string | Main Domain |
| CriminalIP.IP.hostname.data.domain_name_full | string | Full Hostname |
| CriminalIP.IP.hostname.data.confirmed_time | date | Detection Time |
| CriminalIP.IP.ids | object | IDS Rules |
| CriminalIP.IP.ids.count | number | Number of IDS Records |
| CriminalIP.IP.ids.data | list(object) | IDS Records |
| CriminalIP.IP.ids.data.classification | string | Classification |
| CriminalIP.IP.ids.data.url | string | Reference URL |
| CriminalIP.IP.ids.data.message | string | IDS Message |
| CriminalIP.IP.ids.data.confirmed_time | date | Detection Time |
| CriminalIP.IP.ids.data.source_system | string | Source System |
| CriminalIP.IP.vpn | object | VPN Info |
| CriminalIP.IP.vpn.count | number | Number of VPN Records |
| CriminalIP.IP.vpn.data | list(object) | VPN Records |
| CriminalIP.IP.vpn.data.vpn_name | string | VPN Name |
| CriminalIP.IP.vpn.data.vpn_url | string | VPN URL |
| CriminalIP.IP.vpn.data.vpn_source_url | string | VPN Source URL |
| CriminalIP.IP.vpn.data.socket_type | string | Socket Type |
| CriminalIP.IP.vpn.data.confirmed_time | date | Detection Time |
| CriminalIP.IP.anonymous_vpn | object | Anonymous VPN Info |
| CriminalIP.IP.anonymous_vpn.count | number | Number of Anonymous VPN Records |
| CriminalIP.IP.anonymous_vpn.data | list(object) | Anonymous VPN Records |
| CriminalIP.IP.anonymous_vpn.data.vpn_name | string | Anonymous VPN Name |
| CriminalIP.IP.anonymous_vpn.data.vpn_url | string | VPN URL |
| CriminalIP.IP.anonymous_vpn.data.vpn_source_url | string | VPN Source URL |
| CriminalIP.IP.anonymous_vpn.data.socket_type | string | Socket Type |
| CriminalIP.IP.anonymous_vpn.data.confirmed_time | date | Detection Time |
| CriminalIP.IP.webcam | object | Webcam Info |
| CriminalIP.IP.webcam.count | number | Number of Webcam Records |
| CriminalIP.IP.webcam.data | list(object) | Webcam Records |
| CriminalIP.IP.webcam.data.image_path | string | Image Path |
| CriminalIP.IP.webcam.data.cam_url | string | Camera URL |
| CriminalIP.IP.webcam.data.country | string | Country |
| CriminalIP.IP.webcam.data.city | string | City |
| CriminalIP.IP.webcam.data.open_port_no | number | Port |
| CriminalIP.IP.webcam.data.manufacturer | string | Manufacturer |
| CriminalIP.IP.webcam.data.confirmed_time | date | Detection Time |
| CriminalIP.IP.honeypot | object | Honeypot Logs |
| CriminalIP.IP.honeypot.count | number | Number of Honeypot Records |
| CriminalIP.IP.honeypot.data | list(object) | Honeypot Records |
| CriminalIP.IP.honeypot.data.ip_address | string | Attacker IP |
| CriminalIP.IP.honeypot.data.log_date | string | Log Date |
| CriminalIP.IP.honeypot.data.dst_port | number | Destination Port |
| CriminalIP.IP.honeypot.data.message | string | Message |
| CriminalIP.IP.honeypot.data.user_agent | string | User Agent |
| CriminalIP.IP.honeypot.data.protocol_type | string | Protocol |
| CriminalIP.IP.honeypot.data.confirmed_time | date | Detection Time |
| CriminalIP.IP.ip_category | object | IP Category Info |
| CriminalIP.IP.ip_category.count | number | Number of Categories |
| CriminalIP.IP.ip_category.data | list(object) | Category Records |
| CriminalIP.IP.ip_category.data.detect_source | string | Detection Source |
| CriminalIP.IP.ip_category.data.type | string | Type |
| CriminalIP.IP.ip_category.data.detect_info | object | Additional Info |
| CriminalIP.IP.ip_category.data.detect_info.md5 | string | MD5 Hash |
| CriminalIP.IP.ip_category.data.detect_info.domain | string | Domain |
| CriminalIP.IP.ip_category.data.confirmed_time | date | Detection Time |
| CriminalIP.IP.port | object | Port Information |
| CriminalIP.IP.port.count | number | Number of Ports |
| CriminalIP.IP.port.data | list(object) | Port Records |
| CriminalIP.IP.port.data.app_name | string | Application |
| CriminalIP.IP.port.data.confirmed_time | date | Detection Time |
| CriminalIP.IP.port.data.banner | string | Banner |
| CriminalIP.IP.port.data.app_version | string | App Version |
| CriminalIP.IP.port.data.open_port_no | number | Port Number |
| CriminalIP.IP.port.data.port_status | string | Status |
| CriminalIP.IP.port.data.protocol | string | Protocol |
| CriminalIP.IP.port.data.socket | string | Socket Type |
| CriminalIP.IP.port.data.tags | list(string) | Tags |
| CriminalIP.IP.port.data.dns_names | string | DNS Names |
| CriminalIP.IP.port.data.sdn_common_name | string | SDN Common Name |
| CriminalIP.IP.port.data.jarm_hash | string | JARM Hash |
| CriminalIP.IP.port.data.ssl_info_raw | string | SSL Info |
| CriminalIP.IP.port.data.technologies | list(object) | Technologies |
| CriminalIP.IP.port.data.technologies.tech_name | string | Tech Name |
| CriminalIP.IP.port.data.technologies.tech_version | string | Version |
| CriminalIP.IP.port.data.technologies.tech_logo_url | string | Logo URL |
| CriminalIP.IP.port.data.is_vulnerability | boolean | Has Vulnerability |
| CriminalIP.IP.vulnerability | object | Vulnerabilities |
| CriminalIP.IP.vulnerability.count | number | Number of Vulnerabilities |
| CriminalIP.IP.vulnerability.data | list(object) | Vulnerability Records |
| CriminalIP.IP.vulnerability.data.cve_id | string | CVE ID |
| CriminalIP.IP.vulnerability.data.cve_description | string | Description |
| CriminalIP.IP.vulnerability.data.cvssv2_vector | string | CVSS v2 Vector |
| CriminalIP.IP.vulnerability.data.cvssv2_score | number | CVSS v2 Score |
| CriminalIP.IP.vulnerability.data.cvssv3_vector | string | CVSS v3 Vector |
| CriminalIP.IP.vulnerability.data.cvssv3_score | number | CVSS v3 Score |
| CriminalIP.IP.vulnerability.data.list_cwe | list(object) | CWE List |
| CriminalIP.IP.vulnerability.data.list_cwe.cve_id | string | CVE ID |
| CriminalIP.IP.vulnerability.data.list_cwe.cwe_id | number | CWE ID |
| CriminalIP.IP.vulnerability.data.list_cwe.cwe_name | string | CWE Name |
| CriminalIP.IP.vulnerability.data.list_cwe.cwe_description | string | CWE Description |
| CriminalIP.IP.vulnerability.data.list_edb | list(object) | Exploit-DB List |
| CriminalIP.IP.vulnerability.data.list_edb.cve_id | string | CVE ID |
| CriminalIP.IP.vulnerability.data.list_edb.edb_id | number | EDB ID |
| CriminalIP.IP.vulnerability.data.list_edb.type | string | Type |
| CriminalIP.IP.vulnerability.data.list_edb.platform | string | Platform |
| CriminalIP.IP.vulnerability.data.list_edb.verify_code | number | Verification Code |
| CriminalIP.IP.vulnerability.data.list_edb.title | string | Title |
| CriminalIP.IP.vulnerability.data.list_edb.confirmed_time | date | Detection Time |
| CriminalIP.IP.vulnerability.data.app_name | string | Application |
| CriminalIP.IP.vulnerability.data.app_version | string | Version |
| CriminalIP.IP.vulnerability.data.open_port_no_list | object | Port Info |
| CriminalIP.IP.vulnerability.data.open_port_no_list.TCP | list(number) | Vulnerable TCP Ports |
| CriminalIP.IP.vulnerability.data.open_port_no_list.UDP | list(number) | Vulnerable UDP Ports |
| CriminalIP.IP.vulnerability.data.have_more_ports | boolean | More Than 5 Ports |
| CriminalIP.IP.vulnerability.data.open_port_no | list(object) | Port Records |
| CriminalIP.IP.vulnerability.data.open_port_no.port | number | Port Number |
| CriminalIP.IP.vulnerability.data.open_port_no.socket | string | Socket Type |
| CriminalIP.IP.vulnerability.data.list_child | list(object) | Child Vulnerabilities |
| CriminalIP.IP.vulnerability.data.list_child.app_name | string | Application |
| CriminalIP.IP.vulnerability.data.list_child.app_version | string | Version |
| CriminalIP.IP.vulnerability.data.list_child.vendor | string | Vendor |
| CriminalIP.IP.vulnerability.data.list_child.type | string | Type |
| CriminalIP.IP.vulnerability.data.list_child.is_vuln | string | Is Vulnerable |
| CriminalIP.IP.vulnerability.data.list_child.target_hw | string | Target HW |
| CriminalIP.IP.vulnerability.data.list_child.target_sw | string | Target SW |
| CriminalIP.IP.vulnerability.data.list_child.update | string | Update |
| CriminalIP.IP.vulnerability.data.list_child.edition | string | Edition |
| CriminalIP.IP.vulnerability.data.vendor | string | Vendor |
| CriminalIP.IP.vulnerability.data.type | string | Type |
| CriminalIP.IP.vulnerability.data.is_vuln | string | Is Vulnerable |
| CriminalIP.IP.vulnerability.data.target_hw | string | Target HW |
| CriminalIP.IP.vulnerability.data.target_sw | string | Target SW |
| CriminalIP.IP.vulnerability.data.update | string | Update |
| CriminalIP.IP.vulnerability.data.edition | string | Edition |
| CriminalIP.IP.mobile | object | Mobile Info |
| CriminalIP.IP.mobile.count | number | Number of Records |
| CriminalIP.IP.mobile.data | list(object) | Mobile Records |
| CriminalIP.IP.mobile.data.broadband | string | Broadband |
| CriminalIP.IP.mobile.data.organization | string | Organization |

#### Command Example
```
!criminal-ip-ip-report ip=8.8.8.8
```

#### Context Example
```json
{
  "CriminalIP": {
    "IP": {
      "status": 200,
      "ip": "8.8.8.8",
      "issues": {
        "is_vpn": false,
        "is_cloud": true,
        "is_tor": false,
        "is_proxy": false,
        "is_hosting": false,
        "is_mobile": false,
        "is_darkweb": false,
        "is_scanner": false,
        "is_snort": false,
        "is_anonymous_vpn": false
      },
      "score": {
        "inbound": "Safe",
        "outbound": "Safe"
      },
      "user_search_count": 1234,
      "whois": {
        "count": 1,
        "data": [
          {
            "as_name": "GOOGLE",
            "as_no": 15169,
            "city": "Mountain View",
            "region": "California",
            "org_name": "Google LLC",
            "org_country_code": "US",
            "confirmed_time": "2024-01-15T10:30:00Z"
          }
        ]
      },
      "port": {
        "count": 2,
        "data": [
          {
            "app_name": "DNS",
            "open_port_no": 53,
            "protocol": "UDP",
            "confirmed_time": "2024-01-15T10:30:00Z"
          }
        ]
      }
    }
  }
}
```

---

### criminal-ip-check-malicious-ip

***
Determines whether an IP is malicious or safe through Criminal IP Asset Search.

#### Base Command
`criminal-ip-check-malicious-ip`

#### Input
| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------|--------------|
| ip | IP address to check | Required |
| enable_vpn | Include VPN usage in evaluation (default true) | Optional |
| enable_cloud | Include Cloud usage in evaluation (default true) | Optional |
| enable_tor | Include Tor usage in evaluation (default true) | Optional |
| enable_proxy | Include Proxy usage in evaluation (default true) | Optional |
| enable_hosting | Include Hosting usage in evaluation (default true) | Optional |
| enable_mobile | Include Mobile usage in evaluation (default true) | Optional |
| enable_darkweb | Include Darkweb usage in evaluation (default true) | Optional |
| enable_scanner | Include Scanner usage in evaluation (default true) | Optional |
| enable_snort | Include Snort usage in evaluation (default true) | Optional |
| enable_anonymous_vpn | Include Anonymous VPN usage in evaluation (default true) | Optional |

#### Context Output
| **Path** | **Type** | **Description** |
|----------|----------|-----------------|
| CriminalIP.Mal_IP.ip | string | Queried IP |
| CriminalIP.Mal_IP.malicious | boolean | True if malicious, False otherwise |
| CriminalIP.Mal_IP.real_ip_list | list(object) | List of detected Real IPs (if any) |
| CriminalIP.Mal_IP.real_ip_list.ip_address | string | Real IP address |
| CriminalIP.Mal_IP.real_ip_list.confirmed_time | date | Detection time |

#### Command Example
```
!criminal-ip-check-malicious-ip ip=192.168.1.1 enable_vpn=false
```

#### Context Example
```json
{
  "CriminalIP": {
    "Mal_IP": {
      "ip": "192.168.1.1",
      "malicious": false,
      "real_ip_list": []
    }
  }
}
```

---

### criminal-ip-domain-quick-scan

***
Performs a Domain Quick Scan using Criminal IP.

#### Base Command
`criminal-ip-domain-quick-scan`

#### Input
| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------|--------------|
| domain | Domain to be quickly scanned | Required |

#### Context Output
| **Path** | **Type** | **Description** |
|----------|----------|-----------------|
| CriminalIP.Domain_Quick.status | number | Status code |
| CriminalIP.Domain_Quick.message | string | Status message |
| CriminalIP.Domain_Quick.data | object | Malicious detail |
| CriminalIP.Domain_Quick.data.call_count | number | Total number of calls |
| CriminalIP.Domain_Quick.data.domain | string | Target domain |
| CriminalIP.Domain_Quick.data.reg_dtime | date | Registration time |
| CriminalIP.Domain_Quick.data.type | string | Malicious activity type |
| CriminalIP.Domain_Quick.data.result | string | Classification (malicious/safe/unknown) |

#### Command Example
```
!criminal-ip-domain-quick-scan domain=example.com
```

#### Context Example
```json
{
  "CriminalIP": {
    "Domain_Quick": {
      "status": 200,
      "message": "Success",
      "data": {
        "call_count": 1,
        "domain": "example.com",
        "reg_dtime": "2024-01-15T10:30:00Z",
        "type": "clean",
        "result": "safe"
      }
    }
  }
}
```

---

### criminal-ip-domain-lite-scan

***
Initiates a Domain Lite Scan and returns a scan_id.

#### Base Command
`criminal-ip-domain-lite-scan`

#### Input
| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------|--------------|
| domain | Domain to perform Lite Scan | Required |

#### Context Output
| **Path** | **Type** | **Description** |
|----------|----------|-----------------|
| CriminalIP.Domain_Lite.status | number | Status code |
| CriminalIP.Domain_Lite.message | string | Status message |
| CriminalIP.Domain_Lite.data | object | Response data |
| CriminalIP.Domain_Lite.data.query | string | Input query |
| CriminalIP.Domain_Lite.data.scan_id | string | Lite scan_id |

#### Command Example
```
!criminal-ip-domain-lite-scan domain=example.com
```

#### Context Example
```json
{
  "CriminalIP": {
    "Domain_Lite": {
      "status": 200,
      "message": "Success",
      "data": {
        "query": "example.com",
        "scan_id": "abc123def456"
      }
    }
  }
}
```

---

### criminal-ip-domain-lite-scan-status

***
Checks the progress of Lite Scan.

#### Base Command
`criminal-ip-domain-lite-scan-status`

#### Input
| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------|--------------|
| scan_id | scan_id to check Lite Scan status | Required |

#### Context Output
| **Path** | **Type** | **Description** |
|----------|----------|-----------------|
| CriminalIP.Domain_Lite_Status.status | number | Status code |
| CriminalIP.Domain_Lite_Status.message | string | Status message |
| CriminalIP.Domain_Lite_Status.data | object | Progress object |
| CriminalIP.Domain_Lite_Status.data.scan_percentage | number | 0–100; -1 on failure; -2 if domain not found |

#### Command Example
```
!criminal-ip-domain-lite-scan-status scan_id=abc123def456
```

#### Context Example
```json
{
  "CriminalIP": {
    "Domain_Lite_Status": {
      "status": 200,
      "message": "Success",
      "data": {
        "scan_percentage": 100
      }
    }
  }
}
```

---

### criminal-ip-domain-lite-scan-result

***
Returns the Lite Scan results for the completed scan_id.

#### Base Command
`criminal-ip-domain-lite-scan-result`

#### Input
| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------|--------------|
| scan_id | scan_id to fetch Lite Scan result | Required |

#### Context Output
| **Path** | **Type** | **Description** |
|----------|----------|-----------------|
| CriminalIP.Domain_Lite_Result.status | number | Status code |
| CriminalIP.Domain_Lite_Result.message | string | Status message |
| CriminalIP.Domain_Lite_Result.data | object | Report |
| CriminalIP.Domain_Lite_Result.data.classification | object | Domain classification (CIP) |
| CriminalIP.Domain_Lite_Result.data.dns_record | object | DNS information |
| CriminalIP.Domain_Lite_Result.data.dns_record.dns_record_type_a | object | A records |
| CriminalIP.Domain_Lite_Result.data.dns_record.dns_record_type_a.ipv4 | list(string) | IPv4 list |
| CriminalIP.Domain_Lite_Result.data.dns_record.dns_record_type_a.ipv6 | list(string) | IPv6 list |
| CriminalIP.Domain_Lite_Result.data.dns_record.dns_record_type_cname | list(string) | CNAMEs |
| CriminalIP.Domain_Lite_Result.data.dns_record.dns_record_type_mx | list(list(string)) | MX records |
| CriminalIP.Domain_Lite_Result.data.dns_record.dns_record_type_ns | list(string) | NS records |
| CriminalIP.Domain_Lite_Result.data.dns_record.dns_record_type_ptr | list(string) | PTR records |
| CriminalIP.Domain_Lite_Result.data.dns_record.dns_record_type_soa | list(string) | SOA records |
| CriminalIP.Domain_Lite_Result.data.domain_score | string | Domain score string |
| CriminalIP.Domain_Lite_Result.data.main_domain_info | object | Main domain info |
| CriminalIP.Domain_Lite_Result.data.main_domain_info.changed_url | string | Changed URL (if redirected) |
| CriminalIP.Domain_Lite_Result.data.main_domain_info.domain_created | string | Created date |
| CriminalIP.Domain_Lite_Result.data.main_domain_info.domain_registrar | string | Registrar |
| CriminalIP.Domain_Lite_Result.data.main_domain_info.inserted_url | string | Input URL |
| CriminalIP.Domain_Lite_Result.data.main_domain_info.main_domain | string | Main domain |
| CriminalIP.Domain_Lite_Result.data.mapped_ip | list(object) | Mapped IPs |
| CriminalIP.Domain_Lite_Result.data.mapped_ip[].ip | string | IP |
| CriminalIP.Domain_Lite_Result.data.mapped_ip[].country | string | Country code |
| CriminalIP.Domain_Lite_Result.data.mapped_ip[].as_name | string | ASN name |
| CriminalIP.Domain_Lite_Result.data.mapped_ip[].score | string | Risk score |
| CriminalIP.Domain_Lite_Result.data.real_ip | list(object) | Cloudflare real IPs |
| CriminalIP.Domain_Lite_Result.data.report_time | string | Report time |
| CriminalIP.Domain_Lite_Result.data.summary | object | Threat summary |
| CriminalIP.Domain_Lite_Result.data.summary.abuse_record | object | Abuse summary of linked IPs |
| CriminalIP.Domain_Lite_Result.data.summary.abuse_record.critical | number | Critical count |
| CriminalIP.Domain_Lite_Result.data.summary.abuse_record.dangerous | number | Dangerous count |
| CriminalIP.Domain_Lite_Result.data.summary.abuse_record.moderate | number | Moderate count |
| CriminalIP.Domain_Lite_Result.data.summary.dga_score | number | DGA score |
| CriminalIP.Domain_Lite_Result.data.summary.fake_https_url | boolean | Fake https scheme |
| CriminalIP.Domain_Lite_Result.data.summary.mail_server | boolean | Has mail server |
| CriminalIP.Domain_Lite_Result.data.summary.overlong_domain | boolean | Hostname length ≥ 30 |
| CriminalIP.Domain_Lite_Result.data.summary.punycode | boolean | Contains xn-- |
| CriminalIP.Domain_Lite_Result.data.summary.real_ip | number | Count of real IPs |
| CriminalIP.Domain_Lite_Result.data.summary.symbol_url | boolean | Contains '@' |
| CriminalIP.Domain_Lite_Result.data.summary.url_phishing_prob | number | ML phishing probability (0–100) |

#### Command Example
```
!criminal-ip-domain-lite-scan-result scan_id=abc123def456
```

#### Context Example
```json
{
  "CriminalIP": {
    "Domain_Lite_Result": {
      "status": 200,
      "message": "Success",
      "data": {
        "classification": {
          "result": "safe"
        },
        "domain_score": "Safe",
        "main_domain_info": {
          "main_domain": "example.com",
          "domain_created": "2024-01-01",
          "domain_registrar": "Example Registrar"
        },
        "mapped_ip": [
          {
            "ip": "93.184.216.34",
            "country": "US",
            "as_name": "EDGECAST",
            "score": "Safe"
          }
        ],
        "summary": {
          "abuse_record": {
            "critical": 0,
            "dangerous": 0,
            "moderate": 0
          },
          "dga_score": 0,
          "fake_https_url": false,
          "mail_server": true,
          "overlong_domain": false,
          "punycode": false,
          "real_ip": 0,
          "symbol_url": false,
          "url_phishing_prob": 0
        }
      }
    }
  }
}
```

---

### criminal-ip-check-last-scan-date

***
Checks whether a Full Scan exists within the last 7 days and returns the latest scan_id.

#### Base Command
`criminal-ip-check-last-scan-date`

#### Input
| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------|--------------|
| domain | Domain to check scan history | Required |

#### Context Output
| **Path** | **Type** | **Description** |
|----------|----------|-----------------|
| CriminalIP.Scan_Date.scan_id | string | Latest scan ID (if exists) |
| CriminalIP.Scan_Date.scanned | boolean | True if scanned within last 7 days |

#### Command Example
```
!criminal-ip-check-last-scan-date domain=example.com
```

#### Context Example
```json
{
  "CriminalIP": {
    "Scan_Date": {
      "scan_id": "xyz789abc123",
      "scanned": true
    }
  }
}
```

---

### criminal-ip-domain-full-scan

***
Initiates a Domain Full Scan and returns a scan_id.

#### Base Command
`criminal-ip-domain-full-scan`

#### Input
| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------|--------------|
| domain | Domain to perform Full Scan | Required |

#### Context Output
| **Path** | **Type** | **Description** |
|----------|----------|-----------------|
| CriminalIP.Full_Scan.status | number | Status code |
| CriminalIP.Full_Scan.message | string | Status message |
| CriminalIP.Full_Scan.data | object | Response data |
| CriminalIP.Full_Scan.data.query | string | Input query |
| CriminalIP.Full_Scan.data.scan_id | string | Full scan_id |

#### Command Example
```
!criminal-ip-domain-full-scan domain=example.com
```

#### Context Example
```json
{
  "CriminalIP": {
    "Full_Scan": {
      "status": 200,
      "message": "Success",
      "data": {
        "query": "example.com",
        "scan_id": "full123scan456"
      }
    }
  }
}
```

---

### criminal-ip-domain-full-scan-status

***
Checks the progress of Full Scan.

#### Base Command
`criminal-ip-domain-full-scan-status`

#### Input
| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------|--------------|
| scan_id | scan_id to check Full Scan status | Required |

#### Context Output
| **Path** | **Type** | **Description** |
|----------|----------|-----------------|
| CriminalIP.Full_Scan_Status.status | number | Status code |
| CriminalIP.Full_Scan_Status.message | string | Status message |
| CriminalIP.Full_Scan_Status.data | object | Progress object |
| CriminalIP.Full_Scan_Status.data.scan_percentage | number | 0–100; -1 on failure; -2 if domain not found |

#### Command Example
```
!criminal-ip-domain-full-scan-status scan_id=full123scan456
```

#### Context Example
```json
{
  "CriminalIP": {
    "Full_Scan_Status": {
      "status": 200,
      "message": "Success",
      "data": {
        "scan_percentage": 75
      }
    }
  }
}
```

---

### criminal-ip-domain-full-scan-result

***
Returns Full Scan results for the completed scan_id.

#### Base Command
`criminal-ip-domain-full-scan-result`

#### Input
| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------|--------------|
| scan_id | scan_id to fetch Full Scan result | Required |

#### Context Output
| **Path** | **Type** | **Description** |
|----------|----------|-----------------|
| CriminalIP.Full_Scan_Result.status | number | Status code |
| CriminalIP.Full_Scan_Result.message | string | Status message |
| CriminalIP.Full_Scan_Result.data | object | Report |
| CriminalIP.Full_Scan_Result.data.certificates | list(object) | Certificates |
| CriminalIP.Full_Scan_Result.data.certificates[].subject | string | Subject |
| CriminalIP.Full_Scan_Result.data.certificates[].issuer | string | Issuer |
| CriminalIP.Full_Scan_Result.data.certificates[].valid_from | string | Valid from |
| CriminalIP.Full_Scan_Result.data.certificates[].valid_to | string | Valid to |
| CriminalIP.Full_Scan_Result.data.classification | object | Domain classification |
| CriminalIP.Full_Scan_Result.data.connected_domain_subdomain | list(object) | Connected domains/subdomains |
| CriminalIP.Full_Scan_Result.data.connected_ip | list(object) | Connected IPs (basic) |
| CriminalIP.Full_Scan_Result.data.connected_ip_info | list(object) | Connected IPs (detailed) |
| CriminalIP.Full_Scan_Result.data.cookies | list(object) | Cookies |
| CriminalIP.Full_Scan_Result.data.detected_program | object | Detected programs |
| CriminalIP.Full_Scan_Result.data.dns_record | object | DNS information |
| CriminalIP.Full_Scan_Result.data.frames | list(object) | Frames and transfers count |
| CriminalIP.Full_Scan_Result.data.html_page_link_domains | list(object) | Domains from HTML links |
| CriminalIP.Full_Scan_Result.data.javascript_variables | list(object) | JavaScript globals |
| CriminalIP.Full_Scan_Result.data.links | list(object) | HTML links (title, URL) |
| CriminalIP.Full_Scan_Result.data.main_certificate | object | Main certificate |
| CriminalIP.Full_Scan_Result.data.main_domain_info | object | Main domain info (with score) |
| CriminalIP.Full_Scan_Result.data.mapped_ip | list(object) | Mapped IP info |
| CriminalIP.Full_Scan_Result.data.network_logs | object | Network logs |
| CriminalIP.Full_Scan_Result.data.network_logs.abuse_record | object | Abuse summary |
| CriminalIP.Full_Scan_Result.data.network_logs.data | list(object) | Per-request logs |
| CriminalIP.Full_Scan_Result.data.page_networking_info | object | Overall page comms |
| CriminalIP.Full_Scan_Result.data.page_redirections | list(object) | Redirection history |
| CriminalIP.Full_Scan_Result.data.report_time | string | Report time |
| CriminalIP.Full_Scan_Result.data.screenshots | list(string) | Screenshot URLs |
| CriminalIP.Full_Scan_Result.data.security_headers | list(object) | Security-relevant headers |
| CriminalIP.Full_Scan_Result.data.ssl | boolean | SSL presence |
| CriminalIP.Full_Scan_Result.data.ssl_detail | object | SSL details |
| CriminalIP.Full_Scan_Result.data.subdomains | list(object) | Subdomains and scores |
| CriminalIP.Full_Scan_Result.data.technologies | list(object) | Detected technologies |
| CriminalIP.Full_Scan_Result.data.summary | object | Threat summary |
| CriminalIP.Full_Scan_Result.data.summary.abuse_record | object | Critical/Dangerous counts |
| CriminalIP.Full_Scan_Result.data.summary.associated_ip | string | Associated IPs |
| CriminalIP.Full_Scan_Result.data.summary.connecte_to_ip_directly | number | URLs using raw IP |
| CriminalIP.Full_Scan_Result.data.summary.cred_input | string | Form submission safety |
| CriminalIP.Full_Scan_Result.data.summary.dga_score | number | DGA score |
| CriminalIP.Full_Scan_Result.data.summary.diff_domain_favicon | string | Favicon domain validation |
| CriminalIP.Full_Scan_Result.data.summary.domain_in_subdomain | boolean | Domain impersonation in subdomain |
| CriminalIP.Full_Scan_Result.data.summary.double_slash_url | boolean | Contains double slashes |
| CriminalIP.Full_Scan_Result.data.summary.email_domain_check | boolean | Non-main-domain email present |
| CriminalIP.Full_Scan_Result.data.summary.fake_domain | boolean | Looks like a popular site |
| CriminalIP.Full_Scan_Result.data.summary.fake_https_url | boolean | Fake HTTPS scheme |
| CriminalIP.Full_Scan_Result.data.summary.fake_ssl | object | Certificate category (self_signed/expired/no_ssl/mismatch) |
| CriminalIP.Full_Scan_Result.data.summary.hidden_element | number | Hidden elements count |
| CriminalIP.Full_Scan_Result.data.summary.hidden_iframe | number | Hidden iframe count |
| CriminalIP.Full_Scan_Result.data.summary.html_request_url | number | External media requests to main domain |
| CriminalIP.Full_Scan_Result.data.summary.iframe | number | iframe count |
| CriminalIP.Full_Scan_Result.data.summary.js_obfuscated | number | Obfuscated JS issues |
| CriminalIP.Full_Scan_Result.data.summary.list_of_countries | list(string) | Countries observed |
| CriminalIP.Full_Scan_Result.data.summary.mail_server | boolean | Mail server present |
| CriminalIP.Full_Scan_Result.data.summary.mitm_attack | boolean | Cert covers ≥60 domains |
| CriminalIP.Full_Scan_Result.data.summary.newborn_domain | string | Domain created within 90 days |
| CriminalIP.Full_Scan_Result.data.summary.overlong_domain | boolean | Hostname length ≥30 |
| CriminalIP.Full_Scan_Result.data.summary.page_warning | boolean | "Oops/Warning" text present |
| CriminalIP.Full_Scan_Result.data.summary.phishing_record | number | Phishing/malicious domains count |
| CriminalIP.Full_Scan_Result.data.summary.punycode | boolean | Contains xn-- |
| CriminalIP.Full_Scan_Result.data.summary.real_ip | number | Real IP count |
| CriminalIP.Full_Scan_Result.data.summary.redirection_diff_asn | number | ASN changes in redirects |
| CriminalIP.Full_Scan_Result.data.summary.redirection_diff_country | number | Country changes in redirects |
| CriminalIP.Full_Scan_Result.data.summary.redirection_diff_domain | number | Domain changes in redirects |
| CriminalIP.Full_Scan_Result.data.summary.redirection_onclick | string | Onclick redirection behavior |
| CriminalIP.Full_Scan_Result.data.summary.sfh | string | Form action validity |
| CriminalIP.Full_Scan_Result.data.summary.spf1 | string | SPF1 failure on MX |
| CriminalIP.Full_Scan_Result.data.summary.suspicious_cookie | boolean | Cookie domain mismatches main |
| CriminalIP.Full_Scan_Result.data.summary.suspicious_element | number | Suspicious HTML objects |
| CriminalIP.Full_Scan_Result.data.summary.suspicious_file | number | Downloadable threats (VT) |
| CriminalIP.Full_Scan_Result.data.summary.suspicious_footer | boolean | Company info outside footer |
| CriminalIP.Full_Scan_Result.data.summary.symbol_url | boolean | Contains '@' |
| CriminalIP.Full_Scan_Result.data.summary.url_anchor | number | Suspicious anchor links |
| CriminalIP.Full_Scan_Result.data.summary.url_phishing_prob | number | ML phishing probability (0–100) |
| CriminalIP.Full_Scan_Result.data.summary.web_traffic | number | Web traffic ranking |

#### Command Example
```
!criminal-ip-domain-full-scan-result scan_id=full123scan456
```

#### Context Example
```json
{
  "CriminalIP": {
    "Full_Scan_Result": {
      "status": 200,
      "message": "Success",
      "data": {
        "classification": {
          "result": "safe"
        },
        "main_domain_info": {
          "main_domain": "example.com",
          "domain_created": "2024-01-01",
          "domain_registrar": "Example Registrar"
        },
        "certificates": [
          {
            "subject": "CN=example.com",
            "issuer": "Let's Encrypt Authority X3",
            "valid_from": "2024-01-01T00:00:00Z",
            "valid_to": "2024-12-31T23:59:59Z"
          }
        ],
        "ssl": true,
        "summary": {
          "abuse_record": {
            "critical": 0,
            "dangerous": 0,
            "moderate": 0
          },
          "associated_ip": "1",
          "fake_domain": false,
          "fake_https_url": false,
          "mail_server": true,
          "newborn_domain": "false",
          "overlong_domain": false,
          "punycode": false,
          "real_ip": 0,
          "url_phishing_prob": 0,
          "web_traffic": 500000
        }
      }
    }
  }
}
```

---

### criminal-ip-domain-full-scan-make-email-body

***
Builds an email body summarizing notable findings from a completed Full Scan.

#### Base Command
`criminal-ip-domain-full-scan-make-email-body`

#### Input
| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------|--------------|
| scan_id | scan_id of the completed Full Scan | Required |
| domain | Domain of the completed Full Scan | Required |

#### Context Output
| **Path** | **Type** | **Description** |
|----------|----------|-----------------|
| CriminalIP.Email_Body.body_element | string | Email body text |
| CriminalIP.Email_Body.domain | string | Target domain |
| CriminalIP.Email_Body.scan_id | string | Scan ID |

#### Command Example
```
!criminal-ip-domain-full-scan-make-email-body scan_id=full123scan456 domain=example.com
```

#### Context Example
```json
{
  "CriminalIP": {
    "Email_Body": {
      "body_element": "Criminal IP Full Scan Report for example.com\n\nScan completed successfully with the following findings:\n- Domain Status: Safe\n- SSL Certificate: Valid\n- No malicious activities detected\n\nFor detailed analysis, please review the full scan results.",
      "domain": "example.com",
      "scan_id": "full123scan456"
    }
  }
}
```

---

### criminal-ip-micro-asm

***
Performs a Micro ASM-style summary for a domain with a completed Full Scan.

#### Base Command
`criminal-ip-micro-asm`

#### Input
| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------|--------------|
| scan_id | scan_id of completed Full Scan | Required |
| domain | Domain of completed Full Scan | Required |

#### Context Output
| **Path** | **Type** | **Description** |
|----------|----------|-----------------|
| CriminalIP.Micro_ASM.domain | string | Target domain |
| CriminalIP.Micro_ASM.result | string | ASM summary result (may be empty if nothing notable) |
| CriminalIP.Micro_ASM.scan_id | string | Scan ID |

#### Command Example
```
!criminal-ip-micro-asm scan_id=full123scan456 domain=example.com
```

#### Context Example
```json
{
  "CriminalIP": {
    "Micro_ASM": {
      "domain": "example.com",
      "result": "No significant security issues detected. Domain appears to be properly configured with valid SSL certificate and no malicious indicators.",
      "scan_id": "full123scan456"
    }
  }
}
```