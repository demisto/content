Rapid7's on-premise vulnerability management solution, Nexpose, helps you reduce your threat exposure by enabling you to assess and respond to changes in your environment real time and prioritizing risk across vulnerabilities, configurations, and controls.
This integration was integrated and tested with version xx of Rapid7 Nexpose

## Configure Rapid7 Nexpose on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Rapid7 Nexpose.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://192.0.2.0:8080) | True |
    | Username | True |
    | Password | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | 2FA Token | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### nexpose-get-asset
***
Returns the specified asset.


#### Base Command

`nexpose-get-asset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Asset ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Asset.Addresses | unknown | All addresses discovered on the asset. | 
| Nexpose.Asset.AssetId | number | Id of the asset. | 
| Nexpose.Asset.Hardware | string | The primary Media Access Control \(MAC\) address of the asset. The format is six groups of two hexadecimal digits separated by colons. | 
| Nexpose.Asset.Aliases | unknown | All host names or aliases discovered on the asset. | 
| Nexpose.Asset.HostType | string | The type of asset, Valid values are unknown, guest, hypervisor, physical, mobile | 
| Nexpose.Asset.Site | string | Asset site name. | 
| Nexpose.Asset.OperatingSystem | string | Operating system of the asset. | 
| Nexpose.Asset.Vulnerabilities | number | The total number of vulnerabilities on the asset. | 
| Nexpose.Asset.CPE | string | The Common Platform Enumeration \(CPE\) of the operating system. | 
| Nexpose.Asset.LastScanDate | date | Last scan date of the asset. | 
| Nexpose.Asset.LastScanId | number | Id of the asset's last scan. | 
| Nexpose.Asset.RiskScore | number | The risk score \(with criticality adjustments\) of the asset. | 
| Nexpose.Asset.Software.Software | string | The description of the software. | 
| Nexpose.Asset.Software.Version | string | The version of the software. | 
| Nexpose.Asset.Services.Name | string | The name of the service. | 
| Nexpose.Asset.Services.Port | number | The port of the service. | 
| Nexpose.Asset.Services.Product | string | The product running the service. | 
| Nexpose.Asset.Services.protocol | string | The protocol of the service, valid values are ip, icmp, igmp, ggp, tcp, pup, udp, idp, esp, nd, raw | 
| Nexpose.Asset.Users.FullName | string | The full name of the user account. | 
| Nexpose.Asset.Users.Name | string | The name of the user account. | 
| Nexpose.Asset.Users.UserId | number | The identifier of the user account. | 
| Nexpose.Asset.Vulnerability.Id | number | The identifier of the vulnerability. | 
| Nexpose.Asset.Vulnerability.Instances | number | The number of vulnerable occurrences of the vulnerability. This does not include invulnerable instances. | 
| Nexpose.Asset.Vulnerability.Title | string | The title \(summary\) of the vulnerability. | 
| Nexpose.Asset.Vulnerability.Malware | number | The malware kits that are known to be used to exploit the vulnerability. | 
| Nexpose.Asset.Vulnerability.Exploit | number | The exploits that can be used to exploit a vulnerability. | 
| Nexpose.Asset.Vulnerability.CVSS | string | The CVSS exploit score. | 
| Nexpose.Asset.Vulnerability.Risk | number | The risk score of the vulnerability, rounded to a maximum of to digits of precision. If using the default Rapid7 Real Risk™ model, this value ranges from 0-1000. | 
| Nexpose.Asset.Vulnerability.PublishedOn | date | The date the vulnerability was first published or announced. The format is an ISO 8601 date, YYYY-MM-DD. | 
| Nexpose.Asset.Vulnerability.ModifiedOn | date | The last date the vulnerability was modified. The format is an ISO 8601 date, YYYY-MM-DD. | 
| Nexpose.Asset.Vulnerability.Severity | string | The severity of the vulnerability, one of: "Moderate", "Severe", "Critical". | 
| Endpoint.IP | string | Endpoint IP address. | 
| Endpoint.HostName | string | Endpoint host name. | 
| Endpoint.OS | string | Endpoint operating system. | 
| CVE.ID | string | Common Vulnerabilities and Exposures ids | 

#### Command example
```!nexpose-get-asset id=1```
#### Context Example
```json
{
    "CVE": [
        {
            "CVSS": {},
            "ID": "CVE-1999-0524"
        },
        {
            "CVSS": {},
            "ID": "CVE-2015-4000"
        },
        {
            "CVSS": {},
            "ID": "CVE-2016-2183"
        }
    ],
    "DBotScore": [
        {
            "Indicator": "CVE-1999-0524",
            "Score": 0,
            "Type": "cve",
            "Vendor": "Rapid7 Nexpose"
        },
        {
            "Indicator": "CVE-2015-4000",
            "Score": 0,
            "Type": "cve",
            "Vendor": "Rapid7 Nexpose"
        },
        {
            "Indicator": "CVE-2016-2183",
            "Score": 0,
            "Type": "cve",
            "Vendor": "Rapid7 Nexpose"
        }
    ],
    "Endpoint": {
        "ID": 1,
        "IPAddress": "192.0.2.0",
        "OS": "Linux 3.10",
        "Vendor": "Rapid7 Nexpose"
    },
    "Nexpose": {
        "Asset": {
            "Addresses": "192.0.2.0",
            "AssetId": 1,
            "Hardware": "00:0C:29:9A:D8:2C",
            "LastScanDate": "2022-11-02T14:54:19.040Z",
            "LastScanId": "-",
            "OperatingSystem": "Linux 3.10",
            "RiskScore": 1727.206298828125,
            "Service": [
                {
                    "Name": "SSH",
                    "Port": 22,
                    "Product": "OpenSSH",
                    "Protocol": "tcp",
                    "configurations": [
                        {
                            "name": "ssh.algorithms.compression",
                            "value": "none,zlib@openssh.com"
                        },
                        {
                            "name": "ssh.algorithms.encryption",
                            "value": "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-cbc,aes192-cbc,aes256-cbc,blowfish-cbc,cast128-cbc,3des-cbc"
                        },
                        {
                            "name": "ssh.algorithms.hostkey",
                            "value": "ssh-rsa,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519"
                        },
                        {
                            "name": "ssh.algorithms.kex",
                            "value": "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
                        },
                        {
                            "name": "ssh.algorithms.mac",
                            "value": "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1"
                        },
                        {
                            "name": "ssh.banner",
                            "value": "SSH-2.0-OpenSSH_7.4"
                        },
                        {
                            "name": "ssh.protocol.version",
                            "value": "2.0"
                        },
                        {
                            "name": "ssh.rsa.pubkey.fingerprint",
                            "value": "A74AFD453C6FBD15CF99481E0FFFC110"
                        }
                    ],
                    "family": "OpenSSH",
                    "vendor": "OpenBSD",
                    "version": "7.4"
                }
            ],
            "Site": "Test",
            "Software": null,
            "User": null,
            "Vulnerabilities": 7,
            "Vulnerability": [
                {
                    "CVSS": 0,
                    "Exploit": 0,
                    "Id": "generic-icmp-timestamp",
                    "Instances": 1,
                    "Malware": 0,
                    "ModifiedOn": "2019-06-11",
                    "PublishedOn": "1997-08-01",
                    "Risk": 0,
                    "Severity": "Moderate",
                    "Title": "ICMP timestamp response"
                },
                {
                    "CVSS": 0,
                    "Exploit": 0,
                    "Id": "generic-tcp-timestamp",
                    "Instances": 1,
                    "Malware": 0,
                    "ModifiedOn": "2018-03-21",
                    "PublishedOn": "1997-08-01",
                    "Risk": 0,
                    "Severity": "Moderate",
                    "Title": "TCP timestamp response"
                },
                {
                    "CVSS": 0,
                    "Exploit": 0,
                    "Id": "ssh-3des-ciphers",
                    "Instances": 1,
                    "Malware": 0,
                    "ModifiedOn": "2020-03-31",
                    "PublishedOn": "2009-02-01",
                    "Risk": 0,
                    "Severity": "Moderate",
                    "Title": "SSH Server Supports 3DES Cipher Suite"
                },
                {
                    "CVSS": 2.6,
                    "Exploit": 0,
                    "Id": "ssh-cbc-ciphers",
                    "Instances": 1,
                    "Malware": 0,
                    "ModifiedOn": "2020-03-31",
                    "PublishedOn": "2013-02-08",
                    "Risk": 521.99,
                    "Severity": "Moderate",
                    "Title": "SSH CBC vulnerability"
                },
                {
                    "CVSS": 4.3,
                    "Exploit": 0,
                    "Id": "ssh-cve-2015-4000",
                    "Instances": 1,
                    "Malware": 0,
                    "ModifiedOn": "2020-07-13",
                    "PublishedOn": "2015-05-20",
                    "Risk": 209.11,
                    "Severity": "Severe",
                    "Title": "SSH Server Supports diffie-hellman-group1-sha1"
                },
                {
                    "CVSS": 5,
                    "Exploit": 0,
                    "Id": "ssh-cve-2016-2183-sweet32",
                    "Instances": 1,
                    "Malware": 0,
                    "ModifiedOn": "2020-04-01",
                    "PublishedOn": "2016-08-24",
                    "Risk": 544.64,
                    "Severity": "Severe",
                    "Title": "SSH Birthday attacks on 64-bit block ciphers (SWEET32)"
                },
                {
                    "CVSS": 4.3,
                    "Exploit": 0,
                    "Id": "ssh-weak-kex-algorithms",
                    "Instances": 1,
                    "Malware": 0,
                    "ModifiedOn": "2020-04-07",
                    "PublishedOn": "2017-07-13",
                    "Risk": 451.47,
                    "Severity": "Severe",
                    "Title": "SSH Server Supports Weak Key Exchange Algorithms"
                }
            ],
            "addresses": [
                {}
            ],
            "assessedForPolicies": false,
            "assessedForVulnerabilities": true,
            "history": [
                {
                    "date": "2020-11-19T08:34:55.732Z",
                    "scanId": 731,
                    "type": "SCAN",
                    "version": 661
                },
                {
                    "date": "2020-11-19T11:43:22.530Z",
                    "scanId": 732,
                    "type": "SCAN",
                    "version": 662
                },
                {
                    "date": "2020-11-19T11:48:46.222Z",
                    "scanId": 733,
                    "type": "SCAN",
                    "version": 663
                },
                {
                    "date": "2020-11-19T12:23:04.991Z",
                    "scanId": 734,
                    "type": "SCAN",
                    "version": 664
                },
                {
                    "date": "2020-11-20T08:09:14.195Z",
                    "scanId": 735,
                    "type": "SCAN",
                    "version": 665
                },
                {
                    "date": "2020-11-20T08:32:31.365Z",
                    "scanId": 736,
                    "type": "SCAN",
                    "version": 666
                },
                {
                    "date": "2020-11-20T14:48:30.629Z",
                    "scanId": 737,
                    "type": "SCAN",
                    "version": 667
                },
                {
                    "date": "2020-11-21T02:12:34.451Z",
                    "scanId": 738,
                    "type": "SCAN",
                    "version": 668
                },
                {
                    "date": "2020-11-22T02:15:18.720Z",
                    "scanId": 739,
                    "type": "SCAN",
                    "version": 669
                },
                {
                    "date": "2020-11-22T07:39:56.475Z",
                    "scanId": 740,
                    "type": "SCAN",
                    "version": 670
                },
                {
                    "date": "2020-11-23T12:20:09.479Z",
                    "scanId": 741,
                    "type": "SCAN",
                    "version": 671
                },
                {
                    "date": "2020-11-23T16:08:32.817Z",
                    "scanId": 742,
                    "type": "SCAN",
                    "version": 672
                },
                {
                    "date": "2020-11-23T17:06:19.005Z",
                    "scanId": 743,
                    "type": "SCAN",
                    "version": 673
                },
                {
                    "date": "2020-11-23T18:45:55.410Z",
                    "scanId": 744,
                    "type": "SCAN",
                    "version": 674
                },
                {
                    "date": "2020-11-24T02:17:33.306Z",
                    "scanId": 745,
                    "type": "SCAN",
                    "version": 675
                },
                {
                    "date": "2020-11-24T17:51:19.010Z",
                    "scanId": 746,
                    "type": "SCAN",
                    "version": 676
                },
                {
                    "date": "2020-11-24T21:53:57.781Z",
                    "scanId": 747,
                    "type": "SCAN",
                    "version": 677
                },
                {
                    "date": "2020-11-24T22:27:52.438Z",
                    "scanId": 748,
                    "type": "SCAN",
                    "version": 678
                },
                {
                    "date": "2020-11-25T00:16:12.130Z",
                    "scanId": 749,
                    "type": "SCAN",
                    "version": 679
                },
                {
                    "date": "2020-11-25T02:19:56.655Z",
                    "scanId": 750,
                    "type": "SCAN",
                    "version": 680
                },
                {
                    "date": "2020-11-25T23:31:56.357Z",
                    "scanId": 751,
                    "type": "SCAN",
                    "version": 681
                },
                {
                    "date": "2020-11-26T02:17:08.190Z",
                    "scanId": 752,
                    "type": "SCAN",
                    "version": 682
                },
                {
                    "date": "2020-11-26T06:59:48.177Z",
                    "scanId": 753,
                    "type": "SCAN",
                    "version": 683
                },
                {
                    "date": "2020-11-26T07:53:35.544Z",
                    "scanId": 754,
                    "type": "SCAN",
                    "version": 684
                },
                {
                    "date": "2020-11-26T13:39:42.885Z",
                    "scanId": 755,
                    "type": "SCAN",
                    "version": 685
                },
                {
                    "date": "2020-11-26T13:52:54.897Z",
                    "scanId": 756,
                    "type": "SCAN",
                    "version": 686
                },
                {
                    "date": "2020-11-26T13:56:50.039Z",
                    "scanId": 757,
                    "type": "SCAN",
                    "version": 687
                },
                {
                    "date": "2020-11-26T14:01:04.104Z",
                    "scanId": 758,
                    "type": "SCAN",
                    "version": 688
                },
                {
                    "date": "2020-11-26T15:21:42.044Z",
                    "scanId": 759,
                    "type": "SCAN",
                    "version": 689
                },
                {
                    "date": "2020-11-26T17:10:55.179Z",
                    "scanId": 760,
                    "type": "SCAN",
                    "version": 690
                },
                {
                    "date": "2020-11-26T17:13:44.124Z",
                    "scanId": 761,
                    "type": "SCAN",
                    "version": 691
                },
                {
                    "date": "2022-07-10T11:51:17.874Z",
                    "description": "nxadmin",
                    "type": "VULNERABILITY_EXCEPTION_APPLIED",
                    "version": 692,
                    "vulnerabilityExceptionId": 1
                },
                {
                    "date": "2022-11-02T14:54:19.040Z",
                    "description": "nxadmin",
                    "type": "VULNERABILITY_EXCEPTION_UNAPPLIED",
                    "version": 693,
                    "vulnerabilityExceptionId": 1
                }
            ],
            "ip": "192.0.2.0",
            "mac": "00:0C:29:9A:D8:2C",
            "osFingerprint": {
                "cpe": {
                    "part": "o",
                    "product": "linux_kernel",
                    "targetHW": "arm64",
                    "v2.2": "cpe:/o:linux:linux_kernel:3.10.0::~~~~arm64~",
                    "v2.3": "cpe:2.3:o:linux:linux_kernel:3.10.0:*:*:*:*:*:arm64:*",
                    "vendor": "linux",
                    "version": "3.10.0"
                },
                "description": "Linux 3.10",
                "family": "Linux",
                "id": 6,
                "product": "Linux",
                "systemName": "Linux",
                "type": "General",
                "vendor": "Linux",
                "version": "3.10"
            },
            "rawRiskScore": 1727.206298828125,
            "services": [
                {
                    "Name": "SSH",
                    "Port": 22,
                    "Product": "OpenSSH",
                    "Protocol": "tcp",
                    "configurations": [
                        {
                            "name": "ssh.algorithms.compression",
                            "value": "none,zlib@openssh.com"
                        },
                        {
                            "name": "ssh.algorithms.encryption",
                            "value": "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-cbc,aes192-cbc,aes256-cbc,blowfish-cbc,cast128-cbc,3des-cbc"
                        },
                        {
                            "name": "ssh.algorithms.hostkey",
                            "value": "ssh-rsa,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519"
                        },
                        {
                            "name": "ssh.algorithms.kex",
                            "value": "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
                        },
                        {
                            "name": "ssh.algorithms.mac",
                            "value": "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1"
                        },
                        {
                            "name": "ssh.banner",
                            "value": "SSH-2.0-OpenSSH_7.4"
                        },
                        {
                            "name": "ssh.protocol.version",
                            "value": "2.0"
                        },
                        {
                            "name": "ssh.rsa.pubkey.fingerprint",
                            "value": "A74AFD453C6FBD15CF99481E0FFFC110"
                        }
                    ],
                    "family": "OpenSSH",
                    "vendor": "OpenBSD",
                    "version": "7.4"
                }
            ],
            "vulnerabilities": [
                {
                    "added": "2004-11-01",
                    "categories": [
                        "Network"
                    ],
                    "cves": [
                        "CVE-1999-0524"
                    ],
                    "cvss": {
                        "v2": {
                            "accessComplexity": "L",
                            "accessVector": "L",
                            "authentication": "N",
                            "availabilityImpact": "N",
                            "confidentialityImpact": "N",
                            "exploitScore": 3.9487,
                            "impactScore": 0,
                            "integrityImpact": "N",
                            "score": 0,
                            "vector": "AV:L/AC:L/Au:N/C:N/I:N/A:N"
                        }
                    },
                    "denialOfService": false,
                    "description": {
                        "html": "<p>The remote host responded to an ICMP timestamp request.  The ICMP timestamp response\n      contains the remote host&#39;s date and time.  This information could theoretically be\n      used against some systems to exploit weak time-based random number generators in\n      other services.</p>\n    \n\n<p>In addition, the versions of some operating systems can be accurately fingerprinted\n      by analyzing their responses to invalid ICMP timestamp requests.</p>",
                        "text": "The remote host responded to an ICMP timestamp request. The ICMP timestamp response contains the remote host's date and time. This information could theoretically be used against some systems to exploit weak time-based random number generators in other services.\n\nIn addition, the versions of some operating systems can be accurately fingerprinted by analyzing their responses to invalid ICMP timestamp requests."
                    },
                    "exploits": 0,
                    "id": "generic-icmp-timestamp",
                    "instances": 1,
                    "malwareKits": 0,
                    "modified": "2019-06-11",
                    "pci": {
                        "adjustedCVSSScore": 0,
                        "adjustedSeverityScore": 1,
                        "fail": false,
                        "status": "Pass"
                    },
                    "published": "1997-08-01",
                    "results": [
                        {
                            "proof": "<p><p>Able to determine remote system time.</p></p>",
                            "since": "2020-04-20T13:56:34.818Z",
                            "status": "vulnerable"
                        }
                    ],
                    "riskScore": 0,
                    "severity": "Moderate",
                    "severityScore": 1,
                    "since": "2020-04-20T13:56:34.818Z",
                    "status": "vulnerable",
                    "title": "ICMP timestamp response"
                },
                {
                    "added": "2011-04-01",
                    "categories": [
                        "Network"
                    ],
                    "cvss": {
                        "v2": {
                            "accessComplexity": "L",
                            "accessVector": "N",
                            "authentication": "N",
                            "availabilityImpact": "N",
                            "confidentialityImpact": "N",
                            "exploitScore": 9.9968,
                            "impactScore": 0,
                            "integrityImpact": "N",
                            "score": 0,
                            "vector": "AV:N/AC:L/Au:N/C:N/I:N/A:N"
                        }
                    },
                    "denialOfService": false,
                    "description": {
                        "html": "<p>\n      The remote host responded with a TCP timestamp.  The TCP timestamp response\n      can be used to approximate the remote host&#39;s uptime, potentially aiding in\n      further attacks.  Additionally, some operating systems can be fingerprinted\n      based on the behavior of their TCP timestamps.\n    </p>",
                        "text": "The remote host responded with a TCP timestamp. The TCP timestamp response can be used to approximate the remote host's uptime, potentially aiding in further attacks. Additionally, some operating systems can be fingerprinted based on the behavior of their TCP timestamps."
                    },
                    "exploits": 0,
                    "id": "generic-tcp-timestamp",
                    "instances": 1,
                    "malwareKits": 0,
                    "modified": "2018-03-21",
                    "pci": {
                        "adjustedCVSSScore": 0,
                        "adjustedSeverityScore": 1,
                        "fail": false,
                        "status": "Pass"
                    },
                    "published": "1997-08-01",
                    "results": [
                        {
                            "proof": "<p><p>Able to determine system boot time.</p></p>",
                            "since": "2020-05-03T08:11:38.006Z",
                            "status": "vulnerable"
                        }
                    ],
                    "riskScore": 0,
                    "severity": "Moderate",
                    "severityScore": 1,
                    "since": "2020-05-03T08:11:38.006Z",
                    "status": "vulnerable",
                    "title": "TCP timestamp response"
                },
                {
                    "added": "2020-03-31",
                    "categories": [
                        "Network",
                        "SSH"
                    ],
                    "cvss": {
                        "v2": {
                            "accessComplexity": "H",
                            "accessVector": "N",
                            "authentication": "N",
                            "availabilityImpact": "N",
                            "confidentialityImpact": "N",
                            "exploitScore": 4.928,
                            "impactScore": 0,
                            "integrityImpact": "N",
                            "score": 0,
                            "vector": "AV:N/AC:H/Au:N/C:N/I:N/A:N"
                        }
                    },
                    "denialOfService": false,
                    "description": {
                        "html": "<p>\n      Since 3DES (Triple Data Encryption Standard) only provides an effective security of 112 bits, it is considered close to end of life by some agencies.\n      ECRYPT II (from 2012) recommends for generic application independent long-term protection of at least 128 bits security. The same recommendation has also been reported by BSI Germany (from 2015) and ANSSI France (from 2014), 128 bit is the recommended symmetric size and should be mandatory after 2020. While NIST (from 2012) still considers 3DES being appropriate to use until the end of 2030.\n    </p>",
                        "text": "Since 3DES (Triple Data Encryption Standard) only provides an effective security of 112 bits, it is considered close to end of life by some agencies. ECRYPT II (from 2012) recommends for generic application independent long-term protection of at least 128 bits security. The same recommendation has also been reported by BSI Germany (from 2015) and ANSSI France (from 2014), 128 bit is the recommended symmetric size and should be mandatory after 2020. While NIST (from 2012) still considers 3DES being appropriate to use until the end of 2030."
                    },
                    "exploits": 0,
                    "id": "ssh-3des-ciphers",
                    "instances": 1,
                    "malwareKits": 0,
                    "modified": "2020-03-31",
                    "pci": {
                        "adjustedCVSSScore": 0,
                        "adjustedSeverityScore": 1,
                        "fail": false,
                        "status": "Pass"
                    },
                    "published": "2009-02-01",
                    "results": [
                        {
                            "port": 22,
                            "proof": "<p><ul><li>Running SSH service</li><li>Insecure 3DES ciphers in use: 3des-cbc</li></ul></p>",
                            "protocol": "tcp",
                            "since": "2020-04-20T13:56:34.818Z",
                            "status": "vulnerable-version"
                        }
                    ],
                    "riskScore": 0,
                    "severity": "Moderate",
                    "severityScore": 1,
                    "since": "2020-04-20T13:56:34.818Z",
                    "status": "vulnerable",
                    "title": "SSH Server Supports 3DES Cipher Suite"
                },
                {
                    "added": "2020-03-31",
                    "categories": [
                        "Network",
                        "SSH"
                    ],
                    "cvss": {
                        "v2": {
                            "accessComplexity": "H",
                            "accessVector": "N",
                            "authentication": "N",
                            "availabilityImpact": "N",
                            "confidentialityImpact": "P",
                            "exploitScore": 4.928,
                            "impactScore": 2.8627,
                            "integrityImpact": "N",
                            "score": 2.6,
                            "vector": "AV:N/AC:H/Au:N/C:P/I:N/A:N"
                        }
                    },
                    "denialOfService": false,
                    "description": {
                        "html": "<p>\n        SSH contains a vulnerability in the way certain types of errors are handled. Attacks leveraging this vulnerabilty would lead to the loss of the SSH session. According to CPNI Vulnerability Advisory SSH:\n    </p>\n    \n<p>\n        If exploited, this attack can potentially allow an attacker to recover up to 32 bits of plaintext from an arbitrary block of \n        ciphertext from a connection secured using the SSH protocol in the standard configuration. If OpenSSH is used in the standard \n        configuration, then the attacker&#39;s success probability for recovering 32 bits of plaintext is 2^{-18}. A variant of the attack \n        against OpenSSH in the standard configuration can verifiably recover 14 bits of plaintext with probability 2^{-14}. The success \n        probability of the attack for other implementations of SSH is not known.\n    </p>",
                        "text": "SSH contains a vulnerability in the way certain types of errors are handled. Attacks leveraging this vulnerabilty would lead to the loss of the SSH session. According to CPNI Vulnerability Advisory SSH: \n\n If exploited, this attack can potentially allow an attacker to recover up to 32 bits of plaintext from an arbitrary block of ciphertext from a connection secured using the SSH protocol in the standard configuration. If OpenSSH is used in the standard  configuration, then the attacker's success probability for recovering 32 bits of plaintext is 2^{-18}. A variant of the attack against OpenSSH in the standard configuration can verifiably recover 14 bits of plaintext with probability 2^{-14}. The success  probability of the attack for other implementations of SSH is not known."
                    },
                    "exploits": 0,
                    "id": "ssh-cbc-ciphers",
                    "instances": 1,
                    "malwareKits": 0,
                    "modified": "2020-03-31",
                    "pci": {
                        "adjustedCVSSScore": 2,
                        "adjustedSeverityScore": 2,
                        "fail": false,
                        "status": "Pass"
                    },
                    "published": "2013-02-08",
                    "results": [
                        {
                            "port": 22,
                            "proof": "<p><ul><li>Running SSH service</li><li>Insecure CBC ciphers in use: aes128-cbc,aes192-cbc,aes256-cbc,blowfish-cbc,cast128-cbc,3des-cbc</li></ul></p>",
                            "protocol": "tcp",
                            "since": "2020-04-20T13:56:34.818Z",
                            "status": "vulnerable-version"
                        }
                    ],
                    "riskScore": 521.99,
                    "severity": "Moderate",
                    "severityScore": 3,
                    "since": "2020-04-20T13:56:34.818Z",
                    "status": "vulnerable",
                    "title": "SSH CBC vulnerability"
                },
                {
                    "added": "2020-03-31",
                    "categories": [
                        "Network",
                        "SSH"
                    ],
                    "cves": [
                        "CVE-2015-4000"
                    ],
                    "cvss": {
                        "v2": {
                            "accessComplexity": "M",
                            "accessVector": "N",
                            "authentication": "N",
                            "availabilityImpact": "N",
                            "confidentialityImpact": "N",
                            "exploitScore": 8.5888,
                            "impactScore": 2.8627,
                            "integrityImpact": "P",
                            "score": 4.3,
                            "vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N"
                        },
                        "v3": {
                            "attackComplexity": "H",
                            "attackVector": "N",
                            "availabilityImpact": "N",
                            "confidentialityImpact": "N",
                            "exploitScore": 2.2212,
                            "impactScore": 1.4124,
                            "integrityImpact": "L",
                            "privilegeRequired": "N",
                            "scope": "U",
                            "score": 3.7,
                            "userInteraction": "N",
                            "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"
                        }
                    },
                    "denialOfService": false,
                    "description": {
                        "html": "<p>\n      The prime modulus offered when diffie-hellman-group1-sha1 is used only has a size of 1024 bits. This\n      size is considered weak and within theoretical range of the so-called Logjam attack.\n    </p>",
                        "text": "The prime modulus offered when diffie-hellman-group1-sha1 is used only has a size of 1024 bits. This size is considered weak and within theoretical range of the so-called Logjam attack."
                    },
                    "exploits": 0,
                    "id": "ssh-cve-2015-4000",
                    "instances": 1,
                    "malwareKits": 0,
                    "modified": "2020-07-13",
                    "pci": {
                        "adjustedCVSSScore": 4,
                        "adjustedSeverityScore": 3,
                        "fail": true,
                        "status": "Fail"
                    },
                    "published": "2015-05-20",
                    "results": [
                        {
                            "port": 22,
                            "proof": "<p><ul><li>Running SSH service</li><li>Insecure key exchange in use: diffie-hellman-group1-sha1</li></ul></p>",
                            "protocol": "tcp",
                            "since": "2020-04-20T13:56:34.818Z",
                            "status": "vulnerable-version"
                        }
                    ],
                    "riskScore": 209.11,
                    "severity": "Severe",
                    "severityScore": 4,
                    "since": "2020-04-20T13:56:34.818Z",
                    "status": "vulnerable",
                    "title": "SSH Server Supports diffie-hellman-group1-sha1"
                },
                {
                    "added": "2020-03-31",
                    "categories": [
                        "Network",
                        "SSH"
                    ],
                    "cves": [
                        "CVE-2016-2183"
                    ],
                    "cvss": {
                        "v2": {
                            "accessComplexity": "L",
                            "accessVector": "N",
                            "authentication": "N",
                            "availabilityImpact": "N",
                            "confidentialityImpact": "P",
                            "exploitScore": 9.9968,
                            "impactScore": 2.8627,
                            "integrityImpact": "N",
                            "score": 5,
                            "vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N"
                        },
                        "v3": {
                            "attackComplexity": "L",
                            "attackVector": "N",
                            "availabilityImpact": "N",
                            "confidentialityImpact": "H",
                            "exploitScore": 3.887,
                            "impactScore": 3.5952,
                            "integrityImpact": "N",
                            "privilegeRequired": "N",
                            "scope": "U",
                            "score": 7.5,
                            "userInteraction": "N",
                            "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                        }
                    },
                    "denialOfService": false,
                    "description": {
                        "html": "<p>\n      Legacy block ciphers having a block size of 64 bits are vulnerable to a practical collision attack when used in CBC\n      mode. The security of a block cipher is often reduced to the key size k: the best attack should\n      be the exhaustive search of the key, with complexity 2 to the power of k. However, the block size n is also an\n      important security parameter, defining the amount of data that can be encrypted under the same key. This is\n      particularly important when using common modes of operation: we require block ciphers to be secure with up to 2 to\n      the power of n queries, but most modes of operation (e.g. CBC, CTR, GCM, OCB, etc.) are unsafe with more than 2\n      to the power of half n blocks of message (the birthday bound). With a modern block cipher with 128-bit blocks such\n      as AES, the birthday bound corresponds to 256 exabytes. However, for a block cipher with 64-bit blocks, the birthday\n      bound corresponds to only 32 GB, which is easily reached in practice. Once a collision between two cipher blocks\n      occurs it is possible to use the collision to extract the plain text data.\n    </p>",
                        "text": "Legacy block ciphers having a block size of 64 bits are vulnerable to a practical collision attack when used in CBC mode. The security of a block cipher is often reduced to the key size k: the best attack should be the exhaustive search of the key, with complexity 2 to the power of k. However, the block size n is also an important security parameter, defining the amount of data that can be encrypted under the same key. This is particularly important when using common modes of operation: we require block ciphers to be secure with up to 2 to the power of n queries, but most modes of operation (e.g. CBC, CTR, GCM, OCB, etc.) are unsafe with more than 2 to the power of half n blocks of message (the birthday bound). With a modern block cipher with 128-bit blocks such as AES, the birthday bound corresponds to 256 exabytes. However, for a block cipher with 64-bit blocks, the birthday bound corresponds to only 32 GB, which is easily reached in practice. Once a collision between two cipher blocks occurs it is possible to use the collision to extract the plain text data."
                    },
                    "exploits": 0,
                    "id": "ssh-cve-2016-2183-sweet32",
                    "instances": 1,
                    "malwareKits": 0,
                    "modified": "2020-04-01",
                    "pci": {
                        "adjustedCVSSScore": 5,
                        "adjustedSeverityScore": 3,
                        "fail": true,
                        "status": "Fail"
                    },
                    "published": "2016-08-24",
                    "results": [
                        {
                            "port": 22,
                            "proof": "<p><ul><li>Running SSH service</li><li>Insecure 3DES ciphers in use: 3des-cbc</li></ul></p>",
                            "protocol": "tcp",
                            "since": "2020-04-20T13:56:34.818Z",
                            "status": "vulnerable-version"
                        }
                    ],
                    "riskScore": 544.64,
                    "severity": "Severe",
                    "severityScore": 5,
                    "since": "2020-04-20T13:56:34.818Z",
                    "status": "vulnerable",
                    "title": "SSH Birthday attacks on 64-bit block ciphers (SWEET32)"
                },
                {
                    "added": "2020-03-31",
                    "categories": [
                        "Network",
                        "SSH"
                    ],
                    "cvss": {
                        "v2": {
                            "accessComplexity": "M",
                            "accessVector": "N",
                            "authentication": "N",
                            "availabilityImpact": "N",
                            "confidentialityImpact": "P",
                            "exploitScore": 8.5888,
                            "impactScore": 2.8627,
                            "integrityImpact": "N",
                            "score": 4.3,
                            "vector": "AV:N/AC:M/Au:N/C:P/I:N/A:N"
                        }
                    },
                    "denialOfService": false,
                    "description": {
                        "html": "<p>\n      The server supports one or more weak key exchange algorithms. It is highly adviseable to remove weak key exchange algorithm support from SSH configuration files on hosts to prevent them from being used to establish connections.\n    </p>",
                        "text": "The server supports one or more weak key exchange algorithms. It is highly adviseable to remove weak key exchange algorithm support from SSH configuration files on hosts to prevent them from being used to establish connections."
                    },
                    "exploits": 0,
                    "id": "ssh-weak-kex-algorithms",
                    "instances": 1,
                    "malwareKits": 0,
                    "modified": "2020-04-07",
                    "pci": {
                        "adjustedCVSSScore": 4,
                        "adjustedSeverityScore": 3,
                        "fail": true,
                        "status": "Fail"
                    },
                    "published": "2017-07-13",
                    "results": [
                        {
                            "port": 22,
                            "proof": "<p><ul><li>Running SSH service</li><li>Insecure key exchange algorithms in use: diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1</li></ul></p>",
                            "protocol": "tcp",
                            "since": "2020-04-20T13:56:34.818Z",
                            "status": "vulnerable-version"
                        }
                    ],
                    "riskScore": 451.47,
                    "severity": "Severe",
                    "severityScore": 4,
                    "since": "2020-04-20T13:56:34.818Z",
                    "status": "vulnerable",
                    "title": "SSH Server Supports Weak Key Exchange Algorithms"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Nexpose Asset 1
>| AssetId |Addresses|Hardware|Site|OperatingSystem|LastScanDate|LastScanId|RiskScore|
---------|---|---|---|---|---|---|---|---|
>| 1 | 192.0.2.0 | 00:0C:29:9A:D8:2C | Test | Linux 3.10 | 2022-11-02T14:54:19.040Z | - | 1727.206298828125 |
>### Vulnerabilities
>|Id|Title|Malware|Exploit|CVSS|Risk|PublishedOn|ModifiedOn|Severity|Instances|
>|---|---|---|---|---|---|---|---|---|---|
>| generic-icmp-timestamp | ICMP timestamp response | 0 | 0 | 0.0 | 0.0 | 1997-08-01 | 2019-06-11 | Moderate | 1 |
>| generic-tcp-timestamp | TCP timestamp response | 0 | 0 | 0.0 | 0.0 | 1997-08-01 | 2018-03-21 | Moderate | 1 |
>| ssh-3des-ciphers | SSH Server Supports 3DES Cipher Suite | 0 | 0 | 0.0 | 0.0 | 2009-02-01 | 2020-03-31 | Moderate | 1 |
>| ssh-cbc-ciphers | SSH CBC vulnerability | 0 | 0 | 2.6 | 521.99 | 2013-02-08 | 2020-03-31 | Moderate | 1 |
>| ssh-cve-2015-4000 | SSH Server Supports diffie-hellman-group1-sha1 | 0 | 0 | 4.3 | 209.11 | 2015-05-20 | 2020-07-13 | Severe | 1 |
>| ssh-cve-2016-2183-sweet32 | SSH Birthday attacks on 64-bit block ciphers (SWEET32) | 0 | 0 | 5.0 | 544.64 | 2016-08-24 | 2020-04-01 | Severe | 1 |
>| ssh-weak-kex-algorithms | SSH Server Supports Weak Key Exchange Algorithms | 0 | 0 | 4.3 | 451.47 | 2017-07-13 | 2020-04-07 | Severe | 1 |
>### Services
>|Name|Port|Product|Protocol|
>|---|---|---|---|
>| SSH | 22 | OpenSSH | tcp |


### nexpose-get-assets
***
Returns all assets for which you have access.


#### Base Command

`nexpose-get-assets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | Number of records to retrieve in each API call when pagination is used. | Optional | 
| page | A specific page to retrieve when pagination is used. | Optional | 
| sort | Criteria to sort the records by, in the format: property[,ASC\|DESC]. If not specified, default sort order is ascending. Multiple sort criteria can be specified, separated by a ';'. For example: 'riskScore,DESC;hostName,ASC'. | Optional | 
| limit | A number of records to limit the response to. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Asset.AssetId | number | The identifier of the asset. | 
| Nexpose.Asset.Address | string | The primary IPv4 or IPv6 address of the asset. | 
| Nexpose.Asset.Name | string | The primary host name \(local or FQDN\) of the asset. | 
| Nexpose.Asset.Site | string | Asset site name. | 
| Nexpose.Asset.Exploits | number | The number of distinct exploits that can exploit any of the vulnerabilities on the asset. | 
| Nexpose.Asset.Malware | number | The number of distinct malware kits that vulnerabilities on the asset are susceptible to. | 
| Nexpose.Asset.OperatingSystem | string | Operating system of the asset. | 
| Nexpose.Asset.Vulnerabilities | number | The total number of vulnerabilities. | 
| Nexpose.Asset.RiskScore | number | The risk score \(with criticality adjustments\) of the asset. | 
| Nexpose.Asset.Assessed | boolean | Whether the asset has been assessed for vulnerabilities at least once. | 
| Nexpose.Asset.LastScanDate | date | Last scan date of the asset. | 
| Nexpose.Asset.LastScanId | number | Id of the asset's last scan. | 
| Endpoint.IP | string | Endpoint IP address. | 
| Endpoint.HostName | string | Endpoint host name. | 
| Endpoint.OS | string | Endpoint operating system. | 

#### Command example
```!nexpose-get-assets limit=3```
#### Context Example
```json
{
    "Endpoint": [
        {
            "ID": 2,
            "IPAddress": "192.0.2.0",
            "OS": "Linux 3.10",
            "Vendor": "Rapid7 Nexpose"
        },
        {
            "ID": 3,
            "IPAddress": "192.0.2.0",
            "Vendor": "Rapid7 Nexpose"
        },
        {
            "ID": 4,
            "IPAddress": "192.0.2.0",
            "Vendor": "Rapid7 Nexpose"
        }
    ],
    "Nexpose": {
        "Asset": [
            {
                "Address": "192.0.2.0",
                "Assessed": true,
                "AssetId": 2,
                "Exploits": 0,
                "LastScanDate": "2022-11-02T14:54:19.040Z",
                "LastScanId": "-",
                "Malware": 0,
                "OperatingSystem": "Linux 3.10",
                "RiskScore": 1727.206298828125,
                "Site": "Test",
                "Vulnerabilities": 7,
                "addresses": [
                    {
                        "ip": "192.0.2.0",
                        "mac": "00:0C:29:9A:D8:2C"
                    }
                ],
                "assessedForPolicies": false,
                "history": [
                    {
                        "date": "2020-11-26T06:59:48.177Z",
                        "scanId": 753,
                        "type": "SCAN",
                        "version": 683
                    },
                    {
                        "date": "2020-11-26T07:53:35.544Z",
                        "scanId": 754,
                        "type": "SCAN",
                        "version": 684
                    },
                    {
                        "date": "2020-11-26T13:39:42.885Z",
                        "scanId": 755,
                        "type": "SCAN",
                        "version": 685
                    },
                    {
                        "date": "2020-11-26T13:52:54.897Z",
                        "scanId": 756,
                        "type": "SCAN",
                        "version": 686
                    },
                    {
                        "date": "2020-11-26T13:56:50.039Z",
                        "scanId": 757,
                        "type": "SCAN",
                        "version": 687
                    },
                    {
                        "date": "2020-11-26T14:01:04.104Z",
                        "scanId": 758,
                        "type": "SCAN",
                        "version": 688
                    },
                    {
                        "date": "2020-11-26T15:21:42.044Z",
                        "scanId": 759,
                        "type": "SCAN",
                        "version": 689
                    },
                    {
                        "date": "2020-11-26T17:10:55.179Z",
                        "scanId": 760,
                        "type": "SCAN",
                        "version": 690
                    },
                    {
                        "date": "2020-11-26T17:13:44.124Z",
                        "scanId": 761,
                        "type": "SCAN",
                        "version": 691
                    },
                    {
                        "date": "2022-07-10T11:51:17.874Z",
                        "description": "nxadmin",
                        "type": "VULNERABILITY_EXCEPTION_APPLIED",
                        "version": 692,
                        "vulnerabilityExceptionId": 1
                    },
                    {
                        "date": "2022-11-02T14:54:19.040Z",
                        "description": "nxadmin",
                        "type": "VULNERABILITY_EXCEPTION_UNAPPLIED",
                        "version": 693,
                        "vulnerabilityExceptionId": 1
                    }
                ],
                "mac": "00:0C:29:9A:D8:2C",
                "osFingerprint": {
                    "cpe": {
                        "part": "o",
                        "product": "linux_kernel",
                        "targetHW": "arm64",
                        "v2.2": "cpe:/o:linux:linux_kernel:3.10.0::~~~~arm64~",
                        "v2.3": "cpe:2.3:o:linux:linux_kernel:3.10.0:*:*:*:*:*:arm64:*",
                        "vendor": "linux",
                        "version": "3.10.0"
                    },
                    "description": "Linux 3.10",
                    "family": "Linux",
                    "id": 6,
                    "product": "Linux",
                    "systemName": "Linux",
                    "type": "General",
                    "vendor": "Linux",
                    "version": "3.10"
                },
                "rawRiskScore": 1727.206298828125,
                "services": [
                    {
                        "configurations": [
                            {
                                "name": "ssh.algorithms.compression",
                                "value": "none,zlib@openssh.com"
                            },
                            {
                                "name": "ssh.algorithms.encryption",
                                "value": "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-cbc,aes192-cbc,aes256-cbc,blowfish-cbc,cast128-cbc,3des-cbc"
                            },
                            {
                                "name": "ssh.algorithms.hostkey",
                                "value": "ssh-rsa,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519"
                            },
                            {
                                "name": "ssh.algorithms.kex",
                                "value": "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
                            },
                            {
                                "name": "ssh.algorithms.mac",
                                "value": "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1"
                            },
                            {
                                "name": "ssh.banner",
                                "value": "SSH-2.0-OpenSSH_7.4"
                            },
                            {
                                "name": "ssh.protocol.version",
                                "value": "2.0"
                            },
                            {
                                "name": "ssh.rsa.pubkey.fingerprint",
                                "value": "A74AFD453C6FBD15CF99481E0FFFC110"
                            }
                        ],
                        "family": "OpenSSH",
                        "name": "SSH",
                        "port": 22,
                        "product": "OpenSSH",
                        "protocol": "tcp",
                        "vendor": "OpenBSD",
                        "version": "7.4"
                    }
                ],
                "vulnerabilities": {
                    "critical": 0,
                    "moderate": 4,
                    "severe": 3
                }
            },
            {
                "Address": "192.0.2.0",
                "Assessed": true,
                "AssetId": 3,
                "Exploits": 0,
                "LastScanDate": "2020-07-27T12:40:34.550Z",
                "LastScanId": 402,
                "Malware": 0,
                "RiskScore": 0,
                "Site": "Test",
                "Vulnerabilities": 0,
                "addresses": [
                    {
                        "ip": "192.0.2.0"
                    }
                ],
                "assessedForPolicies": false,
                "history": [
                    {
                        "date": "2020-07-26T09:54:20.099Z",
                        "scanId": 400,
                        "type": "SCAN",
                        "version": 1
                    },
                    {
                        "date": "2020-07-27T12:40:34.550Z",
                        "scanId": 402,
                        "type": "SCAN",
                        "version": 2
                    }
                ],
                "rawRiskScore": 0,
                "vulnerabilities": {
                    "critical": 0,
                    "moderate": 0,
                    "severe": 0
                }
            },
            {
                "Address": "192.0.2.0",
                "Assessed": false,
                "AssetId": 4,
                "Exploits": 0,
                "LastScanDate": "2020-07-29T11:11:57.552Z",
                "LastScanId": "-",
                "Malware": 0,
                "RiskScore": 0,
                "Vulnerabilities": 0,
                "addresses": [
                    {
                        "ip": "192.0.2.0"
                    }
                ],
                "assessedForPolicies": false,
                "history": [
                    {
                        "date": "2020-07-29T11:11:57.552Z",
                        "description": "nxadmin",
                        "type": "ASSET-IMPORT",
                        "user": "nxadmin",
                        "version": 1
                    }
                ],
                "rawRiskScore": 0,
                "vulnerabilities": {
                    "critical": 0,
                    "moderate": 0,
                    "severe": 0
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Nexpose Asset
>|AssetId|Address|Exploits|Malware|Vulnerabilities|RiskScore|Assessed|LastScanDate|LastScanId|
>|---|---|---|---|---|---|---|---|---|
>| 4 | 192.0.2.0 | 0 | 0 | 0 | 0.0 | false | 2020-07-29T11:11:57.552Z | - |


### nexpose-search-assets
***
Search all assets matching filters (with Returns all assets for which you have access that match the given search criteria.


#### Base Command

`nexpose-search-assets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Queries to use as a filter, according to the Search Criteria API standard. Multiple queries can be specified, separated by a ';' separator. For example: 'ip-address in-range 192.0.2.0,192.0.2.0;host-name is myhost'. For more information regarding Search Criteria, refer to https://help.rapid7.com/insightvm/en-us/api/index.html#section/Overview/Responses. | Optional | 
| page_size | Number of records to retrieve in each API call when pagination is used. | Optional | 
| page | A specific page to retrieve when pagination is used. | Optional | 
| limit | A number of records to limit the response to. Default is 10. | Optional | 
| sort | Criteria to sort the records by, in the format: property[,ASC\|DESC]. If not specified, default sort order is ascending. Multiple sort criteria can be specified, separated by a ';' separator. For example: 'riskScore,DESC;hostName,ASC'. | Optional | 
| ipAddressIs | A specific IP address to search. | Optional | 
| hostNameIs | A specific host name to search. | Optional | 
| riskScoreHigherThan | A minimum risk score to use as a filter. | Optional | 
| vulnerabilityTitleContains | A string to search for in vulnerabilities titles. | Optional | 
| siteIdIn | Site IDs to filter for. Can be a comma-separated list. | Optional | 
| siteNameIn | Site names to filter for. Can be a comma-separated list. | Optional | 
| match | Operator to determine how to match filters. "all" requires that all filters match for an asset to be included. "any" requires only one filter to match for an asset to be included. Possible values are: all, any. Default is all. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Asset.AssetId | number | The identifier of the asset. | 
| Nexpose.Asset.Address | string | The primary IPv4 or IPv6 address of the asset. | 
| Nexpose.Asset.Name | string | The primary host name \(local or FQDN\) of the asset. | 
| Nexpose.Asset.Site | string | Asset site name. | 
| Nexpose.Asset.Exploits | number | The number of distinct exploits that can exploit any of the vulnerabilities on the asset. | 
| Nexpose.Asset.Malware | number | The number of distinct malware kits that vulnerabilities on the asset are susceptible to. | 
| Nexpose.Asset.OperatingSystem | string | Operating system of the asset. | 
| Nexpose.Asset.Vulnerabilities | number | The total number of vulnerabilities. | 
| Nexpose.Asset.RiskScore | number | The risk score \(with criticality adjustments\) of the asset. | 
| Nexpose.Asset.Assessed | boolean | Whether the asset has been assessed for vulnerabilities at least once. | 
| Nexpose.Asset.LastScanDate | date | Last scan date of the asset. | 
| Nexpose.Asset.LastScanId | number | Id of the asset's last scan. | 
| Endpoint.IP | string | Endpoint IP address. | 
| Endpoint.HostName | string | Endpoint host name. | 
| Endpoint.OS | string | Endpoint operating system. | 

#### Command example
```!nexpose-search-assets match=all riskScoreHigherThan=1000 limit=3```
#### Context Example
```json
{
    "Endpoint": [
        {
            "ID": 2,
            "IPAddress": "192.0.2.0",
            "OS": "Linux 3.10",
            "Vendor": "Rapid7 Nexpose"
        },
        {
            "Hostname": "angular.testsparker.com",
            "ID": 11,
            "IPAddress": "192.0.2.0",
            "OS": "Ubuntu Linux",
            "Vendor": "Rapid7 Nexpose"
        },
        {
            "ID": 12,
            "IPAddress": "192.0.2.0",
            "OS": "Microsoft Windows",
            "Vendor": "Rapid7 Nexpose"
        }
    ],
    "Nexpose": {
        "Asset": [
            {
                "Address": "192.0.2.0",
                "Assessed": true,
                "AssetId": 2,
                "Exploits": 0,
                "LastScanDate": "2022-11-02T14:54:19.040Z",
                "LastScanId": "-",
                "Malware": 0,
                "OperatingSystem": "Linux 3.10",
                "RiskScore": 1727.206298828125,
                "Site": "Test",
                "Vulnerabilities": 7,
                "addresses": [
                    {
                        "ip": "192.0.2.0",
                        "mac": "00:0C:29:9A:D8:2C"
                    }
                ],
                "assessedForPolicies": false,
                "history": [
                    {
                        "date": "2020-11-24T02:17:33.306Z",
                        "scanId": 745,
                        "type": "SCAN",
                        "version": 675
                    },
                    {
                        "date": "2020-11-24T17:51:19.010Z",
                        "scanId": 746,
                        "type": "SCAN",
                        "version": 676
                    },
                    {
                        "date": "2020-11-24T21:53:57.781Z",
                        "scanId": 747,
                        "type": "SCAN",
                        "version": 677
                    },
                    {
                        "date": "2020-11-24T22:27:52.438Z",
                        "scanId": 748,
                        "type": "SCAN",
                        "version": 678
                    },
                    {
                        "date": "2020-11-25T00:16:12.130Z",
                        "scanId": 749,
                        "type": "SCAN",
                        "version": 679
                    },
                    {
                        "date": "2020-11-25T02:19:56.655Z",
                        "scanId": 750,
                        "type": "SCAN",
                        "version": 680
                    },
                    {
                        "date": "2020-11-25T23:31:56.357Z",
                        "scanId": 751,
                        "type": "SCAN",
                        "version": 681
                    },
                    {
                        "date": "2020-11-26T02:17:08.190Z",
                        "scanId": 752,
                        "type": "SCAN",
                        "version": 682
                    },
                    {
                        "date": "2020-11-26T06:59:48.177Z",
                        "scanId": 753,
                        "type": "SCAN",
                        "version": 683
                    },
                    {
                        "date": "2020-11-26T07:53:35.544Z",
                        "scanId": 754,
                        "type": "SCAN",
                        "version": 684
                    },
                    {
                        "date": "2020-11-26T13:39:42.885Z",
                        "scanId": 755,
                        "type": "SCAN",
                        "version": 685
                    },
                    {
                        "date": "2020-11-26T13:52:54.897Z",
                        "scanId": 756,
                        "type": "SCAN",
                        "version": 686
                    },
                    {
                        "date": "2020-11-26T13:56:50.039Z",
                        "scanId": 757,
                        "type": "SCAN",
                        "version": 687
                    },
                    {
                        "date": "2020-11-26T14:01:04.104Z",
                        "scanId": 758,
                        "type": "SCAN",
                        "version": 688
                    },
                    {
                        "date": "2020-11-26T15:21:42.044Z",
                        "scanId": 759,
                        "type": "SCAN",
                        "version": 689
                    },
                    {
                        "date": "2020-11-26T17:10:55.179Z",
                        "scanId": 760,
                        "type": "SCAN",
                        "version": 690
                    },
                    {
                        "date": "2020-11-26T17:13:44.124Z",
                        "scanId": 761,
                        "type": "SCAN",
                        "version": 691
                    },
                    {
                        "date": "2022-07-10T11:51:17.874Z",
                        "description": "nxadmin",
                        "type": "VULNERABILITY_EXCEPTION_APPLIED",
                        "version": 692,
                        "vulnerabilityExceptionId": 1
                    },
                    {
                        "date": "2022-11-02T14:54:19.040Z",
                        "description": "nxadmin",
                        "type": "VULNERABILITY_EXCEPTION_UNAPPLIED",
                        "version": 693,
                        "vulnerabilityExceptionId": 1
                    }
                ],
                "mac": "00:0C:29:9A:D8:2C",
                "osFingerprint": {
                    "cpe": {
                        "part": "o",
                        "product": "linux_kernel",
                        "targetHW": "arm64",
                        "v2.2": "cpe:/o:linux:linux_kernel:3.10.0::~~~~arm64~",
                        "v2.3": "cpe:2.3:o:linux:linux_kernel:3.10.0:*:*:*:*:*:arm64:*",
                        "vendor": "linux",
                        "version": "3.10.0"
                    },
                    "description": "Linux 3.10",
                    "family": "Linux",
                    "id": 6,
                    "product": "Linux",
                    "systemName": "Linux",
                    "type": "General",
                    "vendor": "Linux",
                    "version": "3.10"
                },
                "rawRiskScore": 1727.206298828125,
                "services": [
                    {
                        "configurations": [
                            {
                                "name": "ssh.algorithms.compression",
                                "value": "none,zlib@openssh.com"
                            },
                            {
                                "name": "ssh.algorithms.encryption",
                                "value": "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-cbc,aes192-cbc,aes256-cbc,blowfish-cbc,cast128-cbc,3des-cbc"
                            },
                            {
                                "name": "ssh.algorithms.hostkey",
                                "value": "ssh-rsa,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519"
                            },
                            {
                                "name": "ssh.algorithms.kex",
                                "value": "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
                            },
                            {
                                "name": "ssh.algorithms.mac",
                                "value": "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1"
                            },
                            {
                                "name": "ssh.banner",
                                "value": "SSH-2.0-OpenSSH_7.4"
                            },
                            {
                                "name": "ssh.protocol.version",
                                "value": "2.0"
                            },
                            {
                                "name": "ssh.rsa.pubkey.fingerprint",
                                "value": "A74AFD453C6FBD15CF99481E0FFFC110"
                            }
                        ],
                        "family": "OpenSSH",
                        "name": "SSH",
                        "port": 22,
                        "product": "OpenSSH",
                        "protocol": "tcp",
                        "vendor": "OpenBSD",
                        "version": "7.4"
                    }
                ],
                "vulnerabilities": {
                    "critical": 0,
                    "moderate": 4,
                    "severe": 3
                }
            },
            {
                "Address": "192.0.2.0",
                "Assessed": true,
                "AssetId": 11,
                "Exploits": 2,
                "LastScanDate": "2022-11-02T14:54:19.055Z",
                "LastScanId": "-",
                "Malware": 0,
                "Name": "angular.testsparker.com",
                "OperatingSystem": "Ubuntu Linux",
                "RiskScore": 7689.2607421875,
                "Site": "PANW",
                "Vulnerabilities": 26,
                "addresses": [
                    {
                        "ip": "192.0.2.0"
                    }
                ],
                "assessedForPolicies": false,
                "history": [
                    {
                        "date": "2020-10-01T22:40:08.844Z",
                        "scanId": 650,
                        "type": "SCAN",
                        "version": 1
                    },
                    {
                        "date": "2022-07-10T11:51:17.898Z",
                        "description": "nxadmin",
                        "type": "VULNERABILITY_EXCEPTION_APPLIED",
                        "version": 2,
                        "vulnerabilityExceptionId": 1
                    },
                    {
                        "date": "2022-11-02T14:54:19.055Z",
                        "description": "nxadmin",
                        "type": "VULNERABILITY_EXCEPTION_UNAPPLIED",
                        "version": 3,
                        "vulnerabilityExceptionId": 1
                    }
                ],
                "hostNames": [
                    {
                        "name": "angular.testsparker.com",
                        "source": "user"
                    }
                ],
                "osFingerprint": {
                    "description": "Ubuntu Linux",
                    "family": "Linux",
                    "id": 7,
                    "product": "Linux",
                    "systemName": "Ubuntu Linux",
                    "vendor": "Ubuntu"
                },
                "rawRiskScore": 7689.2607421875,
                "services": [
                    {
                        "configurations": [
                            {
                                "name": "http.banner",
                                "value": "Apache/2.4.29 (Ubuntu)"
                            },
                            {
                                "name": "http.banner.server",
                                "value": "Apache/2.4.29 (Ubuntu)"
                            },
                            {
                                "name": "verbs-1",
                                "value": "GET"
                            },
                            {
                                "name": "verbs-2",
                                "value": "HEAD"
                            },
                            {
                                "name": "verbs-3",
                                "value": "OPTIONS"
                            },
                            {
                                "name": "verbs-4",
                                "value": "POST"
                            },
                            {
                                "name": "verbs-count",
                                "value": "4"
                            }
                        ],
                        "family": "Apache",
                        "name": "HTTP",
                        "port": 80,
                        "product": "HTTPD",
                        "protocol": "tcp",
                        "vendor": "Apache",
                        "version": "2.4.29"
                    },
                    {
                        "configurations": [
                            {
                                "name": "http.banner",
                                "value": "Apache/2.4.29 (Ubuntu)"
                            },
                            {
                                "name": "http.banner.server",
                                "value": "Apache/2.4.29 (Ubuntu)"
                            }
                        ],
                        "family": "Apache",
                        "name": "HTTP",
                        "port": 8000,
                        "product": "HTTPD",
                        "protocol": "tcp",
                        "vendor": "Apache",
                        "version": "2.4.29"
                    }
                ],
                "vulnerabilities": {
                    "critical": 1,
                    "moderate": 2,
                    "severe": 23
                }
            },
            {
                "Address": "192.0.2.0",
                "Assessed": true,
                "AssetId": 12,
                "Exploits": 4,
                "LastScanDate": "2049-03-01T04:31:56Z",
                "LastScanId": "-",
                "Malware": 0,
                "OperatingSystem": "Microsoft Windows",
                "RiskScore": 19446.267578125,
                "Site": "PANW",
                "Vulnerabilities": 46,
                "addresses": [
                    {
                        "ip": "192.0.2.0"
                    }
                ],
                "assessedForPolicies": false,
                "databases": [
                    {
                        "id": 0,
                        "name": "test"
                    }
                ],
                "history": [
                    {
                        "date": "2020-10-01T22:40:08.974Z",
                        "scanId": 650,
                        "type": "SCAN",
                        "version": 1
                    },
                    {
                        "date": "2021-06-29T06:58:48.740Z",
                        "scanId": 762,
                        "type": "SCAN",
                        "version": 2
                    },
                    {
                        "date": "2049-03-01T04:31:56Z",
                        "description": "nxadmin",
                        "type": "ASSET-IMPORT",
                        "user": "nxadmin",
                        "version": 3
                    }
                ],
                "osFingerprint": {
                    "description": "Microsoft Windows",
                    "family": "Windows",
                    "id": 11,
                    "product": "Windows",
                    "systemName": "Microsoft Windows",
                    "vendor": "Microsoft"
                },
                "rawRiskScore": 19446.267578125,
                "services": [
                    {
                        "configurations": [
                            {
                                "name": "PHP",
                                "value": "7.1.26"
                            },
                            {
                                "name": "http.banner",
                                "value": "Apache/2.4.25 (Debian)"
                            },
                            {
                                "name": "http.banner.server",
                                "value": "Apache/2.4.25 (Debian)"
                            },
                            {
                                "name": "http.banner.x-powered-by",
                                "value": "PHP/7.1.26"
                            },
                            {
                                "name": "verbs-1",
                                "value": "GET"
                            },
                            {
                                "name": "verbs-count",
                                "value": "1"
                            }
                        ],
                        "family": "Apache",
                        "name": "HTTP",
                        "port": 80,
                        "product": "HTTPD",
                        "protocol": "tcp",
                        "vendor": "Apache",
                        "version": "2.4.25"
                    },
                    {
                        "configurations": [
                            {
                                "name": "PHP",
                                "value": "7.1.26"
                            },
                            {
                                "name": "http.banner",
                                "value": "Apache/2.4.25 (Debian)"
                            },
                            {
                                "name": "http.banner.server",
                                "value": "Apache/2.4.25 (Debian)"
                            },
                            {
                                "name": "http.banner.x-powered-by",
                                "value": "PHP/7.1.26"
                            },
                            {
                                "name": "verbs-1",
                                "value": "GET"
                            },
                            {
                                "name": "verbs-count",
                                "value": "1"
                            }
                        ],
                        "family": "Apache",
                        "name": "HTTP",
                        "port": 8080,
                        "product": "HTTPD",
                        "protocol": "tcp",
                        "vendor": "Apache",
                        "version": "2.4.25"
                    }
                ],
                "vulnerabilities": {
                    "critical": 7,
                    "moderate": 0,
                    "severe": 39
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Nexpose Asset
>|AssetId|Address|Site|Exploits|Malware|OperatingSystem|RiskScore|Assessed|LastScanDate|LastScanId|
>|---|---|---|---|---|---|---|---|---|---|
>| 12 | 192.0.2.0 | PANW | 4 | 0 | Microsoft Windows | 19446.267578125 | true | 2049-03-01T04:31:56Z | - |


### nexpose-get-scan
***
Get a specific scan.


#### Base Command

`nexpose-get-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of a specific scan to retrieve.  Can be a comma-separated list. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Scan.Id | number | The identifier of the scan. | 
| Nexpose.Scan.ScanType | string | The scan type \(automated, manual, scheduled\). | 
| Nexpose.Scan.StartedBy | string | The name of the user that started the scan. | 
| Nexpose.Scan.Assets | number | The number of assets found in the scan | 
| Nexpose.Scan.TotalTime | string | The duration of the scan in minutes. | 
| Nexpose.Scan.Status | string | The scan status. Valid values are aborted, unknown, running, finished, stopped, error, paused, dispatched, integrating | 
| Nexpose.Scan.Completed | date | The end time of the scan in ISO8601 format. | 
| Nexpose.Scan.Vulnerabilities.Critical | number | The number of critical vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Moderate | number | The number of moderate vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Severe | number | The number of severe vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Total | number | The total number of vulnerabilities. | 

#### Command example
```!nexpose-get-scan id=1```
#### Context Example
```json
{
    "Nexpose": {
        "Scan": {
            "Assets": 0,
            "Completed": "2019-12-03T20:48:01.368Z",
            "Id": 1,
            "ScanName": "Tue 03 Dec 2019 10:47 PM",
            "ScanType": "Manual",
            "Status": "finished",
            "TotalTime": "51.316 seconds",
            "Vulnerabilities": {
                "Critical": 0,
                "Moderate": 0,
                "Severe": 0,
                "Total": 0
            },
            "engineId": 3,
            "engineIds": [
                3
            ],
            "engineName": "Local scan engine",
            "startTime": "2019-12-03T20:47:10.052Z",
            "startedByUsername": "nxadmin",
            "vulnerabilities": {
                "Critical": 0,
                "Moderate": 0,
                "Severe": 0,
                "Total": 0
            }
        }
    }
}
```

#### Human Readable Output

>### Nexpose Scan ID 1
>|Id|ScanType|ScanName|Assets|TotalTime|Completed|Status|
>|---|---|---|---|---|---|---|
>| 1 | Manual | Tue 03 Dec 2019 10:47 PM | 0 | 51.316 seconds | 2019-12-03T20:48:01.368Z | finished |
>### Vulnerabilities
>|Critical|Severe|Moderate|Total|
>|---|---|---|---|
>| 0 | 0 | 0 | 0 |


### nexpose-get-asset-vulnerability
***
Returns details and possible remediations for an asset's vulnerability.


#### Base Command

`nexpose-get-asset-vulnerability`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of an asset to search for the vulnerability. | Required | 
| vulnerabilityId | ID of a vulnerability to search for. Example: 7-zip-cve-2008-6536. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Asset.AssetId | number | Identifier of the asset. | 
| Nexpose.Asset.Vulnerability.Id | number | The identifier of the vulnerability. | 
| Nexpose.Asset.Vulnerability.Title | string | The title \(summary\) of the vulnerability. | 
| Nexpose.Asset.Vulnerability.Severity | string | The severity of the vulnerability, one of: "Moderate", "Severe", "Critical". | 
| Nexpose.Asset.Vulnerability.RiskScore | number | The risk score of the vulnerability, rounded to a maximum of to digits of precision. If using the default Rapid7 Real Risk™ model, this value ranges from 0-1000. | 
| Nexpose.Asset.Vulnerability.CVSS | string | The CVSS vector\(s\) for the vulnerability. | 
| Nexpose.Asset.Vulnerability.CVSSV3 | string | The CVSS v3 vector. | 
| Nexpose.Asset.Vulnerability.Published | date | The date the vulnerability was first published or announced. The format is an ISO 8601 date, YYYY-MM-DD. | 
| Nexpose.Asset.Vulnerability.Added | date | The date the vulnerability coverage was added. The format is an ISO 8601 date, YYYY-MM-DD. | 
| Nexpose.Asset.Vulnerability.Modified | date | The last date the vulnerability was modified. The format is an ISO 8601 date, YYYY-MM-DD. | 
| Nexpose.Asset.Vulnerability.CVSSScore | number | The CVSS score, which ranges from 0-10. | 
| Nexpose.Asset.Vulnerability.CVSSV3Score | number | The CVSS3 score, which ranges from 0-10. | 
| Nexpose.Asset.Vulnerability.Categories | unknown | All vulnerability categories assigned to this vulnerability. | 
| Nexpose.Asset.Vulnerability.CVES | unknown | All CVEs assigned to this vulnerability. | 
| Nexpose.Asset.Vulnerability.Check.Port | number | The port of the service the result was discovered on. | 
| Nexpose.Asset.Vulnerability.Check.Protocol | string | The protocol of the service the result was discovered on, valid values ip, icmp, igmp, ggp, tcp, pup, udp, idp, esp, nd, raw | 
| Nexpose.Asset.Vulnerability.Check.Since | date | The date and time the result was first recorded, in the ISO8601 format. If the result changes status this value is the date and time of the status change. | 
| Nexpose.Asset.Vulnerability.Check.Proof | string | The proof explaining why the result was found vulnerable. | 
| Nexpose.Asset.Vulnerability.Check.Status | string | The status of the vulnerability check result. Valid values are, unknown, not-vulnerable, vulnerable, vulnerable-version, vulnerable-potential, vulnerable-with-exception-applied, vulnerable-version-with-exception-applied, vulnerable-potential-with-exception-applied | 
| Nexpose.Asset.Vulnerability.Solution.Type | string | The type of the solution. One of: "Configuration", "Rollup patch", "Patch". | 
| Nexpose.Asset.Vulnerability.Solution.Summary | string | The summary of the solution. | 
| Nexpose.Asset.Vulnerability.Solution.Steps | string | The steps required to remediate the vulnerability. | 
| Nexpose.Asset.Vulnerability.Solution.Estimate | string | The estimated duration to apply the solution, in minutes. | 
| Nexpose.Asset.Vulnerability.Solution.AdditionalInformation | string | Additional information or resources that can assist in applying the remediation | 
| CVE.ID | string | Common Vulnerabilities and Exposures ids | 

#### Command example
```!nexpose-get-asset-vulnerability id=1 vulnerabilityId=ssh-cve-2016-2183-sweet32```
#### Context Example
```json
{
    "CVE": {
        "CVSS": {},
        "ID": "CVE-2016-2183"
    },
    "DBotScore": {
        "Indicator": "CVE-2016-2183",
        "Score": 0,
        "Type": "cve",
        "Vendor": "Rapid7 Nexpose"
    },
    "Nexpose": {
        "Asset": {
            "AssetId": "1",
            "Vulnerability": [
                {
                    "Added": "2020-03-31",
                    "CVES": [
                        "CVE-2016-2183"
                    ],
                    "CVSS": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
                    "CVSSScore": 5,
                    "CVSSV3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "CVSSV3Score": 7.5,
                    "Categories": [
                        "Network",
                        "SSH"
                    ],
                    "Check": [
                        {
                            "Port": 22,
                            "Proof": "Running SSH serviceInsecure 3DES ciphers in use: 3des-cbc",
                            "Protocol": "tcp",
                            "Since": "2020-04-20T13:56:34.818Z",
                            "Status": "vulnerable-version"
                        }
                    ],
                    "Id": "ssh-cve-2016-2183-sweet32",
                    "Modified": "2020-04-01",
                    "Published": "2016-08-24",
                    "RiskScore": 544.64,
                    "Severity": "Severe",
                    "Solution": [
                        {
                            "Estimate": "10.0 minutes",
                            "Steps": "Remove all 3DES ciphers from the cipher list specified in sshd_config.",
                            "Summary": "Disable SSH support for 3DES cipher suite",
                            "Type": "configuration",
                            "confidence": "exact",
                            "id": "ssh-disable-3des-ciphers",
                            "matches": [
                                {
                                    "confidence": "exact",
                                    "fingerprint": {
                                        "description": "OpenBSD OpenSSH 7.4",
                                        "family": "OpenSSH",
                                        "product": "OpenSSH",
                                        "vendor": "OpenBSD",
                                        "version": "7.4"
                                    },
                                    "solution": "ssh-disable-3des-ciphers",
                                    "type": "service"
                                }
                            ],
                            "steps": {
                                "html": "<p>\n<p>Remove all 3DES ciphers from the cipher list specified in sshd_config.</p></p>"
                            },
                            "summary": {
                                "html": "Disable SSH support for 3DES cipher suite"
                            }
                        }
                    ],
                    "Title": "SSH Birthday attacks on 64-bit block ciphers (SWEET32)",
                    "cvss": {
                        "v2": {
                            "accessComplexity": "L",
                            "accessVector": "N",
                            "authentication": "N",
                            "availabilityImpact": "N",
                            "confidentialityImpact": "P",
                            "exploitScore": 9.9968,
                            "impactScore": 2.8627,
                            "integrityImpact": "N"
                        },
                        "v3": {
                            "attackComplexity": "L",
                            "attackVector": "N",
                            "availabilityImpact": "N",
                            "confidentialityImpact": "H",
                            "exploitScore": 3.887,
                            "impactScore": 3.5952,
                            "integrityImpact": "N",
                            "privilegeRequired": "N",
                            "scope": "U",
                            "userInteraction": "N"
                        }
                    },
                    "denialOfService": false,
                    "description": {
                        "html": "<p>\n      Legacy block ciphers having a block size of 64 bits are vulnerable to a practical collision attack when used in CBC\n      mode. The security of a block cipher is often reduced to the key size k: the best attack should\n      be the exhaustive search of the key, with complexity 2 to the power of k. However, the block size n is also an\n      important security parameter, defining the amount of data that can be encrypted under the same key. This is\n      particularly important when using common modes of operation: we require block ciphers to be secure with up to 2 to\n      the power of n queries, but most modes of operation (e.g. CBC, CTR, GCM, OCB, etc.) are unsafe with more than 2\n      to the power of half n blocks of message (the birthday bound). With a modern block cipher with 128-bit blocks such\n      as AES, the birthday bound corresponds to 256 exabytes. However, for a block cipher with 64-bit blocks, the birthday\n      bound corresponds to only 32 GB, which is easily reached in practice. Once a collision between two cipher blocks\n      occurs it is possible to use the collision to extract the plain text data.\n    </p>",
                        "text": "Legacy block ciphers having a block size of 64 bits are vulnerable to a practical collision attack when used in CBC mode. The security of a block cipher is often reduced to the key size k: the best attack should be the exhaustive search of the key, with complexity 2 to the power of k. However, the block size n is also an important security parameter, defining the amount of data that can be encrypted under the same key. This is particularly important when using common modes of operation: we require block ciphers to be secure with up to 2 to the power of n queries, but most modes of operation (e.g. CBC, CTR, GCM, OCB, etc.) are unsafe with more than 2 to the power of half n blocks of message (the birthday bound). With a modern block cipher with 128-bit blocks such as AES, the birthday bound corresponds to 256 exabytes. However, for a block cipher with 64-bit blocks, the birthday bound corresponds to only 32 GB, which is easily reached in practice. Once a collision between two cipher blocks occurs it is possible to use the collision to extract the plain text data."
                    },
                    "exploits": 0,
                    "malwareKits": 0,
                    "pci": {
                        "adjustedCVSSScore": 5,
                        "adjustedSeverityScore": 3,
                        "fail": true,
                        "status": "Fail"
                    },
                    "severityScore": 5
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Vulnerability ssh-cve-2016-2183-sweet32
>|Id|Title|Severity|RiskScore|CVSS|CVSSV3|Published|Added|Modified|CVSSScore|CVSSV3Score|Categories|CVES|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| ssh-cve-2016-2183-sweet32 | SSH Birthday attacks on 64-bit block ciphers (SWEET32) | Severe | 544.64 | AV:N/AC:L/Au:N/C:P/I:N/A:N | CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 2016-08-24 | 2020-03-31 | 2020-04-01 | 5.0 | 7.5 | Network,<br/>SSH | CVE-2016-2183 |
>### Checks
>|Port|Protocol|Since|Proof|Status|
>|---|---|---|---|---|
>| 22 | tcp | 2020-04-20T13:56:34.818Z | Running SSH serviceInsecure 3DES ciphers in use: 3des-cbc | vulnerable-version |
>### Solutions
>|Type|Summary|Steps|Estimate|
>|---|---|---|---|
>| configuration | Disable SSH support for 3DES cipher suite | Remove all 3DES ciphers from the cipher list specified in sshd_config. | 10.0 minutes |


### nexpose-create-shared-credential
***
Create a new shared credential. For detailed explanation of all parameters of this command, please see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/createSharedCredential


#### Base Command

`nexpose-create-shared-credential`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the credential. | Required | 
| site_assignment | Site assignment configuration for the credential. Assign the shared scan credential either to be available to all sites, or a specific list of sites. Possible values are: All-Sites, Specific-Sites. | Required | 
| service | Credential service type. Possible values are: AS400, CIFS, CIFSHash, CVS, DB2, FTP, HTTP, MS-SQL, MySQL, Notes, Oracle, POP, PostgresSQL, Remote-Exec, SNMP, SNMPv3, SSH, SSH-Key, Sybase, Telnet. | Required | 
| database | Database name. | Optional | 
| description | Description for the credential. | Optional | 
| domain | Domain address. | Optional | 
| host_restriction | Hostname or IP address to restrict the credentials to. | Optional | 
| http_realm | HTTP realm. | Optional | 
| notes_id_password | Password for the notes account that will be used for authenticating. | Optional | 
| ntlm_hash | NTLM password hash. | Optional | 
| oracle_enumerate_sids | Whether the scan engine should attempt to enumerate SIDs from the environment. Possible values are: true, false. | Optional | 
| oracle_listener_password | Oracle Net Listener password. Used to enumerate SIDs from your environment. | Optional | 
| oracle_sid | Oracle database name. | Optional | 
| password | Password for the credential. | Optional | 
| port_restriction | Further restricts the credential to attempt to authenticate on a specific port. Can be used only if `host_restriction` is used. | Optional | 
| sites | List of site IDs for the shared credential that are explicitly assigned access to the shared scan credential, allowing it to use the credential during a scan. | Optional | 
| community_name | SNMP community for authentication. | Optional | 
| authentication_type | SNMPv3 authentication type for the credential. Possible values are: No-Authentication, MD5, SHA. | Optional | 
| privacy_password | SNMPv3 privacy password to use. | Optional | 
| privacy_type | SNMPv3 Privacy protocol to use. Possible values are: No-Privacy, DES, AES-128, AES-192, AES-192-With-3-DES-Key-Extension, AES-256, AES-256-With-3-DES-Key-Extension. | Optional | 
| ssh_key_pem | PEM formatted private key. | Optional | 
| ssh_permission_elevation | Elevation type to use for scans. Possible values are: None, sudo, sudosu, su, pbrun, Privileged-Exec. | Optional | 
| ssh_permission_elevation_password | Password to use for elevation. | Optional | 
| ssh_permission_elevation_username | Username to use for elevation. | Optional | 
| ssh_private_key_password | Password for the private key. | Optional | 
| use_windows_authentication | Whether to use Windows authentication. Possible values are: true, false. | Optional | 
| username | Username for the credential. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.SharedCredential.id | number | ID of the generated credential. | 

#### Command example
```!nexpose-create-shared-credential name="Test" service=FTP site_assignment="All-Sites" username="test" password="test"```
#### Context Example
```json
{
    "Nexpose": {
        "SharedCredential": {
            "id": 24
        }
    }
}
```

#### Human Readable Output

>New shared credential has been created with ID 24.

### nexpose-create-site
***
Creates a new site with the specified configuration.


#### Base Command

`nexpose-create-site`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Site name. Must be unique. | Required | 
| description | Site's description. | Optional | 
| assets | Addresses of assets to include in site scans. Can be a comma-separated list. | Required | 
| scanTemplateId | ID of a scan template to use. If not specified, the default scan template will be used. Use `nexpose-get-report-templates` to get a list of all available templates. | Optional | 
| importance | Site importance. Defaults to "normal" if not specified. Possible values are: very_low, low, normal, high, very_high. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Site.Id | number | ID of the created site. | 

### nexpose-create-vulnerability-exception
***
Create a new vulnerability exception.


#### Base Command

`nexpose-create-vulnerability-exception`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| expires | The date and time the vulnerability exception is set to expire in an ISO 8601 date format. | Optional | 
| vulnerability_id | ID of the vulnerability to create the exception for. Example: 7-zip-cve-2008-6536. | Required | 
| scope_type | The type of the exception scope. If set to anything other than `Global`, `scope_id` parameter is required. Possible values are: Global, Site, Asset, Asset-Group. | Required | 
| state | State of the vulnerability exception. Possible values are: Expired, Approved, Rejected, Under-Review. | Required | 
| comment | A comment from the submitter as to why the exception was submitted. | Optional | 
| reason | Reason why the vulnerability exception was submitted. Possible values are: False-Positive, Compensating-Control, Acceptable-Use, Acceptable-Risk, Other. | Required | 
| scope_id | ID of the chosen `scope_type` (site ID, asset ID, etc.). Required if `scope_type` is anything other than `Global`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.VulnerabilityException.id | number | ID of the generated vulnerability exception. | 

### nexpose-delete-asset
***
Delete an asset.


#### Base Command

`nexpose-delete-asset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the asset to delete. | Required | 


### nexpose-delete-scan-schedule
***
Delete a scheduled scan.


#### Base Command

`nexpose-delete-scan-schedule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Id of the site to delete. | Optional | 
| site_name | Name of the site to delete (can be used instead of `site_id`). | Optional | 
| schedule_id | ID of the scheduled scan to delete. | Required | 


### nexpose-delete-shared-credential
***
Delete a shared credential.


#### Base Command

`nexpose-delete-shared-credential`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the shared credential to delete. | Required | 


### nexpose-delete-site-scan-credential
***
Delete a site scan credential.


#### Base Command

`nexpose-delete-site-scan-credential`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site_id`). | Optional | 
| credential_id | ID of the site scan credential to delete. | Required | 


### nexpose-delete-site
***
Deletes a site.


#### Base Command

`nexpose-delete-site`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of a site to delete. | Optional | 
| site_name | Name of the site to delete (can be used instead of `site_id`). | Optional | 


### nexpose-delete-vulnerability-exception
***
Delete a vulnerability exception.


#### Base Command

`nexpose-delete-vulnerability-exception`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the vulnerability exception to delete. | Required | 


#### Command example
```!nexpose-delete-vulnerability-exception id=1```
#### Human Readable Output

>Vulnerability exception with ID 1 has been deleted.

### nexpose-get-sites
***
Retrieves accessible sites.


#### Base Command

`nexpose-get-sites`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | Number of records to retrieve in each API call when pagination is used. | Optional | 
| page | A specific page to retrieve when pagination is used. | Optional | 
| limit | A number of records to limit the response to. Default is 10. | Optional | 
| sort | Criteria to sort the records by, in the format: property[,ASC\|DESC]. If not specified, default sort order is ascending. Multiple sort criteria can be specified, separated by a ';'. For example: 'riskScore,DESC;hostName,ASC'. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Site.Id | number | The identifier of the site. | 
| Nexpose.Site.Name | string | The site name. | 
| Nexpose.Site.Assets | number | The number of assets that belong to the site. | 
| Nexpose.Site.Type | string | The type of the site. Valid values are agent, dynamic, static | 
| Nexpose.Site.Vulnerabilities | number | The total number of vulnerabilities. | 
| Nexpose.Site.Risk | number | The risk score \(with criticality adjustments\) of the site. | 
| Nexpose.Site.LastScan | date | The date and time of the site's last scan. | 

#### Command example
```!nexpose-get-sites limit=10```
#### Context Example
```json
{
    "Nexpose": {
        "Site": [
            {
                "Assets": 4,
                "Id": 3,
                "LastScan": "2021-08-03T14:09:15.321Z",
                "Name": "Authenticated-Assets",
                "Risk": 20402,
                "Type": "static",
                "Vulnerabilities": 41,
                "importance": "normal",
                "scanEngine": 3,
                "scanTemplate": "full-audit-without-web-spider",
                "vulnerabilities": {
                    "critical": 0,
                    "moderate": 16,
                    "severe": 25
                }
            },
            {
                "Assets": 19,
                "Id": 2,
                "LastScan": "2021-06-29T07:06:54.733Z",
                "Name": "PANW",
                "Risk": 216326,
                "Type": "static",
                "Vulnerabilities": 461,
                "importance": "normal",
                "scanEngine": 3,
                "scanTemplate": "full-audit-without-web-spider",
                "vulnerabilities": {
                    "critical": 141,
                    "moderate": 13,
                    "severe": 307
                }
            },
            {
                "Assets": 9,
                "Id": 1,
                "LastScan": "2020-11-26T17:13:54.117Z",
                "Name": "Test",
                "Risk": 21173,
                "Type": "static",
                "Vulnerabilities": 53,
                "description": "This is a test site with test asset",
                "importance": "very_low",
                "scanEngine": 3,
                "scanTemplate": "full-audit-without-web-spider",
                "vulnerabilities": {
                    "critical": 7,
                    "moderate": 4,
                    "severe": 42
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Nexpose sites
>| Id  |Name|Assets|Vulnerabilities|Risk|Type|LastScan|
-----|---|---|---|---|---|---|---|
>| 3 | Authenticated-Assets | 4 | 41 | 20402.0 | static | 2021-08-03T14:09:15.321Z |
>| 2 | PANW | 19 | 461 | 216326.0 | static | 2021-06-29T07:06:54.733Z |
>| 1 | Test | 9 | 53 | 21173.0 | static | 2020-11-26T17:13:54.117Z |


### nexpose-get-report-templates
***
Returns all available report templates.


#### Base Command

`nexpose-get-report-templates`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Template.Id | number | The identifier of the report template. | 
| Nexpose.Template.Name | string | The name of the report template. | 
| Nexpose.Template.Description | string | The description of the report template. | 
| Nexpose.Template.Type | string | The type of the report template. document is a templatized, typically printable, report that has various sections of content. export is data-oriented output, typically CSV. file is a printable report template using a report template file. | 

#### Command example
```!nexpose-get-report-templates```
#### Context Example
```json
{
    "Nexpose": {
        "Template": [
            {
                "Description": "Provides comprehensive details about discovered assets, vulnerabilities, and users.",
                "Id": "audit-report",
                "Name": "Audit Report",
                "Type": "document",
                "builtin": true,
                "sections": [
                    "CoverPage",
                    "ExecutiveSummary",
                    "ScanSettings",
                    "SystemOverview",
                    "VulnerabilityDetailListing",
                    "ServiceListing",
                    "UserGroupListing",
                    "DatabaseListing",
                    "FileSystemListing",
                    "PolicyEvaluation",
                    "SpideredWebsite"
                ]
            },
            {
                "Description": "Compares current scan results to those of an earlier baseline scan.",
                "Id": "baseline-comparison",
                "Name": "Baseline Comparison",
                "Type": "document",
                "builtin": true,
                "sections": [
                    "CoverPage",
                    "ExecutiveSummary",
                    "BaselineComparison"
                ]
            },
            {
                "Description": "Provides a high-level view of security data, including general results information and statistical charts.",
                "Id": "executive-overview",
                "Name": "Executive Overview",
                "Type": "document",
                "builtin": true,
                "sections": [
                    "CoverPage",
                    "ExecutiveSummary",
                    "BaselineComparison"
                ]
            },
            {
                "Description": "Provides information and metrics about 10 discovered vulnerabilities with the highest risk scores.",
                "Id": "highest-risk-vulns",
                "Name": "Highest Risk Vulnerabilities",
                "Type": "document",
                "builtin": true,
                "sections": [
                    "CoverPage",
                    "TOC",
                    "HighestRiskVulnerabilities"
                ]
            },
            {
                "Description": "Lists results for standard policy scans (AS/400, Oracle, Domino, Windows Group, CIFS/SMB account). Does not include Policy Manager results.",
                "Id": "policy-eval",
                "Name": "Policy Evaluation",
                "Type": "document",
                "builtin": true,
                "sections": [
                    "CoverPage",
                    "PolicyEvaluation"
                ]
            },
            {
                "Description": "Provides detailed remediation instructions for each discovered vulnerability.",
                "Id": "remediation-plan",
                "Name": "Remediation Plan",
                "Type": "document",
                "builtin": true,
                "sections": [
                    "CoverPage",
                    "SystemOverview",
                    "RiskAssessment",
                    "RemediationPlan"
                ]
            },
            {
                "Description": "Lists test results for each discovered vulnerability, including how it was verified.",
                "Id": "report-card",
                "Name": "Report Card",
                "Type": "document",
                "builtin": true,
                "sections": [
                    "CoverPage",
                    "VulnerabilityReportCardByNode",
                    "VulnerabilityIndex"
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Nexpose templates
>|Id|Name|Description|Type|
>|---|---|---|---|
>| audit-report | Audit Report | Provides comprehensive details about discovered assets, vulnerabilities, and users. | document |
>| baseline-comparison | Baseline Comparison | Compares current scan results to those of an earlier baseline scan. | document |
>| executive-overview | Executive Overview | Provides a high-level view of security data, including general results information and statistical charts. | document |
>| highest-risk-vulns | Highest Risk Vulnerabilities | Provides information and metrics about 10 discovered vulnerabilities with the highest risk scores. | document |
>| policy-eval | Policy Evaluation | Lists results for standard policy scans (AS/400, Oracle, Domino, Windows Group, CIFS/SMB account). Does not include Policy Manager results. | document |
>| remediation-plan | Remediation Plan | Provides detailed remediation instructions for each discovered vulnerability. | document |
>| report-card | Report Card | Lists test results for each discovered vulnerability, including how it was verified. | document |


### nexpose-create-asset
***
Create a new asset.


#### Base Command

`nexpose-create-asset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site_id`). | Optional | 
| date | The date the data was collected on the asset in an ISO 8601 format. | Required | 
| ip | Primary IPv4 or IPv6 address of the asset. | Required | 
| host_name | Hostname of the asset. | Optional | 
| host_name_source | The source used to detect the host name. "user" indicates the host name source is user-supplied. Possible values are: User, DNS, NetBIOS, DCE, EPSEC, LDAP, Other. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Site.Asset.id | string | ID of the newly created asset. | 

### nexpose-create-assets-report
***
Generates a new report on given assets according to a template and arguments.


#### Base Command

`nexpose-create-assets-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| assets | Asset IDs to create the report on. Can be a comma-separated list. | Required | 
| template | Report template ID to create the report with. If not provided, the first available template will be used. | Optional | 
| name | Report name. | Optional | 
| format | Report format (uses PDF by default). Possible values are: pdf, rtf, xml, html, text. | Optional | 
| download_immediately | Whether to download the report immediately after the report is generated. Defaults to "true". If the report takes longer than 10 seconds to generate, set to "false". Possible values are: true, false. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryId | string | Entry Id of the report file. | 
| InfoFile.Name | string | Name of the report file. | 
| InfoFile.Extension | string | File extension of the report file. | 
| InfoFile.Info | string | Informatiom about the report file. | 
| InfoFile.Size | number | Size of the report file \(in bytes\). | 
| InfoFile.Type | string | Type of the report file. | 
| Nexpose.Report.ID | string | The identifier of the report. | 
| Nexpose.Report.InstanceID | string | The identifier of the report instance. | 
| Nexpose.Report.Name | string | The report name. | 
| Nexpose.Report.Format | string | The report format. | 

### nexpose-create-sites-report
***
Generates a new report on given sites according to a template and arguments.


#### Base Command

`nexpose-create-sites-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sites | Site IDs to create the report on, can be a comma-separated list. | Optional | 
| site_names | Names of sites to create the report on, can be a comma-separated list. | Optional | 
| template | Report template ID to use for report's creation. If not provided, the first available template will be used. | Optional | 
| name | Report name. | Optional | 
| format | Report format (uses PDF by default). Possible values are: pdf, rtf, xml, html, text. | Optional | 
| download_immediately | If true, downloads the report immediately after the report is generated. The default is "true". If the report takes longer than 10 seconds to generate, set to "false". Possible values are: true, false. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryId | string | Entry Id of the report file | 
| InfoFile.Name | string | Name of the report file | 
| InfoFile.Extension | string | File extension of the report file | 
| InfoFile.Info | string | Info about the report file | 
| InfoFile.Size | number | Size of the report file | 
| InfoFile.Type | string | Type of the report file | 
| Nexpose.Report.ID | string | The identifier of the report. | 
| Nexpose.Report.InstanceID | string | The identifier of the report instance. | 
| Nexpose.Report.Name | string | The report name. | 
| Nexpose.Report.Format | string | The report format. | 

### nexpose-create-site-scan-credential
***
Create a new site scan credential. For detailed explanation of all parameters of this command, please see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/createSiteCredential


#### Base Command

`nexpose-create-site-scan-credential`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site_id`). | Optional | 
| name | Name of the credential. | Required | 
| service | Credential service type. Possible values are: AS400, CIFS, CIFSHash, CVS, DB2, FTP, HTTP, MS-SQL, MySQL, Notes, Oracle, POP, PostgresSQL, Remote-Exec, SNMP, SNMPv3, SSH, SSH-Key, Sybase, Telnet. | Required | 
| database | Database name. | Optional | 
| description | Description for the credential. | Optional | 
| domain | Domain address. | Optional | 
| host_restriction | Hostname or IP address to restrict the credentials to. | Optional | 
| http_realm | HTTP realm. | Optional | 
| notes_id_password | Password for the notes account that will be used for authenticating. | Optional | 
| ntlm_hash | NTLM password hash. | Optional | 
| oracle_enumerate_sids | Whether the scan engine should attempt to enumerate SIDs from the environment. Possible values are: true, false. | Optional | 
| oracle_listener_password | Oracle Net Listener password. Used to enumerate SIDs from your environment. | Optional | 
| oracle_sid | Oracle database name. | Optional | 
| password | Password for the credential. | Optional | 
| port_restriction | Further restricts the credential to attempt to authenticate on a specific port. Can be used only if `host_restriction` is used. | Optional | 
| community_name | SNMP community for authentication. | Optional | 
| authentication_type | SNMPv3 authentication type for the credential. Possible values are: No-Authentication, MD5, SHA. | Optional | 
| privacy_password | SNMPv3 privacy password to use. | Optional | 
| privacy_type | SNMPv3 Privacy protocol to use. Possible values are: No-Privacy, DES, AES-128, AES-192, AES-192-With-3-DES-Key-Extension, AES-256, AES-256-With-3-DES-Key-Extension. | Optional | 
| ssh_key_pem | PEM formatted private key. | Optional | 
| ssh_permission_elevation | Elevation type to use for scans. Possible values are: None, sudo, sudosu, su, pbrun, Privileged-Exec. | Optional | 
| ssh_permission_elevation_password | Password to use for elevation. | Optional | 
| ssh_permission_elevation_username | Username to use for elevation. | Optional | 
| ssh_private_key_password | Password for the private key. | Optional | 
| use_windows_authentication | Whether to use Windows authentication. Possible values are: true, false. | Optional | 
| username | Username for the credential. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.SiteScanCredential.id | number | ID of the generated credential. | 

### nexpose-create-scan-report
***
Generates a new report for a specified scan.


#### Base Command

`nexpose-create-scan-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan | ID of the scan to create a report about. | Required | 
| template | Report template ID to use for creation. If not provided, the first available template will be used. | Optional | 
| name | Report name. | Optional | 
| format | Report format (uses PDF by default). Possible values are: pdf, rtf, xml, html, text. | Optional | 
| download_immediately | If true, downloads the report immediately after the report is generated. The default is "true". If the report takes longer than 10 seconds to generate, set to "false". Possible values are: true, false. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryId | string | Entry Id of the report file | 
| InfoFile.Name | string | Name of the report file | 
| InfoFile.Extension | string | File extension of the report file | 
| InfoFile.Info | string | Info about the report file | 
| InfoFile.Size | number | Size of the report file | 
| InfoFile.Type | string | Type of the report file | 
| Nexpose.Report.ID | string | The identifier of the report. | 
| Nexpose.Report.InstanceID | string | The identifier of the report instance. | 
| Nexpose.Report.Name | string | The report name. | 
| Nexpose.Report.Format | string | The report format. | 

#### Command example
```!nexpose-create-scan-report scan=1 download_immediately=false```
#### Context Example
```json
{
    "Nexpose": {
        "Report": {
            "Format": "pdf",
            "ID": 2725,
            "InstanceID": 2701,
            "Name": "report 2022-11-10 10:52:10.882635"
        }
    }
}
```

#### Human Readable Output

>### Report Information
>|Format|ID|InstanceID|Name|
>|---|---|---|---|
>| pdf | 2725 | 2701 | report 2022-11-10 10:52:10.882635 |


### nexpose-create-scan-schedule
***
Create a new site scan schedule.


#### Base Command

`nexpose-create-scan-schedule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site_id`). | Optional | 
| enabled | Whether to enable the scheduled scan after creation or not. Possible values are: True, False. Default is True. | Optional | 
| on_scan_repeat | The desired behavior of a repeating scheduled scan when the previous scan was paused due to reaching its maximum duration. Possible values are: Restart-Scan, Resume-Scan. | Required | 
| start | The scheduled start date and time formatted in ISO 8601 format. Repeating schedules will determine the next schedule to begin based on this date and time. | Required | 
| excluded_asset_group_ids | A list of ids for asset groups to exclude from the scan. | Optional | 
| excluded_addresses | A list of addresses to exclude from the scan. | Optional | 
| included_asset_group_ids | A list of ids for asset groups to include in the scan. | Optional | 
| included_addresses | A list of addresses to include in the scan. | Optional | 
| duration_days | Maximum duration of the scan in days. | Optional | 
| duration_hours | Maximum duration of the scan in hours. | Optional | 
| duration_minutes | Maximum duration of the scan in minutes. | Optional | 
| frequency | How frequent should the schedule to repeat (Every...). Possible values are: Hour, Day, Week, Date-of-month. | Optional | 
| interval_time | The interval time the schedule should repeat. This depends on the value set in `frequency`. For example, if the value of `frequency` is set to "Day" and `interval` is set to 2, then the schedule will repeat every 2 days. Required only if frequency is used. | Optional | 
| date_of_month | Specifies the schedule repeat day of the interval month. For example, if `date_of_month` is 17 and `interval` is set to 2, then the schedule will repeat every 2 months on the 17th day of the month. Required and used only if frequency is set to `Date of month`. | Optional | 
| scan_name | A unique user-defined name for the scan launched by the schedule. If not explicitly set in the schedule, the scan name will be generated prior to the scan launching. | Optional | 
| scan_template | ID of the scan template to use. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.ScanSchedule.id | int | ID of the newly created scan schedule. | 

### nexpose-list-assigned-shared-credential
***
Retrieve information about shared credentials for a specific site.


#### Base Command

`nexpose-list-assigned-shared-credential`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site_id`). | Optional | 
| limit | A number of records to limit the response to. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.AssignedSharedCredential.enabled | string | Flag indicating whether the shared credential is enabled for the site's scans. | 
| Nexpose.AssignedSharedCredential.id | string | ID of the shared credential. | 
| Nexpose.AssignedSharedCredential.name | string | The name of the shared credential. | 
| Nexpose.AssignedSharedCredential.service | string | Credential service type. | 

#### Command example
```!nexpose-list-assigned-shared-credential site_id=1 limit=3```
#### Context Example
```json
{
    "Nexpose": {
        "AssignedSharedCredential": [
            {
                "enabled": true,
                "id": 6,
                "name": "shared credentials",
                "service": "as400"
            },
            {
                "enabled": true,
                "id": 7,
                "name": "shared credentials",
                "service": "ssh"
            },
            {
                "enabled": true,
                "id": 8,
                "name": "shared credentials",
                "service": "snmpv3"
            }
        ]
    }
}
```

#### Human Readable Output

>### Nexpose Assigned Shared Credentials
>| Id  |Name|Service|Enabled|
-----|---|---|---|---|
>| 1 | shared credentials | as400 | true |
>| 2 | shared credentials | ssh | true |
>| 3 | shared credentials | snmpv3 | true |


### nexpose-list-vulnerability
***
Retrieve information about all or a specific vulnerability.


#### Base Command

`nexpose-list-vulnerability`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of a specific vulnerability to retrieve. | Optional | 
| page_size | Number of records to retrieve in each API call when pagination is used. | Optional | 
| page | A specific page to retrieve when pagination is used. | Optional | 
| limit | A number of records to limit the response to. Default is 10. | Optional | 
| sort | Criteria to sort the records by, in the format: property[,ASC\|DESC]. If not specified, default sort order is ascending. Multiple sort criteria can be specified, separated by a ';'. For example: 'riskScore,DESC;hostName,ASC'. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Vulnerability.added | string | The date the vulnerability coverage was added in an ISO 8601 format. | 
| Nexpose.Vulnerability.categories | array | All vulnerability categories assigned to this vulnerability. | 
| Nexpose.Vulnerability.cves | array | All CVEs assigned to this vulnerability. | 
| Nexpose.Vulnerability.cvss.v2.accessComplexity | string | Access Complexity \(AC\) component which measures the complexity of the attack required to exploit the vulnerability once an attacker has gained access to the target system. | 
| Nexpose.Vulnerability.cvss.v2.accessVector | string | Access Vector \(Av\) component which reflects how the vulnerability is exploited. | 
| Nexpose.Vulnerability.cvss.v2.authentication | string | Authentication \(Au\) component which measures the number of times an attacker must authenticate to a target in order to exploit a vulnerability. | 
| Nexpose.Vulnerability.cvss.v2.availabilityImpact | string | Availability Impact \(A\) component which measures the impact to availability of a successfully exploited vulnerability. | 
| Nexpose.Vulnerability.cvss.v2.confidentialityImpact | string | Confidentiality Impact \(C\) component which measures the impact on confidentiality of a successfully exploited vulnerability. | 
| Nexpose.Vulnerability.cvss.v2.exploitScore | number | The CVSS exploit score. | 
| Nexpose.Vulnerability.cvss.v2.impactScore | number | The CVSS impact score. | 
| Nexpose.Vulnerability.cvss.v2.integrityImpact | string | Integrity Impact \(I\) component measures the impact to integrity of a successfully exploited vulnerability. | 
| Nexpose.Vulnerability.cvss.v2.score | number | The CVSS score, which ranges from 0-10. | 
| Nexpose.Vulnerability.cvss.v2.vector | string | The CVSS v2 vector. | 
| Nexpose.Vulnerability.cvss.v3.attackComplexity | string | Access Complexity \(AC\) component with measures the conditions beyond the attacker's control that must exist in order to exploit the vulnerability. | 
| Nexpose.Vulnerability.cvss.v3.attackVector | string | Attack Vector \(AV\) component which measures context by which vulnerability exploitation is possible. | 
| Nexpose.Vulnerability.cvss.v3.availabilityImpact | string | Availability Impact \(A\) measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability. | 
| Nexpose.Vulnerability.cvss.v3.confidentialityImpact | string | Confidentiality Impact \(C\) component which measures the impact on confidentiality of a successfully exploited vulnerability. | 
| Nexpose.Vulnerability.cvss.v3.exploitScore | number | The CVSS impact score. | 
| Nexpose.Vulnerability.cvss.v3.impactScore | number | The CVSS exploit score. | 
| Nexpose.Vulnerability.cvss.v3.integrityImpact | string | Integrity Impact \(I\) measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information. | 
| Nexpose.Vulnerability.cvss.v3.privilegeRequired | string | Privileges Required \(PR\) measures the level of privileges an attacker must possess before successfully exploiting the vulnerability. | 
| Nexpose.Vulnerability.cvss.v3.scope | string | Scope \(S\) measures the collection of privileges defined by a computing authority \(e.g. an application, an operating system, or a sandbox environment\) when granting access to computing resources \(e.g. files, CPU, memory, etc\). These privileges are assigned based on some method of identification and authorization. | 
| Nexpose.Vulnerability.cvss.v3.score | number | The CVSS score, which ranges from 0-10. | 
| Nexpose.Vulnerability.cvss.v3.userInteraction | string | User Interaction \(UI\) measures the requirement for a user, other than the attacker, to participate in the successful compromise of the vulnerable component. | 
| Nexpose.Vulnerability.cvss.v3.vector | string | The CVSS v3 vector. | 
| Nexpose.Vulnerability.denialOfService | boolean | Whether the vulnerability can lead to Denial of Service \(DoS\). | 
| Nexpose.Vulnerability.description.html | string | Hypertext Markup Language \(HTML\) representation of the content. | 
| Nexpose.Vulnerability.description.text | string | Textual representation of the content. | 
| Nexpose.Vulnerability.exploits | number | The exploits that can be used to exploit a vulnerability. | 
| Nexpose.Vulnerability.id | string | The identifier of the vulnerability. | 
| Nexpose.Vulnerability.malwareKits | number | The malware kits that are known to be used to exploit the vulnerability. | 
| Nexpose.Vulnerability.modified | string | The last date the vulnerability was modified in an ISO 8601 format. | 
| Nexpose.Vulnerability.pci.adjustedCVSSScore | number | The CVSS score of the vulnerability, adjusted for PCI rules and exceptions, on a scale of 0-10. | 
| Nexpose.Vulnerability.pci.adjustedSeverityScore | number | The severity score of the vulnerability, adjusted for PCI rules and exceptions, on a scale of 0-10. | 
| Nexpose.Vulnerability.pci.fail | boolean | Whether if present on a host this vulnerability would cause a PCI failure. True if "status" is "Fail", false otherwise. | 
| Nexpose.Vulnerability.pci.specialNotes | string | Any special notes or remarks about the vulnerability that pertain to PCI compliance. | 
| Nexpose.Vulnerability.pci.status | string | The PCI compliance status of the vulnerability. Can be either "Pass", or "Fail". | 
| Nexpose.Vulnerability.published | string | The date the vulnerability was first published or announced in an ISO 8601 format. | 
| Nexpose.Vulnerability.riskScore | number | The risk score of the vulnerability, rounded to a maximum of to digits of precision. If using the default Rapid7 Real Risk model, this value ranges from 0-1000. | 
| Nexpose.Vulnerability.severity | string | The severity of the vulnerability, can be either "Moderate", "Severe", or "Critical". | 
| Nexpose.Vulnerability.severityScore | number | The severity score of the vulnerability, on a scale of 0-10. | 
| Nexpose.Vulnerability.title | string | The title \(summary\) of the vulnerability. | 

#### Command example
```!nexpose-list-vulnerability limit=3```
#### Context Example
```json
{
    "Nexpose": {
        "Vulnerability": [
            {
                "added": "2018-05-16",
                "categories": [
                    "7-Zip"
                ],
                "cves": [
                    "CVE-2008-6536"
                ],
                "cvss": {
                    "v2": {
                        "accessComplexity": "L",
                        "accessVector": "N",
                        "authentication": "N",
                        "availabilityImpact": "C",
                        "confidentialityImpact": "C",
                        "exploitScore": 9.9968,
                        "impactScore": 10.0008,
                        "integrityImpact": "C",
                        "score": 10,
                        "vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C"
                    }
                },
                "denialOfService": false,
                "description": {
                    "html": "<p>Unspecified vulnerability in 7-zip before 4.5.7 has unknown impact and remote attack vectors, as demonstrated by the PROTOS GENOME test suite for Archive Formats (c10).</p>",
                    "text": "Unspecified vulnerability in 7-zip before 4.5.7 has unknown impact and remote attack vectors, as demonstrated by the PROTOS GENOME test suite for Archive Formats (c10)."
                },
                "exploits": 0,
                "id": "7-zip-cve-2008-6536",
                "malwareKits": 0,
                "modified": "2018-06-08",
                "pci": {
                    "adjustedCVSSScore": 10,
                    "adjustedSeverityScore": 5,
                    "fail": true,
                    "status": "Fail"
                },
                "published": "2009-03-29",
                "riskScore": 898.42,
                "severity": "Critical",
                "severityScore": 10,
                "title": "7-Zip: CVE-2008-6536: Unspecified vulnerability in 7-zip before 4.5.7"
            },
            {
                "added": "2018-05-16",
                "categories": [
                    "7-Zip",
                    "Remote Execution"
                ],
                "cves": [
                    "CVE-2016-2334"
                ],
                "cvss": {
                    "v2": {
                        "accessComplexity": "M",
                        "accessVector": "N",
                        "authentication": "N",
                        "availabilityImpact": "C",
                        "confidentialityImpact": "C",
                        "exploitScore": 8.5888,
                        "impactScore": 10.0008,
                        "integrityImpact": "C",
                        "score": 9.3,
                        "vector": "AV:N/AC:M/Au:N/C:C/I:C/A:C"
                    },
                    "v3": {
                        "attackComplexity": "L",
                        "attackVector": "L",
                        "availabilityImpact": "H",
                        "confidentialityImpact": "H",
                        "exploitScore": 1.8346,
                        "impactScore": 5.8731,
                        "integrityImpact": "H",
                        "privilegeRequired": "N",
                        "scope": "U",
                        "score": 7.8,
                        "userInteraction": "R",
                        "vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
                    }
                },
                "denialOfService": false,
                "description": {
                    "html": "<p>Heap-based buffer overflow in the NArchive::NHfs::CHandler::ExtractZlibFile method in 7zip before 16.00 and p7zip allows remote attackers to execute arbitrary code via a crafted HFS+ image.</p>",
                    "text": "Heap-based buffer overflow in the NArchive::NHfs::CHandler::ExtractZlibFile method in 7zip before 16.00 and p7zip allows remote attackers to execute arbitrary code via a crafted HFS+ image."
                },
                "exploits": 0,
                "id": "7-zip-cve-2016-2334",
                "malwareKits": 0,
                "modified": "2018-06-08",
                "pci": {
                    "adjustedCVSSScore": 9,
                    "adjustedSeverityScore": 5,
                    "fail": true,
                    "status": "Fail"
                },
                "published": "2016-12-13",
                "riskScore": 715.39,
                "severity": "Critical",
                "severityScore": 9,
                "title": "7-Zip: CVE-2016-2334: Heap-based buffer overflow vulnerability"
            },
            {
                "added": "2018-05-16",
                "categories": [
                    "7-Zip",
                    "Trojan"
                ],
                "cves": [
                    "CVE-2016-7804"
                ],
                "cvss": {
                    "v2": {
                        "accessComplexity": "M",
                        "accessVector": "N",
                        "authentication": "N",
                        "availabilityImpact": "P",
                        "confidentialityImpact": "P",
                        "exploitScore": 8.5888,
                        "impactScore": 6.443,
                        "integrityImpact": "P",
                        "score": 6.8,
                        "vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P"
                    },
                    "v3": {
                        "attackComplexity": "L",
                        "attackVector": "L",
                        "availabilityImpact": "H",
                        "confidentialityImpact": "H",
                        "exploitScore": 1.8346,
                        "impactScore": 5.8731,
                        "integrityImpact": "H",
                        "privilegeRequired": "N",
                        "scope": "U",
                        "score": 7.8,
                        "userInteraction": "R",
                        "vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
                    }
                },
                "denialOfService": false,
                "description": {
                    "html": "<p>Untrusted search path vulnerability in 7 Zip for Windows 16.02 and earlier allows remote attackers to gain privileges via a Trojan horse DLL in an unspecified directory.</p>",
                    "text": "Untrusted search path vulnerability in 7 Zip for Windows 16.02 and earlier allows remote attackers to gain privileges via a Trojan horse DLL in an unspecified directory."
                },
                "exploits": 0,
                "id": "7-zip-cve-2016-7804",
                "malwareKits": 0,
                "modified": "2018-06-08",
                "pci": {
                    "adjustedCVSSScore": 6,
                    "adjustedSeverityScore": 4,
                    "fail": true,
                    "specialNotes": "The presence of malware, including rootkits, backdoors, or trojan horse programs are a violation of PCI DSS, and result in an automatic failure. ",
                    "status": "Fail"
                },
                "published": "2017-05-22",
                "riskScore": 576.96,
                "severity": "Severe",
                "severityScore": 7,
                "title": "7-Zip: CVE-2016-7804: Untrusted search path vulnerability"
            }
        ]
    }
}
```

#### Human Readable Output

>### Nexpose Vulnerabilities
>|Title|MalwareKits|Exploits|CVSS|CVSSv3|Risk|PublishedOn|ModifiedOn|Severity|
>|---|---|---|---|---|---|---|---|---|
>| 7-Zip: CVE-2008-6536: Unspecified vulnerability in 7-zip before 4.5.7 | 0 | 0 | 10.0 |  | 898.42 | 2009-03-29 | 2018-06-08 | Critical |
>| 7-Zip: CVE-2016-2334: Heap-based buffer overflow vulnerability | 0 | 0 | 9.3 | 7.8 | 715.39 | 2016-12-13 | 2018-06-08 | Critical |
>| 7-Zip: CVE-2016-7804: Untrusted search path vulnerability | 0 | 0 | 6.8 | 7.8 | 576.96 | 2017-05-22 | 2018-06-08 | Severe |


### nexpose-list-scan-schedule
***
Retrieve information about scan schedules for a specific site or a specific scan schedule.


#### Base Command

`nexpose-list-scan-schedule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site_id`). | Optional | 
| schedule_id | ID of the scheduled scan (optional, will return a single specific scan if used). | Optional | 
| limit | A number of records to limit the response to. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.ScanSchedule.assets.excludedAssetGroups.assetGroupIDs | array | List of asset group identifiers that will be excluded from scans. | 
| Nexpose.ScanSchedule.assets.excludedTargets.addresses | array | List of addresses that will be excluded from scans. | 
| Nexpose.ScanSchedule.assets.includedAssetGroups.assetGroupIDs | array | List of asset group identifiers that will be included in scans. | 
| Nexpose.ScanSchedule.assets.includedTargets.addresses | array | List of addresses that will be included in scans. | 
| Nexpose.ScanSchedule.duration | string | Specifies the maximum duration the scheduled scan is allowed to run in an ISO 8601 duration format. | 
| Nexpose.ScanSchedule.enabled | string | Flag indicating whether the scan schedule is enabled. | 
| Nexpose.ScanSchedule.id | int | The identifier of the scan schedule. | 
| Nexpose.ScanSchedule.nextRuntimes | array | List the next 10 dates in the future the schedule will launch. | 
| Nexpose.ScanSchedule.onScanRepeat | string | Specifies the desired behavior of a repeating scheduled scan when the previous scan was paused due to reaching is maximum duration. | 
| Nexpose.ScanSchedule.repeat.dayOfWeek | unknown | Specifies the desired behavior of a repeating scheduled scan when the previous scan was paused due to reaching is maximum duration. | 
| Nexpose.ScanSchedule.repeat.every | unknown | The frequency schedule repeats. Each value represents a different unit of time and is used in conjunction with the property interval. | 
| Nexpose.ScanSchedule.repeat.interval | unknown | The interval time the schedule should repeat. The is depends on the value set in every. | 
| Nexpose.ScanSchedule.repeat.weekOfMonth For This property only applies to schedules with a every value of "day-of-month". | unknown | The week of the month the scheduled task should repeat. | 
| Nexpose.ScanSchedule.repeat.scanEngineId | unknown | A user-defined name for the scan launched by the schedule. | 
| Nexpose.ScanSchedule.repeat.scanName | unknown | A user-defined name for the scan launched by the schedule. | 
| Nexpose.ScanSchedule.repeat.scanTemplateId | unknown | The identifier of the scan template to be used for this scan schedule. If not set, the site's assigned scan template will be used. | 
| Nexpose.ScanSchedule.repeat.start | unknown | The scheduled start date and time. Repeating schedules will determine the next schedule to begin based on this date and time. | 

#### Command example
```!nexpose-list-scan-schedule site_id=1 limit=3```
#### Human Readable Output

>No scan schedules were found for the site.

### nexpose-list-shared-credential
***
Retrieve information about all or a specific shared credential.


#### Base Command

`nexpose-list-shared-credential`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of a specific shared credential to retrieve. | Optional | 
| limit | A number of records to limit the response to. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.SharedCredential.account.authenticationType | string | SNMPv3 authentication type for the credential. | 
| Nexpose.SharedCredential.account.communityName | string | SNMP community for authentication. | 
| Nexpose.SharedCredential.account.database | string | Database name. | 
| Nexpose.SharedCredential.account.domain | string | Domain address. | 
| Nexpose.SharedCredential.account.enumerateSids | boolean | Whether the scan engine should attempt to enumerate SIDs from the environment. | 
| Nexpose.SharedCredential.account.notesIDPassword | string | Password for the notes account that will be used for authenticating. | 
| Nexpose.SharedCredential.account.ntlmHash | string | NTLM password hash. | 
| Nexpose.SharedCredential.account.oracleListenerPassword | string | The Oracle Net Listener password. Used to enumerate SIDs from the environment. | 
| Nexpose.SharedCredential.account.password | string | Password for the credential. | 
| Nexpose.SharedCredential.account.pemKey | string | PEM formatted private key. | 
| Nexpose.SharedCredential.account.permissionElevation | string | Elevation type to use for scans. | 
| Nexpose.SharedCredential.account.permissionElevationPassword | string | Password to use for elevation. | 
| Nexpose.SharedCredential.account.permissionElevationUserName | string | Username to use for elevation. | 
| Nexpose.SharedCredential.account.privacyPassword | string | SNMPv3 privacy password to use. | 
| Nexpose.SharedCredential.account.privacyType | string | SNMPv3 Privacy protocol to use. | 
| Nexpose.SharedCredential.account.privateKeyPassword | string | Password for the private key. | 
| Nexpose.SharedCredential.account.realm | string | HTTP realm. | 
| Nexpose.SharedCredential.account.service | string | Credential service type. | 
| Nexpose.SharedCredential.account.sid | string | Oracle database name. | 
| Nexpose.SharedCredential.account.useWindowsAuthentication | boolean | Whether to use Windows authentication. | 
| Nexpose.SharedCredential.account.username | string | Username for the credential. | 
| Nexpose.SharedCredential.description | string | Description for the credential. | 
| Nexpose.SharedCredential.hostRestriction | string | Hostname or IP address to restrict the credentials to. | 
| Nexpose.SharedCredential.id | number | ID of the shared credential. | 
| Nexpose.SharedCredential.name | string | Name of the credential. | 
| Nexpose.SharedCredential.portRestriction | number | Further restricts the credential to attempt to authenticate on a specific port. Can be used only if \`host_restriction\` is used. | 
| Nexpose.SharedCredential.siteAssignment | string | Site assignment configuration for the credential. | 
| Nexpose.SharedCredential.sites | array | List of site IDs for the shared credential that are explicitly assigned access to the shared scan credential, allowing it to use the credential during a scan. | 

#### Command example
```!nexpose-list-shared-credential limit=3```
#### Context Example
```json
{
    "Nexpose": {
        "SharedCredential": [
            {
                "account": {
                    "authenticationType": "md5",
                    "privacyType": "no-privacy",
                    "service": "snmpv3",
                    "username": "test"
                },
                "id": 1,
                "name": "shared credentials",
                "siteAssignment": "specific-sites",
                "sites": [
                    1
                ]
            },
            {
                "account": {
                    "service": "as400",
                    "username": "test"
                },
                "id": 2,
                "name": "shared credentials",
                "siteAssignment": "specific-sites",
                "sites": [
                    1
                ]
            },
            {
                "account": {
                    "permissionElevation": "sudosu",
                    "permissionElevationUsername": "test",
                    "service": "ssh",
                    "username": "test"
                },
                "id": 3,
                "name": "shared credentials",
                "siteAssignment": "specific-sites",
                "sites": [
                    1
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Nexpose Shared Credentials
>| Id  |Name|Service|UserName|AvailableToSites|
-----|---|---|---|---|---|
>| 1 | shared credentials | snmpv3 | test | 1 |
>| 2 | shared credentials | as400 | test | 1 |
>| 3 | shared credentials | ssh | test | 1 |


### nexpose-list-site-scan-credential
***
Retrieve information about all or a specific sca credential.


#### Base Command

`nexpose-list-site-scan-credential`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site_id`). | Optional | 
| credential_id | ID of a specific scan credential to retrieve. | Optional | 
| limit | A number of records to limit the response to. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.SiteScanCredential.account.authenticationType | string | SNMPv3 authentication type for the credential. | 
| Nexpose.SiteScanCredential.account.communityName | string | SNMP community for authentication. | 
| Nexpose.SiteScanCredential.account.database | string | Database name. | 
| Nexpose.SiteScanCredential.account.domain | string | Domain address. | 
| Nexpose.SiteScanCredential.account.enumerateSids | boolean | Whether the scan engine should attempt to enumerate SIDs from the environment. | 
| Nexpose.SiteScanCredential.account.notesIDPassword | string | Password for the notes account that will be used for authenticating. | 
| Nexpose.SiteScanCredential.account.ntlmHash | string | NTLM password hash. | 
| Nexpose.SiteScanCredential.account.oracleListenerPassword | string | The Oracle Net Listener password. Used to enumerate SIDs from the environment. | 
| Nexpose.SiteScanCredential.account.password | string | Password for the credential. | 
| Nexpose.SiteScanCredential.account.pemKey | string | PEM formatted private key. | 
| Nexpose.SiteScanCredential.account.permissionElevation | string | Elevation type to use for scans. | 
| Nexpose.SiteScanCredential.account.permissionElevationPassword | string | Password to use for elevation. | 
| Nexpose.SiteScanCredential.account.permissionElevationUserName | string | Username to use for elevation. | 
| Nexpose.SiteScanCredential.account.privacyPassword | string | SNMPv3 privacy password to use. | 
| Nexpose.SiteScanCredential.account.privacyType | string | SNMPv3 Privacy protocol to use. | 
| Nexpose.SiteScanCredential.account.privateKeyPassword | string | Password for the private key. | 
| Nexpose.SiteScanCredential.account.realm | string | HTTP realm. | 
| Nexpose.SiteScanCredential.account.service | string | Credential service type. | 
| Nexpose.SiteScanCredential.account.sid | string | Oracle database name. | 
| Nexpose.SiteScanCredential.account.useWindowsAuthentication | boolean | Whether to use Windows authentication. | 
| Nexpose.SiteScanCredential.account.username | string | Username for the credential. | 
| Nexpose.SiteScanCredential.description | string | Description for the credential. | 
| Nexpose.SiteScanCredential.hostRestriction | string | Hostname or IP address to restrict the credentials to. | 
| Nexpose.SiteScanCredential.id | number | ID of the credential. | 
| Nexpose.SiteScanCredential.name | string | Name of the credential. | 
| Nexpose.SiteScanCredential.portRestriction | number | Further restricts the credential to attempt to authenticate on a specific port. Can be used only if \`host_restriction\` is used. | 

#### Command example
```!nexpose-list-site-scan-credential site_id=1 limit=3```
#### Human Readable Output

>No site scan credentials were found for site "1".

### nexpose-list-vulnerability-exceptions
***
Retrieve information about scan schedules for a specific site or a specific scan schedule


#### Base Command

`nexpose-list-vulnerability-exceptions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the vulnerability exception to retrieve. If not set, all vulnerability exceptions. | Optional | 
| page_size | Number of records to retrieve in each API call when pagination is used. | Optional | 
| page | A specific page to retrieve when pagination is used. | Optional | 
| sort | Criteria to sort the records by, in the format: property[,ASC\|DESC]. If not specified, default sort order is ascending. Multiple sort criteria can be specified, separated by a ';'. For example: 'riskScore,DESC;hostName,ASC'. Default is submit.date,ASC. | Optional | 
| limit | A number of records to limit the response to. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.VulnerabilityException.expires | string | The date and time the vulnerability exception is set to expire. | 
| Nexpose.VulnerabilityException.id | int | The The identifier of the vulnerability exception. | 
| Nexpose.VulnerabilityException.scope.id | int | The identifier of the vulnerability to which the exception applies. | 
| Nexpose.VulnerabilityException.scope.key | string | If the scope type is "Instance", an optional key to discriminate the instance the exception applies to. | 
| Nexpose.VulnerabilityException.scope.port | int | If the scope type is "Instance" and the vulnerability is detected on a service, the port on which the exception applies. | 
| Nexpose.VulnerabilityException.scope.type | string | The type of the exception scope. One of: "Global", "Site", "Asset", "Asset Group", "Instance" | 
| Nexpose.VulnerabilityException.scope.vulnerability | string | The identifier of the vulnerability to which the exception applies. | 
| Nexpose.VulnerabilityException.state | string | The state of the vulnerability exception. One of: "Deleted", "Expired", "Approved", "Rejected", \`"Under Review". | 
| Nexpose.VulnerabilityException.submit.comment | string | A comment from the submitter as to why the exception was submitted. | 
| Nexpose.VulnerabilityException.submit.date | string | The date and time the vulnerability exception was submitted. | 
| Nexpose.VulnerabilityException.submit.name | string | The login name of the user that submitted the vulnerability exception. | 
| Nexpose.VulnerabilityException.submit.reason | string | The reason the vulnerability exception was submitted. One of: "False Positive", "Compensating Control", "Acceptable Use", "Acceptable Risk", "Other" | 
| Nexpose.VulnerabilityException.submit.user | int | The identifier of the user that submitted the vulnerability exception. | 

#### Command example
```!nexpose-list-vulnerability-exceptions sort="submit.date,ASC"```
#### Context Example
```json
{
    "Nexpose": {
        "VulnerabilityException": [
            {
                "expires": "2028-03-01T04:31:56Z",
                "id": 2,
                "review": {
                    "comment": "Auto approved by submitter.",
                    "date": "2022-10-31T14:39:15.736Z",
                    "name": "nxadmin",
                    "user": 1
                },
                "scope": {
                    "type": "global",
                    "vulnerability": "tlsv1_0-enabled"
                },
                "state": "approved",
                "submit": {
                    "date": "2022-06-29T16:10:06.616880Z",
                    "name": "nxadmin",
                    "reason": "false positive",
                    "user": 1
                }
            },
            {
                "id": 4,
                "review": {
                    "date": "2022-10-30T13:54:31.084Z",
                    "name": "nxadmin",
                    "user": 1
                },
                "scope": {
                    "type": "global",
                    "vulnerability": "php-cve-2018-10545"
                },
                "state": "rejected",
                "submit": {
                    "date": "2022-07-13T13:27:31.647402Z",
                    "name": "nxadmin",
                    "reason": "acceptable use",
                    "user": 1
                }
            },
            {
                "id": 5,
                "scope": {
                    "type": "global",
                    "vulnerability": "cifs-smb-signing-disabled"
                },
                "state": "under review",
                "submit": {
                    "date": "2022-10-27T11:40:34.109268Z",
                    "name": "nxadmin",
                    "reason": "acceptable use",
                    "user": 1
                }
            },
            {
                "id": 6,
                "scope": {
                    "type": "global",
                    "vulnerability": "apache-httpd-cve-2017-3167"
                },
                "state": "under review",
                "submit": {
                    "date": "2022-10-27T11:42:05.995090Z",
                    "name": "nxadmin",
                    "reason": "acceptable use",
                    "user": 1
                }
            },
            {
                "id": 7,
                "review": {
                    "comment": "Auto approved by submitter.",
                    "date": "2022-10-27T11:55:14.550Z",
                    "name": "nxadmin",
                    "user": 1
                },
                "scope": {
                    "id": 1,
                    "type": "asset group",
                    "vulnerability": "apache-httpd-cve-2009-1195"
                },
                "state": "approved",
                "submit": {
                    "date": "2022-10-27T11:55:14.539218Z",
                    "name": "nxadmin",
                    "reason": "false positive",
                    "user": 1
                }
            },
            {
                "id": 8,
                "review": {
                    "comment": "Auto approved by submitter.",
                    "date": "2022-10-27T11:57:31.969Z",
                    "name": "nxadmin",
                    "user": 1
                },
                "scope": {
                    "id": 3,
                    "type": "asset group",
                    "vulnerability": "certificate-common-name-mismatch"
                },
                "state": "approved",
                "submit": {
                    "date": "2022-10-27T11:57:31.955017Z",
                    "name": "nxadmin",
                    "reason": "acceptable use",
                    "user": 1
                }
            },
            {
                "id": 9,
                "scope": {
                    "id": 1,
                    "type": "site",
                    "vulnerability": "apache-httpd-cve-2017-3167"
                },
                "state": "under review",
                "submit": {
                    "date": "2022-10-27T12:04:12.622393Z",
                    "name": "nxadmin",
                    "reason": "acceptable use",
                    "user": 1
                }
            },
            {
                "id": 10,
                "scope": {
                    "id": 3,
                    "type": "asset group",
                    "vulnerability": "apache-httpd-cve-2017-3167"
                },
                "state": "under review",
                "submit": {
                    "date": "2022-10-27T12:04:49.768889Z",
                    "name": "nxadmin",
                    "reason": "acceptable use",
                    "user": 1
                }
            },
            {
                "id": 11,
                "review": {
                    "comment": "Auto approved by submitter.",
                    "date": "2022-10-30T09:21:40.349Z",
                    "name": "nxadmin",
                    "user": 1
                },
                "scope": {
                    "id": 1,
                    "type": "site",
                    "vulnerability": "apache-httpd-cve-2010-1452"
                },
                "state": "approved",
                "submit": {
                    "date": "2022-10-30T09:21:40.345560Z",
                    "name": "nxadmin",
                    "reason": "other",
                    "user": 1
                }
            },
            {
                "id": 13,
                "review": {
                    "comment": "Auto approved by submitter.",
                    "date": "2022-10-30T09:39:43.162Z",
                    "name": "nxadmin",
                    "user": 1
                },
                "scope": {
                    "id": 15,
                    "type": "asset",
                    "vulnerability": "apache-httpd-cve-2010-1623"
                },
                "state": "approved",
                "submit": {
                    "date": "2022-10-30T09:39:43.151066Z",
                    "name": "nxadmin",
                    "reason": "other",
                    "user": 1
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Nexpose Vulnerability Exceptions
>|Id|Vulnerability|ExceptionScope|Reason|ReportedBy|ReviewStatus|ReviewedOn|ExpiresOn|
>|---|---|---|---|---|---|---|---|
>| 2 | tlsv1_0-enabled | global | false positive | nxadmin | approved | 2022-10-31T14:39:15.736Z | 2028-03-01T04:31:56Z |
>| 4 | php-cve-2018-10545 | global | acceptable use | nxadmin | rejected | 2022-10-30T13:54:31.084Z |  |
>| 5 | cifs-smb-signing-disabled | global | acceptable use | nxadmin | under review |  |  |
>| 6 | apache-httpd-cve-2017-3167 | global | acceptable use | nxadmin | under review |  |  |
>| 7 | apache-httpd-cve-2009-1195 | asset group | false positive | nxadmin | approved | 2022-10-27T11:55:14.550Z |  |
>| 8 | certificate-common-name-mismatch | asset group | acceptable use | nxadmin | approved | 2022-10-27T11:57:31.969Z |  |
>| 9 | apache-httpd-cve-2017-3167 | site | acceptable use | nxadmin | under review |  |  |
>| 10 | apache-httpd-cve-2017-3167 | asset group | acceptable use | nxadmin | under review |  |  |
>| 11 | apache-httpd-cve-2010-1452 | site | other | nxadmin | approved | 2022-10-30T09:21:40.349Z |  |
>| 13 | apache-httpd-cve-2010-1623 | asset | other | nxadmin | approved | 2022-10-30T09:39:43.162Z |  |


### nexpose-start-site-scan
***
Starts a scan for the specified site.


#### Base Command

`nexpose-start-site-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site`). | Optional | 
| hosts | Hosts that should be included as a part of the scan. Can an IP Addresses or a hostname. Can be a comma-separated list. | Optional | 
| name | Scan name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Scan.Id | number | The identifier of the scan. | 
| Nexpose.Scan.ScanType | string | The scan type \(automated, manual, scheduled\). | 
| Nexpose.Scan.StartedBy | date | The name of the user that started the scan. | 
| Nexpose.Scan.Assets | number | The number of assets found in the scan | 
| Nexpose.Scan.TotalTime | string | The duration of the scan in minutes. | 
| Nexpose.Scan.Completed | date | The end time of the scan in ISO8601 format. | 
| Nexpose.Scan.Status | string | The scan status. Valid values are aborted, unknown, running, finished, stopped, error, paused, dispatched, integrating | 
| Nexpose.Scan.Vulnerabilities.Critical | number | The number of critical vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Moderate | number | The number of moderate vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Severe | number | The number of severe vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Total | number | The total number of vulnerabilities. | 

### nexpose-start-assets-scan
***
Starts a scan for specified asset IP addresses and host names.


#### Base Command

`nexpose-start-assets-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| IPs | IP addresses of assets to scan. Can be a comma-separated list. | Optional | 
| hostNames | Hostnames of assets to scan. Can be a comma-separated list. | Optional | 
| name | Scan name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Scan.Id | number | The identifier of the scan. | 
| Nexpose.Scan.ScanType | string | The scan type \(automated, manual, scheduled\). | 
| Nexpose.Scan.StartedBy | date | The name of the user that started the scan. | 
| Nexpose.Scan.Assets | number | The number of assets found in the scan | 
| Nexpose.Scan.TotalTime | string | The duration of the scan in minutes. | 
| Nexpose.Scan.Completed | date | The end time of the scan in ISO8601 format. | 
| Nexpose.Scan.Status | string | The scan status. Valid values are aborted, unknown, running, finished, stopped, error, paused, dispatched, integrating | 
| Nexpose.Scan.Vulnerabilities.Critical | number | The number of critical vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Moderate | number | The number of moderate vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Severe | number | The number of severe vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Total | number | The total number of vulnerabilities. | 

### nexpose-stop-scan
***
Stop a running scan.


#### Base Command

`nexpose-stop-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of a running scan. | Required | 


### nexpose-pause-scan
***
Pause a running scan.


#### Base Command

`nexpose-pause-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of a running scan. | Required | 


### nexpose-resume-scan
***
Resume a paused scan.


#### Base Command

`nexpose-resume-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of a paused scan. | Required | 


### nexpose-get-scans
***
Return a list of scans. Returns only active scans by default (active=true).


#### Base Command

`nexpose-get-scans`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| active | Whether to return only active scans or not. Possible values are: true, false. Default is true. | Optional | 
| page_size | Number of records to retrieve in each API call when pagination is used. | Optional | 
| page | A specific page to retrieve when pagination is used. | Optional | 
| limit | A number of records to limit the response to. Default is 10. | Optional | 
| sort | Criteria to sort the records by, in the format: property[,ASC\|DESC]. If not specified, default sort order is ascending. Multiple sort criteria can be specified, separated by a ';'. For example: 'riskScore,DESC;hostName,ASC'. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Scan.Id | number | The identifier of the scan. | 
| Nexpose.Scan.ScanType | string | The scan type \(automated, manual, scheduled\). | 
| Nexpose.Scan.StartedBy | date | The name of the user that started the scan. | 
| Nexpose.Scan.Assets | number | The number of assets found in the scan | 
| Nexpose.Scan.TotalTime | string | The duration of the scan in minutes. | 
| Nexpose.Scan.Completed | date | The end time of the scan in ISO8601 format. | 
| Nexpose.Scan.Status | string | The scan status. Valid values are aborted, unknown, running, finished, stopped, error, paused, dispatched, integrating | 

#### Command example
```!nexpose-get-scans active=false limit=3```
#### Context Example
```json
{
    "Nexpose": {
        "Scan": [
            {
                "Assets": 0,
                "Completed": "2019-12-03T20:48:01.368Z",
                "Id": 1,
                "ScanName": "Tue 03 Dec 2019 10:47 PM",
                "ScanType": "Manual",
                "Status": "finished",
                "TotalTime": "51.316 seconds",
                "engineId": 3,
                "engineName": "Local scan engine",
                "siteId": 1,
                "siteName": "Test",
                "startTime": "2019-12-03T20:47:10.052Z",
                "startedByUsername": "N/A",
                "vulnerabilities": {
                    "critical": 0,
                    "moderate": 0,
                    "severe": 0,
                    "total": 0
                }
            },
            {
                "Assets": 0,
                "Completed": "2019-12-03T20:53:09.453Z",
                "Id": 2,
                "ScanName": "Tue 03 Dec 2019 10:52 PM",
                "ScanType": "Manual",
                "Status": "finished",
                "TotalTime": "29.91 seconds",
                "engineId": 3,
                "engineName": "Local scan engine",
                "siteId": 1,
                "siteName": "Test",
                "startTime": "2019-12-03T20:52:39.543Z",
                "startedByUsername": "N/A",
                "vulnerabilities": {
                    "critical": 0,
                    "moderate": 0,
                    "severe": 0,
                    "total": 0
                }
            },
            {
                "Assets": 0,
                "Completed": "2019-12-03T21:01:33.970Z",
                "Id": 3,
                "ScanName": "scan 2019-12-03 19:58:25.961787",
                "ScanType": "Manual",
                "Status": "finished",
                "TotalTime": "28.904 seconds",
                "engineId": 3,
                "engineName": "Local scan engine",
                "siteId": 1,
                "siteName": "Test",
                "startTime": "2019-12-03T21:01:05.066Z",
                "startedByUsername": "N/A",
                "vulnerabilities": {
                    "critical": 0,
                    "moderate": 0,
                    "severe": 0,
                    "total": 0
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Nexpose scans
>|Id|ScanType|ScanName|Assets|TotalTime|Completed|Status|
>|---|---|---|---|---|---|---|
>| 1 | Manual | Tue 03 Dec 2019 10:47 PM | 0 | 51.316 seconds | 2019-12-03T20:48:01.368Z | finished |
>| 2 | Manual | Tue 03 Dec 2019 10:52 PM | 0 | 29.91 seconds | 2019-12-03T20:53:09.453Z | finished |
>| 3 | Manual | scan 2019-12-03 19:58:25.961787 | 0 | 28.904 seconds | 2019-12-03T21:01:33.970Z | finished |


### nexpose-disable-shared-credential
***
Disable an assigned shared credential.


#### Base Command

`nexpose-disable-shared-credential`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site_id`). | Optional | 
| credential_id | ID of the scan schedule to update. | Required | 


### nexpose-download-report
***
Returns the generated report.


#### Base Command

`nexpose-download-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | ID of the report. | Required | 
| instance_id | ID of the report instance. Supports a "latest" value. keyword. | Required | 
| name | Report name. | Optional | 
| format | Report format (uses PDF by default). Possible values are: pdf, rtf, xml, html, text, nexpose-simple-xml. Default is pdf. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryId | string | Entry ID of the report file. | 
| InfoFile.Name | string | Name of the report file. | 
| InfoFile.Extension | string | File extension of the report file. | 
| InfoFile.Info | string | Information about the report file. | 
| InfoFile.Size | number | Size of the report file \(in bytes\). | 
| InfoFile.Type | string | Type of the report file. | 

#### Command example
```!nexpose-download-report report_id=1 instance_id=latest```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "2324@403762e2-be4e-4f12-8a17-26cdb21b129e",
        "Extension": "pdf",
        "Info": "application/pdf",
        "Name": "report 2022-11-10 10:52:56.050804.pdf",
        "Size": 76699,
        "Type": "PDF document, version 1.4"
    }
}
```

#### Human Readable Output



### nexpose-enable-shared-credential
***
Enable an assigned shared credential.


#### Base Command

`nexpose-enable-shared-credential`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site_id`). | Optional | 
| credential_id | ID of the scan schedule to update. | Required | 


### nexpose-get-report-status
***
Returns the status of a report generation process.


#### Base Command

`nexpose-get-report-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | ID of the report. | Required | 
| instance_id | ID of the report instance. Supports a "latest" value. keyword. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Report.ID | string | The identifier of the report. | 
| Nexpose.Report.InstanceID | string | The identifier of the report instance. | 
| Nexpose.Report.Status | string | The status of the report generation process. Valid values: "aborted", "failed", "complete", "running", "unknown" | 

#### Command example
```!nexpose-get-report-status report_id=1 instance_id=latest```
#### Context Example
```json
{
    "Nexpose": {
        "Report": {
            "ID": "1",
            "InstanceID": "latest",
            "Status": "complete"
        }
    }
}
```

#### Human Readable Output

>### Report Generation Status
>|ID|InstanceID|Status|
>|---|---|---|
>| 1 | latest | complete |


### nexpose-update-scan-schedule
***
Update an existing site scan schedule.


#### Base Command

`nexpose-update-scan-schedule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site_id`). | Optional | 
| schedule_id | ID of the scan schedule to update. | Optional | 
| enabled | A flag indicating whether the scheduled scan is enabled or not. Possible values are: True, False. Default is True. | Optional | 
| on_scan_repeat | The desired behavior of a repeating scheduled scan when the previous scan was paused due to reaching its maximum duration. Possible values are: Restart-Scan, Resume-Scan. | Required | 
| start | The scheduled start date and time formatted in ISO 8601 format. Repeating schedules will determine the next schedule to begin based on this date and time. | Required | 
| excluded_asset_group_ids | A list of ids for asset groups to exclude from the scan. | Optional | 
| excluded_addresses | A list of addresses to exclude from the scan. | Optional | 
| included_asset_group_ids | A list of ids for asset groups to include in the scan. | Optional | 
| included_addresses | A list of addresses to include in the scan. | Optional | 
| duration_days | Maximum duration of the scan in days. | Optional | 
| duration_hours | Maximum duration of the scan in hours. | Optional | 
| duration_minutes | Maximum duration of the scan in minutes. | Optional | 
| frequency | How frequent should the schedule to repeat (Every...). Possible values are: Hour, Day, Week, Date-of-month. | Optional | 
| interval_time | The interval time the schedule should repeat. This depends on the value set in `frequency`. For example, if the value of `frequency` is set to "Day" and `interval` is set to 2, then the schedule will repeat every 2 days. Required only if frequency is used. | Optional | 
| date_of_month | Specifies the schedule repeat day of the interval month. For example, if `date_of_month` is 17 and `interval` is set to 2, then the schedule will repeat every 2 months on the 17th day of the month. Required and used only if frequency is set to `Date of month`. | Optional | 
| scan_name | A unique user-defined name for the scan launched by the schedule. If not explicitly set in the schedule, the scan name will be generated prior to the scan launching. | Optional | 
| scan_template | ID of the scan template to use. | Optional | 


### nexpose-update-site-scan-credential
***
Update an existing site scan credential. For detailed explanation of all parameters of this command, please see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/setSiteCredentials


#### Base Command

`nexpose-update-site-scan-credential`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site_id`). | Optional | 
| credential_id | ID of the site scan credential to update. | Required | 
| name | Name of the credential. | Required | 
| service | Credential service type. Possible values are: AS400, CIFS, CIFSHash, CVS, DB2, FTP, HTTP, MS-SQL, MySQL, Notes, Oracle, POP, PostgresSQL, Remote-Exec, SNMP, SNMPv3, SSH, SSH-Key, Sybase, Telnet. | Required | 
| database | Database name. | Optional | 
| description | Description for the credential. | Optional | 
| domain | Domain address. | Optional | 
| host_restriction | Hostname or IP address to restrict the credentials to. | Optional | 
| http_realm | HTTP realm. | Optional | 
| notes_id_password | Password for the notes account that will be used for authenticating. | Optional | 
| ntlm_hash | NTLM password hash. | Optional | 
| oracle_enumerate_sids | Whether the scan engine should attempt to enumerate SIDs from the environment. Possible values are: true, false. | Optional | 
| oracle_listener_password | Oracle Net Listener password. Used to enumerate SIDs from your environment. | Optional | 
| oracle_sid | Oracle database name. | Optional | 
| password | Password for the credential. | Optional | 
| port_restriction | Further restricts the credential to attempt to authenticate on a specific port. Can be used only if `host_restriction` is used. | Optional | 
| community_name | SNMP community for authentication. | Optional | 
| authentication_type | SNMPv3 authentication type for the credential. Possible values are: No-Authentication, MD5, SHA. | Optional | 
| privacy_password | SNMPv3 privacy password to use. | Optional | 
| privacy_type | SNMPv3 Privacy protocol to use. Possible values are: No-Privacy, DES, AES-128, AES-192, AES-192-With-3-DES-Key-Extension, AES-256, AES-256-With-3-DES-Key-Extension. | Optional | 
| ssh_key_pem | PEM formatted private key. | Optional | 
| ssh_permission_elevation | Elevation type to use for scans. Possible values are: None, sudo, sudosu, su, pbrun, Privileged Exec. | Optional | 
| ssh_permission_elevation_password | Password to use for elevation. | Optional | 
| ssh_permission_elevation_username | Username to use for elevation. | Optional | 
| ssh_private_key_password | Password for the private key. | Optional | 
| use_windows_authentication | Whether to use Windows authentication. Possible values are: true, false. | Optional | 
| username | Username for the credential. | Optional | 


### nexpose-update-vulnerability-exception-expiration
***
Update an existing vulnerability exception.


#### Base Command

`nexpose-update-vulnerability-exception-expiration`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the vulnerability exception to update. | Required | 
| expiration | An expiration date for the vulnerability exception formatted in ISO 8601 format. Must be a date in the future. | Required | 


#### Command example
```!nexpose-update-vulnerability-exception-expiration id=12 expiration=2024-10-10T10:00:00Z```
#### Human Readable Output

>Successfully updated expiration date of vulnerability exception 1.

### nexpose-update-vulnerability-exception-status
***
Update an existing vulnerability exception.


#### Base Command

`nexpose-update-vulnerability-exception-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the vulnerability exception to update. | Required | 
| status | A status to update the vulnerability exception to. Possible values are: Recall, Approve, Reject. | Required | 


#### Command example
```!nexpose-update-vulnerability-exception-status id=1 status=Approve```
#### Human Readable Output

>Successfully updated status of vulnerability exception 1.

### nexpose-update-shared-credential
***
Update an existing shared credential.


#### Base Command

`nexpose-update-shared-credential`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the shared credential to update. | Required | 
| name | Name of the credential. | Required | 
| site_assignment | Site assignment configuration for the credential. Assign the shared scan credential either to be available to all sites, or a specific list of sites. Possible values are: All-Sites, Specific-Sites. | Required | 
| service | Credential service type. Possible values are: AS400, CIFS, CIFSHash, CVS, DB2, FTP, HTTP, MS-SQL, MySQL, Notes, Oracle, POP, PostgresSQL, Remote-Exec, SNMP, SNMPv3, SSH, SSH-Key, Sybase, Telnet. | Required | 
| database | Database name. | Optional | 
| description | Description for the credential. | Optional | 
| domain | Domain address. | Optional | 
| host_restriction | Hostname or IP address to restrict the credentials to. | Optional | 
| http_realm | HTTP realm. | Optional | 
| notes_id_password | Password for the notes account that will be used for authenticating. | Optional | 
| ntlm_hash | NTLM password hash. | Optional | 
| oracle_enumerate_sids | Whether the scan engine should attempt to enumerate SIDs from the environment. Possible values are: true, false. | Optional | 
| oracle_listener_password | Oracle Net Listener password. Used to enumerate SIDs from your environment. | Optional | 
| oracle_sid | Oracle database name. | Optional | 
| password | Password for the credential. | Optional | 
| port_restriction | Further restricts the credential to attempt to authenticate on a specific port. Can be used only if `host_restriction` is used. | Optional | 
| sites | List of site IDs for the shared credential that are explicitly assigned access to the shared scan credential, allowing it to use the credential during a scan. | Optional | 
| community_name | SNMP community for authentication. | Optional | 
| authentication_type | SNMPv3 authentication type for the credential. Possible values are: No-Authentication, MD5, SHA. | Optional | 
| privacy_password | SNMPv3 privacy password to use. | Optional | 
| privacy_type | SNMPv3 Privacy protocol to use. Possible values are: No-Privacy, DES, AES-128, AES-192, AES-192-With-3-DES-Key-Extension, AES-256, AES-256-With-3-DES-Key-Extension. | Optional | 
| ssh_key_pem | PEM formatted private key. | Optional | 
| ssh_permission_elevation | Elevation type to use for scans. Possible values are: None, sudo, sudosu, su, pbrun, Privileged-Exec. | Optional | 
| ssh_permission_elevation_password | Password to use for elevation. | Optional | 
| ssh_permission_elevation_username | Username to use for elevation. | Optional | 
| ssh_private_key_password | Password for the private key. | Optional | 
| use_windows_authentication | Whether to use Windows authentication. Possible values are: true, false. | Optional | 
| username | Username for the credential. | Optional | 

