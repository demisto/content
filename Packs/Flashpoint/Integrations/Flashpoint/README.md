Use the Flashpoint integration to access intelligence reports, technical data, and uniquely sourced conversations from illicit threat communities.

## Configure Flashpoint on Demisto

1.  Navigate to **Settings** > **Integrations** > **Servers & Services**.
2.  Search for Flashpoint.
3.  Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Example** |
    | ---------             | -----------           | -------            |
    | Name | A meaningful name for the integration instance. | Flashpoint_instance_1 |
    | URL  | The URL to the Flashpoint server, including the scheme.  |  https:/<span></span>/fp.tools |
    | API Key  |  Your Flashpoint API key. | N/A  |
    | Trust any certificate (not secure)  | When selected, certificates are not checked. | N/A |
    | Use system proxy settings |  Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration. |  https:/<span></span>/proxyserver.com |

4.  Click **Test** to validate the new instance.

## Commands

You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Get the reputation of an IP

* * *

Returns the reputation of an IP. The IP is considered malicious if there’s at least one IOC event in the Flashpoint database matching the IP indicator. The IP address is considered suspicious if it matches with any one of the torrent’s peer IP address or forum visit’s peer IP address.

##### Base Command

`ip`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP to check whether it is malicious or suspicious. | Optional |

##### 
Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. |
| DBotScore.Score | number | The indicator score. |
| DBotScore.Type | string | The indicator type. |
| DBotScore.Vendor | string | The vendor used to calculate the score. |
| IP.Address | string | The IP address. |
| IP.Malicious.Description | string | The description of the malicious IP. |
| IP.Malicious.Vendor | string | The vendor of the malicious IP. |
| Flashpoint.IP.Event.Href | string | The list of the reference link of the indicator. |
| Flashpoint.IP.Event.Address | string | The IP address of the indicator. |
| Flashpoint.IP.Event.EventDetails | Unknown | The event details in which the indicator is observed. |
| Flashpoint.IP.Event.Category | string | The category of the indicator. |
| Flashpoint.IP.Event.Fpid | string | The FPID of the indicator. |
| Flashpoint.IP.Event.Timestamp | string | The time at which the indicator is observed. |
| Flashpoint.IP.Event.Type | string | The type of the indicator. |
| Flashpoint.IP.Event.Uuid | string | The UUID of the indicator. |
| Flashpoint.IP.Event.Comment | string | The comment which was provided when the indicator was observed. |

##### Command Example
```
!ip ip="210.122.7.129"
```

##### Context Example
```
{
    "DBotScore": {
        "Indicator": "210.122.7.129",
        "Score": 3,
        "Type": "ip",
        "Vendor": "Flashpoint"
    },
    "Flashpoint.IP.Event": [
        {
            "Address": "210.122.7.129",
            "Category": "Network activity",
            "Comment": "",
            "EventDetails": {
                "RelatedEvent": null,
                "Tags": [
                    "source:OSINT"
                ],
                "attack_ids": null,
                "fpid": "4J0I4NojWB2fm8IhKRJ6iw",
                "href": "https://fp.tools/api/v4/indicators/event/4J0I4NojWB2fm8IhKRJ6iw",
                "info": "Lazarus Resurfaces, Targets Global Banks and Bitcoin Users",
                "reports": null,
                "timestamp": "1518471985"
            },
            "Fpid": "KyhpGHc2XYKp2iUESO7ejA",
            "Href": "https://fp.tools/api/v4/indicators/attribute/KyhpGHc2XYKp2iUESO7ejA",
            "Timestamp": "1518471985",
            "Type": "ip-dst",
            "Uuid": "5a820b31-3894-4ed9-bd2a-29d6ac110002"
        }
    ],
    "IP": {
        "Address": "210.122.7.129",
        "Malicious": {
            "Description": "Found in malicious indicators dataset",
            "Vendor": "Flashpoint"
        }
    }
}
```

##### Human Readable Output

##### Flashpoint IP address reputation for 210.122.7.129

Reputation: Malicious

##### Events in which this IOC observed

| **Date Observed (UTC)** | **Name** | **Tags** |
| --- | --- | --- |
| Feb 12, 2018 21:46 | Lazarus Resurfaces, Targets Global Banks and Bitcoin Users | source:OSINT |

All events and details (fp-tools):
https:/<span></span>/fp.tools/home/search/iocs?group=indicator&ioc_type=ip-dst%2Cip-src&ioc_value=210.122.7.129

### Get the reputation of a domain

* * *

Returns the reputation of a domain. The domain is considered malicious if there’s at least one IOC event in the Flashpoint database matching the domain indicator.

##### Base Command

`domain`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain name to check. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. |
| DBotScore.Score | number | The indicator score. |
| DBotScore.Type | string | The indicator type. |
| DBotScore.Vendor | string | The vendor used to calculate the score. |
| Flashpoint.Domain.Event.Href | string | A list of reference links for the indicator. |
| Flashpoint.Domain.Event.Domain | string | The domain of the indicator. |
| Flashpoint.Domain.Event.EventDetails | unknown | The event details in which the indicator is observed. |
| Flashpoint.Domain.Event.Category | string | The category of the indicator. |
| Flashpoint.Domain.Event.Fpid | string | The FPID of the indicator. |
| Flashpoint.Domain.Event.Timestamp | string | The time at which the indicator is observed. |
| Flashpoint.Domain.Event.Type | string | The type of the indicator. |
| Flashpoint.Domain.Event.Uuid | string | The UUID of the indicator. |
| Flashpoint.Domain.Event.Comment | string | The comment that was provided when the indicator was observed. |
| Domain.Malicious.Description | string | The description of the malicious indicator. |
| Domain.Malicious.Vendor | string | The vendor of the malicious indicator. |
| Domain.Name | string | The name of the domain. |

##### Command Example
```
!domain domain="subaat.com"
```

##### Context Example
```
{
    "DBotScore": {
        "Indicator": "subaat.com",
        "Score": 3,
        "Type": "domain",
        "Vendor": "Flashpoint"
    },
    "Domain": {
        "Malicious": {
            "Description": "Found in malicious indicators dataset",
            "Vendor": "Flashpoint"
        },
        "Name": "subaat.com"
    },
    "Flashpoint.Domain.Event": [
        {
            "Category": "Network activity",
            "Comment": "",
            "Domain": "subaat.com",
            "EventDetails": {
                "RelatedEvent": null,
                "Tags": [
                    "misp-galaxy:mitre-enterprise-attack-attack-pattern=\"Spearphishing Attachment - T1193\"",
                    "misp-galaxy:mitre-enterprise-attack-attack-pattern=\"Scripting - T1064\"",
                    "misp-galaxy:mitre-enterprise-attack-attack-pattern=\"Command-Line Interface - T1059\"",
                    "misp-galaxy:mitre-enterprise-attack-attack-pattern=\"System Information Discovery - T1082\"",
                    "misp-galaxy:mitre-enterprise-attack-attack-pattern=\"Remote Services - T1021\"",
                    "misp-galaxy:mitre-enterprise-attack-attack-pattern=\"Exfiltration Over Command and Control Channel - T1041\"",
                    "os:Windows",
                    "source:phishing",
                    "type:RAT",
                    "malware:rat:Quasar",
                    "malware:banker:Lokibot",
                    "file_name: njrat.exe",
                    "file_name: excel_.exe"
                ],
                "attack_ids": [
                    "T1193",
                    "T1064",
                    "T1059",
                    "T1082",
                    "T1021",
                    "T1041"
                ],
                "fpid": "xTcVdG3mU2ayoTZATFTqJQ",
                "href": "https://fp.tools/api/v4/indicators/event/xTcVdG3mU2ayoTZATFTqJQ",
                "info": "Gorgon Group actor profile",
                "reports": null,
                "timestamp": "1569441099"
            },
            "Fpid": "ua5eL6q5W5CTmYcmAhS0XQ",
            "Href": "https://fp.tools/api/v4/indicators/attribute/ua5eL6q5W5CTmYcmAhS0XQ",
            "Timestamp": "1569436997",
            "Type": "domain",
            "Uuid": "5d8bb545-7ef0-4463-9595-02bac9bb0799"
        }
    ]
}
```

##### Human Readable Output

##### Flashpoint Domain reputation for subaat<span></span>.com

Reputation: Malicious

##### Events in which this IOC observed

| **Date Observed (UTC)** | **Name** | **Tags** |
| --- | --- | --- |
| Sep 25, 2019 19:51 | Gorgon Group actor profile | misp-galaxy:mitre-enterprise-attack-attack-pattern=“Spearphishing Attachment - T1193”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“Scripting - T1064”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“Command-Line Interface - T1059”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“System Information Discovery - T1082”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“Remote Services - T1021”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“Exfiltration Over Command and Control Channel - T1041”, os:Windows, source:phishing, type:RAT, malware:rat:Quasar, malware:banker:Lokibot, file_name: njrat.exe, file_name: excel_.exe |

All events and details (fp-tools):
https:/<span></span>/fp.tools/home/search/iocs?group=indicator&ioc_type=domain&ioc_value=subaat<span></span>.com

### Get the reputation of the filename

* * *

Returns the reputation of the filename. The filename is considered malicious if there’s at least one IOC event in the Flashpoint database matching the filename indicator.

##### Base Command

`filename`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filename | The filename to check. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. |
| DBotScore.Score | number | The indicator score. |
| DBotScore.Type | string | The indicator type. |
| DBotScore.Vendor | string | The vendor used to calculate the score. |
| Flashpoint.Filename.Event.Href | string | A list of reference links for the indicator. |
| Flashpoint.Filename.Event.Filename | string | The filename of the indicator. |
| Flashpoint.Filename.Event.EventDetails | unknown | The event details in which the indicator is observed. |
| Flashpoint.Filename.Event.Category | string | The category of the indicator. |
| Flashpoint.Filename.Event.Fpid | string | The FPID of the indicator. |
| Flashpoint.Filename.Event.Timestamp | string | The time at which the indicator is observed. |
| Flashpoint.Filename.Event.Type | string | The type of the indicator. |
| Flashpoint.Filename.Event.Uuid | string | The UUID of the indicator. |
| Flashpoint.Filename.Event.Comment | string | The comment which was provided when the indicator was observed. |

##### Command Example
```
!filename filename=".locked"
```

##### Context Example
```
{
    "DBotScore": {
        "Indicator": ".locked",
        "Score": 3,
        "Type": "filename",
        "Vendor": "Flashpoint"
    },
    "Filename": {
        "Malicious": {
            "Description": "Found in malicious indicators dataset",
            "Vendor": "Flashpoint"
        },
        "Name": ".locked"
    },
    "Flashpoint.Filename.Event": [
        {
            "Category": "Artifacts dropped",
            "Comment": "",
            "EventDetails": {
                "RelatedEvent": null,
                "Tags": [
                    "malware:ransomware:lockergoga",
                    "report:lKyimEX1TWS8x6AtdiJ_vA",
                    "report:jEteM4YxQZCdm4macbE3vQ",
                    "report:w0fL5MgoQ_Wih8XyB6Lowg",
                    "report:7t-BsuFKTL-HJWbid8nupg"
                ],
                "attack_ids": null,
                "fpid": "iBUPRQOoU4SQrH64LGUbzw",
                "href": "https://fp.tools/api/v4/indicators/event/iBUPRQOoU4SQrH64LGUbzw",
                "info": "LockerGoga",
                "reports": [
                    "https://fp.tools/home/intelligence/reports/report/lKyimEX1TWS8x6AtdiJ_vA",
                    "https://fp.tools/home/intelligence/reports/report/jEteM4YxQZCdm4macbE3vQ",
                    "https://fp.tools/home/intelligence/reports/report/w0fL5MgoQ_Wih8XyB6Lowg",
                    "https://fp.tools/home/intelligence/reports/report/7t-BsuFKTL-HJWbid8nupg"
                ],
                "timestamp": "1571934618"
            },
            "Filename": ".locked",
            "Fpid": "nFIUupaMWdSpJQZI03ryZA",
            "Href": "https://fp.tools/api/v4/indicators/attribute/nFIUupaMWdSpJQZI03ryZA",
            "Timestamp": "1553280019",
            "Type": "filename",
            "Uuid": "5c952c13-d048-4741-a769-05cd0a640c05"
        }
    ]
}
```

##### Human Readable Output

##### Flashpoint Filename reputation for .locked

Reputation: Malicious

##### Events in which this IOC observed

| **Date Observed (UTC)** | **Name** | **Tags** |
| --- | --- | --- |
| Oct 24, 2019 16:30 | LockerGoga | malware:ransomware:lockergoga, report:lKyimEX1TWS8x6AtdiJ_vA, report:jEteM4YxQZCdm4macbE3vQ, report:w0fL5MgoQ_Wih8XyB6Lowg, report:7t-BsuFKTL-HJWbid8nupg |

All events and details (fp-tools):
https:/<span></span>/fp.tools/home/search/iocs?group=indicator&ioc_type=filename&ioc_value=.locked

### Get the reputation of the URL

* * *

Returns the reputation of the URL. The URL is considered malicious if there’s at least one IOC event in the Flashpoint database matching the URL indicator.

##### Base Command

`url`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to check. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. |
| DBotScore.Score | number | The indicator score. |
| DBotScore.Type | string | The indicator type. |
| DBotScore.Vendor | string | The vendor used to calculate the score. |
| Flashpoint.Url.Event.Href | string | A list of reference links for the indicator. |
| Flashpoint.Url.Event.Url | string | The URL of the indicator. |
| Flashpoint.Url.Event.EventDetails | unknown | The event details in which the indicator is observed. |
| Flashpoint.Url.Event.Category | string | The category of the indicator. |
| Flashpoint.Url.Event.Fpid | string | The FPID of the indicator. |
| Flashpoint.Url.Event.Timestamp | string | The time at which the indicator is observed. |
| Flashpoint.Url.Event.Type | string | The type of the indicator. |
| Flashpoint.Url.Event.Uuid | string | The UUID of the indicator. |
| Flashpoint.Url.Event.Comment | string | The comment which was provided when the indicator was observed. |
| URL.Malicious.Description | string | The description of the malicious URL. |
| URL.Malicious.Vendor | string | The vendor of the malicious URL. |

##### Command Example
```
!url url="92.63.197.153/krabaldento.exe"
```

##### Context Example
```
{
    "DBotScore": {
        "Indicator": "92.63.197.153/krabaldento.exe",
        "Score": 3,
        "Type": "url",
        "Vendor": "Flashpoint"
    },
    "Flashpoint.URL.Event": [
        {
            "Category": "Network activity",
            "Comment": "Network Indicators",
            "EventDetails": {
                "RelatedEvent": null,
                "Tags": [
                    "malware:ransomware:GandCrab",
                    "report:lKyimEX1TWS8x6AtdiJ_vA",
                    "report:7t-BsuFKTL-HJWbid8nupg"
                ],
                "attack_ids": null,
                "fpid": "tg9pLoOcXzmo36by0whRIA",
                "href": "https://fp.tools/api/v4/indicators/event/tg9pLoOcXzmo36by0whRIA",
                "info": "GandCrab 2019",
                "reports": [
                    "https://fp.tools/home/intelligence/reports/report/lKyimEX1TWS8x6AtdiJ_vA",
                    "https://fp.tools/home/intelligence/reports/report/7t-BsuFKTL-HJWbid8nupg"
                ],
                "timestamp": "1571934622"
            },
            "Fpid": "XEAP2wmHVqaHERj7E23gTg",
            "Href": "https://fp.tools/api/v4/indicators/attribute/XEAP2wmHVqaHERj7E23gTg",
            "Timestamp": "1551736985",
            "Type": "url",
            "Url": "92.63.197.153/krabaldento.exe",
            "Uuid": "5c7da099-fe38-4cc5-a2f5-11200a640c05"
        }
    ],
    "URL": {
        "Malicious": {
            "Description": "Found in malicious indicators dataset",
            "Vendor": "Flashpoint"
        },
        "Name": "92.63.197.153/krabaldento.exe"
    }
}
```

##### Human Readable Output

##### Flashpoint URL reputation for 92.63.197.153/krabaldento.exe

Reputation: Malicious

##### Events in which this IOC observed

| **Date Observed (UTC)** | **Name** | **Tags** |
| --- | --- | --- |
| Oct 24, 2019 16:30 | GandCrab 2019 | malware:ransomware:GandCrab, report:lKyimEX1TWS8x6AtdiJ_vA, report:7t-BsuFKTL-HJWbid8nupg |

All events and details (fp-tools):
https:/<span></span>/fp.tools/home/search/iocs?group=indicator&ioc_type=url&ioc_value=92.63.197.153/krabaldento.exe

### Get the reputation of the file-hash

* * *

Returns the reputation of the file-hash. The file-hash is considered malicious if there’s at least one IOC event in the Flashpoint database matching the file-hash indicator.

##### Base Command

`file`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | A list of hashes of the file to query. Supports MD5, SHA1, and SHA256. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. |
| DBotScore.Score | number | The indicator score. |
| DBotScore.Type | string | The indicator type. |
| DBotScore.Vendor | string | The vendor used to calculate the score. |
| Flashpoint.File.Event.Href | string | A list of reference links for the indicator. |
| Flashpoint.File.Event.MD5 | string | The MD5 file hash of the indicator. |
| Flashpoint.File.Event.SHA1 | string | The SHA1 file hash of the indicator. |
| Flashpoint.File.Event.SHA256 | string | The SHA256 file hash of the indicator. |
| Flashpoint.File.Event.EventDetails | unknown | The event details in which the indicator observed. |
| Flashpoint.File.Event.Category | string | The category of the indicator. |
| Flashpoint.File.Event.Fpid | string | The FPID of the indicator. |
| Flashpoint.File.Event.Timestamp | string | The time at which the indicator is observed. |
| Flashpoint.File.Event.Type | string | The type of the indicator. |
| Flashpoint.File.Event.Uuid | string | The UUID of the indicator. |
| Flashpoint.File.Event.Comment | string | The comment which was provided when the indicator was observed. |
| File.Malicious.Description | string | The description of the malicious file. |
| File.Malicious.Vendor | string | The vendor of the malicious file. |
| File.MD5 | string | The MD5 hash of the file. |
| File.SHA1 | string | The SHA1 hash of the file. |
| File.SHA256 | string | The SHA256 hash of the file. |

##### Command Example
```
!file file="ab09761ad832efb9359fac985d1a2ab74f8a8d182d7b71188a121b850b80dfe5"
```

##### Context Example
```
{
    "DBotScore": {
        "Indicator": "ab09761ad832efb9359fac985d1a2ab74f8a8d182d7b71188a121b850b80dfe5",
        "Score": 3,
        "Type": "SHA256",
        "Vendor": "Flashpoint"
    },
    "File": {
        "Malicious": {
            "Description": "Found in malicious indicators dataset",
            "Vendor": "Flashpoint"
        },
        "SHA256": "ab09761ad832efb9359fac985d1a2ab74f8a8d182d7b71188a121b850b80dfe5"
    },
    "Flashpoint.File.Event": [
        {
            "Category": "Payload delivery",
            "Comment": "",
            "EventDetails": {
                "RelatedEvent": [
                    {
                        "Event": {
                            "fpid": "DHDkx7UaWX6bYoBo2dqxlA",
                            "info": "win_ransomware_generic"
                        }
                    }
                ],
                "Tags": [
                    "source:VirusTotal",
                    "type:Ransomware",
                    "gandcrab",
                    "malware:GandCrab",
                    "os:Windows"
                ],
                "attack_ids": null,
                "fpid": "Lc3dCH1sXbOIYkKTyUQoow",
                "href": "https://fp.tools/api/v4/indicators/event/Lc3dCH1sXbOIYkKTyUQoow",
                "info": "Gandcrab",
                "reports": null,
                "timestamp": "1576735275"
            },
            "Fpid": "rqIX70QLVlC3aAydF8uECQ",
            "Href": "https://fp.tools/api/v4/indicators/attribute/rqIX70QLVlC3aAydF8uECQ",
            "SHA256": "ab09761ad832efb9359fac985d1a2ab74f8a8d182d7b71188a121b850b80dfe5",
            "Timestamp": "1560826915",
            "Type": "sha256",
            "Uuid": "f161c532-26fa-422d-ad71-3781b6619894"
        },
        {
            "Category": "Payload delivery",
            "Comment": "",
            "EventDetails": {
                "RelatedEvent": [
                    {
                        "Event": {
                            "fpid": "6tTJ5r_nUoW5FGlEtGl_Yg",
                            "info": "crime_azorult_2"
                        }
                    },
                    {
                        "Event": {
                            "fpid": "4VTU1zY3V5qO0W7HvEgeig",
                            "info": "crime_azorult_1"
                        }
                    },
                    {
                        "Event": {
                            "fpid": "Lc3dCH1sXbOIYkKTyUQoow",
                            "info": "Gandcrab"
                        }
                    }
                ],
                "Tags": [
                    "source:VirusTotal",
                    "type:Ransomware",
                    "win_ransomware_generic",
                    "os:Windows"
                ],
                "attack_ids": null,
                "fpid": "DHDkx7UaWX6bYoBo2dqxlA",
                "href": "https://fp.tools/api/v4/indicators/event/DHDkx7UaWX6bYoBo2dqxlA",
                "info": "win_ransomware_generic",
                "reports": null,
                "timestamp": "1563386535"
            },
            "Fpid": "9oi7LdmmWGuh1AG4fKv13g",
            "Href": "https://fp.tools/api/v4/indicators/attribute/9oi7LdmmWGuh1AG4fKv13g",
            "SHA256": "ab09761ad832efb9359fac985d1a2ab74f8a8d182d7b71188a121b850b80dfe5",
            "Timestamp": "1560826913",
            "Type": "sha256",
            "Uuid": "08f5ac60-45cb-4bc1-be05-591eb51071dc"
        }
    ]
}
```

##### Human Readable Output

##### Flashpoint File reputation for ab09761ad832efb9359fac985d1a2ab74f8a8d182d7b71188a121b850b80dfe5

Reputation: Malicious

##### Events in which this IOC observed

| **Date Observed (UTC)** | **Name** | **Tags** |
| --- | --- | --- |
| Dec 19, 2019 06:01 | Gandcrab | source:VirusTotal, type:Ransomware, gandcrab, malware:GandCrab, os:Windows |
| Jul 17, 2019 18:02 | win_ransomware_generic | source:VirusTotal, type:Ransomware, win_ransomware_generic, os:Windows |

All events and details (fp-tools):
https:/<span></span>/fp.tools/home/search/iocs?group=indicator&ioc_type=md5%2Csha1%2Csha256%2Csha512&ioc_value=ab09761ad832efb9359fac985d1a2ab74f8a8d182d7b71188a121b850b80dfe5

### Get the reputation of an Email

* * *

Returns the reputation of an email. The email is considered malicious if there’s at least one IOC event in Flashpoint database matching the email indicator.

##### Base Command

`email`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The email to check. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. |
| DBotScore.Score | number | The indicator score. |
| DBotScore.Type | string | The indicator type. |
| DBotScore.Vendor | string | The vendor used to calculate the score. |
| Flashpoint.Email.Event.Href | string | The list of the reference links of the indicator. |
| Flashpoint.Email.Event.EventDetails | unknown | The event details in which the indicator is observed. |
| Flashpoint.Email.Event.Category | string | The category of the indicator. |
| Flashpoint.Email.Event.Fpid | string | The FPID of the indicator. |
| Flashpoint.Email.Event.Timestamp | string | The time at which the indicator is observed. |
| Flashpoint.Email.Event.Type | string | The type of the indicator. |
| Flashpoint.Email.Event.Uuid | string | The UUID of the indicator. |
| Flashpoint.Email.Event.Comment | string | The comment which was provided when the indicator was observed. |
| Account.Email.Malicious.Description | string | The description of the malicious email account. |
| Account.Email.Malicious.Vendor | string | The vendor of the malicious email. |
| Account.Email.Name | string | The name of the indicator. |

##### Command Example
```
!email email="qicifomuejijika@o2.pl"
```

##### Context Example
```
{
    "Account.Email": {
        "Malicious": {
            "Description": "Found in malicious indicators dataset",
            "Vendor": "Flashpoint"
        },
        "Name": "qicifomuejijika@o2.pl"
    },
    "DBotScore": {
        "Indicator": "qicifomuejijika@o2.pl",
        "Score": 3,
        "Type": "email",
        "Vendor": "Flashpoint"
    },
    "Flashpoint.Email.Event": [
        {
            "Category": "Network activity",
            "Comment": "",
            "EventDetails": {
                "RelatedEvent": null,
                "Tags": [
                    "malware:ransomware:lockergoga",
                    "report:lKyimEX1TWS8x6AtdiJ_vA",
                    "report:jEteM4YxQZCdm4macbE3vQ",
                    "report:w0fL5MgoQ_Wih8XyB6Lowg",
                    "report:7t-BsuFKTL-HJWbid8nupg"
                ],
                "attack_ids": null,
                "fpid": "iBUPRQOoU4SQrH64LGUbzw",
                "href": "https://fp.tools/api/v4/indicators/event/iBUPRQOoU4SQrH64LGUbzw",
                "info": "LockerGoga",
                "reports": [
                    "https://fp.tools/home/intelligence/reports/report/lKyimEX1TWS8x6AtdiJ_vA",
                    "https://fp.tools/home/intelligence/reports/report/jEteM4YxQZCdm4macbE3vQ",
                    "https://fp.tools/home/intelligence/reports/report/w0fL5MgoQ_Wih8XyB6Lowg",
                    "https://fp.tools/home/intelligence/reports/report/7t-BsuFKTL-HJWbid8nupg"
                ],
                "timestamp": "1571934618"
            },
            "Fpid": "TrwIYc5AWP-xtjODCXyp7w",
            "Href": "https://fp.tools/api/v4/indicators/attribute/TrwIYc5AWP-xtjODCXyp7w",
            "Timestamp": "1553280098",
            "Type": "email-dst",
            "Uuid": "5c952c62-ef38-4fcc-8b6e-0f140a640c05"
        }
    ]
}
```

##### Human Readable Output

##### Flashpoint Email reputation for qicifomuejijika<span></span>@o2.pl

Reputation: Malicious

##### Events in which this IOC observed

| **Date Observed (UTC)** | **Name** | **Tags** |
| --- | --- | --- |
| Oct 24, 2019 16:30 | LockerGoga | malware:ransomware:lockergoga, report:lKyimEX1TWS8x6AtdiJ_vA, report:jEteM4YxQZCdm4macbE3vQ, report:w0fL5MgoQ_Wih8XyB6Lowg, report:7t-BsuFKTL-HJWbid8nupg |

All events and details (fp-tools):
https:/<span></span>/fp.tools/home/search/iocs?group=indicator&ioc_type=email-dst%2Cemail-src%2Cemail-src-display-name%2Cemail-subject&ioc_value=qicifomuejijika%40o2<span></span>.pl

### Search for intelligence reports

* * *

Returns a list of intelligence reports based on a keyword or text.

##### Base Command

`flashpoint-search-intelligence-reports`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_search | Search for a report using a keyword or text. | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Flashpoint.Report | Unknown | Display a list of reports based on a specified search query or keyword. |

##### Command Example
```
!flashpoint-search-intelligence-reports report_search="isis"
```

##### Context Example
```
{
    "Flashpoint.Report": [
        {
            "NotifiedAt": "2019-12-13T19:17:32.520+00:00",
            "PlatformUrl": "https://fp.tools/home/intelligence/reports/report/urDeGGjbTwWOSDikhp9YDw#detail",
            "PostedAt": "2019-12-13T19:17:32.520+00:00",
            "ReportId": "urDeGGjbTwWOSDikhp9YDw",
            "Summary": "On December 5, 2019, the al-Qaeda affiliated Global Islamic Media Front (GIMF) announced the launch of its server on the messaging platform RocketChat. The announcement follows the purge of jihadists from multiple social media and communication platforms, most notably Telegram.",
            "Title": "Al-Qaeda Affiliated Unit Launches Private RocketChat Server",
            "UpdatedAt": "2019-12-13T19:17:32.520+00:00"
        },
        {
            "NotifiedAt": null,
            "PlatformUrl": "https://fp.tools/home/intelligence/reports/report/WFhcFuASR3CbxbC6IzuKBA#detail",
            "PostedAt": "2019-12-13T18:28:05.858+00:00",
            "ReportId": "WFhcFuASR3CbxbC6IzuKBA",
            "Summary": "WEEK OF DECEMBER 9 KEY DEVELOPMENTS ",
            "Title": "Iran Global Spotlight (Analyst Knowledge Page)",
            "UpdatedAt": "2019-12-13T18:28:05.858+00:00"
        },
        {
            "NotifiedAt": "2019-12-02T21:13:08.271+00:00",
            "PlatformUrl": "https://fp.tools/home/intelligence/reports/report/og0aVCYmSeS-mpSXOF21Rg#detail",
            "PostedAt": "2019-12-02T21:13:08.271+00:00",
            "ReportId": "og0aVCYmSeS-mpSXOF21Rg",
            "Summary": "Despite Telegram?s aggressive and sustained targeting of jihadists on its platform, ISIS?s official media and supportive groups are beginning to rebuild on Telegram.",
            "Title": "ISIS Media Rebuilds Following Sweeping Suspensions",
            "UpdatedAt": "2019-12-02T21:13:08.271+00:00"
        },
        {
            "NotifiedAt": "2019-11-25T21:21:41.647+00:00",
            "PlatformUrl": "https://fp.tools/home/intelligence/reports/report/Kd1HMXJQRYmKDmECAmsPMA#detail",
            "PostedAt": "2019-11-25T21:21:41.647+00:00",
            "ReportId": "Kd1HMXJQRYmKDmECAmsPMA",
            "Summary": "Between November 22 and 24, 2019, Telegram removed more than 7,000 jihadist channnels and bots from its platform?in the largest purge of ISIS propaganda in Telegram?s history. The takedown drastically impacted ISIS propaganda dissemination, knocking out critical channels and groups, many of which had operated uninterrupted for years.",
            "Title": "Telegram Targets ISIS Propaganda in Largest Platform Purge",
            "UpdatedAt": "2019-11-25T21:21:41.647+00:00"
        },
        {
            "NotifiedAt": "2019-11-22T19:24:21.634+00:00",
            "PlatformUrl": "https://fp.tools/home/intelligence/reports/report/mwpd9Dn7SuO_K7KLPzfJeA#detail",
            "PostedAt": "2019-11-22T19:24:21.634+00:00",
            "ReportId": "mwpd9Dn7SuO_K7KLPzfJeA",
            "Summary": "",
            "Title": "Global Spotlight - Iran: Key Developments This Week",
            "UpdatedAt": "2019-11-22T19:24:21.634+00:00"
        }
    ]
}
```

##### Human Readable Output

##### Flashpoint Intelligence reports related to search: isis

Top 5 reports:

1.  ISIS Media Rebuilds Following Sweeping Suspensions
    Summary: Despite Telegram?s aggressive and sustained targeting of
    jihadists on its platform, ISIS?s official media and supportive groups
    are beginning to rebuild on Telegram.

2.  Telegram Targets ISIS Propaganda in Largest Platform Purge
    Summary: Between November 22 and 24, 2019, Telegram removed more than
    7,000 jihadist channnels and bots from its platform?in the largest purge
    of ISIS propaganda in Telegram?s history. The takedown drastically
    impacted ISIS propaganda dissemination, knocking out critical channels
    and groups, many of which had operated uninterrupted for years.

3.  Global Spotlight - Iran: Key Developments ThisWeek
    Summary: N/A

4.  Dropbox Account Disseminates Far-Right Extremist Content
    Summary: Flashpoint analysts have identified a Dropbox account called
    ?NS Library? belonging to a far-right extremist containing over 200
    white supremacist publications and guides?including neo-Nazi literature
    and propaganda, instruction manuals for making homemade weapons,
    survival guides, attackers? manifestos, and workout manuals, among other
    content.

5.  ISIS Activity Continues Unabated Following al-Baghdadi’s Death
    Summary: On October 26, 2019, ISIS?s former leader Abu Bakr al-Baghdadi
    killed himself in the midst of a US military operation. Less than a week
    later, ISIS confirmed al-Baghdadi?s death, and announced that Abu
    Ibrahim al-Hashimi al-Qurashi is the group?s new leader. Link to
    Report-search on Flashpoint platform:
    https:/<span></span>/fp.tools/home/search/reports?query=isis

### Get a single report

* * *

Returns a single report by its ID.

##### Base Command

`flashpoint-get-single-intelligence-report`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Search report by report ID. The report ID can be known from the output context path `Flashpoint.Report.ReportId` of the report-search command or some other investigation. | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Flashpoint.Report.NotifiedAt | string | The notification date of the report. |
| Flashpoint.Report.PlatformUrl | string | The platform URL of the report. It helps to redirect the Flashpoint platform. |
| Flashpoint.Report.PostedAt | number | The posted date of the report. |
| Flashpoint.Report.Summary | string | The summary of the report. |
| Flashpoint.Report.Title | string | The title of the report. |
| Flashpoint.Report.UpdatedAt | string | The last update date of the report. |
| Flashpoint.Report.ReportId | string | The unique ID of the report. |

##### Command Example
```
!flashpoint-get-single-intelligence-report report_id="e-QdYuuwRwCntzRljzn9-A"
```

##### Context Example
```
{
    "Flashpoint.Report": {
        "NotifiedAt": "2019-09-23T20:27:20.638+00:00",
        "PlatformUrl": "https://fp.tools/home/intelligence/reports/report/e-QdYuuwRwCntzRljzn9-A#detail",
        "PostedAt": "2019-09-23T20:27:20.638+00:00",
        "ReportId": "e-QdYuuwRwCntzRljzn9-A",
        "Summary": "On September 17, 2019, multiple pro-ISIS Telegram groups disseminated a message warning of the dangers of exposed exif data?a type of metadata showing GPS coordinates, time, and date the image was taken and the make and model of the device used?that is typically captured from images taken by a phone or camera, unless the security settings are properly configured.",
        "Title": "ISIS Supporters Warn of the Risks Associated with Exif Data",
        "UpdatedAt": "2019-09-23T20:27:20.638+00:00"
    }
}
```

##### Human Readable Output

##### Flashpoint Intelligence Report details

##### Below are the details found:

| **Title** | **Date Published (UTC)** | **Summary** | **Tags** |
| --- | --- | --- | --- |
| ISIS Supporters Warn of the Risks Associated with Exif Data | Sep 23, 2019 20:27 | On September 17, 2019, multiple pro-ISIS Telegram groups disseminated a message warning of the dangers of exposed exif data?a type of metadata showing GPS coordinates, time, and date the image was taken and the make and model of the device used?that is typically captured from images taken by a phone or camera, unless the security settings are properly configured. | Intelligence Report, Law Enforcement & Military, Physical Threats, Jihadist, Propaganda, Terrorism, Global |

### Get related reports

* * *

Returns related reports for a given report ID.

##### Base Command

`flashpoint-get-related-reports`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Search reports by the report ID. The report ID can be known from the output context path `Flashpoint.Report.ReportId` of report-search command or some other investigation. | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Flashpoint.Report | Unknown | Display a list of related reports based on the report FPID. |

##### Command Example
```
!flashpoint-get-related-reports report_id="tiPqg51OQpOTsoFyTaYa_w"
```

##### Context Example
```
{
    "Flashpoint.Report": [
        {
            "NotifiedAt": "2019-10-02T19:31:41.625+00:00",
            "PlatformUrl": "https://fp.tools/home/intelligence/reports/report/X6YSFdWWQ3yDa9_0r627sg#detail",
            "PostedAt": "2019-10-02T19:31:41.625+00:00",
            "ReportId": "X6YSFdWWQ3yDa9_0r627sg",
            "Summary": "On September 30, 2019, the admin of ?The_Bowlcast? Telegram channel promoted the launch of the militant, white supremacist group ?Atomwaffen Division?s? (AWD) latest website and new video dubbed ?Nuclear Congress 2019,? which subtlely discusses the need for AWD to accomplish its goals?alluding to the need for new financing and recruitment.",
            "Title": "Atomwaffen Division Resumes Recruitment Activity",
            "UpdatedAt": "2019-10-02T19:31:41.625+00:00"
        },
        {
            "NotifiedAt": "2019-09-26T19:52:21.089+00:00",
            "PlatformUrl": "https://fp.tools/home/intelligence/reports/report/iQRHJvzySma6-aHNE973mA#detail",
            "PostedAt": "2019-09-26T19:52:21.089+00:00",
            "ReportId": "iQRHJvzySma6-aHNE973mA",
            "Summary": "On June 14, 2019, a militant white supremacy group called ?Vorherrschaft Division? (VSD) announced its creation in its Telegram channel \"Vorherrschaft division propaganda posting.\"",
            "Title": "\"Vorherrschaft Division\" (VSD): A Nascent Militant White Supremacy Group",
            "UpdatedAt": "2019-09-26T19:52:21.089+00:00"
        },
        {
            "NotifiedAt": "2019-11-04T21:14:28.506+00:00",
            "PlatformUrl": "https://fp.tools/home/intelligence/reports/report/90paj4gCSBG8FT8R_SCtgQ#detail",
            "PostedAt": "2019-11-04T21:14:28.506+00:00",
            "ReportId": "90paj4gCSBG8FT8R_SCtgQ",
            "Summary": "In August 2019, militant white supremacist channel ?Stack the Bodies to God? appeared on Telegram, inciting violence and providing a large quantity of informational resources?including extremist publications, tactical manuals, survival guides, guerrilla warfare tactics, instructions for making homemade explosives, weapons, and ricin, and internet security tips.",
            "Title": "Neo-Nazi Telegram Channel Incites Violence, Spreads Extremist Content",
            "UpdatedAt": "2019-11-04T21:14:28.506+00:00"
        },
        {
            "NotifiedAt": "2019-11-25T19:12:47.634+00:00",
            "PlatformUrl": "https://fp.tools/home/intelligence/reports/report/pQBUFAlfSce-xQd7Ignmyg#detail",
            "PostedAt": "2019-11-25T19:12:47.634+00:00",
            "ReportId": "pQBUFAlfSce-xQd7Ignmyg",
            "Summary": "Members of the far-right community are preparing for what they call ?meme war 2020??content spread via social media focused on left-leaning targets?in the lead up to the 2020 U.S. presidential election. ",
            "Title": "Far-Right Prepares for \"Meme War 2020\"",
            "UpdatedAt": "2019-11-25T19:12:47.634+00:00"
        },
        {
            "NotifiedAt": "2019-10-23T18:47:40.810+00:00",
            "PlatformUrl": "https://fp.tools/home/intelligence/reports/report/iEOIjuPjREmCIJR7Krbpnw#detail",
            "PostedAt": "2019-10-23T18:47:40.810+00:00",
            "ReportId": "iEOIjuPjREmCIJR7Krbpnw",
            "Summary": "The term ?boogaloo? (also known as ?the boogaloo? and ?big igloo?) is the latest term used by accelerationists?advocates of hastening the collapse of society through violence?to describe an armed revolution against society to rebuild a white-ethno state.",
            "Title": "\"Boogaloo\": Accelerationists' Latest Call to Action",
            "UpdatedAt": "2019-10-23T18:47:40.810+00:00"
        }
    ]
}
```

##### Human Readable Output

##### Flashpoint Intelligence related reports:

Top 5 related reports:

1.  Neo-Nazi Telegram Channel Incites Violence, Spreads Extremist Content
    Summary: In August 2019, militant white supremacist channel ?Stack the
    Bodies to God? appeared on Telegram, inciting violence and providing a
    large quantity of informational resources?including extremist
    publications, tactical manuals, survival guides, guerrilla warfare
    tactics, instructions for making homemade explosives, weapons, and
    ricin, and internet security tips.

2.  Atomwaffen Division Resumes Recruitment Activity
    Summary: On September 30, 2019, the admin of ?The_Bowlcast? Telegram
    channel promoted the launch of the militant, white supremacist group
    ?Atomwaffen Division?s? (AWD) latest website and new video dubbed
    ?Nuclear Congress 2019,? which subtlely discusses the need for AWD to
    accomplish its goals?alluding to the need for new financing and
    recruitment.

3.  “Vorherrschaft Division” (VSD): A Nascent Militant White Supremacy Group
    Summary: On June 14, 2019, a militant white supremacy group called
    ?Vorherrschaft Division? (VSD) announced its creation in its Telegram
    channel “Vorherrschaft division propaganda posting.”

4.  “Boogaloo”: Accelerationists’ Latest Call to Action
    Summary: The term ?boogaloo? (also known as ?the boogaloo? and ?big
    igloo?) is the latest term used by accelerationists?advocates of
    hastening the collapse of society through violence?to describe an armed
    revolution against society to rebuild a white-ethno state.

5.  Far-Right Prepares for “Meme War 2020”
    Summary: Members of the far-right community are preparing for what they
    call ?meme war 2020??content spread via social media focused on
    left-leaning targets?in the lead up to the 2020 U.S. presidential
    election. Link to the given Report on Flashpoint platform:
    https:/<span></span>/fp.tools/home/intelligence/reports/report/tiPqg51OQpOTsoFyTaYa_w#detail

### Get a single event's details

* * *

Returns the details of a single event.

##### Base Command

`flashpoint-get-single-event`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The UUID or FPID that identifies a particular event. The event ID can be fetched from the output context path `Flashpoint.Event.EventId` get-events command or indicator reputation command response or some other investigation. | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Flashpoint.Event.ObservedTime | string | The date the event was triggered. |
| Flashpoint.Event.EventCreatorEmail | string | The event creator of the email. |
| Flashpoint.Event.Href | Unknown | Display the event reference. |
| Flashpoint.Event.Tags | Unknown | Display the event tags. |
| Flashpoint.Event.EventId | string | Display the event ID (event FPID). |
| Flashpoint.Event.Name | string | The name of the event. |

##### Command Example
```
!flashpoint-get-single-event event_id=Hu2SoTWJWteLrH9mR94JbQ
```

##### Context Example
```
{
    "Flashpoint.Event": {
        "EventCreatorEmail": "info@flashpoint-intel.com",
        "EventId": "Hu2SoTWJWteLrH9mR94JbQ",
        "Href": "https://fp.tools/api/v4/indicators/event/Hu2SoTWJWteLrH9mR94JbQ",
        "Name": "[CryptingService_4c0d570ecdf23529c91b8decf27107db5c5e9430_2019-06-17T03:01:03.000Z](https://fp.tools/home/technical_data/iocs/items/5d0960cc-6128-4416-9996-05d20a640c05)",
        "ObservedTime": "Jun 18, 2019  22:08",
        "Tags": "source:CryptingService2"
    }
}
```

##### Human Readable Output

##### Flashpoint Event details

##### Below are the detail found:

| **Observed time (UTC)** | **Name** | **Tags** |
| --- | --- | --- |
| Jun 18, 2019 22:08 | CryptingService_4c0d570ecdf23529c91b8decf27107db5c5e9430_2019-06-17T03:01:03.000Z | source:CryptingService2 |

### Get all event details

* * *

Returns all the details of an event.

##### Base Command

`flashpoint-get-events`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time_period | Search events based on a specified time period. | Optional |
| report_fpid | Search events by the report's FPID. A user can get a report's FPID from the output of the report-search or related-reports commands and use it in this command to get events for a specific Flashpoint report. | Optional |
| limit | Specify the maximum number of records to display. | Optional |
| attack_ids | Comma-separated values, attack_ids can be found in the event's information or on the Flashpoint platform using filtering events by attack IDs. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Flashpoint.Event | Unknown | Display a list of multiple events. |

##### Command Example
```
!flashpoint-get-events limit=20
```

##### Context Example
```
{
    "Flashpoint.Event": [
        {
            "EventCreatorEmail": "info@flashpoint-intel.com",
            "EventId": "nx7tsJYKWKm259vMLduWGw",
            "Href": "https://fp.tools/api/v4/indicators/event/nx7tsJYKWKm259vMLduWGw",
            "Name": "[Loki](https://fp.tools/home/technical_data/iocs/items/5d087e04-1464-4a26-964e-05cd0a640c05)",
            "ObservedTime": "Dec 18, 2019  12:00",
            "Tags": "source:VirusTotal, type:Stealer, malware:Loki, loki, os:Windows"
        },
        {
            "EventCreatorEmail": "info@flashpoint-intel.com",
            "EventId": "yV-3FFFwXWW3xxB6IMnP0g",
            "Href": "https://fp.tools/api/v4/indicators/event/yV-3FFFwXWW3xxB6IMnP0g",
            "Name": "[NetWire](https://fp.tools/home/technical_data/iocs/items/5d58176a-6020-418a-b5aa-05d20a640c05)",
            "ObservedTime": "Dec 18, 2019  12:00",
            "Tags": "source:VirusTotal, T1060, netwire, T1056, os:Windows, type:RAT, malware:NetWire, T1082, T1116, T1113, misp-galaxy:mitre-enterprise-attack-attack-pattern=\"Registry Run Keys / Start Folder - T1060\", misp-galaxy:mitre-enterprise-attack-attack-pattern=\"Input Capture - T1056\", misp-galaxy:mitre-enterprise-attack-attack-pattern=\"System Information Discovery - T1082\", misp-galaxy:mitre-enterprise-attack-attack-pattern=\"Code Signing - T1116\", misp-galaxy:mitre-enterprise-attack-attack-pattern=\"Screen Capture - T1113\""
        },
        {
            "EventCreatorEmail": "info@flashpoint-intel.com",
            "EventId": "PSP0k-dFUiWbX9YWV9pMag",
            "Href": "https://fp.tools/api/v4/indicators/event/PSP0k-dFUiWbX9YWV9pMag",
            "Name": "[unpacked_cutwailv4](https://fp.tools/home/technical_data/iocs/items/5dfa14da-d190-48ab-80b6-23fe0a212040)",
            "ObservedTime": "Dec 18, 2019  12:00",
            "Tags": "source:VirusTotal, v:4, os:Windows, T1204, unpacked_cutwailv4, malware:Cutwail, T1060, type:Botnet"
        },
        {
            "EventCreatorEmail": "info@flashpoint-intel.com",
            "EventId": "hirKFHGUVAySCvUzchchgA",
            "Href": "https://fp.tools/api/v4/indicators/event/hirKFHGUVAySCvUzchchgA",
            "Name": "[CyberGate](https://fp.tools/home/technical_data/iocs/items/5d07d55f-e9f8-4530-b57c-05cd0a640c05)",
            "ObservedTime": "Dec 18, 2019  12:00",
            "Tags": "source:VirusTotal, os:Windows, type:RAT, cybergate, malware:CyberGate"
        },
        {
            "EventCreatorEmail": "info@flashpoint-intel.com",
            "EventId": "E1EnVbazXKOoV6eIMwz68A",
            "Href": "https://fp.tools/api/v4/indicators/event/E1EnVbazXKOoV6eIMwz68A",
            "Name": "[UNKN actor profile (distributor of Revil Ransomware)](https://fp.tools/home/technical_data/iocs/items/5dfa10af-7470-4ac5-af4e-dc260a21270c)",
            "ObservedTime": "Dec 18, 2019  11:51",
            "Tags": "malware:ransomware, ransomware:Revil, actor:UNKN, origin:Russia"
        },
        {
            "EventCreatorEmail": "info@flashpoint-intel.com",
            "EventId": "F8igomEDVVOG2bWhNcfBaQ",
            "Href": "https://fp.tools/api/v4/indicators/event/F8igomEDVVOG2bWhNcfBaQ",
            "Name": "[win_snatch_loader_g2](https://fp.tools/home/technical_data/iocs/items/5db9a5f0-01a8-4f2b-867c-0a340a640c05)",
            "ObservedTime": "Dec 18, 2019  11:00",
            "Tags": "source:VirusTotal, win_snatch_loader_g2, malware:SnatchLoader, os:Windows, type:Downloader"
        },
        {
            "EventCreatorEmail": "info@flashpoint-intel.com",
            "EventId": "vjqRiYHvWnWBweTqiqNTBQ",
            "Href": "https://fp.tools/api/v4/indicators/event/vjqRiYHvWnWBweTqiqNTBQ",
            "Name": "[Sofacy_CollectorStealer_Gen2](https://fp.tools/home/technical_data/iocs/items/5de6be25-b70c-4077-9f8a-00bd0a2120d6)",
            "ObservedTime": "Dec 18, 2019  11:00",
            "Tags": "source:VirusTotal, actor:APT28, sofacy_collectorstealer_gen2, origin:Russia, type:Stealer"
        },
        {
            "EventCreatorEmail": "info@flashpoint-intel.com",
            "EventId": "78hNTAcJWWezTL9t8WuUtg",
            "Href": "https://fp.tools/api/v4/indicators/event/78hNTAcJWWezTL9t8WuUtg",
            "Name": "[crime_tinynuke_1](https://fp.tools/home/technical_data/iocs/items/5d0950fb-faa4-42f6-a116-05d00a640c05)",
            "ObservedTime": "Dec 18, 2019  10:00",
            "Tags": "source:VirusTotal, crime_tinynuke_1"
        },
        {
            "EventCreatorEmail": "info@flashpoint-intel.com",
            "EventId": "_0VfrtauWN6VpZ5d2QFiUA",
            "Href": "https://fp.tools/api/v4/indicators/event/_0VfrtauWN6VpZ5d2QFiUA",
            "Name": "[win_tinba_g1](https://fp.tools/home/technical_data/iocs/items/5df9f8be-e188-4516-80f9-03030a21270c)",
            "ObservedTime": "Dec 18, 2019  10:00",
            "Tags": "source:VirusTotal, type:Banker, malware:tinba, win_tinba_g1, os:Windows, target: Russia, target:Japan"
        },
        {
            "EventCreatorEmail": "info@flashpoint-intel.com",
            "EventId": "Ajj-czMuVhO6MLsIYpcdUg",
            "Href": "https://fp.tools/api/v4/indicators/event/Ajj-czMuVhO6MLsIYpcdUg",
            "Name": "[win_tinba_g0](https://fp.tools/home/technical_data/iocs/items/5d70500d-e88c-40ee-ae95-05cd0a640c05)",
            "ObservedTime": "Dec 18, 2019  10:00",
            "Tags": "source:VirusTotal, type:Banker, win_tinba_g0, target: Russia, malware:tinba, target:Japan, os:Windows"
        },
        {
            "EventCreatorEmail": "info@flashpoint-intel.com",
            "EventId": "f97cPO5dVqO74ttWZwbFqQ",
            "Href": "https://fp.tools/api/v4/indicators/event/f97cPO5dVqO74ttWZwbFqQ",
            "Name": "[MegaCortex_Load_Dinkum_CLib](https://fp.tools/home/technical_data/iocs/items/5da01a84-b3fc-4eef-961d-0a340a640c05)",
            "ObservedTime": "Dec 18, 2019  07:03",
            "Tags": "source:VirusTotal, megacortex_load_dinkum_clib, malware:MegaCortex, type:Ransomware, os:Windows"
        },
        {
            "EventCreatorEmail": "info@flashpoint-intel.com",
            "EventId": "Y_0iIuFFXU-wuNBCs0kF_g",
            "Href": "https://fp.tools/api/v4/indicators/event/Y_0iIuFFXU-wuNBCs0kF_g",
            "Name": "[Command_Line_Options](https://fp.tools/home/technical_data/iocs/items/5da01a75-0f20-41da-83e1-56550a640c05)",
            "ObservedTime": "Dec 18, 2019  07:03",
            "Tags": "source:VirusTotal, command_line_options"
        },
        {
            "EventCreatorEmail": "info@flashpoint-intel.com",
            "EventId": "Lc3dCH1sXbOIYkKTyUQoow",
            "Href": "https://fp.tools/api/v4/indicators/event/Lc3dCH1sXbOIYkKTyUQoow",
            "Name": "[Gandcrab](https://fp.tools/home/technical_data/iocs/items/5d07d587-a9ac-4da1-9c72-05cd0a640c05)",
            "ObservedTime": "Dec 18, 2019  07:03",
            "Tags": "source:VirusTotal, type:Ransomware, gandcrab, malware:GandCrab, os:Windows"
        },
        {
            "EventCreatorEmail": "info@flashpoint-intel.com",
            "EventId": "Nc-OJiCGWaWqVgLbFHiotA",
            "Href": "https://fp.tools/api/v4/indicators/event/Nc-OJiCGWaWqVgLbFHiotA",
            "Name": "[botox_lampeduza_amaterasu_output5E0600](https://fp.tools/home/technical_data/iocs/items/5d1504b4-572c-47dd-afb2-05d20a640c05)",
            "ObservedTime": "Dec 18, 2019  07:00",
            "Tags": "source:VirusTotal, botox_lampeduza_amaterasu_output5e0600"
        },
        {
            "EventCreatorEmail": "info@flashpoint-intel.com",
            "EventId": "Ut6zC32_VMSg6vB-cvwNmg",
            "Href": "https://fp.tools/api/v4/indicators/event/Ut6zC32_VMSg6vB-cvwNmg",
            "Name": "[Sodinokibi_Unreachable_After_MZ_Check](https://fp.tools/home/technical_data/iocs/items/5da01a74-4b5c-4160-83c6-05d00a640c05)",
            "ObservedTime": "Dec 18, 2019  06:02",
            "Tags": "source:VirusTotal, sodinokibi_unreachable_after_mz_check"
        },
        {
            "EventCreatorEmail": "info@flashpoint-intel.com",
            "EventId": "w0B3dKLxX9aat0O0YyS-6A",
            "Href": "https://fp.tools/api/v4/indicators/event/w0B3dKLxX9aat0O0YyS-6A",
            "Name": "[CryptingService_27a1ad076d1c155856c0ad08dd302018281aba1e_2019-12-18T02:01:02.000Z](https://fp.tools/home/technical_data/iocs/items/5df9a7f3-7260-44d7-bcdd-03010a21270c)",
            "ObservedTime": "Dec 18, 2019  04:15",
            "Tags": "source:CryptingService2"
        },
        {
            "EventCreatorEmail": "info@flashpoint-intel.com",
            "EventId": "8tWwTNyfWY2oBqSmmI0AUg",
            "Href": "https://fp.tools/api/v4/indicators/event/8tWwTNyfWY2oBqSmmI0AUg",
            "Name": "[ryuk3_exe](https://fp.tools/home/technical_data/iocs/items/5dc0f4cc-cb70-44bf-bdbf-00540a2123fc)",
            "ObservedTime": "Dec 18, 2019  01:00",
            "Tags": "source:VirusTotal, type:Ransomware, ryuk3_exe, os:Windows, malware:Ryuk"
        },
        {
            "EventCreatorEmail": "info@flashpoint-intel.com",
            "EventId": "J7W0HoNDULyq7p6FqLEH6Q",
            "Href": "https://fp.tools/api/v4/indicators/event/J7W0HoNDULyq7p6FqLEH6Q",
            "Name": "[Kovter](https://fp.tools/home/technical_data/iocs/items/5d0aa281-9768-4f33-9903-05d20a640c05)",
            "ObservedTime": "Dec 18, 2019  00:00",
            "Tags": "source:VirusTotal, actor:KovCoreG, kovter, os:Windows, type:Trojan, malware:Kovter"
        },
        {
            "EventCreatorEmail": "info@flashpoint-intel.com",
            "EventId": "zzc5kPgfUzeUO3epfZs6ug",
            "Href": "https://fp.tools/api/v4/indicators/event/zzc5kPgfUzeUO3epfZs6ug",
            "Name": "[predatorthethief retrohunt](https://fp.tools/home/technical_data/iocs/items/5df9165e-0e34-4cc8-b7f5-004e0a21253a)",
            "ObservedTime": "Dec 17, 2019  17:55",
            "Tags": "malware:trojan:PredatorTheThief"
        },
        {
            "EventCreatorEmail": "info@flashpoint-intel.com",
            "EventId": "NXgn9Ty5VeiTzGMGNkHMnA",
            "Href": "https://fp.tools/api/v4/indicators/event/NXgn9Ty5VeiTzGMGNkHMnA",
            "Name": "[Golang_Win](https://fp.tools/home/technical_data/iocs/items/5da90f11-2240-420f-849a-12a70a640c05)",
            "ObservedTime": "Dec 17, 2019  05:02",
            "Tags": "source:VirusTotal, golang_win"
        }
    ]
}
```

##### Human Readable Output

##### Flashpoint Events

##### Below are the detail found:

| **Observed time (UTC)** | **Name** | **Tags** |
| --- | --- | --- |
| Dec 11, 2019 10:16 | CryptingService_4273f08ae5f229f6301e7e0cc9e9005cebc4da20_2019-12-11T03:01:01.000Z | source:CryptingService2 |
| Dec 11, 2019 09:00 | NetWire | source:VirusTotal, T1060, netwire, T1056, os:Windows, type:RAT, malware:NetWire, T1082, T1116, T1113, misp-galaxy:mitre-enterprise-attack-attack-pattern=“Registry Run Keys / Start Folder - T1060”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“Input Capture - T1056”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“System Information Discovery - T1082”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“Code Signing - T1116”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“Screen Capture - T1113” |
| Dec 11, 2019 08:00 | CyberGate | source:VirusTotal, os:Windows, type:RAT, cybergate, malware:CyberGate |
| Dec 11, 2019 07:04 | ROKRAT_Nov17_1 | source:VirusTotal, T1057, T1105, T1063, os:Windows, target:SouthKorea, T1003, T1012, T1082, rokrat_nov17_1, malware:Rokrat, T1071, exfil:C2, T1102, T1041, T1056, type:RAT, T1497, T1113, misp-galaxy:mitre-enterprise-attack-attack-pattern=“Process Discovery - T1057”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“Remote File Copy - T1105”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“Security Software Discovery - T1063”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“Credential Dumping - T1003”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“Query Registry - T1012”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“System Information Discovery - T1082”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“Standard Application Layer Protocol - T1071”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“Web Service - T1102”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“Exfiltration Over Command and Control Channel - T1041”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“Input Capture - T1056”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“Screen Capture - T1113” |
| Dec 11, 2019 07:04 | Sodinokibi_Unreachable_After_MZ_Check | source:VirusTotal, sodinokibi_unreachable_after_mz_check |
| Dec 11, 2019 07:04 | MegaCortex_Load_Dinkum_CLib | source:VirusTotal, megacortex_load_dinkum_clib, malware:MegaCortex, type:Ransomware, os:Windows |
| Dec 11, 2019 07:04 | Command_Line_Options | source:VirusTotal, command_line_options |
| Dec 11, 2019 06:17 | CryptingService_74dd32ce57900738cba4d945e4619289ff040a9e_2019-12-11T03:01:01.000Z | source:CryptingService2 |
| Dec 11, 2019 06:03 | Gandcrab | source:VirusTotal, type:Ransomware, gandcrab, malware:GandCrab, os:Windows |
| Dec 11, 2019 06:00 | botox_lampeduza_amaterasu_output5E0600 | source:VirusTotal, botox_lampeduza_amaterasu_output5e0600 |
| Dec 11, 2019 04:17 | CryptingService_e2f163c72837c6b4386ef9158d017418ab149b13_2019-12-11T03:01:01.000Z | source:CryptingService2 |
| Dec 11, 2019 04:16 | CryptingService_2c13004c346bf79bbec61f6a65fb5b11d5c6f557_2019-12-11T02:01:02.000Z | source:CryptingService2 |
| Dec 11, 2019 04:16 | CryptingService_5eda60cd7c1d4e5dd4fc5e0d3746bd4879de3959_2019-12-11T03:01:01.000Z | source:CryptingService2 |
| Dec 11, 2019 04:16 | CryptingService_981ad08f56f265e9e7209e09e3842d8a6b7f7563_2019-12-11T03:01:01.000Z | source:CryptingService2 |
| Dec 11, 2019 04:16 | CryptingService_7dbfe923559cbb91031dbe2b616c16f5aa40233f_2019-12-11T02:01:02.000Z | source:CryptingService2 |
| Dec 11, 2019 04:00 | cobalt_beacon | source:VirusTotal, cobalt_beacon |
| Dec 10, 2019 19:00 | Loki | source:VirusTotal, type:Stealer, malware:Loki, loki, os:Windows |
| Dec 10, 2019 19:00 | crime_alina_pos_3 | source:VirusTotal, crime_alina_pos_3, type:POS, malware:Alina |
| Dec 10, 2019 19:00 | Kovter | source:VirusTotal, actor:KovCoreG, kovter, os:Windows, type:Trojan, malware:Kovter |
| Dec 10, 2019 17:24 | zeroclear Oilrig | origin:Iran, actor:APT34, malware:ransomware:zeroclear |

All events and details (fp-tools):
https:/<span></span>/fp.tools/home/search/iocs

### Get any type of indicator

* * *

Returns any type of indicator by searching common terms.

##### Base Command

`flashpoint-common-lookup`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | Specify the indicator value such as domain, IP, email, URL etc. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. |
| DBotScore.Score | number | The indicator score. |
| DBotScore.Type | string | The indicator type. |
| DBotScore.Vendor | string | The vendor used to calculate the score. |

##### Command Example
```
!flashpoint-common-lookup indicator="mondns.myftp.biz"
```

##### Context Example
```
{
    "DBotScore": {
        "Indicator": "mondns.myftp.biz",
        "Score": 3,
        "Type": "domain",
        "Vendor": "Flashpoint"
    }
}
```

##### Human Readable Output

##### Flashpoint reputation for mondns<span></span>.myftp<span></span>.biz

Reputation: Malicious

##### Events in which this IOC observed

| **Date Observed (UTC)** | **Name** | **Tags** |
| --- | --- | --- |
| Oct 11, 2019 15:30 | ModiRAT | misp-galaxy:mitre-enterprise-attack-attack-pattern=“Deobfuscate/Decode Files or Information - T1140”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“System Owner/User Discovery - T1033”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“System Information Discovery - T1082”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“Screen Capture - T1113”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“Custom Command and Control Protocol - T1094”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“Data Encoding - T1132”, misp-galaxy:mitre-enterprise-attack-attack-pattern=“Uncommonly Used Port - T1065”, malware:ModiRAT, type:RAT, os:Windows, report:FQmMHh1rR_WuGd_PNVv-bQ |

### Get forum details

* * *

Returns the details of the forum.

##### Base Command

`flashpoint-get-forum-details`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| forum_id | Specifies the forum ID for which the details are to be fetched. The forum ID can be known from the context path `Flashpoint.Forum.ForumId or Flashpoint.Forum.Post.Forum.id` of flashpoint-search-forum-posts command or some other investigation. | Required |

##### <a id="Context_Output_1411"></a>Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Flashpoint.Forum.Description | string | The detailed information of the supplied forum ID. |
| Flashpoint.Forum.Hostname | string | The host details of the supplied forum ID. |
| Flashpoint.Forum.Name | string | The name of the forum. |
| Flashpoint.Forum.Stats | Unknown | The displayed statistical information such as the number of posts, rooms, threads and users details. |
| Flashpoint.Forum.Tags | Unknown | The displayed list of tags which include ID, name, parent_tag, and UUID. |
| Flashpoint.Forum.ForumId | string | The forum’s unique ID. |

##### Command Example
```
!flashpoint-get-forum-details forum_id=ifY5BsXeXQqdTx3fafZbIg
```

##### Context Example
```
{
    "Flashpoint.Forum": {
        "Description": "0hack (\u96f6\u9ed1\u8054\u76df) is a Chinese-language hacker training forum. The forum appears to be affiliated with \u975e\u51e1\u5b89\u5168\u7f51, 803389.com.",
        "ForumId": "ifY5BsXeXQqdTx3fafZbIg",
        "Hostname": "bbs.0hack.com",
        "Name": "0hack",
        "Stats": {
            "posts": 1226,
            "rooms": 11,
            "threads": 226,
            "users": 114
        },
        "Tags": [
            {
                "id": 31,
                "name": "Chinese",
                "parent_tag": 28,
                "uuid": "e725fc5d-71f9-4403-ab00-ae609f2fd3bd"
            },
            {
                "id": 6,
                "name": "Cyber Threat",
                "parent_tag": null,
                "uuid": "09fb6a4a-e072-495d-97bf-d80f059828fd"
            },
            {
                "id": 8,
                "name": "Hacking",
                "parent_tag": 6,
                "uuid": "c88a0cd8-a259-46d7-b8b4-b6e0060f16a0"
            },
            {
                "id": 28,
                "name": "Language",
                "parent_tag": null,
                "uuid": "6d6719ac-9ead-4980-a783-1f32ac398e2b"
            }
        ]
    }
}
```

##### Human Readable Output

##### Flashpoint Forum details

##### Below are the details found:

| **Name** | **Hostname** | **Tags** |
| --- | --- | --- |
| 0hack | bbs<span></span>.0hack<span></span>.com | Chinese, Cyber Threat, Hacking, Language |

### Get the details of a room

* * *

Returns the details of a room.

##### Base Command

`flashpoint-get-forum-room-details`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| room_id | Specify the room ID which is used to retrieve the room information in the forum. The room ID can be known from the context path `Flashpoint.Forum.Post.Room.id` of flashpoint-search-forum-posts command or some other investigation. | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Flashpoint.Forum.Room.Forum | Unknown | Display all forum details such as forum name, hostname, platform URL, stats and tags etc. |
| Flashpoint.Forum.Room.Title | string | The room title. A user can use the same title in the forum search command. |
| Flashpoint.Forum.Room.Url | string | The room's URL. |
| Flashpoint.Forum.Room.RoomId | string | The unique ID of the forum room. |

##### Command Example
```
!flashpoint-get-forum-room-details room_id="dBoQqur5XmGGYLxSrc8C9A"
```

##### Context Example
```
{
    "Flashpoint.Forum.Room": {
        "Forum": {
            "description": "This is the restored 2013 database of the Carding.pro SQL dump. Crdpro was set up by the threat actor operating under the alias \"Makaka\" to drive traffic to their forum Crdclub.",
            "hostname": "crdpro.su",
            "id": "4aFfW6e7VVea1cP7G-Z7mw",
            "legacy_id": "_OU09w6LVm69kgAyDaTv5A",
            "name": "Crdpro",
            "platform_url": "https://fp.tools/home/search/forums?forum_ids=4aFfW6e7VVea1cP7G-Z7mw",
            "stats": {
                "posts": 987018,
                "rooms": 132,
                "threads": 116115,
                "users": 50902
            },
            "tags": [
                {
                    "id": 6,
                    "name": "Cyber Threat",
                    "parent_tag": null,
                    "uuid": "09fb6a4a-e072-495d-97bf-d80f059828fd"
                },
                {
                    "id": 9,
                    "name": "Fraud",
                    "parent_tag": null,
                    "uuid": "fa9a9533-0cf1-42b6-9553-08ebbbaaa60b"
                },
                {
                    "id": 28,
                    "name": "Language",
                    "parent_tag": null,
                    "uuid": "6d6719ac-9ead-4980-a783-1f32ac398e2b"
                },
                {
                    "id": 29,
                    "name": "English",
                    "parent_tag": null,
                    "uuid": "2fb5aeb5-7afc-4e04-a5bc-465297456ffc"
                },
                {
                    "id": 30,
                    "name": "Russian",
                    "parent_tag": null,
                    "uuid": "c3815816-c639-4ea2-9e5c-aec29eee2b1a"
                }
            ]
        },
        "RoomId": "dBoQqur5XmGGYLxSrc8C9A",
        "Title": "Bank Carding",
        "Url": "forumdisplay.php?f=70&s=6e25902255e1b57bfe37dd2749dafd66"
    }
}
```

##### Human Readable Output

##### Flashpoint Room details

##### Below are the detail found:

| **Forum Name** | **Title** | **URL** |
| --- | --- | --- |
| Crdpro | Bank Carding | forumdisplay.php?f=70&s=6e25902255e1b57bfe37dd2749dafd66 |

### Get the user's details

* * *

Gets details on the user.

##### Base Command

`flashpoint-get-forum-user-details`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | Specify a user's ID which is used to retrieve the user’s information. The user ID can be known from the context path `Flashpoint.Forum.Post.User.id` of flashpoint-search-forum-posts command or some other investigation. | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Flashpoint.Forum.User.Forum | Unknown | Display all of the forum's details like ID, hostname, description, stats, tags etc. |
| Flashpoint.Forum.User.Name | string | The name of the user. |
| Flashpoint.Forum.User.PlatformUrl | string | The platform URL of the user which is redirected to the Flashpoint platform. |
| Flashpoint.Forum.User.Url | string | The URL of the user. |
| Flashpoint.Forum.User.UserId | string | Unique ID of a forum user. |

##### Command Example
```
!flashpoint-get-forum-user-details user_id="P3au_EzEX4-uctmRfdUYeA"
```

##### Context Example
```
{
    "Flashpoint.Forum.User": {
        "Forum": {
            "description": "This is the restored 2013 database of the Carding.pro SQL dump. Crdpro was set up by the threat actor operating under the alias \"Makaka\" to drive traffic to their forum Crdclub.",
            "hostname": "crdpro.su",
            "id": "4aFfW6e7VVea1cP7G-Z7mw",
            "legacy_id": "_OU09w6LVm69kgAyDaTv5A",
            "name": "Crdpro",
            "platform_url": "https://fp.tools/home/search/forums?forum_ids=4aFfW6e7VVea1cP7G-Z7mw",
            "stats": {
                "posts": 987018,
                "rooms": 132,
                "threads": 116115,
                "users": 50902
            },
            "tags": [
                {
                    "id": 6,
                    "name": "Cyber Threat",
                    "parent_tag": null,
                    "uuid": "09fb6a4a-e072-495d-97bf-d80f059828fd"
                },
                {
                    "id": 9,
                    "name": "Fraud",
                    "parent_tag": null,
                    "uuid": "fa9a9533-0cf1-42b6-9553-08ebbbaaa60b"
                },
                {
                    "id": 28,
                    "name": "Language",
                    "parent_tag": null,
                    "uuid": "6d6719ac-9ead-4980-a783-1f32ac398e2b"
                },
                {
                    "id": 29,
                    "name": "English",
                    "parent_tag": null,
                    "uuid": "2fb5aeb5-7afc-4e04-a5bc-465297456ffc"
                },
                {
                    "id": 30,
                    "name": "Russian",
                    "parent_tag": null,
                    "uuid": "c3815816-c639-4ea2-9e5c-aec29eee2b1a"
                }
            ]
        },
        "Name": "IllWillPub",
        "PlatformUrl": "https://fp.tools/home/search/forums?author_id=P3au_EzEX4-uctmRfdUYeA",
        "Url": "http://www.crdpro.su/member.php?s=9f099a0eebc5f7c79e36fc688af2f697&u=50678",
        "UserId": "P3au_EzEX4-uctmRfdUYeA"
    }
}
```

##### Human Readable Output

##### Flashpoint User details

##### Below are the detail found:

| **Forum Name** | **Name** | **URL** |
| --- | --- | --- |
| Crdpro | IllWillPub | http:/<span></span>/www<span></span>.crdpro.su/member<span></span>.php?s=9f099a0eebc5f7c79e36fc688af2f697&u=50678 |

### Get the details of a post

* * *

Returns the details of a post.

##### Base Command

`flashpoint-get-forum-post-details`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| post_id | Specify the post ID which gives post information embed in the forum, room, user etc. The post ID can be known from the context path `Flashpoint.Forum.Post.PostId` of flashpoint-search-forum-posts command or some other investigation. | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Flashpoint.Forum.Post.Forum | Unknown | Display all forum details of a post such as ID, hostname, stats, description, tags etc. |
| Flashpoint.Forum.Post.Room | Unknown | Display the room details of a post such as room title, ID, URL, platform URL etc. |
| Flashpoint.Forum.Post.User | Unknown | Display a user's details of a post such as a user's ID, name, URL, platform URL etc. |
| Flashpoint.Forum.Post.PlatformUrl | string | The platform URL a user can redirect to the Flashpoint platform. |
| Flashpoint.Forum.Post.PublishedAt | Unknown | The published date of the post. |
| Flashpoint.Forum.Post.Url | Unknown | The URL display of the post. |
| Flashpoint.Forum.Post.PostId | string | The unique ID of the forum post. |

##### Command Example
```
!flashpoint-get-forum-post-details post_id=PDo1xGiKXDebHGc8fZme6g
```

##### Context Example
```
{
    "Flashpoint.Forum.Post": {
        "Forum": {
            "description": "Ukrainian forum with focus on Russian-Ukrainian conflict.",
            "hostname": "ord-ua.com",
            "id": "rJnT5ETuWcW9jTCnsobFZQ",
            "legacy_id": null,
            "name": "Ord-UA",
            "platform_url": "https://fp.tools/home/search/forums?forum_ids=rJnT5ETuWcW9jTCnsobFZQ",
            "stats": {
                "posts": 163710,
                "rooms": 1,
                "threads": 13916,
                "users": 71614
            },
            "tags": [
                {
                    "id": 55,
                    "name": "Communities in Conflict",
                    "parent_tag": 17,
                    "uuid": "83a2e5d4-e591-42be-943f-4af7d5de30e4"
                },
                {
                    "id": 28,
                    "name": "Language",
                    "parent_tag": null,
                    "uuid": "6d6719ac-9ead-4980-a783-1f32ac398e2b"
                },
                {
                    "id": 30,
                    "name": "Russian",
                    "parent_tag": 28,
                    "uuid": "c3815816-c639-4ea2-9e5c-aec29eee2b1a"
                },
                {
                    "id": 98,
                    "name": "Ukrainian",
                    "parent_tag": null,
                    "uuid": "9bf8c176-3b2d-4445-a2f5-6fe92843a4a1"
                }
            ]
        },
        "PlatformUrl": "https://fp.tools/home/ddw/forums/threads/M3NorvmYVoG6rVFHnP3T9w?id=PDo1xGiKXDebHGc8fZme6g",
        "PostId": "PDo1xGiKXDebHGc8fZme6g",
        "PublishedAt": "2019-12-10T01:17:00+00:00",
        "Room": {
            "forum": "/forums/sites/rJnT5ETuWcW9jTCnsobFZQ",
            "id": "UWUdaSQ7VXCkHq4KDQalpQ",
            "legacy_id": null,
            "native_id": "forum",
            "platform_url": "https://fp.tools/home/search/forums?room_title=\"%D0%A4%D0%BE%D1%80%D1%83%D0%BC\"",
            "title": "\u0424\u043e\u0440\u0443\u043c",
            "url": "forum"
        },
        "Url": "2014/10/22/dsns-na-choli-z-bochkovskim-i-k/?lpage=1&page=580",
        "User": {
            "id": "0vK-XB2KWaeYqXjXaO9ruA",
            "legacy_id": null,
            "name": "\u0414\u0443\u0431\u043e\u0432\u0438\u043a",
            "native_id": "\u0414\u0443\u0431\u043e\u0432\u0438\u043a",
            "platform_url": "https://fp.tools/home/search/forums?author_id=0vK-XB2KWaeYqXjXaO9ruA",
            "url": null
        }
    }
}
```

##### Human Readable Output

##### Flashpoint Post details

##### Below are the detail found:

| **Published at** | **Forum Name** | **Room Title** | **Author Name** | **Thread Title** | **URL** | **Platform url** |
| --- | --- | --- | --- | --- | --- | --- |
| 2019-12-10T01:17:00+00:00 | Ord-UA | Форум | Дубовик | ДСНС на чолі з Бочковським і К…. | 2014/10/22/dsns-na-choli-z-bochkovskim-i-k/?lpage=1&page=580 | https:/<span></span>/fp.tools/home/ddw/forums/threads/M3NorvmYVoG6rVFHnP3T9w?id=PDo1xGiKXDebHGc8fZme6g |

### Search forum sites

* * *

Searches the forum sites using a keyword. The search will return in-site content such as name, title, description etc.

##### Base Command

`flashpoint-search-forum-sites`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_search | Search by site keyword or text. This keyword is used for search information in forum sites. This keyword or text is known by fp user. | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Flashpoint.Forum.Site | Unknown | The list of forum site details based on the search keyword. |

##### Command Example
```
!flashpoint-search-forum-sites site_search="0hack"
```

##### Context Example
```
{
    "Flashpoint.Forum.Site": [
        {
            "Description": "0hack (\u96f6\u9ed1\u8054\u76df) is a Chinese-language hacker training forum. The forum appears to be affiliated with \u975e\u51e1\u5b89\u5168\u7f51, 803389.com.",
            "Hostname": "bbs.0hack.com",
            "Name": "0hack"
        }
    ]
}
```

##### Human Readable Output

##### Flashpoint Forum sites related to search: 0hack

Top 10 sites:

##### Below are the detail found:

| **Name** | **Hostname** | **Description** |
| --- | --- | --- |
| 0hack | bbs<span></span>.0hack<span></span>.com | 0hack (零黑联盟) is a Chinese-language hacker training forum. The forum appears to be affiliated with 非凡安全网, 803389<span></span>.com. |

### Search forum posts

* * *

Searches the forum posts using a keyword.

##### Base Command

`flashpoint-search-forum-posts`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| post_search | Search a post by keyword or text which is used for search information in forum posts. | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Flashpoint.Forum.Post | Unknown | Display a list of forum posts based on the specified search keyword. |

##### Command Example
```
!flashpoint-search-forum-posts post_search="The Courtyard Café"
```

##### Context Example
```
{
    "Flashpoint.Forum.Post": [
        {
            "Forum": {
                "description": "The Sammyboy Times forum",
                "hostname": "www.sammyboy.com",
                "id": "TTIpsoLTW8m1AKn4qU52sQ",
                "legacy_id": null,
                "name": "The Sammyboy Times",
                "platform_url": "https://fp.tools/home/search/forums?forum_ids=TTIpsoLTW8m1AKn4qU52sQ",
                "stats": {
                    "posts": 459033,
                    "rooms": 14,
                    "threads": 21736,
                    "users": 6571
                },
                "tags": [
                    {
                        "id": 6,
                        "name": "Cyber Threat",
                        "parent_tag": null,
                        "uuid": "09fb6a4a-e072-495d-97bf-d80f059828fd"
                    },
                    {
                        "id": 29,
                        "name": "English",
                        "parent_tag": 28,
                        "uuid": "2fb5aeb5-7afc-4e04-a5bc-465297456ffc"
                    },
                    {
                        "id": 8,
                        "name": "Hacking",
                        "parent_tag": 6,
                        "uuid": "c88a0cd8-a259-46d7-b8b4-b6e0060f16a0"
                    },
                    {
                        "id": 28,
                        "name": "Language",
                        "parent_tag": null,
                        "uuid": "6d6719ac-9ead-4980-a783-1f32ac398e2b"
                    }
                ]
            },
            "PlatformUrl": "https://fp.tools/home/ddw/forums/threads/BTdC6qjzVQ63D7p810ea8g?id=Exe7t24dVfSUooUSbsOPsw",
            "PostId": "Exe7t24dVfSUooUSbsOPsw",
            "PublishedAt": "2019-12-18T11:43:00+00:00",
            "Room": {
                "forum": "/forums/sites/TTIpsoLTW8m1AKn4qU52sQ",
                "id": "pVGplbH4XPGMwryH9g8L6g",
                "legacy_id": "PB9r4WC8Xh-7vP109JAUZQ",
                "native_id": "the-courtyard-caf%C3%A9.2",
                "platform_url": "https://fp.tools/home/search/forums?room_title=\"The%20Courtyard%20Caf%C3%A9\"",
                "title": "The Courtyard Caf\u00e9",
                "url": "forums/the-courtyard-caf%C3%A9.2"
            },
            "Url": "threads/kfc-promotion-8-pieces-sour-cream-onion-chicken-for-4-18-20-dec.277554/post-3015468",
            "User": {
                "id": "f5xG_0M2Wl-XFOpvlZGQow",
                "legacy_id": "oR-Cwv6DVF6tKAEr1g3ZjA",
                "name": "syed putra",
                "native_id": "4371",
                "platform_url": "https://fp.tools/home/search/forums?author_id=f5xG_0M2Wl-XFOpvlZGQow",
                "url": "https://www.sammyboy.com/members/syed-putra.4371"
            }
        },
        {
            "Forum": {
                "description": "The Sammyboy Times forum",
                "hostname": "www.sammyboy.com",
                "id": "TTIpsoLTW8m1AKn4qU52sQ",
                "legacy_id": null,
                "name": "The Sammyboy Times",
                "platform_url": "https://fp.tools/home/search/forums?forum_ids=TTIpsoLTW8m1AKn4qU52sQ",
                "stats": {
                    "posts": 459033,
                    "rooms": 14,
                    "threads": 21736,
                    "users": 6571
                },
                "tags": [
                    {
                        "id": 6,
                        "name": "Cyber Threat",
                        "parent_tag": null,
                        "uuid": "09fb6a4a-e072-495d-97bf-d80f059828fd"
                    },
                    {
                        "id": 29,
                        "name": "English",
                        "parent_tag": 28,
                        "uuid": "2fb5aeb5-7afc-4e04-a5bc-465297456ffc"
                    },
                    {
                        "id": 8,
                        "name": "Hacking",
                        "parent_tag": 6,
                        "uuid": "c88a0cd8-a259-46d7-b8b4-b6e0060f16a0"
                    },
                    {
                        "id": 28,
                        "name": "Language",
                        "parent_tag": null,
                        "uuid": "6d6719ac-9ead-4980-a783-1f32ac398e2b"
                    }
                ]
            },
            "PlatformUrl": "https://fp.tools/home/ddw/forums/threads/BTdC6qjzVQ63D7p810ea8g?id=xaQRdIiRW1eQ4kS6TxAC5A",
            "PostId": "xaQRdIiRW1eQ4kS6TxAC5A",
            "PublishedAt": "2019-12-18T11:41:00+00:00",
            "Room": {
                "forum": "/forums/sites/TTIpsoLTW8m1AKn4qU52sQ",
                "id": "pVGplbH4XPGMwryH9g8L6g",
                "legacy_id": "PB9r4WC8Xh-7vP109JAUZQ",
                "native_id": "the-courtyard-caf%C3%A9.2",
                "platform_url": "https://fp.tools/home/search/forums?room_title=\"The%20Courtyard%20Caf%C3%A9\"",
                "title": "The Courtyard Caf\u00e9",
                "url": "forums/the-courtyard-caf%C3%A9.2"
            },
            "Url": "threads/kfc-promotion-8-pieces-sour-cream-onion-chicken-for-4-18-20-dec.277554/post-3015466",
            "User": {
                "id": "HzP04FFEX_663EPpm8C1OA",
                "legacy_id": "Mm48bgjkWGGokSgpnl0kSQ",
                "name": "horny",
                "native_id": "153283",
                "platform_url": "https://fp.tools/home/search/forums?author_id=HzP04FFEX_663EPpm8C1OA",
                "url": "https://www.sammyboy.com/members/horny.153283"
            }
        },
        {
            "Forum": {
                "description": "The Sammyboy Times forum",
                "hostname": "www.sammyboy.com",
                "id": "TTIpsoLTW8m1AKn4qU52sQ",
                "legacy_id": null,
                "name": "The Sammyboy Times",
                "platform_url": "https://fp.tools/home/search/forums?forum_ids=TTIpsoLTW8m1AKn4qU52sQ",
                "stats": {
                    "posts": 459033,
                    "rooms": 14,
                    "threads": 21736,
                    "users": 6571
                },
                "tags": [
                    {
                        "id": 6,
                        "name": "Cyber Threat",
                        "parent_tag": null,
                        "uuid": "09fb6a4a-e072-495d-97bf-d80f059828fd"
                    },
                    {
                        "id": 29,
                        "name": "English",
                        "parent_tag": 28,
                        "uuid": "2fb5aeb5-7afc-4e04-a5bc-465297456ffc"
                    },
                    {
                        "id": 8,
                        "name": "Hacking",
                        "parent_tag": 6,
                        "uuid": "c88a0cd8-a259-46d7-b8b4-b6e0060f16a0"
                    },
                    {
                        "id": 28,
                        "name": "Language",
                        "parent_tag": null,
                        "uuid": "6d6719ac-9ead-4980-a783-1f32ac398e2b"
                    }
                ]
            },
            "PlatformUrl": "https://fp.tools/home/ddw/forums/threads/BTdC6qjzVQ63D7p810ea8g?id=iEDOMDW7XHOLQpHJvqIubA",
            "PostId": "iEDOMDW7XHOLQpHJvqIubA",
            "PublishedAt": "2019-12-18T11:40:00+00:00",
            "Room": {
                "forum": "/forums/sites/TTIpsoLTW8m1AKn4qU52sQ",
                "id": "pVGplbH4XPGMwryH9g8L6g",
                "legacy_id": "PB9r4WC8Xh-7vP109JAUZQ",
                "native_id": "the-courtyard-caf%C3%A9.2",
                "platform_url": "https://fp.tools/home/search/forums?room_title=\"The%20Courtyard%20Caf%C3%A9\"",
                "title": "The Courtyard Caf\u00e9",
                "url": "forums/the-courtyard-caf%C3%A9.2"
            },
            "Url": "threads/kfc-promotion-8-pieces-sour-cream-onion-chicken-for-4-18-20-dec.277554/post-3015464",
            "User": {
                "id": "f5xG_0M2Wl-XFOpvlZGQow",
                "legacy_id": "oR-Cwv6DVF6tKAEr1g3ZjA",
                "name": "syed putra",
                "native_id": "4371",
                "platform_url": "https://fp.tools/home/search/forums?author_id=f5xG_0M2Wl-XFOpvlZGQow",
                "url": "https://www.sammyboy.com/members/syed-putra.4371"
            }
        },
        {
            "Forum": {
                "description": "The Sammyboy Times forum",
                "hostname": "www.sammyboy.com",
                "id": "TTIpsoLTW8m1AKn4qU52sQ",
                "legacy_id": null,
                "name": "The Sammyboy Times",
                "platform_url": "https://fp.tools/home/search/forums?forum_ids=TTIpsoLTW8m1AKn4qU52sQ",
                "stats": {
                    "posts": 459033,
                    "rooms": 14,
                    "threads": 21736,
                    "users": 6571
                },
                "tags": [
                    {
                        "id": 6,
                        "name": "Cyber Threat",
                        "parent_tag": null,
                        "uuid": "09fb6a4a-e072-495d-97bf-d80f059828fd"
                    },
                    {
                        "id": 29,
                        "name": "English",
                        "parent_tag": 28,
                        "uuid": "2fb5aeb5-7afc-4e04-a5bc-465297456ffc"
                    },
                    {
                        "id": 8,
                        "name": "Hacking",
                        "parent_tag": 6,
                        "uuid": "c88a0cd8-a259-46d7-b8b4-b6e0060f16a0"
                    },
                    {
                        "id": 28,
                        "name": "Language",
                        "parent_tag": null,
                        "uuid": "6d6719ac-9ead-4980-a783-1f32ac398e2b"
                    }
                ]
            },
            "PlatformUrl": "https://fp.tools/home/ddw/forums/threads/g2g0cO3JUeyFrRQxblYCxw?id=cAGx-p5-VzGxNhcH88CgVQ",
            "PostId": "cAGx-p5-VzGxNhcH88CgVQ",
            "PublishedAt": "2019-12-18T11:23:00+00:00",
            "Room": {
                "forum": "/forums/sites/TTIpsoLTW8m1AKn4qU52sQ",
                "id": "pVGplbH4XPGMwryH9g8L6g",
                "legacy_id": "PB9r4WC8Xh-7vP109JAUZQ",
                "native_id": "the-courtyard-caf%C3%A9.2",
                "platform_url": "https://fp.tools/home/search/forums?room_title=\"The%20Courtyard%20Caf%C3%A9\"",
                "title": "The Courtyard Caf\u00e9",
                "url": "forums/the-courtyard-caf%C3%A9.2"
            },
            "Url": "threads/ministry-of-defence-mindef-is-a.277563/post-3015459",
            "User": {
                "id": "42aVe_v5UuidpcA80eekoQ",
                "legacy_id": "H16SdxrQVp6pmP-2sBO3lA",
                "name": "sweetiepie",
                "native_id": "64347",
                "platform_url": "https://fp.tools/home/search/forums?author_id=42aVe_v5UuidpcA80eekoQ",
                "url": "https://www.sammyboy.com/members/sweetiepie.64347"
            }
        },
        {
            "Forum": {
                "description": "The Sammyboy Times forum",
                "hostname": "www.sammyboy.com",
                "id": "TTIpsoLTW8m1AKn4qU52sQ",
                "legacy_id": null,
                "name": "The Sammyboy Times",
                "platform_url": "https://fp.tools/home/search/forums?forum_ids=TTIpsoLTW8m1AKn4qU52sQ",
                "stats": {
                    "posts": 459033,
                    "rooms": 14,
                    "threads": 21736,
                    "users": 6571
                },
                "tags": [
                    {
                        "id": 6,
                        "name": "Cyber Threat",
                        "parent_tag": null,
                        "uuid": "09fb6a4a-e072-495d-97bf-d80f059828fd"
                    },
                    {
                        "id": 29,
                        "name": "English",
                        "parent_tag": 28,
                        "uuid": "2fb5aeb5-7afc-4e04-a5bc-465297456ffc"
                    },
                    {
                        "id": 8,
                        "name": "Hacking",
                        "parent_tag": 6,
                        "uuid": "c88a0cd8-a259-46d7-b8b4-b6e0060f16a0"
                    },
                    {
                        "id": 28,
                        "name": "Language",
                        "parent_tag": null,
                        "uuid": "6d6719ac-9ead-4980-a783-1f32ac398e2b"
                    }
                ]
            },
            "PlatformUrl": "https://fp.tools/home/ddw/forums/threads/b-m8neykUly5gSeufYEfyQ?id=r0yTgwVaUvm_L6t4Y8O8Fw",
            "PostId": "r0yTgwVaUvm_L6t4Y8O8Fw",
            "PublishedAt": "2019-12-18T11:21:00+00:00",
            "Room": {
                "forum": "/forums/sites/TTIpsoLTW8m1AKn4qU52sQ",
                "id": "pVGplbH4XPGMwryH9g8L6g",
                "legacy_id": "PB9r4WC8Xh-7vP109JAUZQ",
                "native_id": "the-courtyard-caf%C3%A9.2",
                "platform_url": "https://fp.tools/home/search/forums?room_title=\"The%20Courtyard%20Caf%C3%A9\"",
                "title": "The Courtyard Caf\u00e9",
                "url": "forums/the-courtyard-caf%C3%A9.2"
            },
            "Url": "threads/church-holds-100-billion-for-2nd-coming-of-jesus-guess-church.277562/post-3015458",
            "User": {
                "id": "eMgRtiHVUiWc2Do8qlG18g",
                "legacy_id": "1Mh9MDBzUc-Vc7RBFwd3XA",
                "name": "JohnTan",
                "native_id": "106375",
                "platform_url": "https://fp.tools/home/search/forums?author_id=eMgRtiHVUiWc2Do8qlG18g",
                "url": "https://www.sammyboy.com/members/johntan.106375"
            }
        },
        {
            "Forum": {
                "description": "The Sammyboy Times forum",
                "hostname": "www.sammyboy.com",
                "id": "TTIpsoLTW8m1AKn4qU52sQ",
                "legacy_id": null,
                "name": "The Sammyboy Times",
                "platform_url": "https://fp.tools/home/search/forums?forum_ids=TTIpsoLTW8m1AKn4qU52sQ",
                "stats": {
                    "posts": 459033,
                    "rooms": 14,
                    "threads": 21736,
                    "users": 6571
                },
                "tags": [
                    {
                        "id": 6,
                        "name": "Cyber Threat",
                        "parent_tag": null,
                        "uuid": "09fb6a4a-e072-495d-97bf-d80f059828fd"
                    },
                    {
                        "id": 29,
                        "name": "English",
                        "parent_tag": 28,
                        "uuid": "2fb5aeb5-7afc-4e04-a5bc-465297456ffc"
                    },
                    {
                        "id": 8,
                        "name": "Hacking",
                        "parent_tag": 6,
                        "uuid": "c88a0cd8-a259-46d7-b8b4-b6e0060f16a0"
                    },
                    {
                        "id": 28,
                        "name": "Language",
                        "parent_tag": null,
                        "uuid": "6d6719ac-9ead-4980-a783-1f32ac398e2b"
                    }
                ]
            },
            "PlatformUrl": "https://fp.tools/home/ddw/forums/threads/KCxhIFNzV3yDC1W7cJE5Lw?id=mUPvMlpZW8WjGNYmgbA5jQ",
            "PostId": "mUPvMlpZW8WjGNYmgbA5jQ",
            "PublishedAt": "2019-12-18T11:15:00+00:00",
            "Room": {
                "forum": "/forums/sites/TTIpsoLTW8m1AKn4qU52sQ",
                "id": "pVGplbH4XPGMwryH9g8L6g",
                "legacy_id": "PB9r4WC8Xh-7vP109JAUZQ",
                "native_id": "the-courtyard-caf%C3%A9.2",
                "platform_url": "https://fp.tools/home/search/forums?room_title=\"The%20Courtyard%20Caf%C3%A9\"",
                "title": "The Courtyard Caf\u00e9",
                "url": "forums/the-courtyard-caf%C3%A9.2"
            },
            "Url": "threads/stressed-uni-student-has-addiction-to-womens-buttocks-caught-taking-upskirt-videos-guess-race-and-university.277560/post-3015456",
            "User": {
                "id": "eMgRtiHVUiWc2Do8qlG18g",
                "legacy_id": "1Mh9MDBzUc-Vc7RBFwd3XA",
                "name": "JohnTan",
                "native_id": "106375",
                "platform_url": "https://fp.tools/home/search/forums?author_id=eMgRtiHVUiWc2Do8qlG18g",
                "url": "https://www.sammyboy.com/members/johntan.106375"
            }
        },
        {
            "Forum": {
                "description": "The Sammyboy Times forum",
                "hostname": "www.sammyboy.com",
                "id": "TTIpsoLTW8m1AKn4qU52sQ",
                "legacy_id": null,
                "name": "The Sammyboy Times",
                "platform_url": "https://fp.tools/home/search/forums?forum_ids=TTIpsoLTW8m1AKn4qU52sQ",
                "stats": {
                    "posts": 459033,
                    "rooms": 14,
                    "threads": 21736,
                    "users": 6571
                },
                "tags": [
                    {
                        "id": 6,
                        "name": "Cyber Threat",
                        "parent_tag": null,
                        "uuid": "09fb6a4a-e072-495d-97bf-d80f059828fd"
                    },
                    {
                        "id": 29,
                        "name": "English",
                        "parent_tag": 28,
                        "uuid": "2fb5aeb5-7afc-4e04-a5bc-465297456ffc"
                    },
                    {
                        "id": 8,
                        "name": "Hacking",
                        "parent_tag": 6,
                        "uuid": "c88a0cd8-a259-46d7-b8b4-b6e0060f16a0"
                    },
                    {
                        "id": 28,
                        "name": "Language",
                        "parent_tag": null,
                        "uuid": "6d6719ac-9ead-4980-a783-1f32ac398e2b"
                    }
                ]
            },
            "PlatformUrl": "https://fp.tools/home/ddw/forums/threads/CYIQywO-Wx2t-2xWZpBz4w?id=GJsY66RSV6KW5Y0A1U30Kg",
            "PostId": "GJsY66RSV6KW5Y0A1U30Kg",
            "PublishedAt": "2019-12-18T11:09:00+00:00",
            "Room": {
                "forum": "/forums/sites/TTIpsoLTW8m1AKn4qU52sQ",
                "id": "pVGplbH4XPGMwryH9g8L6g",
                "legacy_id": "PB9r4WC8Xh-7vP109JAUZQ",
                "native_id": "the-courtyard-caf%C3%A9.2",
                "platform_url": "https://fp.tools/home/search/forums?room_title=\"The%20Courtyard%20Caf%C3%A9\"",
                "title": "The Courtyard Caf\u00e9",
                "url": "forums/the-courtyard-caf%C3%A9.2"
            },
            "Url": "threads/sph-let-go-5-media-staff-as-net-profit-slumps-23-while-ceo-ng-still-paid-in-millions.277529/post-3015454",
            "User": {
                "id": "pofOSuuqVGi-UM9aar9mug",
                "legacy_id": "_jef3w0FWEyoy8ka_1QyTw",
                "name": "Valium",
                "native_id": "155762",
                "platform_url": "https://fp.tools/home/search/forums?author_id=pofOSuuqVGi-UM9aar9mug",
                "url": "https://www.sammyboy.com/members/valium.155762"
            }
        },
        {
            "Forum": {
                "description": "The Sammyboy Times forum",
                "hostname": "www.sammyboy.com",
                "id": "TTIpsoLTW8m1AKn4qU52sQ",
                "legacy_id": null,
                "name": "The Sammyboy Times",
                "platform_url": "https://fp.tools/home/search/forums?forum_ids=TTIpsoLTW8m1AKn4qU52sQ",
                "stats": {
                    "posts": 459033,
                    "rooms": 14,
                    "threads": 21736,
                    "users": 6571
                },
                "tags": [
                    {
                        "id": 6,
                        "name": "Cyber Threat",
                        "parent_tag": null,
                        "uuid": "09fb6a4a-e072-495d-97bf-d80f059828fd"
                    },
                    {
                        "id": 29,
                        "name": "English",
                        "parent_tag": 28,
                        "uuid": "2fb5aeb5-7afc-4e04-a5bc-465297456ffc"
                    },
                    {
                        "id": 8,
                        "name": "Hacking",
                        "parent_tag": 6,
                        "uuid": "c88a0cd8-a259-46d7-b8b4-b6e0060f16a0"
                    },
                    {
                        "id": 28,
                        "name": "Language",
                        "parent_tag": null,
                        "uuid": "6d6719ac-9ead-4980-a783-1f32ac398e2b"
                    }
                ]
            },
            "PlatformUrl": "https://fp.tools/home/ddw/forums/threads/YpOP1H1RWwuc4-Dov2Cwww?id=xT3N2UWEW-SR1Gb9vBoGLQ",
            "PostId": "xT3N2UWEW-SR1Gb9vBoGLQ",
            "PublishedAt": "2019-12-18T11:00:00+00:00",
            "Room": {
                "forum": "/forums/sites/TTIpsoLTW8m1AKn4qU52sQ",
                "id": "pVGplbH4XPGMwryH9g8L6g",
                "legacy_id": "PB9r4WC8Xh-7vP109JAUZQ",
                "native_id": "the-courtyard-caf%C3%A9.2",
                "platform_url": "https://fp.tools/home/search/forums?room_title=\"The%20Courtyard%20Caf%C3%A9\"",
                "title": "The Courtyard Caf\u00e9",
                "url": "forums/the-courtyard-caf%C3%A9.2"
            },
            "Url": "threads/oh-is-this-what-pofma-really-stands-for.277558/post-3015452",
            "User": {
                "id": "oWWKc07zUO-VGKR8BdVohw",
                "legacy_id": "0ZN7piYkW9-0G00EgohtNQ",
                "name": "TerrexLee",
                "native_id": "120397",
                "platform_url": "https://fp.tools/home/search/forums?author_id=oWWKc07zUO-VGKR8BdVohw",
                "url": "https://www.sammyboy.com/members/terrexlee.120397"
            }
        },
        {
            "Forum": {
                "description": "The Sammyboy Times forum",
                "hostname": "www.sammyboy.com",
                "id": "TTIpsoLTW8m1AKn4qU52sQ",
                "legacy_id": null,
                "name": "The Sammyboy Times",
                "platform_url": "https://fp.tools/home/search/forums?forum_ids=TTIpsoLTW8m1AKn4qU52sQ",
                "stats": {
                    "posts": 459033,
                    "rooms": 14,
                    "threads": 21736,
                    "users": 6571
                },
                "tags": [
                    {
                        "id": 6,
                        "name": "Cyber Threat",
                        "parent_tag": null,
                        "uuid": "09fb6a4a-e072-495d-97bf-d80f059828fd"
                    },
                    {
                        "id": 29,
                        "name": "English",
                        "parent_tag": 28,
                        "uuid": "2fb5aeb5-7afc-4e04-a5bc-465297456ffc"
                    },
                    {
                        "id": 8,
                        "name": "Hacking",
                        "parent_tag": 6,
                        "uuid": "c88a0cd8-a259-46d7-b8b4-b6e0060f16a0"
                    },
                    {
                        "id": 28,
                        "name": "Language",
                        "parent_tag": null,
                        "uuid": "6d6719ac-9ead-4980-a783-1f32ac398e2b"
                    }
                ]
            },
            "PlatformUrl": "https://fp.tools/home/ddw/forums/threads/KPNwvwZVXf-m79AGqquJ8Q?id=pFpDpiKgVWGixxAPKQqsyA",
            "PostId": "pFpDpiKgVWGixxAPKQqsyA",
            "PublishedAt": "2019-12-18T10:57:00+00:00",
            "Room": {
                "forum": "/forums/sites/TTIpsoLTW8m1AKn4qU52sQ",
                "id": "pVGplbH4XPGMwryH9g8L6g",
                "legacy_id": "PB9r4WC8Xh-7vP109JAUZQ",
                "native_id": "the-courtyard-caf%C3%A9.2",
                "platform_url": "https://fp.tools/home/search/forums?room_title=\"The%20Courtyard%20Caf%C3%A9\"",
                "title": "The Courtyard Caf\u00e9",
                "url": "forums/the-courtyard-caf%C3%A9.2"
            },
            "Url": "threads/workforce-sg-wsg-is-a.277557/post-3015451",
            "User": {
                "id": "42aVe_v5UuidpcA80eekoQ",
                "legacy_id": "H16SdxrQVp6pmP-2sBO3lA",
                "name": "sweetiepie",
                "native_id": "64347",
                "platform_url": "https://fp.tools/home/search/forums?author_id=42aVe_v5UuidpcA80eekoQ",
                "url": "https://www.sammyboy.com/members/sweetiepie.64347"
            }
        },
        {
            "Forum": {
                "description": "The Sammyboy Times forum",
                "hostname": "www.sammyboy.com",
                "id": "TTIpsoLTW8m1AKn4qU52sQ",
                "legacy_id": null,
                "name": "The Sammyboy Times",
                "platform_url": "https://fp.tools/home/search/forums?forum_ids=TTIpsoLTW8m1AKn4qU52sQ",
                "stats": {
                    "posts": 459033,
                    "rooms": 14,
                    "threads": 21736,
                    "users": 6571
                },
                "tags": [
                    {
                        "id": 6,
                        "name": "Cyber Threat",
                        "parent_tag": null,
                        "uuid": "09fb6a4a-e072-495d-97bf-d80f059828fd"
                    },
                    {
                        "id": 29,
                        "name": "English",
                        "parent_tag": 28,
                        "uuid": "2fb5aeb5-7afc-4e04-a5bc-465297456ffc"
                    },
                    {
                        "id": 8,
                        "name": "Hacking",
                        "parent_tag": 6,
                        "uuid": "c88a0cd8-a259-46d7-b8b4-b6e0060f16a0"
                    },
                    {
                        "id": 28,
                        "name": "Language",
                        "parent_tag": null,
                        "uuid": "6d6719ac-9ead-4980-a783-1f32ac398e2b"
                    }
                ]
            },
            "PlatformUrl": "https://fp.tools/home/ddw/forums/threads/CYIQywO-Wx2t-2xWZpBz4w?id=0guT14M-X2ixzc-MuDJPmw",
            "PostId": "0guT14M-X2ixzc-MuDJPmw",
            "PublishedAt": "2019-12-18T10:49:00+00:00",
            "Room": {
                "forum": "/forums/sites/TTIpsoLTW8m1AKn4qU52sQ",
                "id": "pVGplbH4XPGMwryH9g8L6g",
                "legacy_id": "PB9r4WC8Xh-7vP109JAUZQ",
                "native_id": "the-courtyard-caf%C3%A9.2",
                "platform_url": "https://fp.tools/home/search/forums?room_title=\"The%20Courtyard%20Caf%C3%A9\"",
                "title": "The Courtyard Caf\u00e9",
                "url": "forums/the-courtyard-caf%C3%A9.2"
            },
            "Url": "threads/sph-let-go-5-media-staff-as-net-profit-slumps-23-while-ceo-ng-still-paid-in-millions.277529/post-3015450",
            "User": {
                "id": "r__we_wyX3WZ0MOlSx_MQQ",
                "legacy_id": "eve1h4-TU_mnlrgoYPCdqQ",
                "name": "Loofydralb",
                "native_id": "2174",
                "platform_url": "https://fp.tools/home/search/forums?author_id=r__we_wyX3WZ0MOlSx_MQQ",
                "url": "https://www.sammyboy.com/members/loofydralb.2174"
            }
        }
    ]
}
```

##### Human Readable Output

##### Flashpoint Forum posts related to search: The Courtyard Café

Top 10 posts:

##### Below are the detail found:

| **Forum Name** | **Thread Title** | **Room Title** | **Author Name** | **Platform URL** |
| --- | --- | --- | --- | --- |
| The Sammyboy Times | Fleeting Pleasures… | The Courtyard Café | glockman | https:/<span></span>/fp.tools/home/ddw/foru… |
| The Sammyboy Times | smoke on the water, fire in th… | The Courtyard Café | syed putra | https:/<span></span>/fp.tools/home/ddw/foru… |
| The Sammyboy Times | [Singapore] - French girl kena… | The Courtyard Café | laksaboy | https:/<span></span>/fp.tools/home/ddw/foru… |
| The Sammyboy Times | smoke on the water, fire in th… | The Courtyard Café | laksaboy | https:/<span></span>/fp.tools/home/ddw/foru… |
| The Sammyboy Times | smoke on the water, fire in th… | The Courtyard Café | Leongsam | https:/<span></span>/fp.tools/home/ddw/foru… |
| The Sammyboy Times | smoke on the water, fire in th… | The Courtyard Café | rambo22 | https:/<span></span>/fp.tools/home/ddw/foru… |
| The Sammyboy Times | Fleeting Pleasures… | The Courtyard Café | nightsafari | https:/<span></span>/fp.tools/home/ddw/foru… |
| The Sammyboy Times | [Singapore] - French girl kena… | The Courtyard Café | nightsafari | https:/<span></span>/fp.tools/home/ddw/foru… |
| The Sammyboy Times | [Singapore] - French girl kena… | The Courtyard Café | nightsafari | https:/<span></span>/fp.tools/home/ddw/foru… |
| The Sammyboy Times | HTHT… | The Courtyard Café | Claire | https:/<span></span>/fp.tools/home/ddw/foru… |

Follow this [link](https://fp.tools/home/search/forums?query=The%20Courtyard%20Caf%C3%A9) to forum post-search on Flashpoint platform.
