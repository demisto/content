## Overview
---

Use the Cisco Firepower integration for unified management of firewalls, application control, intrusion prevention, URL filtering, and advanced malware protection.

Supports FMC 6.2.3 and above

Authentication from a REST API Client
Cisco recommends that you use different accounts for interfacing with the API and the Firepower User Interface. Credentials cannot be used for both interfaces simultaneously, and will be logged out without warning if used for both.


## Configure Cisco Firepower on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Cisco Firepower.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server URL (e.g., https://192.168.0.1)__
    * __Username__
    * __Password__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. ciscofp-list-zones
2. ciscofp-list-ports
3. ciscofp-list-url-categories
4. ciscofp-get-network-object
5. ciscofp-create-network-object
6. ciscofp-update-network-object
7. ciscofp-get-network-groups-object
8. ciscofp-create-network-groups-objects
9. ciscofp-update-network-groups-objects
10. ciscofp-delete-network-groups-objects
11. ciscofp-get-host-object
12. ciscofp-create-host-object
13. ciscofp-update-host-object
14. ciscofp-delete-network-object
15. ciscofp-delete-host-object
16. ciscofp-get-access-policy
17. ciscofp-create-access-policy
18. ciscofp-update-access-policy
19. ciscofp-delete-access-policy
20. ciscofp-list-security-group-tags
21. ciscofp-list-ise-security-group-tag
22. ciscofp-list-vlan-tags
23. ciscofp-list-vlan-tags-group
24. ciscofp-list-applications
25. ciscofp-get-access-rules
26. ciscofp-create-access-rules
27. ciscofp-update-access-rules
28. ciscofp-delete-access-rules
29. ciscofp-list-policy-assignments
30. ciscofp-create-policy-assignments
31. ciscofp-update-policy-assignments
32. ciscofp-get-deployable-devices
33. ciscofp-get-device-records
34. ciscofp-deploy-to-devices
35. ciscofp-get-task-status
### 1. ciscofp-list-zones
---
Retrieves a list of all security zone objects.

##### Base Command

`ciscofp-list-zones`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of items to return. The default is 50. | Optional | 
| offset | Index of first item to return. The default is 0. | Optional | 

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Zone.ID | String | Zone ID. | 
| CiscoFP.Zone.Name | String | Zone name. | 
| CiscoFP.Zone.InterfaceMode | String | Zone interface mode. | 
| CiscoFP.Zone.Interfaces.Name | String | Name of interfaces belonging to the security zone. | 
| CiscoFP.Zone.Interfaces.ID | String | ID of interfaces belonging to the security zone. | 


##### Command Example
```!ciscofp-list-zones```

##### Context Example
```
{
    "CiscoFP.Zone": [
        {
            "InterfaceMode": "ROUTED", 
            "Interfaces": [
                {
                    "ID": "000C29A8-BA3B-0ed3-0000-103079217112", 
                    "Name": "Ethernet1/6"
                }
            ], 
            "ID": "e5156ab2-c736-11e8-bacb-8d7a1cfa386e", 
            "Name": "Trust"
        }, 
        {
            "InterfaceMode": "ROUTED", 
            "Interfaces": [
                {
                    "ID": "000C29A8-BA3B-0ed3-0000-103079217113", 
                    "Name": "Ethernet1/7"
                }
            ], 
            "ID": "001e2d12-c737-11e8-bacb-8d7a1cfa386e", 
            "Name": "Untrust"
        }, 
        {
            "InterfaceMode": "ROUTED", 
            "Interfaces": [
                {
                    "ID": "000C29A8-BA3B-0ed3-0000-103079217109", 
                    "Name": "Ethernet1/3"
                }
            ], 
            "ID": "5884acce-ffdf-11e9-8a1b-81dfc51749cb", 
            "Name": "L3-Trust"
        }, 
        {
            "InterfaceMode": "ROUTED", 
            "Interfaces": [
                {
                    "ID": "000C29A8-BA3B-0ed3-0000-103079217111", 
                    "Name": "Ethernet1/5"
                }
            ], 
            "ID": "6038978c-ffdf-11e9-8a1b-81dfc51749cb", 
            "Name": "L3-Untrust"
        }, 
        {
            "InterfaceMode": "INLINE", 
            "Interfaces": [], 
            "ID": "62c3f83a-305d-11ea-9d47-eda81976c864", 
            "Name": "arseny_zone"
        }
    ]
}
```

##### Human Readable Output
### Cisco Firepower - List zones:
|ID|Name|InterfaceMode|Interfaces|
|---|---|---|---|
| e5156ab2-c736-11e8-bacb-8d7a1cfa386e | Trust | ROUTED | 1 |
| 001e2d12-c737-11e8-bacb-8d7a1cfa386e | Untrust | ROUTED | 1 |
| 5884acce-ffdf-11e9-8a1b-81dfc51749cb | L3-Trust | ROUTED | 1 |
| 6038978c-ffdf-11e9-8a1b-81dfc51749cb | L3-Untrust | ROUTED | 1 |
| 62c3f83a-305d-11ea-9d47-eda81976c864 | arseny_zone | INLINE | 0 |


### 2. ciscofp-list-ports
---
Retrieves list of all port objects.

##### Base Command

`ciscofp-list-ports`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of items to return. The default is 50. | Optional | 
| offset | Index of first item to return. The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Port.ID | String | Port ID. | 
| CiscoFP.Port.Name | String | Port name. | 
| CiscoFP.Port.Protocol | String | Port protocol. | 
| CiscoFP.Port.Port | String | Port number. | 


##### Command Example
```!ciscofp-list-ports```

##### Context Example
```
{
    "CiscoFP.Port": [
        {
            "Port": "5190", 
            "Protocol": "TCP", 
            "ID": "1834d812-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "AOL"
        }, 
        {
            "Port": "6881-6889", 
            "Protocol": "TCP", 
            "ID": "1834e5f0-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "Bittorrent"
        }, 
        {
            "Port": "53", 
            "Protocol": "TCP", 
            "ID": "1834e712-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "DNS_over_TCP"
        }, 
        {
            "Port": "53", 
            "Protocol": "UDP", 
            "ID": "1834e8ca-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "DNS_over_UDP"
        }, 
        {
            "Port": "21", 
            "Protocol": "TCP", 
            "ID": "1834c674-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "FTP"
        }, 
        {
            "Port": "80", 
            "Protocol": "TCP", 
            "ID": "18312adc-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "HTTP"
        }, 
        {
            "Port": "443", 
            "Protocol": "TCP", 
            "ID": "1834bd00-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "HTTPS"
        }, 
        {
            "Port": "143", 
            "Protocol": "TCP", 
            "ID": "1834c37c-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "IMAP"
        }, 
        {
            "Port": "389", 
            "Protocol": "TCP", 
            "ID": "1834d01a-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "LDAP"
        }, 
        {
            "Port": "2049", 
            "Protocol": "TCP", 
            "ID": "1834c9c6-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "NFSD-TCP"
        }, 
        {
            "Port": "2049", 
            "Protocol": "UDP", 
            "ID": "1834caac-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "NFSD-UDP"
        }, 
        {
            "Port": "123", 
            "Protocol": "TCP", 
            "ID": "1834cb92-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "NTP-TCP"
        }, 
        {
            "Port": "123", 
            "Protocol": "UDP", 
            "ID": "1834cc96-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "NTP-UDP"
        }, 
        {
            "Port": "109", 
            "Protocol": "TCP", 
            "ID": "1834c462-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "POP-2"
        }, 
        {
            "Port": "110", 
            "Protocol": "TCP", 
            "ID": "1834c548-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "POP-3"
        }, 
        {
            "Port": "443", 
            "Protocol": "UDP", 
            "ID": "000C29A8-BA3B-0ed3-0000-034359739875", 
            "Name": "quic"
        }, 
        {
            "Port": "80", 
            "Protocol": "UDP", 
            "ID": "000C29A8-BA3B-0ed3-0000-034359739893", 
            "Name": "quic80"
        }, 
        {
            "Port": "1645", 
            "Protocol": "UDP", 
            "ID": "1834ce94-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "RADIUS"
        }, 
        {
            "Port": "520", 
            "Protocol": "UDP", 
            "ID": "1834d114-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "RIP"
        }, 
        {
            "Port": "5060", 
            "Protocol": "UDP", 
            "ID": "1834d204-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "SIP"
        }, 
        {
            "Port": "25", 
            "Protocol": "TCP", 
            "ID": "1834bf44-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "SMTP"
        }, 
        {
            "Port": "465", 
            "Protocol": "TCP", 
            "ID": "1834c07a-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "SMTPS"
        }, 
        {
            "Port": "161", 
            "Protocol": "UDP", 
            "ID": "1834c264-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "SNMP"
        }, 
        {
            "Port": "22", 
            "Protocol": "TCP", 
            "ID": "1834c890-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "SSH"
        }, 
        {
            "Port": "514", 
            "Protocol": "UDP", 
            "ID": "1834d6e6-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "SYSLOG"
        }, 
        {
            "Port": "1021-65535", 
            "Protocol": "TCP", 
            "ID": "1834e50a-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "TCP_high_ports"
        }, 
        {
            "Port": "23", 
            "Protocol": "TCP", 
            "ID": "28e058e4-43b0-11e2-9bcd-7c2f9ed9bbee", 
            "Name": "TELNET"
        }, 
        {
            "Port": "69", 
            "Protocol": "UDP", 
            "ID": "1834d5e2-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "TFTP"
        }, 
        {
            "Port": "5050", 
            "Protocol": "TCP", 
            "ID": "1834da1a-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "Yahoo_Messenger_Messages"
        }, 
        {
            "Port": "5000-5001", 
            "Protocol": "TCP", 
            "ID": "1834db96-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "YahooMessenger_Voice_Chat_TCP"
        }, 
        {
            "Port": "5000-5010", 
            "Protocol": "UDP", 
            "ID": "1834dc86-38bb-11e2-86aa-62f0c593a59a", 
            "Name": "YahooMessenger_Voice_Chat_UDP"
        }
    ]
}
```

##### Human Readable Output
### Cisco Firepower - List ports:
|ID|Name|Protocol|Port|
|---|---|---|---|
| 1834d812-38bb-11e2-86aa-62f0c593a59a | AOL | TCP | 5190 |
| 1834e5f0-38bb-11e2-86aa-62f0c593a59a | Bittorrent | TCP | 6881-6889 |
| 1834e712-38bb-11e2-86aa-62f0c593a59a | DNS_over_TCP | TCP | 53 |
| 1834e8ca-38bb-11e2-86aa-62f0c593a59a | DNS_over_UDP | UDP | 53 |
| 1834c674-38bb-11e2-86aa-62f0c593a59a | FTP | TCP | 21 |
| 18312adc-38bb-11e2-86aa-62f0c593a59a | HTTP | TCP | 80 |
| 1834bd00-38bb-11e2-86aa-62f0c593a59a | HTTPS | TCP | 443 |
| 1834c37c-38bb-11e2-86aa-62f0c593a59a | IMAP | TCP | 143 |
| 1834d01a-38bb-11e2-86aa-62f0c593a59a | LDAP | TCP | 389 |
| 1834c9c6-38bb-11e2-86aa-62f0c593a59a | NFSD-TCP | TCP | 2049 |
| 1834caac-38bb-11e2-86aa-62f0c593a59a | NFSD-UDP | UDP | 2049 |
| 1834cb92-38bb-11e2-86aa-62f0c593a59a | NTP-TCP | TCP | 123 |
| 1834cc96-38bb-11e2-86aa-62f0c593a59a | NTP-UDP | UDP | 123 |
| 1834c462-38bb-11e2-86aa-62f0c593a59a | POP-2 | TCP | 109 |
| 1834c548-38bb-11e2-86aa-62f0c593a59a | POP-3 | TCP | 110 |
| 000C29A8-BA3B-0ed3-0000-034359739875 | quic | UDP | 443 |
| 000C29A8-BA3B-0ed3-0000-034359739893 | quic80 | UDP | 80 |
| 1834ce94-38bb-11e2-86aa-62f0c593a59a | RADIUS | UDP | 1645 |
| 1834d114-38bb-11e2-86aa-62f0c593a59a | RIP | UDP | 520 |
| 1834d204-38bb-11e2-86aa-62f0c593a59a | SIP | UDP | 5060 |
| 1834bf44-38bb-11e2-86aa-62f0c593a59a | SMTP | TCP | 25 |
| 1834c07a-38bb-11e2-86aa-62f0c593a59a | SMTPS | TCP | 465 |
| 1834c264-38bb-11e2-86aa-62f0c593a59a | SNMP | UDP | 161 |
| 1834c890-38bb-11e2-86aa-62f0c593a59a | SSH | TCP | 22 |
| 1834d6e6-38bb-11e2-86aa-62f0c593a59a | SYSLOG | UDP | 514 |
| 1834e50a-38bb-11e2-86aa-62f0c593a59a | TCP_high_ports | TCP | 1021-65535 |
| 28e058e4-43b0-11e2-9bcd-7c2f9ed9bbee | TELNET | TCP | 23 |
| 1834d5e2-38bb-11e2-86aa-62f0c593a59a | TFTP | UDP | 69 |
| 1834da1a-38bb-11e2-86aa-62f0c593a59a | Yahoo_Messenger_Messages | TCP | 5050 |
| 1834db96-38bb-11e2-86aa-62f0c593a59a | YahooMessenger_Voice_Chat_TCP | TCP | 5000-5001 |
| 1834dc86-38bb-11e2-86aa-62f0c593a59a | YahooMessenger_Voice_Chat_UDP | UDP | 5000-5010 |


### 3. ciscofp-list-url-categories
---
Retrieves a list of all URL category objects.

##### Base Command

`ciscofp-list-url-categories`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of items to return. The default is 50. | Optional | 
| offset | Index of first item to return. The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Category.ID | String | ID of the category. | 
| CiscoFP.Category.Name | String | Name of the category. | 


##### Command Example
```!ciscofp-list-url-categories```

##### Context Example
```
{
    "CiscoFP.Category": [
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02054", 
            "Name": "Pornography"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02042", 
            "Name": "Spiritual Healing"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02033", 
            "Name": "Tasteless or Obscene"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02005", 
            "Name": "Shopping"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02016", 
            "Name": "Hate Speech"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02082", 
            "Name": "Digital Postcards"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02028", 
            "Name": "Online Trading"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02034", 
            "Name": "Lotteries"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02071", 
            "Name": "File Transfer Services"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02043", 
            "Name": "Tattoos"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02029", 
            "Name": "Paranormal and Occult"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02064", 
            "Name": "Child Abuse Content"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02007", 
            "Name": "Games"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02037", 
            "Name": "Web Hosting"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02013", 
            "Name": "Nature"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02066", 
            "Name": "Online Storage and Backup"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02070", 
            "Name": "Mobile Phones"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02012", 
            "Name": "Science and Technology"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02022", 
            "Name": "Illegal Activities"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02080", 
            "Name": "SaaS and B2B"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02092", 
            "Name": "Parked Domains"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02008", 
            "Name": "Sports and Recreation"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02001", 
            "Name": "Education"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02024", 
            "Name": "Online Communities"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02096", 
            "Name": "Test Category 3"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02031", 
            "Name": "Lingerie and Swimsuits"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02051", 
            "Name": "Cheating and Plagiarism"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02050", 
            "Name": "Hacking"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02017", 
            "Name": "Reference"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02076", 
            "Name": "Fashion"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02025", 
            "Name": "Filter Avoidance"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02083", 
            "Name": "Politics"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02067", 
            "Name": "Internet Telephony"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02097", 
            "Name": "DIY Projects"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02093", 
            "Name": "Entertainment"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02077", 
            "Name": "Alcohol"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02039", 
            "Name": "Instant Messaging"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02036", 
            "Name": "Weapons"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02075", 
            "Name": "Extreme"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02009", 
            "Name": "Health and Nutrition"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02015", 
            "Name": "Finance"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02074", 
            "Name": "Astrology"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02081", 
            "Name": "Personal Sites"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02073", 
            "Name": "Streaming Audio"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02084", 
            "Name": "Illegal Downloads"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02006", 
            "Name": "Adult"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02061", 
            "Name": "Dining and Drinking"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02026", 
            "Name": "Streaming Media"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02085", 
            "Name": "Organizational Email"
        }, 
        {
            "ID": "abba9b63-bb10-4729-b901-2e2aa0f02020", 
            "Name": "Search Engines and Portals"
        }
    ]
}
```

##### Human Readable Output
### Cisco Firepower - List url categories:
|ID|Name|
|---|---|
| abba9b63-bb10-4729-b901-2e2aa0f02054 | Pornography |
| abba9b63-bb10-4729-b901-2e2aa0f02042 | Spiritual Healing |
| abba9b63-bb10-4729-b901-2e2aa0f02033 | Tasteless or Obscene |
| abba9b63-bb10-4729-b901-2e2aa0f02005 | Shopping |
| abba9b63-bb10-4729-b901-2e2aa0f02016 | Hate Speech |
| abba9b63-bb10-4729-b901-2e2aa0f02082 | Digital Postcards |
| abba9b63-bb10-4729-b901-2e2aa0f02028 | Online Trading |
| abba9b63-bb10-4729-b901-2e2aa0f02034 | Lotteries |
| abba9b63-bb10-4729-b901-2e2aa0f02071 | File Transfer Services |
| abba9b63-bb10-4729-b901-2e2aa0f02043 | Tattoos |
| abba9b63-bb10-4729-b901-2e2aa0f02029 | Paranormal and Occult |
| abba9b63-bb10-4729-b901-2e2aa0f02064 | Child Abuse Content |
| abba9b63-bb10-4729-b901-2e2aa0f02007 | Games |
| abba9b63-bb10-4729-b901-2e2aa0f02037 | Web Hosting |
| abba9b63-bb10-4729-b901-2e2aa0f02013 | Nature |
| abba9b63-bb10-4729-b901-2e2aa0f02066 | Online Storage and Backup |
| abba9b63-bb10-4729-b901-2e2aa0f02070 | Mobile Phones |
| abba9b63-bb10-4729-b901-2e2aa0f02012 | Science and Technology |
| abba9b63-bb10-4729-b901-2e2aa0f02022 | Illegal Activities |
| abba9b63-bb10-4729-b901-2e2aa0f02080 | SaaS and B2B |
| abba9b63-bb10-4729-b901-2e2aa0f02092 | Parked Domains |
| abba9b63-bb10-4729-b901-2e2aa0f02008 | Sports and Recreation |
| abba9b63-bb10-4729-b901-2e2aa0f02001 | Education |
| abba9b63-bb10-4729-b901-2e2aa0f02024 | Online Communities |
| abba9b63-bb10-4729-b901-2e2aa0f02096 | Test Category 3 |
| abba9b63-bb10-4729-b901-2e2aa0f02031 | Lingerie and Swimsuits |
| abba9b63-bb10-4729-b901-2e2aa0f02051 | Cheating and Plagiarism |
| abba9b63-bb10-4729-b901-2e2aa0f02050 | Hacking |
| abba9b63-bb10-4729-b901-2e2aa0f02017 | Reference |
| abba9b63-bb10-4729-b901-2e2aa0f02076 | Fashion |
| abba9b63-bb10-4729-b901-2e2aa0f02025 | Filter Avoidance |
| abba9b63-bb10-4729-b901-2e2aa0f02083 | Politics |
| abba9b63-bb10-4729-b901-2e2aa0f02067 | Internet Telephony |
| abba9b63-bb10-4729-b901-2e2aa0f02097 | DIY Projects |
| abba9b63-bb10-4729-b901-2e2aa0f02093 | Entertainment |
| abba9b63-bb10-4729-b901-2e2aa0f02077 | Alcohol |
| abba9b63-bb10-4729-b901-2e2aa0f02039 | Instant Messaging |
| abba9b63-bb10-4729-b901-2e2aa0f02036 | Weapons |
| abba9b63-bb10-4729-b901-2e2aa0f02075 | Extreme |
| abba9b63-bb10-4729-b901-2e2aa0f02009 | Health and Nutrition |
| abba9b63-bb10-4729-b901-2e2aa0f02015 | Finance |
| abba9b63-bb10-4729-b901-2e2aa0f02074 | Astrology |
| abba9b63-bb10-4729-b901-2e2aa0f02081 | Personal Sites |
| abba9b63-bb10-4729-b901-2e2aa0f02073 | Streaming Audio |
| abba9b63-bb10-4729-b901-2e2aa0f02084 | Illegal Downloads |
| abba9b63-bb10-4729-b901-2e2aa0f02006 | Adult |
| abba9b63-bb10-4729-b901-2e2aa0f02061 | Dining and Drinking |
| abba9b63-bb10-4729-b901-2e2aa0f02026 | Streaming Media |
| abba9b63-bb10-4729-b901-2e2aa0f02085 | Organizational Email |
| abba9b63-bb10-4729-b901-2e2aa0f02020 | Search Engines and Portals |


### 4. ciscofp-get-network-object
---
Retrieves the network objects associated with the specified ID. If not supplied, retrieves a list of all network objects.

##### Base Command

`ciscofp-get-network-object`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | Object ID. | Optional | 
| limit | The number of items to return. The default is 50. | Optional | 
| offset | Index of first item to return. The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Network.ID | String | ID of network object | 
| CiscoFP.Network.Name | String | Name of network object | 
| CiscoFP.Network.Value | String | CIDR | 
| CiscoFP.Network.Overrideable | String | Boolean indicating whether object can be overridden. | 
| CiscoFP.Network.Description | String | Description of the network object. | 


##### Command Example
```!ciscofp-get-network-object ```

##### Context Example
```
{
    "CiscoFP.Network": [
        {
            "Name": "0", 
            "Overridable": false, 
            "Description": " ", 
            "Value": "1.0.0.0/24", 
            "ID": "000C29A8-BA3B-0ed3-0000-124554053261"
        }, 
        {
            "Name": "1", 
            "Overridable": false, 
            "Description": " ", 
            "Value": "1.0.0.0/24", 
            "ID": "000C29A8-BA3B-0ed3-0000-124554053289"
        }, 
        {
            "Name": "2", 
            "Overridable": false, 
            "Description": " ", 
            "Value": "1.0.0.0/24", 
            "ID": "000C29A8-BA3B-0ed3-0000-124554053308"
        }, 
        {
            "Name": "any-ipv4", 
            "Overridable": false, 
            "Description": " ", 
            "Value": "0.0.0.0/0", 
            "ID": "cb7116e8-66a6-480b-8f9b-295191a0940a"
        }, 
        {
            "Name": "demo1", 
            "Overridable": false, 
            "Description": " ", 
            "Value": "10.0.0.0/10", 
            "ID": "000C29A8-BA3B-0ed3-0000-124554061004"
        }, 
        {
            "Name": "Internal-LAN-Network", 
            "Overridable": false, 
            "Description": " ", 
            "Value": "192.168.1.0/24", 
            "ID": "000C29A8-BA3B-0ed3-0000-030064772538"
        }, 
        {
            "Name": "IPv4-Benchmark-Tests", 
            "Overridable": false, 
            "Description": " ", 
            "Value": "198.18.0.0/15", 
            "ID": "86caab8a-9bdd-420d-858b-5690fde8ce58"
        }, 
        {
            "Name": "IPv4-Link-Local", 
            "Overridable": false, 
            "Description": " ", 
            "Value": "169.254.0.0/16", 
            "ID": "f0ce41ae-6ee9-4e00-8762-da9370c4fee5"
        }, 
        {
            "Name": "IPv4-Multicast", 
            "Overridable": false, 
            "Description": " ", 
            "Value": "224.0.0.0/4", 
            "ID": "5622db1c-5cd5-4199-a4c8-d8f86dec3bd4"
        }, 
        {
            "Name": "IPv4-Private-10.0.0.0-8", 
            "Overridable": false, 
            "Description": " ", 
            "Value": "10.0.0.0/8", 
            "ID": "95916354-5aa1-4057-8eea-b42a5a207abc"
        }, 
        {
            "Name": "IPv4-Private-172.16.0.0-12", 
            "Overridable": false, 
            "Description": " ", 
            "Value": "172.16.0.0/12", 
            "ID": "b7a78a7d-20c5-47b2-b02f-86b4360112ac"
        }, 
        {
            "Name": "IPv4-Private-192.168.0.0-16", 
            "Overridable": false, 
            "Description": " ", 
            "Value": "192.168.0.0/16", 
            "ID": "1dcefdd8-07f7-438a-9221-97d63710614e"
        }, 
        {
            "Name": "IPv6-IPv4-Mapped", 
            "Overridable": false, 
            "Description": " ", 
            "Value": "::ffff:0.0.0.0/96", 
            "ID": "1047b91f-db3a-45b8-9c10-f48ed3f0c3d6"
        }, 
        {
            "Name": "IPv6-Link-Local", 
            "Overridable": false, 
            "Description": " ", 
            "Value": "fe80::/10", 
            "ID": "192c14f2-39d9-409d-81e9-357793bdf1ec"
        }, 
        {
            "Name": "IPv6-Private-Unique-Local-Addresses", 
            "Overridable": false, 
            "Description": " ", 
            "Value": "fc00::/7", 
            "ID": "0434674f-87f8-4e17-810e-97100407858b"
        }, 
        {
            "Name": "IPv6-to-IPv4-Relay-Anycast", 
            "Overridable": false, 
            "Description": " ", 
            "Value": "192.88.99.0/24", 
            "ID": "04ea3f1f-f5a9-4eca-b051-487ebeb4c97f"
        }, 
        {
            "Name": "n5n", 
            "Overridable": false, 
            "Description": " ", 
            "Value": "1.0.0.0/24", 
            "ID": "000C29A8-BA3B-0ed3-0000-124554053215"
        }, 
        {
            "Name": "nn", 
            "Overridable": false, 
            "Description": " ", 
            "Value": "1.0.0.0/24", 
            "ID": "000C29A8-BA3B-0ed3-0000-124554053196"
        }, 
        {
            "Name": "nnkn", 
            "Overridable": false, 
            "Description": "jjj", 
            "Value": "1.0.0.0/24", 
            "ID": "000C29A8-BA3B-0ed3-0000-124554053177"
        }, 
        {
            "Name": "nnn", 
            "Overridable": false, 
            "Description": " ", 
            "Value": "1.0.0.0/24", 
            "ID": "000C29A8-BA3B-0ed3-0000-124554053149"
        }, 
        {
            "Name": "playbookTest", 
            "Overridable": false, 
            "Description": "my", 
            "Value": "10.0.0.0/22", 
            "ID": "000C29A8-BA3B-0ed3-0000-133143990065"
        }, 
        {
            "Name": "playbookTestUpdate", 
            "Overridable": true, 
            "Description": "my", 
            "Value": "10.0.0.0/23", 
            "ID": "000C29A8-BA3B-0ed3-0000-124554053327"
        }, 
        {
            "Name": "rrr", 
            "Overridable": false, 
            "Description": " ", 
            "Value": "10.0.0.0/22", 
            "ID": "000C29A8-BA3B-0ed3-0000-124554056653"
        }
    ]
}
```

##### Human Readable Output
### Cisco Firepower - List network objects:
|ID|Name|Value|Overridable|Description|
|---|---|---|---|---|
| 000C29A8-BA3B-0ed3-0000-124554053261 | 0 | 1.0.0.0/24 | false |   |
| 000C29A8-BA3B-0ed3-0000-124554053289 | 1 | 1.0.0.0/24 | false |   |
| 000C29A8-BA3B-0ed3-0000-124554053308 | 2 | 1.0.0.0/24 | false |   |
| cb7116e8-66a6-480b-8f9b-295191a0940a | any-ipv4 | 0.0.0.0/0 | false |   |
| 000C29A8-BA3B-0ed3-0000-124554061004 | demo1 | 10.0.0.0/10 | false |   |
| 000C29A8-BA3B-0ed3-0000-030064772538 | Internal-LAN-Network | 192.168.1.0/24 | false |   |
| 86caab8a-9bdd-420d-858b-5690fde8ce58 | IPv4-Benchmark-Tests | 198.18.0.0/15 | false |   |
| f0ce41ae-6ee9-4e00-8762-da9370c4fee5 | IPv4-Link-Local | 169.254.0.0/16 | false |   |
| 5622db1c-5cd5-4199-a4c8-d8f86dec3bd4 | IPv4-Multicast | 224.0.0.0/4 | false |   |
| 95916354-5aa1-4057-8eea-b42a5a207abc | IPv4-Private-10.0.0.0-8 | 10.0.0.0/8 | false |   |
| b7a78a7d-20c5-47b2-b02f-86b4360112ac | IPv4-Private-172.16.0.0-12 | 172.16.0.0/12 | false |   |
| 1dcefdd8-07f7-438a-9221-97d63710614e | IPv4-Private-192.168.0.0-16 | 192.168.0.0/16 | false |   |
| 1047b91f-db3a-45b8-9c10-f48ed3f0c3d6 | IPv6-IPv4-Mapped | ::ffff:0.0.0.0/96 | false |   |
| 192c14f2-39d9-409d-81e9-357793bdf1ec | IPv6-Link-Local | fe80::/10 | false |   |
| 0434674f-87f8-4e17-810e-97100407858b | IPv6-Private-Unique-Local-Addresses | fc00::/7 | false |   |
| 04ea3f1f-f5a9-4eca-b051-487ebeb4c97f | IPv6-to-IPv4-Relay-Anycast | 192.88.99.0/24 | false |   |
| 000C29A8-BA3B-0ed3-0000-124554053215 | n5n | 1.0.0.0/24 | false |   |
| 000C29A8-BA3B-0ed3-0000-124554053196 | nn | 1.0.0.0/24 | false |   |
| 000C29A8-BA3B-0ed3-0000-124554053177 | nnkn | 1.0.0.0/24 | false | jjj |
| 000C29A8-BA3B-0ed3-0000-124554053149 | nnn | 1.0.0.0/24 | false |   |
| 000C29A8-BA3B-0ed3-0000-133143990065 | playbookTest | 10.0.0.0/22 | false | my |
| 000C29A8-BA3B-0ed3-0000-124554053327 | playbookTestUpdate | 10.0.0.0/23 | true | my |
| 000C29A8-BA3B-0ed3-0000-124554056653 | rrr | 10.0.0.0/22 | false |   |


### 5. ciscofp-create-network-object
---
Creates a network object.

##### Base Command

`ciscofp-create-network-object`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the new object. | Required | 
| value | CIDR | Required | 
| description | The object description. | Optional | 
| overridable | Boolean indicating whether objects can be overridden. Can be "true" or "false". The default is "false". | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Network.ID | String | ID of network object. | 
| CiscoFP.Network.Name | String | Name of network object. | 
| CiscoFP.Network.Value | String | CIDR. | 
| CiscoFP.Network.Overridable | String | Boolean indicating whether the object can be overridden. | 
| CiscoFP.Network.Description | String | Description of the network object. | 


##### Command Example
```!ciscofp-create-network-object name=newTest232 value=10.0.0.0/22 description=test overridable=false```

##### Context Example
```
{
    "CiscoFP.Network": {
        "Name": "newTest232", 
        "Overridable": false, 
        "Description": "test", 
        "Value": "10.0.0.0/22", 
        "ID": "000C29A8-BA3B-0ed3-0000-133143990579"
    }
}
```

##### Human Readable Output
### Cisco Firepower - network object has been created.
|ID|Name|Value|Overridable|Description|
|---|---|---|---|---|
| 000C29A8-BA3B-0ed3-0000-133143990579 | newTest232 | 10.0.0.0/22 | false | test |




### 6. ciscofp-update-network-object
---
Updates the specified network object.

##### Base Command

`ciscofp-update-network-object`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the object to update. | Required | 
| name | The object name. | Required | 
| value | CIDR | Required | 
| description | The object description. | Optional | 
| overridable | Boolean indicating whether the object can be overridden. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Network.ID | String | ID of the network object. | 
| CiscoFP.Network.Name | String | Name of the network object. | 
| CiscoFP.Network.Value | String | CIDR. | 
| CiscoFP.Network.Overridable | String | Boolean indicating whether the object can be overridden. | 
| CiscoFP.Network.Description | String | Description of the network object. | 


##### Command Example
```!ciscofp-update-network-object id=000C29A8-BA3B-0ed3-0000-124554053327 name=playbookTestUpdate value=10.0.0.0/23 description=my playbook test overridable=true```

##### Context Example
```
{
    "CiscoFP.Network": {
        "Name": "playbookTestUpdate", 
        "Overridable": true, 
        "Description": "my", 
        "Value": "10.0.0.0/23", 
        "ID": "000C29A8-BA3B-0ed3-0000-124554053327"
    }
}
```

##### Human Readable Output
### Cisco Firepower - network object has been updated.
|ID|Name|Value|Overridable|Description|
|---|---|---|---|---|
| 000C29A8-BA3B-0ed3-0000-124554053327 | playbookTestUpdate | 10.0.0.0/23 | true | my |


### 7. ciscofp-get-network-groups-object
---
Retrieves the groups of network objects and addresses associated with the specified ID. If not supplied, retrieves a list of all network objects.

##### Base Command

`ciscofp-get-network-groups-object`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the object group for which to return groups and addresses. | Optional | 
| limit | The number of items to return. The default is 50. | Optional | 
| offset | Index of the first item to return. The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.NetworkGroups.ID | String | The group ID. | 
| CiscoFP.NetworkGroups.Name | String | The group name. | 
| CiscoFP.NetworkGroups.Overridable | String | Boolean indicating whether the object can be overridden. | 
| CiscoFP.NetworkGroups.Description | String | The group description. | 
| CiscoFP.NetworkGroups.Addresses.Value | String | IP address / CIDR range. | 
| CiscoFP.NetworkGroups.Addresses.Type | String | The address type. | 
| CiscoFP.NetworkGroups.Objects.Name | String | The object name. | 
| CiscoFP.NetworkGroups.Objects.ID | String | The object ID. | 
| CiscoFP.NetworkGroups.Objects.Type | String | The object type. | 


##### Command Example
```!ciscofp-get-network-groups-object```

##### Context Example
```
{
    "CiscoFP.NetworkGroups": [
        {
            "Name": "any", 
            "Overridable": false, 
            "Objects": [], 
            "Description": " ", 
            "ID": "69fa2a3a-4487-4e3c-816f-4098f684826e", 
            "Addresses": [
                {
                    "Type": "Network", 
                    "Value": "0.0.0.0/0"
                }, 
                {
                    "Type": "Host", 
                    "Value": "::/0"
                }
            ]
        }, 
        {
            "Name": "arseny_group", 
            "Overridable": false, 
            "Objects": [
                {
                    "Type": "Host", 
                    "ID": "000C29A8-BA3B-0ed3-0000-124554052144", 
                    "Name": "playbookTestUpdate2"
                }, 
                {
                    "Type": "Network", 
                    "ID": "0434674f-87f8-4e17-810e-97100407858b", 
                    "Name": "IPv6-Private-Unique-Local-Addresses"
                }, 
                {
                    "Type": "Network", 
                    "ID": "1047b91f-db3a-45b8-9c10-f48ed3f0c3d6", 
                    "Name": "IPv6-IPv4-Mapped"
                }
            ], 
            "Description": " ", 
            "ID": "000C29A8-BA3B-0ed3-0000-124554052162", 
            "Addresses": []
        }, 
        {
            "Name": "ee", 
            "Overridable": false, 
            "Objects": [], 
            "Description": " ", 
            "ID": "000C29A8-BA3B-0ed3-0000-124554053470", 
            "Addresses": [
                {
                    "Type": "Host", 
                    "Value": "1.2.3.4"
                }, 
                {
                    "Type": "Host", 
                    "Value": "1.1.2.2"
                }
            ]
        }, 
        {
            "Name": "eee", 
            "Overridable": false, 
            "Objects": [], 
            "Description": " ", 
            "ID": "000C29A8-BA3B-0ed3-0000-124554053489", 
            "Addresses": [
                {
                    "Type": "Host", 
                    "Value": "1.2.3.4"
                }, 
                {
                    "Type": "Host", 
                    "Value": "1.1.2.2"
                }
            ]
        }, 
        {
            "Name": "IPv4-Private-All-RFC1918", 
            "Overridable": false, 
            "Objects": [], 
            "Description": " ", 
            "ID": "15b12b14-dace-4117-b9d9-a9a7dcfa356f", 
            "Addresses": [
                {
                    "Type": "Network", 
                    "Value": "10.0.0.0/8"
                }, 
                {
                    "Type": "Network", 
                    "Value": "172.16.0.0/12"
                }, 
                {
                    "Type": "Network", 
                    "Value": "192.168.0.0/16"
                }
            ]
        }
    ]
}
```

##### Human Readable Output
### Cisco Firepower - List of network groups object:
|ID|Name|Overridable|Description|Addresses|Objects|
|---|---|---|---|---|---|
| 69fa2a3a-4487-4e3c-816f-4098f684826e | any | false |   | 2 | 0 |
| 000C29A8-BA3B-0ed3-0000-124554052162 | arseny_group | false |   | 0 | 3 |
| 000C29A8-BA3B-0ed3-0000-124554053470 | ee | false |   | 2 | 0 |
| 000C29A8-BA3B-0ed3-0000-124554053489 | eee | false |   | 2 | 0 |
| 15b12b14-dace-4117-b9d9-a9a7dcfa356f | IPv4-Private-All-RFC1918 | false |   | 3 | 0 |

### 8. ciscofp-create-network-groups-objects
---
Creates a group of network objects.

##### Base Command

`ciscofp-create-network-groups-objects`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The group name. | Required | 
| network_objects_id_list | A comma-separated list of object IDs to add to the group. | Optional | 
| network_address_list | A comma-separated list of IP addresses or CIDR ranges to add the group. | Optional | 
| description | The object description. | Optional | 
| overridable | Boolean indicating whether object values can be overridden. Can be "true" or "false". The default is "false". | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.NetworkGroups.ID | String | The group ID. | 
| CiscoFP.NetworkGroups.Name | String | The group name. | 
| CiscoFP.NetworkGroups.Overridable | String | Boolean indicating whether the object can be overridden. | 
| CiscoFP.NetworkGroups.Description | String | The group description. | 
| CiscoFP.NetworkGroups.Addresses.Value | String | IP address or CIDR range. | 
| CiscoFP.NetworkGroups.Addresses.Type | String | The address type. | 
| CiscoFP.NetworkGroups.Objects.Name | String | The object name. | 
| CiscoFP.NetworkGroups.Objects.ID | String | The object ID. | 
| CiscoFP.NetworkGroups.Objects.Type | String | The object type. | 


##### Command Example
```!ciscofp-create-network-groups-objects name=playbookTest3 network_address_list=8.8.8.8,4.4.4.4 description=my playbook test overridable=true```

##### Context Example
```
{
    "CiscoFP.NetworkGroups": {
        "Name": "playbookTest3", 
        "Overridable": true, 
        "Objects": [], 
        "Description": "my", 
        "ID": "000C29A8-BA3B-0ed3-0000-133143990785", 
        "Addresses": [
            {
                "Type": "Host", 
                "Value": "8.8.8.8"
            }, 
            {
                "Type": "Host", 
                "Value": "4.4.4.4"
            }
        ]
    }
}
```

##### Human Readable Output
### Cisco Firepower - network group has been created.
|ID|Name|Overridable|Description|Addresses|Objects|
|---|---|---|---|---|---|
| 000C29A8-BA3B-0ed3-0000-133143990785 | playbookTest3 | true | my | 2 | 0 |


### 9. ciscofp-update-network-groups-objects
---
Updates a group of network objects.

##### Base Command

`ciscofp-update-network-groups-objects`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the group to update. | Required | 
| network_objects_id_list | A comma-separated list of object IDs to add the group. | Optional | 
| network_address_list | A comma-separated list of IP addresses or CIDR ranges to add the group. | Optional | 
| description | The new description for the object. | Optional | 
| overridable | Boolean indicating whether object values can be overridden. Can be "true" or "false". The default is "false". | Optional | 
| name | The group name. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.NetworkGroups.ID | String | The group ID. | 
| CiscoFP.NetworkGroups.Name | String | The group name. | 
| CiscoFP.NetworkGroups.Overridable | String | Boolean indicating whether objects can be overridden. | 
| CiscoFP.NetworkGroups.Description | String | The group description. | 
| CiscoFP.NetworkGroups.Addresses.Value | String | IP address or CIDR range. | 
| CiscoFP.NetworkGroups.Addresses.Type | String | The address type. | 
| CiscoFP.NetworkGroups.Objects.Name | String | The object name. | 
| CiscoFP.NetworkGroups.Objects.ID | String | The object ID. | 
| CiscoFP.NetworkGroups.Objects.Type | String | The object type. | 


##### Command Example
```!ciscofp-update-network-groups-objects id=000C29A8-BA3B-0ed3-0000-124554053470 network_address_list=1.2.3.4,1.2.3.5 description=my playbook test overridable=true name=rrrff```

##### Context Example
```
{
    "CiscoFP.NetworkGroups": {
        "Name": "rrrff", 
        "Overridable": true, 
        "Objects": [], 
        "Description": "my", 
        "ID": "000C29A8-BA3B-0ed3-0000-124554053470", 
        "Addresses": [
            {
                "Type": "Host", 
                "Value": "1.2.3.4"
            }, 
            {
                "Type": "Host", 
                "Value": "1.2.3.5"
            }
        ]
    }
}
```

##### Human Readable Output
### Cisco Firepower - network group has been updated.
|ID|Name|Overridable|Description|Addresses|Objects|
|---|---|---|---|---|---|
| 000C29A8-BA3B-0ed3-0000-124554053470 | rrrff | true | my | 2 | 0 |




### 10. ciscofp-delete-network-groups-objects
---
Deletes a group of network objects.

##### Base Command

`ciscofp-delete-network-groups-objects`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the object to delete. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.NetworkGroups.ID | String | The group ID. | 
| CiscoFP.NetworkGroups.Name | String | The group name. | 
| CiscoFP.NetworkGroups.Overridable | String | Boolean indicating whether object values can be overridden. | 
| CiscoFP.NetworkGroups.Description | String | The group description. | 
| CiscoFP.NetworkGroups.Addresses.Value | String | IP address or CIDR range. | 
| CiscoFP.NetworkGroups.Addresses.Type | String | The address type. | 
| CiscoFP.NetworkGroups.Objects.Name | String | The object name | 
| CiscoFP.NetworkGroups.Objects.ID | String | The object ID. | 
| CiscoFP.NetworkGroups.Objects.Type | String | The object type. | 


##### Command Example
```!ciscofp-delete-network-groups-objects id=000C29A8-BA3B-0ed3-0000-124554053489```

##### Context Example
```
{
    "CiscoFP.NetworkGroups": {
        "Name": "eee", 
        "Overridable": false, 
        "Objects": [], 
        "Description": " ", 
        "ID": "000C29A8-BA3B-0ed3-0000-124554053489", 
        "Addresses": [
            {
                "Type": "Host", 
                "Value": "1.2.3.4"
            }, 
            {
                "Type": "Host", 
                "Value": "1.1.2.2"
            }
        ]
    }
}
```

##### Human Readable Output
### Cisco Firepower - network group - 000C29A8-BA3B-0ed3-0000-124554053489 - has been delete.
|ID|Name|Overridable|Description|Addresses|Objects|
|---|---|---|---|---|---|
| 000C29A8-BA3B-0ed3-0000-124554053489 | eee | false |   | 2 | 0 |


### 11. ciscofp-get-host-object
---
Retrieves the groups of host objects associated with the specified ID. If no ID is passed, the input ID retrieves a list of all network objects.

##### Base Command

`ciscofp-get-host-object`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | ID of the object for which to retrieve host objects. | Optional | 
| limit | Number of items to return. The default is 50 | Optional | 
| offset | Index of the first item to return. The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Host.ID | String | ID of the host object. | 
| CiscoFP.Host.Name | String | Name of host object. | 
| CiscoFP.Host.Value | String | The IP address. | 
| CiscoFP.Host.Overridable | String | Boolean indicating whether object values can be overridden. | 
| CiscoFP.Host.Description | String | A description of the host object. | 


##### Command Example
```!ciscofp-get-host-object```

##### Context Example
```
{
    "CiscoFP.Host": [
        {
            "Name": "any-ipv6", 
            "Overridable": false, 
            "Description": " ", 
            "Value": "::/0", 
            "ID": "dde11d62-288b-4b4c-92e0-1dad0496f14b"
        }, 
        {
            "Name": "playbookTest2", 
            "Overridable": false, 
            "Description": "my", 
            "Value": "1.2.3.4", 
            "ID": "000C29A8-BA3B-0ed3-0000-133143990104"
        }, 
        {
            "Name": "playbookTestUpdate2", 
            "Overridable": true, 
            "Description": "my", 
            "Value": "1.2.3.5", 
            "ID": "000C29A8-BA3B-0ed3-0000-124554052144"
        }, 
        {
            "Name": "SyslogServer", 
            "Overridable": false, 
            "Description": " ", 
            "Value": "10.8.51.161", 
            "ID": "000C29A8-BA3B-0ed3-0000-103079216589"
        }
    ]
}
```

##### Human Readable Output
### Cisco Firepower - List host objects:
|ID|Name|Value|Overridable|Description|
|---|---|---|---|---|
| dde11d62-288b-4b4c-92e0-1dad0496f14b | any-ipv6 | ::/0 | false |   |
| 000C29A8-BA3B-0ed3-0000-133143990104 | playbookTest2 | 1.2.3.4 | false | my |
| 000C29A8-BA3B-0ed3-0000-124554052144 | playbookTestUpdate2 | 1.2.3.5 | true | my |
| 000C29A8-BA3B-0ed3-0000-103079216589 | SyslogServer | 10.8.51.161 | false |   |


### 12. ciscofp-create-host-object
---
Creates a host object.

##### Base Command

`ciscofp-create-host-object`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the new object. | Required | 
| value | The IP address. | Required | 
| description | A description of the new object. | Optional | 
| overridable | Boolean indicating whether object values can be overridden. Can be "true" or "false". The default is "false". | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Host.ID | String | ID of the host object. | 
| CiscoFP.Host.Name | String | Name of the host object. | 
| CiscoFP.Host.Value | String | The IP address. | 
| CiscoFP.Host.Overridable | String | Boolean indicating whether object values can be overridden. | 
| CiscoFP.Host.Description | String | Description of the host object. | 


##### Command Example
```!ciscofp-create-host-object name=newTest322 value=1.2.3.4 description=test overridable=false```

##### Context Example
```
{
    "CiscoFP.Host": {
        "Name": "newTest322", 
        "Overridable": false, 
        "Description": "test", 
        "Value": "1.2.3.4", 
        "ID": "000C29A8-BA3B-0ed3-0000-133143990598"
    }
}
```

##### Human Readable Output
### Cisco Firepower - host object has been created.
|ID|Name|Value|Overridable|Description|
|---|---|---|---|---|
| 000C29A8-BA3B-0ed3-0000-133143990598 | newTest322 | 1.2.3.4 | false | test |




### 13. ciscofp-update-host-object
---
Updates the specified host object.

##### Base Command

`ciscofp-update-host-object`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the object to update. | Required | 
| name | Name of the object. | Required | 
| value | The IP address. | Required | 
| description | Description of the object. | Optional | 
| overridable | Boolean indicating whether object values can be overridden. Can be "true" or "false". The default is "false". | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Host.ID | String | ID of the host object. | 
| CiscoFP.Host.Name | String | Name of the host object. | 
| CiscoFP.Host.Value | String | The IP address. | 
| CiscoFP.Host.Overridable | String | Boolean indicating whether object values can be overridden. | 
| CiscoFP.Host.Description | String | Description of the host object. | 


##### Command Example
```!ciscofp-update-host-object id=000C29A8-BA3B-0ed3-0000-124554052144 name=playbookTestUpdate2 value=1.2.3.5 description=my playbook test overridable=true```

##### Context Example
```
{
    "CiscoFP.Host": {
        "Name": "playbookTestUpdate2", 
        "Overridable": true, 
        "Description": "my", 
        "Value": "1.2.3.5", 
        "ID": "000C29A8-BA3B-0ed3-0000-124554052144"
    }
}
```

##### Human Readable Output
### Cisco Firepower - host object has been updated.
|ID|Name|Value|Overridable|Description|
|---|---|---|---|---|
| 000C29A8-BA3B-0ed3-0000-124554052144 | playbookTestUpdate2 | 1.2.3.5 | true | my |


### 14. ciscofp-delete-network-object
---
Deletes the specified network object.

##### Base Command

`ciscofp-delete-network-object`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the object to delete. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Network.ID | String | ID of the network object. | 
| CiscoFP.Network.Name | String | Name of the network object. | 
| CiscoFP.Network.Value | String | CISR range. | 
| CiscoFP.Network.Overridable | String | Boolean indicating whether object values can be overridden. | 
| CiscoFP.Network.Description | String | Description of the network object. | 


##### Command Example
```!ciscofp-delete-network-object id=000C29A8-BA3B-0ed3-0000-124554053327```

##### Context Example
```
{
    "CiscoFP.Network": {
        "Name": "playbookTestUpdate", 
        "Overridable": true, 
        "Description": "my", 
        "Value": "10.0.0.0/23", 
        "ID": "000C29A8-BA3B-0ed3-0000-124554053327"
    }
}
```

##### Human Readable Output
### Cisco Firepower - network object has been deleted.
|ID|Name|Value|Overridable|Description|
|---|---|---|---|---|
| 000C29A8-BA3B-0ed3-0000-124554053327 | playbookTestUpdate | 10.0.0.0/23 | true | my |



### 15. ciscofp-delete-host-object
---
Deletes the specified host object.

##### Base Command

`ciscofp-delete-host-object`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the host object to delete. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Host.ID | String | ID of the host object. | 
| CiscoFP.Host.Name | String | Name of the host object. | 
| CiscoFP.Host.Value | String | CIDR range. | 
| CiscoFP.Host.Overridable | String | Whether the  object can be overridden. | 
| CiscoFP.Host.Description | String | Description of the host object. | 


##### Command Example
```!ciscofp-delete-host-object id=000C29A8-BA3B-0ed3-0000-133143990598```

##### Context Example
```
{
    "CiscoFP.Host": {
        "Name": "newTest322", 
        "Overridable": false, 
        "Description": "test", 
        "Value": "1.2.3.4", 
        "ID": "000C29A8-BA3B-0ed3-0000-133143990598"
    }
}
```

##### Human Readable Output
### Cisco Firepower - host object has been deleted.
|ID|Name|Value|Overridable|Description|
|---|---|---|---|---|
| 000C29A8-BA3B-0ed3-0000-133143990598 | newTest322 | 1.2.3.4 | false | test |

### 16. ciscofp-get-access-policy
---
Retrieves the access control policy associated with the specified ID. If no access policy ID is passed, all access control policies are returned.

##### Base Command

`ciscofp-get-access-policy`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the access policy. | Optional | 
| limit | The maximum number of items to return. The default is 50. | Optional | 
| offset | Index of first item to return. The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Policy.ID | String | The policy ID. | 
| CiscoFP.Policy.Name | String | The name of the policy. | 
| CiscoFP.Policy.DefaultActionID | String | The default action ID of the policy. | 


##### Command Example
```!ciscofp-get-access-policy```

##### Context Example
```
{
    "CiscoFP.Policy": [
        {
            "DefaultActionID": "000C29A8-BA3B-0ed3-0000-000268444674", 
            "ID": "000C29A8-BA3B-0ed3-0000-133143987627", 
            "Name": "BPS tst"
        }, 
        {
            "DefaultActionID": "000C29A8-BA3B-0ed3-0000-000268440576", 
            "ID": "000C29A8-BA3B-0ed3-0000-085899346038", 
            "Name": "Performance Test Policy without AMP"
        }, 
        {
            "DefaultActionID": "000C29A8-BA3B-0ed3-0000-000268444676", 
            "ID": "000C29A8-BA3B-0ed3-0000-133143990165", 
            "Name": "playbookTest4"
        }, 
        {
            "DefaultActionID": "000C29A8-BA3B-0ed3-0000-000268443677", 
            "ID": "000C29A8-BA3B-0ed3-0000-124554066053", 
            "Name": "to test"
        }
    ]
}
```

##### Human Readable Output
### Cisco Firepower - List access policy:
|ID|Name|DefaultActionID|
|---|---|---|
| 000C29A8-BA3B-0ed3-0000-133143987627 | BPS tst | 000C29A8-BA3B-0ed3-0000-000268444674 |
| 000C29A8-BA3B-0ed3-0000-085899346038 | Performance Test Policy without AMP | 000C29A8-BA3B-0ed3-0000-000268440576 |
| 000C29A8-BA3B-0ed3-0000-133143990165 | playbookTest4 | 000C29A8-BA3B-0ed3-0000-000268444676 |
| 000C29A8-BA3B-0ed3-0000-124554066053 | to test | 000C29A8-BA3B-0ed3-0000-000268443677 |


### 17. ciscofp-create-access-policy
---
Creates an access control policy.

##### Base Command

`ciscofp-create-access-policy`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the new access policy. | Required | 
| action | The action to take. Can be "BLOCK", "TRUST", "PERMIT", or "NETWORK_DISCOVERY". | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Policy.ID | String | The policy ID. | 
| CiscoFP.Policy.Name | String | The name of the policy. | 
| CiscoFP.Policy.DefaultActionID | String | The default action ID of the policy. | 


##### Command Example
```!ciscofp-create-access-policy name=newTest232 action=BLOCK```

##### Context Example
```
{
    "CiscoFP.Policy": {
        "DefaultActionID": "", 
        "ID": "000C29A8-BA3B-0ed3-0000-133143990627", 
        "Name": "newTest232"
    }
}
```

##### Human Readable Output
### Cisco Firepower - access policy has been created.
|ID|Name|DefaultActionID|
|---|---|---|
| 000C29A8-BA3B-0ed3-0000-133143990627 | newTest232 |  |



### 18. ciscofp-update-access-policy
---
Updates the specified access control policy.

##### Base Command

`ciscofp-update-access-policy`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The access policy name. | Required | 
| id | ID of the access policy. | Required | 
| default_action_id | ID of the default action. | Required | 
| action | The action to take. Can be "BLOCK", "TRUST", "PERMIT", or "NETWORK_DISCOVERY". | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Policy.ID | String | The policy ID. | 
| CiscoFP.Policy.Name | String | The name of the policy. | 
| CiscoFP.Policy.DefaultActionID | String | The default action ID of the policy. | 


##### Command Example
```!ciscofp-update-access-policy action=BLOCK default_action_id=000C29A8-BA3B-0ed3-0000-000268444682 name=jj id=000C29A8-BA3B-0ed3-0000-133143991123```

##### Context Example
```
{
    "CiscoFP.Policy": {
        "DefaultActionID": "000C29A8-BA3B-0ed3-0000-000268444682", 
        "ID": "000C29A8-BA3B-0ed3-0000-133143991123", 
        "Name": "jj"
    }
}
```

##### Human Readable Output
### Cisco Firepower - access policy has been updated.
|ID|Name|DefaultActionID|
|---|---|---|
| 000C29A8-BA3B-0ed3-0000-133143991123 | jj | 000C29A8-BA3B-0ed3-0000-000268444682 |

### 19. ciscofp-delete-access-policy
---
Deletes the specified access control policy.

##### Base Command

`ciscofp-delete-access-policy`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the access policy. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Policy.ID | String | The policy ID. | 
| CiscoFP.Policy.Name | String | The name of the policy. | 
| CiscoFP.Policy.DefaultActionID | String | The default action ID of the policy. | 


##### Command Example
```!ciscofp-delete-access-policy id=000C29A8-BA3B-0ed3-0000-133143990869```

##### Context Example
```
{
    "CiscoFP.Policy": {
        "DefaultActionID": "000C29A8-BA3B-0ed3-0000-000268444680", 
        "ID": "000C29A8-BA3B-0ed3-0000-133143990869", 
        "Name": "qq"
    }
}
```

##### Human Readable Output
### Cisco Firepower - access policy deleted.
|ID|Name|DefaultActionID|
|---|---|---|
| 000C29A8-BA3B-0ed3-0000-133143990869 | qq | 000C29A8-BA3B-0ed3-0000-000268444680 |



### 20. ciscofp-list-security-group-tags
---
Retrieves a list of all custom security group tag objects.

##### Base Command

`ciscofp-list-security-group-tags`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of items to return. The default is 50 | Optional | 
| offset | Index of first item to return. The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.SecurityGroupTags.ID | String | ID of security group tag. | 
| CiscoFP.SecurityGroupTags.Name | String | Name of security group tag. | 
| CiscoFP.SecurityGroupTags.Tag | Number | The tag number. | 


##### Command Example
```!ciscofp-list-security-group-tags```

##### Context Example
```
{
    "CiscoFP.SecurityGroupTags": [
        {
            "Tag": 1000, 
            "ID": "8d9813aa-32c1-11ea-9d47-eda81976c864", 
            "Name": "sample_tag"
        }, 
        {
            "Tag": 65535, 
            "ID": "5fce8cce-aa67-11e5-816b-95eb712b72a1", 
            "Name": "ANY"
        }
    ]
}
```

##### Human Readable Output
### Cisco Firepower - List security group tags:
|ID|Name|Tag|
|---|---|---|
| 8d9813aa-32c1-11ea-9d47-eda81976c864 | sample_tag | 1000 |
| 5fce8cce-aa67-11e5-816b-95eb712b72a1 | ANY | 65535 |


### 21. ciscofp-list-ise-security-group-tag
---
Retrieves a list of all ISE security group tag objects.


##### Base Command

`ciscofp-list-ise-security-group-tag`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of items to return. The default is 50. | Optional | 
| offset | Index of first item to return. The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.SecurityGroupTags.ID | String | ID of security group tag. | 
| CiscoFP.SecurityGroupTags.Name | String | Name of security group tag. | 
| CiscoFP.SecurityGroupTags.Tag | Number | The tag number. | 


##### Command Example
```!ciscofp-list-ise-security-group-tags```

##### Context Example
```
{
    "CiscoFP.IseSecurityGroupTags": [
        {
            "Tag": 1000, 
            "ID": "8d9813aa-32c1-11ea-9d47-eda81976c864", 
            "Name": "sample_tag"
        }, 
        {
            "Tag": 65535, 
            "ID": "5fce8cce-aa67-11e5-816b-95eb712b72a1", 
            "Name": "ANY"
        }
    ]
}
```

##### Human Readable Output
### Cisco Firepower - List ise security group tags:
|ID|Name|Tag|
|---|---|---|
| 8d9813aa-32c1-11ea-9d47-eda81976c864 | sample_tag | 1000 |
| 5fce8cce-aa67-11e5-816b-95eb712b72a1 | ANY | 65535 |


### 22. ciscofp-list-vlan-tags
---
Retrieves a list of all vlantag objects.

##### Base Command

`ciscofp-list-vlan-tags`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of items to return. The default is 50. | Optional | 
| offset | Index of first item to return. The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.VlanTags.ID | String | ID of the vlan tag. | 
| CiscoFP.VlanTags.Name | String | Name of the vlan tag. | 
| CiscoFP.VlanTags.Overridable | Boolean | Boolean indicating whether object values can be overridden. | 
| CiscoFP.VlanTags.Description | String | Description of the vlan tag. | 
| CiscoFP.VlanTags.StartTag | Number | Start tag number. | 
| CiscoFP.VlanTags.EndTag | Number | End tag number. | 


##### Command Example
```!ciscofp-list-vlan-tags```

##### Context Example
```
{
    "CiscoFP.VlanTags": [
        {
            "StartTag": 2013, 
            "Name": "aaaa", 
            "EndTag": 2013, 
            "Overridable": false, 
            "ID": "000C29A8-BA3B-0ed3-0000-124554052529", 
            "Description": " "
        }
    ]
}
```

##### Human Readable Output
### Cisco Firepower - List vlan tags:
|ID|Name|Overridable|Description|StartTag|EndTag|
|---|---|---|---|---|---|
| 000C29A8-BA3B-0ed3-0000-124554052529 | aaaa | false |   | 2013 | 2013 |


### 23. ciscofp-list-vlan-tags-group
---
Retrieves a list of all vlan group tag objects.

##### Base Command

`ciscofp-list-vlan-tags-group`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of items to return. The default is 50. | Optional | 
| offset | Index of first item to return. The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.VlanTagsGroup.Name | String | Name of the group. | 
| CiscoFP.VlanTagsGroup.ID | String | ID of the group. | 
| CiscoFP.VlanTagsGroup.Description | String | Description of the object. | 
| CiscoFP.VlanTagsGroup.Overridable | Boolean | Boolean indicating whether object values can be overridden. | 
| CiscoFP.VlanTagsGroup.Objects.Name | String | Name of the object. | 
| CiscoFP.VlanTagsGroup.Objects.ID | String | ID of the object. | 
| CiscoFP.VlanTagsGroup.Objects.Description | String | Description of the vlan tag. | 
| CiscoFP.VlanTagsGroup.Objects.Overridable | Boolean | Boolean indicating whether object values can be overridden. | 
| CiscoFP.VlanTagsGroup.Objects.StartTag | Number | Start tag number. | 
| CiscoFP.VlanTagsGroup.Objects.EndTag | Number | End tag number. | 


##### Command Example
```!ciscofp-list-vlan-tags-group```

##### Context Example
```
{
    "CiscoFP.VlanTagsGroup": [
        {
            "Name": "forPlaybookTest", 
            "Objects": [], 
            "Overridable": false, 
            "Description": " ", 
            "ID": "000C29A8-BA3B-0ed3-0000-124554057022"
        }
    ]
}
```

##### Human Readable Output
### Cisco Firepower - List of vlan tags groups objects:
|ID|Name|Overridable|Description|Objects|
|---|---|---|---|---|
| 000C29A8-BA3B-0ed3-0000-124554057022 | forPlaybookTest | false |   | 0 |


### 24. ciscofp-list-applications
---
Retrieves a list of all application objects.

##### Base Command

`ciscofp-list-applications`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of items to return. The default is 50. | Optional | 
| offset | Index of first item to return. The default is 0 | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Applications.Name | String | Name of the application. | 
| CiscoFP.Applications.ID | String | ID of the application. | 
| CiscoFP.Applications.Risk | String | Risk of the application. | 
| CiscoFP.Applications.AppProductivity | String | AppProductivity of the application. | 
| CiscoFP.Applications.ApplicationTypes | String | The application type. | 
| CiscoFP.Applications.AppCategories.ID | String | AppCategory ID. | 
| CiscoFP.Applications.AppCategories.Name | String | AppCategory name. | 
| CiscoFP.Applications.AppCategories.Count | String | AppCategory count. | 


##### Command Example
```!ciscofp-list-applications```

##### Context Example
```
{
    "CiscoFP.Applications": [
        {
            "AppCategories": [
                {
                    "Count": 179, 
                    "ID": "80", 
                    "Name": "mobile application"
                }, 
                {
                    "Count": 59, 
                    "ID": "85", 
                    "Name": "VoIP"
                }
            ], 
            "Risk": "Medium", 
            "AppProductivity": "Medium", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }, 
                {
                    "Name": "Server"
                }
            ], 
            "ID": "2325", 
            "Name": "050plus"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 1009, 
                    "ID": "2", 
                    "Name": "web services provider"
                }, 
                {
                    "Count": 377, 
                    "ID": "11", 
                    "Name": "e-commerce"
                }
            ], 
            "Risk": "Very Low", 
            "AppProductivity": "Low", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "1553", 
            "Name": "1&1 Internet"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 377, 
                    "ID": "11", 
                    "Name": "e-commerce"
                }
            ], 
            "Risk": "Low", 
            "AppProductivity": "Very Low", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "535", 
            "Name": "1-800-Flowers"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 194, 
                    "ID": "118", 
                    "Name": "ad portal"
                }
            ], 
            "Risk": "Low", 
            "AppProductivity": "Very Low", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "3715", 
            "Name": "1000mercis"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 52, 
                    "ID": "82", 
                    "Name": "peer to peer"
                }
            ], 
            "Risk": "Very High", 
            "AppProductivity": "Very Low", 
            "ApplicationTypes": [
                {
                    "Name": "Client"
                }, 
                {
                    "Name": "Server"
                }
            ], 
            "ID": "536", 
            "Name": "100Bao"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 1009, 
                    "ID": "2", 
                    "Name": "web services provider"
                }, 
                {
                    "Count": 377, 
                    "ID": "11", 
                    "Name": "e-commerce"
                }
            ], 
            "Risk": "Very Low", 
            "AppProductivity": "High", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "1205", 
            "Name": "12306.cn"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 385, 
                    "ID": "47", 
                    "Name": "multimedia (TV/video)"
                }
            ], 
            "Risk": "Medium", 
            "AppProductivity": "Very Low", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }, 
                {
                    "Name": "Server"
                }
            ], 
            "ID": "4164", 
            "Name": "123Movies"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 69, 
                    "ID": "44", 
                    "Name": "email"
                }
            ], 
            "Risk": "Very Low", 
            "AppProductivity": "High", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "1206", 
            "Name": "126.com"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 199, 
                    "ID": "37", 
                    "Name": "social networking"
                }
            ], 
            "Risk": "Medium", 
            "AppProductivity": "Very Low", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }, 
                {
                    "Name": "Server"
                }
            ], 
            "ID": "2385", 
            "Name": "17173.com"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 155, 
                    "ID": "3", 
                    "Name": "remote file storage"
                }, 
                {
                    "Count": 234, 
                    "ID": "17", 
                    "Name": "business"
                }, 
                {
                    "Count": 1009, 
                    "ID": "2", 
                    "Name": "web services provider"
                }
            ], 
            "Risk": "Low", 
            "AppProductivity": "Medium", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }, 
                {
                    "Name": "Server"
                }
            ], 
            "ID": "4165", 
            "Name": "1fichier"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 94, 
                    "ID": "25", 
                    "Name": "web content aggregators"
                }
            ], 
            "Risk": "Very Low", 
            "AppProductivity": "Medium", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "2346", 
            "Name": "2345.com"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 1009, 
                    "ID": "2", 
                    "Name": "web services provider"
                }, 
                {
                    "Count": 377, 
                    "ID": "11", 
                    "Name": "e-commerce"
                }, 
                {
                    "Count": 194, 
                    "ID": "118", 
                    "Name": "ad portal"
                }
            ], 
            "Risk": "Very Low", 
            "AppProductivity": "Very Low", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "2493", 
            "Name": "24/7 Media"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 1009, 
                    "ID": "2", 
                    "Name": "web services provider"
                }, 
                {
                    "Count": 377, 
                    "ID": "11", 
                    "Name": "e-commerce"
                }, 
                {
                    "Count": 194, 
                    "ID": "118", 
                    "Name": "ad portal"
                }
            ], 
            "Risk": "Very Low", 
            "AppProductivity": "Very Low", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "2492", 
            "Name": "247 Inc."
        }, 
        {
            "AppCategories": [
                {
                    "Count": 94, 
                    "ID": "25", 
                    "Name": "web content aggregators"
                }
            ], 
            "Risk": "Low", 
            "AppProductivity": "Very Low", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }, 
                {
                    "Name": "Server"
                }
            ], 
            "ID": "537", 
            "Name": "2channel"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 1009, 
                    "ID": "2", 
                    "Name": "web services provider"
                }
            ], 
            "Risk": "Medium", 
            "AppProductivity": "Low", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "1781", 
            "Name": "2Leep"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 1009, 
                    "ID": "2", 
                    "Name": "web services provider"
                }, 
                {
                    "Count": 234, 
                    "ID": "17", 
                    "Name": "business"
                }, 
                {
                    "Count": 199, 
                    "ID": "37", 
                    "Name": "social networking"
                }, 
                {
                    "Count": 194, 
                    "ID": "118", 
                    "Name": "ad portal"
                }
            ], 
            "Risk": "Very Low", 
            "AppProductivity": "Medium", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }, 
                {
                    "Name": "Server"
                }
            ], 
            "ID": "2419", 
            "Name": "33Across"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 61, 
                    "ID": "34", 
                    "Name": "security management"
                }
            ], 
            "Risk": "Low", 
            "AppProductivity": "High", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "3866", 
            "Name": "360 Safeguard"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 1009, 
                    "ID": "2", 
                    "Name": "web services provider"
                }, 
                {
                    "Count": 12, 
                    "ID": "121", 
                    "Name": "healthcare services"
                }
            ], 
            "Risk": "Very Low", 
            "AppProductivity": "High", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "1207", 
            "Name": "39.net"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 998, 
                    "ID": "10", 
                    "Name": "network protocols/services"
                }
            ], 
            "Risk": "Medium", 
            "AppProductivity": "Medium", 
            "ApplicationTypes": [
                {
                    "Name": "Server"
                }
            ], 
            "ID": "3000", 
            "Name": "3Com AMP3"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 998, 
                    "ID": "10", 
                    "Name": "network protocols/services"
                }
            ], 
            "Risk": "Very Low", 
            "AppProductivity": "High", 
            "ApplicationTypes": [
                {
                    "Name": "Server"
                }
            ], 
            "ID": "2", 
            "Name": "3COM-TSMUX"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 160, 
                    "ID": "20", 
                    "Name": "gaming"
                }
            ], 
            "Risk": "Medium", 
            "AppProductivity": "Very Low", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "1256", 
            "Name": "4399.com"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 104, 
                    "ID": "40", 
                    "Name": "instant messaging"
                }
            ], 
            "Risk": "Medium", 
            "AppProductivity": "Very Low", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }, 
                {
                    "Name": "Server"
                }
            ], 
            "ID": "1079", 
            "Name": "4chan"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 155, 
                    "ID": "3", 
                    "Name": "remote file storage"
                }
            ], 
            "Risk": "Low", 
            "AppProductivity": "High", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }, 
                {
                    "Name": "Server"
                }
            ], 
            "ID": "948", 
            "Name": "4shared"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 1009, 
                    "ID": "2", 
                    "Name": "web services provider"
                }, 
                {
                    "Count": 179, 
                    "ID": "80", 
                    "Name": "mobile application"
                }
            ], 
            "Risk": "Very Low", 
            "AppProductivity": "Low", 
            "ApplicationTypes": [
                {
                    "Name": "Client"
                }, 
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "1654", 
            "Name": "500px"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 199, 
                    "ID": "37", 
                    "Name": "social networking"
                }
            ], 
            "Risk": "Low", 
            "AppProductivity": "Low", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "1032", 
            "Name": "51.com"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 385, 
                    "ID": "47", 
                    "Name": "multimedia (TV/video)"
                }
            ], 
            "Risk": "Low", 
            "AppProductivity": "Very Low", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "1031", 
            "Name": "56.com"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 1009, 
                    "ID": "2", 
                    "Name": "web services provider"
                }, 
                {
                    "Count": 377, 
                    "ID": "11", 
                    "Name": "e-commerce"
                }
            ], 
            "Risk": "Very Low", 
            "AppProductivity": "Low", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "1649", 
            "Name": "58 City"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 95, 
                    "ID": "53", 
                    "Name": "multimedia (other)"
                }, 
                {
                    "Count": 117, 
                    "ID": "60", 
                    "Name": "multimedia (music/audio)"
                }
            ], 
            "Risk": "Medium", 
            "AppProductivity": "Low", 
            "ApplicationTypes": [
                {
                    "Name": "Client"
                }, 
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "2218", 
            "Name": "5by5 Radio"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 377, 
                    "ID": "11", 
                    "Name": "e-commerce"
                }
            ], 
            "Risk": "Low", 
            "AppProductivity": "Very Low", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "538", 
            "Name": "6.pm"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 377, 
                    "ID": "11", 
                    "Name": "e-commerce"
                }
            ], 
            "Risk": "Very Low", 
            "AppProductivity": "Low", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "959", 
            "Name": "7digital"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 998, 
                    "ID": "10", 
                    "Name": "network protocols/services"
                }
            ], 
            "Risk": "Very Low", 
            "AppProductivity": "Medium", 
            "ApplicationTypes": [
                {
                    "Name": "Server"
                }
            ], 
            "ID": "4", 
            "Name": "914CG"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 94, 
                    "ID": "25", 
                    "Name": "web content aggregators"
                }, 
                {
                    "Count": 95, 
                    "ID": "53", 
                    "Name": "multimedia (other)"
                }
            ], 
            "Risk": "Medium", 
            "AppProductivity": "Very Low", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }, 
                {
                    "Name": "Server"
                }
            ], 
            "ID": "4167", 
            "Name": "9Gag"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 998, 
                    "ID": "10", 
                    "Name": "network protocols/services"
                }
            ], 
            "Risk": "Very Low", 
            "AppProductivity": "High", 
            "ApplicationTypes": [
                {
                    "Name": "Client"
                }, 
                {
                    "Name": "Server"
                }
            ], 
            "ID": "1087", 
            "Name": "9P"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 377, 
                    "ID": "11", 
                    "Name": "e-commerce"
                }, 
                {
                    "Count": 160, 
                    "ID": "20", 
                    "Name": "gaming"
                }, 
                {
                    "Count": 203, 
                    "ID": "106", 
                    "Name": "news"
                }
            ], 
            "Risk": "Medium", 
            "AppProductivity": "Very Low", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "920", 
            "Name": "9p.com"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 1009, 
                    "ID": "2", 
                    "Name": "web services provider"
                }, 
                {
                    "Count": 385, 
                    "ID": "47", 
                    "Name": "multimedia (TV/video)"
                }, 
                {
                    "Count": 203, 
                    "ID": "106", 
                    "Name": "news"
                }
            ], 
            "Risk": "Medium", 
            "AppProductivity": "Very Low", 
            "ApplicationTypes": [
                {
                    "Name": "Client"
                }, 
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "1389", 
            "Name": "ABC"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 29, 
                    "ID": "88", 
                    "Name": "web spider/search crawler"
                }
            ], 
            "Risk": "Low", 
            "AppProductivity": "Very Low", 
            "ApplicationTypes": [
                {
                    "Name": "Client"
                }
            ], 
            "ID": "2205", 
            "Name": "Abonti"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 94, 
                    "ID": "25", 
                    "Name": "web content aggregators"
                }
            ], 
            "Risk": "Very Low", 
            "AppProductivity": "Medium", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "1167", 
            "Name": "About.com"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 1009, 
                    "ID": "2", 
                    "Name": "web services provider"
                }, 
                {
                    "Count": 385, 
                    "ID": "47", 
                    "Name": "multimedia (TV/video)"
                }, 
                {
                    "Count": 203, 
                    "ID": "106", 
                    "Name": "news"
                }
            ], 
            "Risk": "Very Low", 
            "AppProductivity": "High", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }, 
                {
                    "Name": "Server"
                }
            ], 
            "ID": "4168", 
            "Name": "ABS-CBN"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 998, 
                    "ID": "10", 
                    "Name": "network protocols/services"
                }
            ], 
            "Risk": "Very Low", 
            "AppProductivity": "Very High", 
            "ApplicationTypes": [
                {
                    "Name": "Server"
                }
            ], 
            "ID": "5", 
            "Name": "ACA Services"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 998, 
                    "ID": "10", 
                    "Name": "network protocols/services"
                }
            ], 
            "Risk": "Medium", 
            "AppProductivity": "Medium", 
            "ApplicationTypes": [
                {
                    "Name": "Server"
                }
            ], 
            "ID": "3024", 
            "Name": "ACAP"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 998, 
                    "ID": "10", 
                    "Name": "network protocols/services"
                }
            ], 
            "Risk": "Medium", 
            "AppProductivity": "Medium", 
            "ApplicationTypes": [
                {
                    "Name": "Server"
                }
            ], 
            "ID": "3001", 
            "Name": "Access Network"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 998, 
                    "ID": "10", 
                    "Name": "network protocols/services"
                }
            ], 
            "Risk": "Medium", 
            "AppProductivity": "Medium", 
            "ApplicationTypes": [
                {
                    "Name": "Server"
                }
            ], 
            "ID": "3002", 
            "Name": "AccessBuilder"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 1009, 
                    "ID": "2", 
                    "Name": "web services provider"
                }, 
                {
                    "Count": 377, 
                    "ID": "11", 
                    "Name": "e-commerce"
                }, 
                {
                    "Count": 385, 
                    "ID": "47", 
                    "Name": "multimedia (TV/video)"
                }
            ], 
            "Risk": "Very Low", 
            "AppProductivity": "Low", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "1533", 
            "Name": "AccuWeather"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 377, 
                    "ID": "11", 
                    "Name": "e-commerce"
                }
            ], 
            "Risk": "Low", 
            "AppProductivity": "Very Low", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "539", 
            "Name": "Ace Hardware Corporation"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 234, 
                    "ID": "17", 
                    "Name": "business"
                }
            ], 
            "Risk": "Very Low", 
            "AppProductivity": "High", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "2146", 
            "Name": "Acer"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 94, 
                    "ID": "25", 
                    "Name": "web content aggregators"
                }, 
                {
                    "Count": 385, 
                    "ID": "47", 
                    "Name": "multimedia (TV/video)"
                }
            ], 
            "Risk": "High", 
            "AppProductivity": "Very Low", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }, 
                {
                    "Name": "Server"
                }
            ], 
            "ID": "4169", 
            "Name": "AcFun"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 998, 
                    "ID": "10", 
                    "Name": "network protocols/services"
                }
            ], 
            "Risk": "Very Low", 
            "AppProductivity": "Medium", 
            "ApplicationTypes": [
                {
                    "Name": "Server"
                }
            ], 
            "ID": "6", 
            "Name": "ACI"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 54, 
                    "ID": "23", 
                    "Name": "search engine"
                }, 
                {
                    "Count": 29, 
                    "ID": "88", 
                    "Name": "web spider/search crawler"
                }
            ], 
            "Risk": "Low", 
            "AppProductivity": "Low", 
            "ApplicationTypes": [
                {
                    "Name": "Client"
                }, 
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "2219", 
            "Name": "Acoon.de"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 998, 
                    "ID": "10", 
                    "Name": "network protocols/services"
                }
            ], 
            "Risk": "Low", 
            "AppProductivity": "High", 
            "ApplicationTypes": [
                {
                    "Name": "Server"
                }
            ], 
            "ID": "7", 
            "Name": "ACR-NEMA"
        }, 
        {
            "AppCategories": [
                {
                    "Count": 1009, 
                    "ID": "2", 
                    "Name": "web services provider"
                }
            ], 
            "Risk": "Low", 
            "AppProductivity": "High", 
            "ApplicationTypes": [
                {
                    "Name": "Webapp"
                }
            ], 
            "ID": "1322", 
            "Name": "Acrobat.com"
        }
    ]
}
```

##### Human Readable Output
### Cisco Firepower - List of applications objects:
|ID|Name|Risk|AppProductivity|ApplicationTypes|AppCategories|
|---|---|---|---|---|---|
| 2325 | 050plus | Medium | Medium | 2 | 2 |
| 1553 | 1&1 Internet | Very Low | Low | 1 | 2 |
| 535 | 1-800-Flowers | Low | Very Low | 1 | 1 |
| 3715 | 1000mercis | Low | Very Low | 1 | 1 |
| 536 | 100Bao | Very High | Very Low | 2 | 1 |
| 1205 | 12306.cn | Very Low | High | 1 | 2 |
| 4164 | 123Movies | Medium | Very Low | 2 | 1 |
| 1206 | 126.com | Very Low | High | 1 | 1 |
| 2385 | 17173.com | Medium | Very Low | 2 | 1 |
| 4165 | 1fichier | Low | Medium | 2 | 3 |
| 2346 | 2345.com | Very Low | Medium | 1 | 1 |
| 2493 | 24/7 Media | Very Low | Very Low | 1 | 3 |
| 2492 | 247 Inc. | Very Low | Very Low | 1 | 3 |
| 537 | 2channel | Low | Very Low | 2 | 1 |
| 1781 | 2Leep | Medium | Low | 1 | 1 |
| 2419 | 33Across | Very Low | Medium | 2 | 4 |
| 3866 | 360 Safeguard | Low | High | 1 | 1 |
| 1207 | 39.net | Very Low | High | 1 | 2 |
| 3000 | 3Com AMP3 | Medium | Medium | 1 | 1 |
| 2 | 3COM-TSMUX | Very Low | High | 1 | 1 |
| 1256 | 4399.com | Medium | Very Low | 1 | 1 |
| 1079 | 4chan | Medium | Very Low | 2 | 1 |
| 948 | 4shared | Low | High | 2 | 1 |
| 1654 | 500px | Very Low | Low | 2 | 2 |
| 1032 | 51.com | Low | Low | 1 | 1 |
| 1031 | 56.com | Low | Very Low | 1 | 1 |
| 1649 | 58 City | Very Low | Low | 1 | 2 |
| 2218 | 5by5 Radio | Medium | Low | 2 | 2 |
| 538 | 6.pm | Low | Very Low | 1 | 1 |
| 959 | 7digital | Very Low | Low | 1 | 1 |
| 4 | 914CG | Very Low | Medium | 1 | 1 |
| 4167 | 9Gag | Medium | Very Low | 2 | 2 |
| 1087 | 9P | Very Low | High | 2 | 1 |
| 920 | 9p.com | Medium | Very Low | 1 | 3 |
| 1389 | ABC | Medium | Very Low | 2 | 3 |
| 2205 | Abonti | Low | Very Low | 1 | 1 |
| 1167 | About.com | Very Low | Medium | 1 | 1 |
| 4168 | ABS-CBN | Very Low | High | 2 | 3 |
| 5 | ACA Services | Very Low | Very High | 1 | 1 |
| 3024 | ACAP | Medium | Medium | 1 | 1 |
| 3001 | Access Network | Medium | Medium | 1 | 1 |
| 3002 | AccessBuilder | Medium | Medium | 1 | 1 |
| 1533 | AccuWeather | Very Low | Low | 1 | 3 |
| 539 | Ace Hardware Corporation | Low | Very Low | 1 | 1 |
| 2146 | Acer | Very Low | High | 1 | 1 |
| 4169 | AcFun | High | Very Low | 2 | 2 |
| 6 | ACI | Very Low | Medium | 1 | 1 |
| 2219 | Acoon.de | Low | Low | 2 | 2 |
| 7 | ACR-NEMA | Low | High | 1 | 1 |
| 1322 | Acrobat.com | Low | High | 1 | 1 |


### 25. ciscofp-get-access-rules
---
Retrieves the access control rule associated with the specified policy ID and rule ID. If no rule ID is specified, retrieves a list of all access rules associated with the specified policy ID.

##### Base Command

`ciscofp-get-access-rules`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | Policy ID. | Required | 
| rule_id | Rule ID. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Rule.Action | String | Rule action. | 
| CiscoFP.Rule.Applications.ID | String | Application object ID. | 
| CiscoFP.Rule.Applications.Name | String | Application object name. | 
| CiscoFP.Rule.Category | String | Category of rule. | 
| CiscoFP.Rule.DestinationNetworks.Addresses.Type | String | Address type. | 
| CiscoFP.Rule.DestinationNetworks.Addresses.Value | String | IP address or CIDR range. | 
| CiscoFP.Rule.DestinationNetworks.Objects.ID | String | Object ID. | 
| CiscoFP.Rule.DestinationNetworks.Objects.Name | String | Object name. | 
| CiscoFP.Rule.DestinationNetworks.Objects.Type | String | Object type. | 
| CiscoFP.Rule.DestinationPorts.Addresses.Port | String | Port number. | 
| CiscoFP.Rule.DestinationPorts.Addresses.Protocol | String | Port protocol. | 
| CiscoFP.Rule.DestinationPorts.Objects.ID | String | Port object ID. | 
| CiscoFP.Rule.DestinationPorts.Objects.Name | String | Port object name. | 
| CiscoFP.Rule.DestinationPorts.Objects.Protocol | String | Port object protocol. | 
| CiscoFP.Rule.DestinationPorts.Objects.Type | String | Port object type. | 
| CiscoFP.Rule.DestinationZones.Objects.ID | String | Zone ID. | 
| CiscoFP.Rule.DestinationZones.Objects.Name | String | Zone name. | 
| CiscoFP.Rule.DestinationZones.Objects.Type | String | Zone type. | 
| CiscoFP.Rule.Enabled | Number | Whether the rule is enabled. | 
| CiscoFP.Rule.ID | String | Rule ID. | 
| CiscoFP.Rule.Name | String | Rule name. | 
| CiscoFP.Rule.RuleIndex | Number | The index of the rule. | 
| CiscoFP.Rule.Section | String | The section of the rule. | 
| CiscoFP.Rule.SendEventsToFMC | Number | Boolean indicating whether the device will send events to Cisco Firepower. | 
| CiscoFP.Rule.SourceNetworks.Addresses.Type | String | The address type. | 
| CiscoFP.Rule.SourceNetworks.Addresses.Value | String | IP address or CIDR range. | 
| CiscoFP.Rule.SourceNetworks.Objects.ID | String | Object ID. | 
| CiscoFP.Rule.SourceNetworks.Objects.Name | String | Object name. | 
| CiscoFP.Rule.SourceNetworks.Objects.Type | String | Object type. | 
| CiscoFP.Rule.SourcePorts.Addresses.Port | String | Port number. | 
| CiscoFP.Rule.SourcePorts.Addresses.Protocol | String | Port protocol. | 
| CiscoFP.Rule.SourcePorts.Objects.ID | String | Object ID. | 
| CiscoFP.Rule.SourcePorts.Objects.Name | String | Object name. | 
| CiscoFP.Rule.SourcePorts.Objects.Protocol | String | Object protocol. | 
| CiscoFP.Rule.SourcePorts.Objects.Type | String | Object type. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.ID | String | Object ID. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.Name | String | Object name. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.Type | String | Object type. | 
| CiscoFP.Rule.SourceZones.Objects.ID | String | Object ID. | 
| CiscoFP.Rule.SourceZones.Objects.Name | String | Object name. | 
| CiscoFP.Rule.SourceZones.Objects.Type | String | Object type. | 
| CiscoFP.Rule.Urls.Addresses.URL | String | URL address. | 
| CiscoFP.Rule.Urls.Objects.ID | String | URL object ID. | 
| CiscoFP.Rule.Urls.Objects.Name | String | URL object name. | 
| CiscoFP.Rule.VlanTags.Numbers.EndTag | Number | The vlan tag number end tag. | 
| CiscoFP.Rule.VlanTags.Numbers.StartTag | Number | The vlan tag number start tag. | 
| CiscoFP.Rule.VlanTags.Objects.ID | String | Object ID. | 
| CiscoFP.Rule.VlanTags.Objects.Name | String | Object name. | 
| CiscoFP.Rule.VlanTags.Objects.Type | String | Object type. | 


##### Command Example
```!ciscofp-get-access-rules policy_id=000C29A8-BA3B-0ed3-0000-085899346038```

##### Context Example
```
{
    "CiscoFP.Rule": [
        {
            "Category": "--Undefined--", 
            "SourceZones": {
                "Objects": []
            }, 
            "DestinationZones": {
                "Objects": []
            }, 
            "DestinationNetworks": {
                "Objects": [], 
                "Addresses": []
            }, 
            "DestinationPorts": {
                "Objects": [], 
                "Addresses": []
            }, 
            "Section": "Mandatory", 
            "Enabled": true, 
            "SourcePorts": {
                "Objects": [], 
                "Addresses": []
            }, 
            "RuleIndex": 1, 
            "VlanTags": {
                "Objects": [], 
                "Numbers": []
            }, 
            "Applications": [], 
            "SourceSecurityGroupTags": {
                "Objects": []
            }, 
            "Urls": {
                "Objects": [], 
                "Addresses": []
            }, 
            "Action": "ALLOW", 
            "SourceNetworks": {
                "Objects": [], 
                "Addresses": []
            }, 
            "SendEventsToFMC": true, 
            "ID": "000C29A8-BA3B-0ed3-0000-000268440577", 
            "Name": "IP Any Any Any"
        }, 
        {
            "Category": "--Undefined--", 
            "SourceZones": {
                "Objects": []
            }, 
            "DestinationZones": {
                "Objects": []
            }, 
            "DestinationNetworks": {
                "Objects": [], 
                "Addresses": []
            }, 
            "DestinationPorts": {
                "Objects": [], 
                "Addresses": []
            }, 
            "Section": "Mandatory", 
            "Enabled": true, 
            "SourcePorts": {
                "Objects": [], 
                "Addresses": []
            }, 
            "RuleIndex": 2, 
            "VlanTags": {
                "Objects": [], 
                "Numbers": []
            }, 
            "Applications": [], 
            "SourceSecurityGroupTags": {
                "Objects": []
            }, 
            "Urls": {
                "Objects": [], 
                "Addresses": []
            }, 
            "Action": "ALLOW", 
            "SourceNetworks": {
                "Objects": [], 
                "Addresses": []
            }, 
            "SendEventsToFMC": false, 
            "ID": "000C29A8-BA3B-0ed3-0000-000268441600", 
            "Name": "test"
        }, 
        {
            "Category": "--Undefined--", 
            "SourceZones": {
                "Objects": []
            }, 
            "DestinationZones": {
                "Objects": []
            }, 
            "DestinationNetworks": {
                "Objects": [], 
                "Addresses": []
            }, 
            "DestinationPorts": {
                "Objects": [], 
                "Addresses": []
            }, 
            "Section": "Mandatory", 
            "Enabled": true, 
            "SourcePorts": {
                "Objects": [], 
                "Addresses": []
            }, 
            "RuleIndex": 3, 
            "VlanTags": {
                "Objects": [], 
                "Numbers": []
            }, 
            "Applications": [], 
            "SourceSecurityGroupTags": {
                "Objects": []
            }, 
            "Urls": {
                "Objects": [], 
                "Addresses": []
            }, 
            "Action": "BLOCK", 
            "SourceNetworks": {
                "Objects": [], 
                "Addresses": [
                    {
                        "Type": "Host", 
                        "Value": "10.0.0.5"
                    }
                ]
            }, 
            "SendEventsToFMC": false, 
            "ID": "000C29A8-BA3B-0ed3-0000-000268442624", 
            "Name": "arseny_rule"
        }, 
        {
            "Category": "--Undefined--", 
            "SourceZones": {
                "Objects": [
                    {
                        "Type": "SecurityZone", 
                        "ID": "6038978c-ffdf-11e9-8a1b-81dfc51749cb", 
                        "Name": "L3-Untrust"
                    }, 
                    {
                        "Type": "SecurityZone", 
                        "ID": "e5156ab2-c736-11e8-bacb-8d7a1cfa386e", 
                        "Name": "Trust"
                    }
                ]
            }, 
            "DestinationZones": {
                "Objects": [
                    {
                        "Type": "SecurityZone", 
                        "ID": "e5156ab2-c736-11e8-bacb-8d7a1cfa386e", 
                        "Name": "Trust"
                    }, 
                    {
                        "Type": "SecurityZone", 
                        "ID": "5884acce-ffdf-11e9-8a1b-81dfc51749cb", 
                        "Name": "L3-Trust"
                    }
                ]
            }, 
            "DestinationNetworks": {
                "Objects": [
                    {
                        "Type": "NetworkGroup", 
                        "ID": "000C29A8-BA3B-0ed3-0000-124554053470", 
                        "Name": "ee"
                    }, 
                    {
                        "Type": "Network", 
                        "ID": "000C29A8-BA3B-0ed3-0000-124554053196", 
                        "Name": "nn"
                    }
                ], 
                "Addresses": []
            }, 
            "DestinationPorts": {
                "Objects": [
                    {
                        "Type": "ProtocolPortObject", 
                        "Protocol": "TCP", 
                        "ID": "1834e50a-38bb-11e2-86aa-62f0c593a59a", 
                        "Name": "TCP_high_ports"
                    }, 
                    {
                        "Type": "ProtocolPortObject", 
                        "Protocol": "TCP", 
                        "ID": "1834c07a-38bb-11e2-86aa-62f0c593a59a", 
                        "Name": "SMTPS"
                    }
                ], 
                "Addresses": [
                    {
                        "Protocol": "6", 
                        "Port": "990"
                    }
                ]
            }, 
            "Section": "Default", 
            "Enabled": true, 
            "SourcePorts": {
                "Objects": [
                    {
                        "Type": "ProtocolPortObject", 
                        "Protocol": "TCP", 
                        "ID": "1834bd00-38bb-11e2-86aa-62f0c593a59a", 
                        "Name": "HTTPS"
                    }, 
                    {
                        "Type": "ProtocolPortObject", 
                        "Protocol": "TCP", 
                        "ID": "28e058e4-43b0-11e2-9bcd-7c2f9ed9bbee", 
                        "Name": "TELNET"
                    }
                ], 
                "Addresses": [
                    {
                        "Protocol": "6", 
                        "Port": "900"
                    }
                ]
            }, 
            "RuleIndex": 4, 
            "VlanTags": {
                "Objects": [
                    {
                        "Type": "VlanTag", 
                        "ID": "000C29A8-BA3B-0ed3-0000-124554052529", 
                        "Name": "aaaa"
                    }
                ], 
                "Numbers": [
                    {
                        "StartTag": 1300, 
                        "EndTag": 1300
                    }
                ]
            }, 
            "Applications": [
                {
                    "ID": "536", 
                    "Name": "100Bao"
                }, 
                {
                    "ID": "3715", 
                    "Name": "1000mercis"
                }, 
                {
                    "ID": "948", 
                    "Name": "4shared"
                }, 
                {
                    "ID": "1087", 
                    "Name": "9P"
                }
            ], 
            "SourceSecurityGroupTags": {
                "Objects": [
                    {
                        "Type": "SecurityGroupTag", 
                        "ID": "5fce8cce-aa67-11e5-816b-95eb712b72a1", 
                        "Name": "ANY"
                    }, 
                    {
                        "Type": "SecurityGroupTag", 
                        "ID": "8d9813aa-32c1-11ea-9d47-eda81976c864", 
                        "Name": "sample_tag"
                    }
                ]
            }, 
            "Urls": {
                "Objects": [
                    {
                        "ID": "60f4e2ab-d96c-44a0-bd38-830252b67077", 
                        "Name": "URL CnC"
                    }, 
                    {
                        "ID": "3e2af68e-5fc8-4b1c-b5bc-b4e7cab5c9eb", 
                        "Name": "URL Spam"
                    }
                ], 
                "Addresses": [
                    {
                        "URL": "www.ynet.co.il"
                    }
                ]
            }, 
            "Action": "ALLOW", 
            "SourceNetworks": {
                "Objects": [
                    {
                        "Type": "Network", 
                        "ID": "000C29A8-BA3B-0ed3-0000-124554053289", 
                        "Name": "1"
                    }, 
                    {
                        "Type": "NetworkGroup", 
                        "ID": "69fa2a3a-4487-4e3c-816f-4098f684826e", 
                        "Name": "any"
                    }, 
                    {
                        "Type": "NetworkGroup", 
                        "ID": "000C29A8-BA3B-0ed3-0000-124554053470", 
                        "Name": "ee"
                    }
                ], 
                "Addresses": []
            }, 
            "SendEventsToFMC": false, 
            "ID": "000C29A8-BA3B-0ed3-0000-000268443649", 
            "Name": "mytest"
        }, 
        {
            "Category": "--Undefined--", 
            "SourceZones": {
                "Objects": []
            }, 
            "DestinationZones": {
                "Objects": []
            }, 
            "DestinationNetworks": {
                "Objects": [], 
                "Addresses": [
                    {
                        "Type": "Host", 
                        "Value": "8.8.8.2"
                    }, 
                    {
                        "Type": "Host", 
                        "Value": "4.4.4.8"
                    }
                ]
            }, 
            "DestinationPorts": {
                "Objects": [], 
                "Addresses": []
            }, 
            "Section": "Default", 
            "Enabled": false, 
            "SourcePorts": {
                "Objects": [], 
                "Addresses": []
            }, 
            "RuleIndex": 5, 
            "VlanTags": {
                "Objects": [], 
                "Numbers": []
            }, 
            "Applications": [], 
            "SourceSecurityGroupTags": {
                "Objects": []
            }, 
            "Urls": {
                "Objects": [], 
                "Addresses": [
                    {
                        "URL": "galitz.com"
                    }, 
                    {
                        "URL": "goog.com"
                    }
                ]
            }, 
            "Action": "BLOCK", 
            "SourceNetworks": {
                "Objects": [], 
                "Addresses": [
                    {
                        "Type": "Host", 
                        "Value": "10.0.0.1"
                    }, 
                    {
                        "Type": "Host", 
                        "Value": "8.8.8.6"
                    }
                ]
            }, 
            "SendEventsToFMC": false, 
            "ID": "000C29A8-BA3B-0ed3-0000-000268443653", 
            "Name": "newUpdateTest"
        }, 
        {
            "Category": "--Undefined--", 
            "SourceZones": {
                "Objects": []
            }, 
            "DestinationZones": {
                "Objects": []
            }, 
            "DestinationNetworks": {
                "Objects": [], 
                "Addresses": [
                    {
                        "Type": "Host", 
                        "Value": "1.2.3.5"
                    }
                ]
            }, 
            "DestinationPorts": {
                "Objects": [], 
                "Addresses": []
            }, 
            "Section": "Default", 
            "Enabled": true, 
            "SourcePorts": {
                "Objects": [], 
                "Addresses": []
            }, 
            "RuleIndex": 6, 
            "VlanTags": {
                "Objects": [], 
                "Numbers": []
            }, 
            "Applications": [], 
            "SourceSecurityGroupTags": {
                "Objects": []
            }, 
            "Urls": {
                "Objects": [], 
                "Addresses": [
                    {
                        "URL": "www.google.com"
                    }
                ]
            }, 
            "Action": "ALLOW", 
            "SourceNetworks": {
                "Objects": [], 
                "Addresses": [
                    {
                        "Type": "Host", 
                        "Value": "1.2.3.4"
                    }
                ]
            }, 
            "SendEventsToFMC": false, 
            "ID": "000C29A8-BA3B-0ed3-0000-000268444677", 
            "Name": "playbookTest5"
        }
    ]
}
```

##### Human Readable Output
### Cisco Firepower - List of access rules:
|ID|Name|Action|Enabled|SendEventsToFMC|RuleIndex|Section|Category|Urls|VlanTags|SourceZones|Applications|DestinationZones|SourceNetworks|DestinationNetworks|SourcePorts|DestinationPorts|SourceSecurityGroupTags|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 000C29A8-BA3B-0ed3-0000-000268440577 | IP Any Any Any | ALLOW | true | true | 1 | Mandatory | --Undefined-- | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 000C29A8-BA3B-0ed3-0000-000268441600 | test | ALLOW | true | false | 2 | Mandatory | --Undefined-- | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 000C29A8-BA3B-0ed3-0000-000268442624 | arseny_rule | BLOCK | true | false | 3 | Mandatory | --Undefined-- | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| 000C29A8-BA3B-0ed3-0000-000268443649 | mytest | ALLOW | true | false | 4 | Default | --Undefined-- | 3 | 2 | 2 | 4 | 2 | 3 | 2 | 3 | 3 | 2 |
| 000C29A8-BA3B-0ed3-0000-000268443653 | newUpdateTest | BLOCK | false | false | 5 | Default | --Undefined-- | 2 | 0 | 0 | 0 | 0 | 2 | 2 | 0 | 0 | 0 |
| 000C29A8-BA3B-0ed3-0000-000268444677 | playbookTest5 | ALLOW | true | false | 6 | Default | --Undefined-- | 1 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 0 | 0 |



### 26. ciscofp-create-access-rules
---
Creates an access control rule.

##### Base Command

`ciscofp-create-access-rules`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | The rule's traffic. Can be "ALLOW", "TRUST", "BLOCK", "MONITOR", "BLOCK_RESET", "BLOCK_INTERACTIVE", or "BLOCK_RESET_INTERACTIVE". | Required | 
| rule_name | The rule name. | Required | 
| enabled | Boolean indicating whether to enable the access control rule. | Optional | 
| source_zone_object_ids | A list of source zone object IDs. To get IDs use the ciscofp-list-zones command. | Optional | 
| policy_id | The policy ID in which to create the new rule. | Required | 
| destination_zone_object_ids | A list of destination zone object IDs. To get IDs, use the ciscofp-list-zones command. | Optional | 
| vlan_tag_object_ids | A list of vlan tag object IDs. To get IDs, use the ciscofp-list-vlan-tags command. | Optional | 
| source_network_object_ids | A list of network object IDs. To get IDs, use the ciscofp-get-network-groups-object command. | Optional | 
| source_network_addresses | A list of source IP addresses or CIDR ranges. To get the addresses or ranges, use the ciscofp-get-network-object or ciscofp-get-host-object command, respectively. | Optional | 
| destination_network_object_ids | A list of destination IP addresses or CIDR ranges. To get the addresses or ranges, use the ciscofp-get-network-object or ciscofp-get-host-object command, respectively. | Optional | 
| destination_network_addresses | A list of destination addresses. | Optional | 
| source_port_object_ids | A list of port object IDs. To get IDs,  use the ciscofp-get-network-object or ciscofp-get-host-object commands. | Optional | 
| destination_port_object_ids | A list of port object IDs. To get IDs, use the ciscofp-list-ports command. | Optional | 
| source_security_group_tag_object_ids | A list of security group tag object IDs. To get IDs, use the ciscofp-list-security-group-tags command. | Optional | 
| application_object_ids | A list of application object IDs. To get IDs, use the ciscofp-list-applications command. | Optional | 
| url_object_ids | A list of URL object IDs. To get IDs, use the ciscofp-list-url-categories command. | Optional | 
| url_addresses | A list of URL addresses. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Rule.Action | String | The action that determines how the system handles matching traffic. | 
| CiscoFP.Rule.Applications.ID | String | The application object ID. | 
| CiscoFP.Rule.Applications.Name | String | The application object name. | 
| CiscoFP.Rule.Category | String | The category of rule. | 
| CiscoFP.Rule.DestinationNetworks.Addresses.Type | String | The address type. | 
| CiscoFP.Rule.DestinationNetworks.Addresses.Value | String | The address value. | 
| CiscoFP.Rule.DestinationNetworks.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.DestinationNetworks.Objects.Name | String | The object name. | 
| CiscoFP.Rule.DestinationNetworks.Objects.Type | String | The object type. | 
| CiscoFP.Rule.DestinationPorts.Addresses.Port | String | The port number. | 
| CiscoFP.Rule.DestinationPorts.Addresses.Protocol | String | The port protocol. | 
| CiscoFP.Rule.DestinationPorts.Objects.ID | String | The port object ID. | 
| CiscoFP.Rule.DestinationPorts.Objects.Name | String | The port object name. | 
| CiscoFP.Rule.DestinationPorts.Objects.Protocol | String | The port object protocol. | 
| CiscoFP.Rule.DestinationPorts.Objects.Type | String | The port object type. | 
| CiscoFP.Rule.DestinationZones.Objects.ID | String | The zone ID. | 
| CiscoFP.Rule.DestinationZones.Objects.Name | String | The zone name. | 
| CiscoFP.Rule.DestinationZones.Objects.Type | String | The zone type. | 
| CiscoFP.Rule.Enabled | Number | Boolean indicating whether to enable the rule. | 
| CiscoFP.Rule.ID | String | The rule ID. | 
| CiscoFP.Rule.Name | String | The rule name. | 
| CiscoFP.Rule.RuleIndex | Number | The index of the rule. | 
| CiscoFP.Rule.Section | String | The section of the rule. | 
| CiscoFP.Rule.SendEventsToFMC | Number | Boolean indicating whether the device will send events to Cisco Firepower. | 
| CiscoFP.Rule.SourceNetworks.Addresses.Type | String | The address type. | 
| CiscoFP.Rule.SourceNetworks.Addresses.Value | String | The address value. | 
| CiscoFP.Rule.SourceNetworks.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourceNetworks.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourceNetworks.Objects.Type | String | The object type. | 
| CiscoFP.Rule.SourcePorts.Addresses.Port | String | The address port. | 
| CiscoFP.Rule.SourcePorts.Addresses.Protocol | String | The address protocol. | 
| CiscoFP.Rule.SourcePorts.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourcePorts.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourcePorts.Objects.Protocol | String | The object protocol. | 
| CiscoFP.Rule.SourcePorts.Objects.Type | String | The object type. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.Type | String | The object type. | 
| CiscoFP.Rule.SourceZones.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourceZones.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourceZones.Objects.Type | String | The object type. | 
| CiscoFP.Rule.Urls.Addresses.URL | String | The URL address. | 
| CiscoFP.Rule.Urls.Objects.ID | String | The URL object ID. | 
| CiscoFP.Rule.Urls.Objects.Name | String | The URL object name. | 
| CiscoFP.Rule.VlanTags.Numbers.EndTag | Number | The vlan tag number end tag. | 
| CiscoFP.Rule.VlanTags.Numbers.StartTag | Number | The vlan tag number start tag. | 
| CiscoFP.Rule.VlanTags.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.VlanTags.Objects.Name | String | The object name. | 
| CiscoFP.Rule.VlanTags.Objects.Type | String | The object type. | 


##### Command Example
```!ciscofp-create-access-rules action=ALLOW rule_name=playbookTest5 enabled=true source_network_addresses=1.2.3.4 destination_network_addresses=1.2.3.5 url_addresses=www.google.com policy_id=000C29A8-BA3B-0ed3-0000-085899346038```

##### Human Readable Output### 26. ciscofp-create-access-rules
---
Creates an access control rule.

##### Base Command

`ciscofp-create-access-rules`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | The rule's traffic. Can be "ALLOW", "TRUST", "BLOCK", "MONITOR", "BLOCK_RESET", "BLOCK_INTERACTIVE", or "BLOCK_RESET_INTERACTIVE". | Required | 
| rule_name | The rule name. | Required | 
| enabled | Boolean indicating whether to enable the access control rule. | Optional | 
| source_zone_object_ids | A list of source zone object IDs. To get IDs use the ciscofp-list-zones command. | Optional | 
| policy_id | The policy ID in which to create the new rule. | Required | 
| destination_zone_object_ids | A list of destination zone object IDs. To get IDs, use the ciscofp-list-zones command. | Optional | 
| vlan_tag_object_ids | A list of vlan tag object IDs. To get IDs, use the ciscofp-list-vlan-tags command. | Optional | 
| source_network_object_ids | A list of network object IDs. To get IDs, use the ciscofp-get-network-groups-object command. | Optional | 
| source_network_addresses | A list of source IP addresses or CIDR ranges. To get the addresses or ranges, use the ciscofp-get-network-object or ciscofp-get-host-object command, respectively. | Optional | 
| destination_network_object_ids | A list of destination IP addresses or CIDR ranges. To get the addresses or ranges, use the ciscofp-get-network-object or ciscofp-get-host-object command, respectively. | Optional | 
| destination_network_addresses | A list of destination addresses. | Optional | 
| source_port_object_ids | A list of port object IDs. To get IDs,  use the ciscofp-get-network-object or ciscofp-get-host-object commands. | Optional | 
| destination_port_object_ids | A list of port object IDs. To get IDs, use the ciscofp-list-ports command. | Optional | 
| source_security_group_tag_object_ids | A list of security group tag object IDs. To get IDs, use the ciscofp-list-security-group-tags command. | Optional | 
| application_object_ids | A list of application object IDs. To get IDs, use the ciscofp-list-applications command. | Optional | 
| url_object_ids | A list of URL object IDs. To get IDs, use the ciscofp-list-url-categories command. | Optional | 
| url_addresses | A list of URL addresses. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Rule.Action | String | The action that determines how the system handles matching traffic. | 
| CiscoFP.Rule.Applications.ID | String | The application object ID. | 
| CiscoFP.Rule.Applications.Name | String | The application object name. | 
| CiscoFP.Rule.Category | String | The category of rule. | 
| CiscoFP.Rule.DestinationNetworks.Addresses.Type | String | The address type. | 
| CiscoFP.Rule.DestinationNetworks.Addresses.Value | String | The address value. | 
| CiscoFP.Rule.DestinationNetworks.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.DestinationNetworks.Objects.Name | String | The object name. | 
| CiscoFP.Rule.DestinationNetworks.Objects.Type | String | The object type. | 
| CiscoFP.Rule.DestinationPorts.Addresses.Port | String | The port number. | 
| CiscoFP.Rule.DestinationPorts.Addresses.Protocol | String | The port protocol. | 
| CiscoFP.Rule.DestinationPorts.Objects.ID | String | The port object ID. | 
| CiscoFP.Rule.DestinationPorts.Objects.Name | String | The port object name. | 
| CiscoFP.Rule.DestinationPorts.Objects.Protocol | String | The port object protocol. | 
| CiscoFP.Rule.DestinationPorts.Objects.Type | String | The port object type. | 
| CiscoFP.Rule.DestinationZones.Objects.ID | String | The zone ID. | 
| CiscoFP.Rule.DestinationZones.Objects.Name | String | The zone name. | 
| CiscoFP.Rule.DestinationZones.Objects.Type | String | The zone type. | 
| CiscoFP.Rule.Enabled | Number | Boolean indicating whether to enable the rule. | 
| CiscoFP.Rule.ID | String | The rule ID. | 
| CiscoFP.Rule.Name | String | The rule name. | 
| CiscoFP.Rule.RuleIndex | Number | The index of the rule. | 
| CiscoFP.Rule.Section | String | The section of the rule. | 
| CiscoFP.Rule.SendEventsToFMC | Number | Boolean indicating whether the device will send events to Cisco Firepower. | 
| CiscoFP.Rule.SourceNetworks.Addresses.Type | String | The address type. | 
| CiscoFP.Rule.SourceNetworks.Addresses.Value | String | The address value. | 
| CiscoFP.Rule.SourceNetworks.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourceNetworks.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourceNetworks.Objects.Type | String | The object type. | 
| CiscoFP.Rule.SourcePorts.Addresses.Port | String | The address port. | 
| CiscoFP.Rule.SourcePorts.Addresses.Protocol | String | The address protocol. | 
| CiscoFP.Rule.SourcePorts.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourcePorts.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourcePorts.Objects.Protocol | String | The object protocol. | 
| CiscoFP.Rule.SourcePorts.Objects.Type | String | The object type. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.Type | String | The object type. | 
| CiscoFP.Rule.SourceZones.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourceZones.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourceZones.Objects.Type | String | The object type. | 
| CiscoFP.Rule.Urls.Addresses.URL | String | The URL address. | 
| CiscoFP.Rule.Urls.Objects.ID | String | The URL object ID. | 
| CiscoFP.Rule.Urls.Objects.Name | String | The URL object name. | 
| CiscoFP.Rule.VlanTags.Numbers.EndTag | Number | The vlan tag number end tag. | 
| CiscoFP.Rule.VlanTags.Numbers.StartTag | Number | The vlan tag number start tag. | 
| CiscoFP.Rule.VlanTags.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.VlanTags.Objects.Name | String | The object name. | 
| CiscoFP.Rule.VlanTags.Objects.Type | String | The object type. | 


##### Command Example
```!ciscofp-create-access-rules action=ALLOW rule_name=newTest222322 enabled=true source_network_addresses=1.2.3.4 destination_network_addresses=1.2.3.5 url_addresses=www.google.com policy_id=000C29A8-BA3B-0ed3-0000-085899346038```

##### Context Example
```
{
    "CiscoFP.Rule": {
        "Category": "--Undefined--", 
        "SourceZones": {
            "Objects": []
        }, 
        "DestinationZones": {
            "Objects": []
        }, 
        "DestinationNetworks": {
            "Objects": [], 
            "Addresses": [
                {
                    "Type": "Host", 
                    "Value": "1.2.3.5"
                }
            ]
        }, 
        "DestinationPorts": {
            "Objects": [], 
            "Addresses": []
        }, 
        "Section": "Default", 
        "Enabled": true, 
        "SourcePorts": {
            "Objects": [], 
            "Addresses": []
        }, 
        "RuleIndex": 1, 
        "VlanTags": {
            "Objects": [], 
            "Numbers": []
        }, 
        "Applications": [], 
        "SourceSecurityGroupTags": {
            "Objects": []
        }, 
        "Urls": {
            "Objects": [], 
            "Addresses": [
                {
                    "URL": "www.google.com"
                }
            ]
        }, 
        "Action": "ALLOW", 
        "SourceNetworks": {
            "Objects": [], 
            "Addresses": [
                {
                    "Type": "Host", 
                    "Value": "1.2.3.4"
                }
            ]
        }, 
        "SendEventsToFMC": false, 
        "ID": "000C29A8-BA3B-0ed3-0000-000268444679", 
        "Name": "newTest222322"
    }
}
```

##### Human Readable Output
### Cisco Firepower - the new access rule:
|ID|Name|Action|Enabled|SendEventsToFMC|RuleIndex|Section|Category|Urls|VlanTags|SourceZones|Applications|DestinationZones|SourceNetworks|DestinationNetworks|SourcePorts|DestinationPorts|SourceSecurityGroupTags|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 000C29A8-BA3B-0ed3-0000-000268444679 | newTest222322 | ALLOW | true | false | 1 | Default | --Undefined-- | 1 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 0 | 0 |



### 27. ciscofp-update-access-rules
---
Updates the specified access control rule.

##### Base Command

`ciscofp-update-access-rules`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| update_strategy | The method by which to update the rule. Can be "merge" or "override". If merge, will add the changes requested to the existing rule. If override, will override the fields with the inputs provided and will delete any fields that were not provided. | Required | 
| action | The rule action that determines how the system handles matching traffic. Can be "ALLOW", "TRUST", "BLOCK", "MONITOR", "BLOCK_RESET", "BLOCK_INTERACTIVE", or "BLOCK_RESET_INTERACTIVE". | Optional | 
| rule_name | The rule name. | Optional | 
| enabled | Boolean indicating whether to enable the rule. The default is "true". | Optional | 
| source_zone_object_ids | A list of source zones object IDs. | Optional | 
| policy_id | The policy ID for which to create the new rule. | Required | 
| destination_zone_object_ids | A list of destination zones object IDs. | Optional | 
| vlan_tag_object_ids | A list of vlan tag object IDs. | Optional | 
| source_network_object_ids | A list of source network object IDs. | Optional | 
| source_network_addresses | A list of addresses. | Optional | 
| destination_network_object_ids | A list of destination network object IDs. | Optional | 
| destination_network_addresses | A list of addresses. | Optional | 
| source_port_object_ids | A list of port object IDs. | Optional | 
| destination_port_object_ids | A list of port object IDs. | Optional | 
| source_security_group_tag_object_ids | A list of security group tag object IDs. | Optional | 
| application_object_ids | A list of application object IDs. | Optional | 
| url_object_ids | A list of URL object IDs. | Optional | 
| url_addresses | A list of URL addresses. | Optional | 
| rule_id | The ID of the rule to update. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Rule.Action | String | The action that determines how the system handles matching traffic. | 
| CiscoFP.Rule.Applications.ID | String | The application object ID. | 
| CiscoFP.Rule.Applications.Name | String | The application object name. | 
| CiscoFP.Rule.Category | String | The category of the rule. | 
| CiscoFP.Rule.DestinationNetworks.Addresses.Type | String | The address type. | 
| CiscoFP.Rule.DestinationNetworks.Addresses.Value | String | The address value. | 
| CiscoFP.Rule.DestinationNetworks.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.DestinationNetworks.Objects.Name | String | The object name. | 
| CiscoFP.Rule.DestinationNetworks.Objects.Type | String | The object type. | 
| CiscoFP.Rule.DestinationPorts.Addresses.Port | String | The port number. | 
| CiscoFP.Rule.DestinationPorts.Addresses.Protocol | String | The port protocol. | 
| CiscoFP.Rule.DestinationPorts.Objects.ID | String | The port object ID. | 
| CiscoFP.Rule.DestinationPorts.Objects.Name | String | The port object name. | 
| CiscoFP.Rule.DestinationPorts.Objects.Protocol | String | The port object protocol. | 
| CiscoFP.Rule.DestinationPorts.Objects.Type | String | The port object type. | 
| CiscoFP.Rule.DestinationZones.Objects.ID | String | The destination zone object IDs. | 
| CiscoFP.Rule.DestinationZones.Objects.Name | String | The destination zone object names. | 
| CiscoFP.Rule.DestinationZones.Objects.Type | String | The destination zone object types. | 
| CiscoFP.Rule.Enabled | Number | Boolean indicating whether the rule is enabled. | 
| CiscoFP.Rule.ID | String | The rule ID. | 
| CiscoFP.Rule.Name | String | The rule name. | 
| CiscoFP.Rule.RuleIndex | Number | The index of the rule. | 
| CiscoFP.Rule.Section | String | The section of the rule. | 
| CiscoFP.Rule.SendEventsToFMC | Number | Boolean indicating whether the device will send events to Cisco Firepower. | 
| CiscoFP.Rule.SourceNetworks.Addresses.Type | String | The address type. | 
| CiscoFP.Rule.SourceNetworks.Addresses.Value | String | The address value. | 
| CiscoFP.Rule.SourceNetworks.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourceNetworks.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourceNetworks.Objects.Type | String | The object type. | 
| CiscoFP.Rule.SourcePorts.Addresses.Port | String | The address port. | 
| CiscoFP.Rule.SourcePorts.Addresses.Protocol | String | The address protocol. | 
| CiscoFP.Rule.SourcePorts.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourcePorts.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourcePorts.Objects.Protocol | String | The object protocol. | 
| CiscoFP.Rule.SourcePorts.Objects.Type | String | The object type. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.Type | String | The object type. | 
| CiscoFP.Rule.SourceZones.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourceZones.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourceZones.Objects.Type | String | The object type. | 
| CiscoFP.Rule.Urls.Addresses.URL | String | The URL address. | 
| CiscoFP.Rule.Urls.Objects.ID | String | The URL object ID. | 
| CiscoFP.Rule.Urls.Objects.Name | String | The URL object name. | 
| CiscoFP.Rule.VlanTags.Numbers.EndTag | Number | The vlan tag number end tag. | 
| CiscoFP.Rule.VlanTags.Numbers.StartTag | Number | The vlan tag number start tag. | 
| CiscoFP.Rule.VlanTags.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.VlanTags.Objects.Name | String | The object name. | 
| CiscoFP.Rule.VlanTags.Objects.Type | String | The object type. | 


##### Command Example
```!ciscofp-update-access-rules policy_id=000C29A8-BA3B-0ed3-0000-133143987627 rule_id=000C29A8-BA3B-0ed3-0000-000268444675 update_strategy=merge enabled=false```

##### Context Example
```
{
    "CiscoFP.Rule": {
        "Category": "--Undefined--", 
        "SourceZones": {
            "Objects": []
        }, 
        "DestinationZones": {
            "Objects": []
        }, 
        "DestinationNetworks": {
            "Objects": [], 
            "Addresses": []
        }, 
        "DestinationPorts": {
            "Objects": [], 
            "Addresses": []
        }, 
        "Section": "Default", 
        "Enabled": false, 
        "SourcePorts": {
            "Objects": [], 
            "Addresses": []
        }, 
        "RuleIndex": 1, 
        "VlanTags": {
            "Objects": [], 
            "Numbers": []
        }, 
        "Applications": [], 
        "SourceSecurityGroupTags": {
            "Objects": []
        }, 
        "Urls": {
            "Objects": [], 
            "Addresses": []
        }, 
        "Action": "ALLOW", 
        "SourceNetworks": {
            "Objects": [], 
            "Addresses": []
        }, 
        "SendEventsToFMC": true, 
        "ID": "000C29A8-BA3B-0ed3-0000-000268444675", 
        "Name": "BPS-access-policy"
    }
}
```

##### Human Readable Output
### Cisco Firepower - access rule:
|ID|Name|Action|Enabled|SendEventsToFMC|RuleIndex|Section|Category|Urls|VlanTags|SourceZones|Applications|DestinationZones|SourceNetworks|DestinationNetworks|SourcePorts|DestinationPorts|SourceSecurityGroupTags|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 000C29A8-BA3B-0ed3-0000-000268444675 | BPS-access-policy | ALLOW | false | true | 1 | Default | --Undefined-- | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |



### 28. ciscofp-delete-access-rules
---
Deletes the specified access control rule.

##### Base Command

`ciscofp-delete-access-rules`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The policy ID. | Required | 
| rule_id | The ID of the rule to delete. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Rule.Action | String | The action that determines how the system handles matching traffic. | 
| CiscoFP.Rule.Applications.ID | String | The application object ID. | 
| CiscoFP.Rule.Applications.Name | String | The application object name. | 
| CiscoFP.Rule.Category | String | The category of the rule. | 
| CiscoFP.Rule.DestinationNetworks.Addresses.Type | String | The address type. | 
| CiscoFP.Rule.DestinationNetworks.Addresses.Value | String | The address value. | 
| CiscoFP.Rule.DestinationNetworks.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.DestinationNetworks.Objects.Name | String | The object name. | 
| CiscoFP.Rule.DestinationNetworks.Objects.Type | String | The object type. | 
| CiscoFP.Rule.DestinationPorts.Addresses.Port | String | The port number. | 
| CiscoFP.Rule.DestinationPorts.Addresses.Protocol | String | The port protocol. | 
| CiscoFP.Rule.DestinationPorts.Objects.ID | String | The port object ID. | 
| CiscoFP.Rule.DestinationPorts.Objects.Name | String | The port object name. | 
| CiscoFP.Rule.DestinationPorts.Objects.Protocol | String | The port object protocol. | 
| CiscoFP.Rule.DestinationPorts.Objects.Type | String | The port object type. | 
| CiscoFP.Rule.DestinationZones.Objects.ID | String | The zone IDs. | 
| CiscoFP.Rule.DestinationZones.Objects.Name | String | The zone names. | 
| CiscoFP.Rule.DestinationZones.Objects.Type | String | The zone types. | 
| CiscoFP.Rule.Enabled | Number | Boolean indicating whether the rule is enabled. | 
| CiscoFP.Rule.ID | String | The rule ID. | 
| CiscoFP.Rule.Name | String | The rule name. | 
| CiscoFP.Rule.RuleIndex | Number | The index of the rule. | 
| CiscoFP.Rule.Section | String | The section of the rule. | 
| CiscoFP.Rule.SendEventsToFMC | Number | Boolean indicating whether the device will send events to Cisco Firepower. | 
| CiscoFP.Rule.SourceNetworks.Addresses.Type | String | The address type. | 
| CiscoFP.Rule.SourceNetworks.Addresses.Value | String | The address value. | 
| CiscoFP.Rule.SourceNetworks.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourceNetworks.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourceNetworks.Objects.Type | String | The object type. | 
| CiscoFP.Rule.SourcePorts.Addresses.Port | String | The address port. | 
| CiscoFP.Rule.SourcePorts.Addresses.Protocol | String | The address protocol. | 
| CiscoFP.Rule.SourcePorts.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourcePorts.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourcePorts.Objects.Protocol | String | The object protocol. | 
| CiscoFP.Rule.SourcePorts.Objects.Type | String | The object type. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.Type | String | The object type. | 
| CiscoFP.Rule.SourceZones.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourceZones.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourceZones.Objects.Type | String | The object type. | 
| CiscoFP.Rule.Urls.Addresses.URL | String | The URL address. | 
| CiscoFP.Rule.Urls.Objects.ID | String | The URL object ID. | 
| CiscoFP.Rule.Urls.Objects.Name | String | The URL object name. | 
| CiscoFP.Rule.VlanTags.Numbers.EndTag | Number | The vlan tag number end tag. | 
| CiscoFP.Rule.VlanTags.Numbers.StartTag | Number | The vlan tag number start tag. | 
| CiscoFP.Rule.VlanTags.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.VlanTags.Objects.Name | String | The object name. | 
| CiscoFP.Rule.VlanTags.Objects.Type | String | The object type. | 


##### Command Example
```!ciscofp-delete-access-rules policy_id=000C29A8-BA3B-0ed3-0000-133143991123 rule_id=000C29A8-BA3B-0ed3-0000-000268444684```

##### Context Example
```
{
    "CiscoFP.Rule": {
        "Category": "--Undefined--", 
        "SourceZones": {
            "Objects": []
        }, 
        "DestinationZones": {
            "Objects": []
        }, 
        "DestinationNetworks": {
            "Objects": [], 
            "Addresses": []
        }, 
        "DestinationPorts": {
            "Objects": [], 
            "Addresses": []
        }, 
        "Section": "Default", 
        "Enabled": false, 
        "SourcePorts": {
            "Objects": [], 
            "Addresses": []
        }, 
        "RuleIndex": "", 
        "VlanTags": {
            "Objects": [], 
            "Numbers": []
        }, 
        "Applications": [], 
        "SourceSecurityGroupTags": {
            "Objects": []
        }, 
        "Urls": {
            "Objects": [], 
            "Addresses": []
        }, 
        "Action": "ALLOW", 
        "SourceNetworks": {
            "Objects": [], 
            "Addresses": []
        }, 
        "SendEventsToFMC": false, 
        "ID": "000C29A8-BA3B-0ed3-0000-000268444684", 
        "Name": "hgf"
    }
}
```

##### Human Readable Output
### Cisco Firepower - deleted access rule:
|ID|Name|Action|Enabled|SendEventsToFMC|RuleIndex|Section|Category|Urls|VlanTags|SourceZones|Applications|DestinationZones|SourceNetworks|DestinationNetworks|SourcePorts|DestinationPorts|SourceSecurityGroupTags|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 000C29A8-BA3B-0ed3-0000-000268444684 | hgf | ALLOW | false | false |  | Default | --Undefined-- | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |


### 29. ciscofp-list-policy-assignments
---
Retrieves a list of all policy assignments to target devices.

##### Base Command

`ciscofp-list-policy-assignments`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of items to return. The default is 50 | Optional | 
| offset | Index of first item to return. The default is 0 | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.PolicyAssignments.ID | String | The policy assignments ID. | 
| CiscoFP.PolicyAssignments.Name | String | The policy assignments name. | 
| CiscoFP.PolicyAssignments.PolicyDescription | String | The policy description. | 
| CiscoFP.PolicyAssignments.PolicyID | String | The policy ID. | 
| CiscoFP.PolicyAssignments.PolicyName | String | The policy name. | 
| CiscoFP.PolicyAssignments.Targets.ID | String | The targets ID. | 
| CiscoFP.PolicyAssignments.Targets.Name | String | The targets name. | 
| CiscoFP.PolicyAssignments.Targets.Type | String | The targets type. | 


##### Command Example
```!ciscofp-list-policy-assignments```

##### Context Example
```
{
    "CiscoFP.PolicyAssignments": [
        {
            "PolicyName": "BPS tst", 
            "PolicyDescription": "", 
            "ID": "000C29A8-BA3B-0ed3-0000-133143987627", 
            "PolicyID": "000C29A8-BA3B-0ed3-0000-133143987627", 
            "Targets": [
                {
                    "Type": "Device", 
                    "ID": "43e032dc-07c5-11ea-b83d-d5fdc079bf65", 
                    "Name": "FTD_10.8.49.209"
                }
            ], 
            "Name": "BPS tst"
        }
    ]
}
```

##### Human Readable Output
### Cisco Firepower - List of policy assignments:
|ID|Name|PolicyName|PolicyID|PolicyDescription|Targets|
|---|---|---|---|---|---|
| 000C29A8-BA3B-0ed3-0000-133143987627 | BPS tst | BPS tst | 000C29A8-BA3B-0ed3-0000-133143987627 |  | 1 |


### 30. ciscofp-create-policy-assignments
---
Creates policy assignments to target devices.

##### Base Command

`ciscofp-create-policy-assignments`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The policy ID. | Required | 
| device_ids | A list of device IDs. | Optional | 
| device_group_ids | A list of device group IDs. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.PolicyAssignments.ID | String | The policy assignments ID. | 
| CiscoFP.PolicyAssignments.Name | String | The policy assignments name. | 
| CiscoFP.PolicyAssignments.PolicyDescription | String | The policy description. | 
| CiscoFP.PolicyAssignments.PolicyID | String | The policy ID. | 
| CiscoFP.PolicyAssignments.PolicyName | String | The policy name. | 
| CiscoFP.PolicyAssignments.Targets.ID | String | The targets ID. | 
| CiscoFP.PolicyAssignments.Targets.Name | String | The targets name. | 
| CiscoFP.PolicyAssignments.Targets.Type | String | The targets type. | 


##### Command Example
```!ciscofp-create-policy-assignments policy_id=000C29A8-BA3B-0ed3-0000-085899346038```

##### Context Example
```
{
    "CiscoFP.PolicyAssignments": {
        "PolicyName": "Performance Test Policy without AMP", 
        "PolicyDescription": "", 
        "ID": "000C29A8-BA3B-0ed3-0000-085899346038", 
        "PolicyID": "000C29A8-BA3B-0ed3-0000-085899346038", 
        "Targets": [], 
        "Name": "Performance Test Policy without AMP"
    }
}
```

##### Human Readable Output
### Cisco Firepower - Policy assignments has been done.
|ID|Name|PolicyName|PolicyID|PolicyDescription|Targets|
|---|---|---|---|---|---|
| 000C29A8-BA3B-0ed3-0000-085899346038 | Performance Test Policy without AMP | Performance Test Policy without AMP | 000C29A8-BA3B-0ed3-0000-085899346038 |  | 0 |


### 31. ciscofp-update-policy-assignments
---
Updates the specified policy assignments to target devices.

##### Base Command

`ciscofp-update-policy-assignments`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The policy ID. | Optional | 
| device_ids | A list of device IDs. | Optional | 
| device_group_ids | A list of device group IDs. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.PolicyAssignments.ID | String | The policy assignments ID. | 
| CiscoFP.PolicyAssignments.Name | String | The policy assignments name. | 
| CiscoFP.PolicyAssignments.PolicyDescription | String | The policy description. | 
| CiscoFP.PolicyAssignments.PolicyID | String | The policy ID. | 
| CiscoFP.PolicyAssignments.PolicyName | String | The policy name. | 
| CiscoFP.PolicyAssignments.Targets.ID | String | The targets ID. | 
| CiscoFP.PolicyAssignments.Targets.Name | String | The targets name. | 
| CiscoFP.PolicyAssignments.Targets.Type | String | The targets type. | 


##### Command Example
```!ciscofp-update-policy-assignments policy_id=000C29A8-BA3B-0ed3-0000-085899346038```

##### Context Example
```
{
    "CiscoFP.PolicyAssignments": {
        "PolicyName": "Performance Test Policy without AMP", 
        "PolicyDescription": "", 
        "ID": "000C29A8-BA3B-0ed3-0000-085899346038", 
        "PolicyID": "000C29A8-BA3B-0ed3-0000-085899346038", 
        "Targets": [], 
        "Name": "Performance Test Policy without AMP"
    }
}
```

##### Human Readable Output
### Cisco Firepower - Policy assignments has been done.
|ID|Name|PolicyName|PolicyID|PolicyDescription|Targets|
|---|---|---|---|---|---|
| 000C29A8-BA3B-0ed3-0000-085899346038 | Performance Test Policy without AMP | Performance Test Policy without AMP | 000C29A8-BA3B-0ed3-0000-085899346038 |  | 0 |


### 32. ciscofp-get-deployable-devices
---
Retrieves a list of all devices with configuration changes that are ready to deploy.

##### Base Command

`ciscofp-get-deployable-devices`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of items to return. The default is 50. | Optional | 
| offset | Index of first item to return. The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.DeployableDevices.CanBeDeployed | String | Can be deployed. | 
| CiscoFP.DeployableDevices.UpToDate | String | Up to date. | 
| CiscoFP.DeployableDevices.DeviceID | String | Device ID. | 
| CiscoFP.DeployableDevices.DeviceName | String | Device name. | 
| CiscoFP.DeployableDevices.DeviceType | String | Device type. | 
| CiscoFP.DeployableDevices.Version | String | Device version. | 


##### Command Example
```!ciscofp-get-deployable-devices```

##### Context Example
```
{
    "CiscoFP.DeployableDevices": [
        {
            "DeviceName": "FTD_10.8.49.209", 
            "CanBeDeployed": true, 
            "UpToDate": false, 
            "Version": "1585679109082", 
            "DeviceType": "SENSOR", 
            "DeviceID": "43e032dc-07c5-11ea-b83d-d5fdc079bf65"
        }
    ]
}
```

##### Human Readable Output
### Cisco Firepower - List of deployable devices:
|CanBeDeployed|UpToDate|DeviceID|DeviceName|DeviceType|Version|
|---|---|---|---|---|---|
| true | false | 43e032dc-07c5-11ea-b83d-d5fdc079bf65 | FTD_10.8.49.209 | SENSOR | 1585679109082 |



### 33. ciscofp-get-device-records
---
Retrieves list of all device records.

##### Base Command

`ciscofp-get-device-records`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of items to return. The default is 50. | Optional | 
| offset | Index of first item to return. The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.DeviceRecords.DeviceGroupID | String | The device group ID. | 
| CiscoFP.DeviceRecords.HostName | String | The device host. | 
| CiscoFP.DeviceRecords.ID | String | The device ID. | 
| CiscoFP.DeviceRecords.Name | String | The device name. | 
| CiscoFP.DeviceRecords.Type | String | The device type. | 


##### Command Example
```!ciscofp-get-device-records```

##### Context Example
```
{
    "CiscoFP.DeviceRecords": [
        {
            "Name": "FTD_10.8.49.209", 
            "HostName": "10.8.49.209", 
            "Type": "Device", 
            "DeviceGroupID": "31b082e4-32c5-11ea-9d47-eda81976c864", 
            "ID": "43e032dc-07c5-11ea-b83d-d5fdc079bf65"
        }
    ]
}
```

##### Human Readable Output
### Cisco Firepower - List of device records:
|ID|Name|HostName|Type|DeviceGroupID|
|---|---|---|---|---|
| 43e032dc-07c5-11ea-b83d-d5fdc079bf65 | FTD_10.8.49.209 | 10.8.49.209 | Device | 31b082e4-32c5-11ea-9d47-eda81976c864 |


### 34. ciscofp-deploy-to-devices
---
Creates a request for deploying configuration changes to devices.

##### Base Command

`ciscofp-deploy-to-devices`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| force_deploy | Boolean indicating whether to force deployment. Can be "true" or "false". | Required | 
| ignore_warning | Boolean indicating whether to ignore warning. Can be "true" or "false". | Required | 
| device_ids | A list of device IDs. | Required | 
| version | The version to deploy. To get versions, use the ciscofp-get-deployable-devices command. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Deploy.TaskID | String | The task ID. | 
| CiscoFP.Deploy.ForceDeploy | String | Whether to force deploy. | 
| CiscoFP.Deploy.IgnoreWarning | String | Whether to ignore warning. | 
| CiscoFP.Deploy.Version | String | The version of the policy. | 
| CiscoFP.Deploy.DeviceList | String | The list of devices. | 


##### Command Example
```!ciscofp-deploy-to-devices device_ids=43e032dc-07c5-11ea-b83d-d5fdc079bf65 force_deploy=false ignore_warning=false version=1585679109082```

##### Context Example
```
{
    "CiscoFP.Deploy": {
        "DeviceList": [
            "43e032dc-07c5-11ea-b83d-d5fdc079bf65"
        ], 
        "ForceDeploy": false, 
        "Version": "1585679109082", 
        "TaskID": "133143991633", 
        "IgnoreWarning": false
    }
}
```

##### Human Readable Output
### Cisco Firepower - devices requests to deploy.
|TaskID|ForceDeploy|IgnoreWarning|Version|DeviceList|
|---|---|---|---|---|
| 133143991633 | false | false | 1585679109082 | 1 |


### 35. ciscofp-get-task-status
---
Retrieves information about a previously submitted pending job or task with the specified ID. Used for deploying.

##### Base Command

`ciscofp-get-task-status`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | The ID of the task for which to check the status. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.TaskStatus.Status | String | task status | 


##### Command Example
```!ciscofp-get-task-status task_id=133143991633```

##### Context Example
```
{
    "CiscoFP.TaskStatus": {
        "Status": "Deployed"
    }
}
```

##### Human Readable Output
### Cisco Firepower - 133143991633 status:
|Status|
|---|
| Deployed |
