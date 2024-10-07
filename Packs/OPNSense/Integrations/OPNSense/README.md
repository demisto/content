Manage OPNsense Firewall. 
For more information see OPNsense documentation.
OPNsense is an open source, easy-to-use and easy-to-build HardenedBSD based firewall and routing platform.
This integration was integrated and tested with version 22.1 of OPNSense

## Configure OPNSense in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. https://opnsense.mydomain.ltd) | True |
| API Key | True |
| API Secret | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### opnsense-alias-list
***
Get aliases list


#### Base Command

`opnsense-alias-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Alias | unknown | Aliases list | 

### opnsense-alias-add
***
Create new alias


#### Base Command

`opnsense-alias-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Alias name. | Required | 
| type | Alias type. Possible values are: host, network, port, url, urltable, geoip, networkgroup, mac, external, dynipv6host. | Required | 
| enabled | Alias enabled. Possible values are: 1, 0. Default is 1. | Optional | 
| proto | Alias protocol. Possible values are: inet, inet6. | Optional | 
| updatefreq | Alias update frequency. | Optional | 
| counters | Alias statistics. Possible values are: 0, 1. | Optional | 
| description | Alias description. | Optional | 
| content | Alias content. | Optional | 
| auto_commit | Apply automaticly aliases changes. Possible values are: False, True. Default is False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Alias | unknown | Alias UUID created | 

### opnsense-alias-del
***
Delete alias with uuid


#### Base Command

`opnsense-alias-del`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Alias UUID. | Required | 
| auto_commit | Apply automaticly aliases changes. Possible values are: False, True. Default is False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Alias | unknown | Alias UUID deleted | 

### opnsense-alias-mod
***
Modify an existing alias


#### Base Command

`opnsense-alias-mod`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Alias UUID. | Required | 
| content | Alias content seperated by comma (NB. will replace actual content!). | Required | 
| name | Alias name. | Optional | 
| type | Alias type. Possible values are: host, network, port, url, urltable, geoip, networkgroup, mac, external, dynipv6host. | Optional | 
| proto | Alias protocol. Possible values are: inet, inet6. | Optional | 
| enabled | Alias enabled. Possible values are: 0, 1. | Optional | 
| updatefreq | Alias update frequency. | Optional | 
| counters | Alias statistics. Possible values are: 0, 1. | Optional | 
| description | Alias description. | Optional | 
| auto_commit | Apply automaticly aliases changes. Possible values are: False, True. Default is False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Alias | unknown | Alias UUID modified | 

### opnsense-alias-mod-additem
***
Add item into existing alias


#### Base Command

`opnsense-alias-mod-additem`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Alias name. | Required | 
| entry | Entry to add. | Optional | 
| auto_commit | Apply automaticly aliases changes. Possible values are: False, True. Default is False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Alias | unknown | Alias UUID modified | 

### opnsense-alias-mod-delitem
***
Del item into existing alias


#### Base Command

`opnsense-alias-mod-delitem`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Alias name. | Required | 
| entry | Entry to remove. | Optional | 
| auto_commit | Apply automaticly aliases changes. Possible values are: False, True. Default is False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Alias | unknown | Alias UUID modified | 

### opnsense-alias-get
***
Get alias details


#### Base Command

`opnsense-alias-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Alias UUID. | Optional | 
| name | Alias name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Alias | Unknown | Alias details | 
| OPNSense.Alias.name | Unknown | Alias name | 
| OPNSense.Alias.content | Unknown | Alias content | 
| OPNSense.Alias.description | Unknown | Alias description | 
| OPNSense.Alias.enabled | Unknown | Alias enabled | 

### opnsense-alias-get-uuid
***
Get alias UUID


#### Base Command

`opnsense-alias-get-uuid`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Alias name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Alias | Unknown | Alias UUID | 

### opnsense-interfaces-list
***
Get interfaces list


#### Base Command

`opnsense-interfaces-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Interfaces | Unknown | Interfaces list | 

### opnsense-category-list
***
Get categories list


#### Base Command

`opnsense-category-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Category | Unknown | Categories list | 

### opnsense-category-add
***
Create new category


#### Base Command

`opnsense-category-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Category name. | Required | 
| auto | Automatically added, will be removed when unused. Possible values are: 0, 1. | Optional | 
| color | Category color (format : #YVWXYZ). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Category | Unknown | Category UUID | 

### opnsense-category-del
***
Delete category with uuid


#### Base Command

`opnsense-category-del`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Category UUID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Category | Unknown | Category UUID | 

### opnsense-category-get
***
Get category details


#### Base Command

`opnsense-category-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Category UUID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Category | Unknown | Category details | 

### opnsense-category-mod
***
Modify an axisting category


#### Base Command

`opnsense-category-mod`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Category UUID. | Required | 
| name | Category name. | Optional | 
| color | Category color (format : #YVWXYZ). | Optional | 
| auto | Automatically added, will be removed when unused. Possible values are: 0, 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| cef2c7d7-68d8-41aa-b6b8-1cac38554d58 | Unknown | Category UUID | 

### opnsense-rule-list
***
Get rules list


#### Base Command

`opnsense-rule-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Rule | Unknown | Rules list | 

### opnsense-rule-get
***
Get rule details


#### Base Command

`opnsense-rule-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Rule UUID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Rule | Unknown | Rule details | 
| OPNSense.Rule.description | Unknown | Rule description | 
| OPNSense.Rule.enabled | Unknown | Rule enabled | 
| OPNSense.Rule.source_net | Unknown | Source NET's rule | 
| OPNSense.Rule.destination_net | Unknown | Destination NET's rule | 
| OPNSense.Rule.interface | Unknown | Interface's rule | 

### opnsense-alias-apply
***
Apply configuration


#### Base Command

`opnsense-alias-apply`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### opnsense-device-reboot
***
Reboot the device


#### Base Command

`opnsense-device-reboot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Device | Unknown | Reboot status | 

### opnsense-firmware-info
***
Get firmware info


#### Base Command

`opnsense-firmware-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Firmware | Unknown | Firmware info | 

### opnsense-firmware-status
***
Get firmware status


#### Base Command

`opnsense-firmware-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Firmware | Unknown | Firmware status | 

### opnsense-firmware-upgradestatus
***
Get firmware upgrade status


#### Base Command

`opnsense-firmware-upgradestatus`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Firmware | Unknown | Firmware upgrade status | 

### opnsense-firmware-update
***
Do firmware update


#### Base Command

`opnsense-firmware-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Firmware | Unknown | Firmware update | 

### opnsense-firmware-upgrade
***
Do firmware upgrade


#### Base Command

`opnsense-firmware-upgrade`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Firmware | Unknown | Firmware upgrade | 

### opnsense-rule-del
***
Delete an existing rule


#### Base Command

`opnsense-rule-del`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Rule UUID. | Required | 
| auto_commit | Apply automaticly aliases changes. Possible values are: None, True. Default is None. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Rule | Unknown | Rule UUID | 

### opnsense-rule-add
***
Create a new rule


#### Base Command

`opnsense-rule-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Rule action. Possible values are: pass, block, reject. Default is pass. | Optional | 
| enabled | Rule enabled. Possible values are: 1, 0. Default is 1. | Optional | 
| quick | Rule quick. Possible values are: 1, 0. Default is 1. | Optional | 
| interface | Rule interface. | Optional | 
| direction | Rule direction. Possible values are: in, out. Default is in. | Optional | 
| ipprotocol | Rule IP Protocol. Possible values are: inet, inet6. Default is inet. | Optional | 
| protocol | Rule protocol. Possible values are: any, ICMP, IGMP, GGP, IPENCAP, ST2, TCP, CBT, EGP, IGP, BBN-RCC, NVP, PUP, ARGUS, EMCON, XNET, CHAOS, UDP, MUX, DCN, HMP, PRM, XNS-IDP, TRUNK-1, TRUNK-2, LEAF-1, LEAF-2, RDP, ISO-TP4, NETBLT, MFE-NSP, MERIT-INP, DCCP, 3PC, IDPR, XTP, DDP, IDPR-CMTP, TP++, IL, IPV6, SDRP, IDRP, RSVP, GRE, DSR, BNA, ESP, AH, I-NLSP, SWIPE, NARP, MOBILE, TLSP, SKIP, IPV6-ICMP, CFTP, SAT-EXPAK, KRYPTOLAN, RVD, IPPC, SAT-MON, VISA, IPCV, CPNX, CPHB, WSN, PVP, BR-SAT-MON, SUN-ND, WB-MON, WB-EXPAK, ISO-IP, VMTP, SECURE-VMTP, VINES, TTP, NSFNET-IGP, DGP, TCF, EIGRP, OSPF, SPRITE-RPC, LARP, MTP, AX.25, IPIP, MICP, SCC-SP, ETHERIP, ENCAP, GMTP, IFMP, PNNI, PIM, ARIS, SCPS, QNX, A/N, IPCOMP, SNP, COMPAQ-PEER, IPX-IN-IP, CARP, PGM, L2TP, DDX, IATP, STP, SRP, UTI, SMP, SM, PTP, ISIS, CRTP, CRUDP, SPS, PIPE, SCTP, FC, RSVP-E2E-IGNORE, UDPLITE, MPLS-IN-IP, MANET, HIP, SHIM6, WESP, ROHC, PFSYNC, DIVERT. Default is any. | Optional | 
| source_net | Source Net. Default is any. | Optional | 
| source_not | Source NOT. Possible values are: 0, 1. Default is 0. | Optional | 
| source_port | Source port. | Optional | 
| destination_net | Destination Net. Default is any. | Optional | 
| destination_not | Destination NOT. Possible values are: 0, 1. Default is 0. | Optional | 
| destination_port | Destination port. | Optional | 
| log | Enable logging. Possible values are: 0, 1. Default is 0. | Optional | 
| sequence | Provide a valid sequence for sorting (1 - 99999). Default is 1. | Optional | 
| description | Rule description. | Optional | 
| auto_commit | Apply automaticly aliases changes. Possible values are: None, True. Default is None. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Rule | Unknown | Rule UUID | 

### opnsense-rule-mod
***
Modify an existing rule


#### Base Command

`opnsense-rule-mod`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Rule UUID. | Required | 
| action | Rule action. Possible values are: pass, block, reject. Default is pass. | Optional | 
| enabled | Rule enabled. Possible values are: 1, 0. Default is 1. | Optional | 
| quick | Rule quick. Possible values are: 1, 0. Default is 1. | Optional | 
| interface | Rule interface. | Optional | 
| direction | Rule description. Possible values are: in, out. Default is in. | Optional | 
| ipprotocol | Rule IP protocol. Possible values are: inet, inet6. Default is inet. | Optional | 
| protocol | Rule protocol. Possible values are: any, ICMP, IGMP, GGP, IPENCAP, ST2, TCP, CBT, EGP, IGP, BBN-RCC, NVP, PUP, ARGUS, EMCON, XNET, CHAOS, UDP, MUX, DCN, HMP, PRM, XNS-IDP, TRUNK-1, TRUNK-2, LEAF-1, LEAF-2, RDP, ISO-TP4, NETBLT, MFE-NSP, MERIT-INP, DCCP, 3PC, IDPR, XTP, DDP, IDPR-CMTP, TP++, IL, IPV6, SDRP, IDRP, RSVP, GRE, DSR, BNA, ESP, AH, I-NLSP, SWIPE, NARP, MOBILE, TLSP, SKIP, IPV6-ICMP, CFTP, SAT-EXPAK, KRYPTOLAN, RVD, IPPC, SAT-MON, VISA, IPCV, CPNX, CPHB, WSN, PVP, BR-SAT-MON, SUN-ND, WB-MON, WB-EXPAK, ISO-IP, VMTP, SECURE-VMTP, VINES, TTP, NSFNET-IGP, DGP, TCF, EIGRP, OSPF, SPRITE-RPC, LARP, MTP, AX.25, IPIP, MICP, SCC-SP, ETHERIP, ENCAP, GMTP, IFMP, PNNI, PIM, ARIS, SCPS, QNX, A/N, IPCOMP, SNP, COMPAQ-PEER, IPX-IN-IP, CARP, PGM, L2TP, DDX, IATP, STP, SRP, UTI, SMP, SM, PTP, ISIS, CRTP, CRUDP, SPS, PIPE, SCTP, FC, RSVP-E2E-IGNORE, UDPLITE, MPLS-IN-IP, MANET, HIP, SHIM6, WESP, ROHC, PFSYNC, DIVERT. | Optional | 
| source_net | Source Net. | Optional | 
| source_not | Source NOT. Possible values are: 0, 1. Default is 0. | Optional | 
| source_port | Source port. | Optional | 
| destination_net | Destination Net. | Optional | 
| destination_not | Destination NOT. | Optional | 
| destination_port | Destination port. | Optional | 
| log | Enable log. Possible values are: 0, 1. Default is 0. | Optional | 
| description | Rule description. | Optional | 
| auto_commit | Apply automaticly aliases changes. Possible values are: None, True. Default is None. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Rule | Unknown | Rule UUID | 

### opnsense-rule-apply
***
Apply rules current configuration


#### Base Command

`opnsense-rule-apply`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rollback_revision | Rollback revision. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Rule | Unknown | Action status | 

### opnsense-rule-savepoint
***
Save rules current configuration


#### Base Command

`opnsense-rule-savepoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Rule | Unknown | Action status | 

### opnsense-logs-search
***
Search into firewall logs


#### Base Command

`opnsense-logs-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Log search limit. Default is 1000. | Optional | 
| ip | Search IP in src or dst. | Optional | 
| interface | Interface search filter. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.Logs | Unknown | OPNSense logs | 
| OPNSense.Logs.interface | Unknown | interface in logs | 
| OPNSense.Logs.src | Unknown | SRC in logs | 
| OPNSense.Logs.srcport | Unknown | SRCPORT in logs | 
| OPNSense.Logs.dst | Unknown | DST in logs | 
| OPNSense.Logs.dstport | Unknown | DSTPORT in logs | 
| OPNSense.Logs.action | Unknown | Action in logs | 
| OPNSense.Logs.__timestamp__ | Unknown | timestamp in logs | 
| OPNSense.Logs.label | Unknown | label in logs | 
| OPNSense.Logs.protoname | Unknown | protoname in logs | 

### opnsense-states-search
***
Query states


#### Base Command

`opnsense-states-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Search IP in src or dst. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPNSense.States | Unknown | OPNSense States | 
| OPNSense.States.label | Unknown | label in states | 
| OPNSense.States.descr | Unknown | states description | 
| OPNSense.States.nat_addr | Unknown | nat address in states | 
| OPNSense.States.nat_port | Unknown | nat port in states | 
| OPNSense.States.iface | Unknown | interface in states | 
| OPNSense.States.ipproto | Unknown | IP Protocol in states | 
| OPNSense.States.proto | Unknown | Protocol in states | 

### opnsense-state-del
***
Delete state with ID


#### Base Command

`opnsense-state-del`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| state_id | State ID. | Optional | 


#### Context Output

There is no context output for this command.
### opnsense-rule-revert
***
Revert config to given savepoint


#### Base Command

`opnsense-rule-revert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rollback_revision | Rollback revision. | Optional | 


#### Context Output

There is no context output for this command.