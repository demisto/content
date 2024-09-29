Manages F5 LTM
This integration was integrated and tested with version 16.1.0 of F5LTM

## Configure F5 LTM in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server Address |  | True |
| Port Number |  | True |
| The administrative partition |  | False |
| Username | The Username to use for connection | True |
| Password |  | True |
| Trust any certificate (not secure) | Trust any certificate \(not secure\). | False |
| Use system proxy settings | Use system proxy settings. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### f5-ltm-get-pools
***
Get a list of all pools


#### Base Command

`f5-ltm-get-pools`
#### Input

| **Argument Name** | **Description** | **Required** |
|-------------------| --- | --- |
| expand            | Expand pools in the response. Possible values are: True, False. Default is False. | Optional | 
| partition         | The administrative partition. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| F5.LTM.Pools.membersReference.isSubcollection | Boolean | Member reference subcollection retrieved | 
| F5.LTM.Pools.membersReference.link | String | Member reference links | 
| F5.LTM.Pools.monitor | String | Pool monitor listener | 
| F5.LTM.Pools.name | String | Pool names | 
| F5.LTM.Pools.partition | String | Configuration partition | 


#### Command Example
```!f5-ltm-get-pools expand="false"```

#### Context Example
```json
{
    "F5": {
        "LTM": {
            "Pools": [
                {
                    "membersReference": {
                        "isSubcollection": true,
                        "link": "https://localhost/mgmt/tm/ltm/pool/~Common~Temp/members?ver=16.1.0"
                    },
                    "monitor": "/Common/https_443",
                    "name": "Temp",
                    "partition": "Common"
                },
                {
                    "membersReference": {
                        "isSubcollection": true,
                        "link": "https://localhost/mgmt/tm/ltm/pool/~Common~XSOAR/members?ver=16.1.0"
                    },
                    "monitor": "/Common/https_443",
                    "name": "XSOAR",
                    "partition": "Common"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|membersReference|monitor|name|partition|
>|---|---|---|---|
>| link: https://localhost/mgmt/tm/ltm/pool/~Common~Temp/members?ver=16.1.0<br/>isSubcollection: true | /Common/https_443 | Temp | Common |
>| link: https://localhost/mgmt/tm/ltm/pool/~Common~XSOAR/members?ver=16.1.0<br/>isSubcollection: true | /Common/https_443 | XSOAR | Common |


### f5-ltm-get-pool
***
Get pool details


#### Base Command

`f5-ltm-get-pool`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pool_name | Pool Name. | Required | 
| partition | The administrative partition. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| F5.LTM.Pools.allowNat | String | Pool Nat allowed | 
| F5.LTM.Pools.allowSnat | String | Pool SNat allowed | 
| F5.LTM.Pools.fullPath | String | Pool full path | 
| F5.LTM.Pools.generation | Number | Pool generation | 
| F5.LTM.Pools.ignorePersistedWeight | String | Ignore Persisted Weight status | 
| F5.LTM.Pools.ipTosToClient | String | Client pass through status | 
| F5.LTM.Pools.ipTosToServer | String | Server pass through status | 
| F5.LTM.Pools.kind | String | Pool kind | 
| F5.LTM.Pools.linkQosToClient | String | Link QOS to client status | 
| F5.LTM.Pools.linkQosToServer | String | Link QOS to server status | 
| F5.LTM.Pools.loadBalancingMode | String | Pool load balancing mode | 
| F5.LTM.Pools.membersReference.isSubcollection | Boolean | Members reference subcollection retrieved | 
| F5.LTM.Pools.membersReference.link | String | Members reference link | 
| F5.LTM.Pools.minActiveMembers | Number | Pool minimum active members | 
| F5.LTM.Pools.minUpMembers | Number | Pool minimum Up members | 
| F5.LTM.Pools.minUpMembersAction | String | Pool minimum Up members action | 
| F5.LTM.Pools.minUpMembersChecking | String | Pool minimum Up members checking | 
| F5.LTM.Pools.monitor | String | Pool monitor listener | 
| F5.LTM.Pools.name | String | Pool name | 
| F5.LTM.Pools.partition | String | Configuration partition | 
| F5.LTM.Pools.queueDepthLimit | Number | Pool depth limit | 
| F5.LTM.Pools.queueOnConnectionLimit | String | Pool depth queue on connection limit | 
| F5.LTM.Pools.queueTimeLimit | Number | Pool queue time limit | 
| F5.LTM.Pools.reselectTries | Number | Pool reselect tries | 
| F5.LTM.Pools.selfLink | String | Pool self link | 
| F5.LTM.Pools.serviceDownAction | String | Pool service down action | 
| F5.LTM.Pools.slowRampTime | Number | Pool slow ramp time | 


#### Command Example
```!f5-ltm-get-pool pool_name="XSOAR"```

#### Context Example
```json
{
    "F5": {
        "LTM": {
            "Pools": {
                "allowNat": "yes",
                "allowSnat": "yes",
                "fullPath": "/Common/XSOAR",
                "generation": 1,
                "ignorePersistedWeight": "disabled",
                "ipTosToClient": "pass-through",
                "ipTosToServer": "pass-through",
                "kind": "tm:ltm:pool:poolstate",
                "linkQosToClient": "pass-through",
                "linkQosToServer": "pass-through",
                "loadBalancingMode": "round-robin",
                "membersReference": {
                    "isSubcollection": true,
                    "link": "https://localhost/mgmt/tm/ltm/pool/~Common~XSOAR/members?ver=16.1.0"
                },
                "minActiveMembers": 0,
                "minUpMembers": 0,
                "minUpMembersAction": "failover",
                "minUpMembersChecking": "disabled",
                "monitor": "/Common/https_443",
                "name": "XSOAR",
                "partition": "Common",
                "queueDepthLimit": 0,
                "queueOnConnectionLimit": "disabled",
                "queueTimeLimit": 0,
                "reselectTries": 0,
                "selfLink": "https://localhost/mgmt/tm/ltm/pool/~Common~XSOAR?ver=16.1.0",
                "serviceDownAction": "none",
                "slowRampTime": 10
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|allowNat|allowSnat|fullPath|generation|ignorePersistedWeight|ipTosToClient|ipTosToServer|kind|linkQosToClient|linkQosToServer|loadBalancingMode|membersReference|minActiveMembers|minUpMembers|minUpMembersAction|minUpMembersChecking|monitor|name|partition|queueDepthLimit|queueOnConnectionLimit|queueTimeLimit|reselectTries|selfLink|serviceDownAction|slowRampTime|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| yes | yes | /Common/XSOAR | 1 | disabled | pass-through | pass-through | tm:ltm:pool:poolstate | pass-through | pass-through | round-robin | link: https://localhost/mgmt/tm/ltm/pool/~Common~XSOAR/members?ver=16.1.0<br/>isSubcollection: true | 0 | 0 | failover | disabled | /Common/https_443 | XSOAR | Common | 0 | disabled | 0 | 0 | https://localhost/mgmt/tm/ltm/pool/~Common~XSOAR?ver=16.1.0 | none | 10 |


### f5-ltm-get-pool-members
***
Get Pool Members


#### Base Command

`f5-ltm-get-pool-members`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pool_name | Pool Name. | Required | 
| partition | The administrative partition. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| F5.LTM.Pools.members.address | String | Pool member address | 
| F5.LTM.Pools.members.connectionLimit | Number | Pool member connection limit | 
| F5.LTM.Pools.members.dynamicRatio | Number | Pool member dynamic ratio | 
| F5.LTM.Pools.members.ephemeral | String | Pool member ephemeral | 
| F5.LTM.Pools.members.fqdn.autopopulate | String | Pool member fqdn autopopulate | 
| F5.LTM.Pools.members.fullPath | String | Pool member full path | 
| F5.LTM.Pools.members.generation | Number | Pool member generation | 
| F5.LTM.Pools.members.inheritProfile | String | Pool member inherit profile | 
| F5.LTM.Pools.members.kind | String | Pool member kind | 
| F5.LTM.Pools.members.logging | String | Pool member logging | 
| F5.LTM.Pools.members.monitor | String | Pool member monitor | 
| F5.LTM.Pools.members.name | String | Pool member name | 
| F5.LTM.Pools.members.partition | String | Pool member config partition | 
| F5.LTM.Pools.members.priorityGroup | Number | Pool member priority group | 
| F5.LTM.Pools.members.rateLimit | String | Pool member rate limit | 
| F5.LTM.Pools.members.ratio | Number | Pool member ratio | 
| F5.LTM.Pools.members.selfLink | String | Pool member self link | 
| F5.LTM.Pools.members.session | String | Pool member session | 
| F5.LTM.Pools.members.state | String | Pool member state | 


#### Command Example
```!f5-ltm-get-pool-members pool_name="XSOAR"```

#### Context Example
```json
{
    "F5": {
        "LTM": {
            "Pools": {
                "members": [
                    {
                        "address": "10.10.10.102",
                        "connectionLimit": 0,
                        "dynamicRatio": 1,
                        "ephemeral": "false",
                        "fqdn": {
                            "autopopulate": "disabled"
                        },
                        "fullPath": "/Common/XSOAR1:443",
                        "generation": 1,
                        "inheritProfile": "enabled",
                        "kind": "tm:ltm:pool:members:membersstate",
                        "logging": "disabled",
                        "monitor": "default",
                        "name": "XSOAR1:443",
                        "partition": "Common",
                        "priorityGroup": 0,
                        "rateLimit": "disabled",
                        "ratio": 1,
                        "selfLink": "https://localhost/mgmt/tm/ltm/pool/~Common~XSOAR/members/~Common~XSOAR1:443?ver=16.1.0",
                        "session": "monitor-enabled",
                        "state": "up"
                    },
                    {
                        "address": "1.1.1.1",
                        "connectionLimit": 0,
                        "dynamicRatio": 1,
                        "ephemeral": "false",
                        "fqdn": {
                            "autopopulate": "disabled"
                        },
                        "fullPath": "/Common/XSOAR2:443",
                        "generation": 1,
                        "inheritProfile": "enabled",
                        "kind": "tm:ltm:pool:members:membersstate",
                        "logging": "disabled",
                        "monitor": "default",
                        "name": "XSOAR2:443",
                        "partition": "Common",
                        "priorityGroup": 0,
                        "rateLimit": "disabled",
                        "ratio": 1,
                        "selfLink": "https://localhost/mgmt/tm/ltm/pool/~Common~XSOAR/members/~Common~XSOAR2:443?ver=16.1.0",
                        "session": "monitor-enabled",
                        "state": "up"
                    }
                ],
                "name": "XSOAR"
            }
        }
    }
}
```

#### Human Readable Output

>### Pool Members:
>|members|name|
>|---|---|
>| XSOAR1:443,<br/>XSOAR2:443 | XSOAR |


### f5-ltm-get-nodes
***
Get a list of all nodes
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| partition | The administrative partition. | Optional |


#### Base Command

`f5-ltm-get-nodes`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| F5.LTM.Nodes.address | String | Node address | 
| F5.LTM.Nodes.name | String | Node name | 
| F5.LTM.Nodes.partition | String | Configuration parition | 
| F5.LTM.Nodes.session | String | Node session status | 
| F5.LTM.Nodes.state | String | Node checking state | 


#### Command Example
```!f5-ltm-get-nodes```

#### Context Example
```json
{
    "F5": {
        "LTM": {
            "Nodes": [
                {
                    "address": "2.2.2.2",
                    "name": "Test",
                    "partition": "Common",
                    "session": "user-enabled",
                    "state": "unchecked"
                },
                {
                    "address": "10.10.10.102",
                    "name": "XSOAR1",
                    "partition": "Common",
                    "session": "user-enabled",
                    "state": "unchecked"
                },
                {
                    "address": "1.1.1.1",
                    "name": "XSOAR2",
                    "partition": "Common",
                    "session": "user-enabled",
                    "state": "unchecked"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|address|name|partition|session|state|
>|---|---|---|---|---|
>| 2.2.2.2 | Test | Common | user-enabled | unchecked |
>| 10.10.10.102 | XSOAR1 | Common | user-enabled | unchecked |
>| 1.1.1.1 | XSOAR2 | Common | user-enabled | unchecked |


### f5-ltm-get-node
***
Get node details


#### Base Command

`f5-ltm-get-node`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| node_name | Node Name. | Required | 
| partition | The administrative partition. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| F5.LTM.Nodes.address | String | Node address | 
| F5.LTM.Nodes.connectionLimit | Number | Pool node connection limit | 
| F5.LTM.Nodes.dynamicRatio | Number | Pool node dynamic ratio | 
| F5.LTM.Nodes.ephemeral | String | Pool node ephemeral | 
| F5.LTM.Nodes.fqdn.addressFamily | String | Pool node fqdn address family | 
| F5.LTM.Nodes.fqdn.autopopulate | String | Pool node fqdn autopopulate | 
| F5.LTM.Nodes.fqdn.downInterval | Number | Pool node fqdn down interval | 
| F5.LTM.Nodes.fqdn.interval | String | Pool node fqdn interval | 
| F5.LTM.Nodes.fullPath | String | Pool member full path | 
| F5.LTM.Nodes.generation | Number | Pool node generation | 
| F5.LTM.Nodes.kind | String | Pool node kind | 
| F5.LTM.Nodes.logging | String | Pool node logging status | 
| F5.LTM.Nodes.monitor | String | Pool node monitor listener | 
| F5.LTM.Nodes.name | String | Pool node name | 
| F5.LTM.Nodes.partition | String | Pool node configuration partition | 
| F5.LTM.Nodes.rateLimit | String | Pool node rate limit | 
| F5.LTM.Nodes.ratio | Number | Pool node ratio | 
| F5.LTM.Nodes.selfLink | String | Pool node self link | 
| F5.LTM.Nodes.session | String | Pool node session status | 
| F5.LTM.Nodes.state | String | Pool node checking state | 


#### Command Example
```!f5-ltm-get-node node_name="Test"```

#### Context Example
```json
{
    "F5": {
        "LTM": {
            "Nodes": {
                "address": "2.2.2.2",
                "connectionLimit": 0,
                "dynamicRatio": 1,
                "ephemeral": "false",
                "fqdn": {
                    "addressFamily": "ipv4",
                    "autopopulate": "disabled",
                    "downInterval": 5,
                    "interval": "3600"
                },
                "fullPath": "/Common/Test",
                "generation": 1,
                "kind": "tm:ltm:node:nodestate",
                "logging": "disabled",
                "monitor": "default",
                "name": "Test",
                "partition": "Common",
                "rateLimit": "disabled",
                "ratio": 1,
                "selfLink": "https://localhost/mgmt/tm/ltm/node/~Common~Test?ver=16.1.0",
                "session": "user-enabled",
                "state": "unchecked"
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|address|connectionLimit|dynamicRatio|ephemeral|fqdn|fullPath|generation|kind|logging|monitor|name|partition|rateLimit|ratio|selfLink|session|state|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2.2.2.2 | 0 | 1 | false | addressFamily: ipv4<br/>autopopulate: disabled<br/>downInterval: 5<br/>interval: 3600 | /Common/Test | 1 | tm:ltm:node:nodestate | disabled | default | Test | Common | disabled | 1 | https://localhost/mgmt/tm/ltm/node/~Common~Test?ver=16.1.0 | user-enabled | unchecked |


### f5-ltm-disable-node
***
Disable a node


#### Base Command

`f5-ltm-disable-node`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| node_name | Node to disable. | Required | 
| partition | The administrative partition. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| F5.LTM.Nodes.address | String | Node address | 
| F5.LTM.Nodes.connectionLimit | Number | Pool node connection limit | 
| F5.LTM.Nodes.dynamicRatio | Number | Pool node dynamic ratio | 
| F5.LTM.Nodes.ephemeral | String | Pool node ephemeral | 
| F5.LTM.Nodes.fqdn.addressFamily | String | Pool node fqdn address family | 
| F5.LTM.Nodes.fqdn.autopopulate | String | Pool node fqdn autopopulate | 
| F5.LTM.Nodes.fqdn.downInterval | Number | Pool node fqdn down interval | 
| F5.LTM.Nodes.fqdn.interval | String | Pool node fqdn interval | 
| F5.LTM.Nodes.fullPath | String | Pool member full path | 
| F5.LTM.Nodes.generation | Number | Pool node generation | 
| F5.LTM.Nodes.kind | String | Pool node kind | 
| F5.LTM.Nodes.logging | String | Pool node logging status | 
| F5.LTM.Nodes.monitor | String | Pool node monitor listener | 
| F5.LTM.Nodes.name | String | Pool node name | 
| F5.LTM.Nodes.partition | String | Pool node configuration partition | 
| F5.LTM.Nodes.rateLimit | String | Pool node rate limit | 
| F5.LTM.Nodes.ratio | Number | Pool node ratio | 
| F5.LTM.Nodes.selfLink | String | Pool node self link | 
| F5.LTM.Nodes.session | String | Pool node session status | 
| F5.LTM.Nodes.state | String | Pool node checking state | 


#### Command Example
```!f5-ltm-disable-node node_name="XSOAR1"```

#### Context Example
```json
{
    "F5": {
        "LTM": {
            "Nodes": {
                "address": "10.10.10.102",
                "connectionLimit": 0,
                "dynamicRatio": 1,
                "ephemeral": "false",
                "fqdn": {
                    "addressFamily": "ipv4",
                    "autopopulate": "disabled",
                    "downInterval": 5,
                    "interval": "3600"
                },
                "fullPath": "/Common/XSOAR1",
                "generation": 68,
                "kind": "tm:ltm:node:nodestate",
                "logging": "disabled",
                "monitor": "default",
                "name": "XSOAR1",
                "partition": "Common",
                "rateLimit": "disabled",
                "ratio": 1,
                "selfLink": "https://localhost/mgmt/tm/ltm/node/~Common~XSOAR1?ver=16.1.0",
                "session": "user-disabled",
                "state": "unchecked"
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|address|connectionLimit|dynamicRatio|ephemeral|fqdn|fullPath|generation|kind|logging|monitor|name|partition|rateLimit|ratio|selfLink|session|state|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 10.10.10.102 | 0 | 1 | false | addressFamily: ipv4<br/>autopopulate: disabled<br/>downInterval: 5<br/>interval: 3600 | /Common/XSOAR1 | 68 | tm:ltm:node:nodestate | disabled | default | XSOAR1 | Common | disabled | 1 | https://localhost/mgmt/tm/ltm/node/~Common~XSOAR1?ver=16.1.0 | user-disabled | unchecked |


### f5-ltm-enable-node
***
Enable a node


#### Base Command

`f5-ltm-enable-node`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| node_name | Node to enable. | Required | 
| partition | The administrative partition. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| F5.LTM.Nodes.address | String | Node address | 
| F5.LTM.Nodes.connectionLimit | Number | Pool node connection limit | 
| F5.LTM.Nodes.dynamicRatio | Number | Pool node dynamic ratio | 
| F5.LTM.Nodes.ephemeral | String | Pool node ephemeral | 
| F5.LTM.Nodes.fqdn.addressFamily | String | Pool node fqdn address family | 
| F5.LTM.Nodes.fqdn.autopopulate | String | Pool node fqdn autopopulate | 
| F5.LTM.Nodes.fqdn.downInterval | Number | Pool node fqdn down interval | 
| F5.LTM.Nodes.fqdn.interval | String | Pool node fqdn interval | 
| F5.LTM.Nodes.fullPath | String | Pool member full path | 
| F5.LTM.Nodes.generation | Number | Pool node generation | 
| F5.LTM.Nodes.kind | String | Pool node kind | 
| F5.LTM.Nodes.logging | String | Pool node logging status | 
| F5.LTM.Nodes.monitor | String | Pool node monitor listener | 
| F5.LTM.Nodes.name | String | Pool node name | 
| F5.LTM.Nodes.partition | String | Pool node configuration partition | 
| F5.LTM.Nodes.rateLimit | String | Pool node rate limit | 
| F5.LTM.Nodes.ratio | Number | Pool node ratio | 
| F5.LTM.Nodes.selfLink | String | Pool node self link | 
| F5.LTM.Nodes.session | String | Pool node session status | 
| F5.LTM.Nodes.state | String | Pool node checking state | 


#### Command Example
```!f5-ltm-enable-node node_name="XSOAR1"```

#### Context Example
```json
{
    "F5": {
        "LTM": {
            "Nodes": {
                "address": "10.10.10.102",
                "connectionLimit": 0,
                "dynamicRatio": 1,
                "ephemeral": "false",
                "fqdn": {
                    "addressFamily": "ipv4",
                    "autopopulate": "disabled",
                    "downInterval": 5,
                    "interval": "3600"
                },
                "fullPath": "/Common/XSOAR1",
                "generation": 67,
                "kind": "tm:ltm:node:nodestate",
                "logging": "disabled",
                "monitor": "default",
                "name": "XSOAR1",
                "partition": "Common",
                "rateLimit": "disabled",
                "ratio": 1,
                "selfLink": "https://localhost/mgmt/tm/ltm/node/~Common~XSOAR1?ver=16.1.0",
                "session": "user-enabled",
                "state": "unchecked"
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|address|connectionLimit|dynamicRatio|ephemeral|fqdn|fullPath|generation|kind|logging|monitor|name|partition|rateLimit|ratio|selfLink|session|state|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 10.10.10.102 | 0 | 1 | false | addressFamily: ipv4<br/>autopopulate: disabled<br/>downInterval: 5<br/>interval: 3600 | /Common/XSOAR1 | 67 | tm:ltm:node:nodestate | disabled | default | XSOAR1 | Common | disabled | 1 | https://localhost/mgmt/tm/ltm/node/~Common~XSOAR1?ver=16.1.0 | user-enabled | unchecked |


### f5-ltm-get-pool-member-stats
***
Get Pool Member Stats


#### Base Command

`f5-ltm-get-pool-member-stats`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pool_name | Pool to get its stats. | Required | 
| member_name | Member to get its stats. | Required | 
| partition | The administrative partition. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| F5.LTM.Stats.members.stats.serverside\.curConns.value | String | The current connections of the Pool Member | 
| F5.LTM.Stats.members.name | String | The pool member name | 
| F5.LTM.Stats.members.stats.sessionStatus.description | String | The pool member status | 


#### Command Example
```!f5-ltm-get-pool-member-stats pool_name="XSOAR" member_name="XSOAR1:443"```

#### Context Example
```json
{
    "F5": {
        "LTM": {
            "Stats": {
                "members": [
                    {
                        "name": "XSOAR1:443",
                        "stats": {
                            "addr": {
                                "description": "10.10.10.102"
                            },
                            "connq.ageEdm": {
                                "value": 0
                            },
                            "connq.ageEma": {
                                "value": 0
                            },
                            "connq.ageHead": {
                                "value": 0
                            },
                            "connq.ageMax": {
                                "value": 0
                            },
                            "connq.depth": {
                                "value": 0
                            },
                            "connq.serviced": {
                                "value": 0
                            },
                            "curSessions": {
                                "value": 0
                            },
                            "monitorRule": {
                                "description": "/Common/https_443 (pool monitor)"
                            },
                            "monitorStatus": {
                                "description": "up"
                            },
                            "mr.msgIn": {
                                "value": 0
                            },
                            "mr.msgOut": {
                                "value": 0
                            },
                            "mr.reqIn": {
                                "value": 0
                            },
                            "mr.reqOut": {
                                "value": 0
                            },
                            "mr.respIn": {
                                "value": 0
                            },
                            "mr.respOut": {
                                "value": 0
                            },
                            "nodeName": {
                                "description": "/Common/XSOAR1"
                            },
                            "poolName": {
                                "description": "/Common/XSOAR"
                            },
                            "port": {
                                "value": 443
                            },
                            "serverside.bitsIn": {
                                "value": 0
                            },
                            "serverside.bitsOut": {
                                "value": 0
                            },
                            "serverside.curConns": {
                                "value": 0
                            },
                            "serverside.maxConns": {
                                "value": 0
                            },
                            "serverside.pktsIn": {
                                "value": 0
                            },
                            "serverside.pktsOut": {
                                "value": 0
                            },
                            "serverside.totConns": {
                                "value": 0
                            },
                            "sessionStatus": {
                                "description": "enabled"
                            },
                            "status.availabilityState": {
                                "description": "available"
                            },
                            "status.enabledState": {
                                "description": "enabled"
                            },
                            "status.statusReason": {
                                "description": "Pool member is available"
                            },
                            "totRequests": {
                                "value": 0
                            }
                        }
                    }
                ],
                "pool": "XSOAR",
                "stats": {
                    "activeMemberCnt": {
                        "value": 2
                    },
                    "availableMemberCnt": {
                        "value": 2
                    },
                    "connq.ageEdm": {
                        "value": 0
                    },
                    "connq.ageEma": {
                        "value": 0
                    },
                    "connq.ageHead": {
                        "value": 0
                    },
                    "connq.ageMax": {
                        "value": 0
                    },
                    "connq.depth": {
                        "value": 0
                    },
                    "connq.serviced": {
                        "value": 0
                    },
                    "connqAll.ageEdm": {
                        "value": 0
                    },
                    "connqAll.ageEma": {
                        "value": 0
                    },
                    "connqAll.ageHead": {
                        "value": 0
                    },
                    "connqAll.ageMax": {
                        "value": 0
                    },
                    "connqAll.depth": {
                        "value": 0
                    },
                    "connqAll.serviced": {
                        "value": 0
                    },
                    "curPriogrp": {
                        "value": 0
                    },
                    "curSessions": {
                        "value": 0
                    },
                    "highestPriogrp": {
                        "value": 0
                    },
                    "lowestPriogrp": {
                        "value": 0
                    },
                    "memberCnt": {
                        "value": 2
                    },
                    "monitorRule": {
                        "description": "/Common/https_443"
                    },
                    "status.statusReason": {
                        "description": "The pool is available"
                    }
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Pool Member Stats:
>|curConns|member|pool|
>|---|---|---|
>| 0 | XSOAR1:443 | XSOAR |


### f5-ltm-get-node-stats
***
Get Node Stats


#### Base Command

`f5-ltm-get-node-stats`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| node_name | Node To Query. | Required | 
| partition | The administrative partition. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| F5.LTM.Nodes.stats.serverside\.curConns.value | String | The current connections of the Node | 
| F5.LTM.Nodes.name | String | The node name | 
| F5.LTM.Nodes.stats.sessionStatus.description | String | The node status | 


#### Command Example
```!f5-ltm-get-node-stats node_name="XSOAR1"```

#### Context Example
```json
{
    "F5": {
        "LTM": {
            "Nodes": {
                "name": "XSOAR1",
                "stats": {
                    "addr": {
                        "description": "10.10.10.102"
                    },
                    "curSessions": {
                        "value": 0
                    },
                    "monitorRule": {
                        "description": "none"
                    },
                    "monitorStatus": {
                        "description": "unchecked"
                    },
                    "serverside.bitsIn": {
                        "value": 0
                    },
                    "serverside.bitsOut": {
                        "value": 0
                    },
                    "serverside.curConns": {
                        "value": 0
                    },
                    "serverside.maxConns": {
                        "value": 0
                    },
                    "serverside.pktsIn": {
                        "value": 0
                    },
                    "serverside.pktsOut": {
                        "value": 0
                    },
                    "serverside.totConns": {
                        "value": 0
                    },
                    "sessionStatus": {
                        "description": "enabled"
                    },
                    "status.availabilityState": {
                        "description": "unknown"
                    },
                    "status.enabledState": {
                        "description": "enabled"
                    },
                    "status.statusReason": {
                        "description": "Node address does not have service checking enabled"
                    },
                    "tmName": {
                        "description": "/Common/XSOAR1"
                    },
                    "totRequests": {
                        "value": 0
                    }
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Node Stats:
>|curConns|node|
>|---|---|
>| 0 | XSOAR1 |


### f5-ltm-get-node-by-address
***
Get node information by address


#### Base Command

`f5-ltm-get-node-by-address`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | IP address of the node. | Required | 
| partition | The administrative partition. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| F5.LTM.Nodes.name | String | The node name | 
| F5.LTM.Nodes.address | String | The node address | 


#### Command Example
```!f5-ltm-get-node-by-address ip_address="10.10.10.102"```

#### Context Example
```json
{
    "F5": {
        "LTM": {
            "Nodes": {
                "address": "10.10.10.102",
                "name": "XSOAR1",
                "partition": "Common",
                "session": "user-enabled",
                "state": "unchecked"
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|address|name|partition|session|state|
>|---|---|---|---|---|
>| 10.10.10.102 | XSOAR1 | Common | user-enabled | unchecked |


### f5-ltm-get-pool-by-node
***
Get pool information by node


#### Base Command

`f5-ltm-get-pool-by-node`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| node_name | Node name. | Required | 
| partition | The administrative partition. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| F5.LTM.Nodes.pools | String | The pool names | 
| F5.LTM.Nodes.name | String | The node name | 


#### Command Example
```!f5-ltm-get-pool-by-node node_name="XSOAR1"```

#### Context Example
```json
{
    "F5": {
        "LTM": {
            "Nodes": {
                "name": "XSOAR1",
                "pools": [
                    "XSOAR"
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|name|pools|
>|---|---|
>| XSOAR1 | XSOAR |
