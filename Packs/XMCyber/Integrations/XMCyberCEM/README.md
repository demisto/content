The XM Cyber integration connects XM Cyber's Continuous Exposure Management (CEM) platform with XSOAR, enhancing your Security Information and Event Management (SIEM) and Security Orchestration, Automation, and Response processes with attack graph context and prioritization, while also feeding relevant entities back to CEM to be defined as breach points in CEM scenarios.

## Configure XM Cyber CEM in Cortex

1. Navigate to Settings > Integrations > Servers & Services.
2. Search for XM Cyber CEM.
3. Click Add instance to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The server URL of the XM Cyber instance. | True |
| API Key | The API Key using which the API calls would be made to the XM Cyber instance. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

4. Click Test to validate the URL, API Key, and connection.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### xmcyber-enrich-incident

***
Enriches Hostname and User entities on the SOAR platform by using information available in the XM Cyber platform.

#### Base Command

`xmcyber-enrich-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_values | Specify the Hostname or User to enrich. Supports comma-separated values. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XMCyber.Entity.id | String | The unique identifier of the entity. |
| XMCyber.Entity.collectedAt | Date | The timestamp when the entity data was collected. |
| XMCyber.Entity.name | String | The name of the entity. |
| XMCyber.Entity.os.name | String | The operating system name of the agent entity. |
| XMCyber.Entity.osType | String | The operating system type (Windows, Linux, etc.). |
| XMCyber.Entity.type | String | The type of the entity (agent, activeDirectoryUser, etc.). |
| XMCyber.Entity.xmLabels.id | String | The labels assigned to the entity by XM Cyber. |
| XMCyber.Entity.affectedUniqueEntities | Number | The number of unique entities affected by this entity. |
| XMCyber.Entity.chokePointScore | Number | The choke point score of the entity. |
| XMCyber.Entity.displayName | String | The display name of the Active Directory user entity. |
| XMCyber.Entity.domainName | String | The domain name of the Active Directory user entity. |
| XMCyber.Entity.isEnabled | Boolean | Indicates if the Active Directory user account is enabled. |
| XMCyber.Entity.lastLogon | Date | The last logon timestamp of the Active Directory user. |
| XMCyber.Entity.pwdLastSet | Date | The timestamp when the password was last set for the Active Directory user. |
| XMCyber.Entity.riskScore | Number | The risk score of the entity. |
| XMCyber.Entity.sid | String | The Security Identifier (SID) of the Active Directory user entity. |
| XMCyber.Entity.account_type | String | The account type of the entity. |
| XMCyber.Entity.chokePointScoreLevel | String | The choke point score level of the entity. |
| XMCyber.Entity.importedLabels | String | The imported labels assigned to the entity. |
| XMCyber.Entity.riskScoreLevel | String | The risk score level of the entity. |

#### Command example

```!xmcyber-enrich-incident entity_values="hostname_1,user_1"```

#### Context Example

```json
{
    "XMCyber": {
        "Entity": [
            {
                "id": "activeDirectoryUser-0000000000000000001",
                "affectedUniqueEntities": 0,
                "chokePointScore": 29,
                "collectedAt": "2025-12-04T00:00:00.630Z",
                "displayName": "test.com\\user_1",
                "domainName": "test.com",
                "isEnabled": true,
                "lastLogon": "2025-12-03T10:30:00.000Z",
                "name": "user_1",
                "pwdLastSet": "2024-06-15T08:20:00.000Z",
                "riskScore": 88,
                "sid": "S-1-5-21-1234567890-1234567890-1234567890-1001",
                "type": "activeDirectoryUser",
                "chokePointScoreLevel": "MEDIUM",
                "riskScoreLevel": "HIGH",
                "xmLabels": [
                    {
                        "id": "AD Admins And DCs"
                    },
                    {
                        "id": "AD Tier0"
                    }
                ]
            },
            {
                "id": "0000000000000000002",
                "affectedUniqueEntities": 5,
                "chokePointScore": 75,
                "collectedAt": "2025-12-04T00:00:00.630Z",
                "name": "hostname_1",
                "os": {
                    "name": "Windows Server 2019 (DC)"
                },
                "osType": "Windows",
                "riskScore": 92,
                "type": "agent",
                "chokePointScoreLevel": "HIGH",
                "riskScoreLevel": "CRITICAL",
                "xmLabels": [
                    {
                        "id": "Windows Server"
                    },
                    {
                        "id": "Domain Controller"
                    },
                    {
                        "id": "Public IP"
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Entity Information
>
>|ID|Name|Type|Compromise Risk Score|Choke Point Score|Labels|Affected Unique Entities|Enabled|Display Name|Domain Name|Last Logon Date|Last Password Set Date|OS Type|OS Name|SID|Collected At|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| activeDirectoryUser-0000000000000000001 | user_1 | activeDirectoryUser | HIGH (88) | MEDIUM (29) | AD Admins And DCs, AD Tier0 | 0 | true | test.com\user_1 | test.com | 2025-12-03T10:30:00.000Z | 2025-11-15T08:20:00.000Z |  |  | S-1-5-21-1234567890-1234567890-1234567890-1001 | 2025-12-04T00:00:00.630Z |
>| 0000000000000000002 | hostname_1 | agent | CRITICAL (92) | HIGH (75) | Windows Server, Domain Controller, Public IP | 5 |  |  |  |  |  | Windows | Windows Server 2019 (DC) |  | 2025-12-04T00:00:00.630Z |

### xmcyber-push-breach-point

***
Adds a breach point label to the specified entities based on defined criteria and pushes the label as an Imported Attribute to XM Cyber CEM's platform.

#### Base Command

`xmcyber-push-breach-point`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_values | Specify the Hostname or User to label with the breach point. Supports comma-separated values. | Required |
| attribute_name | The name of the custom label you want to push to CEM as an imported attribute. Default is XSOAR_BP. | Optional |
| parameter | When setting up the condition for when to push the breach point data, this is the parameter of the condition. It is a list of predefined parameters for determining the criteria. Select 'All' to apply the breach point label to all entities. Possible values are: All, Entity ID, Affected Unique Entities, Compromise Risk Score, Choke Point Score, Labels, Domain Name, Is Enabled, Last Login Date, Last Password Set Date. Default is All. | Optional |
| operator | When setting up the condition for when to push the breach point data, this is the operator of the condition. Possible values are: Less than, Greater than, Less than equal to, Greater than equal to, Equals, Not equal to, Contains, Not Contains. Default is Equals. | Optional |
| value | When setting up the condition for when to push the breach point data, this is the value of the condition. Can be boolean, string, integer, float, or date values.<br/><br/>Supported date formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 Dec 2025, 01 Dec 2025 04:45:33, 2025-12-10T14:05:44Z. Default is True. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XMCyber.BreachPoint.attributeName | String | The name of the attribute that was applied to the XM Cyber entities. |
| XMCyber.BreachPoint.matchedEntities | String | The entities that matched the criteria. |
| XMCyber.BreachPoint.notMatchedEntities | String | The entities that did not match the criteria. |
| XMCyber.BreachPoint.parameter | String | The entity parameter used to filter entities. |
| XMCyber.BreachPoint.operator | String | The comparison operator used to match entity values. |
| XMCyber.BreachPoint.value | String | The value used to match against entity properties. |
| XMCyber.BreachPoint.userSuppliedEntities | String | The entities that were provided by the user. |

#### Command example

!xmcyber-push-breach-point entity_values="user1,hostname1,user2" attribute_name="XSOAR_BP" parameter="Compromise Risk Score" operator="Greater than" value="30"

#### Context Example

```json
{
    "XMCyber": {
        "BreachPoint": {
            "attributeName": "XSOAR_BP",
            "matchedEntities": "hostname1,user1",
            "notMatchedEntities": "user2",
            "operator": "Greater than",
            "parameter": "Compromise Risk Score",
            "value": "30",
            "userSuppliedEntities": "user1,hostname1,user2"
        }
    }
}
```

#### Human Readable Output

>### Successfully pushed the attribute 'XSOAR_BP' for the following entities
>
>user1, hostname1

### xmcyber-remove-breach-point

***
Removes a breach point label from the specified entities in XM Cyber CEM's platform.

#### Base Command

`xmcyber-remove-breach-point`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_values | Specify the Hostname or User to remove a breach point label. Supports comma-separated values. | Required |
| attribute_name | The name of the custom label you want to remove from CEM as an imported attribute. Default is XSOAR_BP. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XMCyber.RemoveBreachPoint.attributeName | String | The name of the attribute that was removed from the XM Cyber entities. |
| XMCyber.RemoveBreachPoint.removedLabelEntities | String | The entities from which the label was successfully removed. |
| XMCyber.RemoveBreachPoint.userSuppliedEntities | String | The entities that were provided by the user. |

#### Command example

!xmcyber-remove-breach-point entity_values="user1,hostname1" attribute_name="XSOAR_BP"

#### Context Example

```json
{
    "XMCyber": {
        "RemoveBreachPoint": {
            "attributeName": "XSOAR_BP",
            "removedLabelEntities": "hostname1,user1",
            "userSuppliedEntities": "user1,hostname1"
        }
    }
}
```

#### Human Readable Output

>### Successfully removed the attribute 'XSOAR_BP' from the following entities
>
>user1, hostname1

### xmcyber-calculate-risk-score

***
Calculates the overall risk score for entities based on their Compromise Risk Score and Choke Point Score from XM Cyber enrichment data.

#### Base Command

`xmcyber-calculate-risk-score`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_values | Specify the Hostname or User to calculate the risk score. Supports comma-separated values. | Required |
| compromise_risk_score | Specify the weight of Compromise Risk Score to apply to the final score calculation. Provide the value between 0 and 1. Default is 0.5. | Optional |
| choke_point_score | Specify the weight of Choke Point Score to apply to the final score calculation. Provide the value between 0 and 1. Default is 0.5. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XMCyber.CalculateRiskScore.entities | String | The entity values that were evaluated. |
| XMCyber.CalculateRiskScore.compromisedRiskScoreLevel | String | The risk level based on the highest Compromise Risk Score found. |
| XMCyber.CalculateRiskScore.compromisedRiskScore | Number | The highest Compromise Risk Score found across all evaluated entities. |
| XMCyber.CalculateRiskScore.compromisedChokePointScoreLevel | String | The risk level based on the highest Choke Point Score found. |
| XMCyber.CalculateRiskScore.compromisedChokePointScore | Number | The highest Choke Point Score found across all evaluated entities. |
| XMCyber.CalculateRiskScore.calculatedRiskScore | Number | The final calculated risk score based on weighted combination of Compromise Risk Score and Choke Point Score. |

#### Command example

!xmcyber-calculate-risk-score entity_values="user1,hostname1"

#### Context Example

```json
{
    "XMCyber": {
        "CalculateRiskScore": {
            "entities": "hostname_1, user_1, user_2",
            "compromisedRiskScore": 95,
            "compromisedRiskScoreLevel": "CRITICAL",
            "compromisedChokePointScore": 85,
            "compromisedChokePointScoreLevel": "CRITICAL",
            "calculatedRiskScore": 100
        }
    }
}
```

#### Human Readable Output

>### Risk Score Calculation Results
>
>|Calculated Risk Score|Compromised Risk Score Level|Compromised Risk Score|Compromised Choke Point Level|Compromised Choke Point Score|
>|---|---|---|---|---|
>| 100 | CRITICAL | 95 | CRITICAL | 85 |
