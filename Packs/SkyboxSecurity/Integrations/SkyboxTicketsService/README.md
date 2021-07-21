Skybox® Change Manager workflows for firewall rule creation, recertification and deprovisioning help maintain continuous compliance, close security gaps and limit vulnerability exposures.
This integration was integrated and tested with version xx of SkyboxTicketsService

For more information please refer to the Skybox Developer Guide located at https://downloads.skyboxsecurity.com/files/Installers/Skybox_View/latestDocs/Skybox_DevelopersGuide_V11_4_100.pdf

## Configure SkyboxTicketsService on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SkyboxTicketsService.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | Username | False |
    | Password | False |
    | Trust any certificate (not secure) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### skybox-getTicketWorkflow
***
Retrieves the list of ticket workflows in Skybox,
including an ID and a name for each ticket.


#### Base Command

`skybox-getTicketWorkflow`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ticket ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getTicketWorkflow | String | The ticket workflow | 


#### Command Example
```!skybox-getTicketWorkflow ticketId=434```

#### Context Example
```json
{
    "Skybox": {
        "getTicketWorkflow": {
            "id": 1,
            "name": "General"
        }
    }
}
```

#### Human Readable Output

>### Results
>|id|name|
>|---|---|
>| 1 | General |


### skybox-getOriginalChangeRequestRouteInfoV1
***
Retrieves the route information from an original
change request.


#### Base Command

`skybox-getOriginalChangeRequestRouteInfoV1`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ID of the ticket. | Required | 
| changeRequestId | The ID of the original change request. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getOriginalChangeRequestRouteInfoV1 | String | The original change request route info | 


#### Command Example
``` ```

#### Human Readable Output



### skybox-getTicketTypePhasesByTicketType
***
Retrieves the list of phases for the specified ticket
type.


#### Base Command

`skybox-getTicketTypePhasesByTicketType`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketType | The Ticket Type. Possible values are: VulnerabilityTicket, ApplicationTicket, VulnerabilityDefinitionTicket, AccessChangeTicket, PolicyViolationTicket. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getTicketTypePhasesByTicketType | String | The ticket type phases by ticket type | 


#### Command Example
```!skybox-getTicketTypePhasesByTicketType ticketType=AccessChangeTicket```

#### Context Example
```json
{
    "Skybox": {
        "getTicketTypePhasesByTicketType": [
            {
                "defaultOwner": null,
                "id": 5,
                "name": "Request",
                "order": 1,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": false
            },
            {
                "defaultOwner": null,
                "id": 10,
                "name": "Recertification Request",
                "order": 1,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": false
            },
            {
                "defaultOwner": null,
                "id": 13,
                "name": "Request",
                "order": 1,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": false
            },
            {
                "defaultOwner": null,
                "id": 23,
                "name": "Request",
                "order": 1,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": false
            },
            {
                "defaultOwner": null,
                "id": 28,
                "name": "Request",
                "order": 1,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": false
            },
            {
                "defaultOwner": "skyboxview",
                "id": 6,
                "name": "Technical Details",
                "order": 2,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": false
            },
            {
                "defaultOwner": "IT Risk",
                "id": 11,
                "name": "Recertification Review",
                "order": 2,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": false
            },
            {
                "defaultOwner": "Network Engineering",
                "id": 15,
                "name": "Technical Details",
                "order": 2,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": false
            },
            {
                "defaultOwner": "Network Engineering",
                "id": 19,
                "name": "Technical Details",
                "order": 2,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": false
            },
            {
                "defaultOwner": "IT Risk",
                "id": 25,
                "name": "Risk Assessment",
                "order": 2,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": false
            },
            {
                "defaultOwner": "IT Risk",
                "id": 7,
                "name": "Risk Assessment",
                "order": 3,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": false
            },
            {
                "defaultOwner": "skyboxview",
                "id": 12,
                "name": "Verification",
                "order": 3,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": true
            },
            {
                "defaultOwner": "IT Risk",
                "id": 16,
                "name": "Risk Assessment",
                "order": 3,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": false
            },
            {
                "defaultOwner": "Network Engineering",
                "id": 18,
                "name": "Peer Review",
                "order": 3,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": false
            },
            {
                "defaultOwner": "NOC",
                "id": 26,
                "name": "Implementation Details",
                "order": 3,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": false
            },
            {
                "defaultOwner": "NOC",
                "id": 8,
                "name": "Implementation Details",
                "order": 4,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": false
            },
            {
                "defaultOwner": "NOC",
                "id": 17,
                "name": "Implementation Details",
                "order": 4,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": false
            },
            {
                "defaultOwner": "IT Risk",
                "id": 20,
                "name": "Risk Assessment",
                "order": 4,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": false
            },
            {
                "defaultOwner": "skyboxview",
                "id": 27,
                "name": "Verification",
                "order": 4,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": true
            },
            {
                "defaultOwner": "skyboxview",
                "id": 9,
                "name": "Verification",
                "order": 5,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": true
            },
            {
                "defaultOwner": "skyboxview",
                "id": 14,
                "name": "Verification",
                "order": 5,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": true
            },
            {
                "defaultOwner": "NOC",
                "id": 21,
                "name": "Implementation Details",
                "order": 5,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": false
            },
            {
                "defaultOwner": "skyboxview",
                "id": 22,
                "name": "Verification",
                "order": 6,
                "ticketType": "AccessChangeTicket",
                "waitingForClosure": true
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|defaultOwner|id|name|order|ticketType|waitingForClosure|
>|---|---|---|---|---|---|
>|  | 5 | Request | 1 | AccessChangeTicket | false |
>|  | 10 | Recertification Request | 1 | AccessChangeTicket | false |
>|  | 13 | Request | 1 | AccessChangeTicket | false |
>|  | 23 | Request | 1 | AccessChangeTicket | false |
>|  | 28 | Request | 1 | AccessChangeTicket | false |
>| skyboxview | 6 | Technical Details | 2 | AccessChangeTicket | false |
>| IT Risk | 11 | Recertification Review | 2 | AccessChangeTicket | false |
>| Network Engineering | 15 | Technical Details | 2 | AccessChangeTicket | false |
>| Network Engineering | 19 | Technical Details | 2 | AccessChangeTicket | false |
>| IT Risk | 25 | Risk Assessment | 2 | AccessChangeTicket | false |
>| IT Risk | 7 | Risk Assessment | 3 | AccessChangeTicket | false |
>| skyboxview | 12 | Verification | 3 | AccessChangeTicket | true |
>| IT Risk | 16 | Risk Assessment | 3 | AccessChangeTicket | false |
>| Network Engineering | 18 | Peer Review | 3 | AccessChangeTicket | false |
>| NOC | 26 | Implementation Details | 3 | AccessChangeTicket | false |
>| NOC | 8 | Implementation Details | 4 | AccessChangeTicket | false |
>| NOC | 17 | Implementation Details | 4 | AccessChangeTicket | false |
>| IT Risk | 20 | Risk Assessment | 4 | AccessChangeTicket | false |
>| skyboxview | 27 | Verification | 4 | AccessChangeTicket | true |
>| skyboxview | 9 | Verification | 5 | AccessChangeTicket | true |
>| skyboxview | 14 | Verification | 5 | AccessChangeTicket | true |
>| NOC | 21 | Implementation Details | 5 | AccessChangeTicket | false |
>| skyboxview | 22 | Verification | 6 | AccessChangeTicket | true |


### skybox-getOriginalChangeRequestV7
***
Retrieves the (original) change requests in the
specified ticket.


#### Base Command

`skybox-getOriginalChangeRequestV7`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ID of the ticket. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getOriginalChangeRequestV7 | String | The original change request | 


#### Command Example
```!skybox-getOriginalChangeRequestV7 ticketId=405```

#### Context Example
```json
{
    "Skybox": {
        "getOriginalChangeRequestV7": [
            {
                "NATDestinationAddresses": [],
                "NATDestinationObjects": [],
                "NATPortObjects": [],
                "NATPorts": null,
                "NATSourceAddresses": [],
                "NATSourceObjects": [],
                "applications": [],
                "comment": null,
                "complianceStatus": "YES",
                "createAfter": null,
                "createdBy": "skyboxview",
                "creationTime": "2017-07-31T11:54:08.768000-04:00",
                "description": null,
                "destinationAddresses": [
                    "192.170.33.0-192.170.33.255"
                ],
                "destinationObjects": [
                    {
                        "affectedAccessRules": 11,
                        "firewallFolder": null,
                        "firewallIP": null,
                        "firewallId": 0,
                        "firewallManagementId": 3635,
                        "firewallManagementName": "US_NY_CMA01",
                        "firewallManagementType": "Management",
                        "firewallName": null,
                        "ipRanges": [
                            "192.170.33.0-192.170.33.255"
                        ],
                        "members": null,
                        "newObject": false,
                        "objectName": "DMZ",
                        "objectType": "NETWORK",
                        "ports": null
                    }
                ],
                "expirationDate": null,
                "firewall": {
                    "accessRules": 20,
                    "id": 5,
                    "interfaces": 6,
                    "name": "main_FW",
                    "netInterface": [],
                    "os": "Solaris",
                    "osVendor": "Sun",
                    "osVersion": null,
                    "primaryIp": "192.170.1.97",
                    "routingRules": 23,
                    "services": 2,
                    "status": "Up",
                    "type": "Firewall",
                    "vulnerabilities": 0
                },
                "hideSourceBehindGW": false,
                "id": 573,
                "implementBeforeAccessRule": {
                    "accessRuleId": 160,
                    "actionType": "Allow",
                    "chainNumber": 0,
                    "comment": null,
                    "firewallServiceSpace": {
                        "firewallServices": "0-65535/0-65535/ANY",
                        "negated": false,
                        "originalText": "Any"
                    },
                    "globalUniqueId": "{18D89D4B-9735-4C06-8ED5-3EFC63ECB561}",
                    "order": 3,
                    "originalRuleName": "2",
                    "originalRuleText": null,
                    "primaryChain": false,
                    "sourceIPSpace": {
                        "ipRanges": "200.160.1.0-200.160.2.255",
                        "negated": false,
                        "originalText": "Partners_Networks"
                    },
                    "targetIPSpace": {
                        "ipRanges": "192.170.33.0-192.170.33.255",
                        "negated": false,
                        "originalText": "DMZ"
                    },
                    "translatedFirewallServiceSpace": null,
                    "translatedSourceIPSpace": null,
                    "translatedTargetIPSpace": null
                },
                "implementingAccessRules": [],
                "isDestinationNegated": false,
                "isGlobal": false,
                "isInstallOnAny": false,
                "isLogEnabled": true,
                "isRequiredStatus": "TRUE",
                "isServicesNegated": false,
                "isSharedObject": false,
                "isSourceNegated": false,
                "lastModificationTime": "2017-07-31T11:54:10.816000-04:00",
                "lastModifiedBy": "skyboxview",
                "loggingProfile": null,
                "messages": [],
                "originalChangeRequestId": 0,
                "portObjects": [
                    {
                        "affectedAccessRules": 0,
                        "firewallFolder": null,
                        "firewallIP": null,
                        "firewallId": 0,
                        "firewallManagementId": 3635,
                        "firewallManagementName": "US_NY_CMA01",
                        "firewallManagementType": "Management",
                        "firewallName": null,
                        "ipRanges": [],
                        "members": "info-req,mask-request,echo-request,timestamp",
                        "newObject": false,
                        "objectName": "icmp-requests",
                        "objectType": "SERVICE",
                        "ports": "8/ICMP, 13/ICMP, 15/ICMP, 17/ICMP"
                    }
                ],
                "ports": "8/ICMP, 13/ICMP, 15/ICMP, 17/ICMP",
                "ruleAttributes": {
                    "businessFunction": null,
                    "comment": null,
                    "customFields": [],
                    "email": null,
                    "nextReviewDate": null,
                    "owner": null,
                    "status": "NONE",
                    "ticketId": null
                },
                "ruleGroup": null,
                "ruleType": "DENY",
                "securityProfileGroup": null,
                "sourceAddresses": [
                    "0.0.0.0-255.255.255.255"
                ],
                "sourceObjects": [],
                "useApplicationDefaultPorts": false,
                "userUsage": "ANY",
                "users": [],
                "verificationStatus": "UNKNOWN",
                "vpn": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Original Change Request
>|NATDestinationAddresses|NATDestinationObjects|NATPortObjects|NATPorts|NATSourceAddresses|NATSourceObjects|applications|comment|complianceStatus|createAfter|createdBy|creationTime|description|destinationAddresses|destinationObjects|expirationDate|firewall|hideSourceBehindGW|id|implementBeforeAccessRule|implementingAccessRules|isDestinationNegated|isGlobal|isInstallOnAny|isLogEnabled|isRequiredStatus|isServicesNegated|isSharedObject|isSourceNegated|lastModificationTime|lastModifiedBy|loggingProfile|messages|originalChangeRequestId|portObjects|ports|ruleAttributes|ruleGroup|ruleType|securityProfileGroup|sourceAddresses|sourceObjects|useApplicationDefaultPorts|userUsage|users|verificationStatus|vpn|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  |  |  |  |  |  |  |  | YES |  | skyboxview | 2017-07-31T11:54:08.768000-04:00 |  | 192.170.33.0-192.170.33.255 | {'firewallId': 0, 'firewallName': None, 'firewallIP': None, 'firewallFolder': None, 'firewallManagementId': 3635, 'firewallManagementName': 'US_NY_CMA01', 'firewallManagementType': 'Management', 'objectName': 'DMZ', 'objectType': 'NETWORK', 'ipRanges': ['192.170.33.0-192.170.33.255'], 'ports': None, 'members': None, 'affectedAccessRules': 11, 'newObject': False} |  | accessRules: 20<br/>id: 5<br/>interfaces: 6<br/>name: main_FW<br/>netInterface: <br/>os: Solaris<br/>osVendor: Sun<br/>osVersion: null<br/>primaryIp: 192.170.1.97<br/>routingRules: 23<br/>services: 2<br/>status: Up<br/>type: Firewall<br/>vulnerabilities: 0 | false | 573 | accessRuleId: 160<br/>actionType: Allow<br/>chainNumber: 0<br/>comment: null<br/>firewallServiceSpace: {"firewallServices": "0-65535/0-65535/ANY", "negated": false, "originalText": "Any"}<br/>globalUniqueId: {18D89D4B-9735-4C06-8ED5-3EFC63ECB561}<br/>order: 3<br/>originalRuleName: 2<br/>originalRuleText: null<br/>primaryChain: false<br/>sourceIPSpace: {"ipRanges": "200.160.1.0-200.160.2.255", "negated": false, "originalText": "Partners_Networks"}<br/>targetIPSpace: {"ipRanges": "192.170.33.0-192.170.33.255", "negated": false, "originalText": "DMZ"}<br/>translatedFirewallServiceSpace: null<br/>translatedSourceIPSpace: null<br/>translatedTargetIPSpace: null |  | false | false | false | true | TRUE | false | false | false | 2017-07-31T11:54:10.816000-04:00 | skyboxview |  |  | 0 | {'firewallId': 0, 'firewallName': None, 'firewallIP': None, 'firewallFolder': None, 'firewallManagementId': 3635, 'firewallManagementName': 'US_NY_CMA01', 'firewallManagementType': 'Management', 'objectName': 'icmp-requests', 'objectType': 'SERVICE', 'ipRanges': [], 'ports': '8/ICMP, 13/ICMP, 15/ICMP, 17/ICMP', 'members': 'info-req,mask-request,echo-request,timestamp', 'affectedAccessRules': 0, 'newObject': False} | 8/ICMP, 13/ICMP, 15/ICMP, 17/ICMP | businessFunction: null<br/>comment: null<br/>customFields: <br/>email: null<br/>nextReviewDate: null<br/>owner: null<br/>status: NONE<br/>ticketId: null |  | DENY |  | 0.0.0.0-255.255.255.255 |  | false | ANY |  | UNKNOWN |  |


### skybox-setTicketFields
***
Sets ticket data in Skybox.
You can use this method with all ticket types.


#### Base Command

`skybox-setTicketFields`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ID of the ticket. | Optional | 
| ticketIdType | Specifies whether the ticket ID is the Skybox ticket ID or the ID from the<br/>external ticketing system<br/>Possible values:<br/>l SBV<br/>l EXTERNAL. Possible values are: SBV, EXTERNAL. | Required | 
| ticketFields_typeCode | The Code type of the field. | Optional | 
| ticketFields_value | The field value. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.setTicketFields | String | The ticket fields that have been set | 


#### Command Example
``` ```

#### Human Readable Output



### skybox-createAccessChangeTicket
***
Creates an Access Change ticket with a workflow
and phases.


#### Base Command

`skybox-createAccessChangeTicket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| accessChangeTicket_id | The change ticket ID. Default is The access Chagne Ticket ID. | Optional | 
| accessChangeTicket_comment | The Change ticket comment. Default is The access Change Ticket comment. | Optional | 
| accessChangeTicket_description | The Change ticket description. Default is The access Change Ticket description. | Optional | 
| accessChangeTicket_createdBy | The Change ticket author. Default is The access Change Ticket creator. | Optional | 
| accessChangeTicket_creationTime | The creation time. Default is The access Change Ticket creation time. | Optional | 
| accessChangeTicket_lastModifiedBy | The last modification author. Default is The access Change Ticket last modification author. | Optional | 
| accessChangeTicket_lastModificationTime | The time of the last modification. Default is The change ticket last modification time. | Optional | 
| accessChangeTicket_externalTicketId | The external ticket ID. Default is The acess Change Ticket external ticket ID. | Optional | 
| accessChangeTicket_externalTicketStatus | Possible values:<br/>l Pending<br/>l Open<br/>l Closed<br/>l Error<br/>l Rejected. | Optional | 
| accessChangeTicket_status | Possible values:<br/>l New<br/>l InProgress<br/>l Resolved<br/>l Closed<br/>l Rejected<br/>l Ignored<br/>l Verified<br/>l Reopened<br/>l Demoted. Possible values are: New, InProgress, Resolved, Closed, Rejected, Ignored, Verified, Reopened, Demoted. | Optional | 
| accessChangeTicket_title | The Change ticket title. | Optional | 
| accessChangeTicket_changeDetails | The change ticket details. | Optional | 
| accessChangeTicket_priority | The Priority<br/>Possible values:<br/>l P1<br/>l P2<br/>l P3<br/>l P4<br/>l P5. Possible values are: P1, P2, P3, P4, P5. | Optional | 
| accessChangeTicket_owner | The Change ticket owner. | Optional | 
| accessChangeTicket_dueDate | The Change ticket due date. | Optional | 
| accessChangeTicket_doneDate | The change ticket done date. | Optional | 
| accessChangeTicket_likelihood | The likelihood<br/>Possible values:<br/>l Unknown<br/>l Low<br/>l Medium<br/>l High<br/>l Priority<br/>l Critical. Possible values are: Unknown, Low, Medium, High, Priority, Critical. | Optional | 
| accessChangeTicket_ccList_email | The CC list email address. | Optional | 
| accessChangeTicket_ccList_userName | The CC list username. | Optional | 
| accessChangeTicket_customFields_comment | The custom field comment. | Optional | 
| accessChangeTicket_customFields_createdBy | The custom field author. | Optional | 
| accessChangeTicket_customFields_creationTime | The custom field creation time. | Optional | 
| accessChangeTicket_customFields_description | The custom field description. | Optional | 
| accessChangeTicket_customFields_id | The custom field id. | Optional | 
| accessChangeTicket_customFields_lastModificationTime | The custom field last modification time. | Optional | 
| accessChangeTicket_customFields_lastModifiedBy | The custom field last modification author. | Optional | 
| accessChangeTicket_customFields_name | The custom field name. | Optional | 
| accessChangeTicket_customFields_typeCode | The custom field type code. | Optional | 
| accessChangeTicket_customFields_value | The custom field value. | Optional | 
| accessChangeTicket_currentPhaseName | The access Change Ticket current phase name. | Optional | 
| phases_comment | Phase comment. | Optional | 
| phases_createdBy | Phase author. | Optional | 
| phases_creationTime | Phase creation time. | Optional | 
| phases_current | Current phase. | Optional | 
| phases_demotionsCount | Phase demotions count. | Optional | 
| phases_description | Phase description. | Optional | 
| phases_dueDate | Phase due date. | Optional | 
| phases_endDate | Phase end date. | Optional | 
| phases_id | The Phase ID. | Optional | 
| phases_lastModificationTime | The Phase last modification time. | Optional | 
| phases_lastModifiedBy | The phase last modification author. | Optional | 
| phases_owner | The phase owner. | Optional | 
| phases_revisedDueDate | The phase revised due date. | Optional | 
| phases_startDate | The phase start date. | Optional | 
| phases_ticketTypePhase_defaultOwner | The phase ticket type default owner. | Optional | 
| phases_ticketTypePhase_id | The phase ticket type ID. | Optional | 
| phases_ticketTypePhase_name | The phase ticket type name. | Optional | 
| phases_ticketTypePhase_order | The phase ticket type order. | Optional | 
| phases_ticketTypePhase_ticketType | The phase ticket type. | Optional | 
| phases_ticketTypePhase_waitingForClosure | The phase closure waiting status. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.createAccessChangeTicket | String | The created access change ticket | 


#### Command Example
```!skybox-createAccessChangeTicket accessChangeTicket_id="405" accessChangeTicket_comment="comment" accessChangeTicket_description="The access Change Ticket description" accessChangeTicket_createdBy="skyboxview" accessChangeTicket_creationTime="2021-07-19T11:31:48.352000-04:00" accessChangeTicket_lastModifiedBy="The access Change Ticket last modification author" accessChangeTicket_lastModificationTime="2021-07-19T11:31:48.352000-04:00" accessChangeTicket_externalTicketId="The acess Change Ticket external ticket ID" accessChangeTicket_status="New" accessChangeTicket_title="title" accessChangeTicket_priority="P1" accessChangeTicket_ccList_email="some@example.com" accessChangeTicket_ccList_userName="skyboxview" accessChangeTicket_customFields_id="1" accessChangeTicket_customFields_typeCode="1000004" accessChangeTicket_currentPhaseName="PhaseName"```

#### Context Example
```json
{
    "Skybox": {
        "createAccessChangeTicket": {
            "ccList": [
                {
                    "email": "skyboxview@skyboxsecurity.com",
                    "userName": "skyboxview"
                }
            ],
            "changeDetails": null,
            "comment": "------- Created by: skyboxview  [skybox view] (1626889064413) Phase: Request ------- \n\ncomment",
            "createdBy": "skyboxview",
            "creationTime": "2021-07-21T13:37:43.424000-04:00",
            "currentPhaseName": "Request",
            "customFields": [
                {
                    "comment": null,
                    "createdBy": null,
                    "creationTime": null,
                    "description": null,
                    "id": 0,
                    "lastModificationTime": null,
                    "lastModifiedBy": null,
                    "name": "Department",
                    "typeCode": 1000004,
                    "value": null
                }
            ],
            "description": "The access Change Ticket description",
            "doneDate": null,
            "dueDate": null,
            "externalTicketId": "The acess Change Ticket external ticket ID",
            "externalTicketStatus": null,
            "id": 497,
            "lastModificationTime": "2021-07-21T13:37:43.424000-04:00",
            "lastModifiedBy": "skyboxview",
            "likelihood": null,
            "owner": "skyboxview",
            "priority": "P1",
            "status": "New",
            "title": "title"
        }
    }
}
```

#### Human Readable Output

>### Access Change Ticket Created
>|id|title|priority|
>|---|---|---|
>| 497 | title | P1 |


### skybox-getAttachmentFile
***
Retrieves the specified attachment from Skybox.


#### Base Command

`skybox-getAttachmentFile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attachmentId | The attachement ID. You get the IDs with getAttachmentList. | Required | 
| output_filename | The filename to save the attachment as. Default is output.file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile | Unknown | The info file key with the file entryID | 


#### Command Example
```!skybox-getAttachmentFile attachmentId=1 output_filename=plik.png```

#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "3502@8ed7562a-849d-4bc2-8388-b7e5cf55b5da",
        "Extension": "png",
        "Info": "image/png",
        "Name": "plik.png",
        "Size": 29573,
        "Type": "PNG image data, 593 x 74, 8-bit/color RGBA, non-interlaced"
    }
}
```

#### Human Readable Output



### skybox-createRecertifyTicketV2
***
Creates tickets for certification of a firewall’s
access rules.


#### Base Command

`skybox-createRecertifyTicketV2`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| accessChangeTicket_id | The access Change Ticket ID. | Optional | 
| accessChangeTicket_comment | The access Change Ticket comment. | Optional | 
| accessChangeTicket_description | The access Change Ticket description. | Optional | 
| accessChangeTicket_createdBy | The access Change ticket creator. | Optional | 
| accessChangeTicket_creationTime | The access Change Ticket creation Time. | Optional | 
| accessChangeTicket_lastModifiedBy | The access Change Ticket last modification author. | Optional | 
| accessChangeTicket_lastModificationTime | The access Change Ticket last modification time. | Optional | 
| accessChangeTicket_externalTicketId | The access Change Ticket external ticket ID. | Optional | 
| accessChangeTicket_externalTicketStatus | Possible values:<br/>l Pending<br/>l Open<br/>l Closed<br/>l Error<br/>l Rejected. Possible values are: Pending, Open, Closed, Error, Rejected. | Optional | 
| accessChangeTicket_status | The access change ticket status. Possible values are: New, InProgress, Resolved, Closed, Rejected, Ignored, Verified, Reopened, Demoted. | Optional | 
| accessChangeTicket_title | The access Change Ticket title. | Optional | 
| accessChangeTicket_changeDetails | The access change ticket details. | Optional | 
| accessChangeTicket_priority | The access Change Ticket priority<br/>Possible values:<br/>l P1<br/>l P2<br/>l P3<br/>l P4<br/>l P5. Possible values are: P1, P2, P3, P4, P5. | Optional | 
| accessChangeTicket_owner | The access Change Ticket owner. | Optional | 
| accessChangeTicket_dueDate | The access Change Ticket due Date. | Optional | 
| accessChangeTicket_doneDate | The access Change Ticket done date. | Optional | 
| accessChangeTicket_likelihood | The access Change Ticket likelihood<br/>Possible values:<br/>l Unknown<br/>l Low<br/>l Medium<br/>l High<br/>l Priority<br/>l Critical. Possible values are: Unknown, Low, Medium, High, Priority, Critical. | Optional | 
| accessChangeTicket_ccList_email | The access Change Ticket CC email. | Optional | 
| accessChangeTicket_ccList_userName | The access Change Ticket CC username. | Optional | 
| accessChangeTicket_customFields_comment | The custom field comment. | Optional | 
| accessChangeTicket_customFields_createdBy | The custom field crated by. | Optional | 
| accessChangeTicket_customFields_creationTime | The custom field creation time. | Optional | 
| accessChangeTicket_customFields_description | The custom field description. | Optional | 
| accessChangeTicket_customFields_id | The custom field ID. | Optional | 
| accessChangeTicket_customFields_lastModificationTime | The custom field last modification time. | Optional | 
| accessChangeTicket_customFields_lastModifiedBy | The custom field last modification author. | Optional | 
| accessChangeTicket_customFields_name | The custom fields ame. | Optional | 
| accessChangeTicket_customFields_typeCode | The cusotm fields type code. | Optional | 
| accessChangeTicket_customFields_value | The custom field value. | Optional | 
| accessChangeTicket_currentPhaseName | The current phase name. | Optional | 
| accessRuleElements_action | The access rule action. | Optional | 
| accessRuleElements_comment | The access rule comment. | Optional | 
| accessRuleElements_description | The access rule description. | Optional | 
| accessRuleElements_destinationAddresses | The access rule destination address. | Optional | 
| accessRuleElements_direction | The access rule direction. | Optional | 
| accessRuleElements_disabled | The access rule enablement status. | Optional | 
| accessRuleElements_firewall_id | The firewall ID. | Optional | 
| accessRuleElements_firewall_name | The firewall name. | Optional | 
| accessRuleElements_firewall_path | The firewall path. | Optional | 
| accessRuleElements_globalUniqueId | The access rule global unique ID. | Optional | 
| accessRuleElements_id | The access rule ID. | Optional | 
| accessRuleElements_implied | The access rule implied. | Optional | 
| accessRuleElements_isAuthenticated | The access rule authentication status. | Optional | 
| accessRuleElements_netInterfaces | The access rule network interfaces. | Optional | 
| accessRuleElements_orgDestinationText | The original text in the destination field. | Required | 
| accessRuleElements_orgPortsText | The original text in the services field. | Optional | 
| accessRuleElements_orgRuleNumber | The original rule number. | Optional | 
| accessRuleElements_orgRuleText | The original rule ID as taken from device. | Optional | 
| accessRuleElements_orgSourceText | The text (definition) of the access rule as taken from<br/>the device. | Optional | 
| accessRuleElements_ports | Services resolved to object names, in the form of<br/>80/TCP or 80-80/TCP. | Optional | 
| accessRuleElements_ruleChain | The name of the rule chain. | Optional | 
| accessRuleElements_sbOrder | The order of the rule in its chain. | Optional | 
| accessRuleElements_services | The services (ports) used by the rule. | Optional | 
| accessRuleElements_sourceAddresses | Addresses are resolved to ranges. | Optional | 
| accessRuleElements_sourceNetInterfaces | The source network interfaces. | Optional | 
| workflowId | The workflos ID number. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.createRecertifyTicketV2 | String | The recertify ticket that has been created | 


#### Command Example
``` ```

#### Human Readable Output



### skybox-getAccessChangeTicket
***
Retrieves an Access Change ticket from Skybox.


#### Base Command

`skybox-getAccessChangeTicket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ticket ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getAccessChangeTicket | String | The access change ticket | 


#### Command Example
``` ```

#### Human Readable Output



### skybox-getAccessRequests
***
Retrieves change requests according to their ID
numbers.


#### Base Command

`skybox-getAccessRequests`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| accessRequestIds | The access request IDs. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getAccessRequests | String | The access request | 


#### Command Example
```!skybox-getAccessRequests accessRequestIds=1```

#### Human Readable Output

>null

### skybox-getPotentialVulnerabilitiesV2
***
Retrieves the list of Vulnerability Definitions that, if
the requested change is made, are directly
exposed to assets.


#### Base Command

`skybox-getPotentialVulnerabilitiesV2`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ticket ID. | Required | 
| changeRequestId | The change request ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getPotentialVulnerabilitiesV2 | String | The potential vulnerabilities | 


#### Command Example
```!skybox-getPotentialVulnerabilitiesV2 ticketId=407 changeRequestId=586```

#### Context Example
```json
{
    "Skybox": {
        "getPotentialVulnerabilitiesV2": {}
    }
}
```

#### Human Readable Output

>### Results
>**No entries.**


### skybox-deleteChangeRequests
***
Deletes change requests from a ticket


#### Base Command

`skybox-deleteChangeRequests`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ticket ID. | Required | 
| changeRequestIds | The change request IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.deleteChangeRequests | String | The delete change request status | 


#### Command Example
```!skybox-deleteChangeRequests ticketId=427 changeRequestIds=629```

#### Human Readable Output

>null

### skybox-deleteAccessChangeTicket
***
Deletes the specified Access Change ticket in
Skybox.


#### Base Command

`skybox-deleteAccessChangeTicket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ticket ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.deleteAccessChangeTicket | String | The delete access chagne ticket status | 


#### Command Example
```!skybox-deleteAccessChangeTicket ticketId=426```

#### Human Readable Output

>null

### skybox-getNotImplementedChangeRequestsV2
***
Retrieves the list of unimplemented change
requests in Skybox Change Manager according
to the permissions of the user sending the
request. The information retrieved includes the
reasons that the changes were not implemented.


#### Base Command

`skybox-getNotImplementedChangeRequestsV2`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getNotImplementedChangeRequestsV2 | String | The not implemented change requests | 


#### Command Example
```!skybox-getNotImplementedChangeRequestsV2```

#### Context Example
```json
{
    "Skybox": {
        "getNotImplementedChangeRequestsV2": [
            {
                "additionalDetails": "Source Interface: netInterface2810 [192.170.1.98]\nDestination Interface: netIterface2090 [192.170.34.1]\nSuggested Position: Before #13 (Original Rule ID: 11)\nRule Logging\n",
                "changeDetails": "Source: Finance_Unix\nDestination: DB\nServices: Service_1-1024_TCP (New)\n",
                "changeType": "ADD_RULE",
                "comment": null,
                "completeDate": null,
                "completeStatus": "NOT_COMPLETED",
                "completeStatusInfo": null,
                "dueDate": "2018-09-17T23:58:58.048000-04:00",
                "firewallManagementName": "US_NY_CMA01",
                "firewallName": "prod FW",
                "globalUniqueId": null,
                "id": 614,
                "implementationNotSupportedReasons": null,
                "implementationStatus": "UNKNOWN",
                "isImplementationSupported": true,
                "isRequiredStatus": "TRUE",
                "lastModificationTime": "2018-09-14T14:53:47.392000-04:00",
                "objectId": "-",
                "owner": "NOC",
                "ticketId": 416,
                "ticketPriority": "P2",
                "workflowName": "General"
            },
            {
                "additionalDetails": null,
                "changeDetails": "Service Object: 1-1024/TCP",
                "changeType": "ADD_OBJECT",
                "comment": null,
                "completeDate": null,
                "completeStatus": "NOT_COMPLETED",
                "completeStatusInfo": null,
                "dueDate": "2018-09-17T23:58:58.048000-04:00",
                "firewallManagementName": "US_NY_CMA01",
                "firewallName": null,
                "globalUniqueId": null,
                "id": 616,
                "implementationNotSupportedReasons": null,
                "implementationStatus": "UNKNOWN",
                "isImplementationSupported": true,
                "isRequiredStatus": "TRUE",
                "lastModificationTime": "2018-09-14T14:53:47.392000-04:00",
                "objectId": "Service_1-1024_TCP",
                "owner": "NOC",
                "ticketId": 416,
                "ticketPriority": "P2",
                "workflowName": "General"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|additionalDetails|changeDetails|changeType|comment|completeDate|completeStatus|completeStatusInfo|dueDate|firewallManagementName|firewallName|globalUniqueId|id|implementationNotSupportedReasons|implementationStatus|isImplementationSupported|isRequiredStatus|lastModificationTime|objectId|owner|ticketId|ticketPriority|workflowName|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Source Interface: netInterface2810 [192.170.1.98]<br/>Destination Interface: netIterface2090 [192.170.34.1]<br/>Suggested Position: Before #13 (Original Rule ID: 11)<br/>Rule Logging<br/> | Source: Finance_Unix<br/>Destination: DB<br/>Services: Service_1-1024_TCP (New)<br/> | ADD_RULE |  |  | NOT_COMPLETED |  | 2018-09-17T23:58:58.048000-04:00 | US_NY_CMA01 | prod FW |  | 614 |  | UNKNOWN | true | TRUE | 2018-09-14T14:53:47.392000-04:00 | - | NOC | 416 | P2 | General |
>|  | Service Object: 1-1024/TCP | ADD_OBJECT |  |  | NOT_COMPLETED |  | 2018-09-17T23:58:58.048000-04:00 | US_NY_CMA01 |  |  | 616 |  | UNKNOWN | true | TRUE | 2018-09-14T14:53:47.392000-04:00 | Service_1-1024_TCP | NOC | 416 | P2 | General |


### skybox-getTicketEvents
***
Retrieves the history of a ticket.


#### Base Command

`skybox-getTicketEvents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ticket ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getTicketEvents | String | The ticket events | 


#### Command Example
```!skybox-getTicketEvents ticketId=380```

#### Context Example
```json
{
    "Skybox": {
        "getTicketEvents": [
            {
                "date": "2014-05-25T14:25:25.504000-04:00",
                "id": 320,
                "modifiedField": "Ticket Created",
                "newValue": "Owner: skyboxview",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-05-25T14:25:25.504000-04:00",
                "id": 321,
                "modifiedField": "Change Request Added",
                "newValue": "Change Request #134: Add Rule vlab-cisco [10.41.1.2] Source: Partner_Nets Destination: web_servers (New) Services: 80/TCP, 443/TCP ",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-05-25T14:25:25.504000-04:00",
                "id": 322,
                "modifiedField": "Change Request Added",
                "newValue": "Change Request #135: Add Rule vlab-cisco [10.41.1.2] Source: Partner_Nets Destination: web_servers (New) Services: 80/TCP, 443/TCP ",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-05-25T14:25:25.504000-04:00",
                "id": 323,
                "modifiedField": "Change Request Added",
                "newValue": "Change Request #136: New Object vlab-cisco [10.41.1.2] Address Object: 192.168.90.10-192.168.90.12",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-05-25T14:25:25.504000-04:00",
                "id": 324,
                "modifiedField": "Change Request Added",
                "newValue": "Change Request #137: New Object vlab-cisco [10.41.1.2] Address Object: 192.168.90.10-192.168.90.12",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-05-25T14:25:48.032000-04:00",
                "id": 325,
                "modifiedField": "Promote",
                "newValue": "Phase: Technical Details, Owner: Network Engineering",
                "oldValue": "Phase: Request, Owner: skyboxview",
                "user": "skyboxview"
            },
            {
                "date": "2014-05-25T14:25:48.032000-04:00",
                "id": 326,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Technical Details, Due Date: 5/27/14",
                "oldValue": "Phase: Technical Details, Due Date: ",
                "user": "skyboxview"
            },
            {
                "date": "2014-05-25T14:25:48.032000-04:00",
                "id": 327,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Risk Assessment, Due Date: 5/29/14",
                "oldValue": "Phase: Risk Assessment, Due Date: ",
                "user": "skyboxview"
            },
            {
                "date": "2014-05-25T14:25:48.032000-04:00",
                "id": 328,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Implementation Details, Due Date: 6/2/14",
                "oldValue": "Phase: Implementation Details, Due Date: ",
                "user": "skyboxview"
            },
            {
                "date": "2014-05-25T14:25:48.032000-04:00",
                "id": 329,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Verification, Due Date: 6/3/14",
                "oldValue": "Phase: Verification, Due Date: ",
                "user": "skyboxview"
            },
            {
                "date": "2014-05-25T14:25:48.032000-04:00",
                "id": 330,
                "modifiedField": "Due Date Changed",
                "newValue": "6/3/14",
                "oldValue": "6/4/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-05-25T14:25:48.032000-04:00",
                "id": 331,
                "modifiedField": "Title Changed",
                "newValue": "Add access from partner to web servers",
                "oldValue": "Add access from partner to web server",
                "user": "skyboxview"
            },
            {
                "date": "2014-05-25T14:25:48.032000-04:00",
                "id": 332,
                "modifiedField": "Description Changed",
                "newValue": "Add access from partner to web servers",
                "oldValue": "Add access from partner to web server",
                "user": "skyboxview"
            },
            {
                "date": "2014-05-25T14:25:58.272000-04:00",
                "id": 333,
                "modifiedField": "Promote",
                "newValue": "Phase: Risk Assessment, Owner: IT Risk",
                "oldValue": "Phase: Technical Details, Owner: Network Engineering",
                "user": "skyboxview"
            },
            {
                "date": "2014-05-25T14:25:58.272000-04:00",
                "id": 334,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Risk Assessment, Due Date: 5/27/14",
                "oldValue": "Phase: Risk Assessment, Due Date: 5/29/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-05-25T14:25:58.272000-04:00",
                "id": 335,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Implementation Details, Due Date: 5/29/14",
                "oldValue": "Phase: Implementation Details, Due Date: 6/2/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-05-25T14:25:58.272000-04:00",
                "id": 336,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Verification, Due Date: 5/30/14",
                "oldValue": "Phase: Verification, Due Date: 6/3/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-05-25T14:25:58.272000-04:00",
                "id": 337,
                "modifiedField": "Due Date Changed",
                "newValue": "5/30/14",
                "oldValue": "6/3/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-05-25T14:26:03.392000-04:00",
                "id": 338,
                "modifiedField": "Promote",
                "newValue": "Phase: Implementation Details, Owner: NOC",
                "oldValue": "Phase: Risk Assessment, Owner: IT Risk",
                "user": "skyboxview"
            },
            {
                "date": "2014-05-25T14:26:03.392000-04:00",
                "id": 339,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Implementation Details, Due Date: 5/27/14",
                "oldValue": "Phase: Implementation Details, Due Date: 5/29/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-05-25T14:26:03.392000-04:00",
                "id": 340,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Verification, Due Date: 5/28/14",
                "oldValue": "Phase: Verification, Due Date: 5/30/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-05-25T14:26:03.392000-04:00",
                "id": 341,
                "modifiedField": "Due Date Changed",
                "newValue": "5/28/14",
                "oldValue": "5/30/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:42:09.152000-04:00",
                "id": 417,
                "modifiedField": "Demote",
                "newValue": "Phase: Risk Assessment, Owner: IT Risk",
                "oldValue": "Phase: Implementation Details, Owner: NOC",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:42:09.152000-04:00",
                "id": 418,
                "modifiedField": "Threat Level Changed",
                "newValue": null,
                "oldValue": "Unknown",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:42:09.152000-04:00",
                "id": 419,
                "modifiedField": "Access Required Changed",
                "newValue": null,
                "oldValue": "Unknown",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:42:09.152000-04:00",
                "id": 420,
                "modifiedField": "Privilege Attained Changed",
                "newValue": null,
                "oldValue": "Unknown",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:42:15.296000-04:00",
                "id": 421,
                "modifiedField": "Demote",
                "newValue": "Phase: Technical Details, Owner: Network Engineering",
                "oldValue": "Phase: Risk Assessment, Owner: IT Risk",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:42:23.488000-04:00",
                "id": 422,
                "modifiedField": "Demote",
                "newValue": "Phase: Request, Owner: skyboxview",
                "oldValue": "Phase: Technical Details, Owner: Network Engineering",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:44:52.992000-04:00",
                "id": 423,
                "modifiedField": "Promote",
                "newValue": "Phase: Technical Details, Owner: Network Engineering",
                "oldValue": "Phase: Request, Owner: skyboxview",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:44:52.992000-04:00",
                "id": 424,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Technical Details, Due Date: 9/16/14",
                "oldValue": "Phase: Technical Details, Due Date: 5/27/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:44:52.992000-04:00",
                "id": 425,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Risk Assessment, Due Date: 9/18/14",
                "oldValue": "Phase: Risk Assessment, Due Date: 5/27/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:44:52.992000-04:00",
                "id": 426,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Implementation Details, Due Date: 9/22/14",
                "oldValue": "Phase: Implementation Details, Due Date: 5/27/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:44:52.992000-04:00",
                "id": 427,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Verification, Due Date: 9/23/14",
                "oldValue": "Phase: Verification, Due Date: 5/28/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:44:52.992000-04:00",
                "id": 428,
                "modifiedField": "Due Date Changed",
                "newValue": "9/23/14",
                "oldValue": "5/28/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:44:52.992000-04:00",
                "id": 429,
                "modifiedField": "Change Request Added",
                "newValue": "Change Request #147: Require Access  Source: Partner_Nets Destination: web_servers (New) Services: 80/TCP, 443/TCP ",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:44:52.992000-04:00",
                "id": 430,
                "modifiedField": "Change Request Added",
                "newValue": "Change Request #148: Add Rule main_FW Source: Partner_Nets Destination: web_servers (New) Services: 80/TCP, 443/TCP ",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:44:52.992000-04:00",
                "id": 431,
                "modifiedField": "Change Request Added",
                "newValue": "Change Request #149: Add Rule Partner1 FW Source: Partner_Nets Destination: web_servers (New) Services: 80/TCP, 443/TCP ",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:44:52.992000-04:00",
                "id": 432,
                "modifiedField": "Change Request Added",
                "newValue": "Change Request #150: New Object  Address Object: 192.168.90.10-192.168.90.12",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:44:52.992000-04:00",
                "id": 433,
                "modifiedField": "Change Request Added",
                "newValue": "Change Request #151: New Object US_NY_CMA01 Address Object: 192.168.90.10-192.168.90.12",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:44:52.992000-04:00",
                "id": 434,
                "modifiedField": "Change Request Added",
                "newValue": "Change Request #152: New Object  Address Object: 192.168.90.10-192.168.90.12",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:44:52.992000-04:00",
                "id": 435,
                "modifiedField": "Change Request Deleted",
                "newValue": "Change Request #134: Add Rule vlab-cisco [10.41.1.2] Source: Partner_Nets Destination: web_servers (New) Services: 80/TCP, 443/TCP ",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:44:52.992000-04:00",
                "id": 436,
                "modifiedField": "Change Request Deleted",
                "newValue": "Change Request #135: Add Rule vlab-cisco [10.41.1.2] Source: Partner_Nets Destination: web_servers (New) Services: 80/TCP, 443/TCP ",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:44:52.992000-04:00",
                "id": 437,
                "modifiedField": "Change Request Deleted",
                "newValue": "Change Request #136: New Object vlab-cisco [10.41.1.2] Address Object: 192.168.90.10-192.168.90.12",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:44:52.992000-04:00",
                "id": 438,
                "modifiedField": "Change Request Deleted",
                "newValue": "Change Request #137: New Object vlab-cisco [10.41.1.2] Address Object: 192.168.90.10-192.168.90.12",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:45:48.288000-04:00",
                "id": 439,
                "modifiedField": "Promote",
                "newValue": "Phase: Risk Assessment, Owner: IT Risk",
                "oldValue": "Phase: Technical Details, Owner: Network Engineering",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:45:48.288000-04:00",
                "id": 440,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Risk Assessment, Due Date: 9/16/14",
                "oldValue": "Phase: Risk Assessment, Due Date: 9/18/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:45:48.288000-04:00",
                "id": 441,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Implementation Details, Due Date: 9/18/14",
                "oldValue": "Phase: Implementation Details, Due Date: 9/22/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:45:48.288000-04:00",
                "id": 442,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Verification, Due Date: 9/19/14",
                "oldValue": "Phase: Verification, Due Date: 9/23/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:45:48.288000-04:00",
                "id": 443,
                "modifiedField": "Due Date Changed",
                "newValue": "9/19/14",
                "oldValue": "9/23/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:51:58.976000-04:00",
                "id": 444,
                "modifiedField": "Promote",
                "newValue": "Phase: Implementation Details, Owner: NOC",
                "oldValue": "Phase: Risk Assessment, Owner: IT Risk",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:51:58.976000-04:00",
                "id": 445,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Implementation Details, Due Date: 9/16/14",
                "oldValue": "Phase: Implementation Details, Due Date: 9/18/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:51:58.976000-04:00",
                "id": 446,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Verification, Due Date: 9/17/14",
                "oldValue": "Phase: Verification, Due Date: 9/19/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:51:58.976000-04:00",
                "id": 447,
                "modifiedField": "Due Date Changed",
                "newValue": "9/17/14",
                "oldValue": "9/19/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:51:58.976000-04:00",
                "id": 448,
                "modifiedField": "Change Request Approved",
                "newValue": "Change Request #148 Add Rule approved until 12/14/14",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-14T17:51:58.976000-04:00",
                "id": 449,
                "modifiedField": "Approve Risk Assessments",
                "newValue": "Approved following change requests:\n   Add Rule  firewall main_FW",
                "oldValue": "No risks were accepted",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:25:40.224000-04:00",
                "id": 469,
                "modifiedField": "Demote",
                "newValue": "Phase: Risk Assessment, Owner: IT Risk",
                "oldValue": "Phase: Implementation Details, Owner: NOC",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:25:40.224000-04:00",
                "id": 470,
                "modifiedField": "Threat Level Changed",
                "newValue": null,
                "oldValue": "Unknown",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:25:40.224000-04:00",
                "id": 471,
                "modifiedField": "Access Required Changed",
                "newValue": null,
                "oldValue": "Unknown",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:25:40.224000-04:00",
                "id": 472,
                "modifiedField": "Privilege Attained Changed",
                "newValue": null,
                "oldValue": "Unknown",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:25:46.368000-04:00",
                "id": 473,
                "modifiedField": "Demote",
                "newValue": "Phase: Technical Details, Owner: Network Engineering",
                "oldValue": "Phase: Risk Assessment, Owner: IT Risk",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:25:54.560000-04:00",
                "id": 474,
                "modifiedField": "Demote",
                "newValue": "Phase: Request, Owner: skyboxview",
                "oldValue": "Phase: Technical Details, Owner: Network Engineering",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:26:08.896000-04:00",
                "id": 475,
                "modifiedField": "Promote",
                "newValue": "Phase: Technical Details, Owner: Network Engineering",
                "oldValue": "Phase: Request, Owner: skyboxview",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:26:08.896000-04:00",
                "id": 476,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Technical Details, Due Date: 9/30/14",
                "oldValue": "Phase: Technical Details, Due Date: 9/16/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:26:08.896000-04:00",
                "id": 477,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Risk Assessment, Due Date: 10/2/14",
                "oldValue": "Phase: Risk Assessment, Due Date: 9/16/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:26:08.896000-04:00",
                "id": 478,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Implementation Details, Due Date: 10/6/14",
                "oldValue": "Phase: Implementation Details, Due Date: 9/16/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:26:08.896000-04:00",
                "id": 479,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Verification, Due Date: 10/7/14",
                "oldValue": "Phase: Verification, Due Date: 9/17/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:26:08.896000-04:00",
                "id": 480,
                "modifiedField": "Due Date Changed",
                "newValue": "10/7/14",
                "oldValue": "9/17/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:26:23.232000-04:00",
                "id": 481,
                "modifiedField": "Demote",
                "newValue": "Phase: Request, Owner: skyboxview",
                "oldValue": "Phase: Technical Details, Owner: Network Engineering",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:27:26.720000-04:00",
                "id": 482,
                "modifiedField": "Promote",
                "newValue": "Phase: Technical Details, Owner: Network Engineering",
                "oldValue": "Phase: Request, Owner: skyboxview",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:27:26.720000-04:00",
                "id": 483,
                "modifiedField": "Change Request Modified",
                "newValue": "Change Request #147: Require Access  Source: PAT-INTERNETTR Destination: web_servers (New) Services: 80/TCP, 443/TCP ",
                "oldValue": "Change Request #147: Require Access  Source: Partner_Nets Destination: web_servers (New) Services: 80/TCP, 443/TCP ",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:27:26.720000-04:00",
                "id": 484,
                "modifiedField": "Change Request Added",
                "newValue": "Change Request #159: New Object  Address Object: 192.168.90.10-192.168.90.12",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:27:26.720000-04:00",
                "id": 485,
                "modifiedField": "Change Request Deleted",
                "newValue": "Change Request #148: Add Rule main_FW Source: Partner_Nets Destination: web_servers (New) Services: 80/TCP, 443/TCP ",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:27:26.720000-04:00",
                "id": 486,
                "modifiedField": "Change Request Deleted",
                "newValue": "Change Request #149: Add Rule Partner1 FW Source: Partner_Nets Destination: web_servers (New) Services: 80/TCP, 443/TCP ",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:27:26.720000-04:00",
                "id": 487,
                "modifiedField": "Change Request Deleted",
                "newValue": "Change Request #150: New Object  Address Object: 192.168.90.10-192.168.90.12",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:27:26.720000-04:00",
                "id": 488,
                "modifiedField": "Change Request Deleted",
                "newValue": "Change Request #151: New Object US_NY_CMA01 Address Object: 192.168.90.10-192.168.90.12",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:27:26.720000-04:00",
                "id": 489,
                "modifiedField": "Change Request Deleted",
                "newValue": "Change Request #152: New Object  Address Object: 192.168.90.10-192.168.90.12",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:27:26.720000-04:00",
                "id": 490,
                "modifiedField": "Approve Risk Assessments",
                "newValue": "No risks were accepted",
                "oldValue": "Approved following change requests:\n   Add Rule  firewall main_FW",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:29:09.120000-04:00",
                "id": 491,
                "modifiedField": "Demote",
                "newValue": "Phase: Request, Owner: skyboxview",
                "oldValue": "Phase: Technical Details, Owner: Network Engineering",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:30:33.088000-04:00",
                "id": 492,
                "modifiedField": "Promote",
                "newValue": "Phase: Technical Details, Owner: Network Engineering",
                "oldValue": "Phase: Request, Owner: skyboxview",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:30:33.088000-04:00",
                "id": 493,
                "modifiedField": "Change Request Modified",
                "newValue": "Change Request #147: Require Access  Source: PAT-INTERNETTR Destination: 192.168.200.0/24 Services: 80/TCP, 443/TCP ",
                "oldValue": "Change Request #147: Require Access  Source: PAT-INTERNETTR Destination: web_servers (New) Services: 80/TCP, 443/TCP ",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:30:33.088000-04:00",
                "id": 494,
                "modifiedField": "Change Request Deleted",
                "newValue": "Change Request #159: New Object  Address Object: 192.168.90.10-192.168.90.12",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:34:34.752000-04:00",
                "id": 495,
                "modifiedField": "Demote",
                "newValue": "Phase: Request, Owner: skyboxview",
                "oldValue": "Phase: Technical Details, Owner: Network Engineering",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:34:34.752000-04:00",
                "id": 496,
                "modifiedField": "Change Request Added",
                "newValue": "Change Request #160: Add Rule vlab-cisco Source: PAT-INTERNETTR Destination: 192.168.200.0/24 Services: 80/TCP, 443/TCP ",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:35:37.216000-04:00",
                "id": 497,
                "modifiedField": "Promote",
                "newValue": "Phase: Technical Details, Owner: Network Engineering",
                "oldValue": "Phase: Request, Owner: skyboxview",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:35:37.216000-04:00",
                "id": 498,
                "modifiedField": "Change Request Modified",
                "newValue": "Change Request #147: Require Access  Source: PAT-INTERNETTR Destination: 10.101.50.20 Services: 80/TCP, 443/TCP ",
                "oldValue": "Change Request #147: Require Access  Source: PAT-INTERNETTR Destination: 192.168.200.0/24 Services: 80/TCP, 443/TCP ",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:35:37.216000-04:00",
                "id": 499,
                "modifiedField": "Change Request Added",
                "newValue": "Change Request #161: Add Rule vlab-cisco Source: PAT-INTERNETTR Destination: 10.101.50.20 Services: 80/TCP, 443/TCP ",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:35:37.216000-04:00",
                "id": 500,
                "modifiedField": "Change Request Deleted",
                "newValue": "Change Request #160: Add Rule vlab-cisco Source: PAT-INTERNETTR Destination: 192.168.200.0/24 Services: 80/TCP, 443/TCP ",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:37:26.784000-04:00",
                "id": 501,
                "modifiedField": "Demote",
                "newValue": "Phase: Request, Owner: skyboxview",
                "oldValue": "Phase: Technical Details, Owner: Network Engineering",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:38:54.848000-04:00",
                "id": 502,
                "modifiedField": "Promote",
                "newValue": "Phase: Technical Details, Owner: Network Engineering",
                "oldValue": "Phase: Request, Owner: skyboxview",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:38:55.872000-04:00",
                "id": 503,
                "modifiedField": "Change Request Modified",
                "newValue": "Change Request #147: Require Access  Source: 2.2.2.2 Destination: 5.5.5.7 Services: 80/TCP, 443/TCP ",
                "oldValue": "Change Request #147: Require Access  Source: PAT-INTERNETTR Destination: 10.101.50.20 Services: 80/TCP, 443/TCP ",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:38:55.872000-04:00",
                "id": 504,
                "modifiedField": "Change Request Deleted",
                "newValue": "Change Request #161: Add Rule vlab-cisco Source: PAT-INTERNETTR Destination: 10.101.50.20 Services: 80/TCP, 443/TCP ",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:39:25.568000-04:00",
                "id": 505,
                "modifiedField": "Demote",
                "newValue": "Phase: Request, Owner: skyboxview",
                "oldValue": "Phase: Technical Details, Owner: Network Engineering",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:40:46.464000-04:00",
                "id": 506,
                "modifiedField": "Promote",
                "newValue": "Phase: Technical Details, Owner: Network Engineering",
                "oldValue": "Phase: Request, Owner: skyboxview",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:40:46.464000-04:00",
                "id": 507,
                "modifiedField": "Change Request Added",
                "newValue": "Change Request #162: Modify Rules vlab-cisco [172.20.0.10] Add to Source: 1.2.3.4 ",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:40:46.464000-04:00",
                "id": 508,
                "modifiedField": "Change Request Added",
                "newValue": "Change Request #163: Modify Rules vlab-cisco [172.20.0.10] Add to Source: 1.2.3.4 ",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:40:46.464000-04:00",
                "id": 509,
                "modifiedField": "Change Request Deleted",
                "newValue": "Change Request #147: Require Access  Source: 2.2.2.2 Destination: 5.5.5.7 Services: 80/TCP, 443/TCP ",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:41:27.424000-04:00",
                "id": 510,
                "modifiedField": "Demote",
                "newValue": "Phase: Request, Owner: skyboxview",
                "oldValue": "Phase: Technical Details, Owner: Network Engineering",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:41:59.168000-04:00",
                "id": 511,
                "modifiedField": "Promote",
                "newValue": "Phase: Technical Details, Owner: Network Engineering",
                "oldValue": "Phase: Request, Owner: skyboxview",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:41:59.168000-04:00",
                "id": 512,
                "modifiedField": "Change Request Modified",
                "newValue": "Change Request #162: Modify Rules vlab-cisco [172.20.0.10] Add to Source: 1.2.3.4, 221.221.221.221 ",
                "oldValue": "Change Request #162: Modify Rules vlab-cisco [172.20.0.10] Add to Source: 1.2.3.4 ",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:41:59.168000-04:00",
                "id": 513,
                "modifiedField": "Change Request Added",
                "newValue": "Change Request #164: Modify Rules vlab-cisco [172.20.0.10] Add to Source: 1.2.3.4, 221.221.221.221 ",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:41:59.168000-04:00",
                "id": 514,
                "modifiedField": "Change Request Deleted",
                "newValue": "Change Request #163: Modify Rules vlab-cisco [172.20.0.10] Add to Source: 1.2.3.4 ",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:42:35.008000-04:00",
                "id": 515,
                "modifiedField": "Demote",
                "newValue": "Phase: Request, Owner: skyboxview",
                "oldValue": "Phase: Technical Details, Owner: Network Engineering",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:43:22.112000-04:00",
                "id": 516,
                "modifiedField": "Promote",
                "newValue": "Phase: Technical Details, Owner: Network Engineering",
                "oldValue": "Phase: Request, Owner: skyboxview",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:43:22.112000-04:00",
                "id": 517,
                "modifiedField": "Change Request Modified",
                "newValue": "Change Request #162: Modify Rules vlab-cisco [172.20.0.10] Add to Service: 80/TCP, 443/TCP ",
                "oldValue": "Change Request #162: Modify Rules vlab-cisco [172.20.0.10] Add to Source: 1.2.3.4, 221.221.221.221 ",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:43:22.112000-04:00",
                "id": 518,
                "modifiedField": "Change Request Added",
                "newValue": "Change Request #165: Modify Rules vlab-cisco [172.20.0.10] Add to Service: 80/TCP, 443/TCP ",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:43:22.112000-04:00",
                "id": 519,
                "modifiedField": "Change Request Deleted",
                "newValue": "Change Request #164: Modify Rules vlab-cisco [172.20.0.10] Add to Source: 1.2.3.4, 221.221.221.221 ",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:43:46.688000-04:00",
                "id": 520,
                "modifiedField": "Demote",
                "newValue": "Phase: Request, Owner: skyboxview",
                "oldValue": "Phase: Technical Details, Owner: Network Engineering",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:44:08.192000-04:00",
                "id": 521,
                "modifiedField": "Promote",
                "newValue": "Phase: Technical Details, Owner: Network Engineering",
                "oldValue": "Phase: Request, Owner: skyboxview",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:44:08.192000-04:00",
                "id": 522,
                "modifiedField": "Change Request Modified",
                "newValue": "Change Request #162: Modify Rules vlab-cisco [172.20.0.10] Remove from Service: 80/TCP, 443/TCP ",
                "oldValue": "Change Request #162: Modify Rules vlab-cisco [172.20.0.10] Add to Service: 80/TCP, 443/TCP ",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:44:08.192000-04:00",
                "id": 523,
                "modifiedField": "Change Request Added",
                "newValue": "Change Request #166: Modify Rules vlab-cisco [172.20.0.10] Remove from Service: 80/TCP, 443/TCP ",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:44:08.192000-04:00",
                "id": 524,
                "modifiedField": "Change Request Deleted",
                "newValue": "Change Request #165: Modify Rules vlab-cisco [172.20.0.10] Add to Service: 80/TCP, 443/TCP ",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:44:19.456000-04:00",
                "id": 525,
                "modifiedField": "Promote",
                "newValue": "Phase: Risk Assessment, Owner: IT Risk",
                "oldValue": "Phase: Technical Details, Owner: Network Engineering",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:44:19.456000-04:00",
                "id": 526,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Risk Assessment, Due Date: 9/30/14",
                "oldValue": "Phase: Risk Assessment, Due Date: 10/2/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:44:19.456000-04:00",
                "id": 527,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Implementation Details, Due Date: 10/2/14",
                "oldValue": "Phase: Implementation Details, Due Date: 10/6/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:44:19.456000-04:00",
                "id": 528,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Verification, Due Date: 10/3/14",
                "oldValue": "Phase: Verification, Due Date: 10/7/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:44:19.456000-04:00",
                "id": 529,
                "modifiedField": "Due Date Changed",
                "newValue": "10/3/14",
                "oldValue": "10/7/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:44:46.080000-04:00",
                "id": 530,
                "modifiedField": "Promote",
                "newValue": "Phase: Implementation Details, Owner: NOC",
                "oldValue": "Phase: Risk Assessment, Owner: IT Risk",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:44:46.080000-04:00",
                "id": 531,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Implementation Details, Due Date: 9/30/14",
                "oldValue": "Phase: Implementation Details, Due Date: 10/2/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:44:46.080000-04:00",
                "id": 532,
                "modifiedField": "Phase Revised Due Date Changed",
                "newValue": "Phase: Verification, Due Date: 10/1/14",
                "oldValue": "Phase: Verification, Due Date: 10/3/14",
                "user": "skyboxview"
            },
            {
                "date": "2014-09-29T15:44:46.080000-04:00",
                "id": 533,
                "modifiedField": "Due Date Changed",
                "newValue": "10/1/14",
                "oldValue": "10/3/14",
                "user": "skyboxview"
            },
            {
                "date": "2015-04-15T15:54:52.288000-04:00",
                "id": 786,
                "modifiedField": "Demote",
                "newValue": "Phase: Risk Assessment, Owner: IT Risk",
                "oldValue": "Phase: Implementation Details, Owner: NOC",
                "user": "skyboxview"
            },
            {
                "date": "2015-04-15T15:54:52.288000-04:00",
                "id": 787,
                "modifiedField": "Threat Level Changed",
                "newValue": null,
                "oldValue": "Unknown",
                "user": "skyboxview"
            },
            {
                "date": "2015-04-15T15:54:52.288000-04:00",
                "id": 788,
                "modifiedField": "Access Required Changed",
                "newValue": null,
                "oldValue": "Unknown",
                "user": "skyboxview"
            },
            {
                "date": "2015-04-15T15:54:52.288000-04:00",
                "id": 789,
                "modifiedField": "Privilege Attained Changed",
                "newValue": null,
                "oldValue": "Unknown",
                "user": "skyboxview"
            },
            {
                "date": "2015-04-15T15:55:08.672000-04:00",
                "id": 790,
                "modifiedField": "Demote",
                "newValue": "Phase: Technical Details, Owner: Network Engineering",
                "oldValue": "Phase: Risk Assessment, Owner: IT Risk",
                "user": "skyboxview"
            },
            {
                "date": "2015-04-15T15:55:27.104000-04:00",
                "id": 791,
                "modifiedField": "Demote",
                "newValue": "Phase: Request, Owner: skyboxview",
                "oldValue": "Phase: Technical Details, Owner: Network Engineering",
                "user": "skyboxview"
            },
            {
                "date": "2015-04-15T15:55:56.800000-04:00",
                "id": 792,
                "modifiedField": "Title Changed",
                "newValue": "Remove access from partner to web servers",
                "oldValue": "Add access from partner to web servers",
                "user": "skyboxview"
            },
            {
                "date": "2015-04-15T15:55:56.800000-04:00",
                "id": 793,
                "modifiedField": "Description Changed",
                "newValue": "Remove access from partner to web servers",
                "oldValue": "Add access from partner to web servers",
                "user": "skyboxview"
            },
            {
                "date": "2015-04-15T15:56:20.352000-04:00",
                "id": 794,
                "modifiedField": "Change Request Added",
                "newValue": "Change Request #210: Modify Rules vlab-cisco [172.20.0.10] Remove from Service: 80/TCP, 443/TCP\n",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2015-04-15T15:56:20.352000-04:00",
                "id": 795,
                "modifiedField": "Change Request Deleted",
                "newValue": "Change Request #166: Modify Rules vlab-cisco [172.20.0.10] Remove from Service: 80/TCP, 443/TCP\n",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2017-07-31T09:28:49.408000-04:00",
                "id": 1917,
                "modifiedField": "Threat Level Changed",
                "newValue": null,
                "oldValue": "Unknown",
                "user": "skyboxview"
            },
            {
                "date": "2017-07-31T09:28:49.408000-04:00",
                "id": 1918,
                "modifiedField": "Access Required Changed",
                "newValue": null,
                "oldValue": "Unknown",
                "user": "skyboxview"
            },
            {
                "date": "2017-07-31T09:28:49.408000-04:00",
                "id": 1919,
                "modifiedField": "Privilege Attained Changed",
                "newValue": null,
                "oldValue": "Unknown",
                "user": "skyboxview"
            },
            {
                "date": "2017-07-31T09:28:49.408000-04:00",
                "id": 1920,
                "modifiedField": "Change Request Deleted",
                "newValue": "Change Request #210: Modify Rules vlab-cisco [172.20.0.10]\n Remove from Services: 80/TCP, 443/TCP\n",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2017-07-31T09:28:50.432000-04:00",
                "id": 1921,
                "modifiedField": "Change Request Added",
                "newValue": "Change Request #534: Modify Rules vlab-cisco [172.20.0.10]\n Remove from Services: 80/TCP, 443/TCP\n",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2021-07-15T10:00:19.712000-04:00",
                "id": 2353,
                "modifiedField": "Attachment Added",
                "newValue": "Screenshot 2021-07-14 at 13.32.43.png",
                "oldValue": null,
                "user": "skyboxview"
            },
            {
                "date": "2021-07-15T10:13:02.592000-04:00",
                "id": 2354,
                "modifiedField": "Attachment Added",
                "newValue": "Screenshot 2021-07-12 at 13.48.27.png",
                "oldValue": null,
                "user": "skyboxview"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|date|id|modifiedField|newValue|oldValue|user|
>|---|---|---|---|---|---|
>| 2014-05-25T14:25:25.504000-04:00 | 320 | Ticket Created | Owner: skyboxview |  | skyboxview |
>| 2014-05-25T14:25:25.504000-04:00 | 321 | Change Request Added | Change Request #134: Add Rule vlab-cisco [10.41.1.2] Source: Partner_Nets Destination: web_servers (New) Services: 80/TCP, 443/TCP  |  | skyboxview |
>| 2014-05-25T14:25:25.504000-04:00 | 322 | Change Request Added | Change Request #135: Add Rule vlab-cisco [10.41.1.2] Source: Partner_Nets Destination: web_servers (New) Services: 80/TCP, 443/TCP  |  | skyboxview |
>| 2014-05-25T14:25:25.504000-04:00 | 323 | Change Request Added | Change Request #136: New Object vlab-cisco [10.41.1.2] Address Object: 192.168.90.10-192.168.90.12 |  | skyboxview |
>| 2014-05-25T14:25:25.504000-04:00 | 324 | Change Request Added | Change Request #137: New Object vlab-cisco [10.41.1.2] Address Object: 192.168.90.10-192.168.90.12 |  | skyboxview |
>| 2014-05-25T14:25:48.032000-04:00 | 325 | Promote | Phase: Technical Details, Owner: Network Engineering | Phase: Request, Owner: skyboxview | skyboxview |
>| 2014-05-25T14:25:48.032000-04:00 | 326 | Phase Revised Due Date Changed | Phase: Technical Details, Due Date: 5/27/14 | Phase: Technical Details, Due Date:  | skyboxview |
>| 2014-05-25T14:25:48.032000-04:00 | 327 | Phase Revised Due Date Changed | Phase: Risk Assessment, Due Date: 5/29/14 | Phase: Risk Assessment, Due Date:  | skyboxview |
>| 2014-05-25T14:25:48.032000-04:00 | 328 | Phase Revised Due Date Changed | Phase: Implementation Details, Due Date: 6/2/14 | Phase: Implementation Details, Due Date:  | skyboxview |
>| 2014-05-25T14:25:48.032000-04:00 | 329 | Phase Revised Due Date Changed | Phase: Verification, Due Date: 6/3/14 | Phase: Verification, Due Date:  | skyboxview |
>| 2014-05-25T14:25:48.032000-04:00 | 330 | Due Date Changed | 6/3/14 | 6/4/14 | skyboxview |
>| 2014-05-25T14:25:48.032000-04:00 | 331 | Title Changed | Add access from partner to web servers | Add access from partner to web server | skyboxview |
>| 2014-05-25T14:25:48.032000-04:00 | 332 | Description Changed | Add access from partner to web servers | Add access from partner to web server | skyboxview |
>| 2014-05-25T14:25:58.272000-04:00 | 333 | Promote | Phase: Risk Assessment, Owner: IT Risk | Phase: Technical Details, Owner: Network Engineering | skyboxview |
>| 2014-05-25T14:25:58.272000-04:00 | 334 | Phase Revised Due Date Changed | Phase: Risk Assessment, Due Date: 5/27/14 | Phase: Risk Assessment, Due Date: 5/29/14 | skyboxview |
>| 2014-05-25T14:25:58.272000-04:00 | 335 | Phase Revised Due Date Changed | Phase: Implementation Details, Due Date: 5/29/14 | Phase: Implementation Details, Due Date: 6/2/14 | skyboxview |
>| 2014-05-25T14:25:58.272000-04:00 | 336 | Phase Revised Due Date Changed | Phase: Verification, Due Date: 5/30/14 | Phase: Verification, Due Date: 6/3/14 | skyboxview |
>| 2014-05-25T14:25:58.272000-04:00 | 337 | Due Date Changed | 5/30/14 | 6/3/14 | skyboxview |
>| 2014-05-25T14:26:03.392000-04:00 | 338 | Promote | Phase: Implementation Details, Owner: NOC | Phase: Risk Assessment, Owner: IT Risk | skyboxview |
>| 2014-05-25T14:26:03.392000-04:00 | 339 | Phase Revised Due Date Changed | Phase: Implementation Details, Due Date: 5/27/14 | Phase: Implementation Details, Due Date: 5/29/14 | skyboxview |
>| 2014-05-25T14:26:03.392000-04:00 | 340 | Phase Revised Due Date Changed | Phase: Verification, Due Date: 5/28/14 | Phase: Verification, Due Date: 5/30/14 | skyboxview |
>| 2014-05-25T14:26:03.392000-04:00 | 341 | Due Date Changed | 5/28/14 | 5/30/14 | skyboxview |
>| 2014-09-14T17:42:09.152000-04:00 | 417 | Demote | Phase: Risk Assessment, Owner: IT Risk | Phase: Implementation Details, Owner: NOC | skyboxview |
>| 2014-09-14T17:42:09.152000-04:00 | 418 | Threat Level Changed |  | Unknown | skyboxview |
>| 2014-09-14T17:42:09.152000-04:00 | 419 | Access Required Changed |  | Unknown | skyboxview |
>| 2014-09-14T17:42:09.152000-04:00 | 420 | Privilege Attained Changed |  | Unknown | skyboxview |
>| 2014-09-14T17:42:15.296000-04:00 | 421 | Demote | Phase: Technical Details, Owner: Network Engineering | Phase: Risk Assessment, Owner: IT Risk | skyboxview |
>| 2014-09-14T17:42:23.488000-04:00 | 422 | Demote | Phase: Request, Owner: skyboxview | Phase: Technical Details, Owner: Network Engineering | skyboxview |
>| 2014-09-14T17:44:52.992000-04:00 | 423 | Promote | Phase: Technical Details, Owner: Network Engineering | Phase: Request, Owner: skyboxview | skyboxview |
>| 2014-09-14T17:44:52.992000-04:00 | 424 | Phase Revised Due Date Changed | Phase: Technical Details, Due Date: 9/16/14 | Phase: Technical Details, Due Date: 5/27/14 | skyboxview |
>| 2014-09-14T17:44:52.992000-04:00 | 425 | Phase Revised Due Date Changed | Phase: Risk Assessment, Due Date: 9/18/14 | Phase: Risk Assessment, Due Date: 5/27/14 | skyboxview |
>| 2014-09-14T17:44:52.992000-04:00 | 426 | Phase Revised Due Date Changed | Phase: Implementation Details, Due Date: 9/22/14 | Phase: Implementation Details, Due Date: 5/27/14 | skyboxview |
>| 2014-09-14T17:44:52.992000-04:00 | 427 | Phase Revised Due Date Changed | Phase: Verification, Due Date: 9/23/14 | Phase: Verification, Due Date: 5/28/14 | skyboxview |
>| 2014-09-14T17:44:52.992000-04:00 | 428 | Due Date Changed | 9/23/14 | 5/28/14 | skyboxview |
>| 2014-09-14T17:44:52.992000-04:00 | 429 | Change Request Added | Change Request #147: Require Access  Source: Partner_Nets Destination: web_servers (New) Services: 80/TCP, 443/TCP  |  | skyboxview |
>| 2014-09-14T17:44:52.992000-04:00 | 430 | Change Request Added | Change Request #148: Add Rule main_FW Source: Partner_Nets Destination: web_servers (New) Services: 80/TCP, 443/TCP  |  | skyboxview |
>| 2014-09-14T17:44:52.992000-04:00 | 431 | Change Request Added | Change Request #149: Add Rule Partner1 FW Source: Partner_Nets Destination: web_servers (New) Services: 80/TCP, 443/TCP  |  | skyboxview |
>| 2014-09-14T17:44:52.992000-04:00 | 432 | Change Request Added | Change Request #150: New Object  Address Object: 192.168.90.10-192.168.90.12 |  | skyboxview |
>| 2014-09-14T17:44:52.992000-04:00 | 433 | Change Request Added | Change Request #151: New Object US_NY_CMA01 Address Object: 192.168.90.10-192.168.90.12 |  | skyboxview |
>| 2014-09-14T17:44:52.992000-04:00 | 434 | Change Request Added | Change Request #152: New Object  Address Object: 192.168.90.10-192.168.90.12 |  | skyboxview |
>| 2014-09-14T17:44:52.992000-04:00 | 435 | Change Request Deleted | Change Request #134: Add Rule vlab-cisco [10.41.1.2] Source: Partner_Nets Destination: web_servers (New) Services: 80/TCP, 443/TCP  |  | skyboxview |
>| 2014-09-14T17:44:52.992000-04:00 | 436 | Change Request Deleted | Change Request #135: Add Rule vlab-cisco [10.41.1.2] Source: Partner_Nets Destination: web_servers (New) Services: 80/TCP, 443/TCP  |  | skyboxview |
>| 2014-09-14T17:44:52.992000-04:00 | 437 | Change Request Deleted | Change Request #136: New Object vlab-cisco [10.41.1.2] Address Object: 192.168.90.10-192.168.90.12 |  | skyboxview |
>| 2014-09-14T17:44:52.992000-04:00 | 438 | Change Request Deleted | Change Request #137: New Object vlab-cisco [10.41.1.2] Address Object: 192.168.90.10-192.168.90.12 |  | skyboxview |
>| 2014-09-14T17:45:48.288000-04:00 | 439 | Promote | Phase: Risk Assessment, Owner: IT Risk | Phase: Technical Details, Owner: Network Engineering | skyboxview |
>| 2014-09-14T17:45:48.288000-04:00 | 440 | Phase Revised Due Date Changed | Phase: Risk Assessment, Due Date: 9/16/14 | Phase: Risk Assessment, Due Date: 9/18/14 | skyboxview |
>| 2014-09-14T17:45:48.288000-04:00 | 441 | Phase Revised Due Date Changed | Phase: Implementation Details, Due Date: 9/18/14 | Phase: Implementation Details, Due Date: 9/22/14 | skyboxview |
>| 2014-09-14T17:45:48.288000-04:00 | 442 | Phase Revised Due Date Changed | Phase: Verification, Due Date: 9/19/14 | Phase: Verification, Due Date: 9/23/14 | skyboxview |
>| 2014-09-14T17:45:48.288000-04:00 | 443 | Due Date Changed | 9/19/14 | 9/23/14 | skyboxview |
>| 2014-09-14T17:51:58.976000-04:00 | 444 | Promote | Phase: Implementation Details, Owner: NOC | Phase: Risk Assessment, Owner: IT Risk | skyboxview |
>| 2014-09-14T17:51:58.976000-04:00 | 445 | Phase Revised Due Date Changed | Phase: Implementation Details, Due Date: 9/16/14 | Phase: Implementation Details, Due Date: 9/18/14 | skyboxview |
>| 2014-09-14T17:51:58.976000-04:00 | 446 | Phase Revised Due Date Changed | Phase: Verification, Due Date: 9/17/14 | Phase: Verification, Due Date: 9/19/14 | skyboxview |
>| 2014-09-14T17:51:58.976000-04:00 | 447 | Due Date Changed | 9/17/14 | 9/19/14 | skyboxview |
>| 2014-09-14T17:51:58.976000-04:00 | 448 | Change Request Approved | Change Request #148 Add Rule approved until 12/14/14 |  | skyboxview |
>| 2014-09-14T17:51:58.976000-04:00 | 449 | Approve Risk Assessments | Approved following change requests:<br/>   Add Rule  firewall main_FW | No risks were accepted | skyboxview |
>| 2014-09-29T15:25:40.224000-04:00 | 469 | Demote | Phase: Risk Assessment, Owner: IT Risk | Phase: Implementation Details, Owner: NOC | skyboxview |
>| 2014-09-29T15:25:40.224000-04:00 | 470 | Threat Level Changed |  | Unknown | skyboxview |
>| 2014-09-29T15:25:40.224000-04:00 | 471 | Access Required Changed |  | Unknown | skyboxview |
>| 2014-09-29T15:25:40.224000-04:00 | 472 | Privilege Attained Changed |  | Unknown | skyboxview |
>| 2014-09-29T15:25:46.368000-04:00 | 473 | Demote | Phase: Technical Details, Owner: Network Engineering | Phase: Risk Assessment, Owner: IT Risk | skyboxview |
>| 2014-09-29T15:25:54.560000-04:00 | 474 | Demote | Phase: Request, Owner: skyboxview | Phase: Technical Details, Owner: Network Engineering | skyboxview |
>| 2014-09-29T15:26:08.896000-04:00 | 475 | Promote | Phase: Technical Details, Owner: Network Engineering | Phase: Request, Owner: skyboxview | skyboxview |
>| 2014-09-29T15:26:08.896000-04:00 | 476 | Phase Revised Due Date Changed | Phase: Technical Details, Due Date: 9/30/14 | Phase: Technical Details, Due Date: 9/16/14 | skyboxview |
>| 2014-09-29T15:26:08.896000-04:00 | 477 | Phase Revised Due Date Changed | Phase: Risk Assessment, Due Date: 10/2/14 | Phase: Risk Assessment, Due Date: 9/16/14 | skyboxview |
>| 2014-09-29T15:26:08.896000-04:00 | 478 | Phase Revised Due Date Changed | Phase: Implementation Details, Due Date: 10/6/14 | Phase: Implementation Details, Due Date: 9/16/14 | skyboxview |
>| 2014-09-29T15:26:08.896000-04:00 | 479 | Phase Revised Due Date Changed | Phase: Verification, Due Date: 10/7/14 | Phase: Verification, Due Date: 9/17/14 | skyboxview |
>| 2014-09-29T15:26:08.896000-04:00 | 480 | Due Date Changed | 10/7/14 | 9/17/14 | skyboxview |
>| 2014-09-29T15:26:23.232000-04:00 | 481 | Demote | Phase: Request, Owner: skyboxview | Phase: Technical Details, Owner: Network Engineering | skyboxview |
>| 2014-09-29T15:27:26.720000-04:00 | 482 | Promote | Phase: Technical Details, Owner: Network Engineering | Phase: Request, Owner: skyboxview | skyboxview |
>| 2014-09-29T15:27:26.720000-04:00 | 483 | Change Request Modified | Change Request #147: Require Access  Source: PAT-INTERNETTR Destination: web_servers (New) Services: 80/TCP, 443/TCP  | Change Request #147: Require Access  Source: Partner_Nets Destination: web_servers (New) Services: 80/TCP, 443/TCP  | skyboxview |
>| 2014-09-29T15:27:26.720000-04:00 | 484 | Change Request Added | Change Request #159: New Object  Address Object: 192.168.90.10-192.168.90.12 |  | skyboxview |
>| 2014-09-29T15:27:26.720000-04:00 | 485 | Change Request Deleted | Change Request #148: Add Rule main_FW Source: Partner_Nets Destination: web_servers (New) Services: 80/TCP, 443/TCP  |  | skyboxview |
>| 2014-09-29T15:27:26.720000-04:00 | 486 | Change Request Deleted | Change Request #149: Add Rule Partner1 FW Source: Partner_Nets Destination: web_servers (New) Services: 80/TCP, 443/TCP  |  | skyboxview |
>| 2014-09-29T15:27:26.720000-04:00 | 487 | Change Request Deleted | Change Request #150: New Object  Address Object: 192.168.90.10-192.168.90.12 |  | skyboxview |
>| 2014-09-29T15:27:26.720000-04:00 | 488 | Change Request Deleted | Change Request #151: New Object US_NY_CMA01 Address Object: 192.168.90.10-192.168.90.12 |  | skyboxview |
>| 2014-09-29T15:27:26.720000-04:00 | 489 | Change Request Deleted | Change Request #152: New Object  Address Object: 192.168.90.10-192.168.90.12 |  | skyboxview |
>| 2014-09-29T15:27:26.720000-04:00 | 490 | Approve Risk Assessments | No risks were accepted | Approved following change requests:<br/>   Add Rule  firewall main_FW | skyboxview |
>| 2014-09-29T15:29:09.120000-04:00 | 491 | Demote | Phase: Request, Owner: skyboxview | Phase: Technical Details, Owner: Network Engineering | skyboxview |
>| 2014-09-29T15:30:33.088000-04:00 | 492 | Promote | Phase: Technical Details, Owner: Network Engineering | Phase: Request, Owner: skyboxview | skyboxview |
>| 2014-09-29T15:30:33.088000-04:00 | 493 | Change Request Modified | Change Request #147: Require Access  Source: PAT-INTERNETTR Destination: 192.168.200.0/24 Services: 80/TCP, 443/TCP  | Change Request #147: Require Access  Source: PAT-INTERNETTR Destination: web_servers (New) Services: 80/TCP, 443/TCP  | skyboxview |
>| 2014-09-29T15:30:33.088000-04:00 | 494 | Change Request Deleted | Change Request #159: New Object  Address Object: 192.168.90.10-192.168.90.12 |  | skyboxview |
>| 2014-09-29T15:34:34.752000-04:00 | 495 | Demote | Phase: Request, Owner: skyboxview | Phase: Technical Details, Owner: Network Engineering | skyboxview |
>| 2014-09-29T15:34:34.752000-04:00 | 496 | Change Request Added | Change Request #160: Add Rule vlab-cisco Source: PAT-INTERNETTR Destination: 192.168.200.0/24 Services: 80/TCP, 443/TCP  |  | skyboxview |
>| 2014-09-29T15:35:37.216000-04:00 | 497 | Promote | Phase: Technical Details, Owner: Network Engineering | Phase: Request, Owner: skyboxview | skyboxview |
>| 2014-09-29T15:35:37.216000-04:00 | 498 | Change Request Modified | Change Request #147: Require Access  Source: PAT-INTERNETTR Destination: 10.101.50.20 Services: 80/TCP, 443/TCP  | Change Request #147: Require Access  Source: PAT-INTERNETTR Destination: 192.168.200.0/24 Services: 80/TCP, 443/TCP  | skyboxview |
>| 2014-09-29T15:35:37.216000-04:00 | 499 | Change Request Added | Change Request #161: Add Rule vlab-cisco Source: PAT-INTERNETTR Destination: 10.101.50.20 Services: 80/TCP, 443/TCP  |  | skyboxview |
>| 2014-09-29T15:35:37.216000-04:00 | 500 | Change Request Deleted | Change Request #160: Add Rule vlab-cisco Source: PAT-INTERNETTR Destination: 192.168.200.0/24 Services: 80/TCP, 443/TCP  |  | skyboxview |
>| 2014-09-29T15:37:26.784000-04:00 | 501 | Demote | Phase: Request, Owner: skyboxview | Phase: Technical Details, Owner: Network Engineering | skyboxview |
>| 2014-09-29T15:38:54.848000-04:00 | 502 | Promote | Phase: Technical Details, Owner: Network Engineering | Phase: Request, Owner: skyboxview | skyboxview |
>| 2014-09-29T15:38:55.872000-04:00 | 503 | Change Request Modified | Change Request #147: Require Access  Source: 2.2.2.2 Destination: 5.5.5.7 Services: 80/TCP, 443/TCP  | Change Request #147: Require Access  Source: PAT-INTERNETTR Destination: 10.101.50.20 Services: 80/TCP, 443/TCP  | skyboxview |
>| 2014-09-29T15:38:55.872000-04:00 | 504 | Change Request Deleted | Change Request #161: Add Rule vlab-cisco Source: PAT-INTERNETTR Destination: 10.101.50.20 Services: 80/TCP, 443/TCP  |  | skyboxview |
>| 2014-09-29T15:39:25.568000-04:00 | 505 | Demote | Phase: Request, Owner: skyboxview | Phase: Technical Details, Owner: Network Engineering | skyboxview |
>| 2014-09-29T15:40:46.464000-04:00 | 506 | Promote | Phase: Technical Details, Owner: Network Engineering | Phase: Request, Owner: skyboxview | skyboxview |
>| 2014-09-29T15:40:46.464000-04:00 | 507 | Change Request Added | Change Request #162: Modify Rules vlab-cisco [172.20.0.10] Add to Source: 1.2.3.4  |  | skyboxview |
>| 2014-09-29T15:40:46.464000-04:00 | 508 | Change Request Added | Change Request #163: Modify Rules vlab-cisco [172.20.0.10] Add to Source: 1.2.3.4  |  | skyboxview |
>| 2014-09-29T15:40:46.464000-04:00 | 509 | Change Request Deleted | Change Request #147: Require Access  Source: 2.2.2.2 Destination: 5.5.5.7 Services: 80/TCP, 443/TCP  |  | skyboxview |
>| 2014-09-29T15:41:27.424000-04:00 | 510 | Demote | Phase: Request, Owner: skyboxview | Phase: Technical Details, Owner: Network Engineering | skyboxview |
>| 2014-09-29T15:41:59.168000-04:00 | 511 | Promote | Phase: Technical Details, Owner: Network Engineering | Phase: Request, Owner: skyboxview | skyboxview |
>| 2014-09-29T15:41:59.168000-04:00 | 512 | Change Request Modified | Change Request #162: Modify Rules vlab-cisco [172.20.0.10] Add to Source: 1.2.3.4, 221.221.221.221  | Change Request #162: Modify Rules vlab-cisco [172.20.0.10] Add to Source: 1.2.3.4  | skyboxview |
>| 2014-09-29T15:41:59.168000-04:00 | 513 | Change Request Added | Change Request #164: Modify Rules vlab-cisco [172.20.0.10] Add to Source: 1.2.3.4, 221.221.221.221  |  | skyboxview |
>| 2014-09-29T15:41:59.168000-04:00 | 514 | Change Request Deleted | Change Request #163: Modify Rules vlab-cisco [172.20.0.10] Add to Source: 1.2.3.4  |  | skyboxview |
>| 2014-09-29T15:42:35.008000-04:00 | 515 | Demote | Phase: Request, Owner: skyboxview | Phase: Technical Details, Owner: Network Engineering | skyboxview |
>| 2014-09-29T15:43:22.112000-04:00 | 516 | Promote | Phase: Technical Details, Owner: Network Engineering | Phase: Request, Owner: skyboxview | skyboxview |
>| 2014-09-29T15:43:22.112000-04:00 | 517 | Change Request Modified | Change Request #162: Modify Rules vlab-cisco [172.20.0.10] Add to Service: 80/TCP, 443/TCP  | Change Request #162: Modify Rules vlab-cisco [172.20.0.10] Add to Source: 1.2.3.4, 221.221.221.221  | skyboxview |
>| 2014-09-29T15:43:22.112000-04:00 | 518 | Change Request Added | Change Request #165: Modify Rules vlab-cisco [172.20.0.10] Add to Service: 80/TCP, 443/TCP  |  | skyboxview |
>| 2014-09-29T15:43:22.112000-04:00 | 519 | Change Request Deleted | Change Request #164: Modify Rules vlab-cisco [172.20.0.10] Add to Source: 1.2.3.4, 221.221.221.221  |  | skyboxview |
>| 2014-09-29T15:43:46.688000-04:00 | 520 | Demote | Phase: Request, Owner: skyboxview | Phase: Technical Details, Owner: Network Engineering | skyboxview |
>| 2014-09-29T15:44:08.192000-04:00 | 521 | Promote | Phase: Technical Details, Owner: Network Engineering | Phase: Request, Owner: skyboxview | skyboxview |
>| 2014-09-29T15:44:08.192000-04:00 | 522 | Change Request Modified | Change Request #162: Modify Rules vlab-cisco [172.20.0.10] Remove from Service: 80/TCP, 443/TCP  | Change Request #162: Modify Rules vlab-cisco [172.20.0.10] Add to Service: 80/TCP, 443/TCP  | skyboxview |
>| 2014-09-29T15:44:08.192000-04:00 | 523 | Change Request Added | Change Request #166: Modify Rules vlab-cisco [172.20.0.10] Remove from Service: 80/TCP, 443/TCP  |  | skyboxview |
>| 2014-09-29T15:44:08.192000-04:00 | 524 | Change Request Deleted | Change Request #165: Modify Rules vlab-cisco [172.20.0.10] Add to Service: 80/TCP, 443/TCP  |  | skyboxview |
>| 2014-09-29T15:44:19.456000-04:00 | 525 | Promote | Phase: Risk Assessment, Owner: IT Risk | Phase: Technical Details, Owner: Network Engineering | skyboxview |
>| 2014-09-29T15:44:19.456000-04:00 | 526 | Phase Revised Due Date Changed | Phase: Risk Assessment, Due Date: 9/30/14 | Phase: Risk Assessment, Due Date: 10/2/14 | skyboxview |
>| 2014-09-29T15:44:19.456000-04:00 | 527 | Phase Revised Due Date Changed | Phase: Implementation Details, Due Date: 10/2/14 | Phase: Implementation Details, Due Date: 10/6/14 | skyboxview |
>| 2014-09-29T15:44:19.456000-04:00 | 528 | Phase Revised Due Date Changed | Phase: Verification, Due Date: 10/3/14 | Phase: Verification, Due Date: 10/7/14 | skyboxview |
>| 2014-09-29T15:44:19.456000-04:00 | 529 | Due Date Changed | 10/3/14 | 10/7/14 | skyboxview |
>| 2014-09-29T15:44:46.080000-04:00 | 530 | Promote | Phase: Implementation Details, Owner: NOC | Phase: Risk Assessment, Owner: IT Risk | skyboxview |
>| 2014-09-29T15:44:46.080000-04:00 | 531 | Phase Revised Due Date Changed | Phase: Implementation Details, Due Date: 9/30/14 | Phase: Implementation Details, Due Date: 10/2/14 | skyboxview |
>| 2014-09-29T15:44:46.080000-04:00 | 532 | Phase Revised Due Date Changed | Phase: Verification, Due Date: 10/1/14 | Phase: Verification, Due Date: 10/3/14 | skyboxview |
>| 2014-09-29T15:44:46.080000-04:00 | 533 | Due Date Changed | 10/1/14 | 10/3/14 | skyboxview |
>| 2015-04-15T15:54:52.288000-04:00 | 786 | Demote | Phase: Risk Assessment, Owner: IT Risk | Phase: Implementation Details, Owner: NOC | skyboxview |
>| 2015-04-15T15:54:52.288000-04:00 | 787 | Threat Level Changed |  | Unknown | skyboxview |
>| 2015-04-15T15:54:52.288000-04:00 | 788 | Access Required Changed |  | Unknown | skyboxview |
>| 2015-04-15T15:54:52.288000-04:00 | 789 | Privilege Attained Changed |  | Unknown | skyboxview |
>| 2015-04-15T15:55:08.672000-04:00 | 790 | Demote | Phase: Technical Details, Owner: Network Engineering | Phase: Risk Assessment, Owner: IT Risk | skyboxview |
>| 2015-04-15T15:55:27.104000-04:00 | 791 | Demote | Phase: Request, Owner: skyboxview | Phase: Technical Details, Owner: Network Engineering | skyboxview |
>| 2015-04-15T15:55:56.800000-04:00 | 792 | Title Changed | Remove access from partner to web servers | Add access from partner to web servers | skyboxview |
>| 2015-04-15T15:55:56.800000-04:00 | 793 | Description Changed | Remove access from partner to web servers | Add access from partner to web servers | skyboxview |
>| 2015-04-15T15:56:20.352000-04:00 | 794 | Change Request Added | Change Request #210: Modify Rules vlab-cisco [172.20.0.10] Remove from Service: 80/TCP, 443/TCP<br/> |  | skyboxview |
>| 2015-04-15T15:56:20.352000-04:00 | 795 | Change Request Deleted | Change Request #166: Modify Rules vlab-cisco [172.20.0.10] Remove from Service: 80/TCP, 443/TCP<br/> |  | skyboxview |
>| 2017-07-31T09:28:49.408000-04:00 | 1917 | Threat Level Changed |  | Unknown | skyboxview |
>| 2017-07-31T09:28:49.408000-04:00 | 1918 | Access Required Changed |  | Unknown | skyboxview |
>| 2017-07-31T09:28:49.408000-04:00 | 1919 | Privilege Attained Changed |  | Unknown | skyboxview |
>| 2017-07-31T09:28:49.408000-04:00 | 1920 | Change Request Deleted | Change Request #210: Modify Rules vlab-cisco [172.20.0.10]<br/> Remove from Services: 80/TCP, 443/TCP<br/> |  | skyboxview |
>| 2017-07-31T09:28:50.432000-04:00 | 1921 | Change Request Added | Change Request #534: Modify Rules vlab-cisco [172.20.0.10]<br/> Remove from Services: 80/TCP, 443/TCP<br/> |  | skyboxview |
>| 2021-07-15T10:00:19.712000-04:00 | 2353 | Attachment Added | Screenshot 2021-07-14 at 13.32.43.png |  | skyboxview |
>| 2021-07-15T10:13:02.592000-04:00 | 2354 | Attachment Added | Screenshot 2021-07-12 at 13.48.27.png |  | skyboxview |


### skybox-getChangeRequestReviewers
***
Retriev the Change Request Reviewers


#### Base Command

`skybox-getChangeRequestReviewers`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ticket ID. | Required | 
| changeRequestId | The change request IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getChangeRequestReviewers | String | The change request reviewers | 


#### Command Example
```!skybox-getChangeRequestReviewers ticketId="395" changeRequestId="227"```

#### Human Readable Output

>null

### skybox-getChangeRequestRuleAttributes
***
Retrieves the rule attributes for the access rule in
a change request.


#### Base Command

`skybox-getChangeRequestRuleAttributes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ticket ID. | Required | 
| changeRequestId | The change request ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getChangeRequestRuleAttributes | String | The change request rule attributes | 


#### Command Example
```!skybox-getChangeRequestRuleAttributes ticketId=484 changeRequestId=626```

#### Context Example
```json
{
    "Skybox": {
        "getChangeRequestRuleAttributes": {
            "businessFunction": null,
            "comment": null,
            "customFields": [],
            "email": null,
            "nextReviewDate": null,
            "owner": null,
            "status": "NONE",
            "ticketId": null
        }
    }
}
```

#### Human Readable Output

>### Results
>|businessFunction|comment|customFields|email|nextReviewDate|owner|status|ticketId|
>|---|---|---|---|---|---|---|---|
>|  |  |  |  |  |  | NONE |  |


### skybox-getGeneratedCommands
***
Retrieves the generated command output for the
given change request. For Cisco firewalls, the
command is in Cisco format. For other firewalls,
the command is in a generic format.


#### Base Command

`skybox-getGeneratedCommands`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ticket ID. | Required | 
| changeRequestId | The change request ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getGeneratedCommands | String | The generated commands | 


#### Command Example
```!skybox-getGeneratedCommands ticketId=484 changeRequestId=626```

#### Human Readable Output

>null

### skybox-getImplementedChangeRequests
***
Retrieves the list of implemented change requests
in Skybox Change Manager according to the
permissions of the user sending the request.


#### Base Command

`skybox-getImplementedChangeRequests`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getImplementedChangeRequests | String | The implemented change requests | 


#### Command Example
```!skybox-getImplementedChangeRequests```

#### Context Example
```json
{
    "Skybox": {
        "getImplementedChangeRequests": [
            {
                "additionalDetails": "Suggested Position: Last Rule\nRule Logging\n",
                "changeDetails": "Source: app0\nDestination: Partners_Networks\nServices: sqlnet1\n",
                "changeType": "ADD_RULE",
                "comment": "Implemented by Skybox Change Manager",
                "completeDate": "2016-10-02T04:50:03-04:00",
                "completeStatus": "PROVISIONED",
                "dueDate": "2017-08-01T23:58:58.048000-04:00",
                "firewallManagementName": "US_NY_CMA01",
                "firewallName": "main_FW",
                "globalUniqueId": null,
                "id": 253,
                "implementationStatus": "FALSE",
                "isRequiredStatus": "TRUE",
                "lastModificationTime": "2017-07-31T16:56:28.928000-04:00",
                "objectId": "-",
                "owner": "NOC",
                "ticketId": 376,
                "ticketPriority": "P2",
                "workflowName": "General"
            },
            {
                "additionalDetails": "Suggested Position: Last Rule\nRule Logging\n",
                "changeDetails": "Source: app0\nDestination: Partners_Networks\nServices: sqlnet1\n",
                "changeType": "ADD_RULE",
                "comment": "Implemented by Skybox Change Manager",
                "completeDate": "2016-10-02T04:50:03-04:00",
                "completeStatus": "PROVISIONED",
                "dueDate": "2017-08-01T23:58:58.048000-04:00",
                "firewallManagementName": "US_NY_CMA01",
                "firewallName": "prod FW",
                "globalUniqueId": null,
                "id": 254,
                "implementationStatus": "FALSE",
                "isRequiredStatus": "TRUE",
                "lastModificationTime": "2017-07-31T16:56:28.928000-04:00",
                "objectId": "-",
                "owner": "NOC",
                "ticketId": 376,
                "ticketPriority": "P2",
                "workflowName": "General"
            },
            {
                "additionalDetails": "Suggested Position: Last Rule\nRule Logging\n",
                "changeDetails": "Source: app0\nDestination: Partners_Networks\nServices: Service_1521_TCP (New)\n",
                "changeType": "ADD_RULE",
                "comment": "Implemented by Skybox Change Manager",
                "completeDate": "2016-10-02T04:50:03-04:00",
                "completeStatus": "PROVISIONED",
                "dueDate": "2017-08-01T23:58:58.048000-04:00",
                "firewallManagementName": null,
                "firewallName": "Partner1 FW",
                "globalUniqueId": null,
                "id": 255,
                "implementationStatus": "FALSE",
                "isRequiredStatus": "TRUE",
                "lastModificationTime": "2017-07-31T16:56:28.928000-04:00",
                "objectId": "-",
                "owner": "NOC",
                "ticketId": 376,
                "ticketPriority": "P2",
                "workflowName": "General"
            },
            {
                "additionalDetails": null,
                "changeDetails": "Service Object: 1521/TCP",
                "changeType": "ADD_OBJECT",
                "comment": "Implemented by Skybox Change Manager",
                "completeDate": "2016-10-02T04:50:03-04:00",
                "completeStatus": "PROVISIONED",
                "dueDate": "2017-08-01T23:58:58.048000-04:00",
                "firewallManagementName": null,
                "firewallName": "Partner1 FW",
                "globalUniqueId": null,
                "id": 256,
                "implementationStatus": "FALSE",
                "isRequiredStatus": "TRUE",
                "lastModificationTime": "2017-07-31T16:56:28.928000-04:00",
                "objectId": "Service_1521_TCP",
                "owner": "NOC",
                "ticketId": 376,
                "ticketPriority": "P2",
                "workflowName": "General"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|additionalDetails|changeDetails|changeType|comment|completeDate|completeStatus|dueDate|firewallManagementName|firewallName|globalUniqueId|id|implementationStatus|isRequiredStatus|lastModificationTime|objectId|owner|ticketId|ticketPriority|workflowName|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Suggested Position: Last Rule<br/>Rule Logging<br/> | Source: app0<br/>Destination: Partners_Networks<br/>Services: sqlnet1<br/> | ADD_RULE | Implemented by Skybox Change Manager | 2016-10-02T04:50:03-04:00 | PROVISIONED | 2017-08-01T23:58:58.048000-04:00 | US_NY_CMA01 | main_FW |  | 253 | FALSE | TRUE | 2017-07-31T16:56:28.928000-04:00 | - | NOC | 376 | P2 | General |
>| Suggested Position: Last Rule<br/>Rule Logging<br/> | Source: app0<br/>Destination: Partners_Networks<br/>Services: sqlnet1<br/> | ADD_RULE | Implemented by Skybox Change Manager | 2016-10-02T04:50:03-04:00 | PROVISIONED | 2017-08-01T23:58:58.048000-04:00 | US_NY_CMA01 | prod FW |  | 254 | FALSE | TRUE | 2017-07-31T16:56:28.928000-04:00 | - | NOC | 376 | P2 | General |
>| Suggested Position: Last Rule<br/>Rule Logging<br/> | Source: app0<br/>Destination: Partners_Networks<br/>Services: Service_1521_TCP (New)<br/> | ADD_RULE | Implemented by Skybox Change Manager | 2016-10-02T04:50:03-04:00 | PROVISIONED | 2017-08-01T23:58:58.048000-04:00 |  | Partner1 FW |  | 255 | FALSE | TRUE | 2017-07-31T16:56:28.928000-04:00 | - | NOC | 376 | P2 | General |
>|  | Service Object: 1521/TCP | ADD_OBJECT | Implemented by Skybox Change Manager | 2016-10-02T04:50:03-04:00 | PROVISIONED | 2017-08-01T23:58:58.048000-04:00 |  | Partner1 FW |  | 256 | FALSE | TRUE | 2017-07-31T16:56:28.928000-04:00 | Service_1521_TCP | NOC | 376 | P2 | General |


### skybox-operateOnVulnerabilityDefinitionTicket
***
Enables you to change the phase of a Vulnerability
Definition ticket without sending the full ticket
data.


#### Base Command

`skybox-operateOnVulnerabilityDefinitionTicket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ticket ID. | Required | 
| phaseOperation_phaseId | The phase ID. | Optional | 
| phaseOperation_phaseOwner | The phase owner. | Optional | 
| phaseOperation_reject | The phase operation reject. | Optional | 
| phaseOperation_type | Possible values:<br/>l ACCEPT<br/>l CHANGE_PHASE<br/>l CLOSE<br/>l DEMOTE<br/>l IGNORED<br/>l PROMOTE<br/>l REASSIGN<br/>l REOPEN<br/>l REQUEST_TO_CLOSE. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.operateOnVulnerabilityDefinitionTicket | String | The change status of the vulnerability definition ticket | 


#### Command Example
```!skybox-operateOnVulnerabilityDefinitionTicket phaseOperation_type=ACCEPT ticketId=484 phaseOperation_phaseId=1 phaseOperation_reject=Ignored```

#### Human Readable Output

>null

### skybox-createChangeManagerTicket
***
Creates an Access Change ticket with a workflow
and phases.


#### Base Command

`skybox-createChangeManagerTicket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| accessChangeTicket_id | The change ticket ID. | Optional | 
| accessChangeTicket_comment | The change ticket comment. Default is The change ticket comment. | Optional | 
| accessChangeTicket_description | The change ticket description. | Optional | 
| accessChangeTicket_createdBy | The change ticket author. | Optional | 
| accessChangeTicket_creationTime | The change ticket creation time. | Optional | 
| accessChangeTicket_lastModifiedBy | The change ticket modification author. | Optional | 
| accessChangeTicket_lastModificationTime | The change ticket last modification time. | Optional | 
| accessChangeTicket_externalTicketId | The external ticket ID. | Optional | 
| accessChangeTicket_externalTicketStatus | Possible values:<br/>l Pending<br/>l Open<br/>l Closed<br/>l Error<br/>l Rejected. | Optional | 
| accessChangeTicket_status | Possible values:<br/>l New<br/>l InProgress<br/>l Resolved<br/>l Closed<br/>l Rejected<br/>l Ignored<br/>l Verified<br/>l Reopened<br/>l Demoted. | Optional | 
| accessChangeTicket_title | The change ticket title. | Optional | 
| accessChangeTicket_changeDetails | The change ticket details. | Optional | 
| accessChangeTicket_priority | The change ticket priority.<br/>Possible values:<br/>l P1<br/>l P2<br/>l P3<br/>l P4<br/>l P5. | Optional | 
| accessChangeTicket_owner | The change ticket owner. | Optional | 
| accessChangeTicket_dueDate | The change ticket due date. | Optional | 
| accessChangeTicket_doneDate | The change ticket done date. | Optional | 
| accessChangeTicket_likelihood | Possible values:<br/>l Unknown<br/>l Low<br/>l Medium<br/>l High<br/>l Priority<br/>l Critica. | Optional | 
| accessChangeTicket_ccList_email | The CC list email address. | Optional | 
| accessChangeTicket_ccList_userName | The CC List user name. | Optional | 
| accessChangeTicket_customFields_comment | The custom field comment. | Optional | 
| accessChangeTicket_customFields_createdBy | The custom field creation author. | Optional | 
| accessChangeTicket_customFields_creationTime | The custom field creation time. | Optional | 
| accessChangeTicket_customFields_description | The custom field description. | Optional | 
| accessChangeTicket_customFields_id | The custom field ID. | Optional | 
| accessChangeTicket_customFields_lastModificationTime | The custom field last modification time. | Optional | 
| accessChangeTicket_customFields_lastModifiedBy | The custom field last modification author. | Optional | 
| accessChangeTicket_customFields_name | The custom field name. | Optional | 
| accessChangeTicket_customFields_typeCode | The custom field type code. | Optional | 
| accessChangeTicket_customFields_value | The custom field value. | Optional | 
| accessChangeTicket_currentPhaseName | The current phase name. | Optional | 
| phases_comment | The phase comment. | Optional | 
| phases_createdBy | The phase author. | Optional | 
| phases_creationTime | The phase creation time. | Optional | 
| phases_current | The current phase. | Optional | 
| phases_demotionsCount | The phase demotions count. | Optional | 
| phases_description | The phase description. | Optional | 
| phases_dueDate | The phase due date. | Optional | 
| phases_endDate | The phase end date. | Optional | 
| phases_id | The phase ID. | Optional | 
| phases_lastModificationTime | The phase last modification time. | Optional | 
| phases_lastModifiedBy | The phase last modification author. | Optional | 
| phases_owner | The phase owner. | Optional | 
| phases_revisedDueDate | The phase revised due date. | Optional | 
| phases_startDate | The phase start date. | Optional | 
| phases_ticketTypePhase_defaultOwner | The ticket type phase default owner. | Optional | 
| phases_ticketTypePhase_id | The ticket type phase ID. | Optional | 
| phases_ticketTypePhase_name | The ticket type phase name. | Optional | 
| phases_ticketTypePhase_order | The ticket type phase order. | Optional | 
| phases_ticketTypePhase_ticketType | The ticket type. | Optional | 
| phases_ticketTypePhase_waitingForClosure | The ticket type phase waiting for closure status. | Optional | 
| workflowId | The workflow ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.createChangeManagerTicket | String | The change manager ticket creation status | 


#### Command Example
```!skybox-createChangeManagerTicket accessChangeTicket_title=TEST accessChangeTicket_priority=P1 accessChangeTicket_ccList_email=test@example.com accessChangeTicket_ccList_userName=skyboxview accessChangeTicket_changeDetails=changeDetails accessChangeTicket_comment=SomeComment accessChangeTicket_createdBy=skyboxview  accessChangeTicket_currentPhaseName=PhaseName accessChangeTicket_status=New accessChangeTicket_externalTicketId=123 accessChangeTicket_externalTicketStatus=Pending```

#### Context Example
```json
{
    "Skybox": {
        "createChangeManagerTicket": {
            "ccList": [
                {
                    "email": "skyboxview@skyboxsecurity.com",
                    "userName": "skyboxview"
                }
            ],
            "changeDetails": "changeDetails",
            "comment": "------- Created by: skyboxview  [skybox view] (1626889020925) Phase: Request ------- \n\nSomeComment",
            "createdBy": "skyboxview",
            "creationTime": "2021-07-21T13:37:00.416000-04:00",
            "currentPhaseName": "Request",
            "customFields": [
                {
                    "comment": null,
                    "createdBy": null,
                    "creationTime": null,
                    "description": null,
                    "id": 0,
                    "lastModificationTime": null,
                    "lastModifiedBy": null,
                    "name": "Name",
                    "typeCode": 1000001,
                    "value": null
                },
                {
                    "comment": null,
                    "createdBy": null,
                    "creationTime": null,
                    "description": null,
                    "id": 0,
                    "lastModificationTime": null,
                    "lastModifiedBy": null,
                    "name": "Email",
                    "typeCode": 1000002,
                    "value": null
                },
                {
                    "comment": null,
                    "createdBy": null,
                    "creationTime": null,
                    "description": null,
                    "id": 0,
                    "lastModificationTime": null,
                    "lastModifiedBy": null,
                    "name": "Phone",
                    "typeCode": 1000003,
                    "value": null
                },
                {
                    "comment": null,
                    "createdBy": null,
                    "creationTime": null,
                    "description": null,
                    "id": 0,
                    "lastModificationTime": null,
                    "lastModifiedBy": null,
                    "name": "Department",
                    "typeCode": 1000004,
                    "value": null
                },
                {
                    "comment": null,
                    "createdBy": null,
                    "creationTime": null,
                    "description": null,
                    "id": 0,
                    "lastModificationTime": null,
                    "lastModifiedBy": null,
                    "name": "Case owner",
                    "typeCode": 1000005,
                    "value": null
                }
            ],
            "description": null,
            "doneDate": null,
            "dueDate": null,
            "externalTicketId": "123",
            "externalTicketStatus": "Pending",
            "id": 496,
            "lastModificationTime": "2021-07-21T13:37:00.416000-04:00",
            "lastModifiedBy": "skyboxview",
            "likelihood": "Unknown",
            "owner": "skyboxview",
            "priority": "P1",
            "status": "New",
            "title": "TEST"
        }
    }
}
```

#### Human Readable Output

>### Created Ticket
>|id|priority|title|
>|---|---|---|
>| 496 | P1 | TEST |


### skybox-getTicketsNotImplementedChangeRequestsV2
***
Retrieves the list of unimplemented change
requests in the specified tickets according to the
permissions of the user sending the request. The
information retrieved includes the reasons that the
changes were not implemented.


#### Base Command

`skybox-getTicketsNotImplementedChangeRequestsV2`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketIds | The ticket ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getTicketsNotImplementedChangeRequestsV2 | String | The list of not implemented change requests for specified ticket ID | 


#### Command Example
```!skybox-getTicketsNotImplementedChangeRequestsV2 ticketIds="415"```

#### Human Readable Output

>null

### skybox-findAccessRequests
***
Retrieves all change requests for the specified
firewall created during the specified time frame.


#### Base Command

`skybox-findAccessRequests`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostId | The host ID. | Required | 
| dateRange_endDate | The date range end date. | Optional | 
| dateRange_startDate | The date range start date. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.findAccessRequests | String | The access requests list | 


#### Command Example
```!skybox-findAccessRequests hostId=1```

#### Human Readable Output

>null

### skybox-expandFirewallsForAccessChangeTicket
***
Finds the firewalls for the change requests (sets of
source, destination, and port) in a ticket and
expands the list of change requests in the ticket so
that each change request includes the firewall,
source, destination, and port.


#### Base Command

`skybox-expandFirewallsForAccessChangeTicket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ticket ID. | Required | 
| accessRequestIds | A list of change request IDs. If the list is empty, all change requests<br/>are expanded. | Optional | 
| recalculate | Specifies whether to expand the selected change requests. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.expandFirewallsForAccessChangeTicket | String | The firewall list for the change request | 


#### Command Example
```!skybox-expandFirewallsForAccessChangeTicket recalculate=False ticketId=484 accessRequestIds=627```

#### Context Example
```json
{
    "Skybox": {
        "expandFirewallsForAccessChangeTicket": {
            "ccList": [],
            "changeDetails": null,
            "comment": null,
            "createdBy": "skyboxview",
            "creationTime": "2021-07-19T13:31:28.640000-04:00",
            "currentPhaseName": "Request",
            "customFields": [
                {
                    "comment": null,
                    "createdBy": null,
                    "creationTime": null,
                    "description": null,
                    "id": 0,
                    "lastModificationTime": null,
                    "lastModifiedBy": null,
                    "name": "Name",
                    "typeCode": 1000001,
                    "value": null
                },
                {
                    "comment": null,
                    "createdBy": null,
                    "creationTime": null,
                    "description": null,
                    "id": 0,
                    "lastModificationTime": null,
                    "lastModifiedBy": null,
                    "name": "Email",
                    "typeCode": 1000002,
                    "value": null
                },
                {
                    "comment": null,
                    "createdBy": null,
                    "creationTime": null,
                    "description": null,
                    "id": 0,
                    "lastModificationTime": null,
                    "lastModifiedBy": null,
                    "name": "Phone",
                    "typeCode": 1000003,
                    "value": null
                },
                {
                    "comment": null,
                    "createdBy": null,
                    "creationTime": null,
                    "description": null,
                    "id": 0,
                    "lastModificationTime": null,
                    "lastModifiedBy": null,
                    "name": "Department",
                    "typeCode": 1000004,
                    "value": null
                },
                {
                    "comment": null,
                    "createdBy": null,
                    "creationTime": null,
                    "description": null,
                    "id": 0,
                    "lastModificationTime": null,
                    "lastModifiedBy": null,
                    "name": "Case owner",
                    "typeCode": 1000005,
                    "value": null
                }
            ],
            "description": "asd",
            "doneDate": null,
            "dueDate": "2021-07-27T23:58:59.072000-04:00",
            "externalTicketId": null,
            "externalTicketStatus": null,
            "id": 484,
            "lastModificationTime": "2021-07-20T14:57:40.864000-04:00",
            "lastModifiedBy": "skyboxview",
            "likelihood": null,
            "owner": "skyboxview",
            "priority": "P2",
            "status": "InProgress",
            "title": "qwe"
        }
    }
}
```

#### Human Readable Output

>### Results
>|ccList|changeDetails|comment|createdBy|creationTime|currentPhaseName|customFields|description|doneDate|dueDate|externalTicketId|externalTicketStatus|id|lastModificationTime|lastModifiedBy|likelihood|owner|priority|status|title|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  |  |  | skyboxview | 2021-07-19T13:31:28.640000-04:00 | Request | {'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Name', 'typeCode': 1000001, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Email', 'typeCode': 1000002, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Phone', 'typeCode': 1000003, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Department', 'typeCode': 1000004, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Case owner', 'typeCode': 1000005, 'value': None} | asd |  | 2021-07-27T23:58:59.072000-04:00 |  |  | 484 | 2021-07-20T14:57:40.864000-04:00 | skyboxview |  | skyboxview | P2 | InProgress | qwe |


### skybox-addAttachmentFile
***
Creates an attachment to a ticket in Skybox.


#### Base Command

`skybox-addAttachmentFile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| EntryID | The EntryID of the file to add. | Required | 
| attachmentDesc | The attachment description. | Optional | 
| sourceFileName | The original file name. | Required | 
| ticketId | The ticket ID. | Required | 
| phaseName | The phase for which to add the attachment. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.addAttachmentFile | String | The status of attachment ticket creation | 


#### Command Example
```!skybox-addAttachmentFile EntryID="3080@8ed7562a-849d-4bc2-8388-b7e5cf55b5da" attachmentDesc="testdesc" sourceFileName="tyl2.png" ticketId="484"```

#### Context Example
```json
{
    "Skybox": {
        "addAttachmentFile": {
            "EntryID": "3080@8ed7562a-849d-4bc2-8388-b7e5cf55b5da",
            "id": 8,
            "ticketId": "484"
        }
    }
}
```

#### Human Readable Output

>### Results
>|EntryID|id|ticketId|
>|---|---|---|
>| 3080@8ed7562a-849d-4bc2-8388-b7e5cf55b5da | 8 | 484 |


### skybox-countAccessChangeTickets
***
Counts tickets by owner, phase, status, ID, or free
text. This method is used for page calculations.


#### Base Command

`skybox-countAccessChangeTickets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_createdBy | The filter author user name. | Optional | 
| filter_freeTextFilter | Free text search in the following ticket fields:<br/>l Title<br/>l Comment<br/>l Owner<br/>l ID<br/>l Status<br/>l Priority<br/>l Vendor reference<br/>l Solutions<br/>l CVE catalog ID<br/>l Custom fields of type String. | Optional | 
| filter_modifiedBy | The filter modification author. | Optional | 
| filter_myGroups | Unknown. | Optional | 
| filter_owner | Search tickets by owner. | Optional | 
| filter_phaseName | Search tickets by current phase. | Optional | 
| filter_statusFilter | Search tickets by status.<br/>Possible values:<br/>l New<br/>l InProgress<br/>l Resolved<br/>l Closed<br/>l Rejected<br/>l Ignored<br/>l Verified<br/>l Reopened<br/>l Demoted. | Optional | 
| filter_ticketIdsFilter | Search tickets by IDs. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.countAccessChangeTickets | String | The number of tickets defined by the filter | 


#### Command Example
```!skybox-countAccessChangeTickets filter_myGroups=somegroup```

#### Context Example
```json
{
    "Skybox": {
        "countAccessChangeTickets": 0
    }
}
```

#### Human Readable Output

>### Results
>**No entries.**


### skybox-getDerivedChangeRequestsV7
***
Retrieves the list of derived change requests for
an original change request.


#### Base Command

`skybox-getDerivedChangeRequestsV7`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ID of the ticket. | Required | 
| changeRequestId | The ID of the original change request. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getDerivedChangeRequestsV7 | String | The list of derived change requests for an original change request. | 


#### Command Example
```!skybox-getDerivedChangeRequestsV7 ticketId=484 changeRequestId=624```

#### Context Example
```json
{
    "Skybox": {
        "getDerivedChangeRequestsV7": [
            {
                "NATDestinationAddresses": [],
                "NATDestinationObjects": [],
                "NATPortObjects": [],
                "NATPorts": null,
                "NATSourceAddresses": [],
                "NATSourceObjects": [],
                "applications": [],
                "comment": null,
                "complianceStatus": "NA",
                "createAfter": null,
                "createdBy": "skyboxview",
                "creationTime": "2021-07-20T14:57:40.864000-04:00",
                "description": null,
                "destinationAddresses": [
                    "3.4.5.6-3.4.5.6"
                ],
                "destinationObjects": [],
                "expirationDate": null,
                "firewall": {
                    "accessRules": 6,
                    "id": 294,
                    "interfaces": 2,
                    "name": "dev FW",
                    "netInterface": [],
                    "os": "Solaris",
                    "osVendor": "Sun",
                    "osVersion": null,
                    "primaryIp": "192.170.1.1",
                    "routingRules": 6,
                    "services": 0,
                    "status": "Up",
                    "type": "Firewall",
                    "vulnerabilities": 0
                },
                "hideSourceBehindGW": false,
                "id": 628,
                "implementBeforeAccessRule": null,
                "implementingAccessRules": [],
                "isDestinationNegated": false,
                "isGlobal": false,
                "isInstallOnAny": false,
                "isLogEnabled": true,
                "isRequiredStatus": "NA",
                "isServicesNegated": false,
                "isSharedObject": false,
                "isSourceNegated": false,
                "lastModificationTime": "2021-07-20T14:57:41.888000-04:00",
                "lastModifiedBy": "skyboxview",
                "loggingProfile": null,
                "messages": [
                    {
                        "args": [],
                        "formatedMessage": "The request source and destination are behind the same network interface",
                        "key": "ChangeRequestAddRuleCalculation.srcAndDstBehindSameNetInterface",
                        "level": "WARN"
                    },
                    {
                        "args": [],
                        "formatedMessage": "The request source and destination are behind the same network interface",
                        "key": "ChangeRequestAddRuleCalculation.srcAndDstBehindSameNetInterface",
                        "level": "WARN"
                    }
                ],
                "originalChangeRequestId": 624,
                "portObjects": [],
                "ports": "Any",
                "ruleAttributes": {
                    "businessFunction": null,
                    "comment": null,
                    "customFields": [],
                    "email": null,
                    "nextReviewDate": null,
                    "owner": null,
                    "status": "NONE",
                    "ticketId": null
                },
                "ruleGroup": null,
                "ruleType": "ACCESS_RULE",
                "securityProfileGroup": null,
                "sourceAddresses": [
                    "1.2.3.4-1.2.3.4"
                ],
                "sourceObjects": [],
                "useApplicationDefaultPorts": false,
                "userUsage": "ANY",
                "users": [],
                "verificationStatus": "UNKNOWN",
                "vpn": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|NATDestinationAddresses|NATDestinationObjects|NATPortObjects|NATPorts|NATSourceAddresses|NATSourceObjects|applications|comment|complianceStatus|createAfter|createdBy|creationTime|description|destinationAddresses|destinationObjects|expirationDate|firewall|hideSourceBehindGW|id|implementBeforeAccessRule|implementingAccessRules|isDestinationNegated|isGlobal|isInstallOnAny|isLogEnabled|isRequiredStatus|isServicesNegated|isSharedObject|isSourceNegated|lastModificationTime|lastModifiedBy|loggingProfile|messages|originalChangeRequestId|portObjects|ports|ruleAttributes|ruleGroup|ruleType|securityProfileGroup|sourceAddresses|sourceObjects|useApplicationDefaultPorts|userUsage|users|verificationStatus|vpn|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  |  |  |  |  |  |  |  | NA |  | skyboxview | 2021-07-20T14:57:40.864000-04:00 |  | 3.4.5.6-3.4.5.6 |  |  | accessRules: 6<br/>id: 294<br/>interfaces: 2<br/>name: dev FW<br/>netInterface: <br/>os: Solaris<br/>osVendor: Sun<br/>osVersion: null<br/>primaryIp: 192.170.1.1<br/>routingRules: 6<br/>services: 0<br/>status: Up<br/>type: Firewall<br/>vulnerabilities: 0 | false | 628 |  |  | false | false | false | true | NA | false | false | false | 2021-07-20T14:57:41.888000-04:00 | skyboxview |  | {'args': [], 'formatedMessage': 'The request source and destination are behind the same network interface', 'key': 'ChangeRequestAddRuleCalculation.srcAndDstBehindSameNetInterface', 'level': 'WARN'},<br/>{'args': [], 'formatedMessage': 'The request source and destination are behind the same network interface', 'key': 'ChangeRequestAddRuleCalculation.srcAndDstBehindSameNetInterface', 'level': 'WARN'} | 624 |  | Any | businessFunction: null<br/>comment: null<br/>customFields: <br/>email: null<br/>nextReviewDate: null<br/>owner: null<br/>status: NONE<br/>ticketId: null |  | ACCESS_RULE |  | 1.2.3.4-1.2.3.4 |  | false | ANY |  | UNKNOWN |  |


### skybox-setTicketAccessRequests
***
Sets the list of change requests to the specified
ticket


#### Base Command

`skybox-setTicketAccessRequests`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ID of the ticket. | Required | 
| accessRequests_accessQuery_destinationAddresses | An array of address elements to use as the destination of<br/>the query. | Optional | 
| accessRequests_accessQuery_destinationElements_id | Mandatory for network-context analysis; null for firewallcontext analysis.<br/>Each network entity consists of a network IP address and<br/>a network ID in the model that you can find using<br/>findNetworks. | Required | 
| accessRequests_accessQuery_firewall_id | Mandatory for firewall-context analysis; null for networkcontext analysis.<br/>Use findFirewalls to get this entity. | Optional | 
| accessRequests_accessQuery_mode | Specifies whether the answer is to include accessible or<br/>inaccessible paths.<br/>l 0: Accessible<br/>l 1: Inaccessible<br/>l 2: Both. | Optional | 
| accessRequests_accessQuery_ports | A list of ports (also referred to as services) to use in the<br/>query. | Optional | 
| accessRequests_accessQuery_sourceAddresses | An array of address elements to use as the source of the<br/>query. | Optional | 
| accessRequests_accessQuery_sourceElements_id | Mandatory for network-context analysis; null for firewallcontext analysis.<br/>Each network entity consists of a network IP address and<br/>a network ID in the model that you can find using<br/>findNetworks. | Optional | 
| accessRequests_accessQueryMode | Possible values:<br/>l FirewallMode<br/>l NetworkMode. | Optional | 
| accessRequests_accessStatus | Possible values:<br/>l UNCOMPUTED<br/>l ACCESSIBLE<br/>l UNACCESSIBLE<br/>l ERROR. | Optional | 
| accessRequests_accessType | The access type. | Optional | 
| accessRequests_comment | The access request comment. | Optional | 
| accessRequests_complianceStatus | Possible values:<br/>l UNCOMPUTED<br/>l YES<br/>l NO<br/>l ERROR. | Optional | 
| accessRequests_complianceViolations_aprName | The name of the Access Check in Skybox. | Optional | 
| accessRequests_complianceViolations_aprPath | The path of the Access Check in Skybox. | Optional | 
| accessRequests_complianceViolations_importance | Possible values:<br/>l 0=Very Low<br/>l 1=Low<br/>l 2=Medium<br/>l 3=High<br/>l 4=Critica. | Optional | 
| accessRequests_complianceViolations_portsViolating | List of String. | Optional | 
| accessRequests_createdBy | Acess request author user name. | Optional | 
| accessRequests_creationTime | Access request creation time. | Optional | 
| accessRequests_description | Access request description. | Optional | 
| accessRequests_destinationZones | List of zone names. | Optional | 
| accessRequests_disabled | Access request status. | Optional | 
| accessRequests_id | The access request ID. | Optional | 
| accessRequests_lastModificationTime | The access request last modification time. | Optional | 
| accessRequests_lastModifiedBy | The access request last modification author. | Optional | 
| accessRequests_potentialVulnerabilities_catalogId | The catalog ID. | Optional | 
| accessRequests_potentialVulnerabilities_cveId | The CVE ID. | Optional | 
| accessRequests_potentialVulnerabilities_hostIp | The host IP. | Optional | 
| accessRequests_potentialVulnerabilities_hostName | The hostname. | Optional | 
| accessRequests_potentialVulnerabilities_id | The vulnerability ID. | Optional | 
| accessRequests_potentialVulnerabilities_severity | The vulnerability severity. | Optional | 
| accessRequests_potentialVulnerabilities_title | The vulnerability title. | Optional | 
| accessRequests_sourceZones | List of zone names. | Optional | 
| accessRequests_accessQuery_destinationElements_name | The destination elements name. | Optional | 
| accessRequests_accessQuery_destinationElements_netMask | The destination elements network mask. | Optional | 
| accessRequests_accessQuery_destinationElements_path | The destination elements path. | Optional | 
| accessRequests_accessQuery_destinationElements_type | The destination elements type<br/>The possible values for the type field when it represents a network are:<br/>l 0: Regular<br/>l 1: Cloud<br/>l 2: Tunnel<br/>l 3: Link<br/>l 4: VPN Tunnel<br/>l 5: SerialLink<br/>l 6: Connecting Cloud<br/>Skybox Developer Guide<br/>Skybox version 11.4.100 318<br/>l 7: Artificial Layer2<br/>l 99: Unknown<br/>The possible values for the type field when it represents a network interface are:<br/>l 100: NAT<br/>l 101: Ethernet<br/>l 102: WLAN<br/>l 103: TokenRing<br/>l 104: PPP<br/>l 105: Slip<br/>l 106: Virtual<br/>l 107: Other<br/>l 108: Unknown<br/>l 109: Loopback<br/>l 110: Serial<br/>l 111: Load Balancer<br/>l 112: Tunnel<br/>l 113: Vpn<br/>l 114: Connecting Cloud Interface. | Optional | 
| accessRequests_accessQuery_firewall_name | The firewall name. | Optional | 
| accessRequests_accessQuery_firewall_path | The firewall path. | Optional | 
| accessRequests_accessQuery_sourceElements_IPAddress | The source element ip addresses. | Optional | 
| accessRequests_accessQuery_sourceElements_name | The source elements name. | Optional | 
| accessRequests_accessQuery_sourceElements_netMask | The source elements network mask. | Optional | 
| accessRequests_accessQuery_sourceElements_path | The source elements path. | Optional | 
| accessRequests_accessQuery_sourceElements_type | The source elements type. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.setTicketAccessRequests | String | The status of the access request change | 


#### Command Example
```!skybox-setTicketAccessRequests ticketId=484 accessRequests_accessStatus=ERROR accessRequests_accessType=type accessRequests_comment=comment accessRequests_complianceStatus=ERROR accessRequests_complianceViolations_aprName=accesschacke accessRequests_description=description accessRequests_complianceViolations_aprPath=path accessRequests_createdBy=skyboxview accessRequests_destinationZones=dstzone accessRequests_accessQuery_mode=2 accessRequests_accessQuery_destinationElements_id=1 accessRequests_accessQuery_destinationElements_netMask=24 accessRequests_accessQuery_destinationElements_type=0 accessRequests_accessQuery_firewall_id=1 accessRequests_accessQuery_sourceElements_id=0 accessRequests_accessQuery_sourceElements_netMask=24 accessRequests_accessQuery_sourceElements_type=0 accessRequests_complianceViolations_importance=3 accessRequests_disabled=false accessRequests_id=1 accessRequests_potentialVulnerabilities_id=1```

#### Human Readable Output

>null

### skybox-updateAccessChangeTicket
***
Enables you to modify an Access Change ticket.


#### Base Command

`skybox-updateAccessChangeTicket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| accessChangeTicket_id | The access change ticket ID. | Optional | 
| accessChangeTicket_comment | The access chagne ticket comment. | Optional | 
| accessChangeTicket_description | The access change ticket description. | Optional | 
| accessChangeTicket_createdBy | The access change ticket author. | Optional | 
| accessChangeTicket_creationTime | The access change ticket creation time. | Optional | 
| accessChangeTicket_lastModifiedBy | The access change ticket last modification author. | Optional | 
| accessChangeTicket_lastModificationTime | The access change ticket last modification time. | Optional | 
| accessChangeTicket_externalTicketId | The access chagne ticket external ticket ID. | Optional | 
| accessChangeTicket_externalTicketStatus | Possible values:<br/>l Pending<br/>l Open<br/>l Closed<br/>l Error<br/>l Rejected. | Optional | 
| accessChangeTicket_status | Possible values:<br/>l New<br/>l InProgress<br/>l Resolved<br/>l Closed<br/>l Rejected<br/>l Ignored<br/>l Verified<br/>l Reopened<br/>l Demoted. | Optional | 
| accessChangeTicket_title | The access chagne ticket title. | Optional | 
| accessChangeTicket_changeDetails | The access change ticket details. | Optional | 
| accessChangeTicket_priority | Possible values:<br/>l P1<br/>l P2<br/>l P3<br/>l P4<br/>l P5. Default is P5. | Optional | 
| accessChangeTicket_owner | The access change ticket owner. | Optional | 
| accessChangeTicket_dueDate | The access change ticket due date. | Optional | 
| accessChangeTicket_doneDate | The access change ticket done date. | Optional | 
| accessChangeTicket_likelihood | Possible values:<br/>l Unknown<br/>l Low<br/>l Medium<br/>l High<br/>l Priority<br/>l Critical. | Optional | 
| accessChangeTicket_ccList_email | The CC list email. | Optional | 
| accessChangeTicket_ccList_userName | The CC list user name. | Optional | 
| accessChangeTicket_customFields_comment | The custom field comment. | Optional | 
| accessChangeTicket_customFields_createdBy | The custom field author. | Optional | 
| accessChangeTicket_customFields_creationTime | The cusotm field creation time. | Optional | 
| accessChangeTicket_customFields_description | The cusotm field description. | Optional | 
| accessChangeTicket_customFields_id | The custom field ID. | Optional | 
| accessChangeTicket_customFields_lastModificationTime | The custom field last modification time. | Optional | 
| accessChangeTicket_customFields_lastModifiedBy | The custom field last modification author. | Optional | 
| accessChangeTicket_customFields_name | The custom field name. | Optional | 
| accessChangeTicket_customFields_typeCode | The custom field type code. | Optional | 
| accessChangeTicket_customFields_value | The custom field value. | Optional | 
| accessChangeTicket_currentPhaseName | The custom field phase name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.updateAccessChangeTicket | String | The status of access change ticket update | 


#### Command Example
```!skybox-updateAccessChangeTicket accessChangeTicket_id=484 accessChangeTicket_description=test accessChangeTicket_comment=comment accessChangeTicket_priority=P1 accessChangeTicket_likelihood=Low accessChangeTicket_status=InProgress accessChangeTicket_title=SOMETITLE accessChangeTicket_externalTicketId=123123 accessChangeTicket_externalTicketStatus=Rejected```

#### Context Example
```json
{
    "Skybox": {
        "updateAccessChangeTicket": {
            "ccList": [
                null
            ],
            "changeDetails": null,
            "comment": "------- Created by: skyboxview  [skybox view] (1626889248619) Phase: Request ------- \n\ncomment",
            "createdBy": "skyboxview",
            "creationTime": "2021-07-21T13:40:47.744000-04:00",
            "currentPhaseName": "Request",
            "customFields": [
                {
                    "comment": null,
                    "createdBy": null,
                    "creationTime": null,
                    "description": null,
                    "id": 0,
                    "lastModificationTime": null,
                    "lastModifiedBy": null,
                    "name": "Name",
                    "typeCode": 1000001,
                    "value": null
                },
                {
                    "comment": null,
                    "createdBy": null,
                    "creationTime": null,
                    "description": null,
                    "id": 0,
                    "lastModificationTime": null,
                    "lastModifiedBy": null,
                    "name": "Email",
                    "typeCode": 1000002,
                    "value": null
                },
                {
                    "comment": null,
                    "createdBy": null,
                    "creationTime": null,
                    "description": null,
                    "id": 0,
                    "lastModificationTime": null,
                    "lastModifiedBy": null,
                    "name": "Phone",
                    "typeCode": 1000003,
                    "value": null
                },
                {
                    "comment": null,
                    "createdBy": null,
                    "creationTime": null,
                    "description": null,
                    "id": 0,
                    "lastModificationTime": null,
                    "lastModifiedBy": null,
                    "name": "Department",
                    "typeCode": 1000004,
                    "value": null
                },
                {
                    "comment": null,
                    "createdBy": null,
                    "creationTime": null,
                    "description": null,
                    "id": 0,
                    "lastModificationTime": null,
                    "lastModifiedBy": null,
                    "name": "Case owner",
                    "typeCode": 1000005,
                    "value": null
                }
            ],
            "description": "test",
            "doneDate": null,
            "dueDate": null,
            "externalTicketId": "123123",
            "externalTicketStatus": "Rejected",
            "id": 498,
            "lastModificationTime": "2021-07-21T13:40:47.744000-04:00",
            "lastModifiedBy": "skyboxview",
            "likelihood": "Low",
            "owner": "skyboxview",
            "priority": "P1",
            "status": "InProgress",
            "title": "SOMETITLE"
        }
    }
}
```

#### Human Readable Output

>### Results
>|ccList|changeDetails|comment|createdBy|creationTime|currentPhaseName|customFields|description|doneDate|dueDate|externalTicketId|externalTicketStatus|id|lastModificationTime|lastModifiedBy|likelihood|owner|priority|status|title|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| None |  | ------- Created by: skyboxview  [skybox view] (1626889248619) Phase: Request ------- <br/><br/>comment | skyboxview | 2021-07-21T13:40:47.744000-04:00 | Request | {'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Name', 'typeCode': 1000001, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Email', 'typeCode': 1000002, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Phone', 'typeCode': 1000003, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Department', 'typeCode': 1000004, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Case owner', 'typeCode': 1000005, 'value': None} | test |  |  | 123123 | Rejected | 498 | 2021-07-21T13:40:47.744000-04:00 | skyboxview | Low | skyboxview | P1 | InProgress | SOMETITLE |


### skybox-addDerivedChangeRequests
***
Adds a derived change request to a ticket if the
original change request is of type Access Update


#### Base Command

`skybox-addDerivedChangeRequests`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ID of the ticket. | Required | 
| changeRequestId | The ID of the original change request. | Required | 
| firewalls_accessRules | The number of access rules in the asset. | Optional | 
| firewalls_id | The ID of the asset. | Required | 
| firewalls_interfaces | The firewall interfaces. | Optional | 
| firewalls_name | The asset name. | Optional | 
| firewalls_netInterface_description | The net interface description. | Optional | 
| firewalls_netInterface_id | The net interface ID. | Optional | 
| firewalls_netInterface_ipAddress | The interface IP Address. | Optional | 
| firewalls_netInterface_name | The interface name. | Optional | 
| firewalls_netInterface_type | Possible values:<br/>l NAT<br/>l ETHERNET<br/>l WLAN<br/>l TOKEN_RING<br/>l PPP<br/>l SLIP<br/>l VIRTUAL<br/>l OTHER<br/>l UNKNOWN<br/>l LOOPBACK<br/>l SERIAL<br/>l LOAD_BALANCER<br/>l TUNNEL<br/>l VPN<br/>l CONNECTING_CLOUD_<br/>INTERFACE. | Optional | 
| firewalls_netInterface_zoneName | The interface zone name. | Optional | 
| firewalls_netInterface_zoneType | The interface zone type. | Optional | 
| firewalls_os | The asset operating system. | Optional | 
| firewalls_osVendor | The asset operating system vendor. | Optional | 
| firewalls_osVersion | The version of the asset operating system. | Optional | 
| firewalls_primaryIp | The primary IP address of the asset. | Optional | 
| firewalls_routingRules | The number of routing rules in this asset. | Optional | 
| firewalls_services | The number of services in this asset. | Optional | 
| firewalls_status | The status of the asset:<br/>l Up<br/>l Down<br/>l Not Found<br/>l Unknown. | Optional | 
| firewalls_type | Possible values:<br/>l Firewall<br/>l Router<br/>l LoadBalancer<br/>l Proxy<br/>l NetworkDevice<br/>l WirelessDevice<br/>l IPS<br/>l Switch. | Optional | 
| firewalls_vulnerabilities | The number of vulnerability occurrences on the asset. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.addDerivedChangeRequests | String | The status of adding the derived change requests | 


#### Command Example
``` ```

#### Human Readable Output



### skybox-getPolicyViolations
***
Retrieves the list of Access Policy violations
associated with a change request.


#### Base Command

`skybox-getPolicyViolations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ID of the ticket. | Required | 
| changeRequestId | The ID of the change request for which you want to see policy<br/>violations. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getPolicyViolations | String | The list of Access Policy violations
associated with a change request. | 


#### Command Example
```!skybox-getPolicyViolations changeRequestId=607 ticketId=415```

#### Human Readable Output

>null

### skybox-removeAttachmentFile
***
Deletes an attachment from a ticket in Skybox.


#### Base Command

`skybox-removeAttachmentFile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attachmentId | The ID of the attachment.<br/>Find the ID using getAttachmentList. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.removeAttachmentFile | String | The status of file attachment deletion | 


#### Command Example
```!skybox-removeAttachmentFile attachmentId=9```

#### Human Readable Output

>null

### skybox-getTicketWorkflows
***
Retrieves the list of ticket workflows in Skybox,
including an ID and a name for each ticket.


#### Base Command

`skybox-getTicketWorkflows`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getTicketWorkflows | String | The list of ticket workflows in Skybox,
including an ID and a name for each ticket. | 


#### Command Example
```!skybox-getTicketWorkflows```

#### Context Example
```json
{
    "Skybox": {
        "getTicketWorkflows": [
            {
                "id": 1,
                "name": "General"
            },
            {
                "id": 2,
                "name": "Recertification"
            },
            {
                "id": 3,
                "name": "EMEA - Access Update Requests"
            },
            {
                "id": 4,
                "name": "APAC - Multi Approval"
            },
            {
                "id": 5,
                "name": "NA - Modify Object"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|id|name|
>|---|---|
>| 1 | General |
>| 2 | Recertification |
>| 3 | EMEA - Access Update Requests |
>| 4 | APAC - Multi Approval |
>| 5 | NA - Modify Object |


### skybox-recalculateTicketChangeRequests
***
Recalculates the change requests of the specified
ticket.


#### Base Command

`skybox-recalculateTicketChangeRequests`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ID of the ticket. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.recalculateTicketChangeRequests | String | The recalculation status of the change requests of the specified ticket | 


#### Command Example
```!skybox-recalculateTicketChangeRequests ticketId=484```

#### Human Readable Output

>null

### skybox-findConfigurationItems
***
Retrieves the configuration items that are defined
in the system.


#### Base Command

`skybox-findConfigurationItems`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_ancestorOf | Array of Integer (ancestor IDs). | Optional | 
| filter_childrenOf | Array of Integeger (children IDs). | Optional | 
| filter_configurationItemTypes | The configuration item types (Array of String). | Optional | 
| filter_freeTextFilter | The free text filter. | Optional | 
| filter_ids | The fitler IDs (Array of Integer). | Optional | 
| filter_ignoreEmptyGroups | Should the filter ignore empty groups? (boolean). | Optional | 
| filter_isEnabled | The filter status (boolean). | Optional | 
| filter_nameFilter | The filter name. | Optional | 
| subRange_size | The size of the sub range. | Optional | 
| subRange_start | The sub range start. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.findConfigurationItems | String | The configuration items that are defined
in the system. | 


#### Command Example
``` ```

#### Human Readable Output



### skybox-getSponsoringApplication
***
Retrieves the sponsoring application of the
specified ticket. Sponsoring applications
determine the phase owners for the ticket.


#### Base Command

`skybox-getSponsoringApplication`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ticket ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getSponsoringApplication | String | The sponsoring application of the
specified ticket. | 


#### Command Example
``` ```

#### Human Readable Output



### skybox-addOriginalChangeRequestsV7
***
Adds original change requests to a ticket and then
calculates the derived change requests, checks
whether a change is required, and checks for
policy compliance violations and potential
vulnerabilities.


#### Base Command

`skybox-addOriginalChangeRequestsV7`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ID of the ticke. | Required | 
| changeRequests_comment | The change request comment. | Optional | 
| changeRequests_complianceStatus | Possible values:<br/>l UNCOMPUTED<br/>l YES<br/>l NO<br/>l ERROR. | Optional | 
| changeRequests_createdBy | The change request author. | Optional | 
| changeRequests_creationTime | The change request creation time. | Optional | 
| changeRequests_description | The change request description. | Optional | 
| changeRequests_id | The change request ID. | Optional | 
| changeRequests_isRequiredStatus | Possible values:<br/>l UNCOMPUTED<br/>l YES (change required)<br/>l NO (already permitted)<br/>l Computing<br/>l ERROR. | Optional | 
| changeRequests_lastModificationTime | The change request last modification time. | Optional | 
| changeRequests_lastModifiedBy | The change request last modification author. | Optional | 
| changeRequests_messages_args | The messages arguments. | Optional | 
| changeRequests_messages_formatedMessage | Messages for the user about the change<br/>request that was calculated by the Skybox<br/>Server.<br/>For example, the change request cannot be<br/>calculated because the source and<br/>destination are behind the same interface;<br/>there is no firewall matching the request; or<br/>the request is a duplicate of another request<br/>in the ticket. | Optional | 
| changeRequests_messages_key | The messages key. | Optional | 
| changeRequests_messages_level | Possible values:<br/>l INFO<br/>l WARN<br/>l ERROR. | Optional | 
| changeRequests_originalChangeRequestId | The ID number of the original change<br/>request, when relevant. | Optional | 
| changeRequests_verificationStatus | Possible values:<br/>l Verified<br/>l Not Verified<br/>l Error<br/>l Computing<br/>l Unknown. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.addOriginalChangeRequestsV7 | String | The status of adding an original change request | 


#### Command Example
``` ```

#### Human Readable Output



### skybox-createTicketAccessRequestsForObjectChange
***
Adds change requests to a ticket. The method
finds the access rules in which the specified
object occurs and creates a change request for
each access rule.


#### Base Command

`skybox-createTicketAccessRequestsForObjectChange`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ID of the ticket to which the change requests are<br/>attached. | Required | 
| hostId |  The ID of the device to change. | Required | 
| objectName | The name of the object to change. The object can be an<br/>IP address object or Service object. | Optional | 
| changeType | The type of the change:<br/>l 0: Add to the object. | Required | 
| addressChange | The IP address to add to or delete from the object.<br/>Relevant only if the object is an IP address object. | Optional | 
| portChange | The service to add to or deleted from the object. Relevant<br/>only if the object is a Service object. | Optional | 
| maxAccessRequestsToCreate | Limits the number of change requests that are created. | Required | 
| chainFilterMode | Limits the rule chains searched for affected access rules.<br/>Possible values:<br/>l 0: Search all chains<br/>l 1: Search only primary chain<br/>l 2: Search by chain name. | Required | 
| chainNames | A list of chain names in which to search for the object.<br/>Relevant only if chainFilterMode=2. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.createTicketAccessRequestsForObjectChange | String | The status of the ticket access request object change. | 


#### Command Example
``` ```

#### Human Readable Output



### skybox-getDerivedChangeRequestRouteInfoV1
***
Retrieves the route information from a derived
change request.


#### Base Command

`skybox-getDerivedChangeRequestRouteInfoV1`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ID of the ticket. | Required | 
| changeRequestId | The ID of the original change reques. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getDerivedChangeRequestRouteInfoV1 | String | The route information from a derived
change request. | 


#### Command Example
``` ```

#### Human Readable Output



### skybox-implementChangeRequests
***
Implements the specified change requests.


#### Base Command

`skybox-implementChangeRequests`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| changeRequests_id | The ID of the change request. | Optional | 
| changeRequests_ticketId | The ID of the change request ticket. | Optional | 
| changeRequests_dueDate | The due date of the change request. | Optional | 
| changeRequests_ticketPriority | Possible values:<br/>l P1<br/>l P2<br/>l P3<br/>l P4<br/>l P5. Default is P5. | Optional | 
| changeRequests_changeType | The type of the change request. | Optional | 
| changeRequests_firewallName | The name of the firewall on which to make the<br/>change. | Optional | 
| changeRequests_firewallManagementName | The name of the firewall management on which<br/>to make the change. | Optional | 
| changeRequests_globalUniqueId | The GUID of the entity to change. | Optional | 
| changeRequests_changeDetails | The change details. | Optional | 
| changeRequests_additionalDetails | The change request additional details. | Optional | 
| changeRequests_isRequiredStatus | Possible values:<br/>l UNCOMPUTED<br/>l YES (change required)<br/>l NO (already permitted)<br/>l Computing<br/>l ERROR. | Optional | 
| changeRequests_owner | The owner of the change request. | Optional | 
| changeRequests_completeStatus | The complete status. | Optional | 
| changeRequests_completeDate | The date of completion. | Optional | 
| changeRequests_workflowName | The workflow name. | Optional | 
| changeRequests_comment | The comment. | Optional | 
| changeRequests_lastModificationTime | The last modification time. | Optional | 
| changeRequests_implementationStatus | The implementation status. | Optional | 
| comment | The formula for the comment to add to rules<br/>when the rules are implemented. For example,<br/>&lt;DATE&gt; - Created by &lt;USERNAME&gt;<br/>for ticket &lt;TICKET_ID&gt;.<br/>The comment must include at least 1 of the<br/>parameters (date, user name, or ticket ID). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.implementChangeRequests | String | The change request implementation status | 


#### Command Example
``` ```

#### Human Readable Output



### skybox-getAnalysisTree
***
Returns a list of analyses; each analysis includes
its ID, path, name, and type.


#### Base Command

`skybox-getAnalysisTree`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Legal values:<br/>l Network Assurance Tickets<br/>Public<br/>l Network Assurance Tickets<br/>Private. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getAnalysisTree | String | A list of analyses; each analysis includes
its ID, path, name, and type. | 


#### Command Example
``` ```

#### Human Readable Output



### skybox-operateOnAccessChangeTicket
***
Enables you to change the phase of a ticket
without sending the full ticket data.
The following changes can be made using this method:
l Accept a ticket
l Change a ticket’s phase
l Close a ticket
l Demote a ticket
l Change the status of the ticket to Ignored
l Promote a ticket
l Reassign a ticket
l Reopen a ticket
l Request to close a ticket


#### Base Command

`skybox-operateOnAccessChangeTicket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ticket ID. | Required | 
| phaseOperation_phaseId | Optional, depending on phase type. | Optional | 
| phaseOperation_phaseOwner | Optional, depending on phase type. | Optional | 
| phaseOperation_reject | Optional, depending on phase type. | Optional | 
| phaseOperation_type | Possible values:<br/>l ACCEPT<br/>l CHANGE_PHASE<br/>l CLOSE<br/>l DEMOTE<br/>l IGNORED<br/>l PROMOTE<br/>l REASSIGN<br/>l REOPEN<br/>l REQUEST_TO_CLOSE. Possible values are: ACCEPT, CHANGE_PHASE, CLOSE, DEMOTE, IGNORED, PROMOTE, REASSIGN, REOPEN, REQUEST_TO_CLOSE. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.operateOnAccessChangeTicket | String | The status of the access change ticket phase alteration | 


#### Command Example
```!skybox-operateOnAccessChangeTicket ticketId=415 phaseOperation_type=ACCEPT phaseOperation_phaseId=1 phaseOperation_reject=false phaseOperation_phaseOwner=skyboxview```

#### Human Readable Output

>null

### skybox-analyzeAccessChangeTicket
***
Analyzes policy compliance and access for
change requests of the specified ticket.


#### Base Command

`skybox-analyzeAccessChangeTicket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ID of the ticket to analyze. | Required | 
| accessRequests | A list of change request IDs in the ticket to analyze. An empty list means<br/>that all change requests are analyzed. | Optional | 
| mode | The type of analysis:<br/>l 0: Access analysis only<br/>l 1: Access Policy compliance analysis only<br/>l 2: Both. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.analyzeAccessChangeTicket | String | The analisys of the access change ticket | 


#### Command Example
```!skybox-analyzeAccessChangeTicket mode=2 ticketId=415 accessRequests=605```

#### Context Example
```json
{
    "Skybox": {
        "analyzeAccessChangeTicket": {
            "ccList": [],
            "changeDetails": null,
            "comment": null,
            "createdBy": "skyboxview",
            "creationTime": "2018-09-14T03:55:45.024000-04:00",
            "currentPhaseName": "Verification",
            "customFields": [
                {
                    "comment": null,
                    "createdBy": null,
                    "creationTime": null,
                    "description": null,
                    "id": 0,
                    "lastModificationTime": null,
                    "lastModifiedBy": null,
                    "name": "Name",
                    "typeCode": 1000001,
                    "value": null
                },
                {
                    "comment": null,
                    "createdBy": null,
                    "creationTime": null,
                    "description": null,
                    "id": 0,
                    "lastModificationTime": null,
                    "lastModifiedBy": null,
                    "name": "Email",
                    "typeCode": 1000002,
                    "value": null
                },
                {
                    "comment": null,
                    "createdBy": null,
                    "creationTime": null,
                    "description": null,
                    "id": 0,
                    "lastModificationTime": null,
                    "lastModifiedBy": null,
                    "name": "Phone",
                    "typeCode": 1000003,
                    "value": null
                },
                {
                    "comment": null,
                    "createdBy": null,
                    "creationTime": null,
                    "description": null,
                    "id": 0,
                    "lastModificationTime": null,
                    "lastModifiedBy": null,
                    "name": "Department",
                    "typeCode": 1000004,
                    "value": null
                },
                {
                    "comment": null,
                    "createdBy": null,
                    "creationTime": null,
                    "description": null,
                    "id": 0,
                    "lastModificationTime": null,
                    "lastModifiedBy": null,
                    "name": "Case owner",
                    "typeCode": 1000005,
                    "value": null
                }
            ],
            "description": "20 IPs, HTTPS to DMZ",
            "doneDate": null,
            "dueDate": "2018-09-14T23:58:58.048000-04:00",
            "externalTicketId": null,
            "externalTicketStatus": null,
            "id": 415,
            "lastModificationTime": "2021-07-21T13:42:36.288000-04:00",
            "lastModifiedBy": "skyboxview",
            "likelihood": "Unknown",
            "owner": "skyboxview",
            "priority": "P2",
            "status": "Resolved",
            "title": "20 IPs, HTTPS to DMZ"
        }
    }
}
```

#### Human Readable Output

>### Results
>|ccList|changeDetails|comment|createdBy|creationTime|currentPhaseName|customFields|description|doneDate|dueDate|externalTicketId|externalTicketStatus|id|lastModificationTime|lastModifiedBy|likelihood|owner|priority|status|title|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  |  |  | skyboxview | 2018-09-14T03:55:45.024000-04:00 | Verification | {'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Name', 'typeCode': 1000001, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Email', 'typeCode': 1000002, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Phone', 'typeCode': 1000003, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Department', 'typeCode': 1000004, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Case owner', 'typeCode': 1000005, 'value': None} | 20 IPs, HTTPS to DMZ |  | 2018-09-14T23:58:58.048000-04:00 |  |  | 415 | 2021-07-21T13:42:36.288000-04:00 | skyboxview | Unknown | skyboxview | P2 | Resolved | 20 IPs, HTTPS to DMZ |


### skybox-getVerificationDetails
***
Retrieves the verification details (that is, the
matching FirewallChange objects) for Add Rule or
Modify Rule change requests that are already
verified. If the change request is not verified, the
method returns null.


#### Base Command

`skybox-getVerificationDetails`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ID of the ticket. | Required | 
| changeRequestId | The ID of the (derived) change request for which you want to see the<br/>firewall objects that are changed. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getVerificationDetails | String | The verification details | 


#### Command Example
```!skybox-getVerificationDetails changeRequestId=611 ticketId=415```

#### Human Readable Output

>null

### skybox-getTicketPhases
***
Retrieves from Skybox the list of ticket phases for
a ticket type.


#### Base Command

`skybox-getTicketPhases`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ID of the ticket. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getTicketPhases | String | The available ticket phases | 


#### Command Example
```!skybox-getTicketPhases ticketId=415```

#### Context Example
```json
{
    "Skybox": {
        "getTicketPhases": [
            {
                "comment": null,
                "createdBy": "skyboxview",
                "creationTime": "2018-09-14T03:55:45.024000-04:00",
                "current": false,
                "demotionsCount": 0,
                "description": null,
                "dueDate": null,
                "endDate": "2018-09-14T03:55:45.024000-04:00",
                "id": 386,
                "lastModificationTime": "2018-09-14T03:55:45.024000-04:00",
                "lastModifiedBy": "skyboxview",
                "owner": "skyboxview",
                "revisedDueDate": null,
                "startDate": "2018-09-14T03:55:45.024000-04:00",
                "ticketTypePhase": {
                    "defaultOwner": null,
                    "id": 5,
                    "name": "Request",
                    "order": 1,
                    "ticketType": "AccessChangeTicket",
                    "waitingForClosure": false
                }
            },
            {
                "comment": null,
                "createdBy": "skyboxview",
                "creationTime": "2018-09-14T03:55:45.024000-04:00",
                "current": false,
                "demotionsCount": 0,
                "description": null,
                "dueDate": "2018-09-17T23:58:58.048000-04:00",
                "endDate": "2018-09-14T03:55:53.216000-04:00",
                "id": 387,
                "lastModificationTime": "2018-09-14T03:55:53.216000-04:00",
                "lastModifiedBy": "skyboxview",
                "owner": "skyboxview",
                "revisedDueDate": null,
                "startDate": "2018-09-14T03:55:45.024000-04:00",
                "ticketTypePhase": {
                    "defaultOwner": "skyboxview",
                    "id": 6,
                    "name": "Technical Details",
                    "order": 2,
                    "ticketType": "AccessChangeTicket",
                    "waitingForClosure": false
                }
            },
            {
                "comment": null,
                "createdBy": "skyboxview",
                "creationTime": "2018-09-14T03:55:45.024000-04:00",
                "current": false,
                "demotionsCount": 0,
                "description": null,
                "dueDate": "2018-09-19T23:58:58.048000-04:00",
                "endDate": "2018-09-14T03:55:56.288000-04:00",
                "id": 388,
                "lastModificationTime": "2018-09-14T03:55:56.288000-04:00",
                "lastModifiedBy": "skyboxview",
                "owner": "IT Risk",
                "revisedDueDate": "2018-09-17T23:58:58.048000-04:00",
                "startDate": "2018-09-14T03:55:53.216000-04:00",
                "ticketTypePhase": {
                    "defaultOwner": "IT Risk",
                    "id": 7,
                    "name": "Risk Assessment",
                    "order": 3,
                    "ticketType": "AccessChangeTicket",
                    "waitingForClosure": false
                }
            },
            {
                "comment": null,
                "createdBy": "skyboxview",
                "creationTime": "2018-09-14T03:55:45.024000-04:00",
                "current": false,
                "demotionsCount": 0,
                "description": null,
                "dueDate": "2018-09-21T23:58:58.048000-04:00",
                "endDate": "2018-09-14T03:56:02.432000-04:00",
                "id": 389,
                "lastModificationTime": "2018-09-14T03:56:02.432000-04:00",
                "lastModifiedBy": "skyboxview",
                "owner": "NOC",
                "revisedDueDate": "2018-09-17T23:58:58.048000-04:00",
                "startDate": "2018-09-14T03:55:56.288000-04:00",
                "ticketTypePhase": {
                    "defaultOwner": "NOC",
                    "id": 8,
                    "name": "Implementation Details",
                    "order": 4,
                    "ticketType": "AccessChangeTicket",
                    "waitingForClosure": false
                }
            },
            {
                "comment": null,
                "createdBy": "skyboxview",
                "creationTime": "2018-09-14T03:55:45.024000-04:00",
                "current": true,
                "demotionsCount": 0,
                "description": null,
                "dueDate": "2018-09-24T23:58:58.048000-04:00",
                "endDate": null,
                "id": 390,
                "lastModificationTime": "2018-09-14T03:56:02.432000-04:00",
                "lastModifiedBy": "skyboxview",
                "owner": "skyboxview",
                "revisedDueDate": "2018-09-14T23:58:58.048000-04:00",
                "startDate": "2018-09-14T03:56:02.432000-04:00",
                "ticketTypePhase": {
                    "defaultOwner": "skyboxview",
                    "id": 9,
                    "name": "Verification",
                    "order": 5,
                    "ticketType": "AccessChangeTicket",
                    "waitingForClosure": true
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|comment|createdBy|creationTime|current|demotionsCount|description|dueDate|endDate|id|lastModificationTime|lastModifiedBy|owner|revisedDueDate|startDate|ticketTypePhase|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | skyboxview | 2018-09-14T03:55:45.024000-04:00 | false | 0 |  |  | 2018-09-14T03:55:45.024000-04:00 | 386 | 2018-09-14T03:55:45.024000-04:00 | skyboxview | skyboxview |  | 2018-09-14T03:55:45.024000-04:00 | defaultOwner: null<br/>id: 5<br/>name: Request<br/>order: 1<br/>ticketType: AccessChangeTicket<br/>waitingForClosure: false |
>|  | skyboxview | 2018-09-14T03:55:45.024000-04:00 | false | 0 |  | 2018-09-17T23:58:58.048000-04:00 | 2018-09-14T03:55:53.216000-04:00 | 387 | 2018-09-14T03:55:53.216000-04:00 | skyboxview | skyboxview |  | 2018-09-14T03:55:45.024000-04:00 | defaultOwner: skyboxview<br/>id: 6<br/>name: Technical Details<br/>order: 2<br/>ticketType: AccessChangeTicket<br/>waitingForClosure: false |
>|  | skyboxview | 2018-09-14T03:55:45.024000-04:00 | false | 0 |  | 2018-09-19T23:58:58.048000-04:00 | 2018-09-14T03:55:56.288000-04:00 | 388 | 2018-09-14T03:55:56.288000-04:00 | skyboxview | IT Risk | 2018-09-17T23:58:58.048000-04:00 | 2018-09-14T03:55:53.216000-04:00 | defaultOwner: IT Risk<br/>id: 7<br/>name: Risk Assessment<br/>order: 3<br/>ticketType: AccessChangeTicket<br/>waitingForClosure: false |
>|  | skyboxview | 2018-09-14T03:55:45.024000-04:00 | false | 0 |  | 2018-09-21T23:58:58.048000-04:00 | 2018-09-14T03:56:02.432000-04:00 | 389 | 2018-09-14T03:56:02.432000-04:00 | skyboxview | NOC | 2018-09-17T23:58:58.048000-04:00 | 2018-09-14T03:55:56.288000-04:00 | defaultOwner: NOC<br/>id: 8<br/>name: Implementation Details<br/>order: 4<br/>ticketType: AccessChangeTicket<br/>waitingForClosure: false |
>|  | skyboxview | 2018-09-14T03:55:45.024000-04:00 | true | 0 |  | 2018-09-24T23:58:58.048000-04:00 |  | 390 | 2018-09-14T03:56:02.432000-04:00 | skyboxview | skyboxview | 2018-09-14T23:58:58.048000-04:00 | 2018-09-14T03:56:02.432000-04:00 | defaultOwner: skyboxview<br/>id: 9<br/>name: Verification<br/>order: 5<br/>ticketType: AccessChangeTicket<br/>waitingForClosure: true |


### skybox-findTickets
***
Retrieves the Access Change tickets in the
specified analysis.


#### Base Command

`skybox-findTickets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| analysis_id | The analysis ID. | Optional | 
| analysis_name | The analysis from which to retrieve the tickets. | Optional | 
| analysis_path | The analysis path. | Optional | 
| analysis_type | The analysis type. | Optional | 
| subRange_size | The sub-range size. | Optional | 
| subRange_start | The sub-range start. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.findTickets | String | The Access Change tickets in the
specified analysis. | 


#### Command Example
```!skybox-findTickets analysis_id=2985 subRange_size=10 subRange_start=1```

#### Context Example
```json
{
    "Skybox": {
        "findTickets": [
            {
                "accessChangeTicket": {
                    "ccList": [],
                    "changeDetails": null,
                    "comment": null,
                    "createdBy": "skyboxview",
                    "creationTime": "<not serializable>",
                    "currentPhaseName": "Request",
                    "customFields": [
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Case owner",
                            "typeCode": 1000005,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Department",
                            "typeCode": 1000004,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Name",
                            "typeCode": 1000001,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Email",
                            "typeCode": 1000002,
                            "value": null
                        }
                    ],
                    "description": "Request access for new user to have access the organization content servers.\nShowing the usage of custom fields.",
                    "doneDate": null,
                    "dueDate": "<not serializable>",
                    "externalTicketId": null,
                    "externalTicketStatus": null,
                    "id": 386,
                    "lastModificationTime": "<not serializable>",
                    "lastModifiedBy": "skyboxview",
                    "likelihood": "Unknown",
                    "owner": "skyboxview",
                    "priority": "P3",
                    "status": "Demoted",
                    "title": "Access request for new user to content servers (custom fields)"
                }
            },
            {
                "accessChangeTicket": {
                    "ccList": [],
                    "changeDetails": null,
                    "comment": null,
                    "createdBy": "skyboxview",
                    "creationTime": "<not serializable>",
                    "currentPhaseName": "Request",
                    "customFields": [
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Name",
                            "typeCode": 1000001,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Email",
                            "typeCode": 1000002,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Phone",
                            "typeCode": 1000003,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Department",
                            "typeCode": 1000004,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Case owner",
                            "typeCode": 1000005,
                            "value": null
                        }
                    ],
                    "description": "Add servers to Development_Servers Object",
                    "doneDate": null,
                    "dueDate": "<not serializable>",
                    "externalTicketId": null,
                    "externalTicketStatus": null,
                    "id": 389,
                    "lastModificationTime": "<not serializable>",
                    "lastModifiedBy": "skyboxview",
                    "likelihood": "Unknown",
                    "owner": "skyboxview",
                    "priority": "P3",
                    "status": "Demoted",
                    "title": "Modify Dev Servers Objects"
                }
            },
            {
                "accessChangeTicket": {
                    "ccList": [],
                    "changeDetails": null,
                    "comment": null,
                    "createdBy": "skyboxview",
                    "creationTime": "<not serializable>",
                    "currentPhaseName": "Recertification Request",
                    "customFields": [
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Name",
                            "typeCode": 1000001,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Email",
                            "typeCode": 1000002,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Phone",
                            "typeCode": 1000003,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Department",
                            "typeCode": 1000004,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Case owner",
                            "typeCode": 1000005,
                            "value": null
                        }
                    ],
                    "description": "This ticket recertifies the following main_FW [192.170.1.97] firewall rules: 9, 10, 11, 12, 13, 14 ",
                    "doneDate": null,
                    "dueDate": "<not serializable>",
                    "externalTicketId": null,
                    "externalTicketStatus": null,
                    "id": 395,
                    "lastModificationTime": "<not serializable>",
                    "lastModifiedBy": "skyboxview",
                    "likelihood": "Unknown",
                    "owner": "skyboxview",
                    "priority": "P2",
                    "status": "New",
                    "title": "Recertify 6 rules from main_FW [192.170.1.97] firewall"
                }
            },
            {
                "accessChangeTicket": {
                    "ccList": [],
                    "changeDetails": null,
                    "comment": null,
                    "createdBy": "skyboxview",
                    "creationTime": "<not serializable>",
                    "currentPhaseName": "Request",
                    "customFields": [
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Name",
                            "typeCode": 1000001,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Email",
                            "typeCode": 1000002,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Phone",
                            "typeCode": 1000003,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Department",
                            "typeCode": 1000004,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Case owner",
                            "typeCode": 1000005,
                            "value": null
                        }
                    ],
                    "description": "Add deny rule to block ping to DMZ network",
                    "doneDate": null,
                    "dueDate": null,
                    "externalTicketId": null,
                    "externalTicketStatus": null,
                    "id": 405,
                    "lastModificationTime": "<not serializable>",
                    "lastModifiedBy": "skyboxview",
                    "likelihood": "Unknown",
                    "owner": "skyboxview",
                    "priority": "P2",
                    "status": "New",
                    "title": "Add Deny Rule"
                }
            },
            {
                "accessChangeTicket": {
                    "ccList": [],
                    "changeDetails": null,
                    "comment": null,
                    "createdBy": "skyboxview",
                    "creationTime": "<not serializable>",
                    "currentPhaseName": "Request",
                    "customFields": [
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Name",
                            "typeCode": 1000001,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Email",
                            "typeCode": 1000002,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Phone",
                            "typeCode": 1000003,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Department",
                            "typeCode": 1000004,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Case owner",
                            "typeCode": 1000005,
                            "value": null
                        }
                    ],
                    "description": "testdescription",
                    "doneDate": null,
                    "dueDate": null,
                    "externalTicketId": null,
                    "externalTicketStatus": null,
                    "id": 422,
                    "lastModificationTime": "<not serializable>",
                    "lastModifiedBy": "skyboxview",
                    "likelihood": null,
                    "owner": "skyboxview",
                    "priority": "P2",
                    "status": "New",
                    "title": "testticket"
                }
            },
            {
                "accessChangeTicket": {
                    "ccList": [],
                    "changeDetails": null,
                    "comment": null,
                    "createdBy": "skyboxview",
                    "creationTime": "<not serializable>",
                    "currentPhaseName": "Request",
                    "customFields": [
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Name",
                            "typeCode": 1000001,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Email",
                            "typeCode": 1000002,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Phone",
                            "typeCode": 1000003,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Department",
                            "typeCode": 1000004,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Case owner",
                            "typeCode": 1000005,
                            "value": null
                        }
                    ],
                    "description": "test description",
                    "doneDate": null,
                    "dueDate": null,
                    "externalTicketId": null,
                    "externalTicketStatus": null,
                    "id": 423,
                    "lastModificationTime": "<not serializable>",
                    "lastModifiedBy": "skyboxview",
                    "likelihood": null,
                    "owner": "skyboxview",
                    "priority": "P2",
                    "status": "New",
                    "title": "test"
                }
            },
            {
                "accessChangeTicket": {
                    "ccList": [],
                    "changeDetails": null,
                    "comment": null,
                    "createdBy": "skyboxview",
                    "creationTime": "<not serializable>",
                    "currentPhaseName": "Request",
                    "customFields": [
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Name",
                            "typeCode": 1000001,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Email",
                            "typeCode": 1000002,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Phone",
                            "typeCode": 1000003,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Department",
                            "typeCode": 1000004,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Case owner",
                            "typeCode": 1000005,
                            "value": null
                        }
                    ],
                    "description": null,
                    "doneDate": null,
                    "dueDate": null,
                    "externalTicketId": null,
                    "externalTicketStatus": "Pending",
                    "id": 424,
                    "lastModificationTime": "<not serializable>",
                    "lastModifiedBy": "skyboxview",
                    "likelihood": "Unknown",
                    "owner": "skyboxview",
                    "priority": "P5",
                    "status": "New",
                    "title": null
                }
            },
            {
                "accessChangeTicket": {
                    "ccList": [],
                    "changeDetails": null,
                    "comment": null,
                    "createdBy": "skyboxview",
                    "creationTime": "<not serializable>",
                    "currentPhaseName": "Request",
                    "customFields": [
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Name",
                            "typeCode": 1000001,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Email",
                            "typeCode": 1000002,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Phone",
                            "typeCode": 1000003,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Department",
                            "typeCode": 1000004,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Case owner",
                            "typeCode": 1000005,
                            "value": null
                        }
                    ],
                    "description": null,
                    "doneDate": null,
                    "dueDate": null,
                    "externalTicketId": null,
                    "externalTicketStatus": "Pending",
                    "id": 425,
                    "lastModificationTime": "<not serializable>",
                    "lastModifiedBy": "skyboxview",
                    "likelihood": "Unknown",
                    "owner": "skyboxview",
                    "priority": "P5",
                    "status": "New",
                    "title": null
                }
            },
            {
                "accessChangeTicket": {
                    "ccList": [],
                    "changeDetails": null,
                    "comment": null,
                    "createdBy": "skyboxview",
                    "creationTime": "<not serializable>",
                    "currentPhaseName": "Request",
                    "customFields": [
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Name",
                            "typeCode": 1000001,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Email",
                            "typeCode": 1000002,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Phone",
                            "typeCode": 1000003,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Department",
                            "typeCode": 1000004,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Case owner",
                            "typeCode": 1000005,
                            "value": null
                        }
                    ],
                    "description": null,
                    "doneDate": null,
                    "dueDate": null,
                    "externalTicketId": null,
                    "externalTicketStatus": "Pending",
                    "id": 427,
                    "lastModificationTime": "<not serializable>",
                    "lastModifiedBy": "skyboxview",
                    "likelihood": "Unknown",
                    "owner": "skyboxview",
                    "priority": "P5",
                    "status": "New",
                    "title": null
                }
            },
            {
                "accessChangeTicket": {
                    "ccList": [],
                    "changeDetails": null,
                    "comment": null,
                    "createdBy": "skyboxview",
                    "creationTime": "<not serializable>",
                    "currentPhaseName": "Request",
                    "customFields": [
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Name",
                            "typeCode": 1000001,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Email",
                            "typeCode": 1000002,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Phone",
                            "typeCode": 1000003,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Department",
                            "typeCode": 1000004,
                            "value": null
                        },
                        {
                            "comment": null,
                            "createdBy": null,
                            "creationTime": null,
                            "description": null,
                            "id": 0,
                            "lastModificationTime": null,
                            "lastModifiedBy": null,
                            "name": "Case owner",
                            "typeCode": 1000005,
                            "value": null
                        }
                    ],
                    "description": null,
                    "doneDate": null,
                    "dueDate": null,
                    "externalTicketId": null,
                    "externalTicketStatus": "Pending",
                    "id": 428,
                    "lastModificationTime": "<not serializable>",
                    "lastModifiedBy": "skyboxview",
                    "likelihood": "Unknown",
                    "owner": "skyboxview",
                    "priority": "P5",
                    "status": "New",
                    "title": null
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|accessChangeTicket|
>|---|
>| id: 386<br/>comment: null<br/>description: Request access for new user to have access the organization content servers.<br/>Showing the usage of custom fields.<br/>createdBy: skyboxview<br/>creationTime: <not serializable><br/>lastModifiedBy: skyboxview<br/>lastModificationTime: <not serializable><br/>externalTicketId: null<br/>externalTicketStatus: null<br/>status: Demoted<br/>title: Access request for new user to content servers (custom fields)<br/>changeDetails: null<br/>priority: P3<br/>owner: skyboxview<br/>dueDate: <not serializable><br/>doneDate: null<br/>likelihood: Unknown<br/>ccList: <br/>customFields: {'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Case owner', 'typeCode': 1000005, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Department', 'typeCode': 1000004, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Name', 'typeCode': 1000001, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Email', 'typeCode': 1000002, 'value': None}<br/>currentPhaseName: Request |
>| id: 389<br/>comment: null<br/>description: Add servers to Development_Servers Object<br/>createdBy: skyboxview<br/>creationTime: <not serializable><br/>lastModifiedBy: skyboxview<br/>lastModificationTime: <not serializable><br/>externalTicketId: null<br/>externalTicketStatus: null<br/>status: Demoted<br/>title: Modify Dev Servers Objects<br/>changeDetails: null<br/>priority: P3<br/>owner: skyboxview<br/>dueDate: <not serializable><br/>doneDate: null<br/>likelihood: Unknown<br/>ccList: <br/>customFields: {'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Name', 'typeCode': 1000001, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Email', 'typeCode': 1000002, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Phone', 'typeCode': 1000003, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Department', 'typeCode': 1000004, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Case owner', 'typeCode': 1000005, 'value': None}<br/>currentPhaseName: Request |
>| id: 395<br/>comment: null<br/>description: This ticket recertifies the following main_FW [192.170.1.97] firewall rules: 9, 10, 11, 12, 13, 14 <br/>createdBy: skyboxview<br/>creationTime: <not serializable><br/>lastModifiedBy: skyboxview<br/>lastModificationTime: <not serializable><br/>externalTicketId: null<br/>externalTicketStatus: null<br/>status: New<br/>title: Recertify 6 rules from main_FW [192.170.1.97] firewall<br/>changeDetails: null<br/>priority: P2<br/>owner: skyboxview<br/>dueDate: <not serializable><br/>doneDate: null<br/>likelihood: Unknown<br/>ccList: <br/>customFields: {'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Name', 'typeCode': 1000001, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Email', 'typeCode': 1000002, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Phone', 'typeCode': 1000003, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Department', 'typeCode': 1000004, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Case owner', 'typeCode': 1000005, 'value': None}<br/>currentPhaseName: Recertification Request |
>| id: 405<br/>comment: null<br/>description: Add deny rule to block ping to DMZ network<br/>createdBy: skyboxview<br/>creationTime: <not serializable><br/>lastModifiedBy: skyboxview<br/>lastModificationTime: <not serializable><br/>externalTicketId: null<br/>externalTicketStatus: null<br/>status: New<br/>title: Add Deny Rule<br/>changeDetails: null<br/>priority: P2<br/>owner: skyboxview<br/>dueDate: null<br/>doneDate: null<br/>likelihood: Unknown<br/>ccList: <br/>customFields: {'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Name', 'typeCode': 1000001, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Email', 'typeCode': 1000002, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Phone', 'typeCode': 1000003, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Department', 'typeCode': 1000004, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Case owner', 'typeCode': 1000005, 'value': None}<br/>currentPhaseName: Request |
>| id: 422<br/>comment: null<br/>description: testdescription<br/>createdBy: skyboxview<br/>creationTime: <not serializable><br/>lastModifiedBy: skyboxview<br/>lastModificationTime: <not serializable><br/>externalTicketId: null<br/>externalTicketStatus: null<br/>status: New<br/>title: testticket<br/>changeDetails: null<br/>priority: P2<br/>owner: skyboxview<br/>dueDate: null<br/>doneDate: null<br/>likelihood: null<br/>ccList: <br/>customFields: {'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Name', 'typeCode': 1000001, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Email', 'typeCode': 1000002, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Phone', 'typeCode': 1000003, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Department', 'typeCode': 1000004, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Case owner', 'typeCode': 1000005, 'value': None}<br/>currentPhaseName: Request |
>| id: 423<br/>comment: null<br/>description: test description<br/>createdBy: skyboxview<br/>creationTime: <not serializable><br/>lastModifiedBy: skyboxview<br/>lastModificationTime: <not serializable><br/>externalTicketId: null<br/>externalTicketStatus: null<br/>status: New<br/>title: test<br/>changeDetails: null<br/>priority: P2<br/>owner: skyboxview<br/>dueDate: null<br/>doneDate: null<br/>likelihood: null<br/>ccList: <br/>customFields: {'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Name', 'typeCode': 1000001, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Email', 'typeCode': 1000002, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Phone', 'typeCode': 1000003, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Department', 'typeCode': 1000004, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Case owner', 'typeCode': 1000005, 'value': None}<br/>currentPhaseName: Request |
>| id: 424<br/>comment: null<br/>description: null<br/>createdBy: skyboxview<br/>creationTime: <not serializable><br/>lastModifiedBy: skyboxview<br/>lastModificationTime: <not serializable><br/>externalTicketId: null<br/>externalTicketStatus: Pending<br/>status: New<br/>title: null<br/>changeDetails: null<br/>priority: P5<br/>owner: skyboxview<br/>dueDate: null<br/>doneDate: null<br/>likelihood: Unknown<br/>ccList: <br/>customFields: {'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Name', 'typeCode': 1000001, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Email', 'typeCode': 1000002, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Phone', 'typeCode': 1000003, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Department', 'typeCode': 1000004, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Case owner', 'typeCode': 1000005, 'value': None}<br/>currentPhaseName: Request |
>| id: 425<br/>comment: null<br/>description: null<br/>createdBy: skyboxview<br/>creationTime: <not serializable><br/>lastModifiedBy: skyboxview<br/>lastModificationTime: <not serializable><br/>externalTicketId: null<br/>externalTicketStatus: Pending<br/>status: New<br/>title: null<br/>changeDetails: null<br/>priority: P5<br/>owner: skyboxview<br/>dueDate: null<br/>doneDate: null<br/>likelihood: Unknown<br/>ccList: <br/>customFields: {'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Name', 'typeCode': 1000001, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Email', 'typeCode': 1000002, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Phone', 'typeCode': 1000003, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Department', 'typeCode': 1000004, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Case owner', 'typeCode': 1000005, 'value': None}<br/>currentPhaseName: Request |
>| id: 427<br/>comment: null<br/>description: null<br/>createdBy: skyboxview<br/>creationTime: <not serializable><br/>lastModifiedBy: skyboxview<br/>lastModificationTime: <not serializable><br/>externalTicketId: null<br/>externalTicketStatus: Pending<br/>status: New<br/>title: null<br/>changeDetails: null<br/>priority: P5<br/>owner: skyboxview<br/>dueDate: null<br/>doneDate: null<br/>likelihood: Unknown<br/>ccList: <br/>customFields: {'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Name', 'typeCode': 1000001, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Email', 'typeCode': 1000002, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Phone', 'typeCode': 1000003, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Department', 'typeCode': 1000004, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Case owner', 'typeCode': 1000005, 'value': None}<br/>currentPhaseName: Request |
>| id: 428<br/>comment: null<br/>description: null<br/>createdBy: skyboxview<br/>creationTime: <not serializable><br/>lastModifiedBy: skyboxview<br/>lastModificationTime: <not serializable><br/>externalTicketId: null<br/>externalTicketStatus: Pending<br/>status: New<br/>title: null<br/>changeDetails: null<br/>priority: P5<br/>owner: skyboxview<br/>dueDate: null<br/>doneDate: null<br/>likelihood: Unknown<br/>ccList: <br/>customFields: {'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Name', 'typeCode': 1000001, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Email', 'typeCode': 1000002, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Phone', 'typeCode': 1000003, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Department', 'typeCode': 1000004, 'value': None},<br/>{'comment': None, 'createdBy': None, 'creationTime': None, 'description': None, 'id': 0, 'lastModificationTime': None, 'lastModifiedBy': None, 'name': 'Case owner', 'typeCode': 1000005, 'value': None}<br/>currentPhaseName: Request |


### skybox-setChangeRequestRuleAttributes
***
Sets the rule attributes for the rules in the
specified change requests.


#### Base Command

`skybox-setChangeRequestRuleAttributes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ID of the ticket. | Required | 
| changeRequestId | The IDs of the change requests for which to update the rule<br/>attributes. | Required | 
| ruleAttributes_businessFunction | The rule attribute business function. | Optional | 
| ruleAttributes_comment | The rule attribute comment. | Optional | 
| ruleAttributes_customFields_id | The cusotm field ID. | Optional | 
| ruleAttributes_customFields_name | The custom field name. | Optional | 
| ruleAttributes_customFields_value | The custom field value. | Optional | 
| ruleAttributes_nextReviewDate | The rule attribute next review date. | Optional | 
| ruleAttributes_owner | The rule attribute owner. | Optional | 
| ruleAttributes_status | The recertification status of the rule. Possible values:<br/>l NONE<br/>l IN_PROGRESS<br/>l REJECTED<br/>l CERTIFIED. | Optional | 
| ruleAttributes_ticketId | The rule attribute ticket ID. | Optional | 
| ruleAttributes_customFields_typeCode | The custom fields type code. | Optional | 
| ruleAttributes_customFields_defId | The custom field definition ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.setChangeRequestRuleAttributes | String | The result of change request rule attribute change | 


#### Command Example
```!skybox-setChangeRequestRuleAttributes changeRequestId=602 ticketId=414 ruleAttributes_comment=comment ruleAttributes_email=skybox@example.com ruleAttributes_status=REJECTED ruleAttributes_customFields_id=10001 ruleAttributes_customFields_typeCode=1  ruleAttributes_customFields_defId=1```

#### Human Readable Output

>null

### skybox-getAttachmentList
***
Retrieves the list of attachments to a ticket in
Skybox.


#### Base Command

`skybox-getAttachmentList`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ID of the ticket. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getAttachmentList | String | The list of attachments to a ticket in
Skybox. | 


#### Command Example
```!skybox-getAttachmentList ticketId=380```

#### Context Example
```json
{
    "Skybox": {
        "getAttachmentList": [
            {
                "attachmentExists": true,
                "attachmentSizeInBytes": 29573,
                "comment": null,
                "createdBy": "skyboxview",
                "creationTime": "2021-07-15T10:00:19.712000-04:00",
                "description": "Some FILE",
                "destinationFileName": "ticket_attachments/ticket_id380_1368205396/attachment_id1/Screenshot 2021-07-14 at 13.32.43.png",
                "filename": "Screenshot 2021-07-14 at 13.32.43.png",
                "id": 1,
                "lastModificationTime": "2021-07-15T10:00:19.712000-04:00",
                "modifiedBy": "skyboxview",
                "owner": "skyboxview",
                "phaseName": "Request"
            },
            {
                "attachmentExists": true,
                "attachmentSizeInBytes": 24941,
                "comment": null,
                "createdBy": "skyboxview",
                "creationTime": "2021-07-15T10:13:02.592000-04:00",
                "description": null,
                "destinationFileName": "ticket_attachments/ticket_id380_1368205396/attachment_id2/Screenshot 2021-07-12 at 13.48.27.png",
                "filename": "Screenshot 2021-07-12 at 13.48.27.png",
                "id": 2,
                "lastModificationTime": "2021-07-15T10:13:02.592000-04:00",
                "modifiedBy": "skyboxview",
                "owner": "skyboxview",
                "phaseName": "Request"
            }
        ]
    }
}
```

#### Human Readable Output

>### Attachement List
>|id|filename|description|
>|---|---|---|
>| 1 | Screenshot 2021-07-14 at 13.32.43.png | Some FILE |
>| 2 | Screenshot 2021-07-12 at 13.48.27.png |  |


### skybox-setAddRuleChangeRequestFields
***
Makes changes to specified fields of a change
request.


#### Base Command

`skybox-setAddRuleChangeRequestFields`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ID of the ticket. | Required | 
| changeRequestId | The ID of the change request in which to make the changes. | Required | 
| fields | The JSON list of dictionaries. Each element of the array is a key (name of field) + value set. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.setAddRuleChangeRequestFields | String | The result of the changes to specified fields of a change request | 


#### Command Example
```!skybox-setAddRuleChangeRequestFields ticketId=415 changeRequestId=608 fields={\"twoja\":\"stara\"} debug-mode=true```

#### Human Readable Output

>null

### skybox-setTicketPhases
***
Sets the list of ticket phases for a ticket type in
Skybox.


#### Base Command

`skybox-setTicketPhases`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ID of the ticket. | Required | 
| phases_comment | The phase comment. | Optional | 
| phases_createdBy | The phase author. | Optional | 
| phases_creationTime | The phase creation time. | Optional | 
| phases_current | The phase current status. | Optional | 
| phases_demotionsCount | The phase demotions count. | Optional | 
| phases_description | The phase description. | Optional | 
| phases_dueDate | The phase due date. | Optional | 
| phases_endDate | The phase end date. | Optional | 
| phases_id | The phase id. | Optional | 
| phases_lastModificationTime | The phase last modification time. | Optional | 
| phases_lastModifiedBy | The phase last modification author. | Optional | 
| phases_owner | The phase owner. | Optional | 
| phases_revisedDueDate | The phase revised due date. | Optional | 
| phases_startDate | The phase start date. | Optional | 
| phases_ticketTypePhase_defaultOwner | The ticket type phase default owner. | Optional | 
| phases_ticketTypePhase_id | The ticket type phase ID. | Optional | 
| phases_ticketTypePhase_name | The ticket type phase name. | Optional | 
| phases_ticketTypePhase_order | The ticket type phase order. | Optional | 
| phases_ticketTypePhase_ticketType |  Possible values:<br/>l VulnerabilityTicket<br/>l ApplicationTicket<br/>l VulnerabilityDefinitionTicket<br/>l AccessChangeTicket<br/>l PolicyViolationTicket<br/>l EOLTicket. | Optional | 
| phases_ticketTypePhase_waitingForClosure | The tciket type phase waiting for closure status. | Optional | 
| phaseOperation_phaseId | The phase ID. | Optional | 
| phaseOperation_phaseOwner | The Phase Owner. | Optional | 
| phaseOperation_reject | The phase operation reject. | Optional | 
| phaseOperation_type | Possible values:<br/>l ACCEPT<br/>l CHANGE_PHASE<br/>l CLOSE<br/>l DEMOTE<br/>l IGNORED<br/>l PROMOTE<br/>l REASSIGN<br/>l REOPEN<br/>l REQUEST_TO_CLOSE. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.setTicketPhases | String | The result of setting the list of ticket phases for a ticket type in
Skybox. | 


#### Command Example
``` ```

#### Human Readable Output



### skybox-getTicketAccessRequests
***
Retrieves from Skybox the list of change requests
for the specified ticket.


#### Base Command

`skybox-getTicketAccessRequests`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ID of the ticket. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getTicketAccessRequests | String | The list of change requests for the specified ticket. | 


#### Command Example
```!skybox-getTicketAccessRequests ticketId=415```

#### Context Example
```json
{
    "Skybox": {
        "getTicketAccessRequests": [
            {
                "accessQuery": {
                    "destinationAddresses": [
                        "10.43.1.0-10.43.1.255"
                    ],
                    "destinationElements": [
                        {
                            "IPAddress": "10.43.1.1",
                            "id": 12494,
                            "name": "dmz",
                            "netMask": 0,
                            "path": null,
                            "type": 101
                        }
                    ],
                    "firewall": {
                        "id": 12211,
                        "name": "vlab-pix",
                        "path": "Locations & Networks / US / New York"
                    },
                    "mode": 0,
                    "ports": "433/TCP",
                    "sourceAddresses": [
                        "10.42.1.211-10.42.1.230"
                    ],
                    "sourceElements": [
                        {
                            "IPAddress": "10.42.1.1",
                            "id": 12493,
                            "name": "inside",
                            "netMask": 0,
                            "path": null,
                            "type": 101
                        }
                    ]
                },
                "accessQueryMode": "FirewallMode",
                "accessStatus": "UNACCESSIBLE",
                "accessType": "Access required",
                "comment": null,
                "complianceStatus": "UNCOMPUTED",
                "complianceViolations": [],
                "createdBy": "skyboxview",
                "creationTime": "2018-09-14T03:55:48.096000-04:00",
                "description": null,
                "destinationZones": null,
                "disabled": false,
                "id": 5354,
                "lastModificationTime": "2018-09-14T03:55:48.096000-04:00",
                "lastModifiedBy": "skyboxview",
                "potentialVulnerabilities": [],
                "sourceZones": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|accessQuery|accessQueryMode|accessStatus|accessType|comment|complianceStatus|complianceViolations|createdBy|creationTime|description|destinationZones|disabled|id|lastModificationTime|lastModifiedBy|potentialVulnerabilities|sourceZones|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| destinationAddresses: 10.43.1.0-10.43.1.255<br/>destinationElements: {'IPAddress': '10.43.1.1', 'id': 12494, 'name': 'dmz', 'netMask': 0, 'path': None, 'type': 101}<br/>firewall: {"id": 12211, "name": "vlab-pix", "path": "Locations & Networks / US / New York"}<br/>mode: 0<br/>ports: 433/TCP<br/>sourceAddresses: 10.42.1.211-10.42.1.230<br/>sourceElements: {'IPAddress': '10.42.1.1', 'id': 12493, 'name': 'inside', 'netMask': 0, 'path': None, 'type': 101} | FirewallMode | UNACCESSIBLE | Access required |  | UNCOMPUTED |  | skyboxview | 2018-09-14T03:55:48.096000-04:00 |  |  | false | 5354 | 2018-09-14T03:55:48.096000-04:00 | skyboxview |  |  |


### skybox-testService
***
Tests communication with the service


#### Base Command

`skybox-testService`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| anyValue | A binary number that will be returned back from the api endpoint. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.testService | String | The number that has been returned back from the endpoint. | 


#### Command Example
```!skybox-testService anyValue=1000100111```

#### Context Example
```json
{
    "Skybox": {
        "testService": "1000100111"
    }
}
```

#### Human Readable Output

>1000100111

### skybox-setRecertificationStatus
***
Sets the recertification status for the specified
change requests in the ticket and can be used to
change any other rule attributes for the rules in the
specified change requests.


#### Base Command

`skybox-setRecertificationStatus`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ticket ID. | Required | 
| changeRequestIds | he IDs of the change requests for which to set the<br/>recertification status. | Optional | 
| ruleAttributes_businessFunction | The business function. | Optional | 
| ruleAttributes_comment | The rule attributes comment. | Optional | 
| ruleAttributes_customFields_dataType | The custom field data type. | Optional | 
| ruleAttributes_customFields_defId | The custom field definition ID. | Optional | 
| ruleAttributes_customFields_entityType | The custom field entity type. | Optional | 
| ruleAttributes_customFields_id | The custom fields ID. | Optional | 
| ruleAttributes_customFields_name | The custom fields name. | Optional | 
| ruleAttributes_customFields_value | The custom field value. | Optional | 
| ruleAttributes_email | The rule attributes email. | Optional | 
| ruleAttributes_nextReviewDate | The rule attributes next review date. | Optional | 
| ruleAttributes_owner | The rule attributes owner. | Optional | 
| ruleAttributes_status | The recertification status of the rule. Possible values:<br/>l NONE<br/>l IN_PROGRESS<br/>l REJECTED<br/>l CERTIFIED. Possible values are: NONE, IN_PROGRESS, REJECTED, CERTIFIED. | Optional | 
| ruleAttributes_ticketId | The rule attributes ticket ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.setRecertificationStatus | String | The result of the the recertification status for the specified
change requests | 


#### Command Example
```!skybox-setRecertificationStatus ticketId=395 changeRequestIds=227 ruleAttributes_owner=skyboxview ruleAttributes_comment=comment ruleAttributes_status=IN_PROGRESS ruleAttributes_customFields_defId=1 ruleAttributes_customFields_id=1 ruleAttributes_customFields_dataType=1 ruleAttributes_customFields_entityType=1 ruleAttributes_customFields_name=name ruleAttributes_customFields_value=value```

#### Human Readable Output

>null

### skybox-setTicketDeferChangeRequestsCalculationStatus
***
Enables you to defer the automatic calculation of a
ticket until all change requests are created.


#### Base Command

`skybox-setTicketDeferChangeRequestsCalculationStatus`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ticket ID. | Required | 
| deferChangeRequestsCalculation | l True: Defer calculation of the change<br/>requests<br/>l False: Do not defer calculation. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.setTicketDeferChangeRequestsCalculationStatus | String | Status of changing the defer status change operation | 


#### Command Example
```!skybox-setTicketDeferChangeRequestsCalculationStatus ticketId=415 deferChangeRequestsCalculation=true```

#### Human Readable Output

>null

### skybox-setSponsoringApplication
***
Sets the sponsoring application for a ticket.


#### Base Command

`skybox-setSponsoringApplication`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ticket ID. | Required | 
| sponsoringApplicationId | The sponsoring application ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.setSponsoringApplication | String | The sponsoring application change status | 


#### Command Example
```!skybox-setSponsoringApplication sponsoringApplicationId=1 ticketId=415```

#### Human Readable Output

>null

### skybox-findAccessChangeTickets
***
Retrieves all Access Change tickets that match
the search criteria.


#### Base Command

`skybox-findAccessChangeTickets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_createdBy | The username author. | Optional | 
| filter_freeTextFilter | Free text search in the following ticket fields:<br/>l Title<br/>l Comment<br/>l Owner<br/>l ID<br/>l Status<br/>l Priority<br/>l Vendor reference<br/>l Solutions<br/>l CVE catalog ID<br/>l Custom fields of type String. Possible values are: Title, Comment, Owner, ID, Status, Priority, Vendor reference, Solutions, CVE catalog ID, Custom fields of type String. | Optional | 
| filter_modifiedBy | The modification autor username. | Optional | 
| filter_myGroups | The filter my groups. | Optional | 
| filter_owner | Search tickets by owner. | Optional | 
| filter_phaseName | Search tickets by current phase. | Optional | 
| filter_statusFilter | Search tickets by status.<br/>Possible values:<br/>l New<br/>l InProgress<br/>l Resolved<br/>l Closed<br/>l Rejected<br/>l Ignored<br/>l Verified<br/>l Reopened<br/>l Demoted. Possible values are: New, InProgress, Resolved, Closed, Rejected, Ignored, Verified, Reopened, Demoted. | Optional | 
| filter_ticketIdsFilter | Search tickets by IDs. | Optional | 
| subRange_size | The size of the range. | Optional | 
| subRange_start | The offset of the range. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.findAccessChangeTickets | String | The list of all Access Change tickets that match
the search criteria. | 


#### Command Example
```!skybox-findAccessChangeTickets filter_myGroups=AssignToMyGroup subRange_size=20 subRange_start=1```

#### Human Readable Output

>null

### skybox-getTicketFields
***
Retrieves ticket data from Skybox.
You can use this method with all ticket types.


#### Base Command

`skybox-getTicketFields`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ID of the ticket. | Required | 
| ticketIdType | Signifies whether the ticket ID is the Skybox ticket ID or the ID from the<br/>external ticketing system<br/>Possible values:<br/>l 1 (SBV ID)<br/>l 2 (ID from external ticketing system). Possible values are: 1, 2. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getTicketFields.getTicketFields | String | The ticket data from Skybox | 


#### Command Example
```!skybox-getTicketFields ticketIdType=1 ticketId=380```

#### Context Example
```json
{
    "Skybox": {
        "getTicketFields": [
            {
                "typeCode": 1,
                "value": "380"
            },
            {
                "typeCode": 2,
                "value": null
            },
            {
                "typeCode": 7,
                "value": "Demoted"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|typeCode|value|
>|---|---|
>| 1 | 380 |
>| 2 |  |
>| 7 | Demoted |


### skybox-getTicketsImplementedChangeRequests
***
Retrieves the list of implemented change requests
in the specified tickets according to the
permissions of the user sending the request.


#### Base Command

`skybox-getTicketsImplementedChangeRequests`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketIds | The ticket IDs to get the change requests for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getTicketsImplementedChangeRequests | String | The list of implemented change requests
in the specified tickets according to the
permissions of the user sending the request. | 


#### Command Example
```!skybox-getTicketsImplementedChangeRequests ticketIds=376```

#### Context Example
```json
{
    "Skybox": {
        "getTicketsImplementedChangeRequests": [
            {
                "additionalDetails": "Suggested Position: Last Rule\nRule Logging\n",
                "changeDetails": "Source: app0\nDestination: Partners_Networks\nServices: sqlnet1\n",
                "changeType": "ADD_RULE",
                "comment": "Implemented by Skybox Change Manager",
                "completeDate": "2016-10-02T04:50:03-04:00",
                "completeStatus": "PROVISIONED",
                "dueDate": "2017-08-01T23:58:58.048000-04:00",
                "firewallManagementName": "US_NY_CMA01",
                "firewallName": "main_FW",
                "globalUniqueId": null,
                "id": 253,
                "implementationStatus": "FALSE",
                "isRequiredStatus": "TRUE",
                "lastModificationTime": "2017-07-31T16:56:28.928000-04:00",
                "objectId": "-",
                "owner": "NOC",
                "ticketId": 376,
                "ticketPriority": "P2",
                "workflowName": "General"
            },
            {
                "additionalDetails": "Suggested Position: Last Rule\nRule Logging\n",
                "changeDetails": "Source: app0\nDestination: Partners_Networks\nServices: sqlnet1\n",
                "changeType": "ADD_RULE",
                "comment": "Implemented by Skybox Change Manager",
                "completeDate": "2016-10-02T04:50:03-04:00",
                "completeStatus": "PROVISIONED",
                "dueDate": "2017-08-01T23:58:58.048000-04:00",
                "firewallManagementName": "US_NY_CMA01",
                "firewallName": "prod FW",
                "globalUniqueId": null,
                "id": 254,
                "implementationStatus": "FALSE",
                "isRequiredStatus": "TRUE",
                "lastModificationTime": "2017-07-31T16:56:28.928000-04:00",
                "objectId": "-",
                "owner": "NOC",
                "ticketId": 376,
                "ticketPriority": "P2",
                "workflowName": "General"
            },
            {
                "additionalDetails": "Suggested Position: Last Rule\nRule Logging\n",
                "changeDetails": "Source: app0\nDestination: Partners_Networks\nServices: Service_1521_TCP (New)\n",
                "changeType": "ADD_RULE",
                "comment": "Implemented by Skybox Change Manager",
                "completeDate": "2016-10-02T04:50:03-04:00",
                "completeStatus": "PROVISIONED",
                "dueDate": "2017-08-01T23:58:58.048000-04:00",
                "firewallManagementName": null,
                "firewallName": "Partner1 FW",
                "globalUniqueId": null,
                "id": 255,
                "implementationStatus": "FALSE",
                "isRequiredStatus": "TRUE",
                "lastModificationTime": "2017-07-31T16:56:28.928000-04:00",
                "objectId": "-",
                "owner": "NOC",
                "ticketId": 376,
                "ticketPriority": "P2",
                "workflowName": "General"
            },
            {
                "additionalDetails": null,
                "changeDetails": "Service Object: 1521/TCP",
                "changeType": "ADD_OBJECT",
                "comment": "Implemented by Skybox Change Manager",
                "completeDate": "2016-10-02T04:50:03-04:00",
                "completeStatus": "PROVISIONED",
                "dueDate": "2017-08-01T23:58:58.048000-04:00",
                "firewallManagementName": null,
                "firewallName": "Partner1 FW",
                "globalUniqueId": null,
                "id": 256,
                "implementationStatus": "FALSE",
                "isRequiredStatus": "TRUE",
                "lastModificationTime": "2017-07-31T16:56:28.928000-04:00",
                "objectId": "Service_1521_TCP",
                "owner": "NOC",
                "ticketId": 376,
                "ticketPriority": "P2",
                "workflowName": "General"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|additionalDetails|changeDetails|changeType|comment|completeDate|completeStatus|dueDate|firewallManagementName|firewallName|globalUniqueId|id|implementationStatus|isRequiredStatus|lastModificationTime|objectId|owner|ticketId|ticketPriority|workflowName|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Suggested Position: Last Rule<br/>Rule Logging<br/> | Source: app0<br/>Destination: Partners_Networks<br/>Services: sqlnet1<br/> | ADD_RULE | Implemented by Skybox Change Manager | 2016-10-02T04:50:03-04:00 | PROVISIONED | 2017-08-01T23:58:58.048000-04:00 | US_NY_CMA01 | main_FW |  | 253 | FALSE | TRUE | 2017-07-31T16:56:28.928000-04:00 | - | NOC | 376 | P2 | General |
>| Suggested Position: Last Rule<br/>Rule Logging<br/> | Source: app0<br/>Destination: Partners_Networks<br/>Services: sqlnet1<br/> | ADD_RULE | Implemented by Skybox Change Manager | 2016-10-02T04:50:03-04:00 | PROVISIONED | 2017-08-01T23:58:58.048000-04:00 | US_NY_CMA01 | prod FW |  | 254 | FALSE | TRUE | 2017-07-31T16:56:28.928000-04:00 | - | NOC | 376 | P2 | General |
>| Suggested Position: Last Rule<br/>Rule Logging<br/> | Source: app0<br/>Destination: Partners_Networks<br/>Services: Service_1521_TCP (New)<br/> | ADD_RULE | Implemented by Skybox Change Manager | 2016-10-02T04:50:03-04:00 | PROVISIONED | 2017-08-01T23:58:58.048000-04:00 |  | Partner1 FW |  | 255 | FALSE | TRUE | 2017-07-31T16:56:28.928000-04:00 | - | NOC | 376 | P2 | General |
>|  | Service Object: 1521/TCP | ADD_OBJECT | Implemented by Skybox Change Manager | 2016-10-02T04:50:03-04:00 | PROVISIONED | 2017-08-01T23:58:58.048000-04:00 |  | Partner1 FW |  | 256 | FALSE | TRUE | 2017-07-31T16:56:28.928000-04:00 | Service_1521_TCP | NOC | 376 | P2 | General |


### skybox-getTicketDeferChangeRequestsCalculationStatus
***
Returns the calculation status of the specified
ticket (whether calculation of the change requests
is deferred). Status is boolean


#### Base Command

`skybox-getTicketDeferChangeRequestsCalculationStatus`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | The ticket ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Skybox.getTicketDeferChangeRequestsCalculationStatus | String | The calculation status of the specified
ticket | 


#### Command Example
```!skybox-getTicketDeferChangeRequestsCalculationStatus ticketId=415```

#### Context Example
```json
{
    "Skybox": {
        "getTicketDeferChangeRequestsCalculationStatus": {
            "status": true
        }
    }
}
```

#### Human Readable Output

>### Results
>|status|
>|---|
>| true |

