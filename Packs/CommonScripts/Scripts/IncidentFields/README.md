Returns a dict of all incident fields that exist in the system.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies
---
This script uses the following commands and scripts.
* demisto-api-get

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| exclude_system_fields | Whether to only return non-system fields. If "true", will only output non-system fields. The default value is "false". |
| short_names | Whether to shorten the incident field names. If "true", will cause output to use shortened field names. The default value is "true". |

## Outputs
---
There are no outputs for this script.


## Script Examples
### Example command
```!IncidentFields exclude_system_fields="false" short_names="true"```
### Context Example
```json
{}
```

### Human Readable Output

>```
>{
>    "accountgroups": {
>        "associatedToAll": false,
>        "associatedTypes": [
>            "Brute Force"
>        ],
>        "name": "Account Groups",
>        "shortName": "accountgroups",
>        "type": "shortText"
>    },
>    "accountid": {
>        "associatedToAll": false,
>        "associatedTypes": [
>            "Prisma Cloud",
>            "GCP Compute Engine Misconfiguration",
>            "AWS CloudTrail Misconfiguration",
>            "AWS IAM Policy Misconfiguration",
>            "AWS EC2 Instance Misconfiguration"
>        ],
>        "name": "Account ID",
>        "shortName": "accountid",
>        "type": "shortText"
>    },
>    "accountname": {
>        "associatedToAll": false,
>        "associatedTypes": [
>            "Prisma Cloud",
>            "GCP Compute Engine Misconfiguration",
>            "AWS CloudTrail Misconfiguration",
>            "AWS IAM Policy Misconfiguration",
>            "AWS EC2 Instance Misconfiguration",
>            "Microsoft CAS Alert",
>            "CrowdStrike Falcon Detection"
>        ],
>        "name": "Account Name",
>        "shortName": "accountname",
>        "type": "shortText"
>    },
>    "acquisitionhire": {
>        "associatedToAll": false,
>        "associatedTypes": [
>            "IAM - AD User Activation"
>        ],
>        "name": "Acquisition Hire",
>        "shortName": "acquisitionhire",
>        "type": "shortText"
>    },
>    "activedirectoryaccountstatus": {
>        "associatedToAll": false,
>        "associatedTypes": [
>            "Employee Offboarding"
>        ],
>        "name": "Active Directory Account Status",
>        "shortName": "activedirectoryaccountstatus",
>        "type": "singleSelect"
>    },
>    "activedirectorydisplayname": {
>        "associatedToAll": false,
>        "associatedTypes": [
>            "Employee Offboarding"
>        ],
>        "name": "Active Directory Display Name",
>        "shortName": "activedirectorydisplayname",
>        "type": "shortText"
>    },
>    "activedirectorypasswordstatus": {
>        "associatedToAll": false,
>        "associatedTypes": [
>            "Employee Offboarding"
>        ],
>        "name": "Active Directory Password Status",
>        "shortName": "activedirectorypasswordstatus",
>        "type": "singleSelect"
>    },
>    "agentid": {
>        "associatedToAll": true,
>        "associatedTypes": "all",
>        "name": "Agent ID",
>        "shortName": "agentid",
>        "type": "shortText"
>    },
>    "agentsid": {
>        "associatedToAll": true,
>        "associatedTypes": "all",
>        "name": "Agents ID",
>        "shortName": "agentsid",
>        "type": "multiSelect"
>    },
>    "agentversion": {
>        "associatedToAll": true,
>        "associatedTypes": "all",
>        "name": "Agent Version",
>        "shortName": "agentversion",
>        "type": "multiSelect"
>    },
>```

### Troubleshooting
Multi-tenant environments should be configured with the Cortex Rest API instance when using this 
automation. Make sure the *Use tenant* parameter (in the Cortex Rest API integration) is checked 
to ensure that API calls are made to the current tenant instead of the master tenant.