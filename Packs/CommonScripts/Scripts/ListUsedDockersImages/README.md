List all dockers images that are in used by the installed Integration and Automations. 

Example: !ListUsedDockersImages

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Utility, Dockers, Integration, Automation |


## Inputs
---

 **Argument Name** | **Description** |
| --- | --- |
|export_to_context | a boolean that indicates if to export the result into a context (default is true)

## Outputs
---
Table that list all dockers images that are in used by installed Integrations and Automations

Output example:

**Docker Image** | **Integrations/Automations** |
| --- | --- |
|demisto/ldap:1.0.0.23980 | Active Directory Query v2
|demisto/python3:3.9.6.22912| AutoFocus Daily Feed, McAfee ePO, ServiceNow CMDB, ServiceNow IAM, ServiceNow v2
|demisto/python3:3.9.6.24019| AutoFocus Feed, GitLab (Community Contribution), Palo Alto Networks AutoFocus v2, ExtractEmailV2, GetIndicatorDBotScoreFromCache


