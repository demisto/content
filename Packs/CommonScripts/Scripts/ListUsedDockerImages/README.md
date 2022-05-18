List all Docker images that are in use by the installed integrations and automations.

Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility, Dockers, General |
| Cortex XSOAR Version | 6.1.0 |

Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| export_to_context | Whether to export the result to context. Possible values: "true" and "false". Default is "true". |

Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| UsedDockerImages.DockerImage | The Docker image name. | String |
| UsedDockerImages.ContentItem | The integration or automation name that used the specific Docker image. | String |

## Script Example

```!ListUsedDockerImages```

## Context Example

```json
{
  "UsedDockerImages": [
    {
      "ContentItem": [
        "Active Directory Query v2"
      ],
      "DockerImage": "demisto/ldap:1.0.0.23980"
    },
    {
      "ContentItem": [
        "AutoFocus Daily Feed",
        "McAfee ePO",
        "ServiceNow CMDB",
        "ServiceNow IAM",
        "ServiceNow v2"
      ],
      "DockerImage": "demisto/python3:3.9.6.22912"
    },
    {
      "ContentItem": [
        "AutoFocus Feed",
        "GitLab (Community Contribution)",
        "Palo Alto Networks AutoFocus v2",
        "ExtractEmailV2",
        "GetIndicatorDBotScoreFromCache"
      ],
      "DockerImage": "demisto/python3:3.9.6.24019"
    }
  ]
}
```

## Human Readable Output

 ### Docker Images In use:
|Docker Image|Content Item|
|---|---|
| demisto/ldap:1.0.0.23980 | Active Directory Query v2| 
| demisto/python3:3.9.6.22912 | AutoFocus Daily Feed,<br/>McAfee ePO,<br/>ServiceNow CMDB,<br/>ServiceNow IAM,<br/>ServiceNow v2| 
| demisto/python3:3.9.6.24019 | AutoFocus Feed,<br/>GitLab (Community Contribution),<br/>Palo Alto Networks AutoFocus v2,<br/>ExtractEmailV2,<br/>GetIndicatorDBotScoreFromCache|
