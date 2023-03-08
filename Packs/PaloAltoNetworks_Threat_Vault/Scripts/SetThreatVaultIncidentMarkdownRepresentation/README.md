This automation takes several Incident fields from the Threat Vault incident context and displays them as markdown in the layout.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | dynamic-section |

## Inputs
---
There are no inputs for this script.

## Outputs
---
There are no outputs for this script.


## Script Examples
### Example command
```!SetThreatVaultIncidentMarkdownRepresentation```
### Context Example
```json
{"Spyware": 
    [
        {
            "severity": "medium",
            "pan_id": 22144,
            "attack_name": "WebCompanion Adware Traffic Detection",
            "category": "spyware",
            "action": "alert",
            "change_data": "new coverage",
            "min_version": "8.1.0",
            "max_version": ""
        },
        {
            "severity": "medium",
            "pan_id": 22145,
            "attack_name": "AdLoad Adware Traffic Detection",
            "category": "spyware",
            "action": "alert",
            "change_data": "new coverage",
            "min_version": "8.1.0",
            "max_version": ""
        }
    ]
}
```

### Human Readable Output

### Spyware
|action|attack_name|category|change_data|max_version|min_version|pan_id|severity|
|---|---|---|---|---|---|---|---|
| alert | WebCompanion Adware Traffic Detection | spyware | new coverage |  | 8.1.0 | 22144 | medium |
| alert | AdLoad Adware Traffic Detection | spyware | new coverage |  | 8.1.0 | 22145 | medium |
