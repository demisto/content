Runs validation and linting using the Demisto SDK on content items, such as integrations, automations and content packs.
This automation script is used as part of the content validation that runs as part of the contribution flow.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 5.5.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| filename | Name of the file to validate. |
| data | Base64 encoded contents of the file to validate. |
| entry_id | ID of War Room file entry for the ZIP content pack or the integration/automation YAML. |
| use_system_proxy | Use system proxy settings to download required models from GitHub. |
| trust_any_certificate | Trust any certificate (not secure) to download required models from GitHub. |

## Outputs

---
| **Path** | **Description** | **Type** |
| --- | -- | --- |
| ValidationResult.Name| Name of validated item. | String |
| ValidationResult.Error | The validation error message. | String |
| ValidationResult.Line | The code line number in which the error was found in the lint. | String |
| ValidationResult.ErrorCode | The error code or the name of the linter that identified the issue. | String |

## Script Example

```!ValidateContent entry_id=G2SUaH9ZPmfw7QHWQNk2pa@6```

## Context Example

```
    "ValidationResult": [
        {
            "Name": "MyScript",
            "Error": "{unterminated string literal (detected at line 166)  [syntax]"
            "Line": 165,
            "Error Code/Linter": "mypy"
        },
        {
            "Name": "MyScript",
            "Error": "The following commands contain duplicated arguments:Command example-my-command, contains multiple appearances of the following arguments message.Please make sure to remove the duplications.",
            "Error Code/Linter": "IN113"
        }
    ]
}
```

## Human Readable Output

### Validation Results

| Name     | Error                                                                                                                                                                                         | Line | 	Error Code/Linter |
|----------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------|--------------------|
| MyScript | The following commands contain duplicated arguments: Command example-my-command, contains multiple appearances of the following arguments message. Please make sure to remove the duplications. |      | IN113              |
| MyScript | unterminated string literal (detected at line 166)  [syntax]                                                                                                                                  | 166  | mypy               |
