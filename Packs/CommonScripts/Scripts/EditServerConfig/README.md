Edit the server configuration (under *settings/troubleshooting*). You can either add a new configuration or update and remove an existing one.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| action | The action to make. If update is chosen and the key does not exist, a new key will be added. |
| key | The key to set. |
| value | The value to set. |

## Outputs
---
There are no outputs for this script.


## Script Example
```!EditServerConfig action=update key=content.unlock.integrations value=HelloWorld```


## Human Readable Output

>Server configuration with content.unlock.integrations was updated successfully.
