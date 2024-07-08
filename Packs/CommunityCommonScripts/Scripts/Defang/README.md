Defangs IP, Mail and URL address to prevent them from being recognized.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utilities |
| Cortex XSOAR Version | 6.1.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| input | The input to be defanged. |
| defang_options | Specify which IOC needs defanging. |
| mail_options | Mail defang can be configured to merely defang . or @ or both. |
| url_options | URL defang can be configured to merely defang . or https or :// or all. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Defang.output | The defanged output | string |
