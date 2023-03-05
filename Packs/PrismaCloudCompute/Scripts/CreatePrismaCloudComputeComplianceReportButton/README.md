Generate a compliance report via clicking a button.

## Script Data

---

| **Name** | **Description** |
| --- |-----------------|
| Script Type | python3         |
| Cortex XSOAR Version | 6.0.0           |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| table | The table of data. |
| title | The title of the report. |
| to | The to email address. |

## Outputs

---
There are no outputs for this script.

## Script Examples

### Example command

```!CreatePrismaCloudComputeComplianceReportButton title=test to=test@paloaltonetworks.com table=`{"cve": "cve-123456"}` ```

### Context Example

```json
{}
```

### Human Readable Output

>Mail sent successfully
