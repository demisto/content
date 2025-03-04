This automation allows the definition of CNCS values (for portuguese organizations) or ENISA (for non portuguese organizations). It is used to populate the main options for a data collection task. If a main option is already present is used in classification arg and this automation will return all the specific values for that specific main option.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| classification | Value to filter from either CNCS or ENISA codes |
| org_type | Type of organization \(non_pt or pt_org\) |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IncidentClassification |  | Unknown |
