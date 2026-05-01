## SupportTicketCategoryParser

Parses a delimited support ticket classification string (`<issue_category>|||<problem_concentration>`) into separate fields and validates both values against a provided taxonomy.

### Use Case

The `SupportTicketClassification` LLM script returns a single delimited string in the format `<issue_category>|||<problem_concentration>` (e.g., `XDR Agent|||XDR Agent for Enterprise - Linux`). This script splits that string on the `|||` delimiter, extracts the issue category and problem concentration, and validates both against the provided taxonomy.

### Inputs

| **Argument** | **Description** | **Required** |
| --- | --- | --- |
| classification_result | The combined classification result string from the SupportTicketClassification script, in the format: `<issue_category>\|\|\|<problem_concentration>`. | Required |
| taxonomy | The support ticket taxonomy as a JSON string (list of dicts mapping categories to concentrations). Obtained from the `core-get-support-ticket-taxonomy` command output. | Required |

### Outputs

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Core.SupportTicketCategoryParser.IssueCategory | The parsed issue category. | String |
| Core.SupportTicketCategoryParser.ProblemConcentration | The parsed problem concentration. | String |
| Core.SupportTicketCategoryParser.IsValid | Whether both values are valid entries in the taxonomy. | Boolean |
| Core.SupportTicketCategoryParser.Warnings | List of validation warnings if any values are not found in the taxonomy. | Unknown |

### Example

**Input:**

```
!SupportTicketCategoryParser classification_result="XDR Agent|||XDR Agent for Enterprise - Linux" taxonomy=${Core.SupportTicketTaxonomy}
```

**Output:**

```
Issue Category: XDR Agent
Problem Concentration: XDR Agent for Enterprise - Linux
Valid: Yes
```
