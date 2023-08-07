Determine GCP project hierarchy by looking up parent objects until the organization level is reached.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.8.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| project_id | The project ID instead of the project number.  No need to supply `projects/` before the ID \(i.e., use \`project-name\` instead of \`projects/project-name\` or \`projects/111111111111\`\). |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| GCPHierarchy.id | ID of the project/folder/organization object, such as \`folders/folder-name\`. | string |
| GCPHierarchy.level | Level in relation to the original project such as project, 1, 2, etc. | string |
| GCPHierarchy.number | Number of the project/folder/organization object such as \`folders/111111111111\`. | string |
