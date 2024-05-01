Check DomainTools domain tags and if a tag is found mark incident as high severity

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | DomainTools |
| Cortex XSOAR Version | 6.9.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| incident_id | Incident ID |
| domain_tags | Array of tags in the form of \[\{'label': 'tag1'\},\{'label': 'tag2'\},\{'label': 'tag3'\}\] |
| malicious_tags | Comma-seperated value of malicious tags to check. tag1,tag2,tag3 |

## Outputs

---
There are no outputs for this script.
