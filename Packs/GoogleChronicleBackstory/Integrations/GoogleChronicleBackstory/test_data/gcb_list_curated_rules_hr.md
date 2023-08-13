### Curated Rules:
|Rule ID|Rule Name|Severity|Rule Type|Rule Set|Description|
|---|---|---|---|---|---|
| ur_ttp_GCP__Global | GCE SSH Keys | Low | SINGLE_EVENT | 00000000-0000-0000-0000-000000000000 | Identifies the addition of project-wide SSH keys where there were previously none. |
| ur_ttp_GCP__Editor | GCP Service Account Editor | Low | MULTI_EVENT | 00000000-0000-0000-0000-000000000000 | Identifies a new Service Account created with Editor role within the project. |

Maximum number of curated rules specified in page_size has been returned. To fetch the next set of curated rules, execute the command with the page token as next_page_token.