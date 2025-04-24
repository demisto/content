Copies a file from this incident to the specified incident. The file is recorded as an entry in the specified incident’s War Room.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | DemistoAPI |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies

---
This script uses the following commands and scripts.

* core-api-multipart

## Inputs

---

| **Argument Name** | **Description**                                                                                                                                                                                                                                    |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| entryID           | File entry ID.                                                                                                                                                                                                                                      |
| incidentID        | Incident ID to upload the file to.                                                                                                                                                                                                                  |
| body              | Request body.                                                                                                                                                                                                                                       |
| target            | Where to upload the file<br/>- Available options are:<br/>- \`war room entry\`: the file will be uploaded as War Room entry.<br/>- \`incident attachment\`: the file will be uploaded as incident attachment.<br/>- default are \`war room entry\` |
| using             | Integration instance to use to run the command.                                                                                                                                                                                                     |
## Outputs

---
There are no outputs for this script.

### Troubleshooting

Multi-tenant environments should be configured with the Cortex Rest API instance when using this 
automation. Make sure the *Use tenant* parameter (in the Cortex Rest API integration) is checked 
to ensure that API calls are made to the current tenant instead of the master tenant.