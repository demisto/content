## Information  
A valid API Token for XSOAR from Recorded Future needed to fetch information.
[Get help with Recorded Future for Cortex XSOAR](https://www.recordedfuture.com/support/demisto-integration/).  

**Version:** 1.0.0

---

## Configuration
| Parameter                                      | Description                                                                                                                                                                                                                                 |
|------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Server URL                                     | The URL to the Recorded Future ConnectAPI.                                                                                                                                                                                                  |
| API Token                                      | Valid API Token from Recorded Future.                                                                                                                                                                                                       |
| Classifier                                     | Select "Recorded Future Playbook Alert Classifier".                                                                                                                                                                                                      |
| Mapper (Incoming)                              | Select "Recorded Future Playbook Alert Mapper".                                                                                                                                                                                                                                                                                                              |
| Trust any certificate (not secure)             | -                                                                                                                                                  
| Use system proxy settings                      | -                                                                                                                                                                                                                                           |
| First incident fetch: Time range | Limit incidents to include in the first fetch by time range. Input format: "NN hours" or "NN days". E.g., input "5 days" to fetch all incidents created in the last 5 days.                                                                                         |
| Playbook Alerts: Fetched Categories                               | Some listed Alert Categories may be unavailable due to limitations in the current Recorded Future subscription. The "All Available" option will fetch Playbook Alerts of all types that are available to the specific token                                   |
| Playbook Alerts: Fetched Statuses       | Choose what statuses that is included in the fetch (New, In Progress, Dismissed. Resolved) |
| Playbook Alerts: Fetched Priorites Threshold                   | Choose the threshold of which priorites are fetched (Informational < Moderate < High)                                                                                                                                                                                                                                           |
| Maximum number of incidents per fetch          | Limits the number of returned incidents per fetch                                                                                                                                                                                                                                          |
| Incidents Fetch Interval                       | Choose the interval of polling for updated alerts                                                                                                                                                                                                                                           |
---

## Available Actions
* Search action
  * Search and filter Playbook alerts from Recorded Future to find what is available
  * Searches for the last 24 hours by default
* Details action
  * Provide a Playbook alert id and retrieve the details of that alert
* Update action
  * Update the status of Playbook alerts in Recorded Future

Copyright 2020-2023 Recorded Future, Inc.
