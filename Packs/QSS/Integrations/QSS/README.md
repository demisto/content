QSS integration helps you to fetch Cases from Q-SCMP and add new cases automatically through XSOAR.
This integration was integrated and tested with version 3.6 of Q-SCMP. Please contact your platform administrtor to enable Cortex XSOAR integration. 

### Configure QSS on Cortex XSOAR

### Prerequisites

1. Please contact your Q-SCMP platform administrtor to obtain Cortex **API Key**. 
2. Please contact your Q-SCMP platform administrtor to obtain Cortex **Server URL**. 


### Configure Q-SCMP on Cortex XSOAR
1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for **QSS**.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://<Q-SCMP_service_host>) | True |
    | Fetch incidents | False |
    | Incident type | False |
    | Max fetch | False |
    | API Key | True |
    | Fetch cases with status (Open, Closed) | False |
    | Minimum severity of cases to fetch | False |
    | Flase positive cases to fetch | False |
    | Back time duration of cases to fetch (Hours) | True |
    | First fetch time | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

5. Click **Test** to validate the URLs, token, and connection.

### Use Cases

1. Fetch SOC cases to Cortex SOAR based on the case severity.
2. Fetch SOC cases to Cortex SOAR based on the case status.
3. Fetch SOC cases to Cortex SOAR based on the case false positive flag.

### Fetched Cases Data

1. Case ID
2. Case Creation Date
3. Case Number
4. Case Category
5. Case Sub Category
6. Case Severity
7. Case Status
8. Case Title
9. Case Assignee
10. Case False Positive
11. Case Created By
12. Case Last Update
13. Case TLP
14. Case Description
15. Case Notes
16. Case Tags
17. Case Custom Attributes
18. Case Assets
19. Case IOCs

