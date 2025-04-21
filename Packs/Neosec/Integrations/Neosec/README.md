Neosec is reinventing application security. Its pioneering SaaS platform gives security professionals visibility into behavior across their entire API estate. Built for organizations that expose APIs to partners, suppliers, and users, Neosec discovers all your APIs, analyzes their behavior, and stops threats lurking inside.

##### What does this pack do?
- Ingests alerts from Neosec into XSOAR: 
  - Neosec Posture Alerts covers OWASP top 10 and other vulnerabilities in API endpoints. Handled by R&D. 
  - Neosec Runtime Alerts are on suspicious or malicious user behavior. Handled by SOC analysts.
- Close/Reopens Neosec Alerts

## Configure Neosec in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key | The API Key to use to connect to Neograph API | True |
| URL | Neograph API URL  | False |
| Tenant Key | Tenant identifer (Tenant name) | False |
| Fetch alerts with status | Select the statuses of the alerts you wish to fetch (Open/Closed). | False |
| Fetch alerts with type | Select the types of the alerts you wish to fetch (Posture/Runtime). | False |
| Severity of alerts to fetch | Select the severities of the alerts you wish to fetch.  | False |
| Max incident to fetch |  | False |
| Incident type |  | False |
| Fetch incidents |  | False |
| First fetch time |  | False |
| De-tokenize alerts | Select this if you use tokenization on PII data and wish to ingest Neosec alerts to XSOAR with detokenized data.  | False |
| Neosec Node URL | If the 'De-tokenize alets' is selected, provide the url of the Neosec Node. for example http://[neosec node ip]:8080   | False |


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### neosec-alert-status-set
***
Set alert status(Open, Closed)


#### Base Command

`neosec-alert-status-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert id(UUID) in the Neosec platform. . | Required | 
| alert_status | The alert status. Possible values are: Open, Closed. | Required | 


#### Context Output

There is no context output for this command.