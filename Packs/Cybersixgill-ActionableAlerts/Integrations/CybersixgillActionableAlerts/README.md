Cybersixgill automatically collects intelligence in real-time on all items that appear in the underground sources which we monitor. By using various rules and machine learning models, Cybersixgill automatically correlates these intelligence items with pre defined
organization assets, and automatically alerts users in real time of any relevant intelligence items.

The integration will focus on retrieving Cybersixgill's Actionable Alerts as incidents

## Use Cases
Fetch Incidents & Events

## Configure Cybersixgill on XSOAR


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| client_id | Cybersixgill API client ID | True |
| client_secret | Cybersixgill API client secret | True |
| threat_level | Filter by alert threat level | False |
| threat_type | Filter by alert threat type | False |

## Fetch incidents
You can execute these commands from the XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

## output
```
[{
'name': "<alert name>",
'occurred': '<occurred>',
'details': '<details>',
'severity': <severity>,
'rawJSON': '{
    "alert_name": "<alert name>",
    "category": "regular",
    "content": "<some content>",
    "date": "<date>",
    "id": "<id>",
    "lang": "English",
    "langcode": "en",
    "read": false,
    "threat_level": "imminent",
    "threats": ["Fraud"],
    "title": "<title>",
    "user_id": "<id>",
    "sixgill_severity": 10}'
}]
```

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cybersixgill-update-alert-status
***
updates the existing actionable alert status


#### Base Command

`cybersixgill-update-alert-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert id to update. | Required |
| alert_status | The new status. | Required |
| aggregate_alert_id | The aggregate alert id. | Optional |


#### Context Output

There is no context output for this command.
## Additional Information
Contact us: support@cybersixgill.com
