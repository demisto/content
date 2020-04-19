Delivering the next generation of deep & dark web threat intelligence feeds, Sixgill tailors
threat intelligence to customers’ intelligence needs, maximizing effective mitigation and remediation. Using an agile collection methodology and its proprietary collection automation algorithm, Sixgill provides broad coverage of exclusive-access deep and dark web sources, as well as relevant surface web sources. Sixgill harnesses artificial intelligence and machine learning to automate the production cycle of cyber intelligence from monitoring through extraction to production - unleashing both existing platforms and teams’ performance.

The integration will focus on
Retrieving Sixgill's Actionable Alerts as incidents

This integration was integrated and tested with version 0.1.2 of sixgill-clients

## Use Cases
Fetch Incidents & Events

## Configure Sixgill on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Sixgill.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| client_id | Sixgill API client ID | True |
| client_secret | Sixgill API client secret | True |
| maxIncidents | Max number of incidents that can be fetched | False |
| severity | Filter by alert template severity | False |
| threat_level | Filter by alert threat level | False |
| threat_type | Filter by alert threat type | False |

4. Click **Test** to validate the URLs, token, and connection.
## Fetch incidents
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
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
## Additional Information
Contact us: support@cybersixgill.com

## Known Limitations
