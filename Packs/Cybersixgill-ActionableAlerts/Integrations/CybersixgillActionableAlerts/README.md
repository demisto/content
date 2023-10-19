Cybersixgill automatically collects intelligence in real-time on all items that appear in the underground sources which we monitor. By using various rules and machine learning models, Cybersixgill automatically correlates these intelligence items with pre defined organization assets, and automatically alerts users in real time of any relevant intelligence items.

## Configure Cybersixgill Actionable Alerts on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cybersixgill Actionable Alerts.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Cybersixgill API client ID | client ID for Cybersixgill Alerts API | True |
    | Cybersixgill API client secret | client secret for Cybersixgill Alerts API | True |
    | Cybersixgill Organization ID | Organization ID for Cybersixgill Alerts API | False |
    | Maximum number of incidents to fetch - maximum is 25 | Maximum number of incidents to fetch - maximum is 25 | False |
    | How many days back to fetch incidents on the first run - maximum is 30 | How many days back to fetch incidents on the first run - maximum is 30 | False |
    | Filter by alert threat level |  | False |
    | Filter by alert threat type | Filter by alert threat type | False |
    | Use system proxy settings | Use system proxy settings | False |
    | Trust any certificate (not secure) |  | False |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Incidents Fetch Interval |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
#### Command example
```!cybersixgill-update-alert-status alert_id=6524d72be6ee01241b57a579 alert_status=in_treatment```
#### Human Readable Output

>Actionable alert status updated

#### Command example
```!cybersixgill-update-alert-status alert_id=6524d72be6ee01241b57a579 alert_status=resolved aggregate_alert_id=0```
#### Human Readable Output

>Actionable alert status updated

### cybersixgill-enrich-context

***
Fetch and add context Data for certain alert types.

#### Base Command

`cybersixgill-enrich-context`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert id to fetch context. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cybersixgill.Actor | string | Actor for Compromised CC alert. | 
| Cybersixgill.AdditionalKeywords | string | Additional keywords for Github alert | 
| Cybersixgill.BIN | string | BIN for Compromised CC alert. | 
| Cybersixgill.BreachDate | string | Breach Date for Credentials leak alert. | 
| Cybersixgill.CustomerKeywords | string | Customer Keywords for Github alert. | 
| Cybersixgill.Date | string | Date for Compromised CC alert. | 
| Cybersixgill.DetectionTime | string | Detection time for Phishing alert. | 
| Cybersixgill.DomainCreationDate | string | Domain creation date for Phishing alert. | 
| Cybersixgill.DomainStatus | string | Domain status for Phishing alert. | 
| Cybersixgill.Email | string. | Email ID for Credentials leak alert. | 
| Cybersixgill.Full_number | string | Full CC number for Compromised CC alert. | 
| Cybersixgill.Hash | string | Password hash for Credentials leak alert. | 
| Cybersixgill.Host | string | Host for Credentials leak alert. | 
| Cybersixgill.HostDomain | string | Host Domain for Credentials leak alert. | 
| Cybersixgill.IPAddresses | string | IPAddresses for Phishing alert. | 
| Cybersixgill.MXServers | string | MX Servers for Phishing alert. | 
| Cybersixgill.Malware | string | Malware for Credentials leak alert. | 
| Cybersixgill.Name | string | Name for Credentials leak alert. | 
| Cybersixgill.NameServers | string | Name Servers for Phishing alert. | 
| Cybersixgill.Nameservers | string | Name Servers for Phishing alert. | 
| Cybersixgill.Password | string | Password for Credentials leak alert. | 
| Cybersixgill.Registrar | string | Registrar for Phishing alert. | 
| Cybersixgill.RepositoryName | string | Repository name for Github alert. | 
| Cybersixgill.RepositoryOwnerURL | string | Repositor Owner URL for Github alert. | 
| Cybersixgill.RepositoryUrl | string | Repository URL for Github alert. | 
| Cybersixgill.RogueMXHostDetection | string | Rogue MX hosts detection for Phishing alert. | 
| Cybersixgill.Site | string | Site for Compromised CC alert. | 
| Cybersixgill.SuspiciousDomain | string | Suspicious domain for Phishing alert. | 
| Cybersixgill.Text | string | The actual post text for Compromised CC alert. | 
| Cybersixgill.TriggeredDomain | string | domain that tirggered the Phishing alert. | 
| Cybersixgill.IPAddresses | string | IP Addresses for Phishing alert. | 
| Cybersixgill.DetectionTime | string | Detection time for Phishing alert. | 
| Cybersixgill.MXServers | string | MX Servers for Phishing alert. | 

#### Command example
```!cybersixgill-enrich-context alert_id=6524d72be6ee01241b57a579```
#### Context Example
```json
{
    "Cybersixgill": {
        "DomainCreationDate": "2023-10-08",
        "DomainStatus": "clientTransferProhibited",
        "IPAddresses": "122.xx.94.xx",
        "MXServers": "",
        "NameServers": "**.g*a*e.net, n*2.g*a*e.net",
        "Registrar": "G*a*e.com Pte. Ltd.",
        "SuspiciousDomain": "ni**e.com",
        "TriggeredDomain": "ni*e.com"
    }
}
```

#### Human Readable Output

>### Results
>|DomainCreationDate|DomainStatus|IPAddresses|MXServers|NameServers|Registrar|SuspiciousDomain|TriggeredDomain|
>|---|---|---|---|---|---|---|---|
>| 2023-10-08 | clientTransferProhibited | 122.xx.94.xx |  | **.g*a*e.net, n*2.g*a*e.net | G*a*e.com Pte. Ltd. | ni**e.com | ni**e.com |

