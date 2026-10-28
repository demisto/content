Fetches Cisco Email Threat Defense (ETD) message events and creates incidents.
This integration was integrated and tested with of ETDXsoarConnector.

## Configure Cisco ETD Connector in Cortex

| **Parameter** | **Required** |
| --- | --- |
| ETD Base URL | True |
| api_key | True |
| API Key | True |
| Client ID | True |
| client_secret | True |
| Client Secret | True |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |
| First Fetch Time | False |
| Fetch incidents |  |
| Incidents Fetch Interval |  |
| Incident type | False |
| Max fetch | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cisco-etd-move-message

***
Reclassifies and remediates an ETD message.

#### Base Command

`cisco-etd-move-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | The ETD message ID. | Required |
| verdict | The new verdict. | Required |
| folder | The new folder action. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ETD.Message.ID | String | The message ID. |
| ETD.Message.Verdict | String | The updated verdict. |
| ETD.Message.Folder | String | The updated folder. |

#### Command Example

```text
!cisco-etd-move-message message_id="123456789abcdef" verdict="malicious" folder="quarantine"
```

#### Context Example

```json
{
  "ETD": {
    "Message": {
      "ID": "123456789abcdef",
      "Verdict": "malicious",
      "Folder": "quarantine"
    }
  }
}
```
