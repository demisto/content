Generates a Palo Alto Networks WildFire PDF report.
This integration was created and tested with version 10.1 of PAN-OS

## Configure Palo Alto Networks WildFire Reports on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Palo Alto Networks WildFire Reports.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server base URL (e.g. https://192.168.0.1/publicapi) |  | True |
    | API Key |  | True |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Trust any certificate (not secure) | Trust any certificate \(not secure\). | False |
    | Use system proxy settings | Use system proxy settings. | False |
    | Return warning entry for unsupported file types |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### wildfire-get-report
***
Retrieves results for a file hash using WildFire.


#### Base Command

`wildfire-get-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | SHA256 hash to check. | Optional | 
| md5 | MD5 hash to check. | Optional | 
| hash | Deprecated - Use the sha256 argument instead. | Optional | 
| verbose | Receive extended information from WildFire. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!wildfire-get-report sha256=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890```

#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "123456",
        "Extension": "pdf",
        "Info": "application/pdf",
        "Name": "wildfire_report_abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890.pdf",
        "Size": 27575,
        "Type": "PDF document, version 1.4"
    }
}
```
#### Human Readable Output
