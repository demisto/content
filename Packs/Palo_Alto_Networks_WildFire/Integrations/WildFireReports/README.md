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
### wildfire-report
***
Retrieves results for a file hash using WildFire.


#### Base Command

`wildfire-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | SHA256 hash to check. | Optional | 
| md5 | MD5 hash to check. | Optional | 
| hash | Deprecated - Use the sha256 argument instead. | Optional | 
| verbose | Receive extended information from WildFire. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | string | Name of the file. | 
| File.Type | string | File type, for example: "PE" | 
| File.Size | number | Size of the file. | 
| File.MD5 | string | MD5 hash of the file. | 
| File.SHA1 | string | SHA1 hash of the file. | 
| File.SHA256 | string | SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | Vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| WildFire.Report.Status | string | The status of the submissiom. | 
| WildFire.Report.SHA256 | string | SHA256 hash of the submission. | 
| InfoFile.EntryID | string | The EntryID of the report file. | 
| InfoFile.Extension | string | The extension of the report file. | 
| InfoFile.Name | string | The name of the report file. | 
| InfoFile.Info | string | Details of the report file. | 
| InfoFile.Size | number | The size of the report file. | 
| InfoFile.Type | string | The report file type. | 
| WildFire.Report.Network.UDP.IP | string | Submission related IPs, in UDP protocol. | 
| WildFire.Report.Network.UDP.Port | string | Submission related ports, in UDP protocol. | 
| WildFire.Report.Network.TCP.IP | string | Submission related IPs, in TCP protocol. | 
| WildFire.Report.Network.TCP.Port | string | Submission related ports, in TCP protocol. | 
| WildFire.Report.Network.DNS.Query | string | Submission DNS queries. | 
| WildFire.Report.Network.DNS.Response | string | Submission DNS responses. | 
| WildFire.Report.Evidence.md5 | string | Submission evidence MD5 hash. | 
| WildFire.Report.Evidence.Text | string | Submission evidence text. | 
| WildFire.Report.detection_reasons.description | string | Reason for the detection verdict. | 
| WildFire.Report.detection_reasons.name | string | Name of the detection. | 
| WildFire.Report.detection_reasons.type | string | Type of the detection. | 
| WildFire.Report.detection_reasons.verdict | string | Verdict of the detection. | 
| WildFire.Report.detection_reasons.artifacts | unknown | Artifacts of the detection reasons. | 
| WildFire.Report.iocs | unknown | Associated IOCs. | 
| WildFire.Report.verdict | string | The verdict of the report. | 


#### Command Example
```!wildfire-report sha256=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "Score": 1,
        "Type": "file",
        "Vendor": "WildFire-Reports"
    },
    "File": {
        "MD5": "abcdef1234567890abcdef1234567890",
        "SHA1": "abcdef1234567890abcdef1234567890",
        "SHA256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "Size": "1000",
        "Tags": [
            "malware"
        ],
        "Type": "PDF"
    },
    "InfoFile": {
        "EntryID": "123456",
        "Extension": "pdf",
        "Info": "application/pdf",
        "Name": "wildfire_report_abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890.pdf",
        "Size": 1000,
        "Type": "PDF document, version 1.4"
    },
    "WildFire": {
        "Report": {
            "SHA256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "Status": "Success"
        }
    }
}
```

#### Human Readable Output

>### WildFire File Report - PDF format
>|FileType|MD5|SHA256|Size|Status|
>|---|---|---|---|---|
>| PDF | abcdef1234567890abcdef1234567890 | abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 | 1000 | Completed |

