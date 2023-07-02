ANY.RUN is a cloud-based sanbox with interactive access.

## Use Cases
1. Submit a file, remote file, or URL to ANY.RUN for analysis.
2. Retrieve report details for a given analysis task ID.
3. View history of analysis tasks.


## Configure ANYRUN on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ANYRUN.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | Username | True |
    | Password | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. If using API Key authentication method, insert the text `_token` into the **Username** parameter and the API key you have into the **Password**.

5. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
The commands allow you to launch and download only your own tasks, public submissions are not available at this point.

### anyrun-get-history
***
Get analysis history.


#### Base Command

`anyrun-get-history`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team | If true, gets team history. If empty, gets your submitted analyses history. Possible values are: true, false. Default is false. | Optional | 
| skip | The number of analyses to skip. Possible values are: . Default is 0. | Optional | 
| limit | Limits the history retrieved/searched to the specified number of executed analyses. The range is 1-100. Default is 25. | Optional | 
| filter | File name, hash, or task ID by which to filter the task history. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ANYRUN.Task.Name | String | Task name. | 
| ANYRUN.Task.Verdict | String | ANY.RUN verdict for the submitted file's status. | 
| ANYRUN.Task.Related | String | ANY.RUN link to a related file. | 
| ANYRUN.Task.File | String | ANY.RUN link to download the submitted file. | 
| ANYRUN.Task.Date | Date | The date that the file was submitted for analysis. | 
| ANYRUN.Task.Hash.MD5 | String | MD5 hash of the submitted file. | 
| ANYRUN.Task.Hash.SHA1 | String | SHA1 hash of the submitted file. | 
| ANYRUN.Task.Hash.SHA256 | String | SHA256 hash of the submitted file. | 
| ANYRUN.Task.Hash.HeadHash | String | Head hash of the submitted file. | 
| ANYRUN.Task.Hash.SSDeep | String | SSDeep hash of the submitted file. | 


#### Command Example

```anyrun-get-history skip=0 team=false filter=scribbles2.txt.zip```

#### Context Example
```
{
    "ANYRUN.Task": [
        {
            "Hash": {
                "HeadHash": "e61fcc6a06420106fa6642ef833b9c38", 
                "SHA1": "475d7efc7983357e51ea780e350b0efe6a5ba2e2", 
                "SHA256": "1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1", 
                "SSDeep": "24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9", 
                "MD5": "e61fcc6a06420106fa6642ef833b9c38"
            }, 
            "Name": "scribbles2.txt.zip", 
            "Related": "[https://app.any.run/tasks/892455a2-8c96-45fb-9f2a-18ca4ef184f9](https://app.any.run/tasks/892455a2-8c96-45fb-9f2a-18ca4ef184f9)", 
            "Verdict": "No threats detected", 
            "File": "https://content.any.run/tasks/892455a2-8c96-45fb-9f2a-18ca4ef184f9/download/files/afca4a63-9fe0-461c-8e73-c8fd784cf90e", 
            "Date": "2019-04-24T07:13:06.087Z", 
            "ID": "892455a2-8c96-45fb-9f2a-18ca4ef184f9"
        }, 
        {
            "Hash": {
                "HeadHash": "e61fcc6a06420106fa6642ef833b9c38", 
                "SHA1": "475d7efc7983357e51ea780e350b0efe6a5ba2e2", 
                "SHA256": "1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1", 
                "SSDeep": "24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9", 
                "MD5": "e61fcc6a06420106fa6642ef833b9c38"
            }, 
            "Name": "scribbles2.txt.zip", 
            "Related": "[https://app.any.run/tasks/fe7c63ef-2b7f-4e70-b50c-996ae34b28ef](https://app.any.run/tasks/fe7c63ef-2b7f-4e70-b50c-996ae34b28ef)", 
            "Verdict": "No threats detected", 
            "File": "https://content.any.run/tasks/fe7c63ef-2b7f-4e70-b50c-996ae34b28ef/download/files/227a7bd4-5baa-477b-b319-58d7619b79ef", 
            "Date": "2019-04-24T07:02:38.747Z", 
            "ID": "fe7c63ef-2b7f-4e70-b50c-996ae34b28ef"
        }, 
        {
            "Hash": {
                "HeadHash": "e61fcc6a06420106fa6642ef833b9c38", 
                "SHA1": "475d7efc7983357e51ea780e350b0efe6a5ba2e2", 
                "SHA256": "1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1", 
                "SSDeep": "24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9", 
                "MD5": "e61fcc6a06420106fa6642ef833b9c38"
            }, 
            "Name": "scribbles2.txt.zip", 
            "Related": "[https://app.any.run/tasks/81bb80cd-3bcf-41b3-aac5-c3e35a39ba0d](https://app.any.run/tasks/81bb80cd-3bcf-41b3-aac5-c3e35a39ba0d)", 
            "Verdict": "No threats detected", 
            "File": "https://content.any.run/tasks/81bb80cd-3bcf-41b3-aac5-c3e35a39ba0d/download/files/0c5c1527-b50b-483e-84e1-7b4b8f82d26b", 
            "Date": "2019-04-23T13:46:47.372Z", 
            "ID": "81bb80cd-3bcf-41b3-aac5-c3e35a39ba0d"
        }, 
        {
            "Hash": {
                "HeadHash": "e61fcc6a06420106fa6642ef833b9c38", 
                "SHA1": "475d7efc7983357e51ea780e350b0efe6a5ba2e2", 
                "SHA256": "1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1", 
                "SSDeep": "24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9", 
                "MD5": "e61fcc6a06420106fa6642ef833b9c38"
            }, 
            "Name": "scribbles2.txt.zip", 
            "Related": "[https://app.any.run/tasks/07d4d230-9638-4f04-a226-c7b18a81c329](https://app.any.run/tasks/07d4d230-9638-4f04-a226-c7b18a81c329)", 
            "Verdict": "No threats detected", 
            "File": "https://content.any.run/tasks/07d4d230-9638-4f04-a226-c7b18a81c329/download/files/69dcf7f0-69c2-432e-8d30-3e2f630e0aae", 
            "Date": "2019-04-23T08:11:17.460Z", 
            "ID": "07d4d230-9638-4f04-a226-c7b18a81c329"
        }, 
        {
            "Hash": {
                "HeadHash": "e61fcc6a06420106fa6642ef833b9c38", 
                "SHA1": "475d7efc7983357e51ea780e350b0efe6a5ba2e2", 
                "SHA256": "1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1", 
                "SSDeep": "24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9", 
                "MD5": "e61fcc6a06420106fa6642ef833b9c38"
            }, 
            "Name": "scribbles2.txt.zip", 
            "Related": "[https://app.any.run/tasks/411fe6a6-ca36-4322-8f1d-f5ec67c6346d](https://app.any.run/tasks/411fe6a6-ca36-4322-8f1d-f5ec67c6346d)", 
            "Verdict": "No threats detected", 
            "File": "https://content.any.run/tasks/411fe6a6-ca36-4322-8f1d-f5ec67c6346d/download/files/a006642b-956b-4a9d-a72c-0affdd2dd6c8", 
            "Date": "2019-04-22T12:16:13.302Z", 
            "ID": "411fe6a6-ca36-4322-8f1d-f5ec67c6346d"
        }
    ]
}
```
#### Human Readable Output

>### Results
>|Name|ID|File|Hash|Verdict|Related|Date|
>|---|---|---|---|---|---|---|
>|scribbles2.txt.zip|892455a2-8c96-45fb-9f2a-18ca4ef184f9|https://content.any.run/tasks/892455a2-8c96-45fb-9f2a-18ca4ef184f9/download/files/afca4a63-9fe0-461c-8e73-c8fd784cf90e|MD5: e61fcc6a06420106fa6642ef833b9c38<br> SHA1: 475d7efc7983357e51ea780e350b0efe6a5ba2e2<br> SHA256: 1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1<br> HeadHash: e61fcc6a06420106fa6642ef833b9c38<br> SSDeep: 24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9|No threats detected|https://app.any.run/tasks/892455a2-8c96-45fb-9f2a-18ca4ef184f9">https://app.any.run/tasks/892455a2-8c96-45fb-9f2a-18ca4ef184f9|2019-04-24T07:13:06.087Z|
>|scribbles2.txt.zip|fe7c63ef-2b7f-4e70-b50c-996ae34b28ef|https://content.any.run/tasks/fe7c63ef-2b7f-4e70-b50c-996ae34b28ef/download/files/227a7bd4-5baa-477b-b319-58d7619b79ef|MD5: e61fcc6a06420106fa6642ef833b9c38<br> SHA1: 475d7efc7983357e51ea780e350b0efe6a5ba2e2<br> SHA256: 1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1<br> HeadHash: e61fcc6a06420106fa6642ef833b9c38<br> SSDeep: 24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9|No threats detected|https://app.any.run/tasks/fe7c63ef-2b7f-4e70-b50c-996ae34b28ef">https://app.any.run/tasks/fe7c63ef-2b7f-4e70-b50c-996ae34b28ef|2019-04-24T07:02:38.747Z|
>|scribbles2.txt.zip|81bb80cd-3bcf-41b3-aac5-c3e35a39ba0d|https://content.any.run/tasks/81bb80cd-3bcf-41b3-aac5-c3e35a39ba0d/download/files/0c5c1527-b50b-483e-84e1-7b4b8f82d26b|MD5: e61fcc6a06420106fa6642ef833b9c38<br> SHA1: 475d7efc7983357e51ea780e350b0efe6a5ba2e2<br> SHA256: 1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1<br> HeadHash: e61fcc6a06420106fa6642ef833b9c38<br> SSDeep: 24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9|No threats detected|https://app.any.run/tasks/81bb80cd-3bcf-41b3-aac5-c3e35a39ba0d">https://app.any.run/tasks/81bb80cd-3bcf-41b3-aac5-c3e35a39ba0d|2019-04-23T13:46:47.372Z|
>|scribbles2.txt.zip|07d4d230-9638-4f04-a226-c7b18a81c329|https://content.any.run/tasks/07d4d230-9638-4f04-a226-c7b18a81c329/download/files/69dcf7f0-69c2-432e-8d30-3e2f630e0aae|MD5: e61fcc6a06420106fa6642ef833b9c38<br> SHA1: 475d7efc7983357e51ea780e350b0efe6a5ba2e2<br> SHA256: 1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1<br> HeadHash: e61fcc6a06420106fa6642ef833b9c38<br> SSDeep: 24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9|No threats detected|https://app.any.run/tasks/07d4d230-9638-4f04-a226-c7b18a81c329">https://app.any.run/tasks/07d4d230-9638-4f04-a226-c7b18a81c329|2019-04-23T08:11:17.460Z|
>|scribbles2.txt.zip|411fe6a6-ca36-4322-8f1d-f5ec67c6346d|https://content.any.run/tasks/411fe6a6-ca36-4322-8f1d-f5ec67c6346d/download/files/a006642b-956b-4a9d-a72c-0affdd2dd6c8|MD5: e61fcc6a06420106fa6642ef833b9c38<br> SHA1: 475d7efc7983357e51ea780e350b0efe6a5ba2e2<br> SHA256: 1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1<br> HeadHash: e61fcc6a06420106fa6642ef833b9c38<br> SSDeep: 24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9|No threats detected|https://app.any.run/tasks/411fe6a6-ca36-4322-8f1d-f5ec67c6346d">https://app.any.run/tasks/411fe6a6-ca36-4322-8f1d-f5ec67c6346d|2019-04-22T12:16:13.302Z|

### anyrun-get-report
***
Gets the report of a task created for a submitted file or URL. 

*Note: This command can only get reports for files or URLs deployed by the integration account. It cannot pull reports on public submissions.*



#### Base Command

`anyrun-get-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task | Unique task ID. A task ID is returned when submitting a file or URL for analysis using the `anyrun-run-analysis` command. Task IDs can also be located in the `ID` field of the output of executing the `anyrun-get-history` command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ANYRUN.Task.AnalysisDate | String | Date and time the analysis was executed. | 
| ANYRUN.Task.Behavior.Category | String | Category of a process behavior. | 
| ANYRUN.Task.Behavior.Action | String | Actions performed by a process. | 
| ANYRUN.Task.Behavior.ThreatLevel | Number | Threat score associated with a process behavior. | 
| ANYRUN.Task.Behavior.ProcessUUID | String | Unique ID of the process whose behaviors are being profiled. | 
| ANYRUN.Task.Connection.Reputation | String | Connection reputation. | 
| ANYRUN.Task.Connection.ProcessUUID | String | ID of the process that created the connection. | 
| ANYRUN.Task.Connection.ASN | String | Connection autonomous system network. | 
| ANYRUN.Task.Connection.Country | String | Connection country. | 
| ANYRUN.Task.Connection.Protocol | String | Connection protocol. | 
| ANYRUN.Task.Connection.Port | Number | Connection port number. | 
| ANYRUN.Task.Connection.IP | String | Connection IP number. | 
| ANYRUN.Task.DnsRequest.Reputation | String | Reputation of the DNS request. | 
| ANYRUN.Task.DnsRequest.IP | Unknown | IP addresses associated with a DNS request. | 
| ANYRUN.Task.DnsRequest.Domain | String | Domain resolution of a DNS request. | 
| ANYRUN.Task.Threat.ProcessUUID | String | Unique process ID from where the threat originated. | 
| ANYRUN.Task.Threat.Msg | String | Threat message. | 
| ANYRUN.Task.Threat.Class | String | Class of the threat. | 
| ANYRUN.Task.Threat.SrcPort | Number | Port on which the threat originated. | 
| ANYRUN.Task.Threat.DstPort | Number | Destination port of the threat. | 
| ANYRUN.Task.Threat.SrcIP | String | Source IP address where the threat originated. | 
| ANYRUN.Task.Threat.DstIP | String | Destination IP address of the threat. | 
| ANYRUN.Task.HttpRequest.Reputation | String | Reputation of the HTTP request. | 
| ANYRUN.Task.HttpRequest.Country | String | HTTP request country. | 
| ANYRUN.Task.HttpRequest.ProcessUUID | String | ID of the process making the HTTP request. | 
| ANYRUN.Task.HttpRequest.Body | Unknown | HTTP request body parameters and details. | 
| ANYRUN.Task.HttpRequest.HttpCode | Number | HTTP request response code. | 
| ANYRUN.Task.HttpRequest.Status | String | Status of the HTTP request. | 
| ANYRUN.Task.HttpRequest.ProxyDetected | Boolean | Whether the HTTP request was made through a proxy. | 
| ANYRUN.Task.HttpRequest.Port | Number | HTTP request port. | 
| ANYRUN.Task.HttpRequest.IP | String | HTTP request IP address. | 
| ANYRUN.Task.HttpRequest.URL | String | HTTP request URL. | 
| ANYRUN.Task.HttpRequest.Host | String | HTTP request host. | 
| ANYRUN.Task.HttpRequest.Method | String | HTTP request method type. | 
| ANYRUN.Task.FileInfo | String | Details of the submitted file. | 
| ANYRUN.Task.OS | String | OS of the sandbox in which the file was analyzed. | 
| ANYRUN.Task.ID | String | The unique ID of the task. | 
| ANYRUN.Task.MIME | String | The MIME of the file submitted for analysis. | 
| ANYRUN.Task.MD5 | String | The MD5 hash of the file submitted for analysis. | 
| ANYRUN.Task.SHA1 | String | The SHA1 hash of the file submitted for analysis. | 
| ANYRUN.Task.SHA256 | String | The SHA256 hash of the file submitted for analysis. | 
| ANYRUN.Task.SSDeep | String | SSDeep hash of the file submitted for analysis. | 
| ANYRUN.Task.Verdict | String | ANY.RUN verdict for the maliciousness of the submitted file or URL. | 
| ANYRUN.Task.Process.FileName | String | File name of the process. | 
| ANYRUN.Task.Process.PID | Number | Process identification number. | 
| ANYRUN.Task.Process.PPID | Number | Parent process identification number. | 
| ANYRUN.Task.Process.ProcessUUID | String | Unique process ID \(used by ANY.RUN\). | 
| ANYRUN.Task.Process.CMD | String | Process command. | 
| ANYRUN.Task.Process.Path | String | Path of the executed command. | 
| ANYRUN.Task.Process.User | String | User who executed the command. | 
| ANYRUN.Task.Process.IntegrityLevel | String | The process integrity level. | 
| ANYRUN.Task.Process.ExitCode | Number | Process exit code. | 
| ANYRUN.Task.Process.MainProcess | Boolean | Whether the process is the main process. | 
| ANYRUN.Task.Process.Version.Company | String | Company responsible for the program executed. | 
| ANYRUN.Task.Process.Version.Description | String | Description of the type of program. | 
| ANYRUN.Task.Process.Version.Version | String | Version of the program executed. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | Type of indicator. | 
| DBotScore.Vendor | String | Vendor used to calculate the score. | 
| File.Extension | String | Extension of the file submitted for analysis. | 
| File.Name | String | The name of the file submitted for analysis. | 
| File.MD5 | String | MD5 hash of the file submitted for analysis. | 
| File.SHA1 | String | SHA1 hash of the file submitted for analysis. | 
| File.SHA256 | String | SHA256 hash of the file submitted for analysis. | 
| File.SSDeep | String | SSDeep hash of the file submitted for analysis. | 
| File.Malicious.Vendor | String | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | String | For malicious files, the reason that the vendor made the decision. | 
| URL.Data | String | URL data. | 
| URL.Malicious.Vendor | String | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | String | For malicious URLs, the reason that the vendor made the decision. | 
| ANYRUN.Task.Status | String | Task analysis status. | 


#### Command Example

```anyrun-get-report task=fe7c63ef-2b7f-4e70-b50c-996ae34b28ef```

#### Context Example
```
{
    "ANYRUN.Task": {
        "HttpRequest": [], 
        "SSDeep": "24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9", 
        "Status": "done", 
        "SHA1": "475d7efc7983357e51ea780e350b0efe6a5ba2e2", 
        "Threat": [], 
        "Process": [
            {
                "CMD": "\"C:\\Program Files\\WinRAR\\WinRAR.exe\" \"C:\\Users\\admin\\AppData\\Local\\Temp\\scribbles2.txt.zip\"", 
                "IntegrityLevel": "MEDIUM", 
                "PID": 916, 
                "MainProcess": true, 
                "FileName": "WinRAR.exe", 
                "Version": {
                    "Company": "Alexander Roshal", 
                    "Version": "5.60.0", 
                    "Description": "WinRAR archiver"
                }, 
                "ProcessUUID": "8834c75a-ceba-4ae3-83e6-87b8b460ff82", 
                "User": "admin", 
                "Path": "C:\\Program Files\\WinRAR\\WinRAR.exe", 
                "PPID": 2044, 
                "ExitCode": null
            }
        ], 
        "ID": "fe7c63ef-2b7f-4e70-b50c-996ae34b28ef", 
        "Connection": [], 
        "MIME": "application/zip", 
        "Behavior": [], 
        "Verdict": "No threats detected", 
        "FileInfo": "Zip archive data, at least v2.0 to extract", 
        "SHA256": "1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1", 
        "OS": "Windows 7 Professional Service Pack 1 (build: 7601, 32 bit)", 
        "DnsRequest": [], 
        "AnalysisDate": "2019-04-24T07:02:38.747Z", 
        "MD5": "e61fcc6a06420106fa6642ef833b9c38"
    }, 
    "DBotScore": {
        "Vendor": "ANYRUN", 
        "Indicator": "1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1", 
        "Score": 1, 
        "Type": "hash"
    }, 
    "File": {
        "SHA1": "475d7efc7983357e51ea780e350b0efe6a5ba2e2", 
        "Name": "scribbles2.txt.zip", 
        "Extension": "zip", 
        "SSDeep": "24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9", 
        "SHA256": "1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1", 
        "MD5": "e61fcc6a06420106fa6642ef833b9c38"
    }
}
```

#### Human Readable Output

>### Results
>|OS|AnalysisDate|Verdict|MIME|FileInfo|Process|Status|MD5|SHA1|SHA256|SSDeep|
>|---|---|---|---|---|---|---|---|---|---|---|
>|Windows 7 Professional Service Pack 1 (build: 7601, 32 bit)|2019-04-24T07:02:38.747Z |No threats detected|application/zip|Zip archive data, at least v2.0 to extract| FileName: WinRAR.exe, PID: 916, PPID: 2044, ProcessUUID: 8834c75a-ceba-4ae3-83e6-87b8b460ff82, CMD: \C:\Program Files\WinRAR\WinRAR.exe\ \C:\Users\admin\AppData\Local\Temp\scribbles2.txt.zip, Path: C:\Program Files\WinRAR\WinRAR.exe, User: admin, IntegrityLevel: MEDIUM, ExitCode: null, MainProcess: true, Version: {Company: Alexander Roshal, Description: WinRAR archiver, Version: 5.60.0|done|e61fcc6a06420106fa6642ef833b9c38|475d7efc7983357e51ea780e350b0efe6a5ba2e2|1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1|24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9|

### anyrun-run-analysis
***
Submit a file or url for analysis.


#### Base Command

`anyrun-run-analysis`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| obj_type | Type of new task. Possible values are: file, url, remote file. Default is file. | Optional | 
| file | EntryID of the file to analyze. | Optional | 
| obj_url | URL, used only if 'obj_type' command argument is 'url' or 'download'. Permitted size is 5-512 characters long. | Optional | 
| env_bitness | Bitness of OS. Possible values are: 32, 64. Default is 32. | Optional | 
| env_version | Version of Windows OS. Possible values are: Windows Vista, Windows 7, Windows 8.1, Windows 10. Default is Windows 7. | Optional | 
| env_type | Environment preset type. Possible values are: complete, clean, office. Default is complete. | Optional | 
| opt_network_connect | Network connection state. Possible values are: true, false. Default is true. | Optional | 
| opt_kernel_heavyevasion | Heavy evasion option. Possible values are: true, false. Default is false. | Optional | 
| opt_privacy_type | Privacy settings for generated task. Possible values are: owner, bylink, public. Default is owner. | Optional | 
| obj_ext_browser | Browser name, used only for "url" type. Possible values are: Internet Explorer, Google Chrome, Mozilla Firefox, Opera, Microsoft Edge. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ANYRUN.Task.ID | String | ID of the task created to analyze the submission. | 


#### Command Example
```anyrun-run-analysis obj_type=file file=693@66884384-c643-4343-8cf7-26f59e62a88e env_bitness=64```

#### Context Example
```
{
    "ANYRUN.Task": {
        "ID": "e04b401f-9396-4183-ad00-b6ed34c023e3"
    }
}
```

#### Human Readable Output

>### Results
>|Task|
>|---|
>| e04b401f-9396-4183-ad00-b6ed34c023e3 |


