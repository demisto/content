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
| Domain.Name | String | Domain name. | 
| IP.ASN | String | IP ASN. | 
| IP.Address | String | IP Address. | 
| IP.Geo.Country | String | Origin country of the IP address. | 
| IP.Port | Number | Port number. | 
| ANYRUN.Task.Reports.HTML | String | URL for the HTML report. | 
| ANYRUN.Task.Reports.IOC | String | URL for the IOC report. | 
| ANYRUN.Task.Reports.MISP | String | URL for the MISP report. | 
| ANYRUN.Task.Reports.graph | String | URL for the graph report. | 

#### Command example
```!anyrun-get-report task=45b62ba4-931a-472b-b604-e43879a473fd```

#### Context Example
```json
{
    "ANYRUN": {
        "Task": {
            "Analysisdate": "2022-08-02T11:23:42.846Z",
            "Behavior": [
                {
                    "Action": "Reads the computer name",
                    "Category": "Environment",
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Threatlevel": 0
                },
                {
                    "Action": "Searches for installed software",
                    "Category": "Environment",
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "dafd83d4-86bb-412e-8bec-be8ad78b79b7",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                    "Threatlevel": 0
                },
                {
                    "Action": "Reads CPU info",
                    "Category": "Environment",
                    "Processuuid": "2e9fdeec-25c6-495c-8b04-35b5310b20b0",
                    "Threatlevel": 0
                },
                {
                    "Action": "Application launched itself",
                    "Category": "Suspicious actions",
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Threatlevel": 0
                },
                {
                    "Action": "Application launched itself",
                    "Category": "Suspicious actions",
                    "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                    "Threatlevel": 0
                },
                {
                    "Action": "Reads the computer name",
                    "Category": "Environment",
                    "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                    "Threatlevel": 0
                },
                {
                    "Action": "Reads settings of System Certificates",
                    "Category": "General",
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "40abe4ec-fef1-4fa1-b1f0-7a305e09f4aa",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "2e9fdeec-25c6-495c-8b04-35b5310b20b0",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks Windows Trust Settings",
                    "Category": "General",
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "cf2bf809-c2b6-48a2-a142-050254cd6458",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "713c2780-51cc-4e0e-bc0e-e9d38f5184ac",
                    "Threatlevel": 0
                },
                {
                    "Action": "Searches for installed software",
                    "Category": "Environment",
                    "Processuuid": "2e9fdeec-25c6-495c-8b04-35b5310b20b0",
                    "Threatlevel": 0
                },
                {
                    "Action": "Reads the computer name",
                    "Category": "Environment",
                    "Processuuid": "2e9fdeec-25c6-495c-8b04-35b5310b20b0",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "60116489-5a40-4dd7-8c3c-8091346b6299",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "4c084eba-2541-46a3-833d-513c41115c5f",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "2cab4f07-8ae6-4560-9308-3800d2be988a",
                    "Threatlevel": 0
                },
                {
                    "Action": "Reads the computer name",
                    "Category": "Environment",
                    "Processuuid": "00cdebb4-cbb8-4078-ae10-a250f33f435d",
                    "Threatlevel": 1
                },
                {
                    "Action": "Checks Windows Trust Settings",
                    "Category": "General",
                    "Processuuid": "00cdebb4-cbb8-4078-ae10-a250f33f435d",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "b9122008-82f2-4fa4-a128-956e24ae17ce",
                    "Threatlevel": 1
                },
                {
                    "Action": "Reads settings of System Certificates",
                    "Category": "General",
                    "Processuuid": "00cdebb4-cbb8-4078-ae10-a250f33f435d",
                    "Threatlevel": 0
                },
                {
                    "Action": "Reads settings of System Certificates",
                    "Category": "General",
                    "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                    "Threatlevel": 0
                },
                {
                    "Action": "Creates files in the program directory",
                    "Category": "System destruction",
                    "Processuuid": "00cdebb4-cbb8-4078-ae10-a250f33f435d",
                    "Threatlevel": 1
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "00cdebb4-cbb8-4078-ae10-a250f33f435d",
                    "Threatlevel": 1
                }
            ],
            "Connection": [
                {
                    "ASN": "Zayo Bandwidth Inc",
                    "Country": "US",
                    "IP": "23.35.236.137",
                    "Port": 443,
                    "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                    "Protocol": "tcp",
                    "Reputation": "suspicious"
                },
                {
                    "ASN": "Akamai International B.V.",
                    "Country": null,
                    "IP": "2.18.233.74",
                    "Port": 443,
                    "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                    "Protocol": "tcp",
                    "Reputation": "whitelisted"
                },
                {
                    "ASN": "TRUE INTERNET Co.,Ltd.",
                    "Country": "US",
                    "IP": "23.48.23.34",
                    "Port": 443,
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Protocol": "tcp",
                    "Reputation": "suspicious"
                },
                {
                    "ASN": "Limelight Networks, Inc.",
                    "Country": "GB",
                    "IP": "95.140.236.128",
                    "Port": 80,
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Protocol": "tcp",
                    "Reputation": "malicious"
                },
                {
                    "ASN": "MCI Communications Services, Inc. d/b/a Verizon Business",
                    "Country": "US",
                    "IP": "93.184.220.29",
                    "Port": 80,
                    "Processuuid": null,
                    "Protocol": "tcp",
                    "Reputation": "whitelisted"
                },
                {
                    "ASN": "Amazon.com, Inc.",
                    "Country": "US",
                    "IP": "54.224.241.105",
                    "Port": 443,
                    "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                    "Protocol": "tcp",
                    "Reputation": "unknown"
                },
                {
                    "ASN": "MCI Communications Services, Inc. d/b/a Verizon Business",
                    "Country": "US",
                    "IP": "93.184.220.29",
                    "Port": 80,
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Protocol": "tcp",
                    "Reputation": "whitelisted"
                },
                {
                    "ASN": "Akamai International B.V.",
                    "Country": null,
                    "IP": "2.18.233.74",
                    "Port": 443,
                    "Processuuid": null,
                    "Protocol": "tcp",
                    "Reputation": "whitelisted"
                },
                {
                    "ASN": "TRUE INTERNET Co.,Ltd.",
                    "Country": "US",
                    "IP": "23.48.23.54",
                    "Port": 443,
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Protocol": "tcp",
                    "Reputation": "suspicious"
                },
                {
                    "ASN": "Amazon.com, Inc.",
                    "Country": "US",
                    "IP": "34.237.241.83",
                    "Port": 443,
                    "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                    "Protocol": "tcp",
                    "Reputation": "unknown"
                },
                {
                    "ASN": "TRUE INTERNET Co.,Ltd.",
                    "Country": "US",
                    "IP": "23.48.23.39",
                    "Port": 443,
                    "Processuuid": null,
                    "Protocol": "tcp",
                    "Reputation": "suspicious"
                },
                {
                    "ASN": "TRUE INTERNET Co.,Ltd.",
                    "Country": "US",
                    "IP": "23.48.23.39",
                    "Port": 443,
                    "Processuuid": "00cdebb4-cbb8-4078-ae10-a250f33f435d",
                    "Protocol": "tcp",
                    "Reputation": "suspicious"
                }
            ],
            "Dnsrequest": [
                {
                    "Domain": "geo2.adobe.com",
                    "IP": [
                        "23.35.236.137"
                    ],
                    "Reputation": "whitelisted"
                },
                {
                    "Domain": "armmf.adobe.com",
                    "IP": [
                        "2.18.233.74"
                    ],
                    "Reputation": "whitelisted"
                },
                {
                    "Domain": "acroipm2.adobe.com",
                    "IP": [
                        "23.48.23.34",
                        "23.48.23.54"
                    ],
                    "Reputation": "whitelisted"
                },
                {
                    "Domain": "ctldl.windowsupdate.com",
                    "IP": [
                        "95.140.236.128",
                        "95.140.236.0"
                    ],
                    "Reputation": "whitelisted"
                },
                {
                    "Domain": "p13n.adobe.io",
                    "IP": [
                        "54.224.241.105",
                        "34.237.241.83",
                        "18.213.11.84",
                        "50.16.47.176"
                    ],
                    "Reputation": "whitelisted"
                },
                {
                    "Domain": "ocsp.digicert.com",
                    "IP": [
                        "93.184.220.29"
                    ],
                    "Reputation": "shared"
                },
                {
                    "Domain": "crl3.digicert.com",
                    "IP": [
                        "93.184.220.29"
                    ],
                    "Reputation": "shared"
                },
                {
                    "Domain": "ardownload3.adobe.com",
                    "IP": [
                        "23.48.23.39",
                        "23.48.23.25"
                    ],
                    "Reputation": "whitelisted"
                }
            ],
            "Fileinfo": "PDF document, version 1.3",
            "Httprequest": [
                {
                    "Body": {
                        "Response": {
                            "Hash": {
                                "MD5": "f7dcb24540769805e5bb30d193944dce",
                                "SHA1": "e26c583c562293356794937d9e2e6155d15449ee",
                                "SHA256": "6b88c6ac55bbd6fea0ebe5a760d1ad2cfce251c59d0151a1400701cb927e36ea"
                            },
                            "Permanenturl": "https://content.any.run/tasks/45b62ba4-931a-472b-b604-e43879a473fd/download/files/a72b74e1-8c52-461f-8879-b9329e0e07e2",
                            "Size": 4817,
                            "Threatlevel": "MID",
                            "Type": "compressed"
                        }
                    },
                    "Country": "GB",
                    "Host": "ctldl.windowsupdate.com",
                    "Httpcode": 200,
                    "IP": "95.140.236.128",
                    "Method": "GET",
                    "Port": 80,
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Proxydetected": false,
                    "Reputation": "whitelisted",
                    "Status": "RESPONDED",
                    "URL": "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?f54c0a0f62519d56"
                },
                {
                    "Body": {
                        "Response": {
                            "Hash": {
                                "MD5": "7515e21f59ff1aadff6f6a1a0d105c2b",
                                "SHA1": "5264c5e2334a57d8669d31c67325a9b166e53bef",
                                "SHA256": "55a7640579a0e6c0bc2388063710e5cc3120b4df0840ec8a7af9a4bdc9235029"
                            },
                            "Permanenturl": "https://content.any.run/tasks/45b62ba4-931a-472b-b604-e43879a473fd/download/files/a6a071a2-c307-4d99-9a16-64640129584f",
                            "Size": 631,
                            "Threatlevel": "UNKNOWN",
                            "Type": "der"
                        }
                    },
                    "Country": "US",
                    "Host": "crl3.digicert.com",
                    "Httpcode": 200,
                    "IP": "93.184.220.29",
                    "Method": "GET",
                    "Port": 80,
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Proxydetected": false,
                    "Reputation": "shared",
                    "Status": "RESPONDED",
                    "URL": "http://crl3.digicert.com/DigiCertGlobalRootCA.crl"
                }
            ],
            "ID": "45b62ba4-931a-472b-b604-e43879a473fd",
            "MD5": "02475e29bd0816b697cad5b55cdf897a",
            "MIME": "application/pdf",
            "Network": {
                "Connection": [
                    {
                        "ASN": "Zayo Bandwidth Inc",
                        "Country": "US",
                        "IP": "23.35.236.137",
                        "Port": 443,
                        "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                        "Protocol": "tcp",
                        "Reputation": "suspicious"
                    },
                    {
                        "ASN": "Akamai International B.V.",
                        "Country": null,
                        "IP": "2.18.233.74",
                        "Port": 443,
                        "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                        "Protocol": "tcp",
                        "Reputation": "whitelisted"
                    },
                    {
                        "ASN": "TRUE INTERNET Co.,Ltd.",
                        "Country": "US",
                        "IP": "23.48.23.34",
                        "Port": 443,
                        "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                        "Protocol": "tcp",
                        "Reputation": "suspicious"
                    },
                    {
                        "ASN": "Limelight Networks, Inc.",
                        "Country": "GB",
                        "IP": "95.140.236.128",
                        "Port": 80,
                        "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                        "Protocol": "tcp",
                        "Reputation": "malicious"
                    },
                    {
                        "ASN": "MCI Communications Services, Inc. d/b/a Verizon Business",
                        "Country": "US",
                        "IP": "93.184.220.29",
                        "Port": 80,
                        "Processuuid": null,
                        "Protocol": "tcp",
                        "Reputation": "whitelisted"
                    },
                    {
                        "ASN": "Amazon.com, Inc.",
                        "Country": "US",
                        "IP": "54.224.241.105",
                        "Port": 443,
                        "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                        "Protocol": "tcp",
                        "Reputation": "unknown"
                    },
                    {
                        "ASN": "MCI Communications Services, Inc. d/b/a Verizon Business",
                        "Country": "US",
                        "IP": "93.184.220.29",
                        "Port": 80,
                        "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                        "Protocol": "tcp",
                        "Reputation": "whitelisted"
                    },
                    {
                        "ASN": "Akamai International B.V.",
                        "Country": null,
                        "IP": "2.18.233.74",
                        "Port": 443,
                        "Processuuid": null,
                        "Protocol": "tcp",
                        "Reputation": "whitelisted"
                    },
                    {
                        "ASN": "TRUE INTERNET Co.,Ltd.",
                        "Country": "US",
                        "IP": "23.48.23.54",
                        "Port": 443,
                        "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                        "Protocol": "tcp",
                        "Reputation": "suspicious"
                    },
                    {
                        "ASN": "Amazon.com, Inc.",
                        "Country": "US",
                        "IP": "34.237.241.83",
                        "Port": 443,
                        "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                        "Protocol": "tcp",
                        "Reputation": "unknown"
                    },
                    {
                        "ASN": "TRUE INTERNET Co.,Ltd.",
                        "Country": "US",
                        "IP": "23.48.23.39",
                        "Port": 443,
                        "Processuuid": null,
                        "Protocol": "tcp",
                        "Reputation": "suspicious"
                    },
                    {
                        "ASN": "TRUE INTERNET Co.,Ltd.",
                        "Country": "US",
                        "IP": "23.48.23.39",
                        "Port": 443,
                        "Processuuid": "00cdebb4-cbb8-4078-ae10-a250f33f435d",
                        "Protocol": "tcp",
                        "Reputation": "suspicious"
                    }
                ],
                "Dnsrequest": [
                    {
                        "Domain": "geo2.adobe.com",
                        "IP": [
                            "23.35.236.137"
                        ],
                        "Reputation": "whitelisted"
                    },
                    {
                        "Domain": "armmf.adobe.com",
                        "IP": [
                            "2.18.233.74"
                        ],
                        "Reputation": "whitelisted"
                    },
                    {
                        "Domain": "acroipm2.adobe.com",
                        "IP": [
                            "23.48.23.34",
                            "23.48.23.54"
                        ],
                        "Reputation": "whitelisted"
                    },
                    {
                        "Domain": "ctldl.windowsupdate.com",
                        "IP": [
                            "95.140.236.128",
                            "95.140.236.0"
                        ],
                        "Reputation": "whitelisted"
                    },
                    {
                        "Domain": "p13n.adobe.io",
                        "IP": [
                            "54.224.241.105",
                            "34.237.241.83",
                            "18.213.11.84",
                            "50.16.47.176"
                        ],
                        "Reputation": "whitelisted"
                    },
                    {
                        "Domain": "ocsp.digicert.com",
                        "IP": [
                            "93.184.220.29"
                        ],
                        "Reputation": "shared"
                    },
                    {
                        "Domain": "crl3.digicert.com",
                        "IP": [
                            "93.184.220.29"
                        ],
                        "Reputation": "shared"
                    },
                    {
                        "Domain": "ardownload3.adobe.com",
                        "IP": [
                            "23.48.23.39",
                            "23.48.23.25"
                        ],
                        "Reputation": "whitelisted"
                    }
                ],
                "Httprequest": [
                    {
                        "Body": {
                            "Response": {
                                "Hash": {
                                    "MD5": "f7dcb24540769805e5bb30d193944dce",
                                    "SHA1": "e26c583c562293356794937d9e2e6155d15449ee",
                                    "SHA256": "6b88c6ac55bbd6fea0ebe5a760d1ad2cfce251c59d0151a1400701cb927e36ea"
                                },
                                "Permanenturl": "https://content.any.run/tasks/45b62ba4-931a-472b-b604-e43879a473fd/download/files/a72b74e1-8c52-461f-8879-b9329e0e07e2",
                                "Size": 4817,
                                "Threatlevel": "MID",
                                "Type": "compressed"
                            }
                        },
                        "Country": "GB",
                        "Host": "ctldl.windowsupdate.com",
                        "Httpcode": 200,
                        "IP": "95.140.236.128",
                        "Method": "GET",
                        "Port": 80,
                        "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                        "Proxydetected": false,
                        "Reputation": "whitelisted",
                        "Status": "RESPONDED",
                        "URL": "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?f54c0a0f62519d56"
                    },
                    {
                        "Body": {
                            "Response": {
                                "Hash": {
                                    "MD5": "7515e21f59ff1aadff6f6a1a0d105c2b",
                                    "SHA1": "5264c5e2334a57d8669d31c67325a9b166e53bef",
                                    "SHA256": "55a7640579a0e6c0bc2388063710e5cc3120b4df0840ec8a7af9a4bdc9235029"
                                },
                                "Permanenturl": "https://content.any.run/tasks/45b62ba4-931a-472b-b604-e43879a473fd/download/files/a6a071a2-c307-4d99-9a16-64640129584f",
                                "Size": 631,
                                "Threatlevel": "UNKNOWN",
                                "Type": "der"
                            }
                        },
                        "Country": "US",
                        "Host": "crl3.digicert.com",
                        "Httpcode": 200,
                        "IP": "93.184.220.29",
                        "Method": "GET",
                        "Port": 80,
                        "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                        "Proxydetected": false,
                        "Reputation": "shared",
                        "Status": "RESPONDED",
                        "URL": "http://crl3.digicert.com/DigiCertGlobalRootCA.crl"
                    }
                ],
                "Threat": [
                    {
                        "Class": "Potentially Bad Traffic",
                        "Dstip": "local",
                        "Dstport": 55801,
                        "Message": "ET INFO TLS Handshake Failure",
                        "Processuuid": null,
                        "Srcip": "23.48.23.39",
                        "Srcport": 443
                    }
                ]
            },
            "Os": "Windows 7 Professional Service Pack 1 (build: 7601, 32 bit)",
            "Process": [
                {
                    "Cmd": "",
                    "Exitcode": null,
                    "Filename": "[System Process]",
                    "Integritylevel": "UNKNOWN",
                    "Mainprocess": false,
                    "PID": 0,
                    "PPID": 0,
                    "Path": "[System Process]",
                    "Processuuid": "375da1b2-fd25-4328-a2dd-6d4d7fb44396",
                    "User": "",
                    "Version": {
                        "Company": "",
                        "Description": "",
                        "Version": ""
                    }
                },
                {
                    "Cmd": "",
                    "Exitcode": null,
                    "Filename": "System",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 4,
                    "PPID": 0,
                    "Path": "System",
                    "Processuuid": "a271b969-ce69-49b0-838f-0356818625d0",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "",
                        "Description": "",
                        "Version": ""
                    }
                },
                {
                    "Cmd": "\SystemRoot\System32\smss.exe",
                    "Exitcode": null,
                    "Filename": "smss.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 260,
                    "PPID": 4,
                    "Path": "\SystemRoot\System32\smss.exe",
                    "Processuuid": "9a0ca621-1717-43e1-915a-4fe4d8f6942e",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "",
                        "Description": "",
                        "Version": ""
                    }
                },
                {
                    "Cmd": "%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,12288,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16",
                    "Exitcode": null,
                    "Filename": "csrss.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 340,
                    "PPID": 320,
                    "Path": "C:\Windows\system32\csrss.exe",
                    "Processuuid": "0952f427-a077-4cc6-9355-0b08cef93dc0",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Client Server Runtime Process",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "wininit.exe",
                    "Exitcode": null,
                    "Filename": "wininit.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 376,
                    "PPID": 320,
                    "Path": "C:\Windows\system32\wininit.exe",
                    "Processuuid": "f1749785-eeea-498b-9ae3-0aa0eaec409c",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Windows Start-Up Application",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,12288,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16",
                    "Exitcode": null,
                    "Filename": "csrss.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 384,
                    "PPID": 368,
                    "Path": "C:\Windows\system32\csrss.exe",
                    "Processuuid": "ac42625e-c10a-4f4a-953d-71caa933dc92",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Client Server Runtime Process",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "winlogon.exe",
                    "Exitcode": null,
                    "Filename": "winlogon.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 432,
                    "PPID": 368,
                    "Path": "C:\Windows\system32\winlogon.exe",
                    "Processuuid": "dadff15c-8866-4534-93b3-2524c93986cc",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Windows Logon Application",
                        "Version": "6.1.7601.17514 (win7sp1_rtm.101119-1850)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\services.exe",
                    "Exitcode": null,
                    "Filename": "services.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 468,
                    "PPID": 376,
                    "Path": "C:\Windows\system32\services.exe",
                    "Processuuid": "b074db04-9698-41f7-a2ed-3d930d38a4e8",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Services and Controller app",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\lsass.exe",
                    "Exitcode": null,
                    "Filename": "lsass.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 484,
                    "PPID": 376,
                    "Path": "C:\Windows\system32\lsass.exe",
                    "Processuuid": "b7dca6aa-04a4-4080-9e3c-f2d07ae2b848",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Local Security Authority Process",
                        "Version": "6.1.7601.24545 (win7sp1_ldr_escrow.200102-1707)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\lsm.exe",
                    "Exitcode": null,
                    "Filename": "lsm.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 492,
                    "PPID": 376,
                    "Path": "C:\Windows\system32\lsm.exe",
                    "Processuuid": "1b88a259-2c6a-4fa8-acbf-02289d497622",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Local Session Manager Service",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\svchost.exe -k DcomLaunch",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 592,
                    "PPID": 468,
                    "Path": "C:\Windows\system32\svchost.exe",
                    "Processuuid": "f93b01ef-9719-480c-95b7-642d5d551b1b",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\svchost.exe -k RPCSS",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 672,
                    "PPID": 468,
                    "Path": "C:\Windows\system32\svchost.exe",
                    "Processuuid": "c3cf8aac-4921-44b4-951d-5d8a1db7b617",
                    "User": "NETWORK SERVICE",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 760,
                    "PPID": 468,
                    "Path": "C:\Windows\System32\svchost.exe",
                    "Processuuid": "a8a5af5a-ec52-47d8-9655-199f14ea5c45",
                    "User": "LOCAL SERVICE",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 796,
                    "PPID": 468,
                    "Path": "C:\Windows\System32\svchost.exe",
                    "Processuuid": "270bc634-7c40-4a22-8119-a5bbdfb22422",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\svchost.exe -k LocalService",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 824,
                    "PPID": 468,
                    "Path": "C:\Windows\system32\svchost.exe",
                    "Processuuid": "92be8359-8941-4eff-8dea-f0c816cff7eb",
                    "User": "LOCAL SERVICE",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\svchost.exe -k netsvcs",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 860,
                    "PPID": 468,
                    "Path": "C:\Windows\system32\svchost.exe",
                    "Processuuid": "a4e149c7-1d4e-4de9-956b-058ee9cf394d",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\svchost.exe -k GPSvcGroup",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 968,
                    "PPID": 468,
                    "Path": "C:\Windows\system32\svchost.exe",
                    "Processuuid": "be778e77-cf65-4405-9ad2-c0e5ea36e972",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\svchost.exe -k NetworkService",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 1088,
                    "PPID": 468,
                    "Path": "C:\Windows\system32\svchost.exe",
                    "Processuuid": "e0eff788-3254-4665-8fc6-487f4d789563",
                    "User": "NETWORK SERVICE",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\System32\spoolsv.exe",
                    "Exitcode": null,
                    "Filename": "spoolsv.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 1236,
                    "PPID": 468,
                    "Path": "C:\Windows\System32\spoolsv.exe",
                    "Processuuid": "c76927c0-29c0-402a-9a9a-ebb1191b2801",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Spooler SubSystem App",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 1264,
                    "PPID": 468,
                    "Path": "C:\Windows\system32\svchost.exe",
                    "Processuuid": "ece1b0ec-252e-496b-a5f6-08c661b0e333",
                    "User": "LOCAL SERVICE",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\System32\svchost.exe -k utcsvc",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 1352,
                    "PPID": 468,
                    "Path": "C:\Windows\System32\svchost.exe",
                    "Processuuid": "2e86deea-86d0-48f9-8b59-70228ce98f12",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Common Files\Microsoft Shared\IME14\SHARED\IMEDICTUPDATE.EXE\"",
                    "Exitcode": null,
                    "Filename": "IMEDICTUPDATE.EXE",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 1424,
                    "PPID": 468,
                    "Path": "C:\Program Files\Common Files\Microsoft Shared\IME14\SHARED\IMEDICTUPDATE.EXE",
                    "Processuuid": "9550f782-1f7c-4dfe-86c7-b5bf6eb6a945",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Microsoft Office IME 2010",
                        "Version": "14.0.4734.1000"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\svchost.exe -k NetworkServiceNetworkRestricted",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 1936,
                    "PPID": 468,
                    "Path": "C:\Windows\system32\svchost.exe",
                    "Processuuid": "82765043-e885-448e-8982-e42438ca0a52",
                    "User": "NETWORK SERVICE",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "\"taskhost.exe\"",
                    "Exitcode": null,
                    "Filename": "taskhost.exe",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": false,
                    "PID": 320,
                    "PPID": 468,
                    "Path": "C:\Windows\system32\taskhost.exe",
                    "Processuuid": "0dcb27a1-d908-4b0f-a25f-917cd8df6c1e",
                    "User": "admin",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Tasks",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "taskeng.exe {BB154EF7-42D4-42F2-B57F-9CBB745DE3E3}",
                    "Exitcode": null,
                    "Filename": "taskeng.exe",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": false,
                    "PID": 288,
                    "PPID": 860,
                    "Path": "C:\Windows\system32\taskeng.exe",
                    "Processuuid": "d2a105e9-13a6-4964-81e6-070af81b5dec",
                    "User": "admin",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Task Scheduler Engine",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "\"C:\Windows\system32\Dwm.exe\"",
                    "Exitcode": null,
                    "Filename": "Dwm.exe",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": false,
                    "PID": 936,
                    "PPID": 796,
                    "Path": "C:\Windows\system32\Dwm.exe",
                    "Processuuid": "bbcd1df9-3e48-4e58-9751-b61e7c472815",
                    "User": "admin",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Desktop Window Manager",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\Explorer.EXE",
                    "Exitcode": null,
                    "Filename": "Explorer.EXE",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": false,
                    "PID": 1464,
                    "PPID": 820,
                    "Path": "C:\Windows\Explorer.EXE",
                    "Processuuid": "4966dad3-7df9-4800-87e1-1ae4b32b93a2",
                    "User": "admin",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Windows Explorer",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\System32\ctfmon.exe ",
                    "Exitcode": null,
                    "Filename": "ctfmon.exe",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": false,
                    "PID": 1396,
                    "PPID": 288,
                    "Path": "C:\Windows\System32\ctfmon.exe",
                    "Processuuid": "6307f043-d99d-44e7-a6d7-1e11eea3be3d",
                    "User": "admin",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "CTF Loader",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\SearchIndexer.exe /Embedding",
                    "Exitcode": null,
                    "Filename": "SearchIndexer.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 2544,
                    "PPID": 468,
                    "Path": "C:\Windows\system32\SearchIndexer.exe",
                    "Processuuid": "be7286ed-ef2f-441e-acca-9accb8f377a4",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Microsoft Windows Search Indexer",
                        "Version": "7.00.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "\"C:\Windows\system32\SearchProtocolHost.exe\" Global\UsGthrFltPipeMssGthrPipe3_ Global\UsGthrCtrlFltPipeMssGthrPipe3 1 -2147483646 \"Software\Microsoft\Windows Search\" \"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)\" \"C:\ProgramData\Microsoft\Search\Data\Temp\usgthrsvc\" \"DownLevelDaemon\" ",
                    "Exitcode": null,
                    "Filename": "SearchProtocolHost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 3452,
                    "PPID": 2544,
                    "Path": "C:\Windows\system32\SearchProtocolHost.exe",
                    "Processuuid": "3d0967dc-e2e6-4339-a619-a084045bbbf1",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Microsoft Windows Search Protocol Host",
                        "Version": "7.00.7601.24542 (win7sp1_ldr_escrow.191209-2211)"
                    }
                },
                {
                    "Cmd": "\"C:\Windows\system32\SearchFilterHost.exe\" 0 520 524 532 65536 528 ",
                    "Exitcode": null,
                    "Filename": "SearchFilterHost.exe",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": false,
                    "PID": 3840,
                    "PPID": 2544,
                    "Path": "C:\Windows\system32\SearchFilterHost.exe",
                    "Processuuid": "9384891d-6ead-4179-bac6-3734cee1f6bb",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Microsoft Windows Search Filter Host",
                        "Version": "7.00.7601.24542 (win7sp1_ldr_escrow.191209-2211)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\DllHost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}",
                    "Exitcode": 0,
                    "Filename": "DllHost.exe",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": false,
                    "PID": 2872,
                    "PPID": 592,
                    "Path": "C:\Windows\system32\DllHost.exe",
                    "Processuuid": "93b6c7fc-1aef-4150-be36-b5930f55b85a",
                    "User": "admin",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "COM Surrogate",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\DllHost.exe /Processid:{F9717507-6651-4EDB-BFF7-AE615179BCCF}",
                    "Exitcode": 0,
                    "Filename": "DllHost.exe",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": false,
                    "PID": 2316,
                    "PPID": 592,
                    "Path": "C:\Windows\system32\DllHost.exe",
                    "Processuuid": "86c03f0a-b480-477e-a632-192ba22dac62",
                    "User": "admin",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "COM Surrogate",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\AUDIODG.EXE 0x6cc",
                    "Exitcode": null,
                    "Filename": "AUDIODG.EXE",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 3000,
                    "PPID": 760,
                    "Path": "C:\Windows\system32\AUDIODG.EXE",
                    "Processuuid": "9e9e24d6-751d-4019-b28b-46a44e9018ca",
                    "User": "LOCAL SERVICE",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Windows Audio Device Graph Isolation ",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 3860,
                    "PPID": 468,
                    "Path": "C:\Windows\system32\svchost.exe",
                    "Processuuid": "fd7ffe77-7fc9-4ae2-8592-18f48d7e9752",
                    "User": "LOCAL SERVICE",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\DllHost.exe /Processid:{F9717507-6651-4EDB-BFF7-AE615179BCCF}",
                    "Exitcode": null,
                    "Filename": "DllHost.exe",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": false,
                    "PID": 2588,
                    "PPID": 592,
                    "Path": "C:\Windows\system32\DllHost.exe",
                    "Processuuid": "f945261c-f8b9-44fa-8173-d859bdff9085",
                    "User": "admin",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "COM Surrogate",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe\" \"C:\Users\admin\AppData\Local\Temp\test_file.pdf\"",
                    "Exitcode": null,
                    "Filename": "AcroRd32.exe",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": true,
                    "PID": 2040,
                    "PPID": 1464,
                    "Path": "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe",
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Systems Incorporated",
                        "Description": "Adobe Acrobat Reader DC ",
                        "Version": "20.13.20064.405839"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe\" --type=renderer  \"C:\Users\admin\AppData\Local\Temp\test_file.pdf\"",
                    "Exitcode": null,
                    "Filename": "AcroRd32.exe",
                    "Integritylevel": "LOW",
                    "Mainprocess": false,
                    "PID": 1280,
                    "PPID": 2040,
                    "Path": "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe",
                    "Processuuid": "2e9fdeec-25c6-495c-8b04-35b5310b20b0",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Systems Incorporated",
                        "Description": "Adobe Acrobat Reader DC ",
                        "Version": "20.13.20064.405839"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe\" --backgroundcolor=16514043",
                    "Exitcode": null,
                    "Filename": "RdrCEF.exe",
                    "Integritylevel": "LOW",
                    "Mainprocess": false,
                    "PID": 3316,
                    "PPID": 2040,
                    "Path": "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe",
                    "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Systems Incorporated",
                        "Description": "Adobe RdrCEF",
                        "Version": "20.13.20064.405839"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe\" --type=renderer --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --touch-events=enabled --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-gpu-compositing --lang=en-US --disable-pack-loading --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --log-severity=disable --product-version=\"ReaderServices/20.13.20064 Chrome/80.0.0.0\" --device-scale-factor=1 --num-raster-threads=2 --enable-main-frame-before-activation --service-request-channel-token=14024734510508519417 --renderer-client-id=2 --mojo-platform-channel-handle=1204 --allow-no-sandbox-job /prefetch:1",
                    "Exitcode": null,
                    "Filename": "RdrCEF.exe",
                    "Integritylevel": "LOW",
                    "Mainprocess": false,
                    "PID": 2128,
                    "PPID": 3316,
                    "Path": "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe",
                    "Processuuid": "cf2bf809-c2b6-48a2-a142-050254cd6458",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Systems Incorporated",
                        "Description": "Adobe RdrCEF",
                        "Version": "20.13.20064.405839"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe\" --type=gpu-process --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-pack-loading --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --log-severity=disable --product-version=\"ReaderServices/20.13.20064 Chrome/80.0.0.0\" --lang=en-US --gpu-preferences=KAAAAAAAAADgACAgAQAAAAAAAAAAAGAAAAAAABAAAAAIAAAAAAAAACgAAAAEAAAAIAAAAAAAAAAoAAAAAAAAADAAAAAAAAAAOAAAAAAAAAAQAAAAAAAAAAAAAAAFAAAAEAAAAAAAAAAAAAAABgAAABAAAAAAAAAAAQAAAAUAAAAQAAAAAAAAAAEAAAAGAAAA --use-gl=swiftshader-webgl --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --service-request-channel-token=12223321443149433680 --mojo-platform-channel-handle=1236 --allow-no-sandbox-job --ignored=\" --type=renderer \" /prefetch:2",
                    "Exitcode": 1,
                    "Filename": "RdrCEF.exe",
                    "Integritylevel": "LOW",
                    "Mainprocess": false,
                    "PID": 1180,
                    "PPID": 3316,
                    "Path": "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe",
                    "Processuuid": "dafd83d4-86bb-412e-8bec-be8ad78b79b7",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Systems Incorporated",
                        "Description": "Adobe RdrCEF",
                        "Version": "20.13.20064.405839"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe\" --type=gpu-process --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-pack-loading --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --log-severity=disable --product-version=\"ReaderServices/20.13.20064 Chrome/80.0.0.0\" --lang=en-US --gpu-preferences=KAAAAAAAAADgACAgAQAAAAAAAAAAAGAAAAAAABAAAAAIAAAAAAAAACgAAAAEAAAAIAAAAAAAAAAoAAAAAAAAADAAAAAAAAAAOAAAAAAAAAAQAAAAAAAAAAAAAAAFAAAAEAAAAAAAAAAAAAAABgAAABAAAAAAAAAAAQAAAAUAAAAQAAAAAAAAAAEAAAAGAAAA --use-gl=swiftshader-webgl --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --service-request-channel-token=12378439338200214857 --mojo-platform-channel-handle=1408 --allow-no-sandbox-job --ignored=\" --type=renderer \" /prefetch:2",
                    "Exitcode": 1,
                    "Filename": "RdrCEF.exe",
                    "Integritylevel": "LOW",
                    "Mainprocess": false,
                    "PID": 2860,
                    "PPID": 3316,
                    "Path": "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe",
                    "Processuuid": "713c2780-51cc-4e0e-bc0e-e9d38f5184ac",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Systems Incorporated",
                        "Description": "Adobe RdrCEF",
                        "Version": "20.13.20064.405839"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe\" --type=gpu-process --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-pack-loading --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --log-severity=disable --product-version=\"ReaderServices/20.13.20064 Chrome/80.0.0.0\" --lang=en-US --gpu-preferences=KAAAAAAAAADgACAgAQAAAAAAAAAAAGAAAAAAABAAAAAIAAAAAAAAACgAAAAEAAAAIAAAAAAAAAAoAAAAAAAAADAAAAAAAAAAOAAAAAAAAAAQAAAAAAAAAAAAAAAFAAAAEAAAAAAAAAAAAAAABgAAABAAAAAAAAAAAQAAAAUAAAAQAAAAAAAAAAEAAAAGAAAA --use-gl=swiftshader-webgl --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --service-request-channel-token=13732513110551940315 --mojo-platform-channel-handle=1396 --allow-no-sandbox-job --ignored=\" --type=renderer \" /prefetch:2",
                    "Exitcode": 1,
                    "Filename": "RdrCEF.exe",
                    "Integritylevel": "LOW",
                    "Mainprocess": false,
                    "PID": 2108,
                    "PPID": 3316,
                    "Path": "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe",
                    "Processuuid": "40abe4ec-fef1-4fa1-b1f0-7a305e09f4aa",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Systems Incorporated",
                        "Description": "Adobe RdrCEF",
                        "Version": "20.13.20064.405839"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe\" --type=renderer --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --touch-events=enabled --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-gpu-compositing --lang=en-US --disable-pack-loading --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --log-severity=disable --product-version=\"ReaderServices/20.13.20064 Chrome/80.0.0.0\" --device-scale-factor=1 --num-raster-threads=2 --enable-main-frame-before-activation --service-request-channel-token=4847431092444551383 --renderer-client-id=6 --mojo-platform-channel-handle=1616 --allow-no-sandbox-job /prefetch:1",
                    "Exitcode": null,
                    "Filename": "RdrCEF.exe",
                    "Integritylevel": "LOW",
                    "Mainprocess": false,
                    "PID": 920,
                    "PPID": 3316,
                    "Path": "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe",
                    "Processuuid": "4c084eba-2541-46a3-833d-513c41115c5f",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Systems Incorporated",
                        "Description": "Adobe RdrCEF",
                        "Version": "20.13.20064.405839"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe\" --type=renderer --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --touch-events=enabled --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-gpu-compositing --lang=en-US --disable-pack-loading --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --log-severity=disable --product-version=\"ReaderServices/20.13.20064 Chrome/80.0.0.0\" --device-scale-factor=1 --num-raster-threads=2 --enable-main-frame-before-activation --service-request-channel-token=16593724968950981413 --renderer-client-id=7 --mojo-platform-channel-handle=1536 --allow-no-sandbox-job /prefetch:1",
                    "Exitcode": null,
                    "Filename": "RdrCEF.exe",
                    "Integritylevel": "LOW",
                    "Mainprocess": false,
                    "PID": 3424,
                    "PPID": 3316,
                    "Path": "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe",
                    "Processuuid": "60116489-5a40-4dd7-8c3c-8091346b6299",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Systems Incorporated",
                        "Description": "Adobe RdrCEF",
                        "Version": "20.13.20064.405839"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe\" --type=renderer --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --touch-events=enabled --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-gpu-compositing --lang=en-US --disable-pack-loading --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --log-severity=disable --product-version=\"ReaderServices/20.13.20064 Chrome/80.0.0.0\" --device-scale-factor=1 --num-raster-threads=2 --enable-main-frame-before-activation --service-request-channel-token=6562753338979179477 --renderer-client-id=8 --mojo-platform-channel-handle=1836 --allow-no-sandbox-job /prefetch:1",
                    "Exitcode": null,
                    "Filename": "RdrCEF.exe",
                    "Integritylevel": "LOW",
                    "Mainprocess": false,
                    "PID": 240,
                    "PPID": 3316,
                    "Path": "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe",
                    "Processuuid": "2cab4f07-8ae6-4560-9308-3800d2be988a",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Systems Incorporated",
                        "Description": "Adobe RdrCEF",
                        "Version": "20.13.20064.405839"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Common Files\Adobe\ARM\1.0\AdobeARM.exe\" /PRODUCT:Reader /VERSION:20.0 /MODE:3",
                    "Exitcode": null,
                    "Filename": "AdobeARM.exe",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": false,
                    "PID": 2124,
                    "PPID": 2040,
                    "Path": "C:\Program Files\Common Files\Adobe\ARM\1.0\AdobeARM.exe",
                    "Processuuid": "00cdebb4-cbb8-4078-ae10-a250f33f435d",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Inc.",
                        "Description": "Adobe Reader and Acrobat Manager",
                        "Version": "1.824.39.9311"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\Reader_sl.exe\" ",
                    "Exitcode": 0,
                    "Filename": "Reader_sl.exe",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": false,
                    "PID": 3532,
                    "PPID": 2124,
                    "Path": "C:\Program Files\Adobe\Acrobat Reader DC\Reader\Reader_sl.exe",
                    "Processuuid": "b9122008-82f2-4fa4-a128-956e24ae17ce",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Systems Incorporated",
                        "Description": "Adobe Acrobat SpeedLauncher",
                        "Version": "20.12.20041.394260"
                    }
                }
            ],
            "Reports": {
                "HTML": "https://api.any.run/report/45b62ba4-931a-472b-b604-e43879a473fd/summary/html",
                "IOC": "https://api.any.run/report/45b62ba4-931a-472b-b604-e43879a473fd/ioc/json",
                "MISP": "https://api.any.run/report/45b62ba4-931a-472b-b604-e43879a473fd/summary/misp",
                "graph": "https://content.any.run/tasks/45b62ba4-931a-472b-b604-e43879a473fd/graph"
            },
            "SHA1": "44e4ee171347fb954938ea87400c5bef5ec8be8b",
            "SHA256": "c558877e6ad6de172b8cc10461a12905c6b98d6265e650b3650b35ff73a63b03",
            "SSDeep": "768:ttu1HAfRvxuliB5IXqwdbOiNf6vP47BL1Gq:tiUVMXqcbFfsA7pMq",
            "Status": "done",
            "Threat": [
                {
                    "Class": "Potentially Bad Traffic",
                    "Dstip": "local",
                    "Dstport": 55801,
                    "Message": "ET INFO TLS Handshake Failure",
                    "Processuuid": null,
                    "Srcip": "23.48.23.39",
                    "Srcport": 443
                }
            ],
            "Verdict": "No threats detected"
        }
    },
    "AttackPattern": {
        "Description": null,
        "FirstSeenBySource": null,
        "KillChainPhases": null,
        "MITREID": "T1106",
        "OperatingSystemRefs": null,
        "Publications": null,
        "STIXID": null,
        "Tags": null,
        "Value": "Execution through API"
    },
    "DBotScore": [
        {
            "Indicator": "c558877e6ad6de172b8cc10461a12905c6b98d6265e650b3650b35ff73a63b03",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 1,
            "Type": "file",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "23.35.236.137",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "2.18.233.74",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "23.48.23.34",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "95.140.236.128",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "93.184.220.29",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 1,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "23.48.23.54",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "23.48.23.39",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "geo2.adobe.com",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 1,
            "Type": "domain",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "armmf.adobe.com",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 1,
            "Type": "domain",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "acroipm2.adobe.com",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 1,
            "Type": "domain",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "ctldl.windowsupdate.com",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 1,
            "Type": "domain",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "95.140.236.0",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "p13n.adobe.io",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 1,
            "Type": "domain",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "54.224.241.105",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "34.237.241.83",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "18.213.11.84",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "50.16.47.176",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "ardownload3.adobe.com",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 1,
            "Type": "domain",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "23.48.23.25",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        }
    ],
    "Domain": [
        {
            "Name": "geo2.adobe.com"
        },
        {
            "Name": "armmf.adobe.com"
        },
        {
            "Name": "acroipm2.adobe.com"
        },
        {
            "Name": "ctldl.windowsupdate.com"
        },
        {
            "Name": "p13n.adobe.io"
        },
        {
            "Name": "ardownload3.adobe.com"
        }
    ],
    "File": {
        "Hashes": [
            {
                "type": "MD5",
                "value": "02475e29bd0816b697cad5b55cdf897a"
            },
            {
                "type": "SHA1",
                "value": "44e4ee171347fb954938ea87400c5bef5ec8be8b"
            },
            {
                "type": "SHA256",
                "value": "c558877e6ad6de172b8cc10461a12905c6b98d6265e650b3650b35ff73a63b03"
            }
        ],
        "MD5": "02475e29bd0816b697cad5b55cdf897a",
        "SHA1": "44e4ee171347fb954938ea87400c5bef5ec8be8b",
        "SHA256": "c558877e6ad6de172b8cc10461a12905c6b98d6265e650b3650b35ff73a63b03",
        "Type": "PDF document, version 1.3"
    },
    "IP": [
        {
            "ASN": "Zayo Bandwidth Inc",
            "Address": "23.35.236.137",
            "Geo": {
                "Country": "US"
            },
            "Port": 443,
            "Relationships": [
                {
                    "EntityA": "geo2.adobe.com",
                    "EntityAType": "Domain",
                    "EntityB": "23.35.236.137",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        },
        {
            "ASN": "Akamai International B.V.",
            "Address": "2.18.233.74",
            "Port": 443,
            "Relationships": [
                {
                    "EntityA": "armmf.adobe.com",
                    "EntityAType": "Domain",
                    "EntityB": "2.18.233.74",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        },
        {
            "ASN": "TRUE INTERNET Co.,Ltd.",
            "Address": "23.48.23.34",
            "Geo": {
                "Country": "US"
            },
            "Port": 443,
            "Relationships": [
                {
                    "EntityA": "acroipm2.adobe.com",
                    "EntityAType": "Domain",
                    "EntityB": "23.48.23.34",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        },
        {
            "ASN": "Limelight Networks, Inc.",
            "Address": "95.140.236.128",
            "Geo": {
                "Country": "GB"
            },
            "Malicious": {
                "Description": null,
                "Vendor": "ANYRUN"
            },
            "Port": 80,
            "Relationships": [
                {
                    "EntityA": "ctldl.windowsupdate.com",
                    "EntityAType": "Domain",
                    "EntityB": "95.140.236.128",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        },
        {
            "ASN": "MCI Communications Services, Inc. d/b/a Verizon Business",
            "Address": "93.184.220.29",
            "Geo": {
                "Country": "US"
            },
            "Port": 80,
            "Relationships": [
                {
                    "EntityA": "c558877e6ad6de172b8cc10461a12905c6b98d6265e650b3650b35ff73a63b03",
                    "EntityAType": "File",
                    "EntityB": "93.184.220.29",
                    "EntityBType": "IP",
                    "Relationship": "communicated-with"
                }
            ]
        },
        {
            "ASN": "TRUE INTERNET Co.,Ltd.",
            "Address": "23.48.23.54",
            "Geo": {
                "Country": "US"
            },
            "Port": 443,
            "Relationships": [
                {
                    "EntityA": "acroipm2.adobe.com",
                    "EntityAType": "Domain",
                    "EntityB": "23.48.23.54",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        },
        {
            "ASN": "TRUE INTERNET Co.,Ltd.",
            "Address": "23.48.23.39",
            "Geo": {
                "Country": "US"
            },
            "Port": 443,
            "Relationships": [
                {
                    "EntityA": "ardownload3.adobe.com",
                    "EntityAType": "Domain",
                    "EntityB": "23.48.23.39",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        },
        {
            "Address": "95.140.236.0",
            "Relationships": [
                {
                    "EntityA": "ctldl.windowsupdate.com",
                    "EntityAType": "Domain",
                    "EntityB": "95.140.236.0",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        },
        {
            "Address": "54.224.241.105",
            "Relationships": [
                {
                    "EntityA": "p13n.adobe.io",
                    "EntityAType": "Domain",
                    "EntityB": "54.224.241.105",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        },
        {
            "Address": "34.237.241.83",
            "Relationships": [
                {
                    "EntityA": "p13n.adobe.io",
                    "EntityAType": "Domain",
                    "EntityB": "34.237.241.83",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        },
        {
            "Address": "18.213.11.84",
            "Relationships": [
                {
                    "EntityA": "p13n.adobe.io",
                    "EntityAType": "Domain",
                    "EntityB": "18.213.11.84",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        },
        {
            "Address": "50.16.47.176",
            "Relationships": [
                {
                    "EntityA": "p13n.adobe.io",
                    "EntityAType": "Domain",
                    "EntityB": "50.16.47.176",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        },
        {
            "Address": "23.48.23.25",
            "Relationships": [
                {
                    "EntityA": "ardownload3.adobe.com",
                    "EntityAType": "Domain",
                    "EntityB": "23.48.23.25",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        }
    ],
    "InfoFile": [
        {
            "EntryID": "5413@26c80993-f6f1-476d-89fa-6acd574d0ab2",
            "Extension": "png",
            "Info": "image/png",
            "Name": "screenshot0.png",
            "Size": 42650,
            "Type": "JPEG image data, baseline, precision 8, 1280x720, components 3"
        },
        {
            "EntryID": "5414@26c80993-f6f1-476d-89fa-6acd574d0ab2",
            "Extension": "png",
            "Info": "image/png",
            "Name": "screenshot1.png",
            "Size": 50017,
            "Type": "JPEG image data, baseline, precision 8, 1280x720, components 3"
        }
    ]
}
```

#### Human Readable Output

### Report for Task 45b62ba4-931a-472b-b604-e43879a473fd

|Analysisdate|Behavior|Connection|Dnsrequest|Fileinfo|Httprequest|ID|MD5|MIME|Network|Os|Process|Reports|SHA1|SHA256|SSDeep|Status|Threat|Verdict|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2022-08-02T11:23:42.846Z | Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, Category: Environment, Action: Reads the computer name, Threatlevel: 0,<br>Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, Category: Environment, Action: Searches for installed software, Threatlevel: 0,<br>Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 0,<br>Processuuid: dafd83d4-86bb-412e-8bec-be8ad78b79b7, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 0,<br>Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 0,<br>Processuuid: 2e9fdeec-25c6-495c-8b04-35b5310b20b0, Category: Environment, Action: Reads CPU info, Threatlevel: 0,<br>Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, Category: Suspicious actions, Action: Application launched itself, Threatlevel: 0,<br>Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, Category: Suspicious actions, Action: Application launched itself, Threatlevel: 0,<br>Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, Category: Environment, Action: Reads the computer name, Threatlevel: 0,<br>Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, Category: General, Action: Reads settings of System Certificates, Threatlevel: 0,<br>Processuuid: 40abe4ec-fef1-4fa1-b1f0-7a305e09f4aa, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 0,<br>Processuuid: 2e9fdeec-25c6-495c-8b04-35b5310b20b0, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 0,<br>Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, Category: General, Action: Checks Windows Trust Settings, Threatlevel: 0,<br>Processuuid: cf2bf809-c2b6-48a2-a142-050254cd6458, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 0,<br>Processuuid: 713c2780-51cc-4e0e-bc0e-e9d38f5184ac, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 0,<br>Processuuid: 2e9fdeec-25c6-495c-8b04-35b5310b20b0, Category: Environment, Action: Searches for installed software, Threatlevel: 0,<br>Processuuid: 2e9fdeec-25c6-495c-8b04-35b5310b20b0, Category: Environment, Action: Reads the computer name, Threatlevel: 0,<br>Processuuid: 60116489-5a40-4dd7-8c3c-8091346b6299, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 0,<br>Processuuid: 4c084eba-2541-46a3-833d-513c41115c5f, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 0,<br>Processuuid: 2cab4f07-8ae6-4560-9308-3800d2be988a, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 0,<br>Processuuid: 00cdebb4-cbb8-4078-ae10-a250f33f435d, Category: Environment, Action: Reads the computer name, Threatlevel: 1,<br>Processuuid: 00cdebb4-cbb8-4078-ae10-a250f33f435d, Category: General, Action: Checks Windows Trust Settings, Threatlevel: 0,<br>Processuuid: b9122008-82f2-4fa4-a128-956e24ae17ce, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 1,<br>Processuuid: 00cdebb4-cbb8-4078-ae10-a250f33f435d, Category: General, Action: Reads settings of System Certificates, Threatlevel: 0,<br>Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, Category: General, Action: Reads settings of System Certificates, Threatlevel: 0,<br>Processuuid: 00cdebb4-cbb8-4078-ae10-a250f33f435d, Category: System destruction, Action: Creates files in the program directory, Threatlevel: 1,<br>Processuuid: 00cdebb4-cbb8-4078-ae10-a250f33f435d, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 1 | Reputation: suspicious, Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, ASN: Zayo Bandwidth Inc, Country: US, Protocol: tcp, Port: 443, IP: 23.35.236.137,<br>Reputation: whitelisted, Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, ASN: Akamai International B.V., Country: null, Protocol: tcp, Port: 443, IP: 2.18.233.74,<br>Reputation: suspicious, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, ASN: TRUE INTERNET Co.,Ltd., Country: US, Protocol: tcp, Port: 443, IP: 23.48.23.34,<br>Reputation: malicious, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, ASN: Limelight Networks, Inc., Country: GB, Protocol: tcp, Port: 80, IP: 95.140.236.128,<br>Reputation: whitelisted, Processuuid: null, ASN: MCI Communications Services, Inc. d/b/a Verizon Business, Country: US, Protocol: tcp, Port: 80, IP: 93.184.220.29,<br>Reputation: unknown, Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, ASN: Amazon.com, Inc., Country: US, Protocol: tcp, Port: 443, IP: 54.224.241.105,<br>Reputation: whitelisted, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, ASN: MCI Communications Services, Inc. d/b/a Verizon Business, Country: US, Protocol: tcp, Port: 80, IP: 93.184.220.29,<br>Reputation: whitelisted, Processuuid: null, ASN: Akamai International B.V., Country: null, Protocol: tcp, Port: 443, IP: 2.18.233.74,<br>Reputation: suspicious, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, ASN: TRUE INTERNET Co.,Ltd., Country: US, Protocol: tcp, Port: 443, IP: 23.48.23.54,<br>Reputation: unknown, Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, ASN: Amazon.com, Inc., Country: US, Protocol: tcp, Port: 443, IP: 34.237.241.83,<br>Reputation: suspicious, Processuuid: null, ASN: TRUE INTERNET Co.,Ltd., Country: US, Protocol: tcp, Port: 443, IP: 23.48.23.39,<br>Reputation: suspicious, Processuuid: 00cdebb4-cbb8-4078-ae10-a250f33f435d, ASN: TRUE INTERNET Co.,Ltd., Country: US, Protocol: tcp, Port: 443, IP: 23.48.23.39 | Reputation: whitelisted, IP: [23.35.236.137], Domain: geo2.adobe.com,<br>Reputation: whitelisted, IP: [2.18.233.74], Domain: armmf.adobe.com,<br>Reputation: whitelisted, IP: [23.48.23.34, 23.48.23.54], Domain: acroipm2.adobe.com,<br>Reputation: whitelisted, IP: [95.140.236.128, 95.140.236.0], Domain: ctldl.windowsupdate.com,<br>Reputation: whitelisted, IP: [54.224.241.105, 34.237.241.83, 18.213.11.84, 50.16.47.176], Domain: p13n.adobe.io,<br>Reputation: shared, IP: [93.184.220.29], Domain: ocsp.digicert.com,<br>Reputation: shared, IP: [93.184.220.29], Domain: crl3.digicert.com,<br>Reputation: whitelisted, IP: [23.48.23.39, 23.48.23.25], Domain: ardownload3.adobe.com | PDF document, version 1.3 | Reputation: whitelisted, Country: GB, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, Body: {Response: {Size: 4817, Type: compressed, Threatlevel: MID, Permanenturl: https://content.any.run/tasks/45b62ba4-931a-472b-b604-e43879a473fd/download/files/a72b74e1-8c52-461f-8879-b9329e0e07e2, Hash: {MD5: f7dcb24540769805e5bb30d193944dce, SHA1: e26c583c562293356794937d9e2e6155d15449ee, SHA256: 6b88c6ac55bbd6fea0ebe5a760d1ad2cfce251c59d0151a1400701cb927e36ea}}}, Httpcode: 200, Status: RESPONDED, Proxydetected: false, Port: 80, IP: 95.140.236.128, URL: http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?f54c0a0f62519d56, Host: ctldl.windowsupdate.com, Method: GET,<br>Reputation: shared, Country: US, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, Body: {Response: {Size: 631, Type: der, Threatlevel: UNKNOWN, Permanenturl: https://content.any.run/tasks/45b62ba4-931a-472b-b604-e43879a473fd/download/files/a6a071a2-c307-4d99-9a16-64640129584f, Hash: {MD5: 7515e21f59ff1aadff6f6a1a0d105c2b, SHA1: 5264c5e2334a57d8669d31c67325a9b166e53bef, SHA256: 55a7640579a0e6c0bc2388063710e5cc3120b4df0840ec8a7af9a4bdc9235029}}}, Httpcode: 200, Status: RESPONDED, Proxydetected: false, Port: 80, IP: 93.184.220.29, URL: http://crl3.digicert.com/DigiCertGlobalRootCA.crl, Host: crl3.digicert.com, Method: GET | 45b62ba4-931a-472b-b604-e43879a473fd | 02475e29bd0816b697cad5b55cdf897a | application/pdf | Dnsrequest: [{Reputation: whitelisted, IP: [23.35.236.137], Domain: geo2.adobe.com}, {Reputation: whitelisted, IP: [2.18.233.74], Domain: armmf.adobe.com}, {Reputation: whitelisted, IP: [23.48.23.34, 23.48.23.54], Domain: acroipm2.adobe.com}, {Reputation: whitelisted, IP: [95.140.236.128, 95.140.236.0], Domain: ctldl.windowsupdate.com}, {Reputation: whitelisted, IP: [54.224.241.105, 34.237.241.83, 18.213.11.84, 50.16.47.176], Domain: p13n.adobe.io}, {Reputation: shared, IP: [93.184.220.29], Domain: ocsp.digicert.com}, {Reputation: shared, IP: [93.184.220.29], Domain: crl3.digicert.com}, {Reputation: whitelisted, IP: [23.48.23.39, 23.48.23.25], Domain: ardownload3.adobe.com}], Httprequest: [{Reputation: whitelisted, Country: GB, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, Body: {Response: {Size: 4817, Type: compressed, Threatlevel: MID, Permanenturl: https://content.any.run/tasks/45b62ba4-931a-472b-b604-e43879a473fd/download/files/a72b74e1-8c52-461f-8879-b9329e0e07e2, Hash: {MD5: f7dcb24540769805e5bb30d193944dce, SHA1: e26c583c562293356794937d9e2e6155d15449ee, SHA256: 6b88c6ac55bbd6fea0ebe5a760d1ad2cfce251c59d0151a1400701cb927e36ea}}}, Httpcode: 200, Status: RESPONDED, Proxydetected: false, Port: 80, IP: 95.140.236.128, URL: http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?f54c0a0f62519d56, Host: ctldl.windowsupdate.com, Method: GET}, {Reputation: shared, Country: US, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, Body: {Response: {Size: 631, Type: der, Threatlevel: UNKNOWN, Permanenturl: https://content.any.run/tasks/45b62ba4-931a-472b-b604-e43879a473fd/download/files/a6a071a2-c307-4d99-9a16-64640129584f, Hash: {MD5: 7515e21f59ff1aadff6f6a1a0d105c2b, SHA1: 5264c5e2334a57d8669d31c67325a9b166e53bef, SHA256: 55a7640579a0e6c0bc2388063710e5cc3120b4df0840ec8a7af9a4bdc9235029}}}, Httpcode: 200, Status: RESPONDED, Proxydetected: false, Port: 80, IP: 93.184.220.29, URL: http://crl3.digicert.com/DigiCertGlobalRootCA.crl, Host: crl3.digicert.com, Method: GET}], Connection: [{Reputation: suspicious, Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, ASN: Zayo Bandwidth Inc, Country: US, Protocol: tcp, Port: 443, IP: 23.35.236.137}, {Reputation: whitelisted, Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, ASN: Akamai International B.V., Country: null, Protocol: tcp, Port: 443, IP: 2.18.233.74}, {Reputation: suspicious, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, ASN: TRUE INTERNET Co.,Ltd., Country: US, Protocol: tcp, Port: 443, IP: 23.48.23.34}, {Reputation: malicious, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, ASN: Limelight Networks, Inc., Country: GB, Protocol: tcp, Port: 80, IP: 95.140.236.128}, {Reputation: whitelisted, Processuuid: null, ASN: MCI Communications Services, Inc. d/b/a Verizon Business, Country: US, Protocol: tcp, Port: 80, IP: 93.184.220.29}, {Reputation: unknown, Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, ASN: Amazon.com, Inc., Country: US, Protocol: tcp, Port: 443, IP: 54.224.241.105}, {Reputation: whitelisted, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, ASN: MCI Communications Services, Inc. d/b/a Verizon Business, Country: US, Protocol: tcp, Port: 80, IP: 93.184.220.29}, {Reputation: whitelisted, Processuuid: null, ASN: Akamai International B.V., Country: null, Protocol: tcp, Port: 443, IP: 2.18.233.74}, {Reputation: suspicious, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, ASN: TRUE INTERNET Co.,Ltd., Country: US, Protocol: tcp, Port: 443, IP: 23.48.23.54}, {Reputation: unknown, Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, ASN: Amazon.com, Inc., Country: US, Protocol: tcp, Port: 443, IP: 34.237.241.83}, {Reputation: suspicious, Processuuid: null, ASN: TRUE INTERNET Co.,Ltd., Country: US, Protocol: tcp, Port: 443, IP: 23.48.23.39}, {Reputation: suspicious, Processuuid: 00cdebb4-cbb8-4078-ae10-a250f33f435d, ASN: TRUE INTERNET Co.,Ltd., Country: US, Protocol: tcp, Port: 443, IP: 23.48.23.39}], Threat: [{Processuuid: null, Message: ET INFO TLS Handshake Failure, Class: Potentially Bad Traffic, Srcport: 443, Dstport: 55801, Srcip: 23.48.23.39, Dstip: local}] | Windows 7 Professional Service Pack 1 (build: 7601, 32 bit) | Filename: [System Process], PID: 0, PPID: 0, Processuuid: 375da1b2-fd25-4328-a2dd-6d4d7fb44396, Cmd: , Path: [System Process], User: , Integritylevel: UNKNOWN, Exitcode: null, Mainprocess: false, Version: {Company: , Description: , Version: ,<br>Filename: System, PID: 4, PPID: 0, Processuuid: a271b969-ce69-49b0-838f-0356818625d0, Cmd: , Path: System, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: , Description: , Version: ,<br>Filename: smss.exe, PID: 260, PPID: 4, Processuuid: 9a0ca621-1717-43e1-915a-4fe4d8f6942e, Cmd: \\SystemRoot\\System32\\smss.exe, Path: \\SystemRoot\\System32\\smss.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: , Description: , Version: ,<br>Filename: csrss.exe, PID: 340, PPID: 320, Processuuid: 0952f427-a077-4cc6-9355-0b08cef93dc0, Cmd: %SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows SharedSection=1024,12288,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16, Path: C:\\Windows\\system32\\csrss.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Client Server Runtime Process, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: wininit.exe, PID: 376, PPID: 320, Processuuid: f1749785-eeea-498b-9ae3-0aa0eaec409c, Cmd: wininit.exe, Path: C:\\Windows\\system32\\wininit.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Windows Start-Up Application, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: csrss.exe, PID: 384, PPID: 368, Processuuid: ac42625e-c10a-4f4a-953d-71caa933dc92, Cmd: %SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows SharedSection=1024,12288,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16, Path: C:\\Windows\\system32\\csrss.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Client Server Runtime Process, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: winlogon.exe, PID: 432, PPID: 368, Processuuid: dadff15c-8866-4534-93b3-2524c93986cc, Cmd: winlogon.exe, Path: C:\\Windows\\system32\\winlogon.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Windows Logon Application, Version: 6.1.7601.17514 (win7sp1_rtm.101119-1850),<br>Filename: services.exe, PID: 468, PPID: 376, Processuuid: b074db04-9698-41f7-a2ed-3d930d38a4e8, Cmd: C:\\Windows\\system32\\services.exe, Path: C:\\Windows\\system32\\services.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Services and Controller app, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: lsass.exe, PID: 484, PPID: 376, Processuuid: b7dca6aa-04a4-4080-9e3c-f2d07ae2b848, Cmd: C:\\Windows\\system32\\lsass.exe, Path: C:\\Windows\\system32\\lsass.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Local Security Authority Process, Version: 6.1.7601.24545 (win7sp1_ldr_escrow.200102-1707),<br>Filename: lsm.exe, PID: 492, PPID: 376, Processuuid: 1b88a259-2c6a-4fa8-acbf-02289d497622, Cmd: C:\\Windows\\system32\\lsm.exe, Path: C:\\Windows\\system32\\lsm.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Local Session Manager Service, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: svchost.exe, PID: 592, PPID: 468, Processuuid: f93b01ef-9719-480c-95b7-642d5d551b1b, Cmd: C:\\Windows\\system32\\svchost.exe -k DcomLaunch, Path: C:\\Windows\\system32\\svchost.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: svchost.exe, PID: 672, PPID: 468, Processuuid: c3cf8aac-4921-44b4-951d-5d8a1db7b617, Cmd: C:\\Windows\\system32\\svchost.exe -k RPCSS, Path: C:\\Windows\\system32\\svchost.exe, User: NETWORK SERVICE, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: svchost.exe, PID: 760, PPID: 468, Processuuid: a8a5af5a-ec52-47d8-9655-199f14ea5c45, Cmd: C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted, Path: C:\\Windows\\System32\\svchost.exe, User: LOCAL SERVICE, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: svchost.exe, PID: 796, PPID: 468, Processuuid: 270bc634-7c40-4a22-8119-a5bbdfb22422, Cmd: C:\\Windows\\System32\\svchost.exe -k LocalSystemNetworkRestricted, Path: C:\\Windows\\System32\\svchost.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: svchost.exe, PID: 824, PPID: 468, Processuuid: 92be8359-8941-4eff-8dea-f0c816cff7eb, Cmd: C:\\Windows\\system32\\svchost.exe -k LocalService, Path: C:\\Windows\\system32\\svchost.exe, User: LOCAL SERVICE, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: svchost.exe, PID: 860, PPID: 468, Processuuid: a4e149c7-1d4e-4de9-956b-058ee9cf394d, Cmd: C:\\Windows\\system32\\svchost.exe -k netsvcs, Path: C:\\Windows\\system32\\svchost.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: svchost.exe, PID: 968, PPID: 468, Processuuid: be778e77-cf65-4405-9ad2-c0e5ea36e972, Cmd: C:\\Windows\\system32\\svchost.exe -k GPSvcGroup, Path: C:\\Windows\\system32\\svchost.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: svchost.exe, PID: 1088, PPID: 468, Processuuid: e0eff788-3254-4665-8fc6-487f4d789563, Cmd: C:\\Windows\\system32\\svchost.exe -k NetworkService, Path: C:\\Windows\\system32\\svchost.exe, User: NETWORK SERVICE, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: spoolsv.exe, PID: 1236, PPID: 468, Processuuid: c76927c0-29c0-402a-9a9a-ebb1191b2801, Cmd: C:\\Windows\\System32\\spoolsv.exe, Path: C:\\Windows\\System32\\spoolsv.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Spooler SubSystem App, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: svchost.exe, PID: 1264, PPID: 468, Processuuid: ece1b0ec-252e-496b-a5f6-08c661b0e333, Cmd: C:\\Windows\\system32\\svchost.exe -k LocalServiceNoNetwork, Path: C:\\Windows\\system32\\svchost.exe, User: LOCAL SERVICE, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: svchost.exe, PID: 1352, PPID: 468, Processuuid: 2e86deea-86d0-48f9-8b59-70228ce98f12, Cmd: C:\\Windows\\System32\\svchost.exe -k utcsvc, Path: C:\\Windows\\System32\\svchost.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: IMEDICTUPDATE.EXE, PID: 1424, PPID: 468, Processuuid: 9550f782-1f7c-4dfe-86c7-b5bf6eb6a945, Cmd: \C:\\Program Files\\Common Files\\Microsoft Shared\\IME14\\SHARED\\IMEDICTUPDATE.EXE\, Path: C:\\Program Files\\Common Files\\Microsoft Shared\\IME14\\SHARED\\IMEDICTUPDATE.EXE, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Microsoft Office IME 2010, Version: 14.0.4734.1000,<br>Filename: svchost.exe, PID: 1936, PPID: 468, Processuuid: 82765043-e885-448e-8982-e42438ca0a52, Cmd: C:\\Windows\\system32\\svchost.exe -k NetworkServiceNetworkRestricted, Path: C:\\Windows\\system32\\svchost.exe, User: NETWORK SERVICE, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: taskhost.exe, PID: 320, PPID: 468, Processuuid: 0dcb27a1-d908-4b0f-a25f-917cd8df6c1e, Cmd: \taskhost.exe\, Path: C:\\Windows\\system32\\taskhost.exe, User: admin, Integritylevel: MEDIUM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Tasks, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: taskeng.exe, PID: 288, PPID: 860, Processuuid: d2a105e9-13a6-4964-81e6-070af81b5dec, Cmd: taskeng.exe {BB154EF7-42D4-42F2-B57F-9CBB745DE3E3}, Path: C:\\Windows\\system32\\taskeng.exe, User: admin, Integritylevel: MEDIUM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Task Scheduler Engine, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: Dwm.exe, PID: 936, PPID: 796, Processuuid: bbcd1df9-3e48-4e58-9751-b61e7c472815, Cmd: \C:\\Windows\\system32\\Dwm.exe\, Path: C:\\Windows\\system32\\Dwm.exe, User: admin, Integritylevel: MEDIUM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Desktop Window Manager, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: Explorer.EXE, PID: 1464, PPID: 820, Processuuid: 4966dad3-7df9-4800-87e1-1ae4b32b93a2, Cmd: C:\\Windows\\Explorer.EXE, Path: C:\\Windows\\Explorer.EXE, User: admin, Integritylevel: MEDIUM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Windows Explorer, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: ctfmon.exe, PID: 1396, PPID: 288, Processuuid: 6307f043-d99d-44e7-a6d7-1e11eea3be3d, Cmd: C:\\Windows\\System32\\ctfmon.exe , Path: C:\\Windows\\System32\\ctfmon.exe, User: admin, Integritylevel: MEDIUM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: CTF Loader, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: SearchIndexer.exe, PID: 2544, PPID: 468, Processuuid: be7286ed-ef2f-441e-acca-9accb8f377a4, Cmd: C:\\Windows\\system32\\SearchIndexer.exe /Embedding, Path: C:\\Windows\\system32\\SearchIndexer.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Microsoft Windows Search Indexer, Version: 7.00.7600.16385 (win7_rtm.090713-1255),<br>Filename: SearchProtocolHost.exe, PID: 3452, PPID: 2544, Processuuid: 3d0967dc-e2e6-4339-a619-a084045bbbf1, Cmd: \C:\\Windows\\system32\\SearchProtocolHost.exe\ Global\\UsGthrFltPipeMssGthrPipe3_ Global\\UsGthrCtrlFltPipeMssGthrPipe3 1 -2147483646 \Software\\Microsoft\\Windows Search\ \Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)\ \C:\\ProgramData\\Microsoft\\Search\\Data\\Temp\\usgthrsvc\ \DownLevelDaemon\ , Path: C:\\Windows\\system32\\SearchProtocolHost.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Microsoft Windows Search Protocol Host, Version: 7.00.7601.24542 (win7sp1_ldr_escrow.191209-2211),<br>Filename: SearchFilterHost.exe, PID: 3840, PPID: 2544, Processuuid: 9384891d-6ead-4179-bac6-3734cee1f6bb, Cmd: \C:\\Windows\\system32\\SearchFilterHost.exe\ 0 520 524 532 65536 528 , Path: C:\\Windows\\system32\\SearchFilterHost.exe, User: SYSTEM, Integritylevel: MEDIUM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Microsoft Windows Search Filter Host, Version: 7.00.7601.24542 (win7sp1_ldr_escrow.191209-2211),<br>Filename: DllHost.exe, PID: 2872, PPID: 592, Processuuid: 93b6c7fc-1aef-4150-be36-b5930f55b85a, Cmd: C:\\Windows\\system32\\DllHost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}, Path: C:\\Windows\\system32\\DllHost.exe, User: admin, Integritylevel: MEDIUM, Exitcode: 0, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: COM Surrogate, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: DllHost.exe, PID: 2316, PPID: 592, Processuuid: 86c03f0a-b480-477e-a632-192ba22dac62, Cmd: C:\\Windows\\system32\\DllHost.exe /Processid:{F9717507-6651-4EDB-BFF7-AE615179BCCF}, Path: C:\\Windows\\system32\\DllHost.exe, User: admin, Integritylevel: MEDIUM, Exitcode: 0, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: COM Surrogate, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: AUDIODG.EXE, PID: 3000, PPID: 760, Processuuid: 9e9e24d6-751d-4019-b28b-46a44e9018ca, Cmd: C:\\Windows\\system32\\AUDIODG.EXE 0x6cc, Path: C:\\Windows\\system32\\AUDIODG.EXE, User: LOCAL SERVICE, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Windows Audio Device Graph Isolation , Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: svchost.exe, PID: 3860, PPID: 468, Processuuid: fd7ffe77-7fc9-4ae2-8592-18f48d7e9752, Cmd: C:\\Windows\\system32\\svchost.exe -k LocalServiceAndNoImpersonation, Path: C:\\Windows\\system32\\svchost.exe, User: LOCAL SERVICE, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: DllHost.exe, PID: 2588, PPID: 592, Processuuid: f945261c-f8b9-44fa-8173-d859bdff9085, Cmd: C:\\Windows\\system32\\DllHost.exe /Processid:{F9717507-6651-4EDB-BFF7-AE615179BCCF}, Path: C:\\Windows\\system32\\DllHost.exe, User: admin, Integritylevel: MEDIUM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: COM Surrogate, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: AcroRd32.exe, PID: 2040, PPID: 1464, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, Cmd: \C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe\ \C:\\Users\\admin\\AppData\\Local\\Temp\\test_file.pdf\, Path: C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe, User: admin, Integritylevel: MEDIUM, Exitcode: null, Mainprocess: true, Version: {Company: Adobe Systems Incorporated, Description: Adobe Acrobat Reader DC , Version: 20.13.20064.405839,<br>Filename: AcroRd32.exe, PID: 1280, PPID: 2040, Processuuid: 2e9fdeec-25c6-495c-8b04-35b5310b20b0, Cmd: \C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe\ --type=renderer  \C:\\Users\\admin\\AppData\\Local\\Temp\\test_file.pdf\, Path: C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe, User: admin, Integritylevel: LOW, Exitcode: null, Mainprocess: false, Version: {Company: Adobe Systems Incorporated, Description: Adobe Acrobat Reader DC , Version: 20.13.20064.405839,<br>Filename: RdrCEF.exe, PID: 3316, PPID: 2040, Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, Cmd: \C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe\ --backgroundcolor=16514043, Path: C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe, User: admin, Integritylevel: LOW, Exitcode: null, Mainprocess: false, Version: {Company: Adobe Systems Incorporated, Description: Adobe RdrCEF, Version: 20.13.20064.405839,<br>Filename: RdrCEF.exe, PID: 2128, PPID: 3316, Processuuid: cf2bf809-c2b6-48a2-a142-050254cd6458, Cmd: \C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe\ --type=renderer --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --touch-events=enabled --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-gpu-compositing --lang=en-US --disable-pack-loading --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --log-severity=disable --product-version=\ReaderServices/20.13.20064 Chrome/80.0.0.0\ --device-scale-factor=1 --num-raster-threads=2 --enable-main-frame-before-activation --service-request-channel-token=14024734510508519417 --renderer-client-id=2 --mojo-platform-channel-handle=1204 --allow-no-sandbox-job /prefetch:1, Path: C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe, User: admin, Integritylevel: LOW, Exitcode: null, Mainprocess: false, Version: {Company: Adobe Systems Incorporated, Description: Adobe RdrCEF, Version: 20.13.20064.405839,<br>Filename: RdrCEF.exe, PID: 1180, PPID: 3316, Processuuid: dafd83d4-86bb-412e-8bec-be8ad78b79b7, Cmd: \C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe\ --type=gpu-process --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-pack-loading --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --log-severity=disable --product-version=\ReaderServices/20.13.20064 Chrome/80.0.0.0\ --lang=en-US --gpu-preferences=KAAAAAAAAADgACAgAQAAAAAAAAAAAGAAAAAAABAAAAAIAAAAAAAAACgAAAAEAAAAIAAAAAAAAAAoAAAAAAAAADAAAAAAAAAAOAAAAAAAAAAQAAAAAAAAAAAAAAAFAAAAEAAAAAAAAAAAAAAABgAAABAAAAAAAAAAAQAAAAUAAAAQAAAAAAAAAAEAAAAGAAAA --use-gl=swiftshader-webgl --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --service-request-channel-token=12223321443149433680 --mojo-platform-channel-handle=1236 --allow-no-sandbox-job --ignored=\ --type=renderer \ /prefetch:2, Path: C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe, User: admin, Integritylevel: LOW, Exitcode: 1, Mainprocess: false, Version: {Company: Adobe Systems Incorporated, Description: Adobe RdrCEF, Version: 20.13.20064.405839,<br>Filename: RdrCEF.exe, PID: 2860, PPID: 3316, Processuuid: 713c2780-51cc-4e0e-bc0e-e9d38f5184ac, Cmd: \C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe\ --type=gpu-process --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-pack-loading --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --log-severity=disable --product-version=\ReaderServices/20.13.20064 Chrome/80.0.0.0\ --lang=en-US --gpu-preferences=KAAAAAAAAADgACAgAQAAAAAAAAAAAGAAAAAAABAAAAAIAAAAAAAAACgAAAAEAAAAIAAAAAAAAAAoAAAAAAAAADAAAAAAAAAAOAAAAAAAAAAQAAAAAAAAAAAAAAAFAAAAEAAAAAAAAAAAAAAABgAAABAAAAAAAAAAAQAAAAUAAAAQAAAAAAAAAAEAAAAGAAAA --use-gl=swiftshader-webgl --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --service-request-channel-token=12378439338200214857 --mojo-platform-channel-handle=1408 --allow-no-sandbox-job --ignored=\ --type=renderer \ /prefetch:2, Path: C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe, User: admin, Integritylevel: LOW, Exitcode: 1, Mainprocess: false, Version: {Company: Adobe Systems Incorporated, Description: Adobe RdrCEF, Version: 20.13.20064.405839,<br>Filename: RdrCEF.exe, PID: 2108, PPID: 3316, Processuuid: 40abe4ec-fef1-4fa1-b1f0-7a305e09f4aa, Cmd: \C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe\ --type=gpu-process --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-pack-loading --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --log-severity=disable --product-version=\ReaderServices/20.13.20064 Chrome/80.0.0.0\ --lang=en-US --gpu-preferences=KAAAAAAAAADgACAgAQAAAAAAAAAAAGAAAAAAABAAAAAIAAAAAAAAACgAAAAEAAAAIAAAAAAAAAAoAAAAAAAAADAAAAAAAAAAOAAAAAAAAAAQAAAAAAAAAAAAAAAFAAAAEAAAAAAAAAAAAAAABgAAABAAAAAAAAAAAQAAAAUAAAAQAAAAAAAAAAEAAAAGAAAA --use-gl=swiftshader-webgl --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --service-request-channel-token=13732513110551940315 --mojo-platform-channel-handle=1396 --allow-no-sandbox-job --ignored=\ --type=renderer \ /prefetch:2, Path: C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe, User: admin, Integritylevel: LOW, Exitcode: 1, Mainprocess: false, Version: {Company: Adobe Systems Incorporated, Description: Adobe RdrCEF, Version: 20.13.20064.405839,<br>Filename: RdrCEF.exe, PID: 920, PPID: 3316, Processuuid: 4c084eba-2541-46a3-833d-513c41115c5f, Cmd: \C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe\ --type=renderer --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --touch-events=enabled --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-gpu-compositing --lang=en-US --disable-pack-loading --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --log-severity=disable --product-version=\ReaderServices/20.13.20064 Chrome/80.0.0.0\ --device-scale-factor=1 --num-raster-threads=2 --enable-main-frame-before-activation --service-request-channel-token=4847431092444551383 --renderer-client-id=6 --mojo-platform-channel-handle=1616 --allow-no-sandbox-job /prefetch:1, Path: C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe, User: admin, Integritylevel: LOW, Exitcode: null, Mainprocess: false, Version: {Company: Adobe Systems Incorporated, Description: Adobe RdrCEF, Version: 20.13.20064.405839,<br>Filename: RdrCEF.exe, PID: 3424, PPID: 3316, Processuuid: 60116489-5a40-4dd7-8c3c-8091346b6299, Cmd: \C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe\ --type=renderer --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --touch-events=enabled --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-gpu-compositing --lang=en-US --disable-pack-loading --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --log-severity=disable --product-version=\ReaderServices/20.13.20064 Chrome/80.0.0.0\ --device-scale-factor=1 --num-raster-threads=2 --enable-main-frame-before-activation --service-request-channel-token=16593724968950981413 --renderer-client-id=7 --mojo-platform-channel-handle=1536 --allow-no-sandbox-job /prefetch:1, Path: C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe, User: admin, Integritylevel: LOW, Exitcode: null, Mainprocess: false, Version: {Company: Adobe Systems Incorporated, Description: Adobe RdrCEF, Version: 20.13.20064.405839,<br>Filename: RdrCEF.exe, PID: 240, PPID: 3316, Processuuid: 2cab4f07-8ae6-4560-9308-3800d2be988a, Cmd: \C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe\ --type=renderer --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --touch-events=enabled --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-gpu-compositing --lang=en-US --disable-pack-loading --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --log-severity=disable --product-version=\ReaderServices/20.13.20064 Chrome/80.0.0.0\ --device-scale-factor=1 --num-raster-threads=2 --enable-main-frame-before-activation --service-request-channel-token=6562753338979179477 --renderer-client-id=8 --mojo-platform-channel-handle=1836 --allow-no-sandbox-job /prefetch:1, Path: C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe, User: admin, Integritylevel: LOW, Exitcode: null, Mainprocess: false, Version: {Company: Adobe Systems Incorporated, Description: Adobe RdrCEF, Version: 20.13.20064.405839,<br>Filename: AdobeARM.exe, PID: 2124, PPID: 2040, Processuuid: 00cdebb4-cbb8-4078-ae10-a250f33f435d, Cmd: \C:\\Program Files\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe\ /PRODUCT:Reader /VERSION:20.0 /MODE:3, Path: C:\\Program Files\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe, User: admin, Integritylevel: MEDIUM, Exitcode: null, Mainprocess: false, Version: {Company: Adobe Inc., Description: Adobe Reader and Acrobat Manager, Version: 1.824.39.9311,<br>Filename: Reader_sl.exe, PID: 3532, PPID: 2124, Processuuid: b9122008-82f2-4fa4-a128-956e24ae17ce, Cmd: \C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\Reader_sl.exe\ , Path: C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\Reader_sl.exe, User: admin, Integritylevel: MEDIUM, Exitcode: 0, Mainprocess: false, Version: {Company: Adobe Systems Incorporated, Description: Adobe Acrobat SpeedLauncher, Version: 20.12.20041.394260 | IOC: https://api.any.run/report/45b62ba4-931a-472b-b604-e43879a473fd/ioc/json, MISP: https://api.any.run/report/45b62ba4-931a-472b-b604-e43879a473fd/summary/misp, HTML: https://api.any.run/report/45b62ba4-931a-472b-b604-e43879a473fd/summary/html, graph: https://content.any.run/tasks/45b62ba4-931a-472b-b604-e43879a473fd/graph | 44e4ee171347fb954938ea87400c5bef5ec8be8b | c558877e6ad6de172b8cc10461a12905c6b98d6265e650b3650b35ff73a63b03 | 768:ttu1HAfRvxuliB5IXqwdbOiNf6vP47BL1Gq:tiUVMXqcbFfsA7pMq | done | Processuuid: null, Message: ET INFO TLS Handshake Failure, Class: Potentially Bad Traffic, Srcport: 443, Dstport: 55801, Srcip: 23.48.23.39, Dstip: local | No threats detected |

### anyrun-run-analysis
***
Submit a file or url for analysis.


#### Base Command

`anyrun-run-analysis`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| obj_type | Type of new task. Possible values are: file, url, remote file. Default is file. | Optional | 
| polling | Whether to use polling. Possible values are: false, true. Default is false. | Optional | 
| interval_in_seconds | The interval (in seconds) of when to next poll for results. | Optional | 
| timeout | The timeout (in seconds) of the polling. | Optional | 
| file | EntryID of the file to analyze. | Optional | 
| obj_url | URL, used only if 'obj_type' command argument is 'url' or 'download'. Permitted size is 5-512 characters long. | Optional | 
| env_bitness | Bitness of OS. Possible values are: 32, 64. Default is 32. | Optional | 
| env_version | Version of Windows OS. Possible values are: Windows Vista, Windows 7, Windows 8.1, Windows 10. Default is Windows 7. | Optional | 
| env_type | Environment preset type. Possible values are: complete, clean, office. Default is complete. | Optional | 
| opt_network_connect | Network connection state. Possible values are: true, false. Default is true. | Optional | 
| opt_kernel_heavyevasion | Heavy evasion option. Possible values are: true, false. Default is false. | Optional | 
| opt_privacy_type | Privacy settings for generated task. Possible values are: owner, bylink, public. Default is owner. | Optional | 


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
| Domain.Name | String | Domain name. | 
| IP.ASN | String | IP ASN. | 
| IP.Address | String | IP Address. | 
| IP.Geo.Country | String | Origin country of the IP address. | 
| IP.Port | Number | Port number. | 
| ANYRUN.Task.Status | String | Task analysis status. | 
| ANYRUN.Task.Reports.HTML | String | URL for the HTML report. | 
| ANYRUN.Task.Reports.IOC | String | URL for the IOC report. | 
| ANYRUN.Task.Reports.MISP | String | URL for the MISP report. | 
| ANYRUN.Task.Reports.graph | String | URL for the graph report. | 

#### Command example
```!anyrun-run-analysis file=5333@26c80993-f6f1-476d-89fa-6acd574d0ab2 polling=true timeout=1300 interval_in_seconds=10```

#### Context Example
```json
{
    "ANYRUN": {
        "Task": {
            "Analysisdate": "2022-08-02T11:23:42.846Z",
            "Behavior": [
                {
                    "Action": "Reads the computer name",
                    "Category": "Environment",
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Threatlevel": 0
                },
                {
                    "Action": "Searches for installed software",
                    "Category": "Environment",
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "dafd83d4-86bb-412e-8bec-be8ad78b79b7",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                    "Threatlevel": 0
                },
                {
                    "Action": "Reads CPU info",
                    "Category": "Environment",
                    "Processuuid": "2e9fdeec-25c6-495c-8b04-35b5310b20b0",
                    "Threatlevel": 0
                },
                {
                    "Action": "Application launched itself",
                    "Category": "Suspicious actions",
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Threatlevel": 0
                },
                {
                    "Action": "Application launched itself",
                    "Category": "Suspicious actions",
                    "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                    "Threatlevel": 0
                },
                {
                    "Action": "Reads the computer name",
                    "Category": "Environment",
                    "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                    "Threatlevel": 0
                },
                {
                    "Action": "Reads settings of System Certificates",
                    "Category": "General",
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "40abe4ec-fef1-4fa1-b1f0-7a305e09f4aa",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "2e9fdeec-25c6-495c-8b04-35b5310b20b0",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks Windows Trust Settings",
                    "Category": "General",
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "cf2bf809-c2b6-48a2-a142-050254cd6458",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "713c2780-51cc-4e0e-bc0e-e9d38f5184ac",
                    "Threatlevel": 0
                },
                {
                    "Action": "Searches for installed software",
                    "Category": "Environment",
                    "Processuuid": "2e9fdeec-25c6-495c-8b04-35b5310b20b0",
                    "Threatlevel": 0
                },
                {
                    "Action": "Reads the computer name",
                    "Category": "Environment",
                    "Processuuid": "2e9fdeec-25c6-495c-8b04-35b5310b20b0",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "60116489-5a40-4dd7-8c3c-8091346b6299",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "4c084eba-2541-46a3-833d-513c41115c5f",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "2cab4f07-8ae6-4560-9308-3800d2be988a",
                    "Threatlevel": 0
                },
                {
                    "Action": "Reads the computer name",
                    "Category": "Environment",
                    "Processuuid": "00cdebb4-cbb8-4078-ae10-a250f33f435d",
                    "Threatlevel": 1
                },
                {
                    "Action": "Checks Windows Trust Settings",
                    "Category": "General",
                    "Processuuid": "00cdebb4-cbb8-4078-ae10-a250f33f435d",
                    "Threatlevel": 0
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "b9122008-82f2-4fa4-a128-956e24ae17ce",
                    "Threatlevel": 1
                },
                {
                    "Action": "Reads settings of System Certificates",
                    "Category": "General",
                    "Processuuid": "00cdebb4-cbb8-4078-ae10-a250f33f435d",
                    "Threatlevel": 0
                },
                {
                    "Action": "Reads settings of System Certificates",
                    "Category": "General",
                    "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                    "Threatlevel": 0
                },
                {
                    "Action": "Creates files in the program directory",
                    "Category": "System destruction",
                    "Processuuid": "00cdebb4-cbb8-4078-ae10-a250f33f435d",
                    "Threatlevel": 1
                },
                {
                    "Action": "Checks supported languages",
                    "Category": "Unusual activities",
                    "Processuuid": "00cdebb4-cbb8-4078-ae10-a250f33f435d",
                    "Threatlevel": 1
                }
            ],
            "Connection": [
                {
                    "ASN": "Zayo Bandwidth Inc",
                    "Country": "US",
                    "IP": "23.35.236.137",
                    "Port": 443,
                    "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                    "Protocol": "tcp",
                    "Reputation": "suspicious"
                },
                {
                    "ASN": "Akamai International B.V.",
                    "Country": null,
                    "IP": "2.18.233.74",
                    "Port": 443,
                    "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                    "Protocol": "tcp",
                    "Reputation": "whitelisted"
                },
                {
                    "ASN": "TRUE INTERNET Co.,Ltd.",
                    "Country": "US",
                    "IP": "23.48.23.34",
                    "Port": 443,
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Protocol": "tcp",
                    "Reputation": "suspicious"
                },
                {
                    "ASN": "Limelight Networks, Inc.",
                    "Country": "GB",
                    "IP": "95.140.236.128",
                    "Port": 80,
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Protocol": "tcp",
                    "Reputation": "malicious"
                },
                {
                    "ASN": "MCI Communications Services, Inc. d/b/a Verizon Business",
                    "Country": "US",
                    "IP": "93.184.220.29",
                    "Port": 80,
                    "Processuuid": null,
                    "Protocol": "tcp",
                    "Reputation": "whitelisted"
                },
                {
                    "ASN": "Amazon.com, Inc.",
                    "Country": "US",
                    "IP": "54.224.241.105",
                    "Port": 443,
                    "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                    "Protocol": "tcp",
                    "Reputation": "unknown"
                },
                {
                    "ASN": "MCI Communications Services, Inc. d/b/a Verizon Business",
                    "Country": "US",
                    "IP": "93.184.220.29",
                    "Port": 80,
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Protocol": "tcp",
                    "Reputation": "whitelisted"
                },
                {
                    "ASN": "Akamai International B.V.",
                    "Country": null,
                    "IP": "2.18.233.74",
                    "Port": 443,
                    "Processuuid": null,
                    "Protocol": "tcp",
                    "Reputation": "whitelisted"
                },
                {
                    "ASN": "TRUE INTERNET Co.,Ltd.",
                    "Country": "US",
                    "IP": "23.48.23.54",
                    "Port": 443,
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Protocol": "tcp",
                    "Reputation": "suspicious"
                },
                {
                    "ASN": "Amazon.com, Inc.",
                    "Country": "US",
                    "IP": "34.237.241.83",
                    "Port": 443,
                    "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                    "Protocol": "tcp",
                    "Reputation": "unknown"
                },
                {
                    "ASN": "TRUE INTERNET Co.,Ltd.",
                    "Country": "US",
                    "IP": "23.48.23.39",
                    "Port": 443,
                    "Processuuid": null,
                    "Protocol": "tcp",
                    "Reputation": "suspicious"
                },
                {
                    "ASN": "TRUE INTERNET Co.,Ltd.",
                    "Country": "US",
                    "IP": "23.48.23.39",
                    "Port": 443,
                    "Processuuid": "00cdebb4-cbb8-4078-ae10-a250f33f435d",
                    "Protocol": "tcp",
                    "Reputation": "suspicious"
                }
            ],
            "Dnsrequest": [
                {
                    "Domain": "geo2.adobe.com",
                    "IP": [
                        "23.35.236.137"
                    ],
                    "Reputation": "whitelisted"
                },
                {
                    "Domain": "armmf.adobe.com",
                    "IP": [
                        "2.18.233.74"
                    ],
                    "Reputation": "whitelisted"
                },
                {
                    "Domain": "acroipm2.adobe.com",
                    "IP": [
                        "23.48.23.34",
                        "23.48.23.54"
                    ],
                    "Reputation": "whitelisted"
                },
                {
                    "Domain": "ctldl.windowsupdate.com",
                    "IP": [
                        "95.140.236.128",
                        "95.140.236.0"
                    ],
                    "Reputation": "whitelisted"
                },
                {
                    "Domain": "p13n.adobe.io",
                    "IP": [
                        "54.224.241.105",
                        "34.237.241.83",
                        "18.213.11.84",
                        "50.16.47.176"
                    ],
                    "Reputation": "whitelisted"
                },
                {
                    "Domain": "ocsp.digicert.com",
                    "IP": [
                        "93.184.220.29"
                    ],
                    "Reputation": "shared"
                },
                {
                    "Domain": "crl3.digicert.com",
                    "IP": [
                        "93.184.220.29"
                    ],
                    "Reputation": "shared"
                },
                {
                    "Domain": "ardownload3.adobe.com",
                    "IP": [
                        "23.48.23.39",
                        "23.48.23.25"
                    ],
                    "Reputation": "whitelisted"
                }
            ],
            "Fileinfo": "PDF document, version 1.3",
            "Httprequest": [
                {
                    "Body": {
                        "Response": {
                            "Hash": {
                                "MD5": "f7dcb24540769805e5bb30d193944dce",
                                "SHA1": "e26c583c562293356794937d9e2e6155d15449ee",
                                "SHA256": "6b88c6ac55bbd6fea0ebe5a760d1ad2cfce251c59d0151a1400701cb927e36ea"
                            },
                            "Permanenturl": "https://content.any.run/tasks/45b62ba4-931a-472b-b604-e43879a473fd/download/files/a72b74e1-8c52-461f-8879-b9329e0e07e2",
                            "Size": 4817,
                            "Threatlevel": "MID",
                            "Type": "compressed"
                        }
                    },
                    "Country": "GB",
                    "Host": "ctldl.windowsupdate.com",
                    "Httpcode": 200,
                    "IP": "95.140.236.128",
                    "Method": "GET",
                    "Port": 80,
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Proxydetected": false,
                    "Reputation": "whitelisted",
                    "Status": "RESPONDED",
                    "URL": "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?f54c0a0f62519d56"
                },
                {
                    "Body": {
                        "Response": {
                            "Hash": {
                                "MD5": "7515e21f59ff1aadff6f6a1a0d105c2b",
                                "SHA1": "5264c5e2334a57d8669d31c67325a9b166e53bef",
                                "SHA256": "55a7640579a0e6c0bc2388063710e5cc3120b4df0840ec8a7af9a4bdc9235029"
                            },
                            "Permanenturl": "https://content.any.run/tasks/45b62ba4-931a-472b-b604-e43879a473fd/download/files/a6a071a2-c307-4d99-9a16-64640129584f",
                            "Size": 631,
                            "Threatlevel": "UNKNOWN",
                            "Type": "der"
                        }
                    },
                    "Country": "US",
                    "Host": "crl3.digicert.com",
                    "Httpcode": 200,
                    "IP": "93.184.220.29",
                    "Method": "GET",
                    "Port": 80,
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "Proxydetected": false,
                    "Reputation": "shared",
                    "Status": "RESPONDED",
                    "URL": "http://crl3.digicert.com/DigiCertGlobalRootCA.crl"
                }
            ],
            "ID": "45b62ba4-931a-472b-b604-e43879a473fd",
            "MD5": "02475e29bd0816b697cad5b55cdf897a",
            "MIME": "application/pdf",
            "Network": {
                "Connection": [
                    {
                        "ASN": "Zayo Bandwidth Inc",
                        "Country": "US",
                        "IP": "23.35.236.137",
                        "Port": 443,
                        "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                        "Protocol": "tcp",
                        "Reputation": "suspicious"
                    },
                    {
                        "ASN": "Akamai International B.V.",
                        "Country": null,
                        "IP": "2.18.233.74",
                        "Port": 443,
                        "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                        "Protocol": "tcp",
                        "Reputation": "whitelisted"
                    },
                    {
                        "ASN": "TRUE INTERNET Co.,Ltd.",
                        "Country": "US",
                        "IP": "23.48.23.34",
                        "Port": 443,
                        "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                        "Protocol": "tcp",
                        "Reputation": "suspicious"
                    },
                    {
                        "ASN": "Limelight Networks, Inc.",
                        "Country": "GB",
                        "IP": "95.140.236.128",
                        "Port": 80,
                        "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                        "Protocol": "tcp",
                        "Reputation": "malicious"
                    },
                    {
                        "ASN": "MCI Communications Services, Inc. d/b/a Verizon Business",
                        "Country": "US",
                        "IP": "93.184.220.29",
                        "Port": 80,
                        "Processuuid": null,
                        "Protocol": "tcp",
                        "Reputation": "whitelisted"
                    },
                    {
                        "ASN": "Amazon.com, Inc.",
                        "Country": "US",
                        "IP": "54.224.241.105",
                        "Port": 443,
                        "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                        "Protocol": "tcp",
                        "Reputation": "unknown"
                    },
                    {
                        "ASN": "MCI Communications Services, Inc. d/b/a Verizon Business",
                        "Country": "US",
                        "IP": "93.184.220.29",
                        "Port": 80,
                        "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                        "Protocol": "tcp",
                        "Reputation": "whitelisted"
                    },
                    {
                        "ASN": "Akamai International B.V.",
                        "Country": null,
                        "IP": "2.18.233.74",
                        "Port": 443,
                        "Processuuid": null,
                        "Protocol": "tcp",
                        "Reputation": "whitelisted"
                    },
                    {
                        "ASN": "TRUE INTERNET Co.,Ltd.",
                        "Country": "US",
                        "IP": "23.48.23.54",
                        "Port": 443,
                        "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                        "Protocol": "tcp",
                        "Reputation": "suspicious"
                    },
                    {
                        "ASN": "Amazon.com, Inc.",
                        "Country": "US",
                        "IP": "34.237.241.83",
                        "Port": 443,
                        "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                        "Protocol": "tcp",
                        "Reputation": "unknown"
                    },
                    {
                        "ASN": "TRUE INTERNET Co.,Ltd.",
                        "Country": "US",
                        "IP": "23.48.23.39",
                        "Port": 443,
                        "Processuuid": null,
                        "Protocol": "tcp",
                        "Reputation": "suspicious"
                    },
                    {
                        "ASN": "TRUE INTERNET Co.,Ltd.",
                        "Country": "US",
                        "IP": "23.48.23.39",
                        "Port": 443,
                        "Processuuid": "00cdebb4-cbb8-4078-ae10-a250f33f435d",
                        "Protocol": "tcp",
                        "Reputation": "suspicious"
                    }
                ],
                "Dnsrequest": [
                    {
                        "Domain": "geo2.adobe.com",
                        "IP": [
                            "23.35.236.137"
                        ],
                        "Reputation": "whitelisted"
                    },
                    {
                        "Domain": "armmf.adobe.com",
                        "IP": [
                            "2.18.233.74"
                        ],
                        "Reputation": "whitelisted"
                    },
                    {
                        "Domain": "acroipm2.adobe.com",
                        "IP": [
                            "23.48.23.34",
                            "23.48.23.54"
                        ],
                        "Reputation": "whitelisted"
                    },
                    {
                        "Domain": "ctldl.windowsupdate.com",
                        "IP": [
                            "95.140.236.128",
                            "95.140.236.0"
                        ],
                        "Reputation": "whitelisted"
                    },
                    {
                        "Domain": "p13n.adobe.io",
                        "IP": [
                            "54.224.241.105",
                            "34.237.241.83",
                            "18.213.11.84",
                            "50.16.47.176"
                        ],
                        "Reputation": "whitelisted"
                    },
                    {
                        "Domain": "ocsp.digicert.com",
                        "IP": [
                            "93.184.220.29"
                        ],
                        "Reputation": "shared"
                    },
                    {
                        "Domain": "crl3.digicert.com",
                        "IP": [
                            "93.184.220.29"
                        ],
                        "Reputation": "shared"
                    },
                    {
                        "Domain": "ardownload3.adobe.com",
                        "IP": [
                            "23.48.23.39",
                            "23.48.23.25"
                        ],
                        "Reputation": "whitelisted"
                    }
                ],
                "Httprequest": [
                    {
                        "Body": {
                            "Response": {
                                "Hash": {
                                    "MD5": "f7dcb24540769805e5bb30d193944dce",
                                    "SHA1": "e26c583c562293356794937d9e2e6155d15449ee",
                                    "SHA256": "6b88c6ac55bbd6fea0ebe5a760d1ad2cfce251c59d0151a1400701cb927e36ea"
                                },
                                "Permanenturl": "https://content.any.run/tasks/45b62ba4-931a-472b-b604-e43879a473fd/download/files/a72b74e1-8c52-461f-8879-b9329e0e07e2",
                                "Size": 4817,
                                "Threatlevel": "MID",
                                "Type": "compressed"
                            }
                        },
                        "Country": "GB",
                        "Host": "ctldl.windowsupdate.com",
                        "Httpcode": 200,
                        "IP": "95.140.236.128",
                        "Method": "GET",
                        "Port": 80,
                        "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                        "Proxydetected": false,
                        "Reputation": "whitelisted",
                        "Status": "RESPONDED",
                        "URL": "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?f54c0a0f62519d56"
                    },
                    {
                        "Body": {
                            "Response": {
                                "Hash": {
                                    "MD5": "7515e21f59ff1aadff6f6a1a0d105c2b",
                                    "SHA1": "5264c5e2334a57d8669d31c67325a9b166e53bef",
                                    "SHA256": "55a7640579a0e6c0bc2388063710e5cc3120b4df0840ec8a7af9a4bdc9235029"
                                },
                                "Permanenturl": "https://content.any.run/tasks/45b62ba4-931a-472b-b604-e43879a473fd/download/files/a6a071a2-c307-4d99-9a16-64640129584f",
                                "Size": 631,
                                "Threatlevel": "UNKNOWN",
                                "Type": "der"
                            }
                        },
                        "Country": "US",
                        "Host": "crl3.digicert.com",
                        "Httpcode": 200,
                        "IP": "93.184.220.29",
                        "Method": "GET",
                        "Port": 80,
                        "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                        "Proxydetected": false,
                        "Reputation": "shared",
                        "Status": "RESPONDED",
                        "URL": "http://crl3.digicert.com/DigiCertGlobalRootCA.crl"
                    }
                ],
                "Threat": [
                    {
                        "Class": "Potentially Bad Traffic",
                        "Dstip": "local",
                        "Dstport": 55801,
                        "Message": "ET INFO TLS Handshake Failure",
                        "Processuuid": null,
                        "Srcip": "23.48.23.39",
                        "Srcport": 443
                    }
                ]
            },
            "Os": "Windows 7 Professional Service Pack 1 (build: 7601, 32 bit)",
            "Process": [
                {
                    "Cmd": "",
                    "Exitcode": null,
                    "Filename": "[System Process]",
                    "Integritylevel": "UNKNOWN",
                    "Mainprocess": false,
                    "PID": 0,
                    "PPID": 0,
                    "Path": "[System Process]",
                    "Processuuid": "375da1b2-fd25-4328-a2dd-6d4d7fb44396",
                    "User": "",
                    "Version": {
                        "Company": "",
                        "Description": "",
                        "Version": ""
                    }
                },
                {
                    "Cmd": "",
                    "Exitcode": null,
                    "Filename": "System",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 4,
                    "PPID": 0,
                    "Path": "System",
                    "Processuuid": "a271b969-ce69-49b0-838f-0356818625d0",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "",
                        "Description": "",
                        "Version": ""
                    }
                },
                {
                    "Cmd": "\SystemRoot\System32\smss.exe",
                    "Exitcode": null,
                    "Filename": "smss.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 260,
                    "PPID": 4,
                    "Path": "\SystemRoot\System32\smss.exe",
                    "Processuuid": "9a0ca621-1717-43e1-915a-4fe4d8f6942e",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "",
                        "Description": "",
                        "Version": ""
                    }
                },
                {
                    "Cmd": "%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,12288,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16",
                    "Exitcode": null,
                    "Filename": "csrss.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 340,
                    "PPID": 320,
                    "Path": "C:\Windows\system32\csrss.exe",
                    "Processuuid": "0952f427-a077-4cc6-9355-0b08cef93dc0",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Client Server Runtime Process",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "wininit.exe",
                    "Exitcode": null,
                    "Filename": "wininit.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 376,
                    "PPID": 320,
                    "Path": "C:\Windows\system32\wininit.exe",
                    "Processuuid": "f1749785-eeea-498b-9ae3-0aa0eaec409c",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Windows Start-Up Application",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,12288,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16",
                    "Exitcode": null,
                    "Filename": "csrss.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 384,
                    "PPID": 368,
                    "Path": "C:\Windows\system32\csrss.exe",
                    "Processuuid": "ac42625e-c10a-4f4a-953d-71caa933dc92",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Client Server Runtime Process",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "winlogon.exe",
                    "Exitcode": null,
                    "Filename": "winlogon.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 432,
                    "PPID": 368,
                    "Path": "C:\Windows\system32\winlogon.exe",
                    "Processuuid": "dadff15c-8866-4534-93b3-2524c93986cc",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Windows Logon Application",
                        "Version": "6.1.7601.17514 (win7sp1_rtm.101119-1850)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\services.exe",
                    "Exitcode": null,
                    "Filename": "services.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 468,
                    "PPID": 376,
                    "Path": "C:\Windows\system32\services.exe",
                    "Processuuid": "b074db04-9698-41f7-a2ed-3d930d38a4e8",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Services and Controller app",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\lsass.exe",
                    "Exitcode": null,
                    "Filename": "lsass.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 484,
                    "PPID": 376,
                    "Path": "C:\Windows\system32\lsass.exe",
                    "Processuuid": "b7dca6aa-04a4-4080-9e3c-f2d07ae2b848",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Local Security Authority Process",
                        "Version": "6.1.7601.24545 (win7sp1_ldr_escrow.200102-1707)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\lsm.exe",
                    "Exitcode": null,
                    "Filename": "lsm.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 492,
                    "PPID": 376,
                    "Path": "C:\Windows\system32\lsm.exe",
                    "Processuuid": "1b88a259-2c6a-4fa8-acbf-02289d497622",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Local Session Manager Service",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\svchost.exe -k DcomLaunch",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 592,
                    "PPID": 468,
                    "Path": "C:\Windows\system32\svchost.exe",
                    "Processuuid": "f93b01ef-9719-480c-95b7-642d5d551b1b",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\svchost.exe -k RPCSS",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 672,
                    "PPID": 468,
                    "Path": "C:\Windows\system32\svchost.exe",
                    "Processuuid": "c3cf8aac-4921-44b4-951d-5d8a1db7b617",
                    "User": "NETWORK SERVICE",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 760,
                    "PPID": 468,
                    "Path": "C:\Windows\System32\svchost.exe",
                    "Processuuid": "a8a5af5a-ec52-47d8-9655-199f14ea5c45",
                    "User": "LOCAL SERVICE",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 796,
                    "PPID": 468,
                    "Path": "C:\Windows\System32\svchost.exe",
                    "Processuuid": "270bc634-7c40-4a22-8119-a5bbdfb22422",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\svchost.exe -k LocalService",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 824,
                    "PPID": 468,
                    "Path": "C:\Windows\system32\svchost.exe",
                    "Processuuid": "92be8359-8941-4eff-8dea-f0c816cff7eb",
                    "User": "LOCAL SERVICE",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\svchost.exe -k netsvcs",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 860,
                    "PPID": 468,
                    "Path": "C:\Windows\system32\svchost.exe",
                    "Processuuid": "a4e149c7-1d4e-4de9-956b-058ee9cf394d",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\svchost.exe -k GPSvcGroup",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 968,
                    "PPID": 468,
                    "Path": "C:\Windows\system32\svchost.exe",
                    "Processuuid": "be778e77-cf65-4405-9ad2-c0e5ea36e972",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\svchost.exe -k NetworkService",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 1088,
                    "PPID": 468,
                    "Path": "C:\Windows\system32\svchost.exe",
                    "Processuuid": "e0eff788-3254-4665-8fc6-487f4d789563",
                    "User": "NETWORK SERVICE",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\System32\spoolsv.exe",
                    "Exitcode": null,
                    "Filename": "spoolsv.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 1236,
                    "PPID": 468,
                    "Path": "C:\Windows\System32\spoolsv.exe",
                    "Processuuid": "c76927c0-29c0-402a-9a9a-ebb1191b2801",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Spooler SubSystem App",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 1264,
                    "PPID": 468,
                    "Path": "C:\Windows\system32\svchost.exe",
                    "Processuuid": "ece1b0ec-252e-496b-a5f6-08c661b0e333",
                    "User": "LOCAL SERVICE",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\System32\svchost.exe -k utcsvc",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 1352,
                    "PPID": 468,
                    "Path": "C:\Windows\System32\svchost.exe",
                    "Processuuid": "2e86deea-86d0-48f9-8b59-70228ce98f12",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Common Files\Microsoft Shared\IME14\SHARED\IMEDICTUPDATE.EXE\"",
                    "Exitcode": null,
                    "Filename": "IMEDICTUPDATE.EXE",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 1424,
                    "PPID": 468,
                    "Path": "C:\Program Files\Common Files\Microsoft Shared\IME14\SHARED\IMEDICTUPDATE.EXE",
                    "Processuuid": "9550f782-1f7c-4dfe-86c7-b5bf6eb6a945",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Microsoft Office IME 2010",
                        "Version": "14.0.4734.1000"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\svchost.exe -k NetworkServiceNetworkRestricted",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 1936,
                    "PPID": 468,
                    "Path": "C:\Windows\system32\svchost.exe",
                    "Processuuid": "82765043-e885-448e-8982-e42438ca0a52",
                    "User": "NETWORK SERVICE",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "\"taskhost.exe\"",
                    "Exitcode": null,
                    "Filename": "taskhost.exe",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": false,
                    "PID": 320,
                    "PPID": 468,
                    "Path": "C:\Windows\system32\taskhost.exe",
                    "Processuuid": "0dcb27a1-d908-4b0f-a25f-917cd8df6c1e",
                    "User": "admin",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Tasks",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "taskeng.exe {BB154EF7-42D4-42F2-B57F-9CBB745DE3E3}",
                    "Exitcode": null,
                    "Filename": "taskeng.exe",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": false,
                    "PID": 288,
                    "PPID": 860,
                    "Path": "C:\Windows\system32\taskeng.exe",
                    "Processuuid": "d2a105e9-13a6-4964-81e6-070af81b5dec",
                    "User": "admin",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Task Scheduler Engine",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "\"C:\Windows\system32\Dwm.exe\"",
                    "Exitcode": null,
                    "Filename": "Dwm.exe",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": false,
                    "PID": 936,
                    "PPID": 796,
                    "Path": "C:\Windows\system32\Dwm.exe",
                    "Processuuid": "bbcd1df9-3e48-4e58-9751-b61e7c472815",
                    "User": "admin",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Desktop Window Manager",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\Explorer.EXE",
                    "Exitcode": null,
                    "Filename": "Explorer.EXE",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": false,
                    "PID": 1464,
                    "PPID": 820,
                    "Path": "C:\Windows\Explorer.EXE",
                    "Processuuid": "4966dad3-7df9-4800-87e1-1ae4b32b93a2",
                    "User": "admin",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Windows Explorer",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\System32\ctfmon.exe ",
                    "Exitcode": null,
                    "Filename": "ctfmon.exe",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": false,
                    "PID": 1396,
                    "PPID": 288,
                    "Path": "C:\Windows\System32\ctfmon.exe",
                    "Processuuid": "6307f043-d99d-44e7-a6d7-1e11eea3be3d",
                    "User": "admin",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "CTF Loader",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\SearchIndexer.exe /Embedding",
                    "Exitcode": null,
                    "Filename": "SearchIndexer.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 2544,
                    "PPID": 468,
                    "Path": "C:\Windows\system32\SearchIndexer.exe",
                    "Processuuid": "be7286ed-ef2f-441e-acca-9accb8f377a4",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Microsoft Windows Search Indexer",
                        "Version": "7.00.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "\"C:\Windows\system32\SearchProtocolHost.exe\" Global\UsGthrFltPipeMssGthrPipe3_ Global\UsGthrCtrlFltPipeMssGthrPipe3 1 -2147483646 \"Software\Microsoft\Windows Search\" \"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)\" \"C:\ProgramData\Microsoft\Search\Data\Temp\usgthrsvc\" \"DownLevelDaemon\" ",
                    "Exitcode": null,
                    "Filename": "SearchProtocolHost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 3452,
                    "PPID": 2544,
                    "Path": "C:\Windows\system32\SearchProtocolHost.exe",
                    "Processuuid": "3d0967dc-e2e6-4339-a619-a084045bbbf1",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Microsoft Windows Search Protocol Host",
                        "Version": "7.00.7601.24542 (win7sp1_ldr_escrow.191209-2211)"
                    }
                },
                {
                    "Cmd": "\"C:\Windows\system32\SearchFilterHost.exe\" 0 520 524 532 65536 528 ",
                    "Exitcode": null,
                    "Filename": "SearchFilterHost.exe",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": false,
                    "PID": 3840,
                    "PPID": 2544,
                    "Path": "C:\Windows\system32\SearchFilterHost.exe",
                    "Processuuid": "9384891d-6ead-4179-bac6-3734cee1f6bb",
                    "User": "SYSTEM",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Microsoft Windows Search Filter Host",
                        "Version": "7.00.7601.24542 (win7sp1_ldr_escrow.191209-2211)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\DllHost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}",
                    "Exitcode": 0,
                    "Filename": "DllHost.exe",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": false,
                    "PID": 2872,
                    "PPID": 592,
                    "Path": "C:\Windows\system32\DllHost.exe",
                    "Processuuid": "93b6c7fc-1aef-4150-be36-b5930f55b85a",
                    "User": "admin",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "COM Surrogate",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\DllHost.exe /Processid:{F9717507-6651-4EDB-BFF7-AE615179BCCF}",
                    "Exitcode": 0,
                    "Filename": "DllHost.exe",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": false,
                    "PID": 2316,
                    "PPID": 592,
                    "Path": "C:\Windows\system32\DllHost.exe",
                    "Processuuid": "86c03f0a-b480-477e-a632-192ba22dac62",
                    "User": "admin",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "COM Surrogate",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\AUDIODG.EXE 0x6cc",
                    "Exitcode": null,
                    "Filename": "AUDIODG.EXE",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 3000,
                    "PPID": 760,
                    "Path": "C:\Windows\system32\AUDIODG.EXE",
                    "Processuuid": "9e9e24d6-751d-4019-b28b-46a44e9018ca",
                    "User": "LOCAL SERVICE",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Windows Audio Device Graph Isolation ",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation",
                    "Exitcode": null,
                    "Filename": "svchost.exe",
                    "Integritylevel": "SYSTEM",
                    "Mainprocess": false,
                    "PID": 3860,
                    "PPID": 468,
                    "Path": "C:\Windows\system32\svchost.exe",
                    "Processuuid": "fd7ffe77-7fc9-4ae2-8592-18f48d7e9752",
                    "User": "LOCAL SERVICE",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "Host Process for Windows Services",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "C:\Windows\system32\DllHost.exe /Processid:{F9717507-6651-4EDB-BFF7-AE615179BCCF}",
                    "Exitcode": null,
                    "Filename": "DllHost.exe",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": false,
                    "PID": 2588,
                    "PPID": 592,
                    "Path": "C:\Windows\system32\DllHost.exe",
                    "Processuuid": "f945261c-f8b9-44fa-8173-d859bdff9085",
                    "User": "admin",
                    "Version": {
                        "Company": "Microsoft Corporation",
                        "Description": "COM Surrogate",
                        "Version": "6.1.7600.16385 (win7_rtm.090713-1255)"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe\" \"C:\Users\admin\AppData\Local\Temp\test_file.pdf\"",
                    "Exitcode": null,
                    "Filename": "AcroRd32.exe",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": true,
                    "PID": 2040,
                    "PPID": 1464,
                    "Path": "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe",
                    "Processuuid": "ba71e993-8e77-4326-b400-0be440ba49f3",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Systems Incorporated",
                        "Description": "Adobe Acrobat Reader DC ",
                        "Version": "20.13.20064.405839"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe\" --type=renderer  \"C:\Users\admin\AppData\Local\Temp\test_file.pdf\"",
                    "Exitcode": null,
                    "Filename": "AcroRd32.exe",
                    "Integritylevel": "LOW",
                    "Mainprocess": false,
                    "PID": 1280,
                    "PPID": 2040,
                    "Path": "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe",
                    "Processuuid": "2e9fdeec-25c6-495c-8b04-35b5310b20b0",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Systems Incorporated",
                        "Description": "Adobe Acrobat Reader DC ",
                        "Version": "20.13.20064.405839"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe\" --backgroundcolor=16514043",
                    "Exitcode": null,
                    "Filename": "RdrCEF.exe",
                    "Integritylevel": "LOW",
                    "Mainprocess": false,
                    "PID": 3316,
                    "PPID": 2040,
                    "Path": "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe",
                    "Processuuid": "ef022081-dc28-4fab-87fc-0c9b3418bf1f",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Systems Incorporated",
                        "Description": "Adobe RdrCEF",
                        "Version": "20.13.20064.405839"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe\" --type=renderer --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --touch-events=enabled --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-gpu-compositing --lang=en-US --disable-pack-loading --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --log-severity=disable --product-version=\"ReaderServices/20.13.20064 Chrome/80.0.0.0\" --device-scale-factor=1 --num-raster-threads=2 --enable-main-frame-before-activation --service-request-channel-token=14024734510508519417 --renderer-client-id=2 --mojo-platform-channel-handle=1204 --allow-no-sandbox-job /prefetch:1",
                    "Exitcode": null,
                    "Filename": "RdrCEF.exe",
                    "Integritylevel": "LOW",
                    "Mainprocess": false,
                    "PID": 2128,
                    "PPID": 3316,
                    "Path": "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe",
                    "Processuuid": "cf2bf809-c2b6-48a2-a142-050254cd6458",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Systems Incorporated",
                        "Description": "Adobe RdrCEF",
                        "Version": "20.13.20064.405839"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe\" --type=gpu-process --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-pack-loading --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --log-severity=disable --product-version=\"ReaderServices/20.13.20064 Chrome/80.0.0.0\" --lang=en-US --gpu-preferences=KAAAAAAAAADgACAgAQAAAAAAAAAAAGAAAAAAABAAAAAIAAAAAAAAACgAAAAEAAAAIAAAAAAAAAAoAAAAAAAAADAAAAAAAAAAOAAAAAAAAAAQAAAAAAAAAAAAAAAFAAAAEAAAAAAAAAAAAAAABgAAABAAAAAAAAAAAQAAAAUAAAAQAAAAAAAAAAEAAAAGAAAA --use-gl=swiftshader-webgl --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --service-request-channel-token=12223321443149433680 --mojo-platform-channel-handle=1236 --allow-no-sandbox-job --ignored=\" --type=renderer \" /prefetch:2",
                    "Exitcode": 1,
                    "Filename": "RdrCEF.exe",
                    "Integritylevel": "LOW",
                    "Mainprocess": false,
                    "PID": 1180,
                    "PPID": 3316,
                    "Path": "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe",
                    "Processuuid": "dafd83d4-86bb-412e-8bec-be8ad78b79b7",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Systems Incorporated",
                        "Description": "Adobe RdrCEF",
                        "Version": "20.13.20064.405839"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe\" --type=gpu-process --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-pack-loading --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --log-severity=disable --product-version=\"ReaderServices/20.13.20064 Chrome/80.0.0.0\" --lang=en-US --gpu-preferences=KAAAAAAAAADgACAgAQAAAAAAAAAAAGAAAAAAABAAAAAIAAAAAAAAACgAAAAEAAAAIAAAAAAAAAAoAAAAAAAAADAAAAAAAAAAOAAAAAAAAAAQAAAAAAAAAAAAAAAFAAAAEAAAAAAAAAAAAAAABgAAABAAAAAAAAAAAQAAAAUAAAAQAAAAAAAAAAEAAAAGAAAA --use-gl=swiftshader-webgl --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --service-request-channel-token=12378439338200214857 --mojo-platform-channel-handle=1408 --allow-no-sandbox-job --ignored=\" --type=renderer \" /prefetch:2",
                    "Exitcode": 1,
                    "Filename": "RdrCEF.exe",
                    "Integritylevel": "LOW",
                    "Mainprocess": false,
                    "PID": 2860,
                    "PPID": 3316,
                    "Path": "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe",
                    "Processuuid": "713c2780-51cc-4e0e-bc0e-e9d38f5184ac",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Systems Incorporated",
                        "Description": "Adobe RdrCEF",
                        "Version": "20.13.20064.405839"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe\" --type=gpu-process --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-pack-loading --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --log-severity=disable --product-version=\"ReaderServices/20.13.20064 Chrome/80.0.0.0\" --lang=en-US --gpu-preferences=KAAAAAAAAADgACAgAQAAAAAAAAAAAGAAAAAAABAAAAAIAAAAAAAAACgAAAAEAAAAIAAAAAAAAAAoAAAAAAAAADAAAAAAAAAAOAAAAAAAAAAQAAAAAAAAAAAAAAAFAAAAEAAAAAAAAAAAAAAABgAAABAAAAAAAAAAAQAAAAUAAAAQAAAAAAAAAAEAAAAGAAAA --use-gl=swiftshader-webgl --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --service-request-channel-token=13732513110551940315 --mojo-platform-channel-handle=1396 --allow-no-sandbox-job --ignored=\" --type=renderer \" /prefetch:2",
                    "Exitcode": 1,
                    "Filename": "RdrCEF.exe",
                    "Integritylevel": "LOW",
                    "Mainprocess": false,
                    "PID": 2108,
                    "PPID": 3316,
                    "Path": "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe",
                    "Processuuid": "40abe4ec-fef1-4fa1-b1f0-7a305e09f4aa",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Systems Incorporated",
                        "Description": "Adobe RdrCEF",
                        "Version": "20.13.20064.405839"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe\" --type=renderer --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --touch-events=enabled --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-gpu-compositing --lang=en-US --disable-pack-loading --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --log-severity=disable --product-version=\"ReaderServices/20.13.20064 Chrome/80.0.0.0\" --device-scale-factor=1 --num-raster-threads=2 --enable-main-frame-before-activation --service-request-channel-token=4847431092444551383 --renderer-client-id=6 --mojo-platform-channel-handle=1616 --allow-no-sandbox-job /prefetch:1",
                    "Exitcode": null,
                    "Filename": "RdrCEF.exe",
                    "Integritylevel": "LOW",
                    "Mainprocess": false,
                    "PID": 920,
                    "PPID": 3316,
                    "Path": "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe",
                    "Processuuid": "4c084eba-2541-46a3-833d-513c41115c5f",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Systems Incorporated",
                        "Description": "Adobe RdrCEF",
                        "Version": "20.13.20064.405839"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe\" --type=renderer --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --touch-events=enabled --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-gpu-compositing --lang=en-US --disable-pack-loading --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --log-severity=disable --product-version=\"ReaderServices/20.13.20064 Chrome/80.0.0.0\" --device-scale-factor=1 --num-raster-threads=2 --enable-main-frame-before-activation --service-request-channel-token=16593724968950981413 --renderer-client-id=7 --mojo-platform-channel-handle=1536 --allow-no-sandbox-job /prefetch:1",
                    "Exitcode": null,
                    "Filename": "RdrCEF.exe",
                    "Integritylevel": "LOW",
                    "Mainprocess": false,
                    "PID": 3424,
                    "PPID": 3316,
                    "Path": "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe",
                    "Processuuid": "60116489-5a40-4dd7-8c3c-8091346b6299",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Systems Incorporated",
                        "Description": "Adobe RdrCEF",
                        "Version": "20.13.20064.405839"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe\" --type=renderer --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --touch-events=enabled --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-gpu-compositing --lang=en-US --disable-pack-loading --log-file=\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\debug.log\" --log-severity=disable --product-version=\"ReaderServices/20.13.20064 Chrome/80.0.0.0\" --device-scale-factor=1 --num-raster-threads=2 --enable-main-frame-before-activation --service-request-channel-token=6562753338979179477 --renderer-client-id=8 --mojo-platform-channel-handle=1836 --allow-no-sandbox-job /prefetch:1",
                    "Exitcode": null,
                    "Filename": "RdrCEF.exe",
                    "Integritylevel": "LOW",
                    "Mainprocess": false,
                    "PID": 240,
                    "PPID": 3316,
                    "Path": "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe",
                    "Processuuid": "2cab4f07-8ae6-4560-9308-3800d2be988a",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Systems Incorporated",
                        "Description": "Adobe RdrCEF",
                        "Version": "20.13.20064.405839"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Common Files\Adobe\ARM\1.0\AdobeARM.exe\" /PRODUCT:Reader /VERSION:20.0 /MODE:3",
                    "Exitcode": null,
                    "Filename": "AdobeARM.exe",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": false,
                    "PID": 2124,
                    "PPID": 2040,
                    "Path": "C:\Program Files\Common Files\Adobe\ARM\1.0\AdobeARM.exe",
                    "Processuuid": "00cdebb4-cbb8-4078-ae10-a250f33f435d",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Inc.",
                        "Description": "Adobe Reader and Acrobat Manager",
                        "Version": "1.824.39.9311"
                    }
                },
                {
                    "Cmd": "\"C:\Program Files\Adobe\Acrobat Reader DC\Reader\Reader_sl.exe\" ",
                    "Exitcode": 0,
                    "Filename": "Reader_sl.exe",
                    "Integritylevel": "MEDIUM",
                    "Mainprocess": false,
                    "PID": 3532,
                    "PPID": 2124,
                    "Path": "C:\Program Files\Adobe\Acrobat Reader DC\Reader\Reader_sl.exe",
                    "Processuuid": "b9122008-82f2-4fa4-a128-956e24ae17ce",
                    "User": "admin",
                    "Version": {
                        "Company": "Adobe Systems Incorporated",
                        "Description": "Adobe Acrobat SpeedLauncher",
                        "Version": "20.12.20041.394260"
                    }
                }
            ],
            "Reports": {
                "HTML": "https://api.any.run/report/45b62ba4-931a-472b-b604-e43879a473fd/summary/html",
                "IOC": "https://api.any.run/report/45b62ba4-931a-472b-b604-e43879a473fd/ioc/json",
                "MISP": "https://api.any.run/report/45b62ba4-931a-472b-b604-e43879a473fd/summary/misp",
                "graph": "https://content.any.run/tasks/45b62ba4-931a-472b-b604-e43879a473fd/graph"
            },
            "SHA1": "44e4ee171347fb954938ea87400c5bef5ec8be8b",
            "SHA256": "c558877e6ad6de172b8cc10461a12905c6b98d6265e650b3650b35ff73a63b03",
            "SSDeep": "768:ttu1HAfRvxuliB5IXqwdbOiNf6vP47BL1Gq:tiUVMXqcbFfsA7pMq",
            "Status": "done",
            "Threat": [
                {
                    "Class": "Potentially Bad Traffic",
                    "Dstip": "local",
                    "Dstport": 55801,
                    "Message": "ET INFO TLS Handshake Failure",
                    "Processuuid": null,
                    "Srcip": "23.48.23.39",
                    "Srcport": 443
                }
            ],
            "Verdict": "No threats detected"
        }
    },
    "AttackPattern": {
        "Description": null,
        "FirstSeenBySource": null,
        "KillChainPhases": null,
        "MITREID": "T1106",
        "OperatingSystemRefs": null,
        "Publications": null,
        "STIXID": null,
        "Tags": null,
        "Value": "Execution through API"
    },
    "DBotScore": [
        {
            "Indicator": "c558877e6ad6de172b8cc10461a12905c6b98d6265e650b3650b35ff73a63b03",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 1,
            "Type": "file",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "23.35.236.137",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "2.18.233.74",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "23.48.23.34",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "95.140.236.128",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "93.184.220.29",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 1,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "23.48.23.54",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "23.48.23.39",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "geo2.adobe.com",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 1,
            "Type": "domain",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "armmf.adobe.com",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 1,
            "Type": "domain",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "acroipm2.adobe.com",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 1,
            "Type": "domain",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "ctldl.windowsupdate.com",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 1,
            "Type": "domain",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "95.140.236.0",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "p13n.adobe.io",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 1,
            "Type": "domain",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "54.224.241.105",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "34.237.241.83",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "18.213.11.84",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "50.16.47.176",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "ardownload3.adobe.com",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 1,
            "Type": "domain",
            "Vendor": "ANYRUN"
        },
        {
            "Indicator": "23.48.23.25",
            "Reliability": "A+ - 3rd party enrichment",
            "Score": 0,
            "Type": "ip",
            "Vendor": "ANYRUN"
        }
    ],
    "Domain": [
        {
            "Name": "geo2.adobe.com"
        },
        {
            "Name": "armmf.adobe.com"
        },
        {
            "Name": "acroipm2.adobe.com"
        },
        {
            "Name": "ctldl.windowsupdate.com"
        },
        {
            "Name": "p13n.adobe.io"
        },
        {
            "Name": "ardownload3.adobe.com"
        }
    ],
    "File": {
        "Hashes": [
            {
                "type": "MD5",
                "value": "02475e29bd0816b697cad5b55cdf897a"
            },
            {
                "type": "SHA1",
                "value": "44e4ee171347fb954938ea87400c5bef5ec8be8b"
            },
            {
                "type": "SHA256",
                "value": "c558877e6ad6de172b8cc10461a12905c6b98d6265e650b3650b35ff73a63b03"
            }
        ],
        "MD5": "02475e29bd0816b697cad5b55cdf897a",
        "SHA1": "44e4ee171347fb954938ea87400c5bef5ec8be8b",
        "SHA256": "c558877e6ad6de172b8cc10461a12905c6b98d6265e650b3650b35ff73a63b03",
        "Type": "PDF document, version 1.3"
    },
    "IP": [
        {
            "ASN": "Zayo Bandwidth Inc",
            "Address": "23.35.236.137",
            "Geo": {
                "Country": "US"
            },
            "Port": 443,
            "Relationships": [
                {
                    "EntityA": "geo2.adobe.com",
                    "EntityAType": "Domain",
                    "EntityB": "23.35.236.137",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        },
        {
            "ASN": "Akamai International B.V.",
            "Address": "2.18.233.74",
            "Port": 443,
            "Relationships": [
                {
                    "EntityA": "armmf.adobe.com",
                    "EntityAType": "Domain",
                    "EntityB": "2.18.233.74",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        },
        {
            "ASN": "TRUE INTERNET Co.,Ltd.",
            "Address": "23.48.23.34",
            "Geo": {
                "Country": "US"
            },
            "Port": 443,
            "Relationships": [
                {
                    "EntityA": "acroipm2.adobe.com",
                    "EntityAType": "Domain",
                    "EntityB": "23.48.23.34",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        },
        {
            "ASN": "Limelight Networks, Inc.",
            "Address": "95.140.236.128",
            "Geo": {
                "Country": "GB"
            },
            "Malicious": {
                "Description": null,
                "Vendor": "ANYRUN"
            },
            "Port": 80,
            "Relationships": [
                {
                    "EntityA": "ctldl.windowsupdate.com",
                    "EntityAType": "Domain",
                    "EntityB": "95.140.236.128",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        },
        {
            "ASN": "MCI Communications Services, Inc. d/b/a Verizon Business",
            "Address": "93.184.220.29",
            "Geo": {
                "Country": "US"
            },
            "Port": 80,
            "Relationships": [
                {
                    "EntityA": "c558877e6ad6de172b8cc10461a12905c6b98d6265e650b3650b35ff73a63b03",
                    "EntityAType": "File",
                    "EntityB": "93.184.220.29",
                    "EntityBType": "IP",
                    "Relationship": "communicated-with"
                }
            ]
        },
        {
            "ASN": "TRUE INTERNET Co.,Ltd.",
            "Address": "23.48.23.54",
            "Geo": {
                "Country": "US"
            },
            "Port": 443,
            "Relationships": [
                {
                    "EntityA": "acroipm2.adobe.com",
                    "EntityAType": "Domain",
                    "EntityB": "23.48.23.54",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        },
        {
            "ASN": "TRUE INTERNET Co.,Ltd.",
            "Address": "23.48.23.39",
            "Geo": {
                "Country": "US"
            },
            "Port": 443,
            "Relationships": [
                {
                    "EntityA": "ardownload3.adobe.com",
                    "EntityAType": "Domain",
                    "EntityB": "23.48.23.39",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        },
        {
            "Address": "95.140.236.0",
            "Relationships": [
                {
                    "EntityA": "ctldl.windowsupdate.com",
                    "EntityAType": "Domain",
                    "EntityB": "95.140.236.0",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        },
        {
            "Address": "54.224.241.105",
            "Relationships": [
                {
                    "EntityA": "p13n.adobe.io",
                    "EntityAType": "Domain",
                    "EntityB": "54.224.241.105",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        },
        {
            "Address": "34.237.241.83",
            "Relationships": [
                {
                    "EntityA": "p13n.adobe.io",
                    "EntityAType": "Domain",
                    "EntityB": "34.237.241.83",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        },
        {
            "Address": "18.213.11.84",
            "Relationships": [
                {
                    "EntityA": "p13n.adobe.io",
                    "EntityAType": "Domain",
                    "EntityB": "18.213.11.84",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        },
        {
            "Address": "50.16.47.176",
            "Relationships": [
                {
                    "EntityA": "p13n.adobe.io",
                    "EntityAType": "Domain",
                    "EntityB": "50.16.47.176",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        },
        {
            "Address": "23.48.23.25",
            "Relationships": [
                {
                    "EntityA": "ardownload3.adobe.com",
                    "EntityAType": "Domain",
                    "EntityB": "23.48.23.25",
                    "EntityBType": "IP",
                    "Relationship": "resolves-to"
                }
            ]
        }
    ],
    "InfoFile": [
        {
            "EntryID": "5413@26c80993-f6f1-476d-89fa-6acd574d0ab2",
            "Extension": "png",
            "Info": "image/png",
            "Name": "screenshot0.png",
            "Size": 42650,
            "Type": "JPEG image data, baseline, precision 8, 1280x720, components 3"
        },
        {
            "EntryID": "5414@26c80993-f6f1-476d-89fa-6acd574d0ab2",
            "Extension": "png",
            "Info": "image/png",
            "Name": "screenshot1.png",
            "Size": 50017,
            "Type": "JPEG image data, baseline, precision 8, 1280x720, components 3"
        }
    ]
}
```

#### Human Readable Output

### Report for Task 45b62ba4-931a-472b-b604-e43879a473fd

|Analysisdate|Behavior|Connection|Dnsrequest|Fileinfo|Httprequest|ID|MD5|MIME|Network|Os|Process|Reports|SHA1|SHA256|SSDeep|Status|Threat|Verdict|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2022-08-02T11:23:42.846Z | Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, Category: Environment, Action: Reads the computer name, Threatlevel: 0,<br>Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, Category: Environment, Action: Searches for installed software, Threatlevel: 0,<br>Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 0,<br>Processuuid: dafd83d4-86bb-412e-8bec-be8ad78b79b7, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 0,<br>Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 0,<br>Processuuid: 2e9fdeec-25c6-495c-8b04-35b5310b20b0, Category: Environment, Action: Reads CPU info, Threatlevel: 0,<br>Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, Category: Suspicious actions, Action: Application launched itself, Threatlevel: 0,<br>Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, Category: Suspicious actions, Action: Application launched itself, Threatlevel: 0,<br>Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, Category: Environment, Action: Reads the computer name, Threatlevel: 0,<br>Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, Category: General, Action: Reads settings of System Certificates, Threatlevel: 0,<br>Processuuid: 40abe4ec-fef1-4fa1-b1f0-7a305e09f4aa, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 0,<br>Processuuid: 2e9fdeec-25c6-495c-8b04-35b5310b20b0, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 0,<br>Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, Category: General, Action: Checks Windows Trust Settings, Threatlevel: 0,<br>Processuuid: cf2bf809-c2b6-48a2-a142-050254cd6458, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 0,<br>Processuuid: 713c2780-51cc-4e0e-bc0e-e9d38f5184ac, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 0,<br>Processuuid: 2e9fdeec-25c6-495c-8b04-35b5310b20b0, Category: Environment, Action: Searches for installed software, Threatlevel: 0,<br>Processuuid: 2e9fdeec-25c6-495c-8b04-35b5310b20b0, Category: Environment, Action: Reads the computer name, Threatlevel: 0,<br>Processuuid: 60116489-5a40-4dd7-8c3c-8091346b6299, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 0,<br>Processuuid: 4c084eba-2541-46a3-833d-513c41115c5f, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 0,<br>Processuuid: 2cab4f07-8ae6-4560-9308-3800d2be988a, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 0,<br>Processuuid: 00cdebb4-cbb8-4078-ae10-a250f33f435d, Category: Environment, Action: Reads the computer name, Threatlevel: 1,<br>Processuuid: 00cdebb4-cbb8-4078-ae10-a250f33f435d, Category: General, Action: Checks Windows Trust Settings, Threatlevel: 0,<br>Processuuid: b9122008-82f2-4fa4-a128-956e24ae17ce, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 1,<br>Processuuid: 00cdebb4-cbb8-4078-ae10-a250f33f435d, Category: General, Action: Reads settings of System Certificates, Threatlevel: 0,<br>Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, Category: General, Action: Reads settings of System Certificates, Threatlevel: 0,<br>Processuuid: 00cdebb4-cbb8-4078-ae10-a250f33f435d, Category: System destruction, Action: Creates files in the program directory, Threatlevel: 1,<br>Processuuid: 00cdebb4-cbb8-4078-ae10-a250f33f435d, Category: Unusual activities, Action: Checks supported languages, Threatlevel: 1 | Reputation: suspicious, Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, ASN: Zayo Bandwidth Inc, Country: US, Protocol: tcp, Port: 443, IP: 23.35.236.137,<br>Reputation: whitelisted, Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, ASN: Akamai International B.V., Country: null, Protocol: tcp, Port: 443, IP: 2.18.233.74,<br>Reputation: suspicious, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, ASN: TRUE INTERNET Co.,Ltd., Country: US, Protocol: tcp, Port: 443, IP: 23.48.23.34,<br>Reputation: malicious, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, ASN: Limelight Networks, Inc., Country: GB, Protocol: tcp, Port: 80, IP: 95.140.236.128,<br>Reputation: whitelisted, Processuuid: null, ASN: MCI Communications Services, Inc. d/b/a Verizon Business, Country: US, Protocol: tcp, Port: 80, IP: 93.184.220.29,<br>Reputation: unknown, Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, ASN: Amazon.com, Inc., Country: US, Protocol: tcp, Port: 443, IP: 54.224.241.105,<br>Reputation: whitelisted, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, ASN: MCI Communications Services, Inc. d/b/a Verizon Business, Country: US, Protocol: tcp, Port: 80, IP: 93.184.220.29,<br>Reputation: whitelisted, Processuuid: null, ASN: Akamai International B.V., Country: null, Protocol: tcp, Port: 443, IP: 2.18.233.74,<br>Reputation: suspicious, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, ASN: TRUE INTERNET Co.,Ltd., Country: US, Protocol: tcp, Port: 443, IP: 23.48.23.54,<br>Reputation: unknown, Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, ASN: Amazon.com, Inc., Country: US, Protocol: tcp, Port: 443, IP: 34.237.241.83,<br>Reputation: suspicious, Processuuid: null, ASN: TRUE INTERNET Co.,Ltd., Country: US, Protocol: tcp, Port: 443, IP: 23.48.23.39,<br>Reputation: suspicious, Processuuid: 00cdebb4-cbb8-4078-ae10-a250f33f435d, ASN: TRUE INTERNET Co.,Ltd., Country: US, Protocol: tcp, Port: 443, IP: 23.48.23.39 | Reputation: whitelisted, IP: [23.35.236.137], Domain: geo2.adobe.com,<br>Reputation: whitelisted, IP: [2.18.233.74], Domain: armmf.adobe.com,<br>Reputation: whitelisted, IP: [23.48.23.34, 23.48.23.54], Domain: acroipm2.adobe.com,<br>Reputation: whitelisted, IP: [95.140.236.128, 95.140.236.0], Domain: ctldl.windowsupdate.com,<br>Reputation: whitelisted, IP: [54.224.241.105, 34.237.241.83, 18.213.11.84, 50.16.47.176], Domain: p13n.adobe.io,<br>Reputation: shared, IP: [93.184.220.29], Domain: ocsp.digicert.com,<br>Reputation: shared, IP: [93.184.220.29], Domain: crl3.digicert.com,<br>Reputation: whitelisted, IP: [23.48.23.39, 23.48.23.25], Domain: ardownload3.adobe.com | PDF document, version 1.3 | Reputation: whitelisted, Country: GB, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, Body: {Response: {Size: 4817, Type: compressed, Threatlevel: MID, Permanenturl: https://content.any.run/tasks/45b62ba4-931a-472b-b604-e43879a473fd/download/files/a72b74e1-8c52-461f-8879-b9329e0e07e2, Hash: {MD5: f7dcb24540769805e5bb30d193944dce, SHA1: e26c583c562293356794937d9e2e6155d15449ee, SHA256: 6b88c6ac55bbd6fea0ebe5a760d1ad2cfce251c59d0151a1400701cb927e36ea}}}, Httpcode: 200, Status: RESPONDED, Proxydetected: false, Port: 80, IP: 95.140.236.128, URL: http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?f54c0a0f62519d56, Host: ctldl.windowsupdate.com, Method: GET,<br>Reputation: shared, Country: US, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, Body: {Response: {Size: 631, Type: der, Threatlevel: UNKNOWN, Permanenturl: https://content.any.run/tasks/45b62ba4-931a-472b-b604-e43879a473fd/download/files/a6a071a2-c307-4d99-9a16-64640129584f, Hash: {MD5: 7515e21f59ff1aadff6f6a1a0d105c2b, SHA1: 5264c5e2334a57d8669d31c67325a9b166e53bef, SHA256: 55a7640579a0e6c0bc2388063710e5cc3120b4df0840ec8a7af9a4bdc9235029}}}, Httpcode: 200, Status: RESPONDED, Proxydetected: false, Port: 80, IP: 93.184.220.29, URL: http://crl3.digicert.com/DigiCertGlobalRootCA.crl, Host: crl3.digicert.com, Method: GET | 45b62ba4-931a-472b-b604-e43879a473fd | 02475e29bd0816b697cad5b55cdf897a | application/pdf | Dnsrequest: [{Reputation: whitelisted, IP: [23.35.236.137], Domain: geo2.adobe.com}, {Reputation: whitelisted, IP: [2.18.233.74], Domain: armmf.adobe.com}, {Reputation: whitelisted, IP: [23.48.23.34, 23.48.23.54], Domain: acroipm2.adobe.com}, {Reputation: whitelisted, IP: [95.140.236.128, 95.140.236.0], Domain: ctldl.windowsupdate.com}, {Reputation: whitelisted, IP: [54.224.241.105, 34.237.241.83, 18.213.11.84, 50.16.47.176], Domain: p13n.adobe.io}, {Reputation: shared, IP: [93.184.220.29], Domain: ocsp.digicert.com}, {Reputation: shared, IP: [93.184.220.29], Domain: crl3.digicert.com}, {Reputation: whitelisted, IP: [23.48.23.39, 23.48.23.25], Domain: ardownload3.adobe.com}], Httprequest: [{Reputation: whitelisted, Country: GB, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, Body: {Response: {Size: 4817, Type: compressed, Threatlevel: MID, Permanenturl: https://content.any.run/tasks/45b62ba4-931a-472b-b604-e43879a473fd/download/files/a72b74e1-8c52-461f-8879-b9329e0e07e2, Hash: {MD5: f7dcb24540769805e5bb30d193944dce, SHA1: e26c583c562293356794937d9e2e6155d15449ee, SHA256: 6b88c6ac55bbd6fea0ebe5a760d1ad2cfce251c59d0151a1400701cb927e36ea}}}, Httpcode: 200, Status: RESPONDED, Proxydetected: false, Port: 80, IP: 95.140.236.128, URL: http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?f54c0a0f62519d56, Host: ctldl.windowsupdate.com, Method: GET}, {Reputation: shared, Country: US, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, Body: {Response: {Size: 631, Type: der, Threatlevel: UNKNOWN, Permanenturl: https://content.any.run/tasks/45b62ba4-931a-472b-b604-e43879a473fd/download/files/a6a071a2-c307-4d99-9a16-64640129584f, Hash: {MD5: 7515e21f59ff1aadff6f6a1a0d105c2b, SHA1: 5264c5e2334a57d8669d31c67325a9b166e53bef, SHA256: 55a7640579a0e6c0bc2388063710e5cc3120b4df0840ec8a7af9a4bdc9235029}}}, Httpcode: 200, Status: RESPONDED, Proxydetected: false, Port: 80, IP: 93.184.220.29, URL: http://crl3.digicert.com/DigiCertGlobalRootCA.crl, Host: crl3.digicert.com, Method: GET}], Connection: [{Reputation: suspicious, Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, ASN: Zayo Bandwidth Inc, Country: US, Protocol: tcp, Port: 443, IP: 23.35.236.137}, {Reputation: whitelisted, Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, ASN: Akamai International B.V., Country: null, Protocol: tcp, Port: 443, IP: 2.18.233.74}, {Reputation: suspicious, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, ASN: TRUE INTERNET Co.,Ltd., Country: US, Protocol: tcp, Port: 443, IP: 23.48.23.34}, {Reputation: malicious, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, ASN: Limelight Networks, Inc., Country: GB, Protocol: tcp, Port: 80, IP: 95.140.236.128}, {Reputation: whitelisted, Processuuid: null, ASN: MCI Communications Services, Inc. d/b/a Verizon Business, Country: US, Protocol: tcp, Port: 80, IP: 93.184.220.29}, {Reputation: unknown, Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, ASN: Amazon.com, Inc., Country: US, Protocol: tcp, Port: 443, IP: 54.224.241.105}, {Reputation: whitelisted, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, ASN: MCI Communications Services, Inc. d/b/a Verizon Business, Country: US, Protocol: tcp, Port: 80, IP: 93.184.220.29}, {Reputation: whitelisted, Processuuid: null, ASN: Akamai International B.V., Country: null, Protocol: tcp, Port: 443, IP: 2.18.233.74}, {Reputation: suspicious, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, ASN: TRUE INTERNET Co.,Ltd., Country: US, Protocol: tcp, Port: 443, IP: 23.48.23.54}, {Reputation: unknown, Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, ASN: Amazon.com, Inc., Country: US, Protocol: tcp, Port: 443, IP: 34.237.241.83}, {Reputation: suspicious, Processuuid: null, ASN: TRUE INTERNET Co.,Ltd., Country: US, Protocol: tcp, Port: 443, IP: 23.48.23.39}, {Reputation: suspicious, Processuuid: 00cdebb4-cbb8-4078-ae10-a250f33f435d, ASN: TRUE INTERNET Co.,Ltd., Country: US, Protocol: tcp, Port: 443, IP: 23.48.23.39}], Threat: [{Processuuid: null, Message: ET INFO TLS Handshake Failure, Class: Potentially Bad Traffic, Srcport: 443, Dstport: 55801, Srcip: 23.48.23.39, Dstip: local}] | Windows 7 Professional Service Pack 1 (build: 7601, 32 bit) | Filename: [System Process], PID: 0, PPID: 0, Processuuid: 375da1b2-fd25-4328-a2dd-6d4d7fb44396, Cmd: , Path: [System Process], User: , Integritylevel: UNKNOWN, Exitcode: null, Mainprocess: false, Version: {Company: , Description: , Version: ,<br>Filename: System, PID: 4, PPID: 0, Processuuid: a271b969-ce69-49b0-838f-0356818625d0, Cmd: , Path: System, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: , Description: , Version: ,<br>Filename: smss.exe, PID: 260, PPID: 4, Processuuid: 9a0ca621-1717-43e1-915a-4fe4d8f6942e, Cmd: \\SystemRoot\\System32\\smss.exe, Path: \\SystemRoot\\System32\\smss.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: , Description: , Version: ,<br>Filename: csrss.exe, PID: 340, PPID: 320, Processuuid: 0952f427-a077-4cc6-9355-0b08cef93dc0, Cmd: %SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows SharedSection=1024,12288,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16, Path: C:\\Windows\\system32\\csrss.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Client Server Runtime Process, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: wininit.exe, PID: 376, PPID: 320, Processuuid: f1749785-eeea-498b-9ae3-0aa0eaec409c, Cmd: wininit.exe, Path: C:\\Windows\\system32\\wininit.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Windows Start-Up Application, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: csrss.exe, PID: 384, PPID: 368, Processuuid: ac42625e-c10a-4f4a-953d-71caa933dc92, Cmd: %SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows SharedSection=1024,12288,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16, Path: C:\\Windows\\system32\\csrss.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Client Server Runtime Process, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: winlogon.exe, PID: 432, PPID: 368, Processuuid: dadff15c-8866-4534-93b3-2524c93986cc, Cmd: winlogon.exe, Path: C:\\Windows\\system32\\winlogon.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Windows Logon Application, Version: 6.1.7601.17514 (win7sp1_rtm.101119-1850),<br>Filename: services.exe, PID: 468, PPID: 376, Processuuid: b074db04-9698-41f7-a2ed-3d930d38a4e8, Cmd: C:\\Windows\\system32\\services.exe, Path: C:\\Windows\\system32\\services.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Services and Controller app, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: lsass.exe, PID: 484, PPID: 376, Processuuid: b7dca6aa-04a4-4080-9e3c-f2d07ae2b848, Cmd: C:\\Windows\\system32\\lsass.exe, Path: C:\\Windows\\system32\\lsass.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Local Security Authority Process, Version: 6.1.7601.24545 (win7sp1_ldr_escrow.200102-1707),<br>Filename: lsm.exe, PID: 492, PPID: 376, Processuuid: 1b88a259-2c6a-4fa8-acbf-02289d497622, Cmd: C:\\Windows\\system32\\lsm.exe, Path: C:\\Windows\\system32\\lsm.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Local Session Manager Service, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: svchost.exe, PID: 592, PPID: 468, Processuuid: f93b01ef-9719-480c-95b7-642d5d551b1b, Cmd: C:\\Windows\\system32\\svchost.exe -k DcomLaunch, Path: C:\\Windows\\system32\\svchost.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: svchost.exe, PID: 672, PPID: 468, Processuuid: c3cf8aac-4921-44b4-951d-5d8a1db7b617, Cmd: C:\\Windows\\system32\\svchost.exe -k RPCSS, Path: C:\\Windows\\system32\\svchost.exe, User: NETWORK SERVICE, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: svchost.exe, PID: 760, PPID: 468, Processuuid: a8a5af5a-ec52-47d8-9655-199f14ea5c45, Cmd: C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted, Path: C:\\Windows\\System32\\svchost.exe, User: LOCAL SERVICE, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: svchost.exe, PID: 796, PPID: 468, Processuuid: 270bc634-7c40-4a22-8119-a5bbdfb22422, Cmd: C:\\Windows\\System32\\svchost.exe -k LocalSystemNetworkRestricted, Path: C:\\Windows\\System32\\svchost.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: svchost.exe, PID: 824, PPID: 468, Processuuid: 92be8359-8941-4eff-8dea-f0c816cff7eb, Cmd: C:\\Windows\\system32\\svchost.exe -k LocalService, Path: C:\\Windows\\system32\\svchost.exe, User: LOCAL SERVICE, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: svchost.exe, PID: 860, PPID: 468, Processuuid: a4e149c7-1d4e-4de9-956b-058ee9cf394d, Cmd: C:\\Windows\\system32\\svchost.exe -k netsvcs, Path: C:\\Windows\\system32\\svchost.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: svchost.exe, PID: 968, PPID: 468, Processuuid: be778e77-cf65-4405-9ad2-c0e5ea36e972, Cmd: C:\\Windows\\system32\\svchost.exe -k GPSvcGroup, Path: C:\\Windows\\system32\\svchost.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: svchost.exe, PID: 1088, PPID: 468, Processuuid: e0eff788-3254-4665-8fc6-487f4d789563, Cmd: C:\\Windows\\system32\\svchost.exe -k NetworkService, Path: C:\\Windows\\system32\\svchost.exe, User: NETWORK SERVICE, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: spoolsv.exe, PID: 1236, PPID: 468, Processuuid: c76927c0-29c0-402a-9a9a-ebb1191b2801, Cmd: C:\\Windows\\System32\\spoolsv.exe, Path: C:\\Windows\\System32\\spoolsv.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Spooler SubSystem App, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: svchost.exe, PID: 1264, PPID: 468, Processuuid: ece1b0ec-252e-496b-a5f6-08c661b0e333, Cmd: C:\\Windows\\system32\\svchost.exe -k LocalServiceNoNetwork, Path: C:\\Windows\\system32\\svchost.exe, User: LOCAL SERVICE, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: svchost.exe, PID: 1352, PPID: 468, Processuuid: 2e86deea-86d0-48f9-8b59-70228ce98f12, Cmd: C:\\Windows\\System32\\svchost.exe -k utcsvc, Path: C:\\Windows\\System32\\svchost.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: IMEDICTUPDATE.EXE, PID: 1424, PPID: 468, Processuuid: 9550f782-1f7c-4dfe-86c7-b5bf6eb6a945, Cmd: \C:\\Program Files\\Common Files\\Microsoft Shared\\IME14\\SHARED\\IMEDICTUPDATE.EXE\, Path: C:\\Program Files\\Common Files\\Microsoft Shared\\IME14\\SHARED\\IMEDICTUPDATE.EXE, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Microsoft Office IME 2010, Version: 14.0.4734.1000,<br>Filename: svchost.exe, PID: 1936, PPID: 468, Processuuid: 82765043-e885-448e-8982-e42438ca0a52, Cmd: C:\\Windows\\system32\\svchost.exe -k NetworkServiceNetworkRestricted, Path: C:\\Windows\\system32\\svchost.exe, User: NETWORK SERVICE, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: taskhost.exe, PID: 320, PPID: 468, Processuuid: 0dcb27a1-d908-4b0f-a25f-917cd8df6c1e, Cmd: \taskhost.exe\, Path: C:\\Windows\\system32\\taskhost.exe, User: admin, Integritylevel: MEDIUM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Tasks, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: taskeng.exe, PID: 288, PPID: 860, Processuuid: d2a105e9-13a6-4964-81e6-070af81b5dec, Cmd: taskeng.exe {BB154EF7-42D4-42F2-B57F-9CBB745DE3E3}, Path: C:\\Windows\\system32\\taskeng.exe, User: admin, Integritylevel: MEDIUM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Task Scheduler Engine, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: Dwm.exe, PID: 936, PPID: 796, Processuuid: bbcd1df9-3e48-4e58-9751-b61e7c472815, Cmd: \C:\\Windows\\system32\\Dwm.exe\, Path: C:\\Windows\\system32\\Dwm.exe, User: admin, Integritylevel: MEDIUM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Desktop Window Manager, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: Explorer.EXE, PID: 1464, PPID: 820, Processuuid: 4966dad3-7df9-4800-87e1-1ae4b32b93a2, Cmd: C:\\Windows\\Explorer.EXE, Path: C:\\Windows\\Explorer.EXE, User: admin, Integritylevel: MEDIUM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Windows Explorer, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: ctfmon.exe, PID: 1396, PPID: 288, Processuuid: 6307f043-d99d-44e7-a6d7-1e11eea3be3d, Cmd: C:\\Windows\\System32\\ctfmon.exe , Path: C:\\Windows\\System32\\ctfmon.exe, User: admin, Integritylevel: MEDIUM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: CTF Loader, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: SearchIndexer.exe, PID: 2544, PPID: 468, Processuuid: be7286ed-ef2f-441e-acca-9accb8f377a4, Cmd: C:\\Windows\\system32\\SearchIndexer.exe /Embedding, Path: C:\\Windows\\system32\\SearchIndexer.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Microsoft Windows Search Indexer, Version: 7.00.7600.16385 (win7_rtm.090713-1255),<br>Filename: SearchProtocolHost.exe, PID: 3452, PPID: 2544, Processuuid: 3d0967dc-e2e6-4339-a619-a084045bbbf1, Cmd: \C:\\Windows\\system32\\SearchProtocolHost.exe\ Global\\UsGthrFltPipeMssGthrPipe3_ Global\\UsGthrCtrlFltPipeMssGthrPipe3 1 -2147483646 \Software\\Microsoft\\Windows Search\ \Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)\ \C:\\ProgramData\\Microsoft\\Search\\Data\\Temp\\usgthrsvc\ \DownLevelDaemon\ , Path: C:\\Windows\\system32\\SearchProtocolHost.exe, User: SYSTEM, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Microsoft Windows Search Protocol Host, Version: 7.00.7601.24542 (win7sp1_ldr_escrow.191209-2211),<br>Filename: SearchFilterHost.exe, PID: 3840, PPID: 2544, Processuuid: 9384891d-6ead-4179-bac6-3734cee1f6bb, Cmd: \C:\\Windows\\system32\\SearchFilterHost.exe\ 0 520 524 532 65536 528 , Path: C:\\Windows\\system32\\SearchFilterHost.exe, User: SYSTEM, Integritylevel: MEDIUM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Microsoft Windows Search Filter Host, Version: 7.00.7601.24542 (win7sp1_ldr_escrow.191209-2211),<br>Filename: DllHost.exe, PID: 2872, PPID: 592, Processuuid: 93b6c7fc-1aef-4150-be36-b5930f55b85a, Cmd: C:\\Windows\\system32\\DllHost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}, Path: C:\\Windows\\system32\\DllHost.exe, User: admin, Integritylevel: MEDIUM, Exitcode: 0, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: COM Surrogate, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: DllHost.exe, PID: 2316, PPID: 592, Processuuid: 86c03f0a-b480-477e-a632-192ba22dac62, Cmd: C:\\Windows\\system32\\DllHost.exe /Processid:{F9717507-6651-4EDB-BFF7-AE615179BCCF}, Path: C:\\Windows\\system32\\DllHost.exe, User: admin, Integritylevel: MEDIUM, Exitcode: 0, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: COM Surrogate, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: AUDIODG.EXE, PID: 3000, PPID: 760, Processuuid: 9e9e24d6-751d-4019-b28b-46a44e9018ca, Cmd: C:\\Windows\\system32\\AUDIODG.EXE 0x6cc, Path: C:\\Windows\\system32\\AUDIODG.EXE, User: LOCAL SERVICE, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Windows Audio Device Graph Isolation , Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: svchost.exe, PID: 3860, PPID: 468, Processuuid: fd7ffe77-7fc9-4ae2-8592-18f48d7e9752, Cmd: C:\\Windows\\system32\\svchost.exe -k LocalServiceAndNoImpersonation, Path: C:\\Windows\\system32\\svchost.exe, User: LOCAL SERVICE, Integritylevel: SYSTEM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: Host Process for Windows Services, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: DllHost.exe, PID: 2588, PPID: 592, Processuuid: f945261c-f8b9-44fa-8173-d859bdff9085, Cmd: C:\\Windows\\system32\\DllHost.exe /Processid:{F9717507-6651-4EDB-BFF7-AE615179BCCF}, Path: C:\\Windows\\system32\\DllHost.exe, User: admin, Integritylevel: MEDIUM, Exitcode: null, Mainprocess: false, Version: {Company: Microsoft Corporation, Description: COM Surrogate, Version: 6.1.7600.16385 (win7_rtm.090713-1255),<br>Filename: AcroRd32.exe, PID: 2040, PPID: 1464, Processuuid: ba71e993-8e77-4326-b400-0be440ba49f3, Cmd: \C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe\ \C:\\Users\\admin\\AppData\\Local\\Temp\\test_file.pdf\, Path: C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe, User: admin, Integritylevel: MEDIUM, Exitcode: null, Mainprocess: true, Version: {Company: Adobe Systems Incorporated, Description: Adobe Acrobat Reader DC , Version: 20.13.20064.405839,<br>Filename: AcroRd32.exe, PID: 1280, PPID: 2040, Processuuid: 2e9fdeec-25c6-495c-8b04-35b5310b20b0, Cmd: \C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe\ --type=renderer  \C:\\Users\\admin\\AppData\\Local\\Temp\\test_file.pdf\, Path: C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe, User: admin, Integritylevel: LOW, Exitcode: null, Mainprocess: false, Version: {Company: Adobe Systems Incorporated, Description: Adobe Acrobat Reader DC , Version: 20.13.20064.405839,<br>Filename: RdrCEF.exe, PID: 3316, PPID: 2040, Processuuid: ef022081-dc28-4fab-87fc-0c9b3418bf1f, Cmd: \C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe\ --backgroundcolor=16514043, Path: C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe, User: admin, Integritylevel: LOW, Exitcode: null, Mainprocess: false, Version: {Company: Adobe Systems Incorporated, Description: Adobe RdrCEF, Version: 20.13.20064.405839,<br>Filename: RdrCEF.exe, PID: 2128, PPID: 3316, Processuuid: cf2bf809-c2b6-48a2-a142-050254cd6458, Cmd: \C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe\ --type=renderer --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --touch-events=enabled --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-gpu-compositing --lang=en-US --disable-pack-loading --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --log-severity=disable --product-version=\ReaderServices/20.13.20064 Chrome/80.0.0.0\ --device-scale-factor=1 --num-raster-threads=2 --enable-main-frame-before-activation --service-request-channel-token=14024734510508519417 --renderer-client-id=2 --mojo-platform-channel-handle=1204 --allow-no-sandbox-job /prefetch:1, Path: C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe, User: admin, Integritylevel: LOW, Exitcode: null, Mainprocess: false, Version: {Company: Adobe Systems Incorporated, Description: Adobe RdrCEF, Version: 20.13.20064.405839,<br>Filename: RdrCEF.exe, PID: 1180, PPID: 3316, Processuuid: dafd83d4-86bb-412e-8bec-be8ad78b79b7, Cmd: \C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe\ --type=gpu-process --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-pack-loading --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --log-severity=disable --product-version=\ReaderServices/20.13.20064 Chrome/80.0.0.0\ --lang=en-US --gpu-preferences=KAAAAAAAAADgACAgAQAAAAAAAAAAAGAAAAAAABAAAAAIAAAAAAAAACgAAAAEAAAAIAAAAAAAAAAoAAAAAAAAADAAAAAAAAAAOAAAAAAAAAAQAAAAAAAAAAAAAAAFAAAAEAAAAAAAAAAAAAAABgAAABAAAAAAAAAAAQAAAAUAAAAQAAAAAAAAAAEAAAAGAAAA --use-gl=swiftshader-webgl --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --service-request-channel-token=12223321443149433680 --mojo-platform-channel-handle=1236 --allow-no-sandbox-job --ignored=\ --type=renderer \ /prefetch:2, Path: C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe, User: admin, Integritylevel: LOW, Exitcode: 1, Mainprocess: false, Version: {Company: Adobe Systems Incorporated, Description: Adobe RdrCEF, Version: 20.13.20064.405839,<br>Filename: RdrCEF.exe, PID: 2860, PPID: 3316, Processuuid: 713c2780-51cc-4e0e-bc0e-e9d38f5184ac, Cmd: \C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe\ --type=gpu-process --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-pack-loading --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --log-severity=disable --product-version=\ReaderServices/20.13.20064 Chrome/80.0.0.0\ --lang=en-US --gpu-preferences=KAAAAAAAAADgACAgAQAAAAAAAAAAAGAAAAAAABAAAAAIAAAAAAAAACgAAAAEAAAAIAAAAAAAAAAoAAAAAAAAADAAAAAAAAAAOAAAAAAAAAAQAAAAAAAAAAAAAAAFAAAAEAAAAAAAAAAAAAAABgAAABAAAAAAAAAAAQAAAAUAAAAQAAAAAAAAAAEAAAAGAAAA --use-gl=swiftshader-webgl --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --service-request-channel-token=12378439338200214857 --mojo-platform-channel-handle=1408 --allow-no-sandbox-job --ignored=\ --type=renderer \ /prefetch:2, Path: C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe, User: admin, Integritylevel: LOW, Exitcode: 1, Mainprocess: false, Version: {Company: Adobe Systems Incorporated, Description: Adobe RdrCEF, Version: 20.13.20064.405839,<br>Filename: RdrCEF.exe, PID: 2108, PPID: 3316, Processuuid: 40abe4ec-fef1-4fa1-b1f0-7a305e09f4aa, Cmd: \C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe\ --type=gpu-process --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-pack-loading --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --log-severity=disable --product-version=\ReaderServices/20.13.20064 Chrome/80.0.0.0\ --lang=en-US --gpu-preferences=KAAAAAAAAADgACAgAQAAAAAAAAAAAGAAAAAAABAAAAAIAAAAAAAAACgAAAAEAAAAIAAAAAAAAAAoAAAAAAAAADAAAAAAAAAAOAAAAAAAAAAQAAAAAAAAAAAAAAAFAAAAEAAAAAAAAAAAAAAABgAAABAAAAAAAAAAAQAAAAUAAAAQAAAAAAAAAAEAAAAGAAAA --use-gl=swiftshader-webgl --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --service-request-channel-token=13732513110551940315 --mojo-platform-channel-handle=1396 --allow-no-sandbox-job --ignored=\ --type=renderer \ /prefetch:2, Path: C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe, User: admin, Integritylevel: LOW, Exitcode: 1, Mainprocess: false, Version: {Company: Adobe Systems Incorporated, Description: Adobe RdrCEF, Version: 20.13.20064.405839,<br>Filename: RdrCEF.exe, PID: 920, PPID: 3316, Processuuid: 4c084eba-2541-46a3-833d-513c41115c5f, Cmd: \C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe\ --type=renderer --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --touch-events=enabled --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-gpu-compositing --lang=en-US --disable-pack-loading --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --log-severity=disable --product-version=\ReaderServices/20.13.20064 Chrome/80.0.0.0\ --device-scale-factor=1 --num-raster-threads=2 --enable-main-frame-before-activation --service-request-channel-token=4847431092444551383 --renderer-client-id=6 --mojo-platform-channel-handle=1616 --allow-no-sandbox-job /prefetch:1, Path: C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe, User: admin, Integritylevel: LOW, Exitcode: null, Mainprocess: false, Version: {Company: Adobe Systems Incorporated, Description: Adobe RdrCEF, Version: 20.13.20064.405839,<br>Filename: RdrCEF.exe, PID: 3424, PPID: 3316, Processuuid: 60116489-5a40-4dd7-8c3c-8091346b6299, Cmd: \C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe\ --type=renderer --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --touch-events=enabled --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-gpu-compositing --lang=en-US --disable-pack-loading --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --log-severity=disable --product-version=\ReaderServices/20.13.20064 Chrome/80.0.0.0\ --device-scale-factor=1 --num-raster-threads=2 --enable-main-frame-before-activation --service-request-channel-token=16593724968950981413 --renderer-client-id=7 --mojo-platform-channel-handle=1536 --allow-no-sandbox-job /prefetch:1, Path: C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe, User: admin, Integritylevel: LOW, Exitcode: null, Mainprocess: false, Version: {Company: Adobe Systems Incorporated, Description: Adobe RdrCEF, Version: 20.13.20064.405839,<br>Filename: RdrCEF.exe, PID: 240, PPID: 3316, Processuuid: 2cab4f07-8ae6-4560-9308-3800d2be988a, Cmd: \C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe\ --type=renderer --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --touch-events=enabled --field-trial-handle=1192,9730817173672335936,3590804128953427602,131072 --disable-features=NetworkService,VizDisplayCompositor --disable-gpu-compositing --lang=en-US --disable-pack-loading --log-file=\C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\debug.log\ --log-severity=disable --product-version=\ReaderServices/20.13.20064 Chrome/80.0.0.0\ --device-scale-factor=1 --num-raster-threads=2 --enable-main-frame-before-activation --service-request-channel-token=6562753338979179477 --renderer-client-id=8 --mojo-platform-channel-handle=1836 --allow-no-sandbox-job /prefetch:1, Path: C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe, User: admin, Integritylevel: LOW, Exitcode: null, Mainprocess: false, Version: {Company: Adobe Systems Incorporated, Description: Adobe RdrCEF, Version: 20.13.20064.405839,<br>Filename: AdobeARM.exe, PID: 2124, PPID: 2040, Processuuid: 00cdebb4-cbb8-4078-ae10-a250f33f435d, Cmd: \C:\\Program Files\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe\ /PRODUCT:Reader /VERSION:20.0 /MODE:3, Path: C:\\Program Files\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe, User: admin, Integritylevel: MEDIUM, Exitcode: null, Mainprocess: false, Version: {Company: Adobe Inc., Description: Adobe Reader and Acrobat Manager, Version: 1.824.39.9311,<br>Filename: Reader_sl.exe, PID: 3532, PPID: 2124, Processuuid: b9122008-82f2-4fa4-a128-956e24ae17ce, Cmd: \C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\Reader_sl.exe\ , Path: C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\Reader_sl.exe, User: admin, Integritylevel: MEDIUM, Exitcode: 0, Mainprocess: false, Version: {Company: Adobe Systems Incorporated, Description: Adobe Acrobat SpeedLauncher, Version: 20.12.20041.394260 | IOC: https://api.any.run/report/45b62ba4-931a-472b-b604-e43879a473fd/ioc/json, MISP: https://api.any.run/report/45b62ba4-931a-472b-b604-e43879a473fd/summary/misp, HTML: https://api.any.run/report/45b62ba4-931a-472b-b604-e43879a473fd/summary/html, graph: https://content.any.run/tasks/45b62ba4-931a-472b-b604-e43879a473fd/graph | 44e4ee171347fb954938ea87400c5bef5ec8be8b | c558877e6ad6de172b8cc10461a12905c6b98d6265e650b3650b35ff73a63b03 | 768:ttu1HAfRvxuliB5IXqwdbOiNf6vP47BL1Gq:tiUVMXqcbFfsA7pMq | done | Processuuid: null, Message: ET INFO TLS Handshake Failure, Class: Potentially Bad Traffic, Srcport: 443, Dstport: 55801, Srcip: 23.48.23.39, Dstip: local | No threats detected |


#### Command example
```!anyrun-run-analysis file=5333@26c80993-f6f1-476d-89fa-6acd574d0ab2```

#### Context Example
```json
{
    "ANYRUN": {
        "Task": {
            "ID": "45b62ba4-931a-472b-b604-e43879a473fd"
        }
}
```

#### Human Readable Output
### Task:

|ID|
|---|
| ec7b793a-dd26-4420-b849-98410a74606e |
