Detonates a file through active integrations that support file detonation.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Detonate File - Cuckoo
* Detonate File - Lastline v2
* Detonate File - ThreatGrid
* CrowdStrike Falcon Sandbox - Detonate file
* ATD - Detonate File
* WildFire - Detonate file
* Detonate File - HybridAnalysis
* Detonate File - SNDBOX
* Detonate File - FireEye AX
* Detonate File - VMRay
* Detonate File - ANYRUN
* Detonate File - JoeSecurity

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| EntryID | The entry ID of the file to be detonated. | EntryID | File | Optional |
| File | The file object of the file to be detonated. | None | File | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Joe.Analysis.Status | The analysis status. | string |
| Joe.Analysis.WebID | The web ID. | string |
| File.Name | The filename (only in case of report type=json). | string |
| File.SHA1 | The SHA1 hash of the file. | string |
| File.SHA256 | The SHA256 hash of the file. | string |
| File.Size | The file size (only in case of report type=json). | number |
| File.Type | The file type. For example, "PE" (only in case of report type=json). | string |
| File.Malicious | The malicious file's description. | unknown |
| File.Malicious.Description | The reason for the vendor to make the decision that the file is malicious. | string |
| File.Malicious.Vendor | The vendor that made the decision that the file is malicious. | string |
| DBotScore | The indicator's object. | unknown |
| DBotScore.Indicator | The indicator we tested. | string |
| DBotScore.Score | The actual score. | number |
| DBotScore.Type | The type of the indicator. | string |
| DBotScore.Vendor | The vendor used to calculate the score. | string |
| IP.Address | The IP addresses's relevant to the sample. | string |
| DBotScore.Malicious.Vendor | The vendor used to calculate the score. | string |
| DBotScore.Malicious.Detections | The sub analysis detection statuses. | string |
| DBotScore.Malicious.SHA1 | The SHA1 hash of the file. | string |
| Sample.State | The sample state. | unknown |
| Sample.ID | The sample ID. | unknown |
| File | The file's object. | unknown |
| File.MD5 | The MD5 hash of the file. | string |
| Joe.Analysis.SampleName | The sample data. Can be, a file name or a URL. | string |
| Joe.Analysis.Comments | The analysis comments. | string |
| Joe.Analysis.Time | The submitted time. | date |
| Joe.Analysis.Runs | The sub-analysis information. | unknown |
| Joe.Analysis.Result | The analysis results. | string |
| Joe.Analysis.Errors | The errors raised during sampling. | unknown |
| Joe.Analysis.Systems | The analysis OS. | unknown |
| Joe.Analysis.MD5 | The MD5 hash of the analysis sample. | string |
| Joe.Analysis.SHA1 | The SHA1 hash of the analysis sample. | string |
| Joe.Analysis.SHA256 | The SHA256 hash of the analysis sample. | string |
| InfoFile.Name | The filename of the report file. | string |
| InfoFile.EntryID | The EntryID of the report file. | string |
| InfoFile.Size | The file size. | number |
| InfoFile.Type | The file type. For example, "PE". | string |
| InfoFile.Info | The basic information of the file. | string |
| File.Extension | The file extension. | string |
| InfoFile | The report file's object. | unknown |
| WildFire.Report | The submission object. | unknown |
| WildFire.Report.Status | The status of the submission. | string |
| WildFire.Report.SHA256 | The SHA256 hash of the submission. | string |
| WildFire.Report.MD5 | The MD5 hash of the submission. | string |
| WildFire.Report.FileType | The type of the submission. | string |
| WildFire.Report.Size | The size of the submission. | number |
| Joe.Analysis | The analysis object. | unknown |
| Cuckoo.Task.Category | The category of the task. | unknown |
| Cuckoo.Task.Machine | The machine of the task. | unknown |
| Cuckoo.Task.Errors | The errors of the task. | unknown |
| Cuckoo.Task.Target | The target of the task. | unknown |
| Cuckoo.Task.Package | The package of the task. | unknown |
| Cuckoo.Task.SampleID | The sample ID of the task. | unknown |
| Cuckoo.Task.Guest | The task guest. | unknown |
| Cuckoo.Task.Custom | The custom values of the task. | unknown |
| Cuckoo.Task.Owner | The task owner. | unknown |
| Cuckoo.Task.Priority | The priority of the task. | unknown |
| Cuckoo.Task.Platform | The platform of the task. | unknown |
| Cuckoo.Task.Options | The task options. | unknown |
| Cuckoo.Task.Status | The task status. | unknown |
| Cuckoo.Task.EnforceTimeout | Whether the timeout of the task is enforced. | unknown |
| Cuckoo.Task.Timeout | The task timeout. | unknown |
| Cuckoo.Task.Memory | The task memory. | unknown |
| Cuckoo.Task.Tags | The task tags. | unknown |
| Cuckoo.Task.ID | The ID of the task. | unknown |
| Cuckoo.Task.AddedOn | The date the task was added. | unknown |
| Cuckoo.Task.CompletedOn | The date the task was completed. | unknown |
| Cuckoo.Task.Score | The reported score of the the task. | unknown |
| Cuckoo.Task.Monitor |The monitor of the reported task. | unknown |
| SNDBOX.Analysis.ID | The analysis ID. | string |
| SNDBOX.Analysis.SampleName | The sample data. Can be, "file name" or "URL". | string |
| SNDBOX.Analysis.Status | The analysis status. | string |
| SNDBOX.Analysis.Time | The time it was submitted. | date |
| SNDBOX.Analysis.Result | The analysis results. | string |
| SNDBOX.Analysis.Errors | The errors raised during sampling. | unknown |
| SNDBOX.Analysis.Link | The analysis link. | string |
| SNDBOX.Analysis.MD5 | The MD5 hash of the analysis sample. | string |
| SNDBOX.Analysis.SHA1 | The SHA1 hash of the analysis sample. | string |
| SNDBOX.Analysis.SHA256 | The SHA256 hash of the analysis sample. | string |
| SNDBOX.Analysis | The `SNDBOX` analysis. | unknown |
| HybridAnalysis.Submit.State | The state of the process. | string |
| HybridAnalysis.Submit.SHA256 | The submission SHA256 hash. | string |
| HybridAnalysis.Submit.JobID | The JobID of the submission. | string |
| HybridAnalysis.Submit.EnvironmentID | The environmentID of the submission. | string |
| HybridAnalysis.Submit | The HybridAnalysis object. | unknown |
| ANYRUN.Task.AnalysisDate | The date and time the analysis was executed. | String |
| ANYRUN.Task.Behavior.Category | The category of a process behavior. | String |
| ANYRUN.Task.Behavior.Action | The actions performed by a process. | String |
| ANYRUN.Task.Behavior.ThreatLevel | The threat score associated with a process behavior. | Number |
| ANYRUN.Task.Behavior.ProcessUUID | The unique ID of the process whose behaviors are being profiled. | String |
| ANYRUN.Task.Connection.Reputation | The connection reputation. | String |
| ANYRUN.Task.Connection.ProcessUUID | The ID of the process that created the connection. | String |
| ANYRUN.Task.Connection.ASN | The connection autonomous system network. | String |
| ANYRUN.Task.Connection.Country | The connection country. | String |
| ANYRUN.Task.Connection.Protocol | The connection protocol. | String |
| ANYRUN.Task.Connection.Port | The connection port number. | Number |
| ANYRUN.Task.Connection.IP | The connection IP address number. | String |
| ANYRUN.Task.DnsRequest.Reputation | The reputation of the DNS request. | String |
| ANYRUN.Task.DnsRequest.IP | The IP addresses associated with a DNS request. | Unknown |
| ANYRUN.Task.DnsRequest.Domain | The domain resolution of a DNS request. | String |
| ANYRUN.Task.Threat.ProcessUUID | The unique process ID from where the threat originated. | String |
| ANYRUN.Task.Threat.Msg | The threat message. | String |
| ANYRUN.Task.Threat.Class | The class of the threat. | String |
| ANYRUN.Task.Threat.SrcPort | The port on which the threat originated. | Number |
| ANYRUN.Task.Threat.DstPort | The destination port of the threat. | Number |
| ANYRUN.Task.Threat.SrcIP | The source IP address where the threat originated. | String |
| ANYRUN.Task.Threat.DstIP | The destination IP address of the threat. | String |
| ANYRUN.Task.HttpRequest.Reputation | The reputation of the HTTP request. | String |
| ANYRUN.Task.HttpRequest.Country | The HTTP request country. | String |
| ANYRUN.Task.HttpRequest.ProcessUUID | The ID of the process making the HTTP request. | String |
| ANYRUN.Task.HttpRequest.Body | The HTTP request body parameters and details. | Unknown |
| ANYRUN.Task.HttpRequest.HttpCode | The HTTP request response code. | Number |
| ANYRUN.Task.HttpRequest.Status | The status of the HTTP request. | String |
| ANYRUN.Task.HttpRequest.ProxyDetected | Whether the HTTP request was made through a proxy. | Boolean |
| ANYRUN.Task.HttpRequest.Port | The HTTP request port. | Number |
| ANYRUN.Task.HttpRequest.IP | The HTTP request IP address. | String |
| ANYRUN.Task.HttpRequest.URL | The HTTP request URL. | String |
| ANYRUN.Task.HttpRequest.Host | The HTTP request host. | String |
| ANYRUN.Task.HttpRequest.Method | The HTTP request method type. | String |
| ANYRUN.Task.FileInfo | The details of the submitted file. | String |
| ANYRUN.Task.OS | The OS of the sandbox in which the file was analyzed. | String |
| ANYRUN.Task.ID | The unique ID of the task. | String |
| ANYRUN.Task.MIME | The MIME of the file submitted for analysis. | String |
| ANYRUN.Task.MD5 | The MD5 hash of the file submitted for analysis. | String |
| ANYRUN.Task.SHA1 | The SHA1 hash of the file submitted for analysis. | String |
| ANYRUN.Task.SHA256 | The SHA256 hash of the file submitted for analysis. | String |
| ANYRUN.Task.SSDeep | The SSDeep hash of the file submitted for analysis. | String |
| ANYRUN.Task.Verdict | The `ANY.RUN` verdict for the maliciousness of the submitted file or URL. | String |
| ANYRUN.Task.Process.FileName | The file name of the process. | String |
| ANYRUN.Task.Process.PID | The process identification number. | Number |
| ANYRUN.Task.Process.PPID | The parent process identification number. | Number |
| ANYRUN.Task.Process.ProcessUUID | The unique process ID (used by `ANY.RUN`). | String |
| ANYRUN.Task.Process.CMD | The process command. | String |
| ANYRUN.Task.Process.Path | The path of the executed command. | String |
| ANYRUN.Task.Process.User | The user who executed the command. | String |
| ANYRUN.Task.Process.IntegrityLevel | The process integrity level. | String |
| ANYRUN.Task.Process.ExitCode | The process exit code. | Number |
| ANYRUN.Task.Process.MainProcess | Whether the process is the main process. | Boolean |
| ANYRUN.Task.Process.Version.Company | The company responsible for the program executed. | String |
| ANYRUN.Task.Process.Version.Description | The description of the type of program. | String |
| ANYRUN.Task.Process.Version.Version | The version of the program executed. | String |
| DBotScore.Indicator | The indicator that was tested. | String |
| DBotScore.Score | The actual score. | Number |
| DBotScore.Type | Type of indicator. | String |
| DBotScore.Vendor | The vendor used to calculate the score. | String |
| File.Extension | The extension of the file submitted for analysis. | String |
| File.Name | The name of the file submitted for analysis. | String |
| File.MD5 | The MD5 hash of the file submitted for analysis. | String |
| File.SHA1 | The SHA1 hash of the file submitted for analysis. | String |
| File.SHA256 | The SHA256 hash of the file submitted for analysis. | String |
| File.SSDeep | The SSDeep hash of the file submitted for analysis. | String |
| File.Malicious.Vendor | The vendor that made the decision that the file is malicious. | String |
| File.Malicious.Description | The reason that the vendor made the decision tha the file is malicious. | String |
| ANYRUN.Task.Status | The task analysis status. | String |

## Playbook Image
---
![Detonate_File_Generic](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Detonate_File_Generic.png)
