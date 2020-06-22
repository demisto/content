Detonate file through active integrations that support file detonation

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Detonate File - Group-IB TDS Polygon
* Detonate File - HybridAnalysis
* WildFire - Detonate file
* CrowdStrike Falcon Sandbox - Detonate file
* Detonate File - FireEye AX
* Detonate File - JoeSecurity
* Detonate File - ANYRUN
* Detonate File - ThreatGrid
* ATD - Detonate File
* Detonate File - SNDBOX
* Detonate File - Cuckoo
* Detonate File - Lastline v2
* Detonate File - VMRay

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| EntryID | Entry ID of file to be detonated | File.EntryID | Optional |
| File | File object of file to be detonated | File.None | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Joe.Analysis.Status | Analysis Status | string |
| Joe.Analysis.WebID | Web ID | string |
| File.Name | Filename \(only in case of report type=json\) | string |
| File.SHA1 | SHA1 of the file | string |
| File.SHA256 | SHA256 of the file | string |
| File.Size | File size \(only in case of report type=json\) | number |
| File.Type | File type e.g. "PE" \(only in case of report type=json\) | string |
| File.Malicious | The File malicious description | unknown |
| File.Malicious.Description | For malicious files, the reason for the vendor to make the decision | string |
| File.Malicious.Vendor | For malicious files, the vendor that made the decision | string |
| DBotScore | The Indicator's object | unknown |
| DBotScore.Indicator | The indicator that was tested | string |
| DBotScore.Score | The actual score | number |
| DBotScore.Type | The type of the indicator | string |
| DBotScore.Vendor | Vendor used to calculate the score | string |
| IP.Address | IP's relevant to the sample | string |
| DBotScore.Malicious.Vendor | Vendor used to calculate the score | string |
| DBotScore.Malicious.Detections | The sub analysis detection statuses | string |
| DBotScore.Malicious.SHA1 | The SHA1 of the file | string |
| Sample.State | The sample state | unknown |
| Sample.ID | The sample ID | unknown |
| File | The File's object | unknown |
| File.MD5 | MD5 of the file | string |
| Joe.Analysis.SampleName | Sample Data, could be a file name or URL | string |
| Joe.Analysis.Comments | Analysis Comments | string |
| Joe.Analysis.Time | Submitted Time | date |
| Joe.Analysis.Runs | Sub\-Analysis Information | unknown |
| Joe.Analysis.Result | Analysis Results | string |
| Joe.Analysis.Errors | Raised errors during sampling | unknown |
| Joe.Analysis.Systems | Analysis OS | unknown |
| Joe.Analysis.MD5 | MD5 of analysis sample | string |
| Joe.Analysis.SHA1 | SHA1 of analysis sample | string |
| Joe.Analysis.SHA256 | SHA256 of analysis sample | string |
| InfoFile.Name | FileName of the report file | string |
| InfoFile.EntryID | The EntryID of the report file | string |
| InfoFile.Size | File Size | number |
| InfoFile.Type | File type e.g. "PE" | string |
| InfoFile.Info | Basic information of the file | string |
| File.Extension | File Extension | string |
| InfoFile | The report file's object | unknown |
| WildFire.Report | The submission object | unknown |
| WildFire.Report.Status | The status of the submission | string |
| WildFire.Report.SHA256 | SHA256 of the submission | string |
| WildFire.Report.MD5 | MD5 of the submission | string |
| WildFire.Report.FileType | The type of the submission | string |
| WildFire.Report.Size | The size of the submission | number |
| Joe.Analysis | Thee Analysis object | unknown |
| Cuckoo.Task.Category | Category of task | unknown |
| Cuckoo.Task.Machine | Machine of task | unknown |
| Cuckoo.Task.Errors | Errors of task | unknown |
| Cuckoo.Task.Target | Target of task | unknown |
| Cuckoo.Task.Package | Package of task | unknown |
| Cuckoo.Task.SampleID | Sample ID of task | unknown |
| Cuckoo.Task.Guest | Task guest | unknown |
| Cuckoo.Task.Custom | Custom values of task | unknown |
| Cuckoo.Task.Owner | Task owner | unknown |
| Cuckoo.Task.Priority | Priority of task | unknown |
| Cuckoo.Task.Platform | Platform of task | unknown |
| Cuckoo.Task.Options | Task options | unknown |
| Cuckoo.Task.Status | Task status | unknown |
| Cuckoo.Task.EnforceTimeout | Is timeout of task enforced | unknown |
| Cuckoo.Task.Timeout | Task timeout | unknown |
| Cuckoo.Task.Memory | Task memory | unknown |
| Cuckoo.Task.Tags | Task tags | unknown |
| Cuckoo.Task.ID | ID of task | unknown |
| Cuckoo.Task.AddedOn | Date on which the task was added | unknown |
| Cuckoo.Task.CompletedOn | Date on which the task was completed | unknown |
| Cuckoo.Task.Score | Reported score of the the task | unknown |
| Cuckoo.Task.Monitor | Monitor of the reported task | unknown |
| SNDBOX.Analysis.ID | Analysis ID | string |
| SNDBOX.Analysis.SampleName | Sample Data, could be a file name or URL | string |
| SNDBOX.Analysis.Status | Analysis Status | string |
| SNDBOX.Analysis.Time | Submitted Time | date |
| SNDBOX.Analysis.Result | Analysis Results | string |
| SNDBOX.Analysis.Errors | Raised errors during sampling | unknown |
| SNDBOX.Analysis.Link | Analysis Link | string |
| SNDBOX.Analysis.MD5 | MD5 of analysis sample | string |
| SNDBOX.Analysis.SHA1 | SHA1 of analysis sample | string |
| SNDBOX.Analysis.SHA256 | SHA256 of analysis sample | string |
| SNDBOX.Analysis | SNDBOX analysis | unknown |
| HybridAnalysis.Submit.State | The state of the process | string |
| HybridAnalysis.Submit.SHA256 | The submission SHA256 | string |
| HybridAnalysis.Submit.JobID | The JobID of the submission | string |
| HybridAnalysis.Submit.EnvironmentID | The environmentID of the submission | string |
| HybridAnalysis.Submit | The HybridAnalysis object | unknown |
| ANYRUN.Task.AnalysisDate | Date and time the analysis was executed. | String |
| ANYRUN.Task.Behavior.Category | Category of a process behavior. | String |
| ANYRUN.Task.Behavior.Action | Actions performed by a process. | String |
| ANYRUN.Task.Behavior.ThreatLevel | Threat score associated with a process behavior. | Number |
| ANYRUN.Task.Behavior.ProcessUUID | Unique ID of the process whose behaviors are being profiled. | String |
| ANYRUN.Task.Connection.Reputation | Connection reputation. | String |
| ANYRUN.Task.Connection.ProcessUUID | ID of the process that created the connection. | String |
| ANYRUN.Task.Connection.ASN | Connection autonomous system network. | String |
| ANYRUN.Task.Connection.Country | Connection country. | String |
| ANYRUN.Task.Connection.Protocol | Connection protocol. | String |
| ANYRUN.Task.Connection.Port | Connection port number. | Number |
| ANYRUN.Task.Connection.IP | Connection IP number. | String |
| ANYRUN.Task.DnsRequest.Reputation | Reputation of the DNS request. | String |
| ANYRUN.Task.DnsRequest.IP | IP addresses associated with a DNS request. | Unknown |
| ANYRUN.Task.DnsRequest.Domain | Domain resolution of a DNS request. | String |
| ANYRUN.Task.Threat.ProcessUUID | Unique process ID from where the threat originated. | String |
| ANYRUN.Task.Threat.Msg | Threat message. | String |
| ANYRUN.Task.Threat.Class | Class of the threat. | String |
| ANYRUN.Task.Threat.SrcPort | Port on which the threat originated. | Number |
| ANYRUN.Task.Threat.DstPort | Destination port of the threat. | Number |
| ANYRUN.Task.Threat.SrcIP | Source IP address where the threat originated. | String |
| ANYRUN.Task.Threat.DstIP | Destination IP address of the threat. | String |
| ANYRUN.Task.HttpRequest.Reputation | Reputation of the HTTP request. | String |
| ANYRUN.Task.HttpRequest.Country | HTTP request country. | String |
| ANYRUN.Task.HttpRequest.ProcessUUID | ID of the process making the HTTP request. | String |
| ANYRUN.Task.HttpRequest.Body | HTTP request body parameters and details. | Unknown |
| ANYRUN.Task.HttpRequest.HttpCode | HTTP request response code. | Number |
| ANYRUN.Task.HttpRequest.Status | Status of the HTTP request. | String |
| ANYRUN.Task.HttpRequest.ProxyDetected | Whether the HTTP request was made through a proxy. | Boolean |
| ANYRUN.Task.HttpRequest.Port | HTTP request port. | Number |
| ANYRUN.Task.HttpRequest.IP | HTTP request IP address. | String |
| ANYRUN.Task.HttpRequest.URL | HTTP request URL. | String |
| ANYRUN.Task.HttpRequest.Host | HTTP request host. | String |
| ANYRUN.Task.HttpRequest.Method | HTTP request method type. | String |
| ANYRUN.Task.FileInfo | Details of the submitted file. | String |
| ANYRUN.Task.OS | OS of the sandbox in which the file was analyzed. | String |
| ANYRUN.Task.ID | The unique ID of the task. | String |
| ANYRUN.Task.MIME | The MIME of the file submitted for analysis. | String |
| ANYRUN.Task.MD5 | The MD5 hash of the file submitted for analysis. | String |
| ANYRUN.Task.SHA1 | The SHA1 hash of the file submitted for analysis. | String |
| ANYRUN.Task.SHA256 | The SHA256 hash of the file submitted for analysis. | String |
| ANYRUN.Task.SSDeep | SSDeep hash of the file submitted for analysis. | String |
| ANYRUN.Task.Verdict | ANY.RUN verdict for the maliciousness of the submitted file or URL. | String |
| ANYRUN.Task.Process.FileName | File name of the process. | String |
| ANYRUN.Task.Process.PID | Process identification number. | Number |
| ANYRUN.Task.Process.PPID | Parent process identification number. | Number |
| ANYRUN.Task.Process.ProcessUUID | Unique process ID \(used by ANY.RUN\). | String |
| ANYRUN.Task.Process.CMD | Process command. | String |
| ANYRUN.Task.Process.Path | Path of the executed command. | String |
| ANYRUN.Task.Process.User | User who executed the command. | String |
| ANYRUN.Task.Process.IntegrityLevel | The process integrity level. | String |
| ANYRUN.Task.Process.ExitCode | Process exit code. | Number |
| ANYRUN.Task.Process.MainProcess | Whether the process is the main process. | Boolean |
| ANYRUN.Task.Process.Version.Company | Company responsible for the program executed. | String |
| ANYRUN.Task.Process.Version.Description | Description of the type of program. | String |
| ANYRUN.Task.Process.Version.Version | Version of the program executed. | String |
| File.Extension | Extension of the file submitted for analysis. | String |
| File.Name | The name of the file submitted for analysis. | String |
| File.MD5 | MD5 hash of the file submitted for analysis. | String |
| File.SHA1 | SHA1 hash of the file submitted for analysis. | String |
| File.SHA256 | SHA256 hash of the file submitted for analysis. | String |
| File.SSDeep | SSDeep hash of the file submitted for analysis. | String |
| File.Malicious.Vendor | For malicious files, the vendor that made the decision. | String |
| File.Malicious.Description | For malicious files, the reason that the vendor made the decision. | String |
| ANYRUN.Task.Status | Task analysis status. | String |

## Playbook Image
---
![Detonate File - Generic](Insert the link to your image here)