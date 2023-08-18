Detonates a URL using the VMRay sandbox integration.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* GenericPolling

### Integrations

* VMRay

### Scripts

* IsIntegrationAvailable

### Commands

* vmray-get-sample
* vmray-get-analysis-by-sample
* vmray-get-threat-indicators
* vmray-get-iocs
* vmray-upload-url
* vmray-get-submission

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| URL | The URL to detonate. | URL.Data | Optional |
| interval | How often to poll for results \(minutes\). | 1 | Optional |
| timeout | How long to wait before giving up waiting for results \(minutes\). | 10 | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| VMRay.Job.JobID | The ID of a new job. | number |
| VMRay.Job.SampleID | The ID of sample. | number |
| VMRay.Job.Created | The timestamp of the created job. | date |
| VMRay.Job.VMName | The name of virtual machine. | string |
| VMRay.Job.VMID | The ID of virtual machine. | number |
| VMRay.Sample.SampleID | The sample ID of the task. | number |
| VMRay.Sample.Created | The timestamp of the created sample. | date |
| VMRay.Submission.SubmissionID | The submission ID. | number |
| VMRay.Submission.HadErrors | Whether there are any errors in the submission. | boolean |
| VMRay.Submission.IsFinished | The status of submission. Can be, "true" or "false". | boolean |
| VMRay.Submission.MD5 | The MD5 hash of the sample in submission. | string |
| VMRay.Submission.SHA1 | The SHA1 hash of the sample in submission. | string |
| VMRay.Submission.SHA256 | The SHA256 hash of the sample in submission. | string |
| VMRay.Submission.Verdict | Verdict for the sample \(Malicious, Suspicious, Clean, Not Available\). | String |
| VMRay.Submission.VerdictReason | Description of the Verdict Reason. | String |
| VMRay.Submission.Severity | Severity of the sample \(Malicious, Suspicious, Good, Blacklisted, Whitelisted, Unknown\). Deprecated. | string |
| VMRay.Submission.SSDeep | The SSDeep hash of the sample in submission. | string |
| VMRay.Submission.SampleID | The ID of the sample in submission. | number |
| VMRay.Sample.FileName | The file name of the sample. | string |
| VMRay.Sample.MD5 | The MD5 hash of the sample. | string |
| VMRay.Sample.SHA1 | The SHA1 hash of the sample. | string |
| VMRay.Sample.SHA256 | The SHA256 hash of the sample. | string |
| VMRay.Sample.SSDeep | The SSDeep of the sample. | string |
| VMRay.Sample.Verdict | Verdict for the sample \(Malicious, Suspicious, Clean, Not Available\). | String |
| VMRay.Sample.VerdictReason | Description of the Verdict Reason. | String |
| VMRay.Sample.Severity | Severity of the sample \(Malicious, Suspicious, Good, Blacklisted, Whitelisted, Unknown\). Deprecated. | string |
| VMRay.Sample.Type | The file type. | string |
| VMRay.Sample.Classifications | The classifications of the sample. | string |
| VMRay.Sample.IOC.URL.AnalysisID | The IDs of the other analyses that contain the given URL. | number |
| VMRay.Sample.IOC.URL.URL | The URL. | unknown |
| VMRay.Sample.IOC.URL.Operation | The operation of the specified URL. | unknown |
| VMRay.Sample.IOC.URL.ID | The ID of the URL. | unknown |
| VMRay.Sample.IOC.URL.Type | The type of the URL. | unknown |
| VMRay.Sample.IOC.Domain.AnalysisID | The IDs of the other analyses that contain the given domain. | unknown |
| VMRay.Sample.IOC.Domain.Domain | The domain. | unknown |
| VMRay.Sample.IOC.Domain.ID | The ID of the domain. | unknown |
| VMRay.Sample.IOC.Domain.Type | The type of the domain. | unknown |
| VMRay.Sample.IOC.IP.AnalysisID | The IDs of the other analyses that contain the given IP address. | unknown |
| VMRay.Sample.IOC.IP.IP | The IP address. | unknown |
| VMRay.Sample.IOC.IP.Operation | The operation of the given IP address. | unknown |
| VMRay.Sample.IOC.IP.ID | The ID of the IP address. | unknown |
| VMRay.Sample.IOC.IP.Type | The type of the IP address. | unknown |
| VMRay.Sample.IOC.Mutex.AnalysisID | The IDs of other analyses that contain the given IP address. | unknown |
| VMRay.Sample.IOC.Mutex.Name | The name of the mutex. | unknown |
| VMRay.Sample.IOC.Mutex.Operation | The operation of the given mutex | unknown |
| VMRay.Sample.IOC.Mutex.ID | The ID of the mutex. | unknown |
| VMRay.Sample.IOC.Mutex.Type | The type of the mutex. | unknown |
| VMRay.Sample.IOC.File.AnalysisID | The IDs of other analyses that contain the given file. | unknown |
| VMRay.Sample.IOC.File.Name | The name of the file. | unknown |
| VMRay.Sample.IOC.File.Operation | The operation of the given file. | unknown |
| VMRay.Sample.IOC.File.ID | The ID of the file. | unknown |
| VMRay.Sample.IOC.File.Type | The type of the file. | unknown |
| VMRay.Sample.IOC.File.Hashes.MD5 | The MD5 hash of the given file. | unknown |
| VMRay.Sample.IOC.File.Hashes.SSDeep | The SSDeep hash of the given file. | unknown |
| VMRay.Sample.IOC.File.Hashes.SHA256 | The SHA256 hash of the given file. | unknown |
| VMRay.Sample.IOC.File.Hashes.SHA1 | The SHA1 hash of the given file. | unknown |
| VMRay.ThreatIndicator.AnalysisID | The list of connected analysis IDs. | unknown |
| VMRay.ThreatIndicator.Category | The category of threat indicators. | unknown |
| VMRay.ThreatIndicator.Classification | The classifications of threat indicators. | unknown |
| VMRay.ThreatIndicator.ID | The ID of the threat indicator. | unknown |
| VMRay.ThreatIndicator.Operation | The operation that caused the indicators. | unknown |

## Playbook Image

---

![Detonate URL - VMRay](../doc_files/Detonate_URL_-_VMRay.png)
