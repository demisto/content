Deprecated. Use the cs-falcon-sandbox-submit-url command with polling=true instead.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* GenericPolling

### Integrations

* VxStream

### Scripts

This playbook does not use any scripts.

### Commands

* crowdstrike-scan
* crowdstrike-submit-url

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| URL | URL to detonate. | URL.Data | Optional |
| EnvironmentID | The environment ID to submit the file to. To get all IDs run the crowdstrike-get-environments command. | 100 | Optional |
| Interval | Polling frequency - how often the polling command should run \(minutes\). | 5 | Optional |
| Timeout | How much time to wait before a timeout occurs \(minutes\). | 30 | Optional |
| dontThrowErrorOnFileDetonation | Should the playbook fail due to an unsupported file type?<br/>use true or false. | false | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.SHA256 | The SHA256 hash of the file. | string |
| File.Malicious | The file malicious description. | unknown |
| File.Type | File type, for example "PE". | string |
| File.Size | The file size. | number |
| File.MD5 | The MD5 hash of the file. | string |
| File.Name | The file name. | string |
| File.SHA1 | The SHA1 hash of the file. | string |
| File | The file object. | unknown |
| File.Malicious.Vendor | The vendor that decided the file was malicious. | string |
| DBotScore | The DBotScore object. | unknown |
| DBotScore.Indicator | The tested indicator. | string |
| DBotScore.Type | The indicator type. | string |
| DBotScore.Vendor | The vendor used to calculate the score. | string |
| DBotScore.Score | The actual score. | number |

## Playbook Image

---

![Detonate URL - CrowdStrike](../doc_files/Detonate_URL_-_CrowdStrike.png)
