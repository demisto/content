Launches an existing Tenable.sc scan by scan ID and waits for the scan to finish by polling its status in pre-defined intervals.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* Tenable.sc

### Scripts
This playbook does not use any scripts.

### Commands
* tenable-sc-launch-scan
* tenable-sc-get-scan-report

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- | 
| ScanID | The scan ID to launch. | ${TenableSC.Scan.ID} | Required |
| diagnosticTarget | The valid IP address/hostname of a specific target to scan. Must be provided with `diagnosticPassword`. | ${Endpoint.IPAddress} | Optional |
| diagnosticPassword | The non-empty string password. | ${Endpoint.Password} | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| TenableSC.ScanResults.Name | The scan name. | string |
| TenableSC.ScanResults.Status | The status of the scan. | string |
| TenableSC.ScanResults.ScannedIPs | The number of scanned IP addresses of the scan. | number |
| TenableSC.ScanResults.StartTime | The start time of the scan. | date |
| TenableSC.ScanResults.EndTime | The end time of the scan. | date |
| TenableSC.ScanResults.Checks | The completed checks of the scan. | number |
| TenableSC.ScanResults.RepositoryName | The repository name of the scan. | string |
| TenableSC.ScanResults.Description | The description of the scan. | string |
| TenableSC.ScanResults.Policy | The policy of the scan. | string |
| TenableSC.ScanResults.Group | The owner group name of the scan | string |
| TenableSC.ScanResults.Owner | The owner user name of the scan. | string |
| TenableSC.ScanResults.Duration | The duration in minutes of the scan. | number |
| TenableSC.ScanResults.ImportTime | The import time of the scan. | date |
| TenableSC.ScanResults.ID | The results ID of the scan. | number |
| TenableSC.ScanResults.Vulnerability.ID | The vulnerability plugin ID of the scan. | number |
| TenableSC.ScanResults.Vulnerability.Name | The vulnerability name of the scan. | string |
| TenableSC.ScanResults.Vulnerability.Family | The vulnerability family of the scan. | string |
| TenableSC.ScanResults.Vulnerability.Severity | The vulnerability severity of the scan. | string |
| TenableSC.ScanResults.Vulnerability.Total | The vulnerability total hosts of the scan. | number |

## Playbook Image
---
![Tenable_sc_scan](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Tenable_sc_scan.png)
