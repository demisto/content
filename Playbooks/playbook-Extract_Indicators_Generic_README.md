`Deprecated` 

We recommend using extractIndicators command instead.

Extracts indicators from input data.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* ExtractDomain
* ExtractEmail
* ExtractURL
* ExtractHash
* ExtractIP

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- | 
| incident | The incident used the integration.  | ${incident} | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.MD5 | The extracted MD5 hash of the file. | string |
| File.SHA1 | The extracted SHA1 hash of the file. | string |
| File.SHA256 | The extracted SHA256 hash of the file. | string |
| URL.Data | The extracted URLs. | string |
| IP.Address | The extracted IP addresses. | string |
| Domain.Name | The extracted domains. | string |
| Account.Email.Address | The extracted emails.| string |

![Extract_Indicators_Generic](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/Extract_Indicators_Generic.png)
