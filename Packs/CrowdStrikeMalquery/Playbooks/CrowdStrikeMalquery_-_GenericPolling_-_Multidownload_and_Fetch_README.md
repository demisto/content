Schedule samples to download.
Using samples-multidownload is a three-step process:

1. Schedule the download with samples-multidownload, which returns a request ID.
2. Provide that request ID to the cs-malquery-get-request, in order to check the status of the operation.
3. When the request status is “done”, use cs-malquery-sample-fetch to download the results as a password-protected archive.

Use this playbook as a sub-playbook to schedule samples for download.
This playbook implements polling by continuously running the `get-request` command until the operation completes.
Once the request status is done the sub-playbook runs cs-malquery-sample-fetch.

The remote action should have the following structure:

1. Initiate the operation - insert the sample SHA256 ids.
2. Poll to check if the operation completed.
3. Get the results of the operation.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* GenericPolling

### Integrations

* CrowdStrikeMalquery

### Scripts

This playbook does not use any scripts.

### Commands

* cs-malquery-sample-fetch
* cs-malquery-samples-multidownload

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| sha256 | Samples sha256 ids. Comma-separated values. |  | Required |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.SHA256 | SHA256 hash. | unknown |
| File.SHA1 | SHA1 hash. | unknown |
| File.SHA512 | SHA512 hash. | unknown |
| File.Name | Name of the file. | unknown |
| File.EntryID | Entry ID. | unknown |
| File.Info | File info. | unknown |
| File.Type | Type of the file. | unknown |
| File.MD5 | MD5 hash. | unknown |

## Playbook Image

---

![CrowdStrikeMalquery - Multidownload and Fetch](../doc_files/CrowdStrikeMalquery_-_Multidownload_and_Fetch.png)
