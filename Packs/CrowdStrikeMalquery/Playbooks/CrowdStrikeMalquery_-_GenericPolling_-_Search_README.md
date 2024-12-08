Use this playbook as a sub-playbook to query the contents of binary files.
This playbook implements polling by continuously running the `get-request` command until the operation completes.
The remote action should have the following structure:

1. Initiate the operation - insert the type of search command (hunt or exact-search) and it's additional arguments if necessary.
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

* cs-malquery-exact-search
* cs-malquery-get-request
* cs-malquery-hunt

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| search_command | \`hunt\` or \`exact-search\`. |  | Required |
| yara_rule | A YARA rule that defines your search.<br/>Relevant for hunt command.<br/> |  | Optional |
| hex | Hex pattern to search. e.g. deadbeef0102 \(for bytes de, ad, be,  ef, 01, 02\).<br/>Relevant for exact-searh command. |  | Optional |
| ascii | ASCII pattern to search. e.g. CrowdStrike.<br/>Relevant for exact-searh command. |  | Optional |
| wide_string | Wide string pattern to search. e.g. CrowdStrike.<br/>Relevant for exact-searh command. |  | Optional |
| limit | Maximum number of results to be returned. |  | Optional |
| max_size | Maximum file size. The value can be specified either in bytes or in multiples of KB/MB/GB. e.g. 128000, 1.3 KB, 8mb. |  | Optional |
| min_size | Minimum file size. e.g. 128000, 1.3 KB, 8mb. |  | Optional |
| max_date | Limit results to files first seen before this date. The format is YYYY/MM/DD - 2018/01/31. |  | Optional |
| min_date | Limit results to files first seen after this date. The format is YYYY/MM/DD - 2018/01/31. |  | Optional |
| filter_filetypes | Limit results to files of certain types such as EMAIL, PCAP, PDF, PE32. Full list can be found in the documentation. Comma-separated values. |  | Optional |
| filter_meta | Specify a subset of metadata fields to return in the results. Possible values - sha256, md5, type, size, first_seen, label, family. Comma-separated values. |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Malquery.File.family | File family. | string |
| Malquery.File.filesize | File size. | unknown |
| Malquery.File.filetype | File type. | unknown |
| Malquery.File.first_seen | Date when the file was first seen. | unknown |
| Malquery.File.label | File label. | unknown |
| Malquery.File.md5 | File MD5. | unknown |
| Malquery.File.sha1 | File SHA1. | unknown |
| Malquery.File.sha256 | File SHA256. | unknown |

## Playbook Image

---

![CrowdStrikeMalquery - Search](../doc_files/CrowdStrikeMalquery_-_Search.png)
