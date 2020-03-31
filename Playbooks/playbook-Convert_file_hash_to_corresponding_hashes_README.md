Gets all of the corresponding hashes for a file even if there is only one hash type available.
For example, if we have only the SHA256 hash, the playbook will get the SHA1 hash and MD5 hash as long as the
original searched hash is recognized by any our the threat intelligence integrations.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
This playbook does not use any sub-playbooks.

## Integrations
This playbook does not use any integrations.

## Scripts
This playbook does not use any scripts.

## Commands
* file

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| SHA256 | The SHA256 hash on which to search. | SHA256 | File | Optional |
| SHA1 | The SHA1 hash on which to search. | SHA1 | File | Optional |
| MD5 | The MD5 hash on which to search. | MD5 | File | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.SHA256 | The output for detected SHA256 hash of the file. | string |
| File.SHA1 | The output for detected SHA1 hash of the file. | string |
| File.MD5 | The output for detected MD5 hash of the file. | string |

![Convert_file_hash_to_corresponding_hashes](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/Convert_file_hash_to_corresponding_hashes.png)
