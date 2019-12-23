## [Unreleased]

## [19.12.1] - 2019-12-23
Fix for failed Convert file hash to corresponding hashes
Fixed casing from FIle.SHA1 to File.SHA1
Fixed Inputs in set

## [19.11.1] - 2019-11-26
#### New Playbook
The playbook enables you to get all of the corresponding file hashes for a file even if there is only one hash type available.
For example, if we have only the SHA256 hash, the playbook will get the SHA1 and MD5 hashes as long as the
original searched hash is recognized by any our the threat intelligence integrations.
