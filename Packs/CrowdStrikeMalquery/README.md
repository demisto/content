CrowdStrike MalQuery allows users to query the contents of binary files to identify clean or malicious samples based on their content using Falcon's search engine.

## What does this pack do?

- Identify malware samples in binary files by performing exact, fuzzy, and YARA rule-based searches.
- Download files or view their metadata by specifying SHA256 hashes and fetch archived results of multi-downloads.

## Playbooks

This pack includes the following built-in playbooks:

- **CrowdStrikeMalquery - Multidownload and Fetch**: Schedule samples for download.
- **CrowdStrikeMalquery - Search**: Query the contents of binary files.
