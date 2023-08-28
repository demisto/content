YARA
---
#### About YARA
YARA is a tool aimed at (but not limited to) helping malware researchers to identify and classify malware samples. With YARA you can create descriptions of malware families (or whatever you want to describe) based on textual or binary patterns. Each description, a.k.a rule, consists of a set of strings and a boolean expression which determine its logic.


#### Pack Contents
`YARA Scan` automation - Performs a YARA scan on the specified files.
`YARA - File Scan` playbook -   A playbook to run YARA scan against uploaded file. To run the playbook, provide the YARA rule content and the entry ID of the file you intend to scan.