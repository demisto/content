## [Unreleased]


## [19.12.1] - 2019-12-25
- Fixed 'IP Enrichment - Generic v2' inputs.
- Removed Change severity task.

## [19.11.1] - 2019-11-26
#### New Playbook
This playbook investigates an access incident by gathering user and IP information, and handling the incident based on the stages in "Handling an incident - Computer Security Incident Handling Guide" by NIST.
https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf

Used Sub-playbooks:
- IP Enrichment - Generic v2
- Account Enrichment - Generic v2.1
- Block IP - Generic v2
- NIST - Lessons Learned