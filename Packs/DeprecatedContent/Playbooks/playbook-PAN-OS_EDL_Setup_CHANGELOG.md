## [Unreleased]
- DEPRECATED. Use PAN-OS EDL Setup v3 playbook instead. 

## [19.12.1] - 2019-12-25
Rule position is not mandatory anymore, the default is Top

## [19.10.2] - 2019-10-29
Added support in attaching the EDL to an existing rule.
Added support in moving new rule to a required position in the rulebase.

## [19.8.2] - 2019-08-22
Added support for configuring an external dynamic list (EDL). The playbook syncs the remote file (if it exists) to Demisto. The playbook also creates a rule and attaches the EDL to the rule.
