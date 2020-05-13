## [Unreleased]


## [20.4.1] - 2020-04-29
#### New Playbook
This playbook processes CIDR indicators of both IPV4 and IPV6. By specifying in the inputs the maximum number of hosts allowed per CIDR, the playbook tags any CIDR that exceeds the number as pending_review. If the maximum CIDR size is not specified in the inputs, the playbook does not run.