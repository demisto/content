## [Unreleased]


## [19.10.0] - 2019-10-03
#### New Playbook
Use this playbook as a sub-playbook to  query PANW Autofocus Threat intelligence system. This sub-playbook is the same as the generic polling sub-playbook besides that it provides outputs in the playbook. The reason for that is that in Autofocus its impossible to query the results of the same query more than once so the outputs have to be in the polling context.

This playbook implements polling by continuously running the command in Step \#2 until the operation completes.
The remote action should have the following structure:

1. Initiate the operation.
2. Poll to check if the operation completed.
3. (optional) Get the results of the operation.