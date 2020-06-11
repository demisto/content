## [Unreleased]


## [20.5.2] - 2020-05-26
- 

## [20.4.1] - 2020-04-29
#### New Playbook
This Playbook simulates a vulnerability scan using the "HelloWorld" sample integration. It's used to demonstrate how to use the GenericPolling mechanism to run jobs that take several seconds or minutes to complete. It is designed to be used as a subplaybook, but you can also use it as a standalone playbook, by providing the ${Endpoint.Hostname} input in the Context.

Other inputs include the report output format (JSON context or File attached), and the Interval/Timeouts to use for polling the scan status until it's complete.
