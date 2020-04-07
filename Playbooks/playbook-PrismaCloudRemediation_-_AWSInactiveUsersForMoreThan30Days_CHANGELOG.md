## [Unreleased]
-

## [19.10.2] - 2019-10-29
#### New Playbook
To increase the security of your AWS account, it is recommended to find and remove IAM user credentials (passwords, access keys) that have not been used within a specified period of time.

To remediate Prisma Cloud Alert Inactive users for more than 30 days, this playbook deactivates the user by disabling the access keys (marking them as inactive) as well as resetting the user console password.