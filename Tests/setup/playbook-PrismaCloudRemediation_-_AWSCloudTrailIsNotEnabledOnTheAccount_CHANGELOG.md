## [Unreleased]
-

## [19.9.1] - 2019-09-18
#### New Playbook
AWS Cloudtrail is a service which provides event history of your AWS account activity, including actions taken through the AWS Management Console, AWS SDKs, command line tools, and other AWS services. To remediate Prisma Cloud Alert "CloudTrail is not enabled on the account", this playbook creates an S3 bucket to host Cloudtrail logs and enable Cloudtrail (includes all region events and global service events).