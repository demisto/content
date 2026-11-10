Before you can use AWS GuardDuty Event Collector, you need to perform several configuration steps in your AWS environment.

To connect to the AWS GuardDuty, the authenticated user or role should have the following actions enabled:
  - guardduty:ListDetectors
  - guardduty:ListFindings
  - guardduty:GetFindings

We recommend that you use roles that have the following built-in AWS policy:
* _AmazonGuardDutyReadOnlyAccess_

To use **all** in **AWS Default Region**, also grant the ec2:DescribeRegions permission (used to list the account's enabled regions). The _AmazonGuardDutyReadOnlyAccess_ policy remains the recommendation for the GuardDuty permissions; ec2:DescribeRegions may need to be granted separately.
The enabled regions are refreshed once a day. To pick up a newly enabled region immediately, run the ***aws-gd-sync-regions*** command.
To collect from all regions, leave **PrivateLink service URL** empty and use private DNS for your VPC endpoints, or create one instance per region.
  
For more information regarding the user or role actions, see [Identity and Access Management for AWS GuardDuty](https://docs.aws.amazon.com/guardduty/latest/ug/security-iam.html).
 
For detailed instructions about setting up an authentication, see [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).


