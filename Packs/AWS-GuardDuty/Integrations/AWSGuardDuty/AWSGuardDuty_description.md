Use this integration to detect and manage threats to your AWS system. We recommend that you use roles that have the following
bulit-in AWS policies:

* _AmazonGuardDutyFullAccess_
* _AmazonGuardDutyReadOnlyAccess_

For detailed instructions about setting up authentication, see: [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).

#### Configure the AWS Guard Duty Integration on Cortex XSOAR
- Name: a descriptive name for the integration instance.
- AWS Default Region: the AWS default region
- Role Arn: add Role Arn of the role created for this integration (such as: arn:aws:iam::<account-no>:role/xsoar-IAM.integration-Role).
- Role Session Name: add a descriptive session name (such as: xsoar-IAM.integration-Role_SESSION).
- Role Session Duration: add a session duration (default is 900). The XSOAR integration will have the permissions assigned only when the session is initiated and for the defined duration.
- Access Key: add the Access key that you saved when creating the IAM user.
- Secret Key: add the Secret key that you saved when creating the IAM user
- Guard Duty Severity level: you can set the severity level of the findings to be fetched. "Low", "Medium", "High"
