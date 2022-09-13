Before you can use AWS GuardDuty Event Collector, you need to perform several configuration steps in your AWS environment.

To connect to the AWS GuardDuty, the authenticated user or role should have the following actions enabled:
  - guardduty:ListDetectors
  - guardduty:ListFindings
  - guardduty:GetFindings

We recommend that you use roles that have the following built-in AWS policy:
* _AmazonGuardDutyReadOnlyAccess_
  
For more information regarding the user or role actions, see [Identity and Access Management for AWS GuardDuty](https://docs.aws.amazon.com/guardduty/latest/ug/security-iam.html).
 
For detailed instructions about setting up authentication, see the [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).

#### Configure the AWS Guard Duty Event Collector 
- AWS Default Region: The AWS Region for this instance of the integration. For example, us-west-2
- Role Arn: The Amazon Resource Name (ARN) role used for EC2 instance authentication. If this is used, an access key and secret key are not required.
- Role Session Name: A descriptive name for the assumed role session. For example, xsiam-IAM.integration-Role_SESSION
- Role Session Duration: The maximum length of each session in seconds. Default: 900 seconds. The integration will have the permissions assigned only when the session is initiated and for the defined duration.
- Access Key: The access key ID used for authentication, that was configured during IAM user configuration. If this is used, Role ARN is not required.
- Secret Key: The secret key used for authentication, that was configured during IAM user configuration. If this is used, Role ARN is not required.
- Guard Duty Severity level: The severity level or higher of findings to be fetched: Low, Medium, or High. For example, if you set the severity level to Medium, only findings with severity level Medium or High will be fetched.


