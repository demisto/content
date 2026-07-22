Use AWS GuardDuty to detect and manage threats to your AWS environment by fetching newly created GuardDuty security findings. Each GuardDuty finding is a data set containing details relating to a unique security issue. 
Each integration instance fetches findings from a single AWS Region.
You can set whether findings that are fetched will be moved to the GuardDuty archive using the *Archive findings After Fetch* parameter.
Create a separate instance for each AWS Region used in your AWS environment. 

We recommend that you use roles that have the following built-in AWS policies:
* _AmazonGuardDutyFullAccess_
* _AmazonGuardDutyReadOnlyAccess_

For detailed instructions about setting up authentication, see: [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).

#### Configure the AWS Guard Duty Integration
- AWS Default Region: The AWS Region for this instance of the integration. For example, us-west-2
- Role Arn: The Amazon Resource Name (ARN) role used for EC2 instance authentication. If this is used, an access key and secret key are not required.
- Role Session Name: A descriptive name for the assumed role session. For example, xsiam-IAM.integration-Role_SESSION
- Role Session Duration: The maximum length of each session in seconds. Default: 900 seconds. The integration will have the permissions assigned only when the session is initiated and for the defined duration.
- Access Key: The access key ID used for authentication, that was configured during IAM user configuration. If this is used, Role ARN is not required.
- Secret Key: The secret key used for authentication, that was configured during IAM user configuration. If this is used, Role ARN is not required.
- Guard Duty Severity level: The severity level or higher of findings to be fetched: Low, Medium, or High. For example, if you set the severity level to Medium, only findings with severity level Medium or High will be fetched.
