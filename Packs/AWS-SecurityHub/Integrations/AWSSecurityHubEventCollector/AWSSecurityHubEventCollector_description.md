For detailed instructions about setting up authentication, see: [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).

#### Configure the AWS Security Hub Integration on Cortex XSIAM
- Role Arn: The Amazon Resource Name (ARN) role used for EC2 instance authentication. If this is used, an access key and secret key are not required. (For example: arn:aws:iam::<account-no>:role/xsoar-IAM.integration-Role).
- Role Session Name: A descriptive name for the assumed role session. For example, xsiam-IAM.integration-Role_SESSION.
- Role Session Duration: The maximum length of each session in seconds. Default: 900 seconds. The integration will have the permissions assigned only when the session is initiated and for the defined duration.
- Access Key: The access key ID used for authentication, that was configured during IAM user configuration. If this is used, Role ARN is not required.
- Secret Key: The secret key used for authentication, that was configured during IAM user configuration. If this is used, Role ARN is not required.
- Security Hub Incidents Severity Level: Severity level of fetched incidents. Could be Low, Medium and High. For example, if you set the severity level to Medium, only findings with severity level Medium or High will be fetched.
- Additional Incidents Filters: A comma-separated list of additional incident filters in the form 'name=name1,value=value1,comparison=comparison1
- Change findings workflow to 'NOTIFIED': Notify the resource owner about the security issue. You can use this status when you are not the resource owner, and you need intervention from the resource owner in order to resolve a security issue.
