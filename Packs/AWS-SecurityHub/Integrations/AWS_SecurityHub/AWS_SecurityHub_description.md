Security Hub collects security data from across AWS accounts, services, and supported third-party partner products and helps you analyze your security trends and identify the highest priority security issues.

For detailed instructions about setting up authentication, see: [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).

#### Configure the AWS Guard Duty Integration on Cortex XSOAR
- Name: a descriptive name for the integration instance.
- Role Arn: add Role Arn of the role created for this integration (such as: arn:aws:iam::<account-no>:role/xsoar-IAM.integration-Role).
- Role Session Name: add a descriptive session name (such as: xsoar-IAM.integration-Role_SESSION).
- AWS Default Region: the AWS default region
- Role Session Duration: add a session duration (default is 900). The XSOAR integration will have the permissions assigned only when the session is initiated and for the defined duration.
- Access Key: add the Access key that you saved when creating the IAM user.
- Secret Key: add the Secret key that you saved when creating the IAM user
- Security Hub Incidents Severity Level: Severity level of fetched incidents. Could be Low, Medium and High.
- Additional Incidents Filters: Additional incident filters, A string of the form 'name=name1,value=value1,comparison=comparison1
- Change findings workflow to 'NOTIFIED': notify the resource owner about the security issue. You can use this status when you are not the resource owner, and you need intervention from the resource owner in order to resolve a security issue.