For detailed instructions about setting up authentication, see: [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).

#### Configure the AWS - Security Hub v2 Integration in Cortex
- AWS Default Region: The AWS region to connect to.
- Access Key: The access key ID used for authentication, that was configured during IAM user configuration. If this is used, Role ARN is not required.
- Secret Key: The secret key used for authentication, that was configured during IAM user configuration. If this is used, Role ARN is not required.
- Role Arn: The Amazon Resource Name (ARN) role used for EC2 instance authentication. If this is used, an access key and secret key are not required. (For example: arn:aws:iam::<account-no>:role/xsoar-IAM.integration-Role).
- Role Session Name: A descriptive name for the assumed role session. For example, xsoar-IAM.integration-Role_SESSION.
- Role Session Duration: The maximum length of each session in seconds. The integration will have the permissions assigned only when the session is initiated and for the defined duration.
- Minimum severity to fetch: The minimum severity of findings to fetch, based on the OCSF severity_id. Findings with this severity or higher are fetched. Leave empty to fetch all severities.
- Additional fetch filters: Extra string filters to narrow the fetch, in the format `fieldname=<OCSF field>,value=<value>,comparison=<comparison>`, with multiple entries separated by `;`. Combined with the time and severity filters using AND.
- Incident Mirroring Direction: The direction to mirror the finding between Cortex and AWS - Security Hub (Incoming, Outgoing, or Incoming And Outgoing).
- Resolve finding of closed incident from Cortex XSOAR in AWS Security Hub: When enabled, closing an incident in Cortex sets the corresponding finding's status to Resolved in AWS Security Hub (applies to outgoing mirroring).

#### Required Permissions
- securityhub:EnableSecurityHubV2
- securityhub:DisableSecurityHubV2
- securityhub:DescribeSecurityHubV2
- securityhub:GetFindingsV2
- securityhub:BatchUpdateFindingsV2
