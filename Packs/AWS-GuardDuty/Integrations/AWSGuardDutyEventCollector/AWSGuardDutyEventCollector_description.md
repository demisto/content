Before you can use AWS GuardDuty Event Collector, you need to perform several configuration steps in your AWS environment.

### Prerequisites
- Attach an instance profile with the required permissions to the Cortex XSIAM server or engine that is running 
on your AWS environment.
- The instance profile requires a minimum permission: sts:AssumeRole.
- The instance profile requires permission to assume the roles needed by the AWS integrations.
The actions the assumed role must have in order for the Guard Duty Event Collector integration to work properly are:
  - guardduty:ListDetectors
  - guardduty:ListFindings
  - guardduty:GetFindings

For more information regarding the assumed role actions, see [Identity and Access Management for AWS GuardDuty](https://docs.aws.amazon.com/guardduty/latest/ug/security-iam.html).

### Configure AWS Settings
1. Create an IAM role for the instance profile.
2. Attach a role to the instance profile.
3. Configure the necessary IAM roles that the AWS integration can assume.


For detailed instructions, see the [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).

