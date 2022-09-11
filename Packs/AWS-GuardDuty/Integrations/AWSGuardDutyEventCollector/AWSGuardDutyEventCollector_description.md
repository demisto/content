Before you can use AWS GuardDuty event collector, you need to perform several configuration steps in your AWS environment.

### Prerequisites
- Attach an instance profile with the required permissions to the Cortex XSIAM server or engine that is running 
on your AWS environment.
- Instance profile requires minimum permission: sts:AssumeRole.
- Instance profile requires permission to assume the roles needed by the AWS integrations.
The actions the assumed role must have in order for the Guard Duty Event Collector integration to work properly:
  - guardduty:ListDetectors
  - guardduty:ListFindings
  - guardduty:GetFindings

For more information regarding the assumed role actions, see the [Identity and Access Management for AWS GuardDuty](https://docs.aws.amazon.com/guardduty/latest/ug/security-iam.html).

### Configure AWS Settings
- Create an IAM Role for the Instance Profile.
- Attach a Role to the Instance Profile.
- Configure the Necessary IAM Roles that the AWS Integration Can Assume.


For detailed instructions, see the [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).

