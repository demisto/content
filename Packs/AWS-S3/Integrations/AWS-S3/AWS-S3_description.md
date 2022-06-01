Before you can use AWS S3, you need to perform several configuration steps in your AWS environment.

### Prerequisites
- Attach an instance profile with the required permissions to the Cortex XSOAR server or engine that is running 
on your AWS environment.
- Instance profile requires minimum permission: sts:AssumeRole.
- Instance profile requires permission to assume the roles needed by the AWS integrations.

### Configure AWS Settings
- Create an IAM Role for the Instance Profile.
- Attach a Role to the Instance Profile.
- Configure the Necessary IAM Roles that the AWS Integration Can Assume.

For detailed instructions, see the [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).
