Before you can use AWS System Manager, you need to perform several configuration steps in your AWS environment.

### Prerequisites
- Attach an instance profile with the required permissions to the Cortex XSOAR server or engine that is running 
on your AWS environment.
- Instance profile requires minimum permission: sts:AssumeRole.
- Instance profile requires permission to assume the roles needed by the AWS integrations.

### Configure AWS Settings
- Create an IAM role for the Instance Profile.
- Attach a role to the Instance Profile.
- Configure the necessary IAM roles that the AWS Integration can assume.

For detailed instructions, see the [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).