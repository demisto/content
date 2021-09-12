Before you can use the AWS Athena integration in XSOAR, you need to perform several configuration steps in your AWS environment.

### Prerequisites
- Attach an instance profile with the required permissions to the XSOAR server or engine that is running 
on your AWS environment.
- Instance profile requires minimum permission: sts:AssumeRole.
- Instance profile requires permission to assume the roles needed by the AWS integrations.

### Configure AWS Settings
1. Create an IAM Role for the Instance Profile.
2. Attach a Role to the Instance Profile.
3. Configure the Necessary IAM Roles that the AWS Integration Can Assume.

For detailed instructions, see the [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).

Command descriptions, input descriptions, and output descriptions are taken from the Amazon ACM documentation. For more information, see the [Amazon Athena documention](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/athena.html).

 Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.
