Before you can use the AWS ACM integration in Demisto, you need to perform several configuration steps in your AWS environment.

### Prerequisites
- Attach an instance profile with the required permissions to the Demisto server or engine that is running 
on your AWS environment.
- Instance profile requires minimum permission: sts:AssumeRole.
- Instance profile requires permission to assume the roles needed by the AWS integrations.

### Configure AWS Settings
1. Create an IAM Role for the Instance Profile.
2. Attach a Role to the Instance Profile.
3. Configure the Necessary IAM Roles that the AWS Integration Can Assume.

For detailed instructions, [see the AWS Integrations Configuration Guide](https://support.demisto.com/hc/en-us/articles/360005686854-AWS-Integrations-Configuration-Guide).

Command descriptions, input descriptions, and output descriptions are taken from the Amazon ACM documentation. For more information, see the [Amazon ACM documention](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/acm.html).