Before you can use AWS S3, you need to perform several configuration steps in your AWS environment.

### Prerequisites
- You need to attach an instance profile with the required permissions to the Demisto server or engine that is running 
on your AWS environment.
- Instance profile requires minimum permission: sts:AssumeRole.
- Instance profile requires permission to assume the roles needed by the AWS integrations

### Configure AWS Settings
- Create an IAM Role for the Instance Profile
- Attach a Role to the Instance Profile
- Configure the Necessary IAM Roles that the AWS Integration Can Assume

To read more detailed instructions, [please view our article](https://support.demisto.com/hc/en-us/articles/360005686854-AWS-Integrations-Configuration-Guide).