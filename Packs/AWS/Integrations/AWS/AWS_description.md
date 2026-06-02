# AWS Integration

This integration enforces AWS security best practices across your cloud environment by:
- Securing RDS instances and clusters by modifying configurations and snapshot attributes.
- Implementing S3 bucket security controls including ACLs, logging, versioning, and public access restrictions.
- Managing EC2 security groups, instance attributes, and metadata options.
- Configuring EKS cluster security settings and CloudTrail logging.
- Managing IAM policies, login profiles, and access keys.

## Supported Platforms

| Platform                                                     | Authentication |
|--------------------------------------------------------------| --- |
| **Cortex Cloud (platform)** or Cortex XSIAM (version >= 3.0) | Automatic — credentials are provided by the Cortex Cloud connector (CTS). No access keys required. |
| **Cortex XSOAR**                                             | Manual — configure an AWS Access Key and Secret Key on the integration instance. Optionally assume a role via STS. |
| **Cortex XSIAM**             (version < 3.0)                 | Manual — configure an AWS Access Key and Secret Key on the integration instance. Optionally assume a role via STS. |

## Multi-Account Support

When **Role name for cross-organization account access** and **AWS organization accounts** are both configured, commands are executed in parallel across every listed account. Each account result is tagged with its `AccountId`. Per-account failures do not abort the batch.

## Configuration (Cortex XSOAR / Cortex XSIAM (version < 3.0))

1. Create an IAM user (or use an existing one) with the required permissions for the commands you intend to run (see the **Prerequisites** section below).
2. Generate an **Access Key ID** and **Secret Access Key** for that user.
3. In the integration instance settings, in the **Access Key / Secret Key** field enter the access key as the Access Key (username) and the secret key as the Secret Key (password).
4. *(Optional)* If you want the integration to assume a role, enter the full role ARN in **Role ARN**. The IAM user must have `sts:AssumeRole` permission on that role.
5. *(Optional)* For cross-account fan-out, enter a comma-separated list of account IDs in **AWS organization accounts** and the role name (that exists in each account) in **Role name for cross-organization account access**.

## Configuration (Cortex Cloud or Cortex XSIAM (version >= 3.0))

Cloud integrations are installed from the **Data Sources** page. Go to **Settings > Data Sources**, click **Add Data Source**, select **AWS**, then in **Advanced Settings > Security Capabilities**, enable **Automation**. No access keys are required.

## Prerequisites

For Cortex Cloud or Cortex XSIAM (version >= 3.0), the connector account must be granted the permissions described in the [Cloud service provider permissions documentation](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Premium-Documentation/Cloud-service-provider-permissions#:~:text=Microsoft%20Azure-,Amazon%20Web%20Services%20provider%20permissions,-ADS).

For Cortex XSOAR / Cortex XSIAM (version < 3.0), the configured IAM user or assumed role must have the IAM permissions required by the specific commands you intend to run. Each command's required permission corresponds to its underlying AWS API action.

### Locating the required permissions for your use case

1. Identify the commands you plan to run (for example, `aws-ec2-instances-describe`).
2. Open the integration's command reference on the [Amazon Web Services page on xsoar.pan.dev](https://xsoar.pan.dev/docs/reference/integrations/aws).
3. For each command, map it to its AWS API action and grant the matching IAM permission. The mapping follows AWS naming conventions — for example:
   - `aws-ec2-instances-describe` → `ec2:DescribeInstances`
   - `aws-s3-bucket-policy-put` → `s3:PutBucketPolicy`
   - `aws-iam-access-key-update` → `iam:UpdateAccessKey`
4. Grant only the permissions for the commands you use, following the principle of least privilege.

For the full, authoritative list of AWS IAM actions, see the [AWS Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html).
