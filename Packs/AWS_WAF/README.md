<~XSIAM>
# AWS WAF
This pack includes Cortex XSIAM content.


## Configuration on Server Side
- For information on configuring **ACL web logging**, refer to the following [documentation](https://docs.aws.amazon.com/waf/latest/developerguide/logging-management.html).
- For information on sending ACL web logs  to **S3 bucket**, refer to the following [documentation](https://docs.aws.amazon.com/waf/latest/developerguide/logging-s3.html).

## Collect Events from Vendor
In order to use the collector, use the [Amazon S3](#amazon-s3) collector.

### Amazon S3
To create or configure the Amazon S3 collector, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Generic-Logs-from-Amazon-S3).


1. Navigate to **Settings** > **Configuration** > **Data Sources** > **Amazon S3**.
2. Press **Add New Istance**.
3. Fill in the following parameters: 

| **Field Name**    | **Description**                                                                                    | **Value**         |
|-------------------|----------------------------------------------------------------------------------------------------|-------------------|
| SQS URL           | The ARN of the Amazon SQS that you configured in the AWS Management Console.                        | \<YourSQSURL\>      |
| Name              | A descriptive name for your log collection configuration.                                           | \<InstanceName\>    |
| AWS Client ID     |  The access key ID, which was received when configuring access keys for the AWS IAM user in AWS.    | \<AWSClientID\>     |
| AWS Client Secret | The secret access key, which was received when configuring access keys for the AWS IAM user in AWS. | \<AWSClientSecret\> |
| Log Type          | Select Generic to configure your log collection to receive generic logs from Amazon S3.             | Generic           |
| Log Format        | Select the log format type as JSON.                                                                 | Json              |
| Vendor            | Set as 'aws'.                                                                                      | aws               |
| Product           | Set as 'waf'.                                                                                       | waf               |
| Compression       | Select 'gzip'.                                                                                      | gzip              |


</~XSIAM>

AWS WAF is a web application firewall service that lets you monitor web requests that are forwarded to an Amazon API Gateway API, an Amazon CloudFront distribution, or an Application Load Balancer. 
You can protect those resources based on conditions that you specify, such as the IP addresses that the requests originate from.

## What does this pack do
### AWS WAF
This integration enables you to:
- Create, retrieve, update, or delete IP sets.
- Create, retrieve, update, or delete Regex patterns sets.
- Create, retrieve, update, or delete Rule groups.
- Create IP rules to associate to a specific rule group.
- Create country rules to associate to a specific rule group.
- Create string match rules to associate to a specific rule group.
- Add statements to existing rules.
