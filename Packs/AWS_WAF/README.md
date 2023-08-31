<~XSIAM>
# AWS WAF
This pack includes Cortex XSIAM content.


## Configuration on Server Side
For information on configuring **ACL web logging**, please refer to the following documentation [here](https://docs.aws.amazon.com/waf/latest/developerguide/logging-management.html).
For information on sending logs ACL web logging to **S3 bucket**, please refer to the following documentation [here](https://docs.aws.amazon.com/waf/latest/developerguide/logging-s3.html).

## Collect Events from Vendor
In order to use the collector, use the [Amazon S3](#amazon-s3) option.

### Amazon S3
To create or configure the Amazon S3 collector, use the information described [here](hhttps://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Generic-Logs-from-Amazon-S3).


1. Navigate to **Settings** > **Configuration** > **Data Sources** > **Amazon S3**.
2. Press **Add New Istance**.
3. Fill in the following parameters: 

| **Field Name**    | **Description** | **Value** |
|-------------------|-----------------|-----------|
| SQS URL           | test            | test      |
| Name              | test            | test      |
| AWS Client ID     | test            | test      |
| AWS Client Secret | test            | test      |
| Log Type          | test            | Generic   |
| Log Format        | test            | Json      |
| Vendor            | test            | aws       |
| Product           | test            | waf       |
| Compression       | test            | gzip      |


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
