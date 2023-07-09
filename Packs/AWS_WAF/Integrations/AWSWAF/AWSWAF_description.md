Use AWS WAF to monitor web requests that are forwarded to an Amazon API Gateway API, an Amazon CloudFront distribution, or an Application Load Balancer. Protect those resources based on conditions that you specify, such as the IP addresses that the requests originate from.
#### Configure the AWS WAF Integration
- AWS Default Region: The AWS Region for this instance of the integration. For example, us-west-2
- Role Arn: The Amazon Resource Name (ARN) role used for authentication. If this is used, an access key and secret key are not required.
- Role Session Name: A descriptive name for the assumed role session. For example, xsiam-IAM.integration-Role_SESSION
- Role Session Duration: The maximum length of each session in seconds. Default: 900 seconds. The integration will have the permissions assigned only when the session is initiated and for the defined duration.
- Access Key: The access key ID used for authentication, that was configured during IAM user configuration. If this is used, Role ARN is not required.
- Secret Key: The secret key used for authentication, that was configured during IAM user configuration. If this is used, Role ARN is not required.
