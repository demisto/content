## Overview
---

 Security Hub provides you with a comprehensive view of the security state of your AWS environment and resources. 
 It also provides you with the compliance status of your environment based on CIS AWS Foundations compliance checks.
 Security Hub collects security data from AWS accounts, services, and integrated third-party products and helps you analyze security trends in your environment to identify the highest priority security issues. 
 For more information about Security Hub, see the * AWS Security Hub User Guide *.
 
 When you use operations in the Security Hub API, the requests are executed only in the AWS Region that is currently active   or in the specific AWS Region that you specify in your request. Any configuration   or settings change that results from the operation is applied only to that Region.   To make the same change in other Regions, execute the same command for each Region to apply the change to.
 For example, if your Region is set to us-west-2, when you use CreateMembers to add a member account to Security Hub, the association of the member account with the master account is created only in the us-west-2 Region.
 Security Hub must be enabled for the member account in the same Region that the invite was sent from.


## Configure AWS - Security Hub on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for AWS - Security Hub.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Fetch incidents__
    * __First fetch time (\<number\> \<time unit\>, e.g., 12 hours, 7 days, 3 months, 1 year)__
    * __Incident type__
    * __Role Arn__
    * __Role Session Name__
    * __AWS Default Region__
    * __Role Session Duration__
    * __Access Key__
    * __Secret Key__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
    * __Security Hub Severity level__ Severity level of fetched incidents
    * __Additional Filters__ Additional filters for fetched incidents
    * __Change findings workflow to 'NOTIFIED'__
4. Click __Test__ to validate the URLs, token, and connection.


## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. aws-securityhub-disable-security-hub
2. aws-securityhub-batch-update-findings
3. aws-securityhub-enable-security-hub
4. aws-securityhub-get-findings
5. aws-securityhub-get-master-account
6. aws-securityhub-list-members
7. aws-securityhub-update-findings (deprecated)
### 1. aws-securityhub-disable-security-hub

---
Disables Security Hub in your account only in the current Region. To disable Security Hub in all Regions, you must submit one request per Region where you have enabled Security Hub. When you disable Security Hub for a master account, it doesn't disable Security Hub for any associated member accounts. When you disable Security Hub, your existing findings and insights and any Security Hub configuration settings are deleted after 90 days and can't be recovered. Any standards that were enabled are disabled, and your master and member account associations are removed. If you want to save your existing findings, you must export them before you disable Security Hub.

##### Base Command

`aws-securityhub-disable-security-hub`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!aws-securityhub-disable-security-hub```

##### Context Example
```
{
    "AWS-SecurityHub": {}
}
```

##### Human Readable Output
### AWS SecurityHub DisableSecurityHub
**No entries.**


### 2. aws-securityhub-batch-update-findings

---
Used by Security Hub customers to update information about their investigation into a finding. Requested by master accounts or member accounts. Master accounts can update findings for their account and their member accounts. Member accounts can update findings for their account. Updates from BatchUpdateFindings do not affect the value of UpdatedAt for a finding. Master accounts can use BatchUpdateFindings to update the following finding fields and objects. *   Confidence *   Criticality *   Note *   RelatedFindings *   Severity *   Types *   UserDefinedFields *   VerificationState *   Workflow Member accounts can only use BatchUpdateFindings to update the Note object.

##### Base Command

`aws-securityhub-batch-update-findings`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| finding_identifiers_id | The identifier of the finding that was specified by the finding provider. | Optional | 
| finding_identifiers_product_arn | The ARN generated by Security Hub that uniquely identifies a product that generates findings. This can be the ARN for a third-party product that is integrated with Security Hub, or the ARN for a custom integration. | Optional | 
| note_text | The updated note text. | Optional | 
| note_updated_by | The principal that updated the note. | Optional | 
| severity_label | The severity value of the finding. The allowed values are the following. *   INFORMATIONAL - No issue was found. *   LOW - The issue does not require action on its own. *   MEDIUM - The issue must be addressed but not urgently. *   HIGH - The issue must be addressed as a priority. *   CRITICAL - The issue must be remediated immediately to avoid it escalating. | Optional | 
| verification_state | Indicates the veracity of a finding. The available values for VerificationState are as follows. *   UNKNOWN - The default disposition of a security finding. *   TRUE_POSITIVE - The security finding is confirmed. *   FALSE_POSITIVE - The security finding was determined to be a false alarm. *   BENIGN_POSITIVE - A special case of TRUE_POSITIVE where the finding doesn't pose any threat, is expected, or both. | Optional | 
| types | One or more finding types in the format of namespace/category/classifier that classify a finding. Valid namespace values are as follows.  Software and Configuration Checks, TTPs, Effects, Unusual Behaviors, Sensitive Data Identifications | Optional | 
| user_defined_fields | A list of name/value string pairs associated with the finding. These are custom, user-defined fields added to a finding. | Optional | 
| workflow_status | The status of the investigation into the finding. The allowed values are the following. *   NEW - The initial state of a finding, before it is reviewed. *   NOTIFIED - Indicates that you notified the resource owner about the security issue. Used when the initial reviewer is not the resource owner, and needs intervention from the resource owner. *   RESOLVED - The finding was reviewed and remediated and is now considered resolved. *   SUPPRESSED - The finding will not be reviewed again and will not be acted upon. | Optional | 
| related_findings_product_arn | The ARN of the product that generated a related finding. | Optional | 
| related_findings_id | The product-generated identifier for a related finding. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-SecurityHub.ProcessedFindings.Id | string | The identifier of the finding that was specified by the finding provider. | 
| AWS-SecurityHub.ProcessedFindings.ProductArn | string | The ARN generated by Security Hub that uniquely identifies a product that generates findings. This can be the ARN for a third-party product that is integrated with Security Hub, or the ARN for a custom integration. | 
| AWS-SecurityHub.ProcessedFindings | Unknown | The list of findings that were updated successfully. | 
| AWS-SecurityHub.UnprocessedFindings.FindingIdentifier.Id | string | The identifier of the finding that was specified by the finding provider. | 
| AWS-SecurityHub.UnprocessedFindings.FindingIdentifier.ProductArn | string | The ARN generated by Security Hub that uniquely identifies a product that generates findings. This can be the ARN for a third-party product that is integrated with Security Hub, or the ARN for a custom integration. | 
| AWS-SecurityHub.UnprocessedFindings.FindingIdentifier | string | The identifier of the finding that was not updated. | 
| AWS-SecurityHub.UnprocessedFindings.ErrorCode | string | The code associated with the error. | 
| AWS-SecurityHub.UnprocessedFindings.ErrorMessage | string | The message associated with the error. | 
| AWS-SecurityHub.UnprocessedFindings | Unknown | The list of findings that were not updated. | 


##### Command Example
```!aws-securityhub-batch-update-findings finding_identifiers_id='arn:aws:securityhub:eu-west-1:676921422616:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/a2ee641f-aec2-4356-a1b6-656cce03be4e' finding_identifiers_product_arn='arn:aws:securityhub:eu-west-1::product/aws/securityhub' note_text=test note_updated_by=Demisto```

##### Context Example
```
{
    "AWS-SecurityHub.ProcessedFindings": []
}
```

##### Human Readable Output
### AWS SecurityHub BatchUpdateFindings
|ProcessedFindings|UnprocessedFindings|
|---|---|
|  | {'FindingIdentifier': {'Id': "'arn:aws:securityhub:eu-west-1:676921422616:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/a2ee641f-aec2-4356-a1b6-656cce03be4e'", 'ProductArn': "'arn:aws:securityhub:eu-west-1::product/aws/securityhub'"}, 'ErrorCode': 'FindingNotFound', 'ErrorMessage': 'Finding Not Found'} |


### 3. aws-securityhub-enable-security-hub

---
Enables Security Hub for your account in the current Region or the Region you specify in the request. Enabling Security Hub also enables the CIS AWS Foundations standard. When you enable Security Hub, you grant to Security Hub the permissions necessary to gather findings from AWS Config, Amazon GuardDuty, Amazon Inspector, and Amazon Macie. To learn more, see Setting Up AWS Security Hub.

##### Base Command

`aws-securityhub-enable-security-hub`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| tags | List of Tags separated by Key Value. For example: "key=key1,value=value1;key=key2,value=value2" | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!aws-securityhub-enable-security-hub```

##### Context Example
```
{
    "AWS-SecurityHub": {}
}
```

##### Human Readable Output
### AWS SecurityHub EnableSecurityHub
**No entries.**


### 4. aws-securityhub-get-findings
---
Returns a list of findings that match the specified criteria.

##### Base Command

`aws-securityhub-get-findings`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| product_arn_value | The string filter value. | Optional | 
| product_arn_comparison | The condition to be applied to a string value when querying for findings | Optional | 
| aws_account_id_value | The string filter value. | Optional | 
| aws_account_id_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| id_value | The string filter value. | Optional | 
| id_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| generator_id_value | The string filter value. | Optional | 
| generator_id_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| type_value | The string filter value. | Optional | 
| type_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| first_observed_at_start | A start date for the date filter. | Optional | 
| first_observed_at_end | An end date for the date filter. | Optional | 
| date_range_unit | A date range unit for the date filter. | Optional | 
| last_observed_at_start | A start date for the date filter. | Optional | 
| last_observed_at_end | An end date for the date filter. | Optional | 
| date_range_unit | A date range unit for the date filter. | Optional | 
| created_at_start | A start date for the date filter. | Optional | 
| created_at_end | An end date for the date filter. | Optional | 
| date_range_unit | A date range unit for the date filter. | Optional | 
| updated_at_start | A start date for the date filter. | Optional | 
| updated_at_end | An end date for the date filter. | Optional | 
| date_range_unit | A date range unit for the date filter. | Optional | 
| severity_label_value | The string filter value. | Optional | 
| severity_label_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| title_value | The string filter value. | Optional | 
| title_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| description_value | The string filter value. | Optional | 
| description_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| recommendation_text_value | The string filter value. | Optional | 
| recommendation_text_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| source_url_value | The string filter value. | Optional | 
| source_url_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| product_fields_key | The key of the map filter. | Optional | 
| product_fields_value | The value for the key in the map filter. | Optional | 
| product_fields_comparison | The condition to apply to a key value when querying for findings with a map filter. | Optional | 
| product_name_value | The string filter value. | Optional | 
| product_name_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| company_name_value | The string filter value. | Optional | 
| company_name_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| user_defined_fields_key | The key of the map filter. | Optional | 
| user_defined_fields_value | The value for the key in the map filter. | Optional | 
| user_defined_fields_comparison | The condition to apply to a key value when querying for findings with a map filter. | Optional | 
| malware_name_value | The string filter value. | Optional | 
| malware_name_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| malware_type_value | The string filter value. | Optional | 
| malware_type_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| malware_path_value | The string filter value. | Optional | 
| malware_path_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| malware_state_value | The string filter value. | Optional | 
| malware_state_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| network_direction_value | The string filter value. | Optional | 
| network_direction_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| network_protocol_value | The string filter value. | Optional | 
| network_protocol_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| network_source_ip_v4_cidr | A finding's CIDR value. | Optional | 
| network_source_ip_v6_cidr | A finding's CIDR value. | Optional | 
| network_source_domain_value | The string filter value. | Optional | 
| network_source_domain_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| network_source_mac_value | The string filter value. | Optional | 
| network_source_mac_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| network_destination_ip_v4_cidr | A finding's CIDR value. | Optional | 
| network_destination_ip_v6_cidr | A finding's CIDR value. | Optional | 
| network_destination_domain_value | The string filter value. | Optional | 
| network_destination_domain_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| process_name_value | The string filter value. | Optional | 
| process_name_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| process_path_value | The string filter value. | Optional | 
| process_path_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| process_launched_at_start | A start date for the date filter. | Optional | 
| process_launched_at_end | An end date for the date filter. | Optional | 
| date_range_unit | A date range unit for the date filter. | Optional | 
| process_terminated_at_start | A start date for the date filter. | Optional | 
| process_terminated_at_end | An end date for the date filter. | Optional | 
| date_range_unit | A date range unit for the date filter. | Optional | 
| threat_intel_indicator_type_value | The string filter value. | Optional | 
| threat_intel_indicator_type_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| threat_intel_indicator_value_value | The string filter value. | Optional | 
| threat_intel_indicator_value_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| threat_intel_indicator_category_value | The string filter value. | Optional | 
| threat_intel_indicator_category_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| threat_intel_indicator_last_observed_at_start | A start date for the date filter. | Optional | 
| threat_intel_indicator_last_observed_at_end | An end date for the date filter. | Optional | 
| date_range_unit | A date range unit for the date filter. | Optional | 
| threat_intel_indicator_source_value | The string filter value. | Optional | 
| threat_intel_indicator_source_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| threat_intel_indicator_source_url_value | The string filter value. | Optional | 
| threat_intel_indicator_source_url_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| resource_type_value | The string filter value. | Optional | 
| resource_type_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| resource_id_value | The string filter value. | Optional | 
| resource_id_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| resource_partition_value | The string filter value. | Optional | 
| resource_partition_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| resource_region_value | The string filter value. | Optional | 
| resource_region_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| resource_tags_key | The key of the map filter. | Optional | 
| resource_tags_value | The value for the key in the map filter. | Optional | 
| resource_tags_comparison | The condition to apply to a key value when querying for findings with a map filter. | Optional | 
| resource_aws_ec2_instance_type_value | The string filter value. | Optional | 
| resource_aws_ec2_instance_type_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| resource_aws_ec2_instance_image_id_value | The string filter value. | Optional | 
| resource_aws_ec2_instance_image_id_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| resource_aws_ec2_instance_ip_v4_addresses_cidr | A finding's CIDR value. | Optional | 
| resource_aws_ec2_instance_ip_v6_addresses_cidr | A finding's CIDR value. | Optional | 
| resource_aws_ec2_instance_key_name_value | The string filter value. | Optional | 
| resource_aws_ec2_instance_key_name_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| resource_aws_ec2_instance_iam_instance_profile_arn_value | The string filter value. | Optional | 
| resource_aws_ec2_instance_iam_instance_profile_arn_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| resource_aws_ec2_instance_vpc_id_value | The string filter value. | Optional | 
| resource_aws_ec2_instance_vpc_id_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| resource_aws_ec2_instance_subnet_id_value | The string filter value. | Optional | 
| resource_aws_ec2_instance_subnet_id_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| resource_aws_ec2_instance_launched_at_start | A start date for the date filter. | Optional | 
| resource_aws_ec2_instance_launched_at_end | An end date for the date filter. | Optional | 
| date_range_unit | A date range unit for the date filter. | Optional | 
| resource_aws_s3_bucket_owner_id_value | The string filter value. | Optional | 
| resource_aws_s3_bucket_owner_id_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| resource_aws_s3_bucket_owner_name_value | The string filter value. | Optional | 
| resource_aws_s3_bucket_owner_name_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| resource_aws_iam_access_key_user_name_value | The string filter value. | Optional | 
| resource_aws_iam_access_key_user_name_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| resource_aws_iam_access_key_status_value | The string filter value. | Optional | 
| resource_aws_iam_access_key_status_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| resource_aws_iam_access_key_created_at_start | A start date for the date filter. | Optional | 
| resource_aws_iam_access_key_created_at_end | An end date for the date filter. | Optional | 
| date_range_unit | A date range unit for the date filter. | Optional | 
| resource_container_name_value | The string filter value. | Optional | 
| resource_container_name_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| resource_container_image_id_value | The string filter value. | Optional | 
| resource_container_image_id_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| resource_container_image_name_value | The string filter value. | Optional | 
| resource_container_image_name_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| resource_container_launched_at_start | A start date for the date filter. | Optional | 
| resource_container_launched_at_end | An end date for the date filter. | Optional | 
| date_range_unit | A date range unit for the date filter. | Optional | 
| resource_details_other_key | The key of the map filter. | Optional | 
| resource_details_other_value | The value for the key in the map filter. | Optional | 
| resource_details_other_comparison | The condition to apply to a key value when querying for findings with a map filter. | Optional | 
| compliance_status_value | The string filter value. | Optional | 
| compliance_status_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| verification_state_value | The string filter value. | Optional | 
| verification_state_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| workflow_state_value | The string filter value. | Optional | 
| workflow_state_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| record_state_value | The string filter value. | Optional | 
| record_state_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| related_findings_product_arn_value | The string filter value. | Optional | 
| related_findings_product_arn_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| related_findings_id_value | The string filter value. | Optional | 
| related_findings_id_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| note_text_value | The string filter value. | Optional | 
| note_text_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| note_updated_at_start | A start date for the date filter. | Optional | 
| note_updated_at_end | An end date for the date filter. | Optional | 
| date_range_unit | A date range unit for the date filter. | Optional | 
| note_updated_by_value | The string filter value. | Optional | 
| note_updated_by_comparison | The condition to be applied to a string value when querying for findings. | Optional | 
| keyword_value | A value for the keyword. | Optional | 
| sort_criteria_field | The finding attribute used to sort findings. | Optional | 
| sort_criteria_sort_order | The order used to sort findings. | Optional | 
| next_token | Paginates results. On your first call to the GetFindings operation, set the value of this parameter to NULL. For subsequent calls to the operation, fill nextToken in the request with the value of nextToken from the previous response to continue listing data. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-SecurityHub.Findings.SchemaVersion | string | The schema version that a finding is formatted for. | 
| AWS-SecurityHub.Findings.Id | string | The security findings provider-specific identifier for a finding. | 
| AWS-SecurityHub.Findings.ProductArn | string | The ARN generated by Security Hub that uniquely identifies a third-party company (security-findings provider) after this provider's product (solution that generates findings) is registered with Security Hub.  | 
| AWS-SecurityHub.Findings.GeneratorId | string | The identifier for the solution-specific component (a discrete unit of logic) that generated a finding. In various security-findings providers' solutions, this generator can be called a rule, a check, a detector, a plug-in, etc.  | 
| AWS-SecurityHub.Findings.AwsAccountId | string | The AWS account ID that a finding is generated in. | 
| AWS-SecurityHub.Findings.Types | Unknown | One or more finding types in the format of namespace/category/classifier that classify a finding. Valid namespace values are: Software and Configuration Checks | TTPs | Effects | Unusual Behaviors | Sensitive Data Identifications | 
| AWS-SecurityHub.Findings.FirstObservedAt | date | An ISO8601-formatted timestamp that indicates when the security-findings provider first observed the potential security issue that a finding captured. | 
| AWS-SecurityHub.Findings.LastObservedAt | date | An ISO8601-formatted timestamp that indicates when the security-findings provider most recently observed the potential security issue that a finding captured. | 
| AWS-SecurityHub.Findings.CreatedAt | date | An ISO8601-formatted timestamp that indicates when the security-findings provider created the potential security issue that a finding captured. | 
| AWS-SecurityHub.Findings.UpdatedAt | date | An ISO8601-formatted timestamp that indicates when the security-findings provider last updated the finding record.  | 
| AWS-SecurityHub.Findings.Severity.Product | number | The native severity as defined by the AWS service or integrated partner product that generated the finding. | 
| AWS-SecurityHub.Findings.Severity.Normalized | number | The normalized severity of a finding. | 
| AWS-SecurityHub.Findings.Severity | Unknown | A finding's severity. | 
| AWS-SecurityHub.Findings.Confidence | number | A finding's confidence. Confidence is defined as the likelihood that a finding accurately identifies the behavior or issue that it was intended to identify. Confidence is scored on a 0-100 basis using a ratio scale, where 0 means zero percent confidence and 100 means 100 percent confidence. | 
| AWS-SecurityHub.Findings.Criticality | number | The level of importance assigned to the resources associated with the finding. A score of 0 means that the underlying resources have no criticality, and a score of 100 is reserved for the most critical resources. | 
| AWS-SecurityHub.Findings.Title | string | A finding's title.  In this release, Title is a required property.  | 
| AWS-SecurityHub.Findings.Description | string | A finding's description.  In this release, Description is a required property.  | 
| AWS-SecurityHub.Findings.Remediation.Recommendation.Text | string | Describes the recommended steps to take to remediate an issue identified in a finding. | 
| AWS-SecurityHub.Findings.Remediation.Recommendation.Url | string | A URL to a page or site that contains information about how to remediate a finding. | 
| AWS-SecurityHub.Findings.Remediation.Recommendation | Unknown | A recommendation on the steps to take to remediate the issue identified by a finding. | 
| AWS-SecurityHub.Findings.Remediation | Unknown | A data type that describes the remediation options for a finding. | 
| AWS-SecurityHub.Findings.SourceUrl | string | A URL that links to a page about the current finding in the security-findings provider's solution. | 
| AWS-SecurityHub.Findings.ProductFields | Unknown | A data type where security-findings providers can include additional solution-specific details that aren't part of the defined AwsSecurityFinding format. | 
| AWS-SecurityHub.Findings.UserDefinedFields | Unknown | A list of name/value string pairs associated with the finding. These are custom, user-defined fields added to a finding.  | 
| AWS-SecurityHub.Findings.Name | string | The name of the malware that was observed. | 
| AWS-SecurityHub.Findings.Type | string | The type of the malware that was observed. | 
| AWS-SecurityHub.Findings.Path | string | The file system path of the malware that was observed. | 
| AWS-SecurityHub.Findings.State | string | The state of the malware that was observed. | 
| AWS-SecurityHub.Findings | string | The findings that matched the filters specified in the request. | 
| AWS-SecurityHub.Findings.Network.Direction | string | The direction of network traffic associated with a finding. | 
| AWS-SecurityHub.Findings.Network.Protocol | string | The protocol of network-related information about a finding. | 
| AWS-SecurityHub.Findings.Network.SourceIpV4 | string | The source IPv4 address of network-related information about a finding. | 
| AWS-SecurityHub.Findings.Network.SourceIpV6 | string | The source IPv6 address of network-related information about a finding. | 
| AWS-SecurityHub.Findings.Network.SourcePort | number | The source port of network-related information about a finding. | 
| AWS-SecurityHub.Findings.Network.SourceDomain | string | The source domain of network-related information about a finding. | 
| AWS-SecurityHub.Findings.Network.SourceMac | string | The source media access control (MAC) address of network-related information about a finding. | 
| AWS-SecurityHub.Findings.Network.DestinationIpV4 | string | The destination IPv4 address of network-related information about a finding. | 
| AWS-SecurityHub.Findings.Network.DestinationIpV6 | string | The destination IPv6 address of network-related information about a finding. | 
| AWS-SecurityHub.Findings.Network.DestinationPort | number | The destination port of network-related information about a finding. | 
| AWS-SecurityHub.Findings.Network.DestinationDomain | string | The destination domain of network-related information about a finding. | 
| AWS-SecurityHub.Findings.Network | string | The details of network-related information about a finding. | 
| AWS-SecurityHub.Findings.Process.Name | string | The name of the process. | 
| AWS-SecurityHub.Findings.Process.Path | string | The path to the process executable. | 
| AWS-SecurityHub.Findings.Process.Pid | number | The process ID. | 
| AWS-SecurityHub.Findings.Process.ParentPid | number | The parent process ID. | 
| AWS-SecurityHub.Findings.Process.LaunchedAt | date | The date/time that the process was launched. | 
| AWS-SecurityHub.Findings.Process.TerminatedAt | date | The date and time when the process was terminated. | 
| AWS-SecurityHub.Findings.Process | Unknown | The details of process-related information about a finding. | 
| AWS-SecurityHub.Findings.ThreatIntelIndicators.Type | string | The type of a threat intel indicator. | 
| AWS-SecurityHub.Findings.ThreatIntelIndicators.Value | string | The value of a threat intel indicator. | 
| AWS-SecurityHub.Findings.ThreatIntelIndicators.Category | string | The category of a threat intel indicator. | 
| AWS-SecurityHub.Findings.ThreatIntelIndicators.LastObservedAt | string | The date and time when the most recent instance of a threat intel indicator was observed. | 
| AWS-SecurityHub.Findings.ThreatIntelIndicators.Source | string | The source of the threat intel indicator. | 
| AWS-SecurityHub.Findings.ThreatIntelIndicators.SourceUrl | string | The URL to the page or site where you can get more information about the threat intel indicator. | 
| AWS-SecurityHub.Findings.ThreatIntelIndicators | string | Threat intel details related to a finding. | 
| AWS-SecurityHub.Findings.Resources.Type | string | The type of the resource that details are provided for. | 
| AWS-SecurityHub.Findings.Resources.Id | string | The canonical identifier for the given resource type. | 
| AWS-SecurityHub.Findings.Resources.Partition | string | The canonical AWS partition name that the Region is assigned to. | 
| AWS-SecurityHub.Findings.Resources.Region | string | The canonical AWS external Region name where this resource is located. | 
| AWS-SecurityHub.Findings.Resources.Tags | string | A list of AWS tags associated with a resource at the time the finding was processed. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsCloudFrontDistribution.DomainName | string | The domain name corresponding to the distribution. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsCloudFrontDistribution.ETag | string | The entity tag is a hash of the object. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsCloudFrontDistribution.LastModifiedTime | date | The date and time that the distribution was last modified. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsCloudFrontDistribution.Logging.Bucket | string | The Amazon S3 bucket to store the access logs in. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsCloudFrontDistribution.Logging.Enabled | string | With this field, you can enable or disable the selected distribution. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsCloudFrontDistribution.Logging.IncludeCookies | string | Specifies whether you want CloudFront to include cookies in access logs. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsCloudFrontDistribution.Logging.Prefix | string | An optional string that you want CloudFront to prefix to the access log filenames for this distribution. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsCloudFrontDistribution.Logging | string | A complex type that controls whether access logs are written for the distribution. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsCloudFrontDistribution.Origins.Items.DomainName | string | Amazon S3 origins: The DNS name of the Amazon S3 bucket from which you want CloudFront to get objects for this origin. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsCloudFrontDistribution.Origins.Items.Id | string | A unique identifier for the origin or origin group. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsCloudFrontDistribution.Origins.Items.OriginPath | string | An optional element that causes CloudFront to request your content from a directory in your Amazon S3 bucket or your custom origin. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsCloudFrontDistribution.Origins.Items | string | A complex type that contains origins or origin groups for this distribution. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsCloudFrontDistribution.Origins | string | A complex type that contains information about origins for this distribution. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsCloudFrontDistribution.Status | string | Indicates the current status of the distribution. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsCloudFrontDistribution.WebAclId | string | A unique identifier that specifies the AWS WAF web ACL, if any, to associate with this distribution. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsCloudFrontDistribution | string | Details about a CloudFront distribution. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsEc2Instance.Type | string | The instance type of the instance.  | 
| AWS-SecurityHub.Findings.Resources.Details.AwsEc2Instance.ImageId | string | The Amazon Machine Image (AMI) ID of the instance. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsEc2Instance.IpV4Addresses | string | The IPv4 addresses associated with the instance. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsEc2Instance.IpV6Addresses | string | The IPv6 addresses associated with the instance. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsEc2Instance.KeyName | string | The key name associated with the instance. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsEc2Instance.IamInstanceProfileArn | string | The IAM profile ARN of the instance. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsEc2Instance.VpcId | string | The identifier of the VPC that the instance was launched in. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsEc2Instance.SubnetId | string | The identifier of the subnet that the instance was launched in. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsEc2Instance.LaunchedAt | date | The date/time the instance was launched. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsEc2Instance | string | Details about an Amazon EC2 instance related to a finding. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsElbv2LoadBalancer.AvailabilityZones.ZoneName | string | The name of the Availability Zone. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsElbv2LoadBalancer.AvailabilityZones.SubnetId | string | The ID of the subnet. You can specify one subnet per Availability Zone. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsElbv2LoadBalancer.AvailabilityZones | string | The Availability Zones for the load balancer. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsElbv2LoadBalancer.CanonicalHostedZoneId | string | The ID of the Amazon Route 53 hosted zone associated with the load balancer. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsElbv2LoadBalancer.CreatedTime | date | The date and time the load balancer was created. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsElbv2LoadBalancer.DNSName | string | The public DNS name of the load balancer. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsElbv2LoadBalancer.IpAddressType | string | The type of IP addresses used by the subnets for your load balancer. The possible values are ipv4 (for IPv4 addresses) and dualstack (for IPv4 and IPv6 addresses). | 
| AWS-SecurityHub.Findings.Resources.Details.AwsElbv2LoadBalancer.Scheme | string | The nodes of an Internet-facing load balancer have public IP addresses. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsElbv2LoadBalancer.SecurityGroups | string | The IDs of the security groups for the load balancer. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsElbv2LoadBalancer.State.Code | string | The state code. The initial state of the load balancer is provisioning. After the load balancer is fully set up and ready to route traffic, its state is active. If the load balancer could not be set up, its state is failed.  | 
| AWS-SecurityHub.Findings.Resources.Details.AwsElbv2LoadBalancer.State.Reason | string | A description of the state. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsElbv2LoadBalancer.State | string | The state of the load balancer. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsElbv2LoadBalancer.Type | string | The type of load balancer. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsElbv2LoadBalancer.VpcId | string | The ID of the VPC for the load balancer. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsElbv2LoadBalancer | string | Details about a load balancer. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsS3Bucket.OwnerId | string | The canonical user ID of the owner of the S3 bucket. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsS3Bucket.OwnerName | string | The display name of the owner of the S3 bucket. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsS3Bucket | string | Details about an Amazon S3 Bucket related to a finding. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsIamAccessKey.UserName | string | The user associated with the IAM access key related to a finding. The UserName parameter has been replaced with the PrincipalName parameter because access keys can also be assigned to principals that are not IAM users. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsIamAccessKey.Status | string | The status of the IAM access key related to a finding. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsIamAccessKey.CreatedAt | date | The creation date/time of the IAM access key related to a finding. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsIamAccessKey.PrincipalId | string | The ID of the principal associated with an access key. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsIamAccessKey.PrincipalType | string | The type of principal associated with an access key. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsIamAccessKey.PrincipalName | string | The name of the principal. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsIamAccessKey | string | Details about an IAM access key related to a finding. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsIamRole.AssumeRolePolicyDocument | string | The trust policy that grants permission to assume the role. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsIamRole.CreateDate | date | The date and time, in ISO 8601 date-time format, when the role was created. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsIamRole.RoleId | string | The stable and unique string identifying the role. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsIamRole.RoleName | string | The friendly name that identifies the role. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsIamRole.MaxSessionDuration | number | The maximum session duration (in seconds) that you want to set for the specified role. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsIamRole.Path | string | The path to the role. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsIamRole | string | Details about an IAM role. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsKmsKey.AWSAccountId | string | The twelve-digit account ID of the AWS account that owns the CMK. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsKmsKey.CreationDate | date | The date and time when the CMK was created. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsKmsKey.KeyId | string | The globally unique identifier for the CMK. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsKmsKey.KeyManager | string | The manager of the CMK. CMKs in your AWS account are either customer managed or AWS managed. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsKmsKey.KeyState | string | The state of the CMK. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsKmsKey.Origin | string | The source of the CMK's key material. When this value is AWS\_KMS, AWS KMS created the key material. When this value is EXTERNAL, the key material was imported from your existing key management infrastructure or the CMK lacks key material. When this value is AWS\_CLOUDHSM, the key material was created in the AWS CloudHSM cluster associated with a custom key store. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsKmsKey | string | Details about a KMS key. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.Code.S3Bucket | string | An Amazon S3 bucket in the same AWS Region as your function. The bucket can be in a different AWS account. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.Code.S3Key | string | The Amazon S3 key of the deployment package. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.Code.S3ObjectVersion | string | For versioned objects, the version of the deployment package object to use. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.Code.ZipFile | string | The base64-encoded contents of the deployment package. AWS SDK and AWS CLI clients handle the encoding for you. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.Code | string | An AwsLambdaFunctionCode object. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.CodeSha256 | string | The SHA256 hash of the function's deployment package. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.DeadLetterConfig.TargetArn | string | The Amazon Resource Name (ARN) of an Amazon SQS queue or Amazon SNS topic. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.DeadLetterConfig | string | The function's dead letter queue. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.Environment.Variables | string | Environment variable key-value pairs. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.Environment.Error.ErrorCode | string | The error code. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.Environment.Error.Message | string | The error message. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.Environment.Error | string | An AwsLambdaFunctionEnvironmentError object. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.Environment | string | The function's environment variables. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.FunctionName | string | The name of the function. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.Handler | string | The function that Lambda calls to begin executing your function. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.KmsKeyArn | string | The KMS key that's used to encrypt the function's environment variables. This key is only returned if you've configured a customer managed CMK. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.LastModified | date | The date and time that the function was last updated, in ISO-8601 format (YYYY-MM-DDThh:mm:ss.sTZD). | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.Layers.Arn | string | The Amazon Resource Name (ARN) of the function layer. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.Layers.CodeSize | number | The size of the layer archive in bytes. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.Layers | string | The function's layers. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.MasterArn | string | For Lambda@Edge functions, the ARN of the master function. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.MemorySize | number | The memory that's allocated to the function. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.RevisionId | string | The latest updated revision of the function or alias. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.Role | string | The function's execution role. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.Runtime | string | The runtime environment for the Lambda function. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.Timeout | number | The amount of time that Lambda allows a function to run before stopping it. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.TracingConfig.Mode | string | The tracing mode. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.TracingConfig | string | The function's AWS X-Ray tracing configuration. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.VpcConfig.SecurityGroupIds | string | A list of VPC security groups IDs. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.VpcConfig.SubnetIds | string | A list of VPC subnet IDs. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.VpcConfig.VpcId | string | The ID of the VPC. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.VpcConfig | string | The function's networking configuration. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction.Version | string | The version of the Lambda function. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsLambdaFunction | string | Details about a Lambda function. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsSnsTopic.KmsMasterKeyId | string | The ID of an AWS-managed customer master key (CMK) for Amazon SNS or a custom CMK. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsSnsTopic.Subscription.Endpoint | string | The subscription's endpoint (format depends on the protocol). | 
| AWS-SecurityHub.Findings.Resources.Details.AwsSnsTopic.Subscription.Protocol | string | The subscription's protocol. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsSnsTopic.Subscription | string | Subscription is an embedded property that describes the subscription endpoints of an Amazon SNS topic. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsSnsTopic.TopicName | string | The name of the topic. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsSnsTopic.Owner | string | The subscription's owner. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsSnsTopic | string | Details about an SNS topic. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsSqsQueue.KmsDataKeyReusePeriodSeconds | number | The length of time, in seconds, for which Amazon SQS can reuse a data key to encrypt or decrypt messages before calling AWS KMS again. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsSqsQueue.KmsMasterKeyId | string | The ID of an AWS-managed customer master key (CMK) for Amazon SQS or a custom CMK. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsSqsQueue.QueueName | string | The name of the new queue. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsSqsQueue.DeadLetterTargetArn | string | The Amazon Resource Name (ARN) of the dead-letter queue to which Amazon SQS moves messages after the value of maxReceiveCount is exceeded. | 
| AWS-SecurityHub.Findings.Resources.Details.AwsSqsQueue | string | Details about an SQS queue. | 
| AWS-SecurityHub.Findings.Resources.Details.Container.Name | string | The name of the container related to a finding. | 
| AWS-SecurityHub.Findings.Resources.Details.Container.ImageId | string | The identifier of the image related to a finding. | 
| AWS-SecurityHub.Findings.Resources.Details.Container.ImageName | string | The name of the image related to a finding. | 
| AWS-SecurityHub.Findings.Resources.Details.Container.LaunchedAt | date | The date and time when the container started. | 
| AWS-SecurityHub.Findings.Resources.Details.Container | string | Details about a container resource related to a finding. | 
| AWS-SecurityHub.Findings.Resources.Details.Other | string | Details about a resource that doesn't have a specific type defined. | 
| AWS-SecurityHub.Findings.Resources.Details | string | Additional details about the resource related to a finding. | 
| AWS-SecurityHub.Findings.Resources | string | A set of resource data types that describe the resources that the finding refers to. | 
| AWS-SecurityHub.Findings.Compliance.Status | string | The result of a compliance check. | 
| AWS-SecurityHub.Findings.Compliance | string | This data type is exclusive to findings that are generated as the result of a check run against a specific rule in a supported standard (for example, CIS AWS Foundations). Contains compliance-related finding details. | 
| AWS-SecurityHub.Findings.VerificationState | string | Indicates the veracity of a finding. | 
| AWS-SecurityHub.Findings.WorkflowState | string | The workflow state of a finding. | 
| AWS-SecurityHub.Findings.RecordState | string | The record state of a finding. | 
| AWS-SecurityHub.Findings.RelatedFindings.ProductArn | string | The ARN of the product that generated a related finding. | 
| AWS-SecurityHub.Findings.RelatedFindings.Id | string | The product-generated identifier for a related finding. | 
| AWS-SecurityHub.Findings.RelatedFindings | string | A list of related findings. | 
| AWS-SecurityHub.Findings.Note.Text | string | The text of a note. | 
| AWS-SecurityHub.Findings.Note.UpdatedBy | string | The principal that created a note. | 
| AWS-SecurityHub.Findings.Note.UpdatedAt | date | The timestamp of when the note was updated. | 
| AWS-SecurityHub.Findings.Note | string | A user-defined note added to a finding. | 
| AWS-SecurityHub.NextToken | string | The token that is required for pagination. | 


##### Command Example
```!aws-securityhub-get-findings```

##### Context Example
```
{
    "AWS-SecurityHub": [
        {
            "LastObservedAt": "2020-07-22T11:30:13.952Z", 
            "FirstObservedAt": "2020-07-05T13:14:29.111Z", 
            "GeneratorId": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.8", 
            "Description": "Password policies are, in part, used to enforce password complexity requirements. IAM password policies can be used to ensure passwords are comprised of different character sets. It is recommended that the password policy require at least one number.", 
            "Workflow": {
                "Status": "NEW"
            }, 
            "Title": "1.8 Ensure IAM password policy requires at least one number", 
            "UpdatedAt": "2020-07-22T11:28:46.637Z", 
            "Compliance": {
                "Status": "WARNING", 
                "StatusReasons": [
                    {
                        "ReasonCode": "CONFIG_ACCESS_DENIED", 
                        "Description": "Unable to describe the supporting AWS Config Rule, Please verify that you have enabled AWS Config."
                    }
                ]
            }, 
            "ProductArn": "arn:aws:securityhub:eu-west-1::product/aws/securityhub", 
            "ProductFields": {
                "aws/securityhub/SeverityLabel": "MEDIUM", 
                "StandardsGuideSubscriptionArn": "arn:aws:securityhub:eu-west-1:676921422616:subscription/cis-aws-foundations-benchmark/v/1.2.0", 
                "RecommendationUrl": "https://docs.aws.amazon.com/console/securityhub/standards-cis-1.8/remediation", 
                "RuleId": "1.8", 
                "RelatedAWSResources:0/name": "securityhub-iam-password-policy-number-check-a08618e1", 
                "StandardsControlArn": "arn:aws:securityhub:eu-west-1:676921422616:control/cis-aws-foundations-benchmark/v/1.2.0/1.8", 
                "RelatedAWSResources:0/type": "AWS::Config::ConfigRule", 
                "aws/securityhub/ProductName": "Security Hub", 
                "aws/securityhub/FindingId": "arn:aws:securityhub:eu-west-1::product/aws/securityhub/arn:aws:securityhub:eu-west-1:676921422616:subscription/cis-aws-foundations-benchmark/v/1.2.0/1.8/finding/d1d15683-7fbd-4b82-8eed-3af50785cdf6", 
                "aws/securityhub/annotation": "Unable to describe the supporting AWS Config Rule, Please verify that you have enabled AWS Config.", 
                "StandardsGuideArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0", 
                "aws/securityhub/CompanyName": "AWS"
            }, 
            "WorkflowState": "NEW", 
            "Resources": [
                {
                    "Region": "eu-west-1", 
                    "Partition": "aws", 
                    "Type": "AwsAccount", 
                    "Id": "AWS::::Account:676921422616"
                }
            ], 
            "Types": [
                "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark"
            ], 
            "Remediation": {
                "Recommendation": {
                    "Url": "https://docs.aws.amazon.com/console/securityhub/standards-cis-1.8/remediation", 
                    "Text": "For directions on how to fix this issue, please consult the AWS Security Hub CIS documentation."
                }
            }, 
            "RecordState": "ACTIVE", 
            "SchemaVersion": "2018-10-08", 
            "Severity": {
                "Product": 40, 
                "Normalized": 40, 
                "Original": "MEDIUM", 
                "Label": "MEDIUM"
            }, 
            "Id": "arn:aws:securityhub:eu-west-1:676921422616:subscription/cis-aws-foundations-benchmark/v/1.2.0/1.8/finding/d1d15683-7fbd-4b82-8eed-3af50785cdf6", 
            "CreatedAt": "2020-07-05T13:14:29.111Z", 
            "AwsAccountId": "676921422616"
        }
    ]
}
```

##### Human Readable Output
### AWS SecurityHub GetFindings
|AwsAccountId|Compliance|CreatedAt|Description|FirstObservedAt|GeneratorId|Id|LastObservedAt|ProductArn|ProductFields|RecordState|Remediation|Resources|SchemaVersion|Severity|Title|Types|UpdatedAt|Workflow|WorkflowState|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 676921422616 | Status: WARNING,StatusReasons: {'ReasonCode': 'CONFIG_ACCESS_DENIED', 'Description': 'Unable to describe the supporting AWS Config Rule, Please verify that you have enabled AWS Config.'} | 2020-07-05T13:14:29.111Z | Password policies are, in part, used to enforce password complexity requirements. IAM password policies can be used to ensure passwords are comprised of different character sets. It is recommended that the password policy require at least one number. | 2020-07-05T13:14:29.111Z | arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.8 | arn:aws:securityhub:eu-west-1:676921422616:subscription/cis-aws-foundations-benchmark/v/1.2.0/1.8/finding/d1d15683-7fbd-4b82-8eed-3af50785cdf6 | 2020-07-22T11:30:13.952Z | arn:aws:securityhub:eu-west-1::product/aws/securityhub | StandardsGuideArn: arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0,StandardsGuideSubscriptionArn: arn:aws:securityhub:eu-west-1:676921422616:subscription/cis-aws-foundations-benchmark/v/1.2.0,RuleId: 1.8,RecommendationUrl: https://docs.aws.amazon.com/console/securityhub/standards-cis-1.8/remediation,RelatedAWSResources:0/name: securityhub-iam-password-policy-number-check-a08618e1,RelatedAWSResources:0/type: AWS::Config::ConfigRule,StandardsControlArn: arn:aws:securityhub:eu-west-1:676921422616:control/cis-aws-foundations-benchmark/v/1.2.0/1.8,aws/securityhub/SeverityLabel: MEDIUM,aws/securityhub/ProductName: Security Hub,aws/securityhub/CompanyName: AWS,aws/securityhub/annotation: Unable to describe the supporting AWS Config Rule, Please verify that you have enabled AWS Config.,aws/securityhub/FindingId: arn:aws:securityhub:eu-west-1::product/aws/securityhub/arn:aws:securityhub:eu-west-1:676921422616:subscription/cis-aws-foundations-benchmark/v/1.2.0/1.8/finding/d1d15683-7fbd-4b82-8eed-3af50785cdf6 | ACTIVE | Recommendation: {"Text": "For directions on how to fix this issue, please consult the AWS Security Hub CIS documentation.", "Url": "https://docs.aws.amazon.com/console/securityhub/standards-cis-1.8/remediation"} | {'Type': 'AwsAccount', 'Id': 'AWS::::Account:676921422616', 'Partition': 'aws', 'Region': 'eu-west-1'} | 2018-10-08 | Product: 40,Label: MEDIUM,Normalized: 40,Original: MEDIUM | 1.8 Ensure IAM password policy requires at least one number | Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark | 2020-07-22T11:28:46.637Z | Status: NEW | NEW |

### 5. aws-securityhub-get-master-account
---
Provides the details for the Security Hub master account to the current member account.

##### Base Command

`aws-securityhub-get-master-account`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-SecurityHub.Master.AccountId | string | The account ID of the Security Hub master account that the invitation was sent from. | 
| AWS-SecurityHub.Master.InvitationId | string | The ID of the invitation sent to the member account. | 
| AWS-SecurityHub.Master.InvitedAt | date | The timestamp of when the invitation was sent. | 
| AWS-SecurityHub.Master.MemberStatus | string | The current status of the association between member and master accounts. | 
| AWS-SecurityHub.Master | Unknown | A list of details about the Security Hub master account for the current member account.  | 


##### Command Example
```!aws-securityhub-get-master-account```

##### Context Example
```
{
    "AWS-SecurityHub": {}
}
```

##### Human Readable Output
### AWS SecurityHub GetMasterAccount
**No entries.**


### 6. aws-securityhub-list-members
---
Lists details about all member accounts for the current Security Hub master account.

##### Base Command

`aws-securityhub-list-members`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| only_associated | <p>Specifies which member accounts the response includes based on their relationship status with the master account. The default value is <code>TRUE</code>. If <code>onlyAssociated</code> is set to <code>TRUE</code>, the response includes member accounts whose relationship status with the master is set to <code>ENABLED</code> or <code>DISABLED</code>. If <code>onlyAssociated</code> is set to <code>FALSE</code>, the response includes all existing member accounts. </p> | Optional | 
| next_token | Paginates results. Set the value of this parameter to NULL on your first call to the ListMembers operation. For subsequent calls to the operation, fill nextToken in the request with the value of nextToken from the previous response to continue listing data. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-SecurityHub.Members.AccountId | string | The AWS account ID of the member account. | 
| AWS-SecurityHub.Members.Email | string | The email address of the member account. | 
| AWS-SecurityHub.Members.MasterId | string | The AWS account ID of the Security Hub master account associated with this member account. | 
| AWS-SecurityHub.Members.MemberStatus | string | The status of the relationship between the member account and its master account. | 
| AWS-SecurityHub.Members.InvitedAt | date | A timestamp for the date and time when the invitation was sent to the member account. | 
| AWS-SecurityHub.Members.UpdatedAt | date | The timestamp for the date and time when the member account was updated. | 
| AWS-SecurityHub.Members | Unknown | Member details returned by the operation. | 
| AWS-SecurityHub.NextToken | string | The token that is required for pagination. | 


##### Command Example
```!aws-securityhub-list-members```

##### Context Example
```
{
    "AWS-SecurityHub": {
        "Members": []
    }
}
```

##### Human Readable Output
### AWS SecurityHub ListMembers
**No entries.**

