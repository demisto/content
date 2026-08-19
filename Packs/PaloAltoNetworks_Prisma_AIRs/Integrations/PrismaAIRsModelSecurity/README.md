Scan and govern AI models with Palo Alto Networks Prisma AIRS AI Model Security: model scans, evaluations, violations, labels, model groups, and security rules.
This integration was integrated and tested with version xx of Palo Alto Networks Prisma AIRS - AI Model Security.

## Configure Palo Alto Networks Prisma AIRS - AI Model Security in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| API Client ID |  | True |
| API Client Secret |  | True |
| Tenant Services Group ID | Default Tenant Services Group ID to use for API calls. Example: 1234567890. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### prisma-airs-model-security-scans-list

***
List all model security scans.

#### Base Command

`prisma-airs-model-security-scans-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of scans to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityScan.uuid | String | The scan UUID. | 
| PrismaAIRs.ModelSecurityScan.model_uri | String | The model URI that was scanned. | 
| PrismaAIRs.ModelSecurityScan.eval_outcome | String | The evaluation outcome \(ALLOWED, BLOCKED\). | 
| PrismaAIRs.ModelSecurityScan.source_type | String | The source type \(HUGGING_FACE, LOCAL, etc.\). | 
| PrismaAIRs.ModelSecurityScan.security_group_uuid | String | The security group UUID. | 
| PrismaAIRs.ModelSecurityScan.security_group_name | String | The security group name. | 
| PrismaAIRs.ModelSecurityScan.scan_origin | String | The scan origin. | 
| PrismaAIRs.ModelSecurityScan.created_at | Date | The creation timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityScan.updated_at | Date | The last update timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityScan.created_by | String | The user who created the scan. | 

### prisma-airs-model-security-scans-create

***
Create a new model security scan to check a model for supply chain security issues. Scan is asynchronous - use scans-get to poll for completion.

#### Base Command

`prisma-airs-model-security-scans-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model_uri | The model URI (HuggingFace URL like https://huggingface.co/microsoft/DialoGPT-medium or local path). | Required | 
| security_group_uuid | The security group UUID to use for scanning. | Required | 
| scan_origin | The scan origin identifier. Possible values are: MODEL_SECURITY_SDK, MODEL_SECURITY_API, MODEL_SECURITY_FRONTEND, HUGGING_FACE. Default is MODEL_SECURITY_API. | Optional | 
| model_name | The model name (optional metadata). | Optional | 
| model_author | The model author (optional metadata). | Optional | 
| model_version | The model version (optional metadata). | Optional | 
| labels | The labels to tag the scan, as a JSON array of key/value objects, e.g. [{"key": "env", "value": "prod"}, {"key": "team", "value": "ml"}]. Keys (&lt;=128 chars) and values (&lt;=256 chars) must match ^[a-zA-Z0-9_-]+$. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityScanCreate.uuid | String | The scan UUID. | 
| PrismaAIRs.ModelSecurityScanCreate.labels | Unknown | The labels \(key/value pairs\) applied to the scan. | 
| PrismaAIRs.ModelSecurityScanCreate.model_uri | String | The model URI that was scanned. | 
| PrismaAIRs.ModelSecurityScanCreate.security_group_uuid | String | The security group UUID used for scanning. | 
| PrismaAIRs.ModelSecurityScanCreate.security_group_name | String | The security group name. | 
| PrismaAIRs.ModelSecurityScanCreate.scan_origin | String | The scan origin. | 
| PrismaAIRs.ModelSecurityScanCreate.eval_outcome | String | The evaluation outcome \(PENDING initially, then ALLOWED/BLOCKED\). | 
| PrismaAIRs.ModelSecurityScanCreate.source_type | String | The model source type. | 
| PrismaAIRs.ModelSecurityScanCreate.owner | String | The scan owner. | 
| PrismaAIRs.ModelSecurityScanCreate.created_at | Date | The creation timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityScanCreate.updated_at | Date | The last update timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityScanCreate.tsg_id | String | The tenant Service Group ID. | 
| PrismaAIRs.ModelSecurityScanCreate.rules_passed | Number | The number of rules that passed. | 
| PrismaAIRs.ModelSecurityScanCreate.rules_failed | Number | The number of rules that failed. | 
| PrismaAIRs.ModelSecurityScanCreate.total_rules | Number | The total number of rules evaluated. | 

### prisma-airs-model-security-scans-get

***
Get model security scan status and results. Use this to poll scan completion after scans-create.

#### Base Command

`prisma-airs-model-security-scans-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The scan UUID to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityScanGet.uuid | String | The scan UUID. | 
| PrismaAIRs.ModelSecurityScanGet.model_uri | String | The model URI that was scanned. | 
| PrismaAIRs.ModelSecurityScanGet.security_group_uuid | String | The security group UUID used for scanning. | 
| PrismaAIRs.ModelSecurityScanGet.security_group_name | String | The security group name. | 
| PrismaAIRs.ModelSecurityScanGet.scan_origin | String | The scan origin. | 
| PrismaAIRs.ModelSecurityScanGet.eval_outcome | String | The evaluation outcome \(PENDING/ALLOWED/BLOCKED\). | 
| PrismaAIRs.ModelSecurityScanGet.source_type | String | The model source type. | 
| PrismaAIRs.ModelSecurityScanGet.owner | String | The scan owner. | 
| PrismaAIRs.ModelSecurityScanGet.created_at | Date | The creation timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityScanGet.updated_at | Date | The last update timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityScanGet.created_by | String | The user who created the scan. | 
| PrismaAIRs.ModelSecurityScanGet.tsg_id | String | The tenant Service Group ID. | 
| PrismaAIRs.ModelSecurityScanGet.model_version_uuid | String | The model version UUID. | 
| PrismaAIRs.ModelSecurityScanGet.enabled_rule_count_snapshot | Number | The snapshot of enabled rules count at scan time. | 
| PrismaAIRs.ModelSecurityScanGet.scanner_version | String | The scanner version used. | 
| PrismaAIRs.ModelSecurityScanGet.time_started | Date | The scan start time in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityScanGet.total_files_scanned | Number | The total files scanned. | 
| PrismaAIRs.ModelSecurityScanGet.total_files_skipped | Number | The total files skipped. | 
| PrismaAIRs.ModelSecurityScanGet.rules_passed | Number | The number of rules that passed. | 
| PrismaAIRs.ModelSecurityScanGet.rules_failed | Number | The number of rules that failed. | 
| PrismaAIRs.ModelSecurityScanGet.total_rules | Number | The total number of rules evaluated. | 
| PrismaAIRs.ModelSecurityScanGet.error_code | String | The error code if scan failed. | 
| PrismaAIRs.ModelSecurityScanGet.error_message | String | The error message if scan failed. | 
| PrismaAIRs.ModelSecurityScanGet.model_formats | Unknown | The model file formats detected. | 

### prisma-airs-model-security-scans-violations

***
Get rule violations for a model security scan. Shows detailed information about which security rules failed and why.

#### Base Command

`prisma-airs-model-security-scans-violations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The scan UUID to retrieve violations for. | Required | 
| limit | The maximum number of violations to return. Default is 50. | Optional | 
| offset | The offset for pagination. Default is 0. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityViolation.scan_uuid | String | The scan UUID. | 
| PrismaAIRs.ModelSecurityViolation.violations.uuid | String | The violation UUID. | 
| PrismaAIRs.ModelSecurityViolation.violations.rule_name | String | The security rule name that failed. | 
| PrismaAIRs.ModelSecurityViolation.violations.rule_description | String | The security rule description. | 
| PrismaAIRs.ModelSecurityViolation.violations.description | String | The violation description. | 
| PrismaAIRs.ModelSecurityViolation.violations.rule_instance_state | String | The rule instance state \(BLOCKING/ALLOWING\). | 
| PrismaAIRs.ModelSecurityViolation.violations.file | String | The file path where violation was found. | 
| PrismaAIRs.ModelSecurityViolation.violations.threat | String | The threat type. | 
| PrismaAIRs.ModelSecurityViolation.violations.threat_description | String | The threat description. | 
| PrismaAIRs.ModelSecurityViolation.violations.module | String | The module where threat was found. | 
| PrismaAIRs.ModelSecurityViolation.violations.operator | String | The operator involved in violation. | 
| PrismaAIRs.ModelSecurityViolation.violations.hash | String | The hash of the violating file. | 
| PrismaAIRs.ModelSecurityViolation.violations.rule_instance_uuid | String | The rule instance UUID. | 
| PrismaAIRs.ModelSecurityViolation.violations.created_at | Date | The violation creation timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityViolation.violations.updated_at | Date | The violation last update timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityViolation.violations.tsg_id | String | The tenant Service Group ID. | 
| PrismaAIRs.ModelSecurityViolation.total_items | Number | The total number of violations available. | 
| PrismaAIRs.ModelSecurityViolation.limit | Number | The limit used for pagination. | 
| PrismaAIRs.ModelSecurityViolation.offset | Number | The offset used for pagination. | 

### prisma-airs-model-security-labels-keys

***
Get distinct label keys across all model security scans. Use for discovering available labels for filtering/organization.

#### Base Command

`prisma-airs-model-security-labels-keys`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of label keys to return. Default is 50. | Optional | 
| offset | The offset for pagination. Default is 0. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityLabelKeys.keys | Unknown | The list of distinct label keys. | 
| PrismaAIRs.ModelSecurityLabelKeys.total_items | Number | The total number of label keys available. | 
| PrismaAIRs.ModelSecurityLabelKeys.limit | Number | The limit used for pagination. | 
| PrismaAIRs.ModelSecurityLabelKeys.offset | Number | The offset used for pagination. | 

### prisma-airs-model-security-labels-values

***
Get distinct values for a specific label key across all model security scans. Use to discover what values exist for a given label.

#### Base Command

`prisma-airs-model-security-labels-values`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key | The label key to get values for. | Required | 
| limit | The maximum number of label values to return. Default is 50. | Optional | 
| offset | The offset for pagination. Default is 0. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityLabelValues.key | String | The label key. | 
| PrismaAIRs.ModelSecurityLabelValues.values | Unknown | The list of distinct label values. | 
| PrismaAIRs.ModelSecurityLabelValues.total_items | Number | The total number of label values available. | 
| PrismaAIRs.ModelSecurityLabelValues.limit | Number | The limit used for pagination. | 
| PrismaAIRs.ModelSecurityLabelValues.offset | Number | The offset used for pagination. | 

### prisma-airs-model-security-labels-add

***
Add labels to a model security scan for organization and filtering. Labels are key-value pairs.

#### Base Command

`prisma-airs-model-security-labels-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_uuid | The scan UUID to add labels to. | Required | 
| labels | The labels to add as JSON array (e.g., '[{"key":"env","value":"prod"}]'). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityLabelsAdd.scan_uuid | String | The scan UUID. | 
| PrismaAIRs.ModelSecurityLabelsAdd.labels_added | Unknown | The labels that were added. | 
| PrismaAIRs.ModelSecurityLabelsAdd.success | Boolean | Whether the operation succeeded. | 

### prisma-airs-model-security-labels-set

***
Set labels on a model security scan, replacing all existing labels. Use this to completely update scan labels.

#### Base Command

`prisma-airs-model-security-labels-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_uuid | The scan UUID to set labels on. | Required | 
| labels | The labels to set as JSON array (e.g., '[{"key":"env","value":"staging"}]'). Replaces all existing labels. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityLabelsSet.scan_uuid | String | The scan UUID. | 
| PrismaAIRs.ModelSecurityLabelsSet.labels_set | Unknown | The labels that were set. | 
| PrismaAIRs.ModelSecurityLabelsSet.success | Boolean | Whether the operation succeeded. | 

### prisma-airs-model-security-labels-delete

***
Delete labels from a model security scan by key. Removes specific labels while preserving others.

#### Base Command

`prisma-airs-model-security-labels-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_uuid | The scan UUID to delete labels from. | Required | 
| keys | A comma-separated list of label keys to delete (e.g., "env,team"). Alternatively, a JSON array. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityLabelsDelete.scan_uuid | String | The scan UUID. | 
| PrismaAIRs.ModelSecurityLabelsDelete.keys_deleted | Unknown | The label keys that were deleted. | 
| PrismaAIRs.ModelSecurityLabelsDelete.success | Boolean | Whether the operation succeeded. | 

### prisma-airs-model-security-scans-evaluation

***
Get a single rule evaluation by UUID. Retrieves detailed information about how a specific rule was evaluated during a scan.

#### Base Command

`prisma-airs-model-security-scans-evaluation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The evaluation UUID to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityEvaluation.uuid | String | The evaluation UUID. | 
| PrismaAIRs.ModelSecurityEvaluation.scan_uuid | String | The scan UUID this evaluation belongs to. | 
| PrismaAIRs.ModelSecurityEvaluation.rule_instance_uuid | String | The rule instance UUID. | 
| PrismaAIRs.ModelSecurityEvaluation.rule_name | String | The security rule name. | 
| PrismaAIRs.ModelSecurityEvaluation.rule_description | String | The security rule description. | 
| PrismaAIRs.ModelSecurityEvaluation.result | String | The evaluation result \(PASSED/FAILED/ERROR\). | 
| PrismaAIRs.ModelSecurityEvaluation.violation_count | Number | The number of violations found. | 
| PrismaAIRs.ModelSecurityEvaluation.rule_instance_state | String | The rule instance state \(BLOCKING/ALLOWING/DISABLED\). | 
| PrismaAIRs.ModelSecurityEvaluation.created_at | Date | The evaluation creation timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityEvaluation.updated_at | Date | The evaluation last update timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityEvaluation.tsg_id | String | The tenant Service Group ID. | 

### prisma-airs-model-security-scans-violation

***
Get a single violation by UUID. Retrieves detailed information about a specific security rule violation found during a scan.

#### Base Command

`prisma-airs-model-security-scans-violation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The violation UUID to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityViolationDetail.uuid | String | The violation UUID. | 
| PrismaAIRs.ModelSecurityViolationDetail.rule_name | String | The security rule name that failed. | 
| PrismaAIRs.ModelSecurityViolationDetail.rule_description | String | The security rule description. | 
| PrismaAIRs.ModelSecurityViolationDetail.description | String | The violation description. | 
| PrismaAIRs.ModelSecurityViolationDetail.rule_instance_state | String | The rule instance state \(BLOCKING/ALLOWING\). | 
| PrismaAIRs.ModelSecurityViolationDetail.file | String | The file path where violation was found. | 
| PrismaAIRs.ModelSecurityViolationDetail.threat | String | The threat type. | 
| PrismaAIRs.ModelSecurityViolationDetail.threat_description | String | The threat description. | 
| PrismaAIRs.ModelSecurityViolationDetail.module | String | The module where threat was found. | 
| PrismaAIRs.ModelSecurityViolationDetail.operator | String | The operator involved in violation. | 
| PrismaAIRs.ModelSecurityViolationDetail.hash | String | The hash of the violating file. | 
| PrismaAIRs.ModelSecurityViolationDetail.rule_instance_uuid | String | The rule instance UUID. | 
| PrismaAIRs.ModelSecurityViolationDetail.created_at | Date | The violation creation timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityViolationDetail.updated_at | Date | The violation last update timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityViolationDetail.tsg_id | String | The tenant Service Group ID. | 

### prisma-airs-model-security-scans-files

***
Get files for a scan. Lists all files that were scanned within a model, showing file structure and scan results.

#### Base Command

`prisma-airs-model-security-scans-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_uuid | The scan UUID to retrieve files for. | Required | 
| limit | The maximum number of files to return. Default is 50. | Optional | 
| offset | The offset for pagination. Default is 0. | Optional | 
| sort_field | The sort by field (path, type). | Optional | 
| sort_dir | The sort direction (asc, desc). | Optional | 
| type | The file type to filter results by (FILE, DIRECTORY). | Optional | 
| result | The scan result to filter results by (SUCCESS, FAILURE). | Optional | 
| query_path | The path prefix to filter files by. Default is /. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityFiles.scan_uuid | String | The scan UUID. | 
| PrismaAIRs.ModelSecurityFiles.files.uuid | String | The file entry UUID. | 
| PrismaAIRs.ModelSecurityFiles.files.path | String | The file path within model. | 
| PrismaAIRs.ModelSecurityFiles.files.parent_path | String | The parent directory path. | 
| PrismaAIRs.ModelSecurityFiles.files.type | String | The file type \(FILE, DIRECTORY\). | 
| PrismaAIRs.ModelSecurityFiles.files.result | String | The scan result \(SUCCESS, FAILURE\). | 
| PrismaAIRs.ModelSecurityFiles.files.model_version_uuid | String | The model version UUID. | 
| PrismaAIRs.ModelSecurityFiles.files.blob_id | String | The blob storage identifier. | 
| PrismaAIRs.ModelSecurityFiles.files.formats | Unknown | The model formats detected. | 
| PrismaAIRs.ModelSecurityFiles.files.scan_uuid | String | The scan UUID. | 
| PrismaAIRs.ModelSecurityFiles.files.created_at | Date | The file entry creation timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityFiles.files.updated_at | Date | The file entry last update timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityFiles.files.tsg_id | String | The tenant Service Group ID. | 
| PrismaAIRs.ModelSecurityFiles.total_items | Number | The total number of files available. | 
| PrismaAIRs.ModelSecurityFiles.limit | Number | The limit used for pagination. | 
| PrismaAIRs.ModelSecurityFiles.offset | Number | The offset used for pagination. | 

### prisma-airs-model-security-scans-evaluations

***
Get rule evaluations for a scan. Lists all rule evaluations showing which security rules passed, failed, or had errors.

#### Base Command

`prisma-airs-model-security-scans-evaluations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_uuid | The scan UUID to retrieve evaluations for. | Required | 
| limit | The maximum number of evaluations to return. Default is 50. | Optional | 
| offset | The offset for pagination. Default is 0. | Optional | 
| sort_field | The sort by field (created_at, updated_at). | Optional | 
| sort_order | The sort order (asc, desc). | Optional | 
| result | The evaluation result to filter results by (PASSED, FAILED, ERROR). | Optional | 
| rule_instance_uuid | The rule instance UUID to filter results by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityEvaluations.scan_uuid | String | The scan UUID. | 
| PrismaAIRs.ModelSecurityEvaluations.evaluations.uuid | String | The rule evaluation UUID. | 
| PrismaAIRs.ModelSecurityEvaluations.evaluations.scan_uuid | String | The scan UUID. | 
| PrismaAIRs.ModelSecurityEvaluations.evaluations.rule_name | String | The security rule name \(e.g., Pickle Scan, Malware Scan\). | 
| PrismaAIRs.ModelSecurityEvaluations.evaluations.result | String | The evaluation result \(PASSED, FAILED, ERROR\). | 
| PrismaAIRs.ModelSecurityEvaluations.evaluations.violation_count | Number | The number of violations detected by this rule. | 
| PrismaAIRs.ModelSecurityEvaluations.evaluations.rule_instance_state | String | The rule instance state \(BLOCKING, MONITORING\). | 
| PrismaAIRs.ModelSecurityEvaluations.evaluations.rule_instance_uuid | String | The rule instance UUID that performed the evaluation. | 
| PrismaAIRs.ModelSecurityEvaluations.evaluations.rule_description | String | The rule description. | 
| PrismaAIRs.ModelSecurityEvaluations.evaluations.created_at | Date | The evaluation creation timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityEvaluations.evaluations.updated_at | Date | The evaluation last update timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityEvaluations.evaluations.tsg_id | String | The tenant Service Group ID. | 
| PrismaAIRs.ModelSecurityEvaluations.total_items | Number | The total number of evaluations available. | 
| PrismaAIRs.ModelSecurityEvaluations.limit | Number | The limit used for pagination. | 
| PrismaAIRs.ModelSecurityEvaluations.offset | Number | The offset used for pagination. | 

### prisma-airs-model-security-models-list

***
List Model Security model catalog entries (aggregate over their scanned versions). Read-only.

#### Base Command

`prisma-airs-model-security-models-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of models to return. Default is 50. | Optional | 
| skip | The number of records to skip from the start (pagination offset). | Optional | 
| search_query | The search query (matches model UUID or name). | Optional | 
| sort_field | The field to sort by. Possible values are: created_at, updated_at. | Optional | 
| sort_order | The sort order. Possible values are: asc, desc. | Optional | 
| latest_version_outcomes | A comma-separated list of latest-version evaluation outcomes to filter by (e.g., PASSED,FAILED). | Optional | 
| latest_version_formats | A comma-separated list of latest-version model formats to filter by. | Optional | 
| latest_version_source_types | A comma-separated list of latest-version source types to filter by (e.g., HUGGING_FACE,S3). | Optional | 
| start_time | The earliest model creation datetime (ISO 8601); only models created on or after this time are returned. | Optional | 
| end_time | The latest model creation datetime (ISO 8601); only models created on or before this time are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityModel.uuid | String | The model UUID. | 
| PrismaAIRs.ModelSecurityModel.name | String | The model name. | 
| PrismaAIRs.ModelSecurityModel.latest_version_uuid | String | The UUID of the model's latest version. | 
| PrismaAIRs.ModelSecurityModel.latest_version_revision | String | The revision label of the latest version. | 
| PrismaAIRs.ModelSecurityModel.latest_version_outcome | String | The evaluation outcome of the latest version. | 
| PrismaAIRs.ModelSecurityModel.latest_version_formats | Unknown | The model formats of the latest version. | 
| PrismaAIRs.ModelSecurityModel.latest_version_source_types | Unknown | The source types of the latest version. | 
| PrismaAIRs.ModelSecurityModel.latest_version_scan_time | Date | The scan time of the latest version, in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityModel.created_at | Date | The creation timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityModel.updated_at | Date | The last update timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 

### prisma-airs-model-security-models-get

***
Get a single Model Security model by UUID. Read-only.

#### Base Command

`prisma-airs-model-security-models-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The model UUID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityModel.uuid | String | The model UUID. | 
| PrismaAIRs.ModelSecurityModel.name | String | The model name. | 
| PrismaAIRs.ModelSecurityModel.latest_version_uuid | String | The UUID of the model's latest version. | 
| PrismaAIRs.ModelSecurityModel.latest_version_revision | String | The revision label of the latest version. | 
| PrismaAIRs.ModelSecurityModel.latest_version_fingerprint | String | The fingerprint of the latest version. | 
| PrismaAIRs.ModelSecurityModel.latest_version_hf_commit_sha | String | The Hugging Face commit SHA of the latest version. | 
| PrismaAIRs.ModelSecurityModel.latest_version_outcome | String | The evaluation outcome of the latest version. | 
| PrismaAIRs.ModelSecurityModel.latest_version_formats | Unknown | The model formats of the latest version. | 
| PrismaAIRs.ModelSecurityModel.latest_version_source_types | Unknown | The source types of the latest version. | 
| PrismaAIRs.ModelSecurityModel.latest_version_scan_time | Date | The scan time of the latest version, in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityModel.created_at | Date | The creation timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityModel.updated_at | Date | The last update timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 

### prisma-airs-model-security-models-versions

***
List the versions (revisions) of a Model Security model. Read-only.

#### Base Command

`prisma-airs-model-security-models-versions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model_uuid | The model UUID whose versions to list. | Required | 
| limit | The maximum number of versions to return. Default is 50. | Optional | 
| skip | The number of records to skip from the start (pagination offset). | Optional | 
| sort_order | The sort order. Possible values are: asc, desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityModelVersion.uuid | String | The model version UUID. | 
| PrismaAIRs.ModelSecurityModelVersion.model_uuid | String | The parent model UUID. | 
| PrismaAIRs.ModelSecurityModelVersion.revision | String | The revision label. | 
| PrismaAIRs.ModelSecurityModelVersion.file_count | Number | The number of files in the version. | 
| PrismaAIRs.ModelSecurityModelVersion.license | String | The model license. | 
| PrismaAIRs.ModelSecurityModelVersion.model_formats | Unknown | The model formats. | 
| PrismaAIRs.ModelSecurityModelVersion.source_types | Unknown | The source types. | 
| PrismaAIRs.ModelSecurityModelVersion.last_eval_outcome | String | The latest evaluation outcome. | 
| PrismaAIRs.ModelSecurityModelVersion.latest_scan_time | Date | The latest scan time in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityModelVersion.hf_model_name | String | The Hugging Face model name. | 
| PrismaAIRs.ModelSecurityModelVersion.hf_organization | String | The Hugging Face organization. | 

### prisma-airs-model-security-models-version-get

***
Get a single Model Security model version by UUID. Read-only.

#### Base Command

`prisma-airs-model-security-models-version-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The model version UUID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityModelVersion.uuid | String | The model version UUID. | 
| PrismaAIRs.ModelSecurityModelVersion.model_uuid | String | The parent model UUID. | 
| PrismaAIRs.ModelSecurityModelVersion.revision | String | The revision label. | 
| PrismaAIRs.ModelSecurityModelVersion.fingerprint | String | The version fingerprint. | 
| PrismaAIRs.ModelSecurityModelVersion.file_count | Number | The number of files in the version. | 
| PrismaAIRs.ModelSecurityModelVersion.license | String | The model license. | 
| PrismaAIRs.ModelSecurityModelVersion.model_formats | Unknown | The model formats. | 
| PrismaAIRs.ModelSecurityModelVersion.source_types | Unknown | The source types. | 
| PrismaAIRs.ModelSecurityModelVersion.last_eval_outcome | String | The latest evaluation outcome. | 
| PrismaAIRs.ModelSecurityModelVersion.latest_scan_time | Date | The latest scan time in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityModelVersion.hf_model_name | String | The Hugging Face model name. | 
| PrismaAIRs.ModelSecurityModelVersion.hf_organization | String | The Hugging Face organization. | 
| PrismaAIRs.ModelSecurityModelVersion.hf_commit_sha | String | The Hugging Face commit SHA. | 
| PrismaAIRs.ModelSecurityModelVersion.hf_commit_title | String | The Hugging Face commit title. | 
| PrismaAIRs.ModelSecurityModelVersion.created_at | Date | The creation timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityModelVersion.updated_at | Date | The last update timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 

### prisma-airs-model-security-models-files

***
List the files of a Model Security model version. Read-only.

#### Base Command

`prisma-airs-model-security-models-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model_version_uuid | The model version UUID whose files to list. | Required | 
| limit | The maximum number of files to return. Default is 50. | Optional | 
| skip | The number of records to skip from the start (pagination offset). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityModelFile.uuid | String | The file UUID. | 
| PrismaAIRs.ModelSecurityModelFile.path | String | The file path within the model tree. | 
| PrismaAIRs.ModelSecurityModelFile.parent_path | String | The parent directory path. | 
| PrismaAIRs.ModelSecurityModelFile.type | String | The entry type \(e.g., FILE\). | 
| PrismaAIRs.ModelSecurityModelFile.result | String | The scan result for the file. | 
| PrismaAIRs.ModelSecurityModelFile.formats | Unknown | The detected file formats. | 
| PrismaAIRs.ModelSecurityModelFile.model_version_uuid | String | The parent model version UUID. | 
| PrismaAIRs.ModelSecurityModelFile.scan_uuid | String | The associated scan UUID. | 

### prisma-airs-model-security-groups-list

***
List all model security groups.

#### Base Command

`prisma-airs-model-security-groups-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of security groups to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityGroup.uuid | String | The security group UUID. | 
| PrismaAIRs.ModelSecurityGroup.name | String | The security group name. | 
| PrismaAIRs.ModelSecurityGroup.description | String | The security group description. | 
| PrismaAIRs.ModelSecurityGroup.source_type | String | The source type \(HUGGING_FACE, LOCAL, S3, GCS, AZURE\). | 
| PrismaAIRs.ModelSecurityGroup.state | String | The group state \(ACTIVE, PENDING\). | 
| PrismaAIRs.ModelSecurityGroup.is_tombstone | Boolean | Whether the group is marked for deletion. | 
| PrismaAIRs.ModelSecurityGroup.created_at | Date | The creation timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityGroup.updated_at | Date | The last update timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityGroup.tsg_id | String | The tenant Service Group ID. | 

### prisma-airs-model-security-groups-get

***
Get model security group details by UUID.

#### Base Command

`prisma-airs-model-security-groups-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The security group UUID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityGroupGet.uuid | String | The security group UUID. | 
| PrismaAIRs.ModelSecurityGroupGet.name | String | The security group name. | 
| PrismaAIRs.ModelSecurityGroupGet.description | String | The security group description. | 
| PrismaAIRs.ModelSecurityGroupGet.source_type | String | The source type \(HUGGING_FACE, LOCAL, S3, GCS, AZURE\). | 
| PrismaAIRs.ModelSecurityGroupGet.state | String | The group state \(ACTIVE, PENDING\). | 
| PrismaAIRs.ModelSecurityGroupGet.is_tombstone | Boolean | Whether the group is marked for deletion. | 
| PrismaAIRs.ModelSecurityGroupGet.created_at | Date | The creation timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityGroupGet.updated_at | Date | The last update timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityGroupGet.tsg_id | String | The tenant Service Group ID. | 

### prisma-airs-model-security-groups-create

***
Create a new model security group for scanning models from a specific source type.

#### Base Command

`prisma-airs-model-security-groups-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The security group name. | Required | 
| source_type | The model source type. Possible values are: HUGGING_FACE, LOCAL, S3, GCS, AZURE. | Required | 
| description | The security group description. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityGroupAdd.uuid | String | The UUID of the created security group. | 
| PrismaAIRs.ModelSecurityGroupAdd.name | String | The name of the created security group. | 
| PrismaAIRs.ModelSecurityGroupAdd.description | String | The description of the created security group. | 
| PrismaAIRs.ModelSecurityGroupAdd.source_type | String | The source type \(HUGGING_FACE, LOCAL, S3, GCS, AZURE\). | 
| PrismaAIRs.ModelSecurityGroupAdd.state | String | The group state \(PENDING initially, becomes ACTIVE after configuration\). | 
| PrismaAIRs.ModelSecurityGroupAdd.is_tombstone | Boolean | Whether the group is marked for deletion. | 
| PrismaAIRs.ModelSecurityGroupAdd.created_at | Date | The creation timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityGroupAdd.updated_at | Date | The last update timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityGroupAdd.tsg_id | String | The tenant Service Group ID. | 

### prisma-airs-model-security-groups-delete

***
Delete a security group. Removes a security group that is no longer needed.

#### Base Command

`prisma-airs-model-security-groups-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The security group UUID to delete. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityGroupDelete.uuid | String | The UUID of deleted security group. | 
| PrismaAIRs.ModelSecurityGroupDelete.deleted | Boolean | Whether the deletion succeeded. | 

### prisma-airs-model-security-groups-update

***
Update an existing security group. Updates the name and/or description of a security group.

#### Base Command

`prisma-airs-model-security-groups-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The security group UUID to update. | Required | 
| name | The new name for the security group. | Optional | 
| description | The new description for the security group. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityGroupUpdate.uuid | String | The UUID of the updated security group. | 
| PrismaAIRs.ModelSecurityGroupUpdate.name | String | The updated security group name. | 
| PrismaAIRs.ModelSecurityGroupUpdate.description | String | The updated security group description. | 
| PrismaAIRs.ModelSecurityGroupUpdate.source_type | String | The model source type \(HUGGING_FACE, LOCAL, S3, GCS, AZURE\). | 
| PrismaAIRs.ModelSecurityGroupUpdate.state | String | The group state after update. | 
| PrismaAIRs.ModelSecurityGroupUpdate.is_tombstone | Boolean | Whether the group is marked for deletion. | 
| PrismaAIRs.ModelSecurityGroupUpdate.created_at | Date | The creation timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityGroupUpdate.updated_at | Date | The last update timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityGroupUpdate.tsg_id | String | The tenant Service Group ID. | 

### prisma-airs-model-security-rules-list

***
List all model security rules.

#### Base Command

`prisma-airs-model-security-rules-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of security rules to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityRule.uuid | String | The security rule UUID. | 
| PrismaAIRs.ModelSecurityRule.name | String | The security rule name. | 
| PrismaAIRs.ModelSecurityRule.description | String | The security rule description. | 
| PrismaAIRs.ModelSecurityRule.rule_type | String | The rule type \(ARTIFACT, METADATA\). | 
| PrismaAIRs.ModelSecurityRule.compatible_sources | Unknown | The compatible source types for this rule. | 
| PrismaAIRs.ModelSecurityRule.default_state | String | The default state \(DISABLED, ALLOWING, BLOCKING\). | 

### prisma-airs-model-security-rules-get

***
Get model security rule details by UUID. Returns full rule definition including description, remediation steps, and editable fields.

#### Base Command

`prisma-airs-model-security-rules-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The rule UUID to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityRuleGet.uuid | String | The rule UUID. | 
| PrismaAIRs.ModelSecurityRuleGet.name | String | The rule name. | 
| PrismaAIRs.ModelSecurityRuleGet.description | String | The rule description. | 
| PrismaAIRs.ModelSecurityRuleGet.rule_type | String | The rule type \(ARTIFACT, METADATA, etc\). | 
| PrismaAIRs.ModelSecurityRuleGet.compatible_sources | Unknown | The compatible source types for this rule. | 
| PrismaAIRs.ModelSecurityRuleGet.default_state | String | The default state \(DISABLED, ALLOWING, BLOCKING\). | 
| PrismaAIRs.ModelSecurityRuleGet.remediation_description | String | The remediation description. | 
| PrismaAIRs.ModelSecurityRuleGet.remediation_steps | Unknown | The remediation steps. | 
| PrismaAIRs.ModelSecurityRuleGet.remediation_url | String | The remediation reference URL. | 
| PrismaAIRs.ModelSecurityRuleGet.editable_fields | Unknown | The editable fields configuration. | 
| PrismaAIRs.ModelSecurityRuleGet.constant_values | Unknown | The constant values for this rule. | 
| PrismaAIRs.ModelSecurityRuleGet.default_values | Unknown | The default values for editable fields. | 

### prisma-airs-model-security-rule-instances-list

***
List rule instances for a security group. Rule instances are rules that have been applied to a security group with specific state (DISABLED/ALLOWING/BLOCKING) and optional field customizations.

#### Base Command

`prisma-airs-model-security-rule-instances-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_group_uuid | The security group UUID to list rule instances for. | Required | 
| limit | The maximum number of rule instances to return. Default is 50. | Optional | 
| offset | The offset for pagination. Default is 0. | Optional | 
| security_rule_uuid | The security rule UUID to filter results by. | Optional | 
| state | The rule state to filter results by. Possible values are: DISABLED, ALLOWING, BLOCKING. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityRuleInstance.security_group_uuid | String | The security group UUID. | 
| PrismaAIRs.ModelSecurityRuleInstance.rule_instances.uuid | String | The rule instance UUID. | 
| PrismaAIRs.ModelSecurityRuleInstance.rule_instances.security_group_uuid | String | The security group UUID this instance belongs to. | 
| PrismaAIRs.ModelSecurityRuleInstance.rule_instances.security_rule_uuid | String | The security rule UUID. | 
| PrismaAIRs.ModelSecurityRuleInstance.rule_instances.state | String | The rule instance state \(DISABLED/ALLOWING/BLOCKING\). | 
| PrismaAIRs.ModelSecurityRuleInstance.rule_instances.rule_name | String | The security rule name. | 
| PrismaAIRs.ModelSecurityRuleInstance.rule_instances.rule_type | String | The security rule type. | 
| PrismaAIRs.ModelSecurityRuleInstance.rule_instances.rule_description | String | The security rule description. | 
| PrismaAIRs.ModelSecurityRuleInstance.rule_instances.created_at | Date | The rule instance creation timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityRuleInstance.rule_instances.updated_at | Date | The rule instance last update timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityRuleInstance.rule_instances.tsg_id | String | The tenant Service Group ID. | 
| PrismaAIRs.ModelSecurityRuleInstance.rule_instances.field_values | Unknown | The custom field values for this rule instance. | 
| PrismaAIRs.ModelSecurityRuleInstance.total_items | Number | The total number of rule instances available. | 
| PrismaAIRs.ModelSecurityRuleInstance.limit | Number | The limit used for pagination. | 
| PrismaAIRs.ModelSecurityRuleInstance.offset | Number | The offset used for pagination. | 

### prisma-airs-model-security-rule-instances-update

***
Update a rule instance within a security group. Use this to enable/disable rules or customize rule field values.

#### Base Command

`prisma-airs-model-security-rule-instances-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_group_uuid | The security group UUID. | Required | 
| rule_instance_uuid | The rule instance UUID to update. | Required | 
| state | The new state for the rule instance. Possible values are: DISABLED, ALLOWING, BLOCKING. | Optional | 
| field_values | The custom field values as JSON string. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityRuleInstanceUpdate.uuid | String | The rule instance UUID. | 
| PrismaAIRs.ModelSecurityRuleInstanceUpdate.security_group_uuid | String | The security group UUID this instance belongs to. | 
| PrismaAIRs.ModelSecurityRuleInstanceUpdate.security_rule_uuid | String | The security rule UUID. | 
| PrismaAIRs.ModelSecurityRuleInstanceUpdate.state | String | The rule instance state \(DISABLED/ALLOWING/BLOCKING\). | 
| PrismaAIRs.ModelSecurityRuleInstanceUpdate.rule_name | String | The security rule name. | 
| PrismaAIRs.ModelSecurityRuleInstanceUpdate.rule_type | String | The security rule type. | 
| PrismaAIRs.ModelSecurityRuleInstanceUpdate.rule_description | String | The security rule description. | 
| PrismaAIRs.ModelSecurityRuleInstanceUpdate.created_at | Date | The rule instance creation timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityRuleInstanceUpdate.updated_at | Date | The rule instance last update timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityRuleInstanceUpdate.tsg_id | String | The tenant Service Group ID. | 
| PrismaAIRs.ModelSecurityRuleInstanceUpdate.field_values | Unknown | The custom field values for this rule instance. | 

### prisma-airs-model-security-rule-instances-get

***
Get a single rule instance within a security group. Retrieves detailed configuration of a specific rule instance.

#### Base Command

`prisma-airs-model-security-rule-instances-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_group_uuid | The security group UUID. | Required | 
| rule_instance_uuid | The rule instance UUID to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityRuleInstanceGet.uuid | String | The rule instance UUID. | 
| PrismaAIRs.ModelSecurityRuleInstanceGet.security_group_uuid | String | The security group UUID this instance belongs to. | 
| PrismaAIRs.ModelSecurityRuleInstanceGet.security_rule_uuid | String | The security rule UUID. | 
| PrismaAIRs.ModelSecurityRuleInstanceGet.state | String | The rule instance state \(DISABLED/ALLOWING/BLOCKING\). | 
| PrismaAIRs.ModelSecurityRuleInstanceGet.rule_name | String | The security rule name. | 
| PrismaAIRs.ModelSecurityRuleInstanceGet.rule_type | String | The security rule type. | 
| PrismaAIRs.ModelSecurityRuleInstanceGet.rule_description | String | The security rule description. | 
| PrismaAIRs.ModelSecurityRuleInstanceGet.created_at | Date | The rule instance creation timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityRuleInstanceGet.updated_at | Date | The rule instance last update timestamp in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). | 
| PrismaAIRs.ModelSecurityRuleInstanceGet.tsg_id | String | The tenant Service Group ID. | 
| PrismaAIRs.ModelSecurityRuleInstanceGet.field_values | Unknown | The custom field values for this rule instance. | 
