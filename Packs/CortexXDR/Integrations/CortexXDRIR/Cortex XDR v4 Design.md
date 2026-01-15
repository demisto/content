# Cortex XDR Command Design

Ticket: [CRTX-198884](https://jira-dc.paloaltonetworks.com/browse/CRTX-198884)

---

## **Commands to deprecate:**

- xdr-get-incidents  \-\> xdr-case-list  
- xdr-get-incident-extra-data  
- xdr-update-incident \-\> xdr-case-update  
- xdr-insert-parsed-alert  
- xdr-insert-cef-alerts  
- xdr-get-cloud-original-alerts  
- xdr-get-alerts \-\> xdr-issue-list  
- xdr-update-alert \-\> xdr-issue-update

## **API Key Lifecycle Management:**

### **xdr-api-key-list**

**API Endpoint:** POST /public\_api/v1/api\_keys/get\_api\_keys

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-existing-API-keys](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-existing-API-keys)

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `api_id` | `List` | `False` |  |
| `role` | `List` | `False` |  |
| `expires_before` | `String` | `False`  | Should support english expressions like “in a year” |
| `expires_after` | `String` | `False` | Should support english expressions like “in a year” |

**Outputs Key:** `PaloAltoNetworksXDR.APIKeyData`

**Outputs:** All API outputs under `reply.DATA`

**Human-Readable Output:**  
All API outputs under `reply.DATA`  
Use string\_to\_table\_header

### **xdr-api-key-delete**

**API Endpoint:** POST /public\_api/v1/api\_keys/delete

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Delete-API-keys](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Delete-API-keys)

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `api_id` | `List` | `True` |  |

**Outputs Key:** N/A

**Output:** N/A

**Human-Readable Output:**  
“API Keys deleted successfully.”

---

## **Case Management:**

### **xdr-case-list**

**API Endpoint:** POST /public\_api/v1/case/search

**Docs**: 

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `case_id` | `List` | `False` |  |
| `case_domain` | `List` | `False` |  |
| severity | `List` | `False` |  |
| `created_before` | `String` | `False` | Should support english expressions like “in a year” |
| `created_after` | `String` | `False` | Should support english expressions like “in a year” |
| `status` | `List` | `False` |  |
| `sort_field` | `String` | `False` | Possible values: "case\_id""severity""creation\_time" |
| `sort_order` | `String` | `False` | Possible values: asc, desc  |
| `limit` | `String` | `False` | See [https://xsoar.pan.dev/docs/integrations/code-conventions\#pagination-in-integration-commands](https://xsoar.pan.dev/docs/integrations/code-conventions#pagination-in-integration-commands) |
| `page_size` | `String` | `False` |  |
| `page` | `String` | `False` |  |

**Outputs Key:** `PaloAltoNetworksXDR.Case`

**Outputs:** All API outputs under `reply.DATA`

**Human-Readable Output:**  
All API outputs under `reply.DATA`  
Use string\_to\_table\_header

### **xdr-case-update**

**API Endpoint:** POST /public\_api/v1/case/update/{case-id}

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Update-existing-case](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Update-existing-case) 

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `case_id` | `String` | `True` |  |
| `status` | `String` | `False` | Possible values: "new""under\_investigation""resolved" |
| `resolve_reason` | `String` | `False` | Possible values: "resolved\_known\_issue""resolved\_duplicate""resolved\_false\_positive""resolved\_other""resolved\_true\_positive""resolved\_security\_testing""resolved\_fixed""resolved\_dismissed" |
| `resolve_comment` | `String` | `False` |  |

**Outputs Key:** N/A

**Outputs:** N/A

**Human-Readable Output:**  
“Case updated successfully”

### **xdr-case-artifact-list**

**API Endpoint:** GET /public\_api/v1/case/artifacts

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Retrieve-Case-Artifacts-by-Case-Id](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Retrieve-Case-Artifacts-by-Case-Id) 

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `case_id` | `String` | `True` |  |

**Outputs Key:** `PaloAltoNetworksXDR.CaseNetworkArtifact`

**Outputs:** All API outputs under `reply.DATA.network_artifacts.DATA`, add the “case\_id” to each artifact

**Outputs Key:** `PaloAltoNetworksXDR.CaseFileArtifact`

**Outputs:** All API outputs under `reply.DATA.file_artifacts.DATA`, add the “case\_id” to each artifact

**Human-Readable Output:**  
All API outputs that are returned to the context  
Use string\_to\_table\_header

---

## **Issue Management:**

### **xdr-issue-list**

**API Endpoint:** POST /v1/issue/search

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Retrieve-issues-based-on-filters](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Retrieve-issues-based-on-filters) 

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `issue_id` | `List` | `False` |  |
| `external_id` | `List` | `False` |  |
| `detection_method` | `String` | `False` |  |
| `domain` | `String` | `False` |  |
| `severity` | `String` | `False` |  |
| `insert_time` | `String` | `False` | Should support english expressions like “in a year” |
| `status` | `List` | `False` |  |
| `sort_field` | `String` | `False` | Possible values: "issue\_id""severity""observation\_time" |
| `sort_order` | `String` | `False` | Possible values: asc, desc |
| `limit` | `String` | `False` | See [https://xsoar.pan.dev/docs/integrations/code-conventions\#pagination-in-integration-commands](https://xsoar.pan.dev/docs/integrations/code-conventions#pagination-in-integration-commands) |
| `page_size` | `String` | `False` |  |
| `page` | `String` | `False` |  |

**Outputs Key:** `PaloAltoNetworksXDR.Issue`

**Outputs:** 

**Human-Readable Output**

**Issues**

| ID | Name | Type | Severity | Description |
| ----- | ----- | ----- | ----- | ----- |
|  |  |  |  |  |

### **xdr-issue-create**

**API Endpoint:** POST /v1/issue

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Create-a-new-issue](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Create-a-new-issue) 

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `name` | `String` | `True` |  |
| `description` | `String` | `True` |  |
| observation\_time | `String` | `True` | Should support english expressions like “in a year” |
| domain | `String` | `True` |  |
| `category` | `String` | `True` |  |
| `asset_id` | `List` | `False` |  |
| `mitre_tactic` | `List` | `False` |  |
| `mitre_tecnique` | `List` | `False` |  |
| `type` | `String` | `False` |  |
| `extended_description` | `String` | `False` |  |
| `impact` | `String` | `False` |  |
| `tags` | `List` | `False` |  |
| `is_excluded` | `String` | `False` | Boolean |
| `is_starred` | `String` | `False` | Boolean |
| `assigned_to` | `String` | `False` |  |
| `assigned_to_pretty` | `String` | `False` |  |
| `severity` | `String` | `False` | Possible values: info, low, medium, high |
| `normalized_fields_json` | `JSON (String)` | `False` | The JSON to add to the “normalized\_fields” field in the API. Make sure that the required schema is properly documented. |
| `custom_fields_json` | `JSON (String)` | `False` | The JSON to add to the “custom\_fields” field in the API. Make sure that the required schema is properly documented. |

**Outputs Key:** `PaloAltoNetworksXDR.Issue`

**Outputs:** All API outputs

**Human-Readable Output:**  
All API outputs  
Use string\_to\_table\_header

### **xdr-issue-update**

**API Endpoint:** POST /v1/issue/{issue-id}

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Update-existing-issue](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Update-existing-issue) 

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `issue_id` | `String` | `True` |  |
| `severity` | `String` | `False` | Possible values: info, low, medium, high |
| `status` | `String` | `False` | Possible values: "new""under\_investigation""resolved" |
| `resolve_reason` | `String` | `False` | Possible values: "resolved\_known\_issue""resolved\_duplicate""resolved\_false\_positive""resolved\_other""resolved\_true\_positive""resolved\_security\_testing""resolved\_fixed""resolved\_dismissed" |
| `resolve_comment` | `String` | `False` |  |

**Outputs Key:** N/A

**Output:** N/A

**Human-Readable Output:**  
“Issue updated successfully”

---

## **Asset Inventory and Groups**

### **xdr-asset-list**

**API Endpoint:** POST /public\_api/v1/assets ***OR*** GET /public\_api/v1/assets/{id}\`

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-all-or-filtered-assets](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-all-or-filtered-assets), [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-asset-by-ID](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-asset-by-ID) 

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `asset_id` | `List` | `False` | If this option is chosen all the others are ignored, use the ***asset/{id}*** endpoint |
| `sort_field` | `String` | `False` |  |
| `sort_order` | `String` | `False` | Possible values: asc, desc |
| `filter_json` | `JSON (String)` | `False` | The JSON to use for the “filter” field in the API. Make sure that the required schema is properly documented. Document that the command “xdr-asset-schema-get” command can be used to help. |
| `limit` | `String` | `False` | See [https://xsoar.pan.dev/docs/integrations/code-conventions\#pagination-in-integration-commands](https://xsoar.pan.dev/docs/integrations/code-conventions#pagination-in-integration-commands) |
| `page_size` | `String` | `False` |  |
| `page` | `String` | `False` |  |

**Outputs Key:** `PaloAltoNetworksXDR.Asset`

**Outputs:** All API outputs under `reply.data`

**Human-Readable Output**

**Assets**

| ID | Name | First Observed | Last Observed | Critical Cases Count | Critical Issues Count |
| ----- | ----- | ----- | ----- | ----- | ----- |
| `xdm.asset.id` | `xdm.asset.name` | `xdm.asset.first_observed` | `xdm.asset.last_observed` | `cases_critical` | `issues_critical` |

### **xdr-asset-schema-get**

**API Endpoint:** POST /public\_api/v1/assets/schema

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-schema-of-asset-inventory](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-schema-of-asset-inventory) 

**Arguments:** N/A

**Outputs Key:** `PaloAltoNetworksXDR.AssetSchema`

**Outputs:** All API outputs under `reply.DATA`

**Human-Readable Output:**  
All API outputs under `reply.DATA`  
Use string\_to\_table\_header

### **xdr-asset-schema-field-options-get**

For fields in the asset schema of type “ENUM”

**API Endpoint:** POST /public\_api/v1/assets/enum/(field\_name)

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-enum-values-of-specified-field](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-enum-values-of-specified-field) 

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `field_name` | `String` | `True` |  |

**Outputs Key:** `PaloAltoNetworksXDR.AssetSchema(val.field_name == {field_name}).options` if AssetScema is not there, create a new dictionary with field\_name,options

**Outputs:** All API outputs under `reply.DATA`

**Human-Readable Output:**  
All API outputs under `reply.DATA`  
Use string\_to\_table\_header

### **xdr-asset-group-create**

**API Endpoint:** POST /public\_api/v1/asset-group/create

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Create-an-Asset-Group](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Create-an-Asset-Group) 

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `group_name` | `String` | `True` |  |
| `group_type` | `String` | `True` | Possible values: “static”, “dynamic” |
| `group_description` | `String` | `False` |  |
| `membership_predicate_json` | `JSON (String)` | `False` | The JSON to use for the “membership\_predicate” field in the API. Make sure that the required schema is properly documented. |

**Outputs Key:** N/A

**Outputs:** `{“XDM.ASSET_GROUP.ID”: reply.data.asset_group_id}`

**Human-Readable Output:**

“Asset group created successfully.”

### **xdr-asset-group-delete**

**API Endpoint:** POST /public\_api/v1/asset-group/delete

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Delete-an-Asset-Group](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Delete-an-Asset-Group) 

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `group_id` | `String` | `True` |  |

**Outputs Key:** N/A

**Outputs:** N/A

**Human-Readable Output:**  
“Asset group deleted successfully.”

### **xdr-asset-group-list**

**API Endpoint:** POST /public\_api/v1/asset-groups

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-all-or-filtered-asset-groups](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-all-or-filtered-asset-groups) 

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `sort_field` | `String` | `False` |  |
| `sort_order` | `String` | `False` |  |
| `filter_json` | `JSON (String)` | `False` | The JSON to use for the “filter” field in the API. Make sure that the required schema is properly documented. |
| `limit` | `String` | `False` | See: [https://xsoar.pan.dev/docs/integrations/code-conventions\#pagination-in-integration-commands](https://xsoar.pan.dev/docs/integrations/code-conventions#pagination-in-integration-commands) |
| `page_size` | `String` | `False` |  |
| `page` | `String` | `False` |  |

**Outputs Key:** `PaloAltoNetworksXDR.AssetGroup`

**Outputs:** All API outputs under `reply.data`

**Human-Readable Output:**

**Asset Group**

| ID | Name | Type | Description |
| ----- | ----- | ----- | ----- |
|  |  |  |  |

### **xdr-asset-group-update**

**API Endpoint:** POST /public\_api/v1/asset-groups/update/{group\_id}

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Update-an-Asset-Group](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Update-an-Asset-Group) 

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `group_name` | `String` | `False` |  |
| `group_type` | `String` | `False` | Possible values: “static”, “dynamic” |
| `group_description` | `String` | `False` |  |
| `membership_predicate_json` | `JSON (String)` | `False` | The JSON to use for the “membership\_predicate” field in the API. Make sure that the required schema is properly documented. |

**Outputs Key:** N/A

**Outputs:** N/A

**Human-Readable Output:**  
“Asset group updated successfully.”

---

## **Detection and Indicators**

### **xdr-bioc-list**

**API Endpoint:** POST /public\_api/v1/bioc/get

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-BIOCs](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-BIOCs)

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `name` | `String` | `False` |  |
| `severity` | `String` | `False` | Possible values: info, low, medium, high |
| `type` | `String` | `False` | Possible values: other, persistence, evasion, tampering, file\_type\_obfuscation, privilege\_escalation, credential\_access, lateral\_movement, execution, collection, exfiltration, infiltration, dropper, file\_privilege\_manipulation, reconnaissance, discovery |
| `is_xql` | `String` | `False` | Possible values: true, false |
| `comment` | `String` | `False` |  |
| `status` | `String` | `False` | Possible values: enabled, disabled |
| `indicator` | `List` | `False` |  |
| `mitre_technique_id_and_name` | `List` | `False` |  |
| `mitre_tactic_id_and_name` | `List` | `False` |  |
| `extra_data` | `String` | `False` | Possible values: true, false Use for “extended\_view” field |
| `limit` | `String` | `False` | See [https://xsoar.pan.dev/docs/integrations/code-conventions\#pagination-in-integration-commands](https://xsoar.pan.dev/docs/integrations/code-conventions#pagination-in-integration-commands) |
| `page_size` | `String` | `False` |  |
| `page` | `String` | `False` |  |

**Outputs Key:** `PaloAltoNetworksXDR.BIOC`

**Outputs:** All API outputs under `objects`

**Human-Readable Output**

**BIOCs**

| Name | Type | Severity | Status |
| ----- | ----- | ----- | ----- |
| `name` | `type` | `severity` | `status` |

### **xdr-bioc-create**

**API Endpoint:** POST /public\_api/v1/bioc/insert

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Insert-or-update-BIOCs](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Insert-or-update-BIOCs)

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `name` | `String` | `False` |  |
| `severity` | `String` | `False` | Possible values: info, low, medium, high |
| `type` | `String` | `False` | Possible values: other, persistence, evasion, tampering, file\_type\_obfuscation, privilege\_escalation, credential\_access, lateral\_movement, execution, collection, exfiltration, infiltration, dropper, file\_privilege\_manipulation, reconnaissance, discovery |
| `is_xql` | `String` | `False` | Possible values: true, false |
| `comment` | `String` | `False` |  |
| `status` | `String` | `False` | Possible values: enabled, disabled |
| `indicator` | `List` | `False` |  |
| `mitre_technique_id_and_name` | `List` | `False` |  |
| `mitre_tactic_id_and_name` | `List` | `False` |  |

**Outputs Key:** `PaloAltoNetworksXDR.BIOC`

**Outputs:** `{“rule_id”: <created_objects.id>}` 

**Human-Readable Output:**  
“BIOC created successfully.”

### **xdr-bioc-update**

**API Endpoint:** POST /public\_api/v1/bioc/insert

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Insert-or-update-BIOCs](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Insert-or-update-BIOCs)

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `rule_id` | `String` | `True` |  |
| `name` | `String` | `False` |  |
| `severity` | `String` | `False` | Possible values: info, low, medium, high |
| `type` | `String` | `False` | Possible values: other, persistence, evasion, tampering, file\_type\_obfuscation, privilege\_escalation, credential\_access, lateral\_movement, execution, collection, exfiltration, infiltration, dropper, file\_privilege\_manipulation, reconnaissance, discovery |
| `is_xql` | `String` | `False` | Possible values: true, false |
| `comment` | `String` | `False` |  |
| `status` | `String` | `False` | Possible values: enabled, disabled |
| `indicator` | `List` | `False` |  |
| `mitre_technique_id_and_name` | `List` | `False` |  |
| `mitre_tactic_id_and_name` | `List` | `False` |  |

**Outputs Key:** `PaloAltoNetworksXDR.BIOC`

**Outputs:** `{“rule_id”: <updated_objects.id>}` 

**Human-Readable Output:**  
“BIOC updated successfully.”

### **xdr-bioc-delete**

**API Endpoint:** POST /public\_api/v1/bioc/delete

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Delete-BIOCs](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Delete-BIOCs)

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `name` | `String` | `False` |  |
| `severity` | `String` | `False` | Possible values: info, low, medium, high |
| `type` | `String` | `False` | Possible values: other, persistence, evasion, tampering, file\_type\_obfuscation, privilege\_escalation, credential\_access, lateral\_movement, execution, collection, exfiltration, infiltration, dropper, file\_privilege\_manipulation, reconnaissance, discovery |
| `is_xql` | `String` | `False` | Possible values: true, false |
| `comment` | `String` | `False` |  |
| `indicator` | `List` | `False` |  |
| `mitre_technique_id_and_name` | `List` | `False` |  |
| `mitre_tactic_id_and_name` | `List` | `False` |  |

**Outputs Key:** N/A

**Outputs:** N/A

**Human-Readable Output:**  
“BIOC deleted successfully.”

### **xdr-correlation-rule-list**

**API Endpoint:** POST /public\_api/v1/correlations/get

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-Correlation-Rules](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-Correlation-Rules)

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `name` | `String` | `False` |  |
| `severity` | `String` | `False` | Possible values: info, low, medium, high |
| `xql_query` | `String` | `False` |  |
| `is_xql` | `String` | `False` | Possible values: true, false |
| `dataset` | `String` | `False` |  |
| `alert_name` | `String` | `False` | Possible values: enabled, disabled |
| `alert_category` | `String` | `False` |  |
| `alert_fields` | `List` | `False` |  |
| `alet_domain` | `String` | `False` |  |
| `filter_json` | `JSON (String)` | `False` | The JSON to add to the “filter” field in the API. Make sure that the required schema is properly documented. |
| `extra_data` | `String` | `False` | Possible values: true, false Use for “extended\_view” field |
| `limit` | `String` | `False` | See [https://xsoar.pan.dev/docs/integrations/code-conventions\#pagination-in-integration-commands](https://xsoar.pan.dev/docs/integrations/code-conventions#pagination-in-integration-commands) |
| `page_size` | `String` | `False` |  |
| `page` | `String` | `False` |  |

**Outputs Key:** `PaloAltoNetworksXDR.CorrelationRule`

**Outputs:** All API outputs under `objects`

**Human-Readable Output**

**Correlation Rule**

| ID | Name | Description | Is Enabled |
| ----- | ----- | ----- | ----- |
| `id` | `name` | `description` | `is_enabled` |

### **xdr-correlation-rule-create**

**API Endpoint:** POST /public\_api/v1/correlations/insert

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Insert-or-update-Correlation-Rules](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Insert-or-update-Correlation-Rules)

**Arguments:**

| name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| name | `String` | False | Correlation rule name. |
| severity | `String` | False | Correlation rule severity. Possible values: "info", "low", "medium", "high" |
| xql\_query | `String` | False | Correlation rule XQL query. |
| is\_enabled | `String` | False | Whether the correlation rule is enabled or disabled. |
| description | `String` | False | Correlation rule description. |
| alert\_name | `String` | False | Alert name. |
| alert\_category | `String` | False | Alert category. Possible values: "other", "persistence", "evasion", "tampering", "file\_type\_obfuscation", "privilege\_escalation", "credential\_access", "lateral\_movement", "execution", "collection", "exfiltration", "infiltration", "dropper", "file\_privilege\_manipulation", "reconnaissance", "discovery" |
| alert\_description | `String` | False | Alert description. |
| alert\_fields | `String` | False | Alert fields. Additional properties object |
| execution\_mode | `String` | False | Correlation rule execution mode. Possible values: "scheduled", "real\_time" |
| search\_window | `String` | False | Search window. |
| schedule | `String` | False | **simple\_schedule** |
| schedule\_linux | `String` | False | **crontab** |
| timezone | `String` | False | Add dropdown |
| suppression\_enabled | `String` | False |  |
| suppression\_duration | `String` | False |  |
| suppression\_fields | `String` | False |  |
| dataset | `String` | False |  |
| user\_defined\_severity | `String` | False |  |
| user\_defined\_category | `String` | False |  |
| mitre\_defs\_json | `JSON (String)` | False | The JSON that will hold the mitre\_defs of the API. Make sure that the required schema is properly documented. Add a link to the docs. |
| investigation\_query\_link | `String` | False |  |
| drilldown\_query\_timeframe | `String` | False |  |
| mapping\_strategy | `String` | False  | Allowed values:"auto""custom" |

**Outputs Key:** `PaloAltoNetworksXDR.CorrelationRule`

**Outputs:** `{“id”: <created_objects.id>}` 

**Human-Readable Output:**  
“Correlation rule created successfully.”

### **xdr-correlation-rule-update**

**API Endpoint:** POST /public\_api/v1/correlations/insert

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Insert-or-update-Correlation-Rules](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Insert-or-update-Correlation-Rules)

**Arguments:**

| name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| rule\_id | `String` | True |  |
| name | `String` | False | Correlation rule name. |
| severity | `String` | False | Correlation rule severity. Possible values: "info", "low", "medium", "high" |
| xql\_query | `String` | False | Correlation rule XQL query. |
| is\_enabled | `String` | False | Whether the correlation rule is enabled or disabled. |
| description | `String` | False | Correlation rule description. |
| alert\_name | `String` | False | Alert name. |
| alert\_category | `String` | False | Alert category. Possible values: "other", "persistence", "evasion", "tampering", "file\_type\_obfuscation", "privilege\_escalation", "credential\_access", "lateral\_movement", "execution", "collection", "exfiltration", "infiltration", "dropper", "file\_privilege\_manipulation", "reconnaissance", "discovery" |
| alert\_description | `String` | False | Alert description. |
| alert\_fields | `String` | False | Alert fields. Additional properties object |
| execution\_mode | `String` | False | Correlation rule execution mode. Possible values: "scheduled", "real\_time" |
| search\_window | `String` | False | Search window. |
| schedule | `String` | False | **simple\_schedule** |
| schedule\_linux | `String` | False | **crontab** |
| timezone | `String` | False | Add dropdown |
| suppression\_enabled | `String` | False |  |
| suppression\_duration | `String` | False |  |
| suppression\_fields | `String` | False |  |
| dataset | `String` | False |  |
| user\_defined\_severity | `String` | False |  |
| user\_defined\_category | `String` | False |  |
| mitre\_defs\_json | `JSON (String)` | False | The JSON that will hold the mitre\_defs of the API. Make sure that the required schema is properly documented. Add a link to the docs. |
| investigation\_query\_link | `String` | False |  |
| drilldown\_query\_timeframe | `String` | False |  |
| mapping\_strategy | `String` | False  | Allowed values:"auto""custom" |

**Outputs Key:** `PaloAltoNetworksXDR.CorrelationRule`

**Outputs:** `{“id”: <updated_objects.id>}` 

**Human-Readable Output:**  
“Correlation rule created successfully.”

### **xdr-correlation-rule-delete**

**API Endpoint:** POST /public\_api/v1/correlations/delete

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Delete-Correlation-Rules](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Delete-Correlation-Rules)

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `rule_id` | `List` | `True` |  |

**Outputs Key:** N/A

**Outputs:** N/A

**Human-Readable Output:**	  
“Correlation rule deleted successfully”

---

## **Content:**

### **xdr-automation-script-create**

NOTE: can override existing

**API Endpoint:** POST /public\_api/v1/scripts/insert

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Insert-or-update-a-script](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Insert-or-update-a-script)

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `entry_id` | `String` | `True` | Should accept a yml or zip file |

**Outputs Key:** N/A

**Outputs:** N/A

**Human-Readable Output**  
“Automation script created successfully”

### **xdr-automation-script-get**

**API Endpoint:** POST /public\_api/v1/scripts/get

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-a-script](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-a-script)

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `field` | `String` | `True` | id,name |
| `value` | `String` | `True` |  |

**Outputs Key:** N/A

**Outputs:** N/A

**Human-Readable Output**  
File output

### **xdr-automation-script-delete**

**API Endpoint:** POST /public\_api/v1/scripts/delete

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Delete-API-keys](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Delete-API-keys)

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `field` | `String` | `True` | id,name |
| `value` | `String` | `True` |  |

**Outputs Key:** N/A

**Output:** N/A

**Human-Readable Output:**  
“Automation script deleted successfully”

### **xdr-automation-playbook-create**

NOTE: can override existing

**API Endpoint:** POST /public\_api/v1/playbooks/insert

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Insert-or-update-playbooks](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Insert-or-update-playbooks)

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `entry_id` | `String` | `True` | Should accept a yml or zip file |

**Outputs Key:** N/A

**Outputs:** N/A

**Human-Readable Output**  
“Automation playbook created successfully”

### **xdr-automation-playbook-get**

**API Endpoint:** POST /public\_api/v1/playbooks/get

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-a-playbook](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-a-playbook)

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `field` | `String` | `True` | id,name |
| `value` | `String` | `True` |  |

**Outputs Key:** N/A

**Outputs:** N/A

**Human-Readable Output**  
File output

### **xdr-automation-playbook-delete**

**API Endpoint:** POST /public\_api/v1/playbooks/delete

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Delete-a-playbook](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Delete-a-playbook)

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `field` | `String` | `True` | id,name |
| `value` | `String` | `True` |  |

**Outputs Key:** N/A

**Output:** N/A

**Human-Readable Output:**  
“Automation playbook deleted successfully.”

---

## **Miscellaneous:**

### **xdr-vulnerability-details-get**

**API Endpoint:** GET /public\_api/uvem/v1/vulnerabilities

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Vulnerabilities](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Vulnerabilities)

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `vulnerability_id` | `String` | `True` | Should accept a yml or zip file |

**Outputs Key:** `PaloAltoNetworksXDR.Vulnerability`

**Outputs:** All API outputs

**Human-Readable Output**

**Vulnerability Details**

| Vulnerability ID | Description |
| ----- | ----- |
| **vulnerabilityID** | **description** |

### **xdr-healthcheck-run**

**API Endpoint:** GET /public\_api/v1/healthcheck

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/System-Health-Check](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/System-Health-Check)

**Arguments:** N/A

**Outputs Key:** `PaloAltoNetworksXDR.HealthStatus`

**Outputs:** The health status

**Human-Readable Output**  
**Cortex health status: {status}**

### **xdr-endpoint-triage-preset-list**

**API Endpoint:** GET /public\_api/v1/get\_triage\_presets

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-triage-presets](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-triage-presets)

**Arguments:** N/A

**Outputs Key:** `PaloAltoNetworksXDR.EndpointTriagePreset`

**Outputs:** All API outputs under `reply.triage_presets`

**Human-Readable Output:**  
All API outputs under `reply.DATA`  
Use string\_to\_table\_header

### **xdr-endpoint-triage**

**API Endpoint:** GET /public\_api/v1/triage\_endpoint

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Initiate-Forensics-Triage](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Initiate-Forensics-Triage)

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `agent_id` | `List` | `True` |  |
| collector\_uuid | `String` | `False` |  |

**Outputs Key:** `PaloAltoNetworksXDR.EndpointTriage`

**Outputs:** All API outputs under `reply`

**Human-Readable Output:**  
All API outputs under `reply`  
Use string\_to\_table\_header

---

## **XQL**

Note: This section is for the “Cortex XDR \- XQL Query Engine” integration

### **xdr-xql-library-list**

**API Endpoint:** POST /public\_api/v1/xql\_library/get

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-XQL-Queries](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-XQL-Queries)

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `extra_data` | `String` | `False` | **extended\_view**  Possible values: true, false |
| `xql_query_name` | `List` | `False` |  |
| `xql_query_tag` | `List` | `False` |  |

**Outputs Key:** `PaloAltoNetworksXQL.Library`

**Outputs:** All API outputs under `xql_queries`

**Human-Readable Output:**  
All API outputs under `xql_queries` without `query_metadata`  
Use string\_to\_table\_header

### **xdr-xql-library-create**

**API Endpoint:** POST /public\_api/v1/xql\_library/insert

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Insert-or-update-XQL-queries](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Insert-or-update-XQL-queries)

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `override_existing` | `String` | `False` | **xql\_queries\_override**  Possible values: true, false |
| `xql_query` | `List` | `False` | Sequentially match the queries with the query name |
| `xql_query_name` | `List` | `False` |  |
| `xql_query_tag` | `List` | `False` |  |

**Outputs Key:** N/A

**Outputs:** N/A

**Human-Readable Output:**  
“XQL queries created successfully.”

### **xdr-xql-library-delete**

**API Endpoint:** POST /public\_api/v1/xql\_library/delete

**Docs**: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Delete-XQL-Queries](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Delete-XQL-Queries)

**Arguments:**

| Input Name | Type | Required | Note |
| ----- | ----- | ----- | ----- |
| `xql_query_name` | `List` | `False` |  |
| `xql_query_tag` | `List` | `False` |  |

**Outputs Key:** N/A

**Outputs:** N/A

**Human-Readable Output:**	  
“XQL queries deleted successfully.”