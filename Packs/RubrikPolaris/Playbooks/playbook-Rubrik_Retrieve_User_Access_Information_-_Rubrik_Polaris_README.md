This playbook retrieves user access information for the provided username or email with the pagination related information.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* RubrikPolaris.

### Scripts

* DeleteContext
* SetAndHandleEmpty

### Commands

* rubrik-sonar-user-access-list

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| user_name | The name of the user to search for. |  | Optional |
| user_email | The email or the UPN of the user to search for. |  | Optional |
| search_time_period | Specify the search time period to look for user access. | 7 days | Optional |
| risk_levels | The comma-separated list of risk levels.<br/><br/>Supported values are: UNKNOWN_RISK, HIGH_RISK, MEDIUM_RISK, LOW_RISK, NO_RISK.<br/><br/>Note: For any other values, whether the obtained result is filtered or not, is not confirmed. | HIGH_RISK | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| RubrikPolaris.UserAccess | User Access Information. | unknown |

## Playbook Image

---

![Rubrik Retrieve User Access Information - Rubrik Polaris](../doc_files/Rubrik_Retrieve_User_Access_Information_-_Rubrik_Polaris.png)
