HackerOne integration allows users to fetch reports by using the fetch incidents capability. It also provides commands to retrieve all the reports and programs.
This integration was integrated and tested with API version v1 of HackerOne.

## Advanced Filter
The`advanced_filter` parameter used both in the `hackerone-report-list` command and in the integration configuration, is used to filter results based on attribute values.
The general filtering syntax is as follows:

```{"attribute": "value1, value2"}```
- `attribute` is the name of the attribute that the filter will be applied against.
- `value` is the value being checked for. You can specify multiple values as a comma-separated list for the attributes that are accepting the multiple values according to the API document.
- To specify multiple filters, use the comma ( , ) to separate them 
  (for example, `{"attribute1": "value1, value2", "attribute2" : "value3, value4"}`).

To get the detailed information regarding the valid attributes for filtering user can refer to the [HackerOne API documentation](https://api.hackerone.com/customer-resources/#reports-get-all-reports).

## Configure HackerOne in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Server URL to connect to HackerOne. | True |
| Username | The username of the user. | True |
| Maximum number of incidents per fetch | The maximum limit is 100. | False |
| First fetch time interval | Date or relative timestamp to start fetching incidents from. <br/><br/>Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, etc | False |
| Program Handle | Fetches reports based on the specified program handle. Supports comma separated values.<br/><br/>Note: To get program handle, use the "hackerone-program-list" command. | True |
| State | Fetches reports based on the specified report state. <br/><br/>Note: Supports comma separated values. | False |
| Severity | Fetches reports based on severity ratings of the report. <br/><br/>Note: Supports comma separated values. | False |
| Advanced Filters | By providing advanced filters users can get specific reports according to their requirements. Supports JSON format.<br/><br/>Note: This will take higher precedence over "Program Handle", "State" and "Severity".<br/><br/>Format accepted: \{"filter\[attribute1\]\[\]": "value1, value2", "filter\[attribute2\]" : "value3"\}<br/><br/>For example: \{"filter\[closed_at__gt\]" : "2020-10-26T10:48:16.834Z", "filter\[state\]\[\]" : "new, triaged"\}<br/><br/>To know more visit: https://api.hackerone.com/customer-resources/#reports-get-all-reports. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Incident type |  | False |
| Fetch incidents |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### hackerone-report-list
***
Retrieves all the reports based on program handle and provided arguments.


#### Base Command

`hackerone-report-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| program_handle | The program handle to fetch the reports based on the specified handle. Users can get the list of the program_handle by executing the "hackerone-program-list" command.<br/><br/>Note: Supports comma separated values. | Required | 
| sort_by | Sort the reports based on the attributes provided.<br/><br/>Possible values: swag_awarded_at, bounty_awarded_at, last_reporter_activity_at, first_program_activity_at, last_program_activity_at, triaged_at, created_at, closed_at, last_public_activity_at, last_activity_at, disclosed_at.<br/><br/>Note: The default sort order for an attribute is descending. Prefix the attributes with a hyphen to sort in ascending order. Supports comma separated values.<br/><br/>Example: -last_reporter_activity_at, created_at. | Optional | 
| page_size | The number of reports to retrieve per page. Default value is 50. <br/><br/>Note: Possible values are between 1 and 100. | Optional | 
| page_number | Page number to retrieve the reports from the specified page. Default value is 1. | Optional | 
| advanced_filter | By providing advanced filters, users can get specific reports according to their requirements. Supports JSON format.<br/><br/>Note: This will take higher precedence over "program_handle", "filter_by_keyword", "state" and "severity".<br/><br/>Format accepted: {"filter[attribute1][]": "value1, value2", "filter[attribute2]" : "value3"}<br/><br/>For example: {"filter[closed_at__gt]":"2020-10-26T10:48:16.834Z","filter[state][]":"new, triaged"}. | Optional | 
| filter_by_keyword | The keyword filter to retrieve the reports by title and keywords. | Optional | 
| state | The state filter to retrieve the reports by current report state.<br/><br/>Possible values: new, pending-program-review, triaged, needs-more-info, resolved, not-applicable, informative, duplicate, spam, retesting.<br/><br/>Note: Supports comma separated values. | Optional | 
| severity | The severity filter to retrieve the reports by the severity ratings.<br/><br/>Possible values: none, low, medium, high, critical.<br/><br/>Note: Supports comma separated values. | Optional | 
| limit | Number of reports to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HackerOne.Report.id | String | The unique ID of the report. | 
| HackerOne.Report.type | String | The type of the object of HackerOne. | 
| HackerOne.Report.attributes.title | String | The title of the report. | 
| HackerOne.Report.attributes.state | String | The state of the Report. It can be new, pending-program-review, triaged, needs-more-info, resolved, not-applicable, informative, duplicate, spam or retesting. | 
| HackerOne.Report.attributes.created_at | Date | The date and time the object was created. Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.vulnerability_information | String | Detailed information about the vulnerability including the steps to reproduce as well as supporting material and references. | 
| HackerOne.Report.attributes.triaged_at | Date | The date and time the object was triaged. Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.closed_at | Date | The date and time the object was closed. Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.last_reporter_activity_at | String | The date and time that the most recent reporter activity was posted on the report. Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.first_program_activity_at | String | The date and time that the first program activity was posted on the report. Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.last_program_activity_at | String | The date and time that the most recent program activity was posted on the report. Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.bounty_awarded_at | String | The date and time that the most recent bounty was awarded on the report. Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.swag_awarded_at | String | The date and time that the most recent swag was awarded on the report. Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.disclosed_at | String | The date and time the report was disclosed. Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.reporter_agreed_on_going_public_at | String | The date and time the reporter agreed for the public disclosure. Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.last_public_activity_at | String | The date and time that the most recent public activity was posted on the report. Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.last_activity_at | String | The date and time that the most recent activity was posted on the report. Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.source | String | A free-form string defining the source of the report for tracking purposes. For example, "detectify", "rapid7" or "jira". | 
| HackerOne.Report.attributes.timer_bounty_awarded_elapsed_time | Number | The total number of seconds that have elapsed between when the timer started and when it stopped ticking. The timer does not take weekends into account. If the field is null and the corresponding miss_at field is set, it means the timer is still counting. | 
| HackerOne.Report.attributes.timer_bounty_awarded_miss_at | Date | The date and time the system expects the program to have awarded a bounty by. The field is null when the system does not expect the report to receive a bounty at the time. | 
| HackerOne.Report.attributes.timer_first_program_response_miss_at | Date | The date and time the system expects the program to have posted an initial public comment to the report by. | 
| HackerOne.Report.attributes.timer_first_program_response_elapsed_time | Number | The total number of seconds that have elapsed between when the timer started and when it stopped ticking. The timer does not take weekends into account. If the field is null and the corresponding miss_at field is set, it means the timer is still counting. | 
| HackerOne.Report.attributes.timer_report_resolved_miss_at | Date | The date and time the system expects the program to have closed the report by. The field is null when the report seems blocked by the reporter. | 
| HackerOne.Report.attributes.timer_report_resolved_elapsed_time | Number | The total number of seconds that have elapsed between when the timer started and when it stopped ticking. The timer does not take weekends into account. If the  field is null and the corresponding miss_at field is set, it means the timer is still counting. | 
| HackerOne.Report.attributes.timer_report_triage_miss_at | Date | The date and time the system expects the program to have triaged the report by. The  field is null when the system does not expect the report to be triaged at the time. | 
| HackerOne.Report.attributes.timer_report_triage_elapsed_time | Number | The total number of seconds that have elapsed between when the timer started and when it stopped ticking. The timer does not take weekends into account. If the field is null and the corresponding miss_at field is set, it means the timer is still counting. | 
| HackerOne.Report.relationships.reporter.data.id | String | The unique ID of the reporter. | 
| HackerOne.Report.relationships.reporter.data.type | String | The type of the object of HackerOne. | 
| HackerOne.Report.relationships.reporter.data.attributes.username | String | The username of the reporter. | 
| HackerOne.Report.relationships.reporter.data.attributes.name | String | The name of the reporter. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.disabled | Boolean | Indicates if the reporter is disabled. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.created_at | String | The date and time the object was created. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.profile_picture.62x62 | String | URL of the profile photo of a reporter of size 62x62. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.profile_picture.82x82 | String | URL of the profile photo of a reporter of size 82x82. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.profile_picture.110x110 | String | URL of the profile photo of a reporter of size 110x110. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.profile_picture.260x260 | String | URL of the profile photo of a reporter of size 260x260. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.bio | String | The reporter's biography, as provided by the reporter. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.reputation | Number | The reputation of the reporter. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.signal | Number | The signal of the reporter. This number ranges from -10 to 7. The closer to 7, the higher the average submission quality of the reporter. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.impact | Number | The impact of the reporter. This number ranges from 0 to 50. The closer to 50, the higher the average severity of the reporter's reports is. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.website | String | The reporter's website, as provided by the reporter. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.location | String | The reporter's location, as provided by the reporter. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.hackerone_triager | Boolean | Indicates if the reporter is a hackerone triager. | 
| HackerOne.Report.data.relationships.program.data.id | String | The unique ID of the program. | 
| HackerOne.Report.data.relationships.program.data.type | String | The type of the object of HackerOne. | 
| HackerOne.Report.data.relationships.program.data.attributes.handle | String | The handle of the program. | 
| HackerOne.Report.data.relationships.program.data.attributes.created_at | String | The date and time the object was created. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.program.data.attributes.updated_at | String | The date and time the object was updated. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.severity.data.id | String | The unique ID of the severity. | 
| HackerOne.Report.data.relationships.severity.data.type | String | The type of the severity of HackerOne. | 
| HackerOne.Report.data.relationships.severity.data.attributes.rating | String | The qualitative rating of the severity. | 
| HackerOne.Report.data.relationships.severity.data.attributes.author_type | String | The involved party that provided the severity. | 
| HackerOne.Report.data.relationships.severity.data.attributes.user_id | Number | The unique id of the user who created the object. | 
| HackerOne.Report.data.relationships.severity.data.attributes.created_at | String | The date and time the object was created. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.severity.data.attributes.score | Number | The vulnerability score calculated from the Common Vulnerability Scoring System \(CVSS\). | 
| HackerOne.Report.data.relationships.severity.data.attributes.attack_complexity | String | A CVSS metric that describes the conditions beyond the attacker's control that must exist in order to exploit the vulnerability. | 
| HackerOne.Report.data.relationships.severity.data.attributes.attack_vector | String | A CVSS metric that reflects the context by which vulnerability exploitation is possible. | 
| HackerOne.Report.data.relationships.severity.data.attributes.availability | String | A CVSS metric that measures the availability of the impacted component resulting from a successfully exploited vulnerability. | 
| HackerOne.Report.data.relationships.severity.data.attributes.confidentiality | String | A CVSS metric that measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability. | 
| HackerOne.Report.data.relationships.severity.data.attributes.integrity | String | A CVSS metric that measures the impact to the integrity of a successfully exploited vulnerability. | 
| HackerOne.Report.data.relationships.severity.data.attributes.privileges_required | String | A CVSS metric that describes the level of privileges an attacker must possess before successfully exploiting the vulnerability. | 
| HackerOne.Report.data.relationships.severity.data.attributes.user_interaction | String | A CVSS metric that captures the requirement for a user, other than the attacker, to participate in the successful compromise of the vulnerability component. | 
| HackerOne.Report.data.relationships.severity.data.attributes.scope | String | A CVSS metric that determines if a successful attack impacts a component other than the vulnerable component. | 
| HackerOne.Report.data.relationships.weakness.data.id | String | The unique ID of the weakness. | 
| HackerOne.Report.data.relationships.weakness.data.type | String | The type of the object of HackerOne. | 
| HackerOne.Report.data.relationships.weakness.data.attributes.name | String | The name of the weakness. | 
| HackerOne.Report.data.relationships.weakness.data.attributes.description | String | The raw description of the weakness. | 
| HackerOne.Report.data.relationships.weakness.data.attributes.external_id | String | The weakness' external reference to CWE or CAPEC. | 
| HackerOne.Report.data.relationships.weakness.data.attributes.created_at | String | The date and time the object was created. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.custom_field_values.data.id | String | The unique ID of the custom field value. | 
| HackerOne.Report.data.relationships.custom_field_values.data.type | String | The type of the object of HackerOne. | 
| HackerOne.Report.data.relationships.custom_field_values.data.attributes.value | String | The attribute's value. | 
| HackerOne.Report.data.relationships.custom_field_values.data.attributes.created_at | String | The date and time the object was created. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.custom_field_values.data.attributes.updated_at | String | The date and time the object was updated. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.id | String | The unique ID of the custom field attribute. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.type | String | The type of the object of HackerOne. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.field_type | String | The type of custom field. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.label | String | The attribute's label. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.internal | Boolean | Internal or public custom field. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.required | Boolean | Whether the field is required or not. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.error_message | String | A custom error message when the regex validation fails. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.helper_text | String | The helper text for custom_field_attribute. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.configuration | String | An optional configuration for the attribute's type. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.checkbox_text | String | The text shown with a checkbox field. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.regex | String | A regex used to validate the input for a text field. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.created_at | String | The date and time the object was created. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.updated_at | String | The date and time the object was updated. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.archived_at | String | The date and time the object was archived. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.assignee.data.id | String | The unique ID of the user. | 
| HackerOne.Report.data.relationships.assignee.data.type | String | The type of the object of HackerOne. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.name | Unknown | The name of the assignee. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.created_at | String | The date and time the object was created. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.permissions | String | The permissions of the group/user. Possible values are reward_management, program_management, user_management, and report_management. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.username | String | The username of the assignee. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.disabled | Boolean | Indicates if the assignee is disabled. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.profile_picture.62x62 | String | URL of the profile photo of the assignee of size 62x62. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.profile_picture.82x82 | String | URL of the profile photo of the assignee of size 82x82. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.profile_picture.110x110 | String | URL of the profile photo of the assignee of size 110x110. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.profile_picture.260x260 | String | URL of the profile photo of the assignee of size 260x260. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.signal | Number | The signal of the assignee. The number ranges from -10 to 7. The closer to 7, the higher the average submission quality of the user. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.impact | Number | The impact of the assignee. This number ranges from 0 to 50. The closer to 50, the higher the average severity of the user's reports is. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.reputation | Number | The reputation of the assignee. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.bio | String | The assignee's biography, as provided by the assignee. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.website | String | The assignee's website, as provided by the assignee. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.location | String | The assignee's location, as provided by the assignee. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.hackerone_triager | Boolean | Indicates if the assignee is a hackerone triager. | 
| HackerOne.Report.data.relationships.structured_scope.data.id | String | The unique ID of the scope. | 
| HackerOne.Report.data.relationships.structured_scope.data.type | String | The type of the HackerOne object. | 
| HackerOne.Report.data.relationships.structured_scope.data.attributes.asset_type | String | The type of the asset. | 
| HackerOne.Report.data.relationships.structured_scope.data.attributes.asset_identifier | String | The identifier of the asset. | 
| HackerOne.Report.data.relationships.structured_scope.data.attributes.eligible_for_bounty | Boolean | If the asset is eligible for a bounty. | 
| HackerOne.Report.data.relationships.structured_scope.data.attributes.eligible_for_submission | Boolean | If the asset is eligible for a submission. | 
| HackerOne.Report.data.relationships.structured_scope.data.attributes.instruction | String | The raw instruction of the asset provided by the program. | 
| HackerOne.Report.data.relationships.structured_scope.data.attributes.max_severity | String | The qualitative rating of the maximum severity allowed on this asset. | 
| HackerOne.Report.data.relationships.structured_scope.data.attributes.created_at | Date | The date and time the object was created. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.structured_scope.data.attributes.updated_at | Date | The date and time the object was updated. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.structured_scope.data.attributes.reference | String | The customer defined reference identifier or tag of the asset. | 
| HackerOne.Report.data.relationships.bounties.data.id | String | The unique ID of the bounty. | 
| HackerOne.Report.data.relationships.bounties.data.type | String | The type of the HackerOne object. | 
| HackerOne.Report.data.relationships.bounties.data.attributes.created_at | Date | The date and time the object was created. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.bounties.data.attributes.amount | String | Amount in USD. | 
| HackerOne.Report.data.relationships.bounties.data.attributes.bonus_amount | String | Bonus amount in USD. | 
| HackerOne.Report.data.relationships.bounties.data.attributes.awarded_amount | String | Amount in awarded currency. | 
| HackerOne.Report.data.relationships.bounties.data.attributes.awarded_bonus_amount | String | Bonus amount in awarded currency. | 
| HackerOne.Report.data.relationships.bounties.data.attributes.awarded_currency | String | The currency used to award the bounty and bonus. | 


#### Command Example
```!hackerone-report-list program_handle=something_h1b page_size=2```

#### Context Example
```json
{
    "HackerOne": {
        "Report": [
            {
                "attributes": {
                    "created_at": "2021-08-10T07:17:41.923Z",
                    "first_program_activity_at": "2021-08-10T07:17:42.048Z",
                    "last_activity_at": "2021-08-10T07:17:42.048Z",
                    "last_program_activity_at": "2021-08-10T07:17:42.048Z",
                    "last_public_activity_at": "2021-08-10T07:17:42.048Z",
                    "last_reporter_activity_at": "2021-08-10T07:17:42.048Z",
                    "state": "new",
                    "title": "Do not use depreciated function isSecure",
                    "vulnerability_information": "## Summary:\nThe depreciated function isSecure is not compatible with for SSL verification.\n\n## Impact\n\nSSL verification will fail regardless of certificate authenticity."
                },
                "id": "1297733",
                "relationships": {
                    "custom_field_values": {
                        "data": [
                            {
                                "attributes": {
                                    "created_at": "2021-08-10T07:17:41.929Z",
                                    "updated_at": "2021-08-10T07:17:41.929Z",
                                    "value": "true"
                                },
                                "id": "198319",
                                "relationships": {
                                    "custom_field_attribute": {
                                        "data": {
                                            "attributes": {
                                                "checkbox_text": "Yes",
                                                "created_at": "2021-08-10T07:14:39.477Z",
                                                "field_type": "Checkbox",
                                                "helper_text": "Is the report urgent in need to be resolved?",
                                                "internal": false,
                                                "label": "Urgent",
                                                "required": false,
                                                "updated_at": "2021-08-10T07:14:39.477Z"
                                            },
                                            "id": "1362",
                                            "type": "custom-field-attribute"
                                        }
                                    }
                                },
                                "type": "custom-field-value"
                            }
                        ]
                    },
                    "program": {
                        "data": {
                            "attributes": {
                                "created_at": "2021-08-09T13:39:20.342Z",
                                "handle": "something_h1b",
                                "updated_at": "2021-08-10T09:29:56.853Z"
                            },
                            "id": "53994",
                            "type": "program"
                        }
                    },
                    "reporter": {
                        "data": {
                            "attributes": {
                                "created_at": "2021-08-02T09:27:56.324Z",
                                "disabled": false,
                                "hackerone_triager": false,
                                "name": "Jahnvi",
                                "profile_picture": {
                                    "110x110": "/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png",
                                    "260x260": "/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png",
                                    "62x62": "/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png",
                                    "82x82": "/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png"
                                },
                                "username": "jahnvi_crest"
                            },
                            "id": "1878386",
                            "type": "user"
                        }
                    },
                    "severity": {
                        "data": {
                            "attributes": {
                                "attack_complexity": "high",
                                "attack_vector": "adjacent",
                                "author_type": "User",
                                "availability": "none",
                                "confidentiality": "high",
                                "created_at": "2021-08-10T07:17:41.970Z",
                                "integrity": "low",
                                "privileges_required": "high",
                                "rating": "medium",
                                "scope": "changed",
                                "score": 6.2,
                                "user_id": 1878386,
                                "user_interaction": "none"
                            },
                            "id": "1185951",
                            "type": "severity"
                        }
                    },
                    "weakness": {
                        "data": {
                            "attributes": {
                                "created_at": "2017-01-05T01:51:19.000Z",
                                "description": "The program calls a function that can never be guaranteed to work safely.",
                                "external_id": "cwe-242",
                                "name": "Use of Inherently Dangerous Function"
                            },
                            "id": "20",
                            "type": "weakness"
                        }
                    }
                },
                "type": "report"
            },
            {
                "attributes": {
                    "closed_at": "2021-08-10T07:11:12.110Z",
                    "created_at": "2021-08-10T07:09:28.496Z",
                    "first_program_activity_at": "2021-08-10T07:09:28.603Z",
                    "last_activity_at": "2021-08-17T07:36:10.504Z",
                    "last_program_activity_at": "2021-08-10T07:11:37.062Z",
                    "last_public_activity_at": "2021-08-10T07:11:37.062Z",
                    "last_reporter_activity_at": "2021-08-10T07:11:37.062Z",
                    "state": "resolved",
                    "timer_first_program_response_elapsed_time": 103,
                    "title": "SQL injection vulnerability in user signup form",
                    "vulnerability_information": "## Summary:\n[add summary of the vulnerability]\n\n## Steps To Reproduce:\n[add details for how we can reproduce the issue]\n\n  1. [add step]\n  1. [add step]\n  1. [add step]\n\n## Supporting Material/References:\n[list any additional material (e.g. screenshots, logs, etc.)]\n\n  * [attachment / reference]\n\n## Impact\n\nCan query for all users in db"
                },
                "id": "1297727",
                "relationships": {
                    "assignee": {
                        "data": {
                            "attributes": {
                                "created_at": "2021-08-09T13:39:21.016Z",
                                "name": "Standard",
                                "permissions": [
                                    "report_management",
                                    "reward_management"
                                ]
                            },
                            "id": "112937",
                            "type": "group"
                        }
                    },
                    "program": {
                        "data": {
                            "attributes": {
                                "created_at": "2021-08-09T13:39:20.342Z",
                                "handle": "something_h1b",
                                "updated_at": "2021-08-10T09:29:56.853Z"
                            },
                            "id": "53994",
                            "type": "program"
                        }
                    },
                    "reporter": {
                        "data": {
                            "attributes": {
                                "created_at": "2021-08-02T09:27:56.324Z",
                                "disabled": false,
                                "hackerone_triager": false,
                                "name": "Jahnvi",
                                "profile_picture": {
                                    "110x110": "/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png",
                                    "260x260": "/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png",
                                    "62x62": "/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png",
                                    "82x82": "/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png"
                                },
                                "username": "jahnvi_crest"
                            },
                            "id": "1878386",
                            "type": "user"
                        }
                    },
                    "severity": {
                        "data": {
                            "attributes": {
                                "author_type": "User",
                                "created_at": "2021-08-10T07:09:28.534Z",
                                "rating": "low",
                                "user_id": 1878386
                            },
                            "id": "1185942",
                            "type": "severity"
                        }
                    },
                    "weakness": {
                        "data": {
                            "attributes": {
                                "created_at": "2017-01-05T01:51:19.000Z",
                                "description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.",
                                "external_id": "cwe-89",
                                "name": "SQL Injection"
                            },
                            "id": "67",
                            "type": "weakness"
                        }
                    }
                },
                "type": "report"
            }
        ]
    }
}
```

#### Human Readable Output

>### Report(s)
>|Report ID|Reporter Username|Title|State|Severity|Created At|Vulnerability Information|
>|---|---|---|---|---|---|---|
>| 1297733 | jahnvi_crest | Do not use depreciated function isSecure | new | medium | 2021-08-10T07:17:41.923Z | ## Summary:<br/>The depreciated function isSecure is not compatible with for SSL verification.<br/><br/>## Impact<br/><br/>SSL verification will fail regardless of certificate authenticity. |
>| 1297727 | jahnvi_crest | SQL injection vulnerability in user signup form | resolved | low | 2021-08-10T07:09:28.496Z | ## Summary:<br/>[add summary of the vulnerability]<br/><br/>## Steps To Reproduce:<br/>[add details for how we can reproduce the issue]<br/><br/>  1. [add step]<br/>  1. [add step]<br/>  1. [add step]<br/><br/>## Supporting Material/References:<br/>[list any additional material (e.g. screenshots, logs, etc.)]<br/><br/>  * [attachment / reference]<br/><br/>## Impact<br/><br/>Can query for all users in db |


### hackerone-program-list
***
Retrieves information about the programs in which the user is a member.


#### Base Command

`hackerone-program-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | The number of programs to retrieve per page. Default value is 50.<br/><br/>Note: Possible values are between 1 and 100. | Optional | 
| page_number | Page number to retrieve the programs from the specified page. Default value is 1. | Optional |
| limit | Number of programs to retrieve. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HackerOne.Program.id | String | The unique ID of the program. | 
| HackerOne.Program.type | String | The type of the object of HackerOne. | 
| HackerOne.Program.attributes.handle | String | The handle of the program. | 
| HackerOne.Program.attributes.policy | String | The policy of the program. | 
| HackerOne.Program.attributes.created_at | Date | The date and time the object was created. Formatted according to ISO 8601. | 
| HackerOne.Program.attributes.updated_at | Date | The date and time the object was updated. Formatted according to ISO 8601. | 


#### Command Example
```!hackerone-program-list page_size=2```

#### Context Example
```json
{
    "HackerOne": {
        "Program": [
            {
                "attributes": {
                    "created_at": "2021-08-09T13:39:20.342Z",
                    "handle": "something_h1b",
                    "policy": "# What we are looking for\r\nWe want to proactively discover and remediate security vulnerabilities on our digital assets\r\n\r\nThe vulnerabilities identified in the HackerOne reports will be classified by the degree of risk as well as the impact they present to the host system, this includes the amount and type of data exposed, privilege level obtained, the proportion of systems or users affected.\r\n\r\n# What is a Bug Bounty Program?\r\nsomething\u2019s Bug Bounty Program (BBP) is an initiative driven and managed by the something Information Security team. \r\n\r\n* Security researchers are encouraged to report any behavior impacting the information security posture of something\u2019 products and services. If you are performing research, please use your own accounts and do not interact with other people\u2019s accounts or data.\r\n* Document your findings thoroughly, providing steps to reproduce and send your report to us. Reports with complete vulnerability details, including screenshots or video, are essential for a quick response. If the report is not detailed enough to reproduce the issue, the issue will not be eligible for a reward.\r\n  *Reference HackerOne guidance on writing quality reports:\r\n   * https://docs.hackerone.com/hackers/quality-reports.html \r\n   * https://www.hacker101.com/sessions/good_reports\r\n\r\n* We will contact you to confirm that we\u2019ve received your report and trace your steps to reproduce your research.\r\n* We will work with the affected teams to validate the report.\r\n* We will issue bounty awards for eligible findings. To be eligible for rewards, reports must comply with all parts of this policy and you must be the first to report the issue to us. You must be 18 or older to be eligible for an award.\r\n* We will notify you of remediation and may reach out for questions or clarification. You must be available to provide additional information if needed by us to reproduce and investigate the report.\r\n\r\n\r\n# Response Targets\r\nWe will make a best effort to meet the following response targets for hackers participating in our program:\r\n\r\n* Time to first response (from report submit) - 1 business days\r\n* Time to triage (from report submit) - 2 business days \r\n* Time to bounty (from triage) - 10 business days\r\n\r\nWe\u2019ll try to keep you informed about our progress throughout the process.\r\n\r\n#  Program Rules\r\n* Do not try to further pivot into the network by using a vulnerability. The rules around Remote Code Execution (RCE), SQL Injection (SQLi), and FileUpload vulnerabilities are listed below.\r\n* Do not try to exploit service providers we use, prohibited actions include, but are not limited to bruteforcing login credentials of Domain Registrars, DNS Hosting Companies, Email Providers and/or others. The Firm does not authorize you to perform any actions to any property/system/service/data not listed below.\r\n* If you encounter Personally Identifiable Information (PII) contact us immediately. Do not proceed with access and immediately purge any local information, if applicable.\r\n* Please limit any automated scanning to 60 requests per second. Aggressive testing that causes service degradation will be grounds for removal from the program.\r\n\r\n* Submit one vulnerability per- report, unless you need to chain vulnerabilities to provide impact.\r\n* When duplicates occur, we only award the first report that was received (provided that it can be fully reproduced).\r\n* Multiple vulnerabilities caused by one underlying issue will be awarded one bounty.\r\n* Social engineering (e.g. phishing, vishing, smishing) is prohibited.\r\n* Make a good faith effort to avoid privacy violations, destruction of data, and interruption or degradation of our service. Only interact with accounts you own or with the explicit permission of the account holder.\r\n\r\n# Disclosure Policy\r\n* As this is a private program, please do not discuss this program or any vulnerabilities (even resolved ones) outside of the program without express consent from the organization.\r\n* Follow HackerOne's [disclosure guidelines](https://www.hackerone.com/disclosure-guidelines).\r\n\r\n\r\n# How To Create Accounts\r\n* Go to our Website\r\n* Register \r\n* use @hackerone.com email address\r\n* Only use accounts you're authorised to access\r\n\r\n# Rewards\r\nOur rewards are based on severity per the Common Vulnerability Scoring Standard (CVSS). Please note these are general guidelines, and that reward decisions are up to the discretion of something.\r\n\r\n#Out of scope vulnerabilities\r\n\r\n\r\n***Note: 0-day vulnerabilities may be reported 30 days after initial publication. We have a team dedicated to tracking these issues; hosts identified by this team and internally ticketed will not be eligible for bounty.***\r\n\r\nThe following issues are considered out of scope:\r\n \r\n When reporting vulnerabilities, please consider (1) attack scenario / exploitability, and (2) security impact of the bug. The following issues are considered out of scope:\r\n\r\n* Disruption of our service (DoS, DDoS).\r\n* PII - do not collect any personally identifiable information - including credit card information, addresses and phone numbers from other customers\r\n* Reports from automated tools or scans\r\n* Social engineering of employees or contractors\r\n* For the time being we are making all vulnerabilities in Flash files out of scope\r\n* Reports affecting outdated browsers\r\n* Known vulnerabilities on deprecated assets not currently covered by CloudFlare.\r\n* Missing security best practices and controls (rate-limiting/throttling, lack of CSRF protection, lack of security headers, missing flags on cookies, descriptive errors, server/technology disclosure - without clear and working exploit)\r\n* Lack of crossdomain.xml, p3p.xml, robots.txt or any other policy files and/or wildcard presence/misconfigurations in these\r\n* Use of a known-vulnerable libraries or frameworks - for example an outdated JQuery or AngularJS (without clear and working exploit)\r\n* Self-exploitation (cookie reuse, self cookie-bomb, self denial-of-service etc.)\r\n* Self Cross-site Scripting vulnerabilities without evidence on how the vulnerability can be used to attack another user\r\n* Lack of HTTPS\r\n* Reports about insecure SSL / TLS configuration\r\n* Password complexityrequirements, account/email enumeration, or any report that discusses how you can learn whether a given username or email address is easy to guess\r\n* Presence/Lack of autocomplete attribute on web forms/password managers\r\n* Server Banner Disclosure/Technology used Disclosure\r\n* Full Path Disclosure\r\n* IP Address Disclosure\r\n* CSRF on logout or insignificant functionalities\r\n* Publicly accessible login panels\r\n* Clickjacking\r\n* CSS Injection attacks (Unless it gives you ability to read anti-CSRF tokens or other sensitive information)\r\n* Tabnabbing\r\n* Host Header Injection (Unless it givesyou access to interim proxies)\r\n* Cache Poisoning\r\n* Reflective File Download\r\n* Cookie scoped to parent domain or anything related to the path misconfiguration and improperly scoped\r\n* Private IP/Hostname disclosures or real IP disclosures for services using CDN\r\n* Open ports which do not lead directly to a vulnerability\r\n* Weak Certificate Hash Algorithm\r\n* Any physical/wireless attempt against our property or data centers\r\n\r\n# Safe Harbor \r\nThis policy is designed to be compatible with common vulnerability disclosure good practice. It does not give you permission to act in any manner that is inconsistent with the law, or which might cause us to be in breach of any of its legal obligations, including but not limited to:\r\n\r\n* The General Data Protection Regulation 2016/679 (GDPR) andthe Data Protection Act 2018\r\n\r\nWe affirm that we will not seek prosecution of any security researcher who reports any security vulnerability on a service or system, where the researcher has acted in good faith and in accordance with this disclosure policy.\r\n\r\nsomething cannot authorize any activity on third-party products or guarantee they won\u2019t pursue legal action against you. We aren\u2019t responsible for your liability from actions performed on third parties.\r\n\r\nThank you for helping keep us and our users safe!\r\n\n",
                    "updated_at": "2021-08-10T09:29:56.853Z"
                },
                "id": "53994",
                "type": "program"
            },
            {
                "attributes": {
                    "created_at": "2021-08-09T13:41:35.764Z",
                    "handle": "checker_program_h1b",
                    "policy": "# What we are looking for\r\nWe want to proactively discover and remediate security vulnerabilities on our digital assets\r\n\r\nThe vulnerabilities identified in the HackerOne reports will be classified by the degree of risk as well as the impact they present to the host system, this includes the amount and type of data exposed, privilege level obtained, the proportion of systems or users affected.\r\n\r\n# What is a Bug Bounty Program?\r\nchecker_program\u2019s Bug Bounty Program (BBP) is an initiative driven and managed by the checker_program Information Security team. \r\n\r\n* Security researchers are encouraged to report any behavior impacting the information security posture of checker_program\u2019 products and services. If you are performing research, please use your own accounts and do not interact with other people\u2019s accounts or data.\r\n* Document your findings thoroughly, providing steps to reproduce and send your report to us. Reports with complete vulnerability details, including screenshots or video, are essential for a quick response. If the report is not detailed enough to reproduce the issue, the issue will not be eligible for a reward.\r\n  *Reference HackerOne guidance on writing quality reports:\r\n   * https://docs.hackerone.com/hackers/quality-reports.html \r\n   * https://www.hacker101.com/sessions/good_reports\r\n\r\n* We will contact you to confirm that we\u2019ve received your report and trace your steps to reproduce your research.\r\n* We will work with the affected teams to validate the report.\r\n* We will issue bounty awards for eligible findings. To be eligible for rewards, reports must comply with all parts of this policy and you must be the first to report the issue to us. You must be 18 or older to be eligible for an award.\r\n* We will notify you of remediation and may reach out for questions or clarification. You must be available to provide additional information if needed by us to reproduce and investigate the report.\r\n\r\n\r\n# Response Targets\r\nWe will make a best effort to meet the following response targets for hackers participating in our program:\r\n\r\n* Time to first response (from report submit) - 1 business days\r\n* Time to triage (from report submit) - 2 business days \r\n* Time to bounty (from triage) - 10 business days\r\n\r\nWe\u2019ll try to keep you informed about our progress throughout the process.\r\n\r\n#  Program Rules\r\n* Do not try to further pivot into the network by using a vulnerability. The rules around Remote Code Execution (RCE), SQL Injection (SQLi), and FileUpload vulnerabilities are listed below.\r\n* Do not try to exploit service providers we use, prohibited actions include, but are not limited to bruteforcing login credentials of Domain Registrars, DNS Hosting Companies, Email Providers and/or others. The Firm does not authorize you to perform any actions to any property/system/service/data not listed below.\r\n* If you encounter Personally Identifiable Information (PII) contact us immediately. Do not proceed with access and immediately purge any local information, if applicable.\r\n* Please limit any automated scanning to 60 requests per second. Aggressive testing that causes service degradation will be grounds for removal from the program.\r\n\r\n* Submit one vulnerability per- report, unless you need to chain vulnerabilities to provide impact.\r\n* When duplicates occur, we only award the first report that was received (provided that it can be fully reproduced).\r\n* Multiple vulnerabilities caused by one underlying issue will be awarded one bounty.\r\n* Social engineering (e.g. phishing, vishing, smishing) is prohibited.\r\n* Make a good faith effort to avoid privacy violations, destruction of data, and interruption or degradation of our service. Only interact with accounts you own or with the explicit permission of the account holder.\r\n\r\n# Disclosure Policy\r\n* As this is a private program, please do not discuss this program or any vulnerabilities (even resolved ones) outside of the program without express consent from the organization.\r\n* Follow HackerOne's [disclosure guidelines](https://www.hackerone.com/disclosure-guidelines).\r\n\r\n\r\n# How To Create Accounts\r\n* Go to our Website\r\n* Register \r\n* use @hackerone.com email address\r\n* Only use accounts you're authorised to access\r\n\r\n# Rewards\r\nOur rewards are based on severity per the Common Vulnerability Scoring Standard (CVSS). Please note these are general guidelines, and that reward decisions are up to the discretion of checker_program.\r\n\r\n#Out of scope vulnerabilities\r\n\r\n\r\n***Note: 0-day vulnerabilities may be reported 30 days after initial publication. We have a team dedicated to tracking these issues; hosts identified by this team and internally ticketed will not be eligible for bounty.***\r\n\r\nThe following issues are considered out of scope:\r\n \r\n When reporting vulnerabilities, please consider (1) attack scenario / exploitability, and (2) security impact of the bug. The following issues are considered out of scope:\r\n\r\n* Disruption of our service (DoS, DDoS).\r\n* PII - do not collect any personally identifiable information - including credit card information, addresses and phone numbers from other customers\r\n* Reports from automated tools or scans\r\n* Social engineering of employees or contractors\r\n* For the time being we are making all vulnerabilities in Flash files out of scope\r\n* Reports affecting outdated browsers\r\n* Known vulnerabilities on deprecated assets not currently covered by CloudFlare.\r\n* Missing security best practices and controls (rate-limiting/throttling, lack of CSRF protection, lack of security headers, missing flags on cookies, descriptive errors, server/technology disclosure - without clear and working exploit)\r\n* Lack of crossdomain.xml, p3p.xml, robots.txt or any other policy files and/or wildcard presence/misconfigurations in these\r\n* Use of a known-vulnerable libraries or frameworks - for example an outdated JQuery or AngularJS (without clear and working exploit)\r\n* Self-exploitation (cookie reuse, self cookie-bomb, self denial-of-service etc.)\r\n* Self Cross-site Scripting vulnerabilities without evidence on how the vulnerability can be used to attack another user\r\n* Lack of HTTPS\r\n* Reports about insecure SSL / TLS configuration\r\n* Password complexityrequirements, account/email enumeration, or any report that discusses how you can learn whether a given username or email address is easy to guess\r\n* Presence/Lack of autocomplete attribute on web forms/password managers\r\n* Server Banner Disclosure/Technology used Disclosure\r\n* Full Path Disclosure\r\n* IP Address Disclosure\r\n* CSRF on logout or insignificant functionalities\r\n* Publicly accessible login panels\r\n* Clickjacking\r\n* CSS Injection attacks (Unless it gives you ability to read anti-CSRF tokens or other sensitive information)\r\n* Tabnabbing\r\n* Host Header Injection (Unless it givesyou access to interim proxies)\r\n* Cache Poisoning\r\n* Reflective File Download\r\n* Cookie scoped to parent domain or anything related to the path misconfiguration and improperly scoped\r\n* Private IP/Hostname disclosures or real IP disclosures for services using CDN\r\n* Open ports which do not lead directly to a vulnerability\r\n* Weak Certificate Hash Algorithm\r\n* Any physical/wireless attempt against our property or data centers\r\n\r\n# Safe Harbor \r\nThis policy is designed to be compatible with common vulnerability disclosure good practice. It does not give you permission to act in any manner that is inconsistent with the law, or which might cause us to be in breach of any of its legal obligations, including but not limited to:\r\n\r\n* The General Data Protection Regulation 2016/679 (GDPR) andthe Data Protection Act 2018\r\n\r\nWe affirm that we will not seek prosecution of any security researcher who reports any security vulnerability on a service or system, where the researcher has acted in good faith and in accordance with this disclosure policy.\r\n\r\nchecker_program cannot authorize any activity on third-party products or guarantee they won\u2019t pursue legal action against you. We aren\u2019t responsible for your liability from actions performed on third parties.\r\n\r\nThank you for helping keep us and our users safe!\r\n\r\n",
                    "updated_at": "2021-08-10T09:29:56.984Z"
                },
                "id": "53996",
                "type": "program"
            }
        ]
    }
}
```

#### Human Readable Output

>### Program(s)
>|Program ID|Handle|Created At|Updated At|
>|---|---|---|---|
>| 53994 | something_h1b | 2021-08-09T13:39:20.342Z | 2021-08-10T09:29:56.853Z |
>| 53996 | checker_program_h1b | 2021-08-09T13:41:35.764Z | 2021-08-10T09:29:56.984Z |
