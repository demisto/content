Pack helps to integrate Group-IB Digital Risk Protection and get violations incidents directly into Cortex XSOAR.
This integration was integrated and tested with version 1.0 of Group-IB Digital Risk Protection.

## Configure Group-IB Digital Risk Protection in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| GIB DRP API URL | Base URL of the Group-IB DRP API, not of the DRP web interface. For the SaaS portal this is <https://drp.group-ib.com/client_api>. | True |
| Fetch incidents |  | False |
| Incident type |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Incidents Fetch Interval |  | False |
| Username |  | True |
| Password |  | True |
| Filter by Violation Section | Fetch Violations found in one DRP section only. Options map to the DRP `section` parameter: Web (1), Mobile Apps (2), Marketplace (3), Social Networks (4), Advertising (5), Instant Messengers (6). Leave empty to fetch from all sections. | False |
| Filter by Violation Type | Fetch only Violations of the selected types (the DRP `subtypes[]` parameter). Leave empty to fetch every type. Known limitation: the bundled ciaops library sends a single subtype to the API, so a selection of two or more types is fetched unfiltered and applied client-side instead - correct, but heavier on the API. Selecting exactly one type is filtered server-side. | False |
| Fetch only Violations awaiting approval | Create incidents only for Violations that Group-IB has sent to you for a decision, i.e. whose approve state is `under_review`. These are the Violations the Approve Violation and Reject Violation buttons act on. Leave disabled to create incidents for Violations in every approve state. The filter applies to creation only: once a Violation has an incident on this instance, its later changes (the decision, the take-down) still arrive and refresh or close that incident. | False |
| Close the incident when a violation is approved | When the Approve Violation button (or the postprocessing playbook) successfully sends an approval through this instance, also close the incident as Resolved. Leave disabled to keep the incident open until Group-IB DRP resolves the violation, which the pre-processing rule then closes. Rejecting a violation always closes the incident as False Positive: Group-IB DRP does nothing more with a rejected violation. | False |
| Filter by Brand | Requests only Violations associated with the specified Brand IDs, as a comma-separated list. Get the available brands with !gibdrp-get-brands (War Room -> Playground) and use the `id` values, not the names. Known limitation: the bundled ciaops library currently sends only the first id of the list to the API, so until it is updated a second id has no effect - configure one brand per instance if you need more. | False |
| Incidents first fetch | Date to start fetching incidents from. | False |
| Download images | Enables or disables loading of each image in each violation. Can significantly affect the speed of data collection if the parameter is enabled, i.e. set to True. Images over 2 MB (or past a 5 MB per-incident total) are skipped to keep incidents within XSOAR entry limits; skipped images remain retrievable via gibdrp-get-violation-by-id. | False |
| Get Typosquatting Only | Returns only records of the Typosquatting type. If not specified, you consume only violations - without Typosquatting detections. | False |
| Number of requests per execution | How many requests the integration sends to the DRP API in one fetch iteration (each request picks up to 30 violations). If you face runtime errors, lower the value. | True |
| Maximum incidents per fetch | Upper bound on the number of XSOAR incidents created in a single fetch iteration, applied per API page: the page (up to 30 violations) that reaches the limit is still processed in full, so one iteration can exceed the value by up to a page, and the remaining pages are left to the next iteration from the same seqUpdate cursor. Acts as a safety valve when "Number of requests per execution" combined with the API page size would otherwise produce a large burst (e.g. after a long downtime). Recommended range 100-500. Set to 0 to disable the cap (not recommended for production). | False |
| Filter by Violation Status | Create incidents only for Group-IB DRP violations whose `status` is one of the selected values (status values as defined by the DRP API). The default, `detected` and `in_response`, covers the violations still being worked on. The filter applies to creation only: once a violation has an incident on this instance, its later status changes still arrive and refresh or close that incident. A violation that arrives already finished (`resolved`, `solved`, `legal`, `false_status`, or rejected by the customer) never creates an incident, whatever is selected. Leave empty to create incidents for every other status. Filtering is applied by the integration after parsing each portion, so the seqUpdate cursor advances even when a whole portion is filtered out. | False |
| Incident severity | Severity assigned to every incident this instance creates. Configure one instance per severity to grade Violations - for example a Phishing-only instance at Critical and a Scam-only instance at Medium. Cortex stores severity on a fixed scale, so the levels are offered by name. | False |
| Create indicators from Violations | Create an indicator from the Violation URI for the selected Violation types only. Leave empty to create no indicators. The indicator is created by the postprocessing playbook (GIBDRPCreateViolationIndicator) from the new incident, so it is linked to the incident and carries Group-IB Digital Risk Protection as its source. Only an http or https URL, a domain or an IPv4 address becomes an indicator; any other URI - a marketplace seller id, a messenger handle, a mail address - creates none. Reputation follows the Violation type: Counterfeit, Scam, Malware and Phishing are published as Malicious, Partner policy compliance, Piracy and Trademark as Suspicious, and No violation as Benign. | False |
| Expire the indicator when the violation is closed | When the violation of an incident created by this instance is resolved, handed to legal, found false or rejected, also expire the indicator that was created from it. Applies only to violation types selected in "Create indicators from Violations". Leave disabled to keep the indicator active. | False |
| Known violations retention (days) | How many days the instance remembers the violations it created incidents for. A remembered violation is passed through to its incident on every change, whatever the status and approval filters say; a forgotten one is treated as new and has to pass them again. A violation is remembered from the last fetch that carried it, so 365 days covers any violation that changed within a year. 0 forgets everything, so every fetched violation is filtered as if it were new. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gibdrp-get-brands

***
Receive all configured brands.

#### Base Command

`gibdrp-get-brands`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBDRP.Brand.name | string | Brand name. |
| GIBDRP.Brand.id | string | Brand ID. |

#### Command example

```!gibdrp-get-brands```

#### Context Example

```json
{
    "GIBDRP": {
        "Brand": [
            {
                "id": "PvY1BZUBSFbLZGo2x8TA",
                "name": "Example Brand"
            }
        ]
    }
}
```

#### Human Readable Output

>### Installed Brands

>|Name|Id|
>|---|---|
>| Example Brand | PvY1BZUBSFbLZGo2x8TA |

### gibdrp-get-subscriptions

***
Receive all configured subscriptions.

#### Base Command

`gibdrp-get-subscriptions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBDRP.Subscription | string | List of configured subscriptions. |

#### Command example

```!gibdrp-get-subscriptions```

#### Context Example

```json
{
    "GIBDRP": {
        "Subscription": [
            "scam"
        ]
    }
}
```

#### Human Readable Output

>### Purchased subscriptions

>|Subscriptions|
>|---|
>| scam |

### gibdrp-get-violation-by-id

***
Getting a single violation by its ID.

#### Base Command

`gibdrp-get-violation-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID violation. | Required |
| download_images | Whether to download the violation's screenshots and attach them as files. Set to false for a quick status check. Possible values are: true, false. Default is true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBDRP.Violation.id | string | Violation ID. |
| GIBDRP.Violation.title | string | Violation title. |
| GIBDRP.Violation.description | string | Violation description. |
| GIBDRP.Violation.status | string | Violation status. |
| GIBDRP.Violation.violation_uri | string | Violation URI. |
| GIBDRP.Violation.source | string | Violation source section. |
| GIBDRP.Violation.detected | date | Detected timestamp. |

### gibdrp-change-violation-status

***
Approves or rejects a single violation pending customer review (approveState `under_review`). Reports whether the instance wants the incident closed after an approval (the "Close the incident when a violation is approved" setting); the GIBDRPResolveViolation automation acts on it, and always closes the incident on a rejection.

#### Base Command

`gibdrp-change-violation-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID violation. | Required |
| status | What status to change to. Possible values are: approve, reject. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBDRP.ViolationDecision.id | String | Violation ID. |
| GIBDRP.ViolationDecision.status | String | The decision sent, approve or reject. |
| GIBDRP.ViolationDecision.approveState | String | The approve state the violation moved to, approved or rejected. |
| GIBDRP.ViolationDecision.closeIncident | Boolean | Whether the instance is configured to close the incident after an approval. |

### gibdrp-create-violation

***
Creates one or more violations in the Group-IB DRP portal. Fails with an error entry if the DRP API rejects every submitted item; a partial success reports both accepted and rejected items.

#### Base Command

`gibdrp-create-violation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | Violation URL(s) to submit, each a valid http/https URL with a non-empty host. A comma-separated list of up to 100 URLs is supported; every URL is submitted with the same violation subtype and brand. A URL already submitted for the same brand and subtype is rejected by Group-IB DRP ("This URL already exists"), so re-running the command with the same URL fails rather than creating a second violation. | Required |
| violation_subtype | Violation subtype assigned to every submitted URL. Possible values are: scam, trademark, phishing, copyright, counterfeit, malware, partnerPolicyCompliance. | Required |
| brand_id | Brand ID the violation(s) belong to. Use !gibdrp-get-brands to list the brand IDs configured for your account. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBDRP.CreatedViolation.succeeded.url | String | URL of the created violation. |
| GIBDRP.CreatedViolation.succeeded.brandId | String | Brand ID the violation was created for. |
| GIBDRP.CreatedViolation.succeeded.violationSubtype | String | Subtype assigned to the created violation. |
| GIBDRP.CreatedViolation.succeeded.violationId | String | ID of the created violation in the DRP system. Can be passed to gibdrp-get-violation-by-id. |
| GIBDRP.CreatedViolation.failed.url | String | URL rejected by the Group-IB DRP API \(populated on partial success\). |
| GIBDRP.CreatedViolation.failed.brandId | String | Brand ID of the rejected item. |
| GIBDRP.CreatedViolation.failed.violationSubtype | String | Subtype of the rejected item. |
| GIBDRP.CreatedViolation.failed.reason | String | Reason the item was rejected. |
