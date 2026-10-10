Pack helps to integrate Group-IB Digital Risk Protection and get violations incidents directly into Cortex XSOAR.
This integration was integrated and tested with version 1.0 of Group-IB Digital Risk Protection.

## Configure Group-IB Digital Risk Protection in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| GIB DRP API URL | The base URL of the Group-IB DRP API, not of the DRP web interface. For the SaaS portal this is <https://drp.group-ib.com/client_api>. | True |
| Username | The email address you log in to Group-IB DRP with. The password is the API key generated in your DRP profile. | True |
| Password | The API key generated in your Group-IB DRP profile. | True |
| Use system proxy settings | Whether to run the integration instance through the proxy server (HTTP or HTTPS) defined in the server configuration. | False |
| Trust any certificate (not secure) | Whether to ignore TLS/SSL certificate validation errors. Use it to test connection issues or to connect to a server without a valid certificate. | False |
| Incident type | The incident type to create when no classifier is set. | False |
| Fetch incidents | Whether to fetch Group-IB DRP violations as incidents. | False |
| Incidents Fetch Interval | The time between two fetches. | False |
| Incidents first fetch | The date or relative time to start fetching incidents from, for example 2026-01-01 or 3 days. | False |
| Number of requests per execution | The number of requests the integration sends to the DRP API in one fetch iteration (each request picks up to 30 violations). If you face runtime errors, lower the value. | True |
| Maximum incidents per fetch | The upper bound on the number of Cortex XSOAR incidents created in a single fetch iteration, applied per API page: the page (up to 30 violations) that reaches the limit is still processed in full, so one iteration can exceed the value by up to a page, and the remaining pages are left to the next iteration from the same seqUpdate cursor. Acts as a safety valve when "Number of requests per execution" combined with the API page size would otherwise produce a large burst (e.g. after a long downtime). Recommended range 100-500. Set to 0 to disable the cap (not recommended for production). | False |
| Filter by Violation Section | The DRP section to fetch violations from. Options map to the DRP `section` parameter: Web (1), Mobile Apps (2), Marketplace (3), Social Networks (4), Advertising (5), Instant Messengers (6). Leave empty to fetch from all sections. | False |
| Filter by Violation Type | The violation types to fetch (the DRP `subtypes[]` parameter). Leave empty to fetch every type. Known limitation: the bundled ciaops library sends a single subtype to the API, so a selection of two or more types is fetched unfiltered and applied client-side instead - correct, but heavier on the API. Selecting exactly one type is filtered server-side. | False |
| Fetch only Violations awaiting approval | Whether to create incidents only for violations that Group-IB has sent to you for a decision, i.e. whose approve state is `under_review`. These are the violations the Approve Violation and Reject Violation buttons act on. Leave disabled to create incidents for violations in every approve state. The filter applies to creation only: once a violation has an incident on this instance, its later changes (the decision, the take-down) still arrive and refresh or close that incident. | False |
| Filter by Violation Status | The violation statuses to create incidents for (status values as defined by the DRP API). The default selection covers the violations still being worked on. The filter applies to creation only: once a violation has an incident on this instance, its later status changes still arrive and refresh or close that incident. A violation that arrives already finished (`resolved`, `solved`, `legal`, `false_status`, or rejected by the customer) never creates an incident, whatever is selected. Leave empty to create incidents for every other status. Filtering is applied by the integration after parsing each portion, so the seqUpdate cursor advances even when a whole portion is filtered out. | False |
| Filter by Brand | The comma-separated list of brand IDs to request violations for. Get the available brands with !gibdrp-get-brands (War Room -> Playground) and use the `id` values, not the names. Known limitation: the bundled ciaops library currently sends only the first ID of the list to the API, so until it is updated a second ID has no effect - configure one brand per instance if you need more. | False |
| Incident severity | The severity assigned to every incident this instance creates. Configure one instance per severity to grade violations - for example a Phishing-only instance at Critical and a Scam-only instance at Medium. Cortex XSOAR stores severity on a fixed scale, so the levels are offered by name. | False |
| Create indicators from Violations | The violation types to create an indicator for, from the violation URI. Leave empty to create no indicators. The indicator is created by the postprocessing playbook (GIBDRPCreateViolationIndicator) from the new incident, so it is linked to the incident and carries Group-IB Digital Risk Protection as its source. Only an http or https URL, a domain or an IPv4 address becomes an indicator; any other URI - a marketplace seller ID, a messenger handle, a mail address - creates none. Reputation follows the violation type: Counterfeit, Scam, Malware and Phishing are published as Malicious, Partner policy compliance, Piracy and Trademark as Suspicious, and No violation as Benign. | False |
| Expire the indicator when the violation is closed | Whether to expire the indicator created from a violation when that violation is resolved, handed to legal, found false or rejected. Applies only to incidents created by this instance and to the violation types selected in "Create indicators from Violations". Leave disabled to keep the indicator active. | False |
| Close the incident when a violation is approved | Whether to close the incident as Resolved when the Approve Violation button (or the postprocessing playbook) successfully sends an approval through this instance. Leave disabled to keep the incident open until Group-IB DRP resolves the violation, which the pre-processing rule then closes. Rejecting a violation always closes the incident as False Positive: Group-IB DRP does nothing more with a rejected violation. | False |
| Download images | Whether to download the images of each violation. Enabling it can significantly slow down data collection. Images over 2 MB (or past a 5 MB per-incident total) are skipped to keep incidents within Cortex XSOAR entry limits; skipped images remain retrievable via gibdrp-get-violation-by-id. | False |
| Get Typosquatting Only | Whether to fetch only records of the Typosquatting type. When disabled, only violations are fetched, without Typosquatting detections. | False |
| Known violations retention (days) | The number of days the instance remembers the violations it created incidents for. A remembered violation is passed through to its incident on every change, whatever the status and approval filters say; a forgotten one is treated as new and has to pass them again. A violation is remembered from the last fetch that carried it, so 365 days covers any violation that changed within a year. 0 forgets everything, so every fetched violation is filtered as if it were new. | False |

## Violation Incidents

### Resolving Violations from the Incident

- The **GIB DRP Violation** layout has **Approve Violation** and **Reject Violation** buttons in the *Information From Group-IB* section. They run the `GIBDRPResolveViolation` automation, which sends the decision to Group-IB DRP.
- Both buttons appear only while the violation is waiting for you, that is while **GIB DRP Approve State** is `under_review`. Once the decision is made - from a button, from the playbook, or in the DRP portal - the approve state changes and the buttons are no longer offered.
- The decision is sent through the instance that fetched the incident. Without that, Cortex XSOAR would run the command on every enabled instance, and with several instances the ones that do not own the violation would fail the button.
- **Approve Violation** does not close the incident by default. An approval settles the customer's half of the case; the take-down continues in DRP afterwards, and the incident closes when the violation is resolved (see Automatic Incident Closing below). With **Close the incident when a violation is approved** enabled on the instance, the button closes the incident as *Resolved* at once.
- **Reject Violation** always closes the incident as *False Positive*: DRP does nothing more with a rejected violation, so nothing later would close the incident. If **Expire the indicator when the violation is closed** is enabled, the indicator created from the violation is expired as well.
- A violation can be changed only while its status is `detected` and its approve state is `under_review`. In any other state the button reports the violation's actual state and changes nothing.

### Automatic Incident Closing

- A violation incident is closed when the work on the violation is over. Two outcomes end it: Group-IB DRP finished with the violation - status `resolved` (taken down; older API versions spell it `solved`) or `legal` (handed to legal) - which closes the incident as *Resolved*; or the violation turned out not to be one - DRP set `false_status`, or the customer rejected it - which closes the incident as *False Positive*.
- For an incident that already exists, the close is done by the `GIBDRPIncidentUpdate` pre-processing rule as soon as the change arrives on a fetch. The fetch passes every change of a known violation through, so the status and approval filters of the instance do not hold the close back.
- For a violation that is already over when its incident is created - which the fetch avoids, so this covers incidents created another way - the close is done by the **Group-IB Digital Risk Protection - Violation Incident Postprocessing** playbook.
- A rejection made from the incident (button or playbook) closes the incident at once. An approval does not, unless **Close the incident when a violation is approved** is enabled.
- With **Expire the indicator when the violation is closed** enabled, every close above also expires the indicator created from the violation.
- Filters by section, type and brand never hide an update, because a violation never changes those. A **Known violations retention (days)** of `0` does: the update is then filtered as if the violation were new.

### The Postprocessing Playbook

New **GIB DRP Violation** incidents run the **Group-IB Digital Risk Protection - Violation Incident Postprocessing** playbook. It closes an incident whose violation is already over, creates the violation's indicator when the instance asked for one, and, while Group-IB DRP is waiting for the customer's decision, assigns an analyst and asks whether to approve the violation. The decision goes through `GIBDRPResolveViolation`, to the instance that fetched the incident.

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
| GIBDRP.Brand.name | string | The brand name. |
| GIBDRP.Brand.id | string | The brand ID. |

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
| GIBDRP.Subscription | string | The list of configured subscriptions. |

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
| id | The violation ID. | Required |
| download_images | Whether to download the violation's screenshots and attach them as files. Set to false for a quick status check. Possible values are: true, false. Default is true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBDRP.Violation.id | string | The violation ID. |
| GIBDRP.Violation.title | string | The violation title. |
| GIBDRP.Violation.description | string | The violation description. |
| GIBDRP.Violation.status | string | The violation status. |
| GIBDRP.Violation.violation_uri | string | The violation URI. |
| GIBDRP.Violation.source | string | The source section of the violation. |
| GIBDRP.Violation.detected | date | The time the violation was detected. |

### gibdrp-change-violation-status

***
Approves or rejects a single violation pending customer review (approveState `under_review`). Reports whether the instance wants the incident closed after an approval (the "Close the incident when a violation is approved" setting); the GIBDRPResolveViolation automation acts on it, and always closes the incident on a rejection.

#### Base Command

`gibdrp-change-violation-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The violation ID. | Required |
| status | The decision to send to Group-IB DRP. Possible values are: approve, reject. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBDRP.ViolationDecision.id | String | The violation ID. |
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
| url | A comma-separated list of violation URLs to submit (up to 100), each a valid http/https URL with a non-empty host. Every URL is submitted with the same violation subtype and brand. A URL already submitted for the same brand and subtype is rejected by Group-IB DRP ("This URL already exists"), so re-running the command with the same URL fails rather than creating a second violation. | Required |
| violation_subtype | The violation subtype assigned to every submitted URL. Possible values are: scam, trademark, phishing, copyright, counterfeit, malware, partnerPolicyCompliance. | Required |
| brand_id | The brand ID the violations belong to. Use !gibdrp-get-brands to list the brand IDs configured for your account. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBDRP.CreatedViolation.succeeded.url | String | The URL of the created violation. |
| GIBDRP.CreatedViolation.succeeded.brandId | String | The brand ID the violation was created for. |
| GIBDRP.CreatedViolation.succeeded.violationSubtype | String | The subtype assigned to the created violation. |
| GIBDRP.CreatedViolation.succeeded.violationId | String | The ID of the created violation in the DRP system. Can be passed to gibdrp-get-violation-by-id. |
| GIBDRP.CreatedViolation.failed.url | String | The URL rejected by the Group-IB DRP API \(populated on partial success\). |
| GIBDRP.CreatedViolation.failed.brandId | String | The brand ID of the rejected item. |
| GIBDRP.CreatedViolation.failed.violationSubtype | String | The subtype of the rejected item. |
| GIBDRP.CreatedViolation.failed.reason | String | The reason the item was rejected. |

#### Command example

```!gibdrp-create-violation url=https://phishing.example.com violation_subtype=phishing brand_id=exampleBrandId```

#### Context Example

```json
{
    "GIBDRP": {
        "CreatedViolation": {
            "failed": [],
            "succeeded": [
                {
                    "brandId": "exampleBrandId",
                    "url": "https://phishing.example.com",
                    "violationId": "exampleViolationId",
                    "violationSubtype": "phishing"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Created violations

>|brandId|url|violationId|violationSubtype|
>|---|---|---|---|
>| exampleBrandId | https:<span>//</span>phishing.example.com | exampleViolationId | phishing |
