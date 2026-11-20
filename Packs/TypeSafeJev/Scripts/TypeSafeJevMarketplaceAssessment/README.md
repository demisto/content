Reviews Cortex Marketplace updates with Jev and installs eligible updates after dependency checks and verified results.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Content Management |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| action | collect, assess, prepare_ai, unpack_ai, wrap_ai, apply_ai, publish, install, review, pack_detail \(read-only pack review details\), or close_review \(resolve a linked review issue and case after verifying the exact installed target\). |
| core_instance | The Core REST API integration instance name. Required for actions that access tenant APIs. |
| jev_model | Expected TypeSafe Jev model alias for prepared and validated review batches. |
| snapshot | Marketplace snapshot returned by the collect action. |
| assessment | Validated Marketplace assessment returned by the assess or apply_ai action. |
| dry_run | Whether state-changing actions should only report the changes they would make. |
| review_plan | Release review plan returned by the prepare_ai action. |
| analysis_response | A list of JSON-serialized Jev response objects, one per analysis batch. A single response can also be passed as a JSON string. |
| batch_json | Serialized release evidence batch supplied to the analysis sub-playbook. |
| installation | TypeSafeJevMarketplace.Installation result \(for action=review\). |
| pack | Pack ID \(e.g. HelloWorld, Core\). Required for pack_detail and close_review. |
| target_version | Target pack version. Optional for pack_detail \(defaults to latest\); required for close_review \(must equal the installed version\). |
| issue_id | close_review: numeric review issue ID. Optional; if blank the review ledger entry for this pack and target is used. |
| case_id | close_review: case ID to close. Optional; defaults to the case linked to the review issue. |
| comment | close_review: resolution comment for issue and case. Optional; default "Marketplace Guard: &lt;pack&gt; updated to &lt;target_version&gt;, verified". |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| TypeSafeJevMarketplace.Snapshot | Current pack versions, newer release notes and observed enabled integrations. | Unknown |
| TypeSafeJevMarketplace.Assessment | Publisher breaking flags, explicit notices and environment evidence. | Unknown |
| TypeSafeJevMarketplace.Routing | Issue routing results. | Unknown |
| TypeSafeJevMarketplace.ReviewPlan | Prepared release batches and immutable finding keys. | Unknown |
| TypeSafeJevMarketplace.Batch | Evidence for the current Jev analysis batch. | Unknown |
| TypeSafeJevMarketplace.AnalystBatch | Wrapped AI result returned by the analysis sub-playbook. | Unknown |
| TypeSafeJevMarketplace.Installation | Verified installations, held updates and failed or unverified outcomes. | Unknown |
| TypeSafeJevMarketplace.Review | Manual review issues created or retained for held or failed updates. | Unknown |
| TypeSafeJevMarketplace.PackDetail | Read-only pack review detail \(action=pack_detail\): installed/latest/target versions, intervening release notes and declared dependencies. | Unknown |
| TypeSafeJevMarketplace.PackDetail.pack_id | Pack ID. | String |
| TypeSafeJevMarketplace.PackDetail.pack_name | Pack display name. | String |
| TypeSafeJevMarketplace.PackDetail.installed | Whether the pack is installed. | Boolean |
| TypeSafeJevMarketplace.PackDetail.installed_version | Currently installed version \(null if not installed\). | String |
| TypeSafeJevMarketplace.PackDetail.latest_version | Latest version available in Marketplace. | String |
| TypeSafeJevMarketplace.PackDetail.target_version | Version under review \(input target_version or latest\). | String |
| TypeSafeJevMarketplace.PackDetail.update_available | True if Marketplace has a newer version than installed. | Boolean |
| TypeSafeJevMarketplace.PackDetail.target_in_marketplace | True if target version exists in the Marketplace changelog. | Boolean |
| TypeSafeJevMarketplace.PackDetail.releases | Versions after installed up to target: version, released, breaking, breaking_notes, release_notes, github_url. | Unknown |
| TypeSafeJevMarketplace.PackDetail.marketplace_url | Marketplace page link. | String |
| TypeSafeJevMarketplace.PackDetail.dependencies | Declared Marketplace dependencies: pack_id, mandatory, required_min_version. | Unknown |
| TypeSafeJevMarketplace.PackDetail.gaps | Data that could not be retrieved. | Unknown |
| TypeSafeJevMarketplace.CloseReview | Verified closure result for a Marketplace review issue and its linked case. | Unknown |
| TypeSafeJevMarketplace.CloseReview.dry_run | Whether the action returned a preview without changing tenant state. | Boolean |
| TypeSafeJevMarketplace.CloseReview.would_resolve | Whether the verified issue and case would be resolved when dry_run is false. | Boolean |
| TypeSafeJevMarketplace.CloseReview.pack | Pack ID whose review was closed. | String |
| TypeSafeJevMarketplace.CloseReview.target_version | Verified installed target version. | String |
| TypeSafeJevMarketplace.CloseReview.installed_version | Installed version verified before closing the review. | String |
| TypeSafeJevMarketplace.CloseReview.issue_id | Resolved Marketplace review issue ID. | String |
| TypeSafeJevMarketplace.CloseReview.case_id | Resolved case ID linked to the review issue. | String |
| TypeSafeJevMarketplace.CloseReview.issue_comment | Resolution comment applied to the issue and case. | String |
| TypeSafeJevMarketplace.CloseReview.issue_status | Verified issue status after resolution. | String |
| TypeSafeJevMarketplace.CloseReview.case_status | Verified case status after resolution. | String |
| TypeSafeJevMarketplace.CloseReview.list_updated | Whether the review ledger was updated. | Boolean |
| TypeSafeJevMarketplace.CloseReview.completed_at | Completion time of the verified closure. | Date |

## Script Examples

### Example command

```text
!TypeSafeJevMarketplaceAssessment action=unpack_ai batch_json="{\"items\":[],\"StateJSON\":\"{}\",\"QuestionsJSON\":\"{}\"}"
```

### Context Example

```json
{
    "TypeSafeJevMarketplace.Batch": {
        "items": [],
        "StateJSON": "{}",
        "QuestionsJSON": "{}"
    }
}
```

### Human Readable Output

```json
{
  "items": [],
  "StateJSON": "{}",
  "QuestionsJSON": "{}"
}
```

## Workflow and safety

Use this automation through the **TypeSafe Jev - Marketplace Daily Assessment**
playbook. The automation gathers Marketplace and enabled-integration evidence,
prepares bounded Jev review batches, validates returned judgments, checks
mandatory dependencies, and verifies installation results.

`dry_run` defaults to `true`. Keep it enabled while validating the assessment.
For `close_review`, dry-run verifies the installed target and linked issue/case,
then returns a preview without resolving them or changing the review ledger.
The `publish`, `install`, `review`, and `close_review` actions can change tenant
state when `dry_run=false`; they may create or resolve review issues and cases
or install Marketplace content. `pack_detail`, `collect`, and assessment
preparation are read-only. Configure the selected Core REST API instance with
only the permissions required by the actions you enable.

Jev output is not authorization. Automatic installation requires valid typed
answers bound to the submitted evidence, resolved dependencies, and
probability and confidence thresholds of at least 0.80. Uncertain, unsupported,
or potentially affected releases are held for review.

## Known limitations

- The Marketplace assessment workflow is supported on Cortex XSIAM.
- Marketplace metadata and release notes are limited to the data exposed by
  Marketplace APIs.
- The inventory covers enabled integration instances. It does not claim full
  coverage of active playbook, script, or rule bindings, or external service
  versions.
