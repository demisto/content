Jev-reviewed platform Marketplace updates with recursive mandatory dependency installation and verified results.

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
| core_instance | Core REST API integration instance name. Required for actions that access tenant APIs. |
| jev_model | Expected TypeSafe Jev model alias for prepared and validated review batches. |
| snapshot | Marketplace snapshot returned by the collect action. |
| assessment | Validated Marketplace assessment returned by the assess or apply_ai action. |
| dry_run | Whether state-changing actions should only report the changes they would make. |
| review_plan | Release review plan returned by the prepare_ai action. |
| analysis_response | Jev response or responses to validate and apply. |
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
| TypeSafeJevMarketplace.PackDetail.pack_id | Pack ID. | Unknown |
| TypeSafeJevMarketplace.PackDetail.pack_name | Pack display name. | Unknown |
| TypeSafeJevMarketplace.PackDetail.installed_version | Currently installed version \(null if not installed\). | Unknown |
| TypeSafeJevMarketplace.PackDetail.latest_version | Latest version available in Marketplace. | Unknown |
| TypeSafeJevMarketplace.PackDetail.target_version | Version under review \(input target_version or latest\). | Unknown |
| TypeSafeJevMarketplace.PackDetail.update_available | True if Marketplace has a newer version than installed. | Unknown |
| TypeSafeJevMarketplace.PackDetail.target_in_marketplace | True if target version exists in the Marketplace changelog. | Unknown |
| TypeSafeJevMarketplace.PackDetail.releases | Versions after installed up to target: version, released, breaking, breaking_notes, release_notes, github_url. | Unknown |
| TypeSafeJevMarketplace.PackDetail.marketplace_url | Marketplace page link. | Unknown |
| TypeSafeJevMarketplace.PackDetail.dependencies | Declared Marketplace dependencies: pack_id, mandatory, required_min_version. | Unknown |
| TypeSafeJevMarketplace.PackDetail.gaps | Data that could not be retrieved. | Unknown |

## Workflow and safety

Use this automation from the **TypeSafe Jev - Marketplace Daily Assessment** playbook. Jev reviews bounded Marketplace release evidence; the automation validates answers, applies confidence thresholds, resolves mandatory dependencies, and routes uncertain or affected updates for manual review. Approved installations are delegated to the maintained `CommonScripts` `ContentPackInstaller`, then verified against installed versions.

`dry_run` defaults to `true`. Keep it enabled while validating the assessment. Non-dry-run actions may install content packs, create or update review issues, and manage associated cases. Grant the selected Core REST API instance only the permissions required for the actions you enable.

## Existing Marketplace content

- `XSOARContentUpdateNotifications` reports new releases. This playbook adds enabled-integration inventory and tenant-specific impact review.
- `ContentPackInstaller` performs the actual Marketplace installation. This automation passes approved pack IDs and exact versions after deterministic checks.
- The deprecated `MarketplacePackInstaller` is not used.

## Examples

Collect a read-only Marketplace snapshot:

```text
!TypeSafeJevMarketplaceAssessment action=collect core_instance="Core REST API instance name"
```

Inspect one pack without changing the tenant:

```text
!TypeSafeJevMarketplaceAssessment action=pack_detail pack=TypeSafeJev core_instance="Core REST API instance name"
```

## Decision controls

Jev output is not authorization. Automatic installation requires valid typed answers bound to the submitted evidence, resolved dependencies, and probability and confidence thresholds of at least 0.80. Uncertain, unsupported, or potentially affected releases are held for review.

## Known limitations

- Supported only on Cortex XSIAM and requires the Core REST API integration.
- Dependency metadata and release notes are limited to the data exposed by Marketplace APIs; `pack_detail` does not discover every tenant content object that references a pack.
- Verify the minimum Core REST API permissions in your tenant before enabling non-dry-run operation.
