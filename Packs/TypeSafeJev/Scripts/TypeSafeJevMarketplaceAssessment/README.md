Jev-reviewed platform Marketplace updates with recursive mandatory dependency installation and verified results.

This automation is intended to be used by the **TypeSafe Jev - Marketplace
Daily Assessment** playbook. It keeps tenant actions in deterministic code:
Jev evaluates bounded release evidence, while this automation validates every
answer, applies confidence gates, resolves dependencies, and decides whether an
update is installed or held for manual review.

## Permissions and safety

- `collect`, `assess`, `prepare_ai`, `apply_ai`, and `pack_detail` read tenant
  data through the selected Core REST API integration instance.
- `unpack_ai` and `wrap_ai` only transform data and do not call tenant APIs.
- `install`, `review`, and `close_review` can change the tenant. Use
  `dry_run=true` first and grant the Core REST API instance only the permissions
  required to read Marketplace metadata, install content packs, and manage the
  generated cases.
- Jev output is not treated as authorization. A release is eligible for
  automatic installation only after schema validation, evidence binding,
  dependency checks, and both probability and confidence thresholds of 0.80.
  All other outcomes are held for review.

## Examples

Collect a read-only Marketplace snapshot:

```text
!TypeSafeJevMarketplaceAssessment action=collect core_instance="Core REST API instance name"
```

Inspect one pack without changing the tenant:

```text
!TypeSafeJevMarketplaceAssessment action=pack_detail pack=TypeSafeJev core_instance="Core REST API instance name"
```

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Content Management |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| action | collect, assess, prepare_ai, unpack_ai, wrap_ai, apply_ai, publish, install, review, or pack_detail \(read-only pack review details\). close_review: after a verified update, resolve the review issue \+ case \(reason other, with comment\) and mark the review list entry resolved. |
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
| issue_id | close_review: numeric review issue ID. Optional; if blank the review issue is found by title "Marketplace Guard - manual review: &lt;pack&gt; ... -&gt; &lt;target_version&gt;". |
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
| TypeSafeJevMarketplace.Review | Manual review cases created/updated for held, unresolved or failed updates. | Unknown |
| TypeSafeJevMarketplace.PackDetail | Read-only pack review detail \(action=pack_detail\): installed/latest/target versions, intervening release notes and links, dependencies, enabled integration instances, referencing content, Jev decision/hold reason and open review issue/case. | Unknown |
| TypeSafeJevMarketplace.PackDetail.pack_id | Pack ID. | Unknown |
| TypeSafeJevMarketplace.PackDetail.pack_name | Pack display name. | Unknown |
| TypeSafeJevMarketplace.PackDetail.installed_version | Currently installed version \(null if not installed\). | Unknown |
| TypeSafeJevMarketplace.PackDetail.latest_version | Latest version available in Marketplace. | Unknown |
| TypeSafeJevMarketplace.PackDetail.target_version | Version under review \(input target_version or latest\). | Unknown |
| TypeSafeJevMarketplace.PackDetail.update_available | True if Marketplace has a newer version than installed. | Unknown |
| TypeSafeJevMarketplace.PackDetail.target_in_marketplace | True if target version exists in the Marketplace changelog. | Unknown |
| TypeSafeJevMarketplace.PackDetail.releases | Versions after installed up to target: version, released, breaking, breaking_notes, release_notes, github_url. | Unknown |
| TypeSafeJevMarketplace.PackDetail.marketplace_url | Marketplace page link. | Unknown |
| TypeSafeJevMarketplace.PackDetail.dependencies | Declared dependencies: pack_id, mandatory, required_min_version, installed_version, latest_marketplace_version, satisfied, available. | Unknown |
| TypeSafeJevMarketplace.PackDetail.integration_instances | Integration instances of the pack: name, id, brand, enabled, health, last_error. | Unknown |
| TypeSafeJevMarketplace.PackDetail.references | Best-effort content referencing the pack \(playbooks, automations, layouts, correlation_rules\): name, id, pack, matched. | Unknown |
| TypeSafeJevMarketplace.PackDetail.guard | Guard state: review_key, review_ledger, state_v2_entries, jev \(decisions with confidence\), hold_reason, recommended_action, open_review_issue \(issue_id, case_ids, status\). | Unknown |
| TypeSafeJevMarketplace.PackDetail.gaps | Data that could not be retrieved. | Unknown |

## Known Limitations

1. This automation is supported only on Cortex XSIAM.
2. The automation requires the Core REST API integration.
3. If Cortex stops polling a Marketplace installation and the target version
   cannot be verified, the update is held for review with its installer task ID.
   Check the task and installed version before retrying.
4. A tenant administrator must verify the minimum Core REST API permissions in
   their environment before enabling non-dry-run operation.
