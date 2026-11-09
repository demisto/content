# TypeSafe Jev

The TypeSafe Jev pack provides Cortex XSOAR and Cortex XSIAM content for
probability-bearing judgments in security playbooks. It includes the TypeSafe
Jev integration, its configuration and command documentation, examples, and
unit tests.

The pack also includes the **TypeSafe Jev - Marketplace Daily Assessment**
playbook. It inventories installed Marketplace packs, reviews newer release
evidence with Jev, resolves mandatory dependencies, and routes uncertain or
potentially breaking updates to manual review. The playbook starts in dry-run
mode and does not change packs or cases unless `DryRun` is explicitly set to
`false`.

The integration exposes five commands:

- `jev-evaluate` evaluates multiple typed questions in one request.
- `jev-noul` evaluates a focused yes/no judgment.
- `jev-choice` selects an option from a defined set.
- `jev-score` scores a state against ordered levels.
- `jev-list-models` lists available TypeSafe model aliases.

Use explicit thresholds and route uncertain or high-impact decisions to an
analyst. Review your organization's data-handling requirements before sending
incident evidence or other sensitive content to the TypeSafe API.

For setup, workflow details, and test commands, see the
[Marketplace assessment playbook documentation](Playbooks/playbook-TypeSafe_Jev_-_Marketplace_Daily_Assessment_README.md).
