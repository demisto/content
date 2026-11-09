# TypeSafe Jev

The TypeSafe Jev pack provides Cortex XSOAR and Cortex XSIAM content for
probability-bearing judgments in security playbooks. It includes the TypeSafe
Jev integration, its configuration and command documentation, examples, and
unit tests. The pack also includes a malware-analysis playbook for Cortex XSIAM.

The integration exposes five commands:

- `jev-evaluate` evaluates multiple typed questions in one request.
- `jev-noul` evaluates a focused yes/no judgment.
- `jev-choice` selects an option from a defined set.
- `jev-score` scores a state against ordered levels.
- `jev-list-models` lists available TypeSafe model aliases.

The **TypeSafe Jev - Malware Analysis** playbook enriches malware alerts with
endpoint, VirusTotal, and WildFire evidence. It uses Jev typed judgments to
support false-positive, manual-review, and containment routing.

Use explicit thresholds and route uncertain or high-impact decisions to an
analyst. Review your organization's data-handling requirements before sending
incident evidence or other sensitive content to the TypeSafe API.
