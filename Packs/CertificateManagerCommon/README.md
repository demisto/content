# Certificate Manager Common

Shared content for the **Certificate Manager SaaS** and **Next-Gen Trust Security** packs. Both products are the same certificate service: CyberArk Certificate Manager SaaS, reached directly, or delivered by Palo Alto Networks through Strata Cloud Manager as Next-Gen Trust Security (NGTS). They fetch the same issues and share the playbooks below.

This pack has no integration of its own. Installing either product pack installs it automatically.

## What's in the pack

| Content | Purpose |
| --- | --- |
| **CertManagerSaaS Certificate Expiry Remediation** playbook | Runs on every expiry issue: refreshes the certificate, fills the issue fields, sets severity, then assigns the case to `CertificateOwnerEmail` or a member of `AssigneeRole` (unassigned when both are empty) — or requests a replacement when `AutoRenew` is `true` (default `false`). |
| **CertManagerSaaS Certificate Compromise Response** playbook | Compromised certificate: enrich, show the blast radius, ask an analyst to confirm, revoke, request a replacement. Also runs on revocation-failed issues, to retry the revocation. |
| **CertManagerSaaS Certificate Compliance Scan** playbook | Finds self-signed, weak-key, deprecated-hash and over-long-validity certificates in one inventory pass. |
| **CertManagerSaaS Certificate Request** playbook | Reusable sub-playbook: request a certificate, poll until issued, return the outcome. Optionally downloads the private key and chain (`DownloadPrivateKey`). Set its outputs to *Shared globally* in the parent. |
| **CertManagerSaaS Certificate Renewal and Keystore Download** playbook | Example: renew a certificate and download it with its private key and chain. Stops before installing it on a target. Doesn't run by itself. See [Certificate renewal and keystore download example](#certificate-renewal-and-keystore-download-example). |
| **CertManagerSaaS Certificate Expiry** incident type | Bound to the Expiry Remediation playbook, which runs automatically. |
| **CertManagerSaaS Revocation Failed** incident type | A key-compromise revocation the CA did not complete. Bound to the Compromise Response playbook. |
| **Incident fields** | Certificate ID, fingerprint, common name, expiry date, days to expiry, issuer, owning application (Certificate Manager SaaS), owning TSG (NGTS), installation location. |
| **Layout** and **layout rules** | `CertManagerSaaS Certificate Expiry Layout`, shared by both incident types, and the XSIAM rules that bind it to them. |
| **CertManagerSaaS - Fetch Classifier** | Gives each fetched issue its type (Certificate Expiry or Revocation Failed), from the `IssueType` key the fetch writes. |
| **CertManagerSaaS - Fetch Incoming Mapper** | Maps the certificate data either integration fetches onto the issue. |
| **CertManagerSaaS Certificate Expiry Trigger** | XSIAM: a recommended automation rule that runs the Expiry Remediation playbook on expiry issues. |
| **CertManagerSaaS Revocation Failed Trigger** | XSIAM: a recommended automation rule that runs the Compromise Response playbook on revocation-failed issues. |

## Dependencies

All three are **mandatory**.

- **Filters And Transformers** — ships `SetIfEmpty`, which the fetch mapper uses to fall back from the issuer common name to the issuer DN.
- **CommonScripts** — `Set`, `SetAndHandleEmpty`, `Print`, `DeleteContext`, `AssignAnalystToIncident`, `GetErrorsFromEntry` and `IsIntegrationAvailable`, used by the playbooks.
- **CommonPlaybooks** — `GenericPolling`, used by the Certificate Request sub-playbook to wait for issuance.

## Expiry issues

Enable **Fetches incidents** on the integration instance. The fetch classifier and mapper are the integration's defaults, and the Expiry Remediation playbook runs on every fetched issue. The classifier types each issue, so the instance's **Incident type** can stay empty; a custom type set there still applies to expiry issues.

One issue is raised per threshold crossing: crossing 30 days raises a High issue, crossing 7 days raises a separate Critical one. Severity is never below Medium: on XSIAM a Low issue creates no case and no grouping, so an expiring certificate there would be invisible.

| Threshold crossed | Severity |
| --- | --- |
| 7 days | Critical |
| 30 days | High |
| A wider fetch window | Medium |

The service evaluates expiry once a day, so any fetch interval of a day or less sees each crossing as soon as the service does.

## Revocation-failed issues

The same fetch raises one **High** "CertManagerSaaS Revocation Failed" issue for each certificate whose `KEY_COMPROMISE` revocation the CA did not complete (revocation status `FAILED`). The key was reported compromised, but clients still trust the certificate, so a person must act. The issue description carries the CA's error. A certificate raises a new issue only after it leaves the failed state and fails again.

## Reputation

Both integrations' `certificate` command scores only revocation, and never scores a certificate Good:

| Revocation | Verdict |
| --- | --- |
| `KEY_COMPROMISE`, and the CA's revocation list confirms it revoked | Malicious |
| `KEY_COMPROMISE` submitted, and the CA can't be checked (a private CA) | Malicious |
| `KEY_COMPROMISE` failed, waiting for approval, or the CA list shows it not revoked | Suspicious, or Malicious with the **Score reported key compromise as** setting |
| Revoked for any other reason | Suspicious |
| Anything else, including a rejected approval | Unknown |

CM SaaS checks public certificates against the CAs' revocation lists about every six hours (`GlobalRevocation` in context); private CAs aren't on those lists, so their certificates usually read `UNKNOWN`. Expiry and self-signed certificates are left to the `CertificateReputation` script of the `Certificate` indicator type.

## Running both integrations

The playbooks work with either integration, or both:

- **Lookups** (search, get) run on every enabled integration, Certificate Manager SaaS first and Next-Gen Trust Security second, and their results land in the same context. When both tenants hold the same certificate, the Next-Gen Trust Security result wins.
- **Each run starts clean:** the playbooks first clear certificate data left in the incident by an earlier run.
- **Write actions** (revoke, replacement request) go to the integration instance that returned the certificate: each result carries `SourceBrand` and `SourceInstance`.
- **A standalone request** (Certificate Request sub-playbook with no certificate) goes to the only enabled integration. With both enabled, it must be told which one through `SourceIntegration` (and `SourceInstance`); otherwise it stops and reports failure.
- **Nothing irreversible runs on an ambiguous lookup:** revoke and auto-renewal act only when exactly one certificate was resolved. Fetched issues carry the certificate fingerprint, so the Expiry Remediation playbook looks it up exactly.

## Certificate renewal and keystore download example

**CertManagerSaaS Certificate Renewal and Keystore Download** shows the first half of certificate delivery. It renews a certificate through the Certificate Request sub-playbook and downloads the new certificate with its private key and chain to the War Room, as a PKCS12 file or PEM files.

- **It stops before installing the certificate on a target.** It does not deliver the certificate anywhere. A placeholder task marks where the install step goes: replace it with the upload command of your target's integration.
- **It's an example.** Copy it and adapt it before you use it in production. It doesn't run by itself: no issue type or automation rule starts it.
- **Prerequisite:** a key generated by a VSatellite. Only such keys can be exported.

**Security note.** The private key leaves the certificate service and passes through Cortex:

- The key is always encrypted with a passphrase. Set it in the integration instance's **Keystore passphrase** setting, from a saved credential, and leave the playbook's `KeystorePassphrase` empty.
- The keystore files stay in the War Room after the run. Anyone who can read the case and knows the passphrase can use the key.
- The integration you add for the install step receives the key and the passphrase. Check how it sends them and whether it shows them in the War Room.

## XSIAM notes

- **Enable the playbook on XSIAM.** XSIAM runs playbooks on issues through automation rules, not through the issue type:
  1. Adopt the playbooks: **Playbooks → Playbook Catalog**, open each `CertManagerSaaS …` playbook and choose **Adopt this playbook**. Only adopted playbooks can run on issues.
  2. Enable the recommended rules **CertManagerSaaS Certificate Expiry Trigger** and **CertManagerSaaS Revocation Failed Trigger** under **Investigation & Response → Automation → Automation Rules**. They apply to newly created issues only.
- Fetched certificates become issues through the correlation rule XSIAM creates for each fetching integration ("… Alerts (automatically generated)"). Allow a few minutes after a fetch.
- Issue exclusion rules (**Settings → Exception & Exclusion Configuration**) silently drop matching issues. Check them if expected issues never appear.
- The layout rule is XSIAM-only; on XSOAR the incident type binds the layout directly.
- Issue domain is assigned automatically; nothing in the pack sets it.
- Incident fields, incident type and mapper require the **xsiam** or **agentix** module. Commands and playbooks work without them.
