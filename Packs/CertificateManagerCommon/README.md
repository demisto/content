# Certificate Manager Common

Shared content for the **Certificate Manager SaaS** and **Next-Gen Trust Security** packs. Both products are the same certificate service: CyberArk Certificate Manager SaaS, reached directly, or delivered by Palo Alto Networks through Strata Cloud Manager as Next-Gen Trust Security (NGTS). They fetch the same issues and share the issue types, fields and layout below.

This pack has no integration of its own. Installing either product pack installs it automatically.

## What's in the pack

| Content | Purpose |
| --- | --- |
| **CertManagerSaaS Certificate Expiry** incident type | A certificate that crossed an expiry threshold. |
| **CertManagerSaaS Revocation Failed** incident type | A key-compromise revocation the CA did not complete. |
| **Incident fields** | Certificate ID, fingerprint, common name, expiry date, days to expiry, issuer, owning application (Certificate Manager SaaS), owning TSG (NGTS), installation location. |
| **Layout** and **layout rules** | `CertManagerSaaS Certificate Expiry Layout`, shared by both incident types, and the XSIAM rules that bind it to them. |
| **CertManagerSaaS - Fetch Classifier** | Gives each fetched issue its type (Certificate Expiry or Revocation Failed), from the `IssueType` key the fetch writes. |
| **CertManagerSaaS - Fetch Incoming Mapper** | Maps the certificate data either integration fetches onto the issue. |

## Dependencies

- **Filters And Transformers** (mandatory) — ships `SetIfEmpty`, which the fetch mapper uses to fall back from the issuer common name to the issuer DN.

## Expiry issues

Enable **Fetches incidents** on the integration instance. The fetch classifier and mapper are the integration's defaults. The classifier types each issue, so the instance's **Incident type** can stay empty; a custom type set there still applies to expiry issues.

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

## XSIAM notes

- Fetched certificates become issues through the correlation rule XSIAM creates for each fetching integration ("… Alerts (automatically generated)"). Allow a few minutes after a fetch.
- Issue exclusion rules (**Settings → Exception & Exclusion Configuration**) silently drop matching issues. Check them if expected issues never appear.
- The layout rule is XSIAM-only; on XSOAR the incident type binds the layout directly.
- Issue domain is assigned automatically; nothing in the pack sets it.
- Incident fields, incident type and mapper require the **xsiam** or **agentix** module.
