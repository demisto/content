# Next-Gen Trust Security

Bring Palo Alto Networks Next-Gen Trust Security (NGTS) into the Cortex XSOAR / XSIAM investigation workspace: raise an issue when a certificate approaches expiry, and let an analyst search, inspect, revoke and replace a certificate without leaving the case.

Next-Gen Trust Security is CyberArk Certificate Manager SaaS delivered through Strata Cloud Manager. The integration authenticates with a Strata Cloud Manager service account. The same service reached directly with a Certificate Manager SaaS API key has its own pack, **Certificate Manager SaaS**.

## What's in the pack

| Content | Purpose |
| --- | --- |
| **Next-Gen Trust Security** integration | `ngts-*` commands, the `certificate` reputation command, and fetch of expiring certificates and failed key-compromise revocations as issues. |
| **NextGenTrustSecurity - Test** | Test playbook. |

The issue types, fields, layout, classifier, mapper and playbooks come from the **Certificate Manager Common** pack, which is installed with this one. See its README for the playbooks and the XSIAM setup.

### Commands

- `certificate` (reputation)
- `ngts-certificate-search` · `ngts-certificate-get` · `ngts-certificate-list-expiring`
- `ngts-certificate-revoke` · `ngts-certificate-request` · `ngts-certificate-request-status` · `ngts-certificate-download`
- `ngts-certificate-keystore-download` (the certificate with its private key, encrypted with a passphrase; restrict it by role)
- `ngts-machine-list` · `ngts-machine-get`

Applications don't apply to NGTS; ownership is the tenant service group (TSG).

## Dependencies

Both are **mandatory**.

- **Certificate Manager Common** — the issue types, fields, layout, classifier, mapper and playbooks.
- **X509Certificate** — ships the `Certificate` indicator type that the `certificate` reputation command writes into.

## Setup

- **Service account.** Create a Strata Cloud Manager service account and grant it a role on the **Next-Gen Trust Security** app:
  - read-only use (search, get, list-expiring, reputation, machines, fetch): the built-in **View Only Administrator** role, or a custom role with *Certificates*, *Machines* and *Certificate Lifecycle* at read access;
  - full use (also request and revoke): a custom role with *Certificates* and *Certificate Requests* at write access, plus *Machines* and *Certificate Lifecycle* at read access. Revoke needs *Certificates* write.
- **Scope the account to the whole tenant.** NGTS workspaces aren't separate TSGs, and the integration works at tenant level: an account limited to some workspaces can miss certificates in search and fetch without any error.
- **Server and token URLs** default to production Strata Cloud Manager and only need changing for other environments.
- **Revocation approval rules.** If an approval rule covers a certificate's CA, NGTS refuses a revocation requested by a service account. The revoke command fails with "Subgraph errors redacted" and changes nothing. To revoke from Cortex, add the integration's service account as a requester exception on the rule. Its revocations then skip NGTS approval, so the control moves to Cortex:
  - put an approval step (for example a manual task) before the revoke command in every playbook that revokes; the Compromise Response playbook already asks an analyst;
  - use a dedicated service account for this integration, and add it only to the approval rules that need it.

  Without such a rule, revocations go straight to the CA.

## Reputation

The `certificate` command scores only revocation, and never scores a certificate Good. A confirmed or unverifiable `KEY_COMPROMISE` revocation is **Malicious**; a reported but unfinished one, or a revocation for any other reason, is **Suspicious**. The full table is in the **Certificate Manager Common** README. Expiry and self-signed certificates are left to the `CertificateReputation` script.

## The Strata Cloud Manager web filter

The Strata Cloud Manager gateway runs a security filter over every request. It rejects text that resembles an attack — SQL-like phrases, HTML or script tags, file paths — even in a revocation comment written in plain English (for example "Revoked in Cortex case 123"). The integration reports such a rejection as a filter block, quoting the text that caused it; reword the text and retry.

## Restricting the revoke command

`ngts-certificate-revoke` is destructive. Restrict it to specific roles under **Settings → Configurations → Integration Permissions** (`/configuration/commandPermissions`) rather than relying on playbook-level guards.
