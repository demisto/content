# Certificate Manager SaaS

Bring CyberArk Certificate Manager SaaS into the Cortex XSOAR / XSIAM investigation workspace: raise an issue when a certificate approaches expiry, and let an analyst search, inspect, revoke and replace a certificate without leaving the case.

This pack is the SaaS counterpart to **CyberArk Certificate Manager Self-Hosted** (the `Venafi` pack), which covers TPP / self-hosted deployments. The same service delivered through Strata Cloud Manager has its own pack, **Next-Gen Trust Security**.

## What's in the pack

| Content | Purpose |
| --- | --- |
| **Certificate Manager SaaS** integration | `cmsaas-*` commands, the `certificate` reputation command, and fetch of expiring certificates and failed key-compromise revocations as issues. |
| **CertificateManagerSaaS - Test** | Test playbook. |

The issue types, fields, layout, classifier, mapper and playbooks come from the **Certificate Manager Common** pack, which is installed with this one. See its README for the playbooks and the XSIAM setup.

### Commands

- `certificate` (reputation)
- `cmsaas-certificate-search` · `cmsaas-certificate-get` · `cmsaas-certificate-list-expiring`
- `cmsaas-certificate-revoke` · `cmsaas-certificate-request` · `cmsaas-certificate-request-status` · `cmsaas-certificate-download`
- `cmsaas-certificate-keystore-download` (the certificate with its private key, encrypted with a passphrase; restrict it by role)
- `cmsaas-machine-list` · `cmsaas-machine-get`
- `cmsaas-application-list`

## Dependencies

Both are **mandatory**.

- **Certificate Manager Common** — the issue types, fields, layout, classifier, mapper and playbooks.
- **X509Certificate** — ships the `Certificate` indicator type that the `certificate` reputation command writes into.

## Reputation

The `certificate` command scores only revocation, and never scores a certificate Good. A confirmed or unverifiable `KEY_COMPROMISE` revocation is **Malicious**; a reported but unfinished one, or a revocation for any other reason, is **Suspicious**. The full table is in the **Certificate Manager Common** README. Expiry and self-signed certificates are left to the `CertificateReputation` script.

## Restricting the revoke command

`cmsaas-certificate-revoke` is destructive. Restrict it to specific roles under **Settings → Configurations → Integration Permissions** (`/configuration/commandPermissions`) rather than relying on playbook-level guards.
