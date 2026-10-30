Search, inspect and act on the certificates held in CyberArk Certificate Manager SaaS (formerly Venafi TLS Protect Cloud) without leaving the investigation workspace.

## Before you start

You need two things: the **API host for your region**, and an **API key** issued on that tenant.

### Server URL

The region is a subdomain prefix, and the US region is the bare host. There is no `api.us.venafi.cloud`.

| Region | Server URL |
| --- | --- |
| United States | `https://api.venafi.cloud` |
| European Union | `https://api.eu.venafi.cloud` |
| United Kingdom | `https://api.uk.venafi.cloud` |
| Australia | `https://api.au.venafi.cloud` |
| Singapore | `https://api.sg.venafi.cloud` |
| Canada | `https://api.ca.venafi.cloud` |

An API key issued in one region is rejected by every other region with **HTTP 401**. If the credential is known to be good, a 401 almost always means the Server URL points at the wrong region.

The Certificate Manager SaaS **web console host is not the API host**. Using the console URL here returns an opaque CDN error.

### API key

1. Sign in to Certificate Manager SaaS.
2. Open your user preferences and copy the **API Key**.
3. Paste it into the **API Key** field of this instance.

The field is a credentials object, so only the password half is used — leave the user name empty. Click **Select from vault** (**Switch to credentials** in older versions) to use a saved credential instead, which is the recommended option when an administrator manages the key centrally.

> If your role has the **Credentials** permission set to *None*, the instance form shows *"Credentials are locked by admin"* and you cannot select a saved credential. Type the key in directly, or ask an administrator to grant the permission.

## Revocation is destructive — restrict it

`cmsaas-certificate-revoke` asks the issuing certificate authority to revoke a certificate. **It cannot be undone**, and a revoked certificate stops being trusted by every client that checks revocation — which usually means an outage for whatever it was protecting.

It is deliberately kept as its own command so that it can be restricted independently of everything else this integration does. Under **Settings → Integrations → Integration Permissions**, grant `cmsaas-certificate-revoke` only to the roles that are allowed to take a certificate out of service; the read commands can stay open to all analysts.

Two further notes:

- Revocation is keyed on the **SHA-1** fingerprint. A digest of any other length is rejected before the call is made, because the API answers an unmatched fingerprint with success and no result — which would otherwise read as "revoked" when nothing happened.
- Use the `comment` argument to record the Cortex case or incident the revocation was performed for. It is stored on the revocation in Certificate Manager SaaS, which is what makes the action traceable in both directions.

## Downloading a private key

`cmsaas-certificate-keystore-download` returns a certificate with its private key as War Room files. With `format=PEM` you get two files: the encrypted private key (`<common name>.key`) and the certificate chain, leaf first (`<common name>.pem`). With `format=PKCS12` you get one `<common name>.p12` file. The key never goes into the context.

**Where the passphrase comes from.** The command uses its `passphrase` argument; when that is empty, it uses the instance's **Keystore passphrase** setting. A playbook can't read the Cortex credentials store, but an instance setting can, so keep the passphrase there: on the setting, click **Select from vault** (**Switch to credentials** in older versions) and pick a saved credential. Check two things:

- The vault list preselects the first saved credential. Make sure you pick yours.
- Switching the setting back to a typed password keeps the old passphrase, because an empty field means "unchanged". To change it, pick another credential.

**Security note:**

- The private key passes through Cortex, encrypted with the passphrase you give. Certificate Manager SaaS never sees the passphrase in clear text.
- Set the passphrase in the instance's **Keystore passphrase** setting, from a saved credential. Don't write it in playbooks, notes or chat.
- Anyone who can see the issue's War Room and knows the passphrase can use the key.
- Restrict the command by role. Under **Settings → Integrations → Integration Permissions**, grant `cmsaas-certificate-keystore-download` only to the roles that may handle private keys.

The download works only when all of these are true:

- **A VSatellite generated the private key.** The certificate was requested without a CSR, so the service generated the key on a VSatellite. Keys from your own CSR, and discovered certificates, can't be downloaded.
- **The VSatellite still has its encryption key.** After a VSatellite is registered again, the keys it generated before can't be exported.
- **The issuing CA provides the issuer chain.** The export needs the chain, and some CAs return only the certificate.
- **The API key's user has a role with the certificate keystore permission.**

## Fetching expiry incidents

Turn on **Fetches incidents** to poll for certificates approaching expiry. One incident, of type **CertManagerSaaS Certificate Expiry**, is created **per threshold a certificate crosses**.

- **The window is filtered server-side.** *Expiry window (days)* is applied by Certificate Manager SaaS, so a fetch costs the same on a tenant with forty thousand certificates as on one with forty.
- **Severity comes from the threshold crossed**: crossing 30 days before expiry raises a High incident, and crossing 7 days raises a second, Critical one. A window wider than 30 days adds a Medium incident when the certificate enters it. The ladder never drops below Medium, because a Low-severity issue creates neither a case nor a grouping.
- **On the first fetch, a certificate already past both thresholds produces only the Critical incident.**
- **An incident's "occurred" time is when the certificate crossed the threshold**, not when the fetch noticed it. That is why *Look back (minutes)* matters: a certificate starts matching the filter the moment it crosses the threshold, which can be hours before the fetch that first returns it. With a look back of zero those certificates are skipped permanently. The default of 1440 (one day) matches the daily cadence on which Certificate Manager SaaS evaluates expiry. Already-created incidents are deduplicated, so a larger look back costs bookkeeping rather than duplicate incidents.
- **Set *First fetch time* at least as large as the expiry window.** A certificate that has been inside the window for three weeks crossed its threshold three weeks ago, so a shorter first fetch will not see it.
- **A certificate imported into the inventory after crossing a threshold misses that threshold's incident**, because the crossing predates the current fetch range; it is picked up at its next threshold. Use `!cmsaas-certificate-list-expiring` to sweep for those, or reset the *last run* timestamp after a bulk import.
- **The same fetch raises failed key-compromise revocations.** A certificate whose `KEY_COMPROMISE` revocation is `FAILED` gets one High incident of type **CertManagerSaaS Revocation Failed**, with the CA's error in the description. It is raised again only after the certificate leaves the failed state and fails anew.
- **The expiry thresholds are tenant-global and set by the customer**, not by this pack. They drive the service's own expiry notifications, not this integration; if they do not include 7 and 30, those notifications and this integration's severity ladder describe different events. Running **Test** writes the tenant's configured thresholds and how they compare to the ladder into the instance debug log.

## What this instance can and cannot do

- **The device host is only partially available.** `cmsaas-certificate-get include_machine_details=true` resolves each installation's host from the machine detail endpoint. Appliance connectors (F5, FortiGATE, NetScaler, Panorama, KEMP, Radware) carry an address; cloud connectors (Azure Key Vault, Azure App Registration) carry a vault or tenant name and **no host at all**. A missing host is a normal outcome, not a failure: `InstallationLocations` still names where the certificate lives — the machine and its plugin, or the cloud keystore type and name.
- **Fingerprint and expiry date are filtered server-side; nothing else is.** The upstream GraphQL API exposes no filter for common name or issuer, so those criteria in `cmsaas-certificate-search` are applied while paging through the inventory 100 certificates at a time. On a large tenant, raise `max_pages` or narrow the search — the output states when a result was truncated. `cmsaas-certificate-list-expiring` filters entirely server-side and is not affected.
- **An unknown fingerprint and a malformed one look identical.** The API answers both with HTTP 200 and no results. For that reason the `!certificate` command produces **no DBotScore at all** for a fingerprint it could not resolve, rather than scoring it 0 (Unknown). Unresolved values are listed separately under `CertManagerSaaS.UnresolvedCertificate`.
- **Certificates are keyed differently by different commands.** Search, detail and revocation are keyed on the **fingerprint**; download and keystore download are keyed on the certificate **identifier**, which is what a completed certificate request returns. `CertManagerSaaS.Certificate.ID` carries the identifier for a certificate you found by fingerprint.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `HTTP 401` on **Test** | Wrong key, or the Server URL points at a region the key was not issued in. |
| `HTTP 403` from a certificate command | The GraphQL root field is not allow-listed for this tenant. This is **not** a credential problem. |
| `HTTP 404` from `cmsaas-application-list` | The applications endpoint is not enabled on this tenant. |
| `The Certificate Manager SaaS GraphQL gateway returned errors` | The gateway redacted a subgraph error, usually transient. Retry; if it persists on a wide search, lower `max_pages`. |
| `nothing was revoked` from `cmsaas-certificate-revoke` | No certificate carries that SHA-1 fingerprint on this tenant. The API reports an unknown and a deleted certificate identically. |
| `The CA did not revoke certificate …` | The CA refused the revocation (status FAILED). The message carries the CA's reason, for example that the certificate is already revoked. |
| `… doesn't hold the private key of certificate …` | A VSatellite didn't generate the private key, for example because the certificate came from your own CSR or was discovered. Only VSatellite-generated keys can be downloaded. |
| `The VSatellite encryption key … no longer exists` | The VSatellite was registered again, and its old encryption key is gone. The keys it generated before can't be exported. |
| `… is protected by a VSatellite key of type …` | The VSatellite uses a key type that the integration doesn't support yet. Only ED25519 is supported. |
| `… can't build the keystore: the issuing CA didn't provide the issuer certificates` | The CA returned only the certificate, not its chain (error 20602). The export needs the chain. |
| `The keystore download failed (HTTP …)` | The message carries the API's own reason. |
| No incidents fetched, but certificates are expiring | Either every crossing is already in the deduplication list, or it happened before the fetch range. Widen *First fetch time*, or reset the *last run* timestamp. |

## Cortex XSIAM

- Expiry issues run the **CertManagerSaaS Certificate Expiry Remediation** playbook through the recommended automation rule **CertManagerSaaS Certificate Expiry Trigger**. Adopt the pack's playbooks in the Playbook Catalog, then enable that rule under **Investigation & Response → Automation → Automation Rules**.
- Fetched items become issues a few minutes after the fetch, through the automatically generated correlation rule. Issue exclusion rules can silently drop them.
