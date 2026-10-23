Search, inspect and act on the certificates held in Next-Gen Trust Security (NGTS) without leaving the investigation workspace. NGTS is reached through the Strata Cloud Manager API gateway.

This integration writes to the same `CertManagerSaaS.*` context as the Certificate Manager SaaS integration, so the pack's playbooks, incident type and fetch mapper serve both.

## Before you start

You need a Strata Cloud Manager **service account** (client ID and client secret) and the **TSG ID** of the tenant that holds NGTS.

1. In Strata Cloud Manager, open **Identity & Access** and create a service account. Copy its **client ID** and **client secret**; the secret is shown only once.
2. Give the service account one of the roles below, scoped to the tenant's TSG.
3. Enter the client ID and client secret in the **Client ID** and **Client Secret** fields, and the TSG ID in **TSG ID**.

The integration exchanges the client credentials for an access token scoped to the TSG ID. It caches the token and reuses it until about a minute before it expires (tokens last about 15 minutes). Changing the client secret, the Token URL or the Server URL invalidates the cached token. If the gateway rejects a cached token, the integration fetches a new one and retries once.

### Which TSG to use

**Use a tenant-wide service account and the tenant's TSG ID.** NGTS workspaces aren't separate TSGs: they divide the certificates inside one tenant, and the service account's role scope decides which workspaces it can reach. The integration works at tenant level, so an account limited to some workspaces can miss certificates and machines: searches, the expiry fetch and `!certificate` silently leave them out. `CertManagerSaaS.Certificate.TSGID` shows the owner that NGTS reports for each certificate.

### Roles

Grant the smallest role that covers the commands you use.

| Setup | Role | Commands |
| --- | --- | --- |
| **Read-only** | The built-in **View Only Administrator**, or a custom role with these NGTS permission sets, all read: `ngts.insights_certificate_inventory`, `ngts.insights_machines_page`, `ngts.configuration_certificate_lifecycle` | Test, fetch, `!certificate`, search, get, list-expiring, download, keystore download, machine list and get |
| **Full** | A custom role with `ngts.insights_certificate_inventory` **write**, `ngts.insights_certificate_requests` **write**, `ngts.insights_machines_page` read and `ngts.configuration_certificate_lifecycle` read | Everything, including `ngts-certificate-request`, `ngts-certificate-request-status` and `ngts-certificate-revoke` |

- `ngts.insights_certificate_inventory` read alone is enough for search, get, list-expiring, `!certificate`, download, keystore download and fetch, but not for the machine commands or `get include_machine_details=true`.
- Revocation needs `ngts.insights_certificate_inventory` **write**; certificate requests need `ngts.insights_certificate_requests` write.
- A missing permission is reported as **HTTP 403**.

### Server URL and Token URL

The defaults are the production endpoints: `https://api.strata.paloaltonetworks.com/ngts` and `https://auth.apps.paloaltonetworks.com/auth/v1/oauth2/access_token`. Change them only together, for a non-production Strata Cloud Manager environment.

## Revocation is destructive — restrict it

`ngts-certificate-revoke` asks the issuing certificate authority to revoke a certificate. **It cannot be undone**, and a revoked certificate stops being trusted by every client that checks revocation.

Under **Settings → Integrations → Integration Permissions**, grant `ngts-certificate-revoke` only to the roles that are allowed to take a certificate out of service. Revocation is keyed on the **SHA-1** fingerprint. Use the `comment` argument to record the Cortex case the revocation was performed for.

## Revocation approval rules

NGTS doesn't let a tenant service account request a revocation that needs approval. When a revocation approval rule covers the certificate's CA, `ngts-certificate-revoke` fails with `Subgraph errors redacted`, and **nothing is changed**: the certificate isn't revoked and no approval request is created. This is the safe default.

To revoke from Cortex anyway, add the integration's service account as a **requester exception** on the approval rule. Its revocations then go straight to the CA.

- **The approval control moves from NGTS to Cortex.** Revocations from this integration no longer wait for the NGTS approvers. Put an approval step in every playbook that revokes, for example a manual task or a conditional question before the revoke command. The **CertManagerSaaS Certificate Compromise Response** playbook already asks an analyst to confirm before it revokes. Also restrict the command, as described above.
- **Keep the exception narrow.** Use a dedicated service account that only this integration uses, and add it as an exception only on the approval rules that need it.

## Downloading a private key

`ngts-certificate-keystore-download` returns a certificate with its private key as War Room files. With `format=PEM` you get two files: the encrypted private key (`<common name>.key`) and the certificate chain, leaf first (`<common name>.pem`). With `format=PKCS12` you get one `<common name>.p12` file. The key never goes into the context.

**Where the passphrase comes from.** The command uses its `passphrase` argument; when that is empty, it uses the instance's **Keystore passphrase** setting. A playbook can't read the Cortex credentials store, but an instance setting can, so keep the passphrase there: on the setting, click **Select from vault** (**Switch to credentials** in older versions) and pick a saved credential. Check two things:

- The vault list preselects the first saved credential. Make sure you pick yours.
- Switching the setting back to a typed password keeps the old passphrase, because an empty field means "unchanged". To change it, pick another credential.

**Security note:**

- The private key passes through Cortex, encrypted with the passphrase you give. NGTS never sees the passphrase in clear text.
- Set the passphrase in the instance's **Keystore passphrase** setting, from a saved credential. Don't write it in playbooks, notes or chat.
- Anyone who can see the issue's War Room and knows the passphrase can use the key.
- Restrict the command by role. Under **Settings → Integrations → Integration Permissions**, grant `ngts-certificate-keystore-download` only to the roles that may handle private keys.

The download works only when all of these are true:

- **A VSatellite generated the private key.** The certificate was requested without a CSR, so the service generated the key on a VSatellite. Keys from your own CSR, and discovered certificates, can't be downloaded.
- **The VSatellite still has its encryption key.** After a VSatellite is registered again, the keys it generated before can't be exported.
- **The issuing CA provides the issuer chain.** The export needs the chain, and some CAs return only the certificate.
- **The service account's role has the Certificates permission set** (`ngts.insights_certificate_inventory`) at read access.

## Fetching expiry incidents

Turn on **Fetches incidents** to poll for certificates approaching expiry. One incident, of type **CertManagerSaaS Certificate Expiry**, is created per threshold a certificate crosses: 30 days before expiry raises a High incident, and 7 days a Critical one. The same fetch raises one High **CertManagerSaaS Revocation Failed** incident for each certificate whose `KEY_COMPROMISE` revocation is `FAILED`. The fetch works exactly as in the Certificate Manager SaaS integration; see its help for the details of *First fetch time* and *Look back*.

## Differences from Certificate Manager SaaS

- **Ownership is the TSG, not an application.** NGTS doesn't show applications in its UI and the integration doesn't use them, so there is no application list command, and `ngts-certificate-request` takes no application ID.
- **Test** requests a new access token (it never trusts a cached one) and runs a one-certificate search, which proves the credentials, the TSG and the inventory permission in one call.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `Strata Cloud Manager rejected the client credentials` | Wrong client ID or secret, a TSG ID the service account does not belong to, or a Token URL from another environment. |
| `HTTP 401` from a command | The gateway rejected a freshly issued token. The Server URL and the Token URL belong to different environments. |
| `HTTP 403` from a command | The service account's role does not permit the operation. See **Roles**. The gateway also answers an unsupported path with 403. |
| Fewer certificates than expected | The service account is limited to some workspaces. See **Which TSG to use**. |
| `Subgraph errors redacted` from `ngts-certificate-revoke` | Usually a revocation approval rule covers the certificate's CA, and NGTS refuses revocations requested by a service account. Nothing was changed. See **Revocation approval rules**. |
| `The CA did not revoke certificate …` | The CA refused the revocation (status FAILED). The message carries the CA's reason, for example that the certificate is already revoked. |
| `… doesn't hold the private key of certificate …` | A VSatellite didn't generate the private key, for example because the certificate came from your own CSR or was discovered. Only VSatellite-generated keys can be downloaded. |
| `The VSatellite encryption key … no longer exists` | The VSatellite was registered again, and its old encryption key is gone. The keys it generated before can't be exported. |
| `… is protected by a VSatellite key of type …` | The VSatellite uses a key type that the integration doesn't support yet. Only ED25519 is supported. |
| `… can't build the keystore: the issuing CA didn't provide the issuer certificates` | The CA returned only the certificate, not its chain (error 20602). The export needs the chain. |
| `The keystore download failed (HTTP …)` | The message carries the API's own reason. |

## Cortex XSIAM

- Expiry issues run the **CertManagerSaaS Certificate Expiry Remediation** playbook through the recommended automation rule **CertManagerSaaS Certificate Expiry Trigger**. Adopt the pack's playbooks in the Playbook Catalog, then enable that rule under **Investigation & Response → Automation → Automation Rules**.
- Fetched items become issues a few minutes after the fetch, through the automatically generated correlation rule. Issue exclusion rules can silently drop them.
