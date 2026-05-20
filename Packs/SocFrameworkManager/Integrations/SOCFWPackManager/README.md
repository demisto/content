SOC Framework Pack Manager — internal HTTP layer used by the SOCFWPackManager
script to install SOC Framework content packs as system content. End users do
not invoke this integration directly.

## Architecture

This integration is paired with the **SOCFWPackManager** script in the same
pack. The script reads the SOC Framework pack catalog, sequences pack
installs, configures integration instances and jobs, and synchronizes the
`value_tags` lookup. Because XSIAM scripts can call `demisto.executeCommand`,
all orchestration lives there. This integration stores the tenant URL,
credentials, and TLS verification setting, and exposes a single command,
`socfw-install-pack`, that downloads a pack ZIP and uploads it as system
content. XSIAM integrations cannot call `demisto.executeCommand`, so the
integration deliberately performs only the work that needs raw HTTP.

End users run `!SOCFWPackManager action=apply pack_id=...` from the XSIAM
Playground. The script invokes `socfw-install-pack` on this integration
internally.

## Configure SOC Framework Pack Manager on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **API Keys** and create a
   Standard API key.
2. Copy the **Key**, the **Key ID**, and click **Copy URL** to capture the
   tenant Server URL.
3. Navigate to **Settings** > **Configurations** > **Integrations**.
4. Search for **SOC Framework Pack Manager**.
5. Click **Add instance** to create and configure a new integration instance.

   | **Parameter** | **Description** | **Required** |
   | --- | --- | --- |
   | Server URL | Tenant API URL (`https://api-tenant.xdr...`) or tenant URL (`https://tenant.xdr...`). The integration adds the `api-` prefix when it is missing. | True |
   | API Key ID | Numeric ID of the Standard API key. | True |
   | API Key | Secret value of the Standard API key. Stored masked. | True |
   | Trust any certificate (not secure) | Disable TLS certificate validation. Off by default. | False |
   | Use system proxy settings | Route HTTP traffic through the system proxy. Off by default. | False |

6. Click **Test** to validate the URL and credentials, then **Done**.

## Commands

You can execute these commands from the Cortex XSIAM CLI as part of an
automation or in a playbook. After you successfully execute a command, a
DBot message appears in the War Room with the command details.

### socfw-install-pack

***
Downloads a SOC Framework pack ZIP from the supplied URL and installs it on
the tenant as system content. Called by the SOCFWPackManager script — do not
invoke directly.

#### Base Command

`socfw-install-pack`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL of the pack ZIP to install (typically a GitHub release asset). | Required |
| filename | Asset filename, including the `.zip` extension. Derived from the URL when omitted. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCFramework.PackInstall.filename | String | Installed pack filename. |
| SOCFramework.PackInstall.url | String | Source URL the pack was downloaded from. |
| SOCFramework.PackInstall.status | String | Install status (success on completion). |
| SOCFramework.PackInstall.response | Unknown | Raw response from the demisto-sdk upload step. |

#### Command example

```!socfw-install-pack url=https://github.com/Palo-Cortex/secops-framework/releases/download/soc-optimization-unified-v3.6.3/soc-optimization-unified-v3.6.3.zip```

#### Context Example

```json
{
    "SOCFramework": {
        "PackInstall": {
            "filename": "soc-optimization-unified-v3.6.3.zip",
            "url": "https://github.com/Palo-Cortex/secops-framework/releases/download/soc-optimization-unified-v3.6.3/soc-optimization-unified-v3.6.3.zip",
            "status": "success",
            "response": {
                "success": true,
                "message": "Uploaded /home/demisto/Packs/soc-optimization-unified-v3.6.3"
            }
        }
    }
}
```

#### Human Readable Output

> Pack **soc-optimization-unified-v3.6.3.zip** installed successfully.
