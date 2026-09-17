SOC Framework Pack Manager — internal HTTP layer used by the SOCFWPackManager
script to install SOC Framework content packs as system content. End users do
not invoke this integration directly.

## Architecture

This integration is paired with the **SOCFWPackManager** script in the same
pack. The script reads the SOC Framework pack catalog, sequences pack
installs, configures integration instances and jobs, and synchronizes the
`value_tags` lookup. Because Cortex XSIAM scripts can call
`demisto.executeCommand`, all orchestration lives there.

This integration stores the tenant URL, credentials, TLS verification setting,
and the pack catalog location. It exposes two commands: `socfw-install-pack`,
which downloads a pack ZIP and uploads it as system content, and
`socfw-catalog-url-get`, which returns the configured catalog location so the
script can read it. Cortex XSIAM integrations cannot call
`demisto.executeCommand`, so the integration deliberately performs only the
work that needs raw HTTP.

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
| Server URL | The tenant API URL or tenant URL. The integration adds the api- prefix when it is missing. | True |
| API Key ID | The numeric ID of the Standard API key, shown in the API Keys table. | True |
| API Key | The secret value of the Standard API key. | True |
| Trust any certificate (not secure) | Whether to disable TLS certificate validation. Off by default. | False |
| Use system proxy settings | Whether to route HTTP traffic through the system proxy. Off by default. | False |
| Pack catalog URL | The location of the SOC Framework pack_catalog.json. Override to point at a fork or branch. Leave empty to use the SOC Framework repository default. | False |

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
>
### socfw-catalog-url-get

***
Returns the SOC Framework pack catalog URL configured on this instance. Called by the SOCFWPackManager script so the catalog location is set once on the instance instead of passed as an argument on every run.

#### Base Command

`socfw-catalog-url-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCFramework.PackManager.CatalogURL | String | The pack catalog URL configured on this instance, or the SOC Framework default when the field is empty. |
