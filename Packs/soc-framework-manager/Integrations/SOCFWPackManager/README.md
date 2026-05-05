# SOC Framework Pack Manager

Installs SOC Framework content packs into Cortex XSIAM from a pack ZIP URL (for example, a GitHub release asset).

## Architecture

This integration is the credential and pack-install layer for the SOC Framework. It is paired with the **SOCFWPackManager** script in this same pack and is not intended to be called directly by end users.

- The **SOCFWPackManager script** is the entry point. It reads the SOC Framework pack catalog, sequences pack installs, configures integration instances and jobs, and synchronizes the `value_tags` lookup. Because XSIAM scripts can call `demisto.executeCommand`, all orchestration lives there.
- The **SOC Framework Pack Manager integration** stores the tenant URL, API Key, and API Key ID, and exposes a single command, `socfw-install-pack`, that downloads a pack ZIP and uploads it as system content. XSIAM integrations cannot call `demisto.executeCommand`, so the integration deliberately does only the part of the work that needs raw HTTP.

End users run `!SOCFWPackManager action=apply pack_id=...` from the Playground. The script invokes `socfw-install-pack` on this integration internally.

## Configure an instance

1. Navigate to **Settings → Configurations → Integrations → API Keys** and create a Standard API key.
2. Copy the **Key** and the **Key ID**.
3. Click **Copy URL** to capture the tenant Server URL.
4. Configure an instance of this integration with those three values.

## Commands

### socfw-install-pack

Downloads a pack ZIP from the supplied URL and installs it as system content. Called by the SOCFWPackManager script — do not invoke directly.

| Argument | Required | Description |
|----------|----------|-------------|
| `url` | yes | URL of the pack ZIP (for example, a GitHub release asset). |
| `filename` | no | Asset filename including `.zip`. Derived from the URL if omitted. |

#### Context Output

| Path | Type | Description |
|------|------|-------------|
| `SOCFramework.PackInstall.filename` | String | Installed pack filename. |
| `SOCFramework.PackInstall.status` | String | Install status. |
