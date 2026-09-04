# Tenzai

Validate Cortex ASM-discovered exposures with Tenzai's agentic penetration testing.

This integration connects Cortex to the Tenzai platform. This version provides connectivity and authentication; validation commands are added in a subsequent release.

## Configure Tenzai in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Tenzai Server URL | The base URL of the Tenzai API (e.g. `https://api.tenzai.io`). | True |
| API Key | The Tenzai partner API key, generated in the Tenzai application. Stored encrypted. | True |
| Trust any certificate (not secure) | | False |
| Use system proxy settings | | False |

After configuring, click **Test** to validate connectivity and that the API key is accepted.

## Commands

This version exposes no runtime commands; it implements the **Test** (`test-module`) connectivity check only.
