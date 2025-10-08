## Configure Cortex Attack Surface Management

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cortex Attack Surface Management.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
     Server URL | The web UI with `api-` appended to front (e.g., https://api-xsiam.paloaltonetworks.com). For more information please see [Cortex XDR API documentation](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-Started-with-Cortex-XDR-APIs). | True 
     API Key ID | See [Cortex XDR API documentation](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-Started-with-Cortex-XDR-APIs). | True 
     API Key | See [Cortex XDR API documentation](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-Started-with-Cortex-XDR-APIs).  **Only standard API key type is supported**. | True 
    
4. Click **Test** to validate the URLs, token, and connection.


---
[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/cortex-attack-surface-management)