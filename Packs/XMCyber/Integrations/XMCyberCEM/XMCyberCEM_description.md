# XM Cyber CEM Help Guide

## How to get your XM Cyber API Key

To get your XM Cyber API Key you have to :

- Log on the XM Cyber UI.
- Go to "System Config" > "Integrations" > "API Keys".
- Create a new API Key with appropriate roles.
  - Click on **Create API Key**
  - Assign the following roles based on your use case:
    - **Reports Read**: Required to populate dashboards in Cortex XSOAR.
    - **Inventory Read and Write**: Required to enrich the incident and push breach point data to XM Cyber.
- Use this API Key directly in this integration or keep it using the Cortex XSOAR credentials store. In that case, the API Key should be stored in the "password" field.

## How to configure the XM Cyber CEM integration

To configure this integration you have to fill in the **Server URL** and the **API Key** fields.

After configuring the integration parameters, you can click Test to ensure that the connection to the XM Cyber platform is successful.

Once the integration instance is configured, it will be used to populate the XM Cyber dashboard.
