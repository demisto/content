## Palo Alto Networks Cortex XDR - IR
[Cortex XDR](https://www.paloaltonetworks.com/cortex/cortex-xdr) is the world's first detection and response app that natively integrates network, endpoint, and cloud data to stop sophisticated attacks.

### Generate an API Key and API Key ID
1. In your Cortex XDR platform, go to **Settings** > **Configurations** > **Integrations** >**API key** page..
2. Click the **+New Key** button in the top right corner.
3. Generate a key of *Security Level* type **Advanced**, and a *Role* according your Permissions.
4. Copy and paste the key from Generated key.
5. From the ID column, copy the Key ID.

### URL
1. In your Cortex XDR platform, go to **Settings** > **Configurations** > **Integrations** > **API key** page.
2. Click the **Copy API URL** button in the top right corner.

---

### Mirroring

**Close-reason default mapping XSOAR -> XDR**: _Other=Other, Duplicate=Duplicate Incident, False Positive=False Positive, Resolved=True Positive_

**Close-reason default mapping XDR -> XSOAR**: _Known Issue=Other, Duplicate Incident=Duplicate, False Positive=False Positive, True Positive=Resolved, Other=Other, Auto=Resolved_

[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/cortex-xdr---ir)
