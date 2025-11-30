Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.

This integration collects audit events from the LivePerson LiveEngage platform (part of LivePerson's Conversational Cloud).

The integration uses the **LivePerson Audit Trail API** to fetch administrative and configuration events, allowing security teams to monitor user changes, skill modifications, agent activity, and other critical actions within their customer engagement platform.

### Authentication and Setup

This integration uses OAuth 2.0 for authentication. To configure an instance, you will need three pieces of information from your LivePerson account:

1.  **Account ID (Site ID):** Your unique LivePerson account identifier.
2.  **Client ID and Client Secret:** These are API keys. You can generate them in your LivePerson admin console, typically under **Manage > APIs**.
3.  **Authorization Server URL:** This is the base URL for the LivePerson authentication service. It is specific to your account's region.

The integration simplifies setup by automatically discovering the correct Event API domain for your account based on the Authorization Server URL you provide.

#### Common Authorization Server URLs
You must provide the URL for your account's region. Do not include `https://`.

* **APAC:** `sy.sentinel.liveperson.net`
* **EMEA:** `lo.sentinel.liveperson.net`
* **US:** `va.sentinel.liveperson.net`

Contact LivePerson support if you are unsure of your account's specific URL.

### Required Configuration
When you add an instance, you will need to fill in these parameters:

* **Authorization Server URL** (e.g., `va.sentinel.liveperson.net`)
* **Account ID**
* **Client ID and Client Secret** (using the credential field)
* **First fetch time** (e.g., `3 days` to set how far back to look for events)

Select **Fetch events** to begin collecting audit data.
