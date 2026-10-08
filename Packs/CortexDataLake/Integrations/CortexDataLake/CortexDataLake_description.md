## Overview

---

Palo Alto Networks Strata Logging Service XSOAR Connector provides cloud-based, centralized log storage and aggregation for your on-premises, virtual (private cloud and public cloud) firewalls, for Prisma Access, and for cloud-delivered services such as Cortex XDR.
This integration was tested with version 2 of Strata Logging Service XSOAR Connector.

---

## Configure Strata Logging Service XSOAR Connector on Cortex XSOAR

---

1. Go to the [HUB](https://apps.paloaltonetworks.com/apps) and log in using your Palo Alto Networks credentials.
2. Under the `Cortex XSOAR` app, select the relevant instance. If you don't have an active `Cortex XSOAR` app, check out the Hub [Docs site](https://docs.paloaltonetworks.com/hub/hub-getting-started/get-started) to learn about app activation.
3. Once the page loads, if required, insert the `license ID` and the `Customer Name` in the required fields and complete the authentication process in order to get the **Registration ID**, **Encryption Key**, and either **Authentication Token** or **Client Secret**.
    * To get the `license ID`, run the command `!GetLicenseID` in the War Room.
    * To get the `Customer Name`, Go to **Settings** \> **ABOUT** \> **License**.
4. Deppending on your tenant, navigate to either of the following:
    * Cortex Agentix: **Settings** > **Data Collection** > **Data Sources & Integrations**.
    * Cortex XSOAR: **Settings** > **Integrations** > **Instances**.
5. Search for Strata Logging Service.
6. Click **Add instance** to create and configure a new integration instance.
    * **Name**: A textual name for the integration instance.
    * **Registration ID**: From the authentication process.
        * The token retrieval URL is inferred based on the tenant's FedRAMP status unless explicitly specified in the **Registration ID** parameter in the format `REGISTRATION_ID@URL`.
    * **Encryption Key**: From the authentication process.
    * **Authentication Token** OR **Client Secret**: From the authentication process.
    * **proxy**: Use system proxy settings.
    * **insecure**: Trust any certificate (not secure).
    * **Fetch incidents**: Whether to fetch incidents.
    * **First fetch time**: First fetch time (\<number\> \<time unit\>, e.g., 12 hours, 7 days, 3 months, 1 year).
    * **Severity of events to fetch (Firewall)**: Select from all, Critical, High, Medium, Low, Informational, or Unused.
    * **Subtype of events to fetch (Firewall)**: Select from all, attack, url, virus, spyware, vulnerability, file, scan, flood, packet, resource, data, url-content, wildfire, extpcap, wildfire-virus, http-hdr-insert, http-hdr, email-hdr, spyware-dns, spyware-wildfire-dns, spyware-wpc-dns, spyware-custom-dns, spyware-cloud-dns, spyware-raven, spyware-wildfire-raven, spyware-wpc-raven, wpc-virus, or sctp.
7. Click **Test** to validate the credentials and connection.

## CDL Server - API Calls Caching Mechanism

The integration implements a caching mechanism for repetitive errors when requesting an access token from the CDL server.
When the integration reaches the limit of allowed calls, the following error will be shown:

```We have found out that your recent attempts to authenticate against the CDL server have failed. Therefore, we have limited the number of calls that the CDL integration performs.```

The integration will re-attempt authentication if the command was called under the following cases:

1. First hour - once every minute.
2. First 48 hours - once in 10 minutes.
3. After that, every 60 minutes.

To try authenticating again, run the 'cdl-reset-authentication-timeout' command and retry.
