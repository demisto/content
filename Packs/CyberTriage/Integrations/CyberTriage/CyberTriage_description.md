## Cyber Triage Integration Setup

This integration requires the **Team** version of Cyber Triage (version 3.16.0 or later). The Standalone desktop version is not supported.

To configure the integration, provide the following:

- **Cyber Triage Server Hostname** — IP address or hostname of the machine running the Cyber Triage server (e.g. `192.168.1.2`).
- **REST Port** — The Cyber Triage REST API port. Leave this as `9443` (the default; it cannot be changed in Cyber Triage).
- **API Key** — REST API token for the Cyber Triage API. Retrieve it from the Cyber Triage server: Options → User Accounts.  Click the three dots next to *api-user* and select *View Details*. Under *API Authentication Token*, copy or create a new authentication token.
- **Windows Admin Credentials** — Username and password of a Windows administrative account used to push the collection tool to target endpoints.  See the [documentation](https://docs.cybertriage.com/en/latest/chapters/importing/psexec.html) for more information.
- **Trust any certificate (not secure)** — Enable to skip SSL certificate verification (useful for self-signed certificates).
- **Use system proxy settings** — Enable if your environment routes traffic through a proxy.

---

## Starting a Collection

After configuring an instance, use the `ct-triage-endpoint` command to initiate a collection. Provide the hostname or IP address of the target Windows endpoint.

Once started, open a Cyber Triage client to review the collected data.

---

## Support

Documentation can be found at [https://docs.cybertriage.com/](https://docs.cybertriage.com/).

For questions or to request an evaluation copy, email: **support@sleuthkitlabs.com**
