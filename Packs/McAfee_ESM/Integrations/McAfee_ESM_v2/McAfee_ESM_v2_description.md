## McAfee ESM v2

Run queries and receive alarms from Trellix (McAfee) ESM. Supports version 11.6 and later.

### Setup

Versions earlier than 11.6.0 are not supported — they reached [Trellix end-of-life](https://www.trellix.com/support/end-of-life-products/) and the integration returns an error immediately if such a version is configured.

Enter the version number of your ESM instance (e.g., `11.6.11`) in the **Version** parameter. The integration selects the correct credential encoding automatically:

| Version range | Credential encoding at login |
| --- | --- |
| 11.6.11 and later | AES-encrypted, applied automatically by the integration |
| 11.6.0 - 11.6.10 | Base64 |
| Earlier than 11.6.0 | **Not supported** — configuration fails immediately |

Starting with ESM 11.6.11, the login API requires the username and password to be AES-encrypted. The integration performs this encryption automatically — you only need to supply your username and password as usual.

Set the **McAfee ESM Timezone in hours** parameter according to the timezone that McAfee ESM uses. For example, if the alarms in ESM are -0600, set the parameter to -6.

### Required Permissions

| Component | Permission |
| --- | --- |
| Alarms | Alarm Management *and* View Data |
| Cases | Incident Management Administrator *and* Incident Management User |
| Watchlists | Watchlists |

---
[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/mc-afee-esm-v2)
