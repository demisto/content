## Run queries and receive alarms from Trellix (McAfee) ESM. Supports version 11.6 and later.

#### Supported Versions
Versions earlier than 11.6 are not supported, as they reached [Trellix end-of-life](https://www.trellix.com/support/end-of-life-products/).

Set the *Version* parameter according to your ESM instance:

| Version | Credential encoding at login |
| --- | --- |
| 11.6.11 and later | AES-encrypted, applied automatically by the integration |
| 11.6.0 - 11.6.10 | Base64 |

Starting with ESM 11.6.11, the login API requires the username and password to be AES-encrypted. The integration performs this encryption automatically - you only need to supply your username and password as usual.

#### Required Permissions
| Component | Permission |
| --- | --- |
| Alarms | Alarm Management *and* View Data |
| Cases | Incident Management Administrator *and* Incident Management User |
| Watchlists | Watchlists |

##### The *Timezone* parameter should be set according to the timezone that McAfee ESM uses. For example, if the alarms in ESM are -0600 then the timezone should be set to -6.


---
[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/mc-afee-esm-v2)