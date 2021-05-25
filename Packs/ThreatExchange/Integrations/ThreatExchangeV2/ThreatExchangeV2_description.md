## Authenticate via an Access Token
The ThreatExchange APIs perform authentication via access tokens consisting of App ID and App Secret.
In order to get your App ID and App Secret, Facebook must first confirm your app's access to ThreatExchange.
After Facebook notifies you that your App can access ThreatExchange, go to the App's **Settings** - **Basic** - and copy your App ID and App Secret.
When configuring ThreatExchange v2 on Cortex XSOAR, set the copied values in the ***App ID*** and ***App Secret*** fields.
For more information see [the ThreatExchange API Overview](https://developers.facebook.com/docs/threat-exchange/api/v10.0)

For Cortex XSOAR versions 6.0 and below, the App Secret should be set in the ***password*** field. 