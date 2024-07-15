**Important:** This integration is supported by Palo Alto Networks.

## Armis Event Collector

Agentless and passive security platform that sees, identifies, and classifies every device, tracks behavior, identifies threats, and takes action automatically to protect critical information and systems.

This integration supports the Armis API 1.8.0 version.
### Obtaining an API key from Armis:

1. Log into the Armis platform and browse to **Settings** by clicking your account icon on the top right-hand side of the screen.
2. Choose **Settings API Management**.
3. Click **Create** and copy the generated key. (Do not share this key and do not create a non-encrypted copy of it.)
4. Refer to [Obtaining an API key from Armis](https://docs.ic.armis.com/docs/introduction_api-keys) for more details.

## General note:

- The **Activities** and **Alerts** event types are expected to have a many logs within a short interval. Therefore, the default limit is 100k and the interval is 1 minute.
- The **Devices** event type is expected to have heavier responses but with fewer events within a long interval. Therefore the default limit is 50k and the interval is 4 hours.
- Internal server errors may occur when there is a significant disparity between the number of events being fetched and the available events within a given time frame. This can happen when the limit set for fetching events is too low, resulting in the retrieval of older events while a substantial number of new events are available.
- If you encounter timeout or internal server errors while fetching events, separate instances for each event type and tweak the limits according to the issues - lowering the limit for timeout or raising the limit for internal server errors.