## XMCO Serenety

To configure an instance of XMCO Serenety integration in Cortex XSOAR:

1. Select `XMCO Serenety Alert` in the Incident type section.
2. Select `XMCO - Serenety Mapper` in the Mapper section.
3. Provide 'Server URL'. The default server URL should be sufficient.

4. Provide 'API Key':

   Retrieve your authentication token via the [XMCO LePortail](https://leportail.xmco.fr)

   Keep the token safe, as it grants access to sensitive threat data related to your organization. Store it in a secure place, such as an encrypted password vault, and do not share it unless absolutely necessary. If you feel that the token has been compromised, please change it immediately.

5. Check the options `Trust any certificate (not secure)` and `Use system proxy settings` if needed. You can test with the `Test` button.
6. The options `Maximum number of incidents per fetch` and `First fetch time` are not used for the moment, so you can let the default values (50 et 3 days).