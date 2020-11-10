## Alien Vault OTX TAXII Feed
This integration fetches indicators from AlienVault OTX using a TAXII client.

If the **All Indicators** checkbox is selected, the integration will run on all **active** collections regaurdless of the 
collections supplied in the **Collections** parameter. Inactive/Empty collections will not return indicators and will result in a Timeout error.

If the **Collections** parameter is not set, the error message will list all the accessible collections.
