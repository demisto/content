Use the Google Maps API. This integration was integrated and tested with version 3.43 of the Google Maps API. This integration always uses the latest API version.
## Configure GoogleMaps on Cortex XSOAR

### Note
In order to use the embedded Google Maps view, make sure a Google Maps Geocoding API key is set in Cortex XSOAR.

---

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for GoogleMaps.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
       | --- | --- | --- |
   | Google Maps API Key | The API key to use for the connection. | True |
   | Raise error an empty result | Whether to consider empty results as an error. | False |
   | Base URL |  | True |
   | Trust any certificate (not secure) |  | False |
   | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### google-maps-geocode
***
Returns the coordinates of the given physical address. Only the first result is returned (the most relevant, according to Google Maps).

#### Base Command

`google-maps-geocode`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_address | The physical address to be geocoded. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleMaps.SearchAddress | String | The address provided as input. For example, a postal address, a business name, or an area. | 
| GoogleMaps.Address | String | Address of the geocoded location. | 
| GoogleMaps.lat | Number | Latitude of the geocoded location. | 
| GoogleMaps.lng | Number | Longitude of the geocoded location. | 
| GoogleMaps.Country | String | Country of the geocoded location. | 


#### Command Example
``` google-maps-geocode address=45 rothschild tel aviv```

#### Human Readable Output
### Results

|Address|Search Address|Lat|Lng|
|---|---|---|---|
| Rothschild Blvd 45, Tel Aviv-Yafo, Israel | 45 rothschild tel aviv | 32.0642807 | 34.774554 |
