Use the Google Maps API.
This integration was integrated and tested with version xx of GoogleMaps
## Configure GoogleMaps on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for GoogleMaps.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Google Maps API Key | The API key to use for the connection. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### google-maps-geocode
***
Returns the coordinates of the given physical address.


#### Base Command

`google-maps-geocode`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| address | The physical address to be geocoded. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleMaps.lat | Number | Latitude of the provided location. | 
| GoogleMaps.lng | Number | Longitude of the provided location | 


#### Command Example
``` ```

#### Human Readable Output


