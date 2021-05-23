## Carbon Black Cloud Live Response
Set up API Keys in the Carbon Black Cloud.


**Creating an API Key**
1. To create an API Key, go to Settings > API Access > API Keys tab in the Carbon Black Cloud web page.
2. Select “Add API Key” from the far right.
3. Give the API Key a unique name, and select the Live Response access level.
4. Hit save, and you will be provided with your API Key Credentials:
  - API Secret Key
  - API ID
5. Go to Settings > API Access and copy the ORG KEY from the top left corner of the page
6. Set up Carbon Black Cloud Live Response integration instance with the ORG KEY and created API Secret Key and API ID


**Getting the sensor id**

To get the sensor id you can run the command ``cbd-device-search`` (should have an instance of Carbon Black Defense integration) and find it according the name,
or manually, in Carbon Black Cloud web page go to Endpoints > search for the sensor name > click > 
the sensor id will appear in the top of the page in the format ``device_id:<the device id>``. 