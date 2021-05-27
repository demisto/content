## Carbon Black Cloud Live Response
Set up API Keys in the Carbon Black Cloud.


#### Create a Custom Access Level

1. In the Carbon Black Cloud web page, go to **Settings** > **API Access** > **Access Levels** tab.
2. Open the *Add Access Level* panel. 
3. Give the access level a unique name (you will need this for creating your API Key) and a description.
4. In the table scroll down to the **General information** permission in **Device** category, and click on the checkbox in **READ** column -> save
5. Scroll down until you see the Live Response category. Configure the required permissions.

#### Create an API Key

1. In the Carbon Black Cloud web page, go to **Settings** > **API Access** > **API Keys** tab.
2. Select **Add API Key** from the far right.
3. Give the API key a unique name, and select the appropriate access level. If you select
   "Custom", you will need to choose the Access Level you created in the *Create a Custom Access Level* section.
4. Click **Save**. You will be provided with your API key credentials:
   - API Secret Key
   - API Key
 
   Click [here](https://developer.carbonblack.com/reference/carbon-black-cloud/authentication) for more information about authentication.
5. Go to Settings > API Access and copy the ORG KEY from the top left corner of the page
6. Set up Carbon Black Cloud Live Response integration instance with the ORG KEY and created API Secret Key and API ID


#### Getting the device id

To get the device id you can run the command ``cbd-device-search`` (should have an instance of Carbon Black Defense integration) and find it according the name,
or manually, in Carbon Black Cloud web page go to Endpoints > search for the device name > click > 
the device id will appear in the top of the page in the format ``device_id:<the device id>``. 