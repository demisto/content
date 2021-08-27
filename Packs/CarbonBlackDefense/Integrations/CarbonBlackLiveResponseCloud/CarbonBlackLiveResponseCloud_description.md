## Carbon Black Cloud Live Response
Set up the API keys in Carbon Black Cloud.


#### Create a Custom Access Level

1. In the Carbon Black Cloud web page, go to **Settings** > **API Access** > **Access Levels** tab.
2. Open the *Add Access Level* panel. 
3. Give the access level a unique name (you will need this for creating your API Key) and a description.
4. In the table, scroll down to the **General information** permission in **Device** category, and click the checkbox in the **READ** column.
5. Click **Save**.
6. Scroll down until you see the Live Response category. Configure the required permissions.

#### Create an API Key

1. In the Carbon Black Cloud web page, go to **Settings** > **API Access** > **API Keys** tab.
2. Select **Add API Key** from the far right.
3. Give the API key a unique name, and select the appropriate access level. If you select
   "Custom", you will need to choose the Access Level you created in the *Create a Custom Access Level* section.
4. Click **Save**. You will be provided with your API key credentials:
   - API Secret Key
   - API Key
 
   Click [here](https://developer.carbonblack.com/reference/carbon-black-cloud/authentication) for more information about authentication.
5. Go to **Settings** > **API Access** and copy the ORG KEY from the top left corner of the page
6. Set up Carbon Black Cloud Live Response integration instance with the ORG KEY and the API Secret Key and API ID you created.


#### Getting the Device ID

To get the device ID:
- In Cortex XSOAR
  1. Create an instance of the Carbon Black Defense integration.
  1. Run the **cbd-device-search** command
  2. Find the ID according to its name.
- From the Carbon Black Cloud web page:
  1. Click **Endpoints**
  2. Search for and click the device name. The device ID will appear at the top of the page in the format *device_id:<the device id>*. 
