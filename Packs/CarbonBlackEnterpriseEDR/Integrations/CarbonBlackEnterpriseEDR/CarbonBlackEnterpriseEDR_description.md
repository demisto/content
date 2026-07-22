## Carbon Black Enterprise EDR
Set up Access Levels and API Keys in the Carbon Black Cloud Console.


**Creating a Custom Access Level**
1. Go to your Carbon Black Cloud console, and open the “Add Access Level” panel from Settings > API Access > Access Levels tab.
2. Give the access level a unique name (you will need this for creating your API Key) and give it a description.
3. From the table below, scroll down until you see your API Service Category. Some Service Categories have multiple permissions that can be configured.

**Creating an API Key**
1. To create an API Key, go to Settings > API Access > API Keys tab in the Carbon Black Cloud console.
2. Select “Add API Key” from the far right.
3. Give the API Key a unique name, and select the appropriate access level provided in the table above. If you select “Custom”, you will need to choose the Access Level you created in the prior section.
4. Hit save, and you will be provided with your API Key Credentials:
  - API Secret Key
  - API ID
  
##### Creating Carbon Black's Query: 
Carbon Black EEDR uses Advanced Search Queries to query for events and processes.
Here's some more information about [Advanced Search Queries](https://developer.carbonblack.com/resources/query_overview.pdf).
