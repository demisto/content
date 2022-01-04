Returns a map entry with a marker on the given coordinate (lat, lng). 

NOTE: Although you do not need to create a [Google Maps](https://xsoar.pan.dev/docs/reference/integrations/google-maps) instance integration, if you want to use the `address` argument, you must set up a Google Maps instance.

Before using this automation, you need to [Setup Google Maps](#-setup-google-maps-in-cortex-xsoar) to work with Cortex XSOAR.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Utility |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| lat | The latitude. For example, `32.064622`. |
| lng | The longitude. For example, `34.774131`. |
| address | A location description. For example, `1600 pennsylvania ave, DC` or `Mount Kilimanjaro`. 


## Outputs
---
There are no outputs for this script.


## Command Example
---
`!ShowOnMap lat=6.1287 lng=1.2215`


## Setup Google Maps in Cortex XSOAR
---

To use this automation, you need to create a new project and Google Maps Platform API. The API needs to be added to Cortex XSOAR. 

Before you begin, ensure that your Google Cloud account has [billing enabled](https://developers.google.com/maps/documentation/javascript/cloud-setup#billing). The Cloud billing account pays for your use of the Google Maps Platform API. 


1. In Google Cloud Platform, do the following:
   1. Create a [Google Cloud Project](https://developers.google.com/maps/documentation/javascript/cloud-setup).
   2. Create a [Google Maps Platform API](https://developers.google.com/maps/documentation/javascript/get-api-key) for your project.

   3. Enable APIs and Services (**API & Services>Dashboard**> **ENABLE APIS AND SERVICES**).
   4. Enable **Maps JavaScriptAPI**.
   5. Create the [Google Maps Platform API key](https://developers.google.com/maps/documentation/javascript/get-api-key#creating-api-keys) ( **Credentials**> **CREATE CREDENTIALS>API key**).
   6. Copy the Google Maps Platform API key.
2. In Cortex XSOAR, add the Google Maps Platform API key.
   1. Select **Settings > ABOUT > Troubleshooting> Add Server Configuration.**
   2. Add the following key and value: 

      | Key | Value |  
      | ----|----- | 
      | `UI.google.api.key`| `Google Maps Plafom API Key` (copied from step 1.3 above)|
    1. Click **Save**.
   
For an example, see [How to Display a Geo-location using Google Maps in the War Room](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u000000oMOUCA2&lang=en_US%E2%80%A9).
