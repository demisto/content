## Digital Guardian ARC Event Collector Help

### Required Parameters

API Client ID 

API Client Secret 

Gateway Base URL 

Auth Server URL 

Export Profile 

### How to get them
API Client ID: 
This is the Tenant ID and can be found in the ARC Tenant Settings 

API Client Secret:  
Authentication Token from the ARC Tenant Settings 

Gateway Base URL:  
From DGMC Cloud Services setup screen, Access Gateway Base URL 

Auth Server URL: 
From DGMC Cloud Services setup screen, Authorization server URL 

The GUID of your Export Profile:
From ARC within the tenant. Admin > reports > export profiles. 
You need the export GUID. So, edit the profile and you’ll see the GUID in the URL.  
(For example the URL might be: https://dgarc.msp.digitalguardian.com/rest/1.0/export_profiles/24e60ea0-1625-40de-b15d-740b4a69642d/export But you only need the GUID portion which is: 24e60ea0-1625-40de-b15d-740b4a69642d) 