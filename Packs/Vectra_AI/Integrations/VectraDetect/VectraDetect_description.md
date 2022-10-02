Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.

# Vectra Detect (Beta) Help

## How to get your Vectra Detect API token
To get your Vectra Detect API token you have to :
- Create a local user with a sufficient role
- Log on the Vectra Detect UI as this local user
- Go to "My Profile" > "General" (tab)
- Copy or generate a new token 
- Use this token directly in this integration or keep it using the XSOAR credentials store. In that case, the token should be stored in the "password" field

## How to configure the Vectra Detect integration
To configure this integration you have to fill in the **Vectra Detect FQDN or IP** and the **API token** fields.  
*Regarding the API Token you can switch to use defined XSOAR credentials store.*  
Now if you want to tune more the integration, you can modify the others fields.

### Fetch queries
This integration provide 3 search queries (one per entity) in order for you to limit the events you want to fetch from Vectra Detect.
These do not affect commands results, just the "Fetches incidents" action.

All fetch queries (Accounts, Hosts, Detections) should be written in Lucene wording.
During the fetch process, they are appended with "*.state:active" to get only the active events from Vectra Detect.
