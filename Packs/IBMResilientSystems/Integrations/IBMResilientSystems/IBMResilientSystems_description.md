**Connection & authentication**


In order to retrieve an API key from the IBM Resilient Systems web UI

1. Go to: **Administrator Settings** > **Users tab** > **API Keys** > **Create API Key**.
2. Capture the generated _API Key ID_ and _API Key Secret_, and provide it to the integration instance configuration.

**Note**: Credentials authentication (username & password) is deprecated and should no longer be used. 


___________
**Fetch**

If new incident fetching is desired, make sure to check the 'Fetch Incidents' box. 
By default, closed incidents won't be fetched. Check the 'Fetch closed incidents' box if this is desired.

Starting from pack version: 1.2.0 , incident **notes**, **tasks**, **attachments** and **artifacts** are also getting fetched.
Beware, fetching these extra data pieces is time-consuming, and increases fetch times (depends on the amount of extra data to be fetched). We suggest reducing the maximum incidents fetch count to mitigate extended fetch times.

___________
**Mirroring**

Default classifiers & mappers are provided for incoming and outgoing incidents.

It's important to configure the desired mirroring direction and pick whether to close mirrored incidents (within the advanced settings) on both sides for an improved experience.

There are editable tags, that allow distinguishing between incoming and outgoing notes, tasks, attachments and artifacts.