**Connection & authentication**


In order to retrieve an API key from the IBM Resilient Systems web UI, go to: _Administrator Settings_ -> _Users tab_ -> _API Keys_ -> **_Create API Key_**.

Capture the generated _API Key ID_ and _API Key Secret_, and provide it to the integration instance configuration.

**Notice**: credentials authentication (username & password) is deprecated and should no longer be used. 


___________
**Fetch**

If new incident fetching is desired, make sure to check the 'Fetch Incidents' box. 
By default, closed incident won't be fetched, check the 'Fetch closed incidents' box if this is desired.

Starting from pack version: 1.2.0 , incident **notes**, **tasks**, **attachments** and **artifacts** are also getting fetched.
Beware, fetching this extra data pieces is time-consuming, and increases fetch times (depends on the amount of extra data to be fetched). We suggest reducing the maximum incidents fetch count to mitigate extended fetch times.

___________
**Mirroring**

Default classifiers & mappers are provided for incoming and outgoing incidents.

It's important to configure the desired mirroring direction and pick whether to close mirrored incidents (Within the advanced settings) on both sides for an improved experience.

There are editable tags, that allow distinguishing between incoming and outgoing notes, tasks, attachments and artifacts.