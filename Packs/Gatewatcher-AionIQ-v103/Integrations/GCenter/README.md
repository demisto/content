# Get an API key from the GCenter:

- Log in to the WebUI of the GCenter
- In the top right, click on: 'Administration' -> 'API keys' (under the 'Authentication' category)
- Click on 'Add an API key'
- Fill in an 'API key name', select the 'Authorized roles' and set an 'Expiration date' of the key
- Click on 'Save changes'
- An API key will be generated, you can copy it for further usage in Cortex XSOAR

# Setting up the GCenter integration

It is supposed you already have the GCenter integration installed

- On XSOAR, click on 'Settings' on the bottom left
- Search for the GCenter integration card
- Click on 'Add instance'
- The instance configuration will show up.
- Example of a configuration:

	- Name - name of the instance, can be retrieved in XSOAR with the 'Source Instance' field
	- Click on 'Fetches incidents'
	- Leave 'Classifier' as default
	- For 'Incident type', select 'Gatewatcher Incident'
	- For 'Mapper (incoming)', select 'Gatewatcher Mapper Incoming'
	- 'GCenter IP address' - the IP address of your GCenter
	- 'GCenter API token' - fill the API key of your GCenter (To get an API key, see the 'Get an API key from the GCenter section')
	- 'GCenter version' - 2.5.3.103
	- 'GCenter username' - admin
	- 'GCenter password' - password
	- Leave unchecked the 'Check the TLS certificate'
	- 'First fetch' - corresponds to the time where the first fetch will go grab events to actual time. The accepted format is: 5 minutes, 1 hour, 2 days, 6 months
	- 'Fetch limit' - corresponds to the number of events grabbed by fetch. XSOAR recommends to not exceed 200 for performance
	- 'Incidents Fetch Interval' - corresponds to the time XSOAR will re-launch the fetch routine
	- 'Do not use by default' - leave unchecked
	- 'Log Level' - 'Off'
	- 'Run on' - 'Single engine: No engine'

- To test the instance configuration: 

	- Click on 'Test results' on the right side of the configuration pop up
	- Click on 'Run test', a green message with 'Success' must appear for the instance to work
