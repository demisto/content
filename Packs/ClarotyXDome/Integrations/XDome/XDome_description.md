In the XDome Instance Settings dialog box, do the following:
* **Name**: Enter a meaningful name for the integration.
* **Fetch incidents**: Choose this option to use the pull-based integration from Cortex XSOAR.
* **Classifier and Mapper**:
  * In the Classifier drop-down list, select xDome - Classifier.
  * In the Mapper drop-down list, select xDome - Incoming Mapper.
* **XDome public API base URL**: Enter your Claroty base url. For additional information please refer to the Integration Guide inside the Claroty Dashboard.
* **API Token**: Enter your API token (generated in the xDome dashboard)
* **The initial time to fetch from**: Define the initial starting time to fetch incidents. For example, if you enter 7 days, the incidents from the previous seven days will be fetched.
* **Maximum number of incidents per fetch**: Limit the maximum number of incidents to fetch per fetching-interval
* **Fetch only unresolved Device-Alert Pairs**: Choose this option to only fetch unresolved device-alert pairs.
* **Alert Types Selection**: Select the required alert types.
* **Incidents Fetch Interval**: Define how often the incidents should be fetched. For example, if you enter 5 minutes, the incidents will be fetched every five minutes.
* **Log Level**: Choose a log level from the drop-down list.
* **Single engine**: Select No engine from the drop-down list.

Click Test. Go to the Test results tab to view the results. If the test was successful, click Save & exit.



