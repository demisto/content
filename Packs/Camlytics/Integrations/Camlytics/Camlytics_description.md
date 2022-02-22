## Camlytics Integration Help

Camlytics provides a very simple and universal way to control all camera events and retrieve channels data. In order to integrate with the application via REST API, complete the following steps:
- Start the application and make sure you have the latest version (min supported version is 1.2.1)
- Make sure the REST API is enabled in settings (should enabled by default)
- To verify that the REST API is working, add a channel, generate any event (object appear, etc.) and go to http://localhost:48462/v1/json/events?limit=10&order=DESC&timeout=5. If no events are available, an empty JSON array will be returned. 
- In case something went wrong, please refer to logs that are located in %APPDATA%\Camlytics\Logs\.

