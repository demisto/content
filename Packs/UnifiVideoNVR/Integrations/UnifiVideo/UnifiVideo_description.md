## UnifiVideo
* In order to get the API key for your Unifi NVR follow this steps:
  * Login to the NVR
  * Go to the Users section in the WebUI 
  * Click on your User name -> Api Access -> Allow API Usage
* For the integration configuration you need to specify the schema and port. Keep in mind that the standard http port is 7080 and 7443 for https. Once you switch the schema you'll probably need also to change the port. Keep also in mind that the integration is using the websocket api endpoint not the user interface port.
