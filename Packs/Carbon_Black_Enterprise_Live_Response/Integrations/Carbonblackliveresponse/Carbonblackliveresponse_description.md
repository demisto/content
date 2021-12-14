Use Live Response for VMware Carbon Black Endpoint Standard or VMware Carbon Black EDR (previously known as Carbon Black Defense and Carbon Black Response respectively). 

For VMware Carbon Black Endpoint Standard:
Provide server URL,  'Live Response' API key and connector. 

For VMware Carbon Black EDR:
Provide server URL and API Token.


When running Live Response commands (e.g. 'cb-process-kill'), it is possible to pass 'wait-timeout' argument to determine the number of seconds to wait for the command to be executed on Live Response side. Once the command has been executed or wait-time has expired - the command information will be returned to the war room. 
Default 'wait-time' is 20 seconds.
