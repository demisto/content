## How to Access the Export Indicators Service
There are two ways that you can access the Export Indicators Service.

### Access the Export Indicators Service by URL and Port (HTTP)
In a web browser, go to **http://*demisto_address*:*listen_port***.


### Access the Export Indicators Service by Instance Name (HTTPS)
To access the EDL service by instance name, make sure ***Instance execute external*** is enabled. 

1. In Demisto, go to **Settings > About > Troubleshooting**.
2. In the **Server Configuration** section, verify that the ***instance.execute.external*** key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add the *instance.execute.external* and set the value to *true*.
3. In a web browser, go to **https://*<demisto_address>*/instance/execute/*<instance_name>*** .
