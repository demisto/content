## F5 Silverline

To configure an instance of F5 Silverline, you need to obtain the following information.

* Server URL
* API Key

## Get your API Key
1. In F5 Silverline portal, go to **Config** > **API Tokens** .
2. If you already have an API key you can find it there.
3. If you do not have an API Key, generate one by clicking **Add**.

## Fetching F5 Silverline Alerts

As the F5 Silverline API does not support fetch incidents for now, we retrieve alerts via a log collector.   
In order to fetch alerts, follow the instructions below:
1. In Cortex XSOAR, install the F5 Silverline integration.
2. In the F5 Silverline portal, go to **Config** > **Log Export** .
3. Configure the F5 Silverline "Log Export". Follow the instructions here: https://support.f5silverline.com/hc/en-us/articles/214152048. The "Host" destination must support TLS+TCP communication. 
4. In Cortex XSOAR, go **Settings** > **Integrations**.
5. Search for Syslog (This integration is installed by  default).
6. Configure the Syslog instance with your log receiver details:
   * Click "Fetches incidents".
   * Set the Classifier to "F5 Silverline Classifier". 
   * Set the Mapper to "F5 Silverline Mapper".
   * IP address - specify the IP address of your log receiver host.
   * Port - specify the port of your log receiver host.
   * Protocol - choose TCP or UDP.
   * Format - specify to 'Auto'.
    
   Once the log receiver is configured it will forward the logs in TCP or UDP to Cortex XSOAR - Syslog integration and you will see that incidents were successfully pulled.
