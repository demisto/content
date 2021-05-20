## F5 Silverline

To configure an instance of F5 Silverline, you need to obtain the following information.

* Server URL
* API Key

## Get your API Key
1. In F5 Silverline portal, go to **Config** > **API Tokens** .
2. If you already have an API key you can find it there.
3. If you do not have an API Key, generate one by clicking the **Add** button.

## Fetching F5 Silverline Alerts

In order to fetch alerts from F5 Silverline you should follow the instructions below:
1. In your Cortex XSOAR install F5 Silverline integration.
2. In F5 Silverline portal, go to **Config** > **Log Export** .
3. F5 Silverline "Log Export" should be configured with a "Host" destination that supports TLS+TCP communication.
4. Follow the instructions here: https://support.f5silverline.com/hc/en-us/articles/214152048
5. In your Cortex XSOAR install Syslog integration.
6. Configure the Syslog instance with your log receiver details:
   * Click on "Fetches incidents".
   * Set the Classifier to "F5 Silverline Classifier". 
   * Set the Mapper to "F5 Silverline Mapper".
   * IP address - The IP of your log receiver host.
   * Port - The port of your log receiver host.
   * Protocol - TCP or UDP.
   * Format - Auto.
7. Once the log receiver is configured it should forward the logs in TCP or UDP toward Cortex XSOAR - Syslog integration.
If everything goes as expected you should be able to ses that incidents were successfully pulled.
